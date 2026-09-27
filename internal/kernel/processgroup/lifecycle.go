// Package processgroup owns retained-child process-group identity for source tools.
package processgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

const observeInterval = 10 * time.Millisecond

// ErrOwnershipLost revokes all numeric targeting, including Wait. Local streams
// must still be joined; child cleanup and exit status remain unverified.
var ErrOwnershipLost = errors.New("fatal process ownership lost; child cleanup unverified")

type operations struct {
	observe func(int, int) (bool, error)
	kill    func(int) error
	wait    func() error
	absent  func(int, time.Duration) error
}

// Child is the sole signal, seal and reap owner after Start. Callers own streams
// and must join them before Finish. No caller may Wait, Release or signal Cmd.
type Child struct {
	mu                                        sync.Mutex
	pid, parent                               int
	ops                                       operations
	terminal, aborted, sealed, lost, finished bool
	failure                                   error
	permissionErr                             error
	terminalReady, abortReady                 chan struct{}
	observerDone                              chan struct{}
	watchStop, watchDone                      chan struct{}
}

// Start admits only an ordinary exec.Command with file-backed or nil stdio.
// CommandContext is forbidden even when its public Cancel field is cleared:
// its private watcher is outside this owner's serialization boundary.
func Start(ctx context.Context, command *exec.Cmd) (*Child, error) {
	if ctx == nil || command == nil || command.Cancel != nil || command.WaitDelay != 0 || command.Process != nil {
		return nil, errors.New("retained child requires an unstarted ordinary command")
	}
	for _, stream := range []any{command.Stdin, command.Stdout, command.Stderr} {
		if stream != nil {
			if _, ok := stream.(*os.File); !ok {
				return nil, errors.New("retained child requires explicitly owned stdio")
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := configure(command); err != nil {
		return nil, err
	}
	if err := command.Start(); err != nil {
		return nil, err
	}
	child := newChild(command.Process.Pid, os.Getpid(), operations{
		observe: observeTerminal, kill: killGroup, wait: command.Wait, absent: waitAbsent,
	})
	go child.observe()
	go func() {
		defer close(child.watchDone)
		select {
		case <-ctx.Done():
			_ = child.Abort()
		case <-child.watchStop:
		}
	}()
	if ctx.Err() != nil {
		_ = child.Abort()
	}
	return child, nil
}

func newChild(pid, parent int, ops operations) *Child {
	return &Child{pid: pid, parent: parent, ops: ops,
		terminalReady: make(chan struct{}), abortReady: make(chan struct{}),
		observerDone: make(chan struct{}),
		watchStop:    make(chan struct{}), watchDone: make(chan struct{}),
	}
}

func (child *Child) Terminal() <-chan struct{} { return child.terminalReady }
func (child *Child) Aborted() <-chan struct{}  { return child.abortReady }

func (child *Child) abortLocked() error {
	if child.aborted {
		return nil
	}
	child.aborted = true
	defer close(child.abortReady)
	if child.sealed {
		return nil
	}
	err := child.ops.kill(child.pid)
	if absentSignal(err) {
		err = nil
	}
	if permissionSignal(err) {
		child.permissionErr = err
		err = nil
	}
	child.failure = errors.Join(child.failure, err)
	return err
}

// Abort attempts termination before any stream or observer join. A late abort
// still publishes failure state but can never signal after the monotone seal.
func (child *Child) Abort() error {
	child.mu.Lock()
	defer child.mu.Unlock()
	return child.abortLocked()
}

func (child *Child) observe() {
	defer close(child.observerDone)
	for {
		// A delayed sysctl must not hold the signal/seal lock.
		terminal, err := child.ops.observe(child.pid, child.parent)
		child.mu.Lock()
		if err != nil {
			child.failure = errors.Join(child.failure, fmt.Errorf("observe retained child: %w", err))
			if errors.Is(err, ErrOwnershipLost) {
				child.lost, child.sealed = true, true
			}
			_ = child.abortLocked()
		} else if terminal {
			child.terminal = true
			close(child.terminalReady)
		}
		child.mu.Unlock()
		if terminal || err != nil {
			return
		}
		time.Sleep(observeInterval)
	}
}

// Finish requires joined caller-owned streams and either Terminal or Abort.
// It retains the join obligation if the kernel refuses termination or hangs;
// no userspace deadline promises a finite completed return in those states.
// waitErr is the real sole Cmd.Wait result, never an observer-derived status.
func (child *Child) Finish(timeout time.Duration) (waitErr, cleanupErr error) {
	child.mu.Lock()
	if child.finished {
		child.mu.Unlock()
		return nil, errors.New("retained child Finish called twice")
	}
	child.finished = true
	if !child.terminal && !child.aborted {
		child.failure = errors.Join(child.failure, errors.New("finish before terminal or abort"))
		_ = child.abortLocked()
	}
	child.mu.Unlock()
	<-child.observerDone
	child.mu.Lock()
	if !child.lost {
		err := child.ops.kill(child.pid)
		if permissionSignal(err) {
			child.permissionErr = err
			err = nil
		}
		if absentSignal(err) {
			err = nil
		}
		child.failure = errors.Join(child.failure, err)
		child.sealed = true
	}
	lost := child.lost
	child.mu.Unlock()
	if !lost {
		waitErr = child.ops.wait()
		cleanupErr = child.ops.absent(child.pid, timeout)
	}
	close(child.watchStop)
	<-child.watchDone
	child.mu.Lock()
	defer child.mu.Unlock()
	if cleanupErr != nil {
		cleanupErr = errors.Join(cleanupErr, child.permissionErr)
	}
	return waitErr, errors.Join(child.failure, cleanupErr)
}
