//go:build darwin || linux

package processgroup

import (
	"context"
	"errors"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

func TestProbeRequiresPostReapObservedAbsence(t *testing.T) {
	for _, states := range [][]error{{syscall.ESRCH}, {nil, syscall.ESRCH}, {syscall.EPERM, syscall.ESRCH}, {syscall.EPERM, nil, syscall.ESRCH}} {
		calls := 0
		err := probeAbsent(123, time.Second, func(pid int, signal syscall.Signal) error {
			if pid != -123 || signal != 0 || calls >= len(states) {
				t.Fatalf("unexpected probe: %d %d", pid, signal)
			}
			err := states[calls]
			calls++
			return err
		})
		if err != nil || calls != len(states) {
			t.Fatalf("absence: %d %v", calls, err)
		}
	}
	for _, result := range []error{nil, syscall.EPERM, syscall.EIO} {
		err := probeAbsent(123, time.Millisecond, func(int, syscall.Signal) error { return result })
		if err == nil || result != nil && !errors.Is(err, result) {
			t.Fatalf("false absence: %v", err)
		}
		if result != syscall.EIO && !strings.Contains(err.Error(), "cleanup timeout") {
			t.Fatal(err)
		}
	}
	for _, budget := range []time.Duration{0, -time.Second} {
		if probeAbsent(123, budget, func(int, syscall.Signal) error { t.Fatal("invalid-budget probe"); return nil }) == nil {
			t.Fatal("invalid budget admitted")
		}
	}
}

// Synthetic identities never reach a syscall. The trace oracle checks the
// ordering independently of Child's flags, with barriers forcing each race.
func TestRetainedSignalSealReapTrace(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "abort_before_seal", true: "abort_after_seal"}[late], func(t *testing.T) {
			var trace []string
			var mu sync.Mutex
			add := func(event string) { mu.Lock(); defer mu.Unlock(); trace = append(trace, event) }
			entered, release := make(chan struct{}), make(chan struct{})
			var enteredOnce sync.Once
			var child *Child
			child = newChild(123, 1, operations{
				kill: func(int) error {
					add("signal.begin")
					enteredOnce.Do(func() { close(entered) })
					<-release
					add("signal.end")
					return nil
				},
				wait: func() error {
					child.mu.Lock()
					sealed := child.sealed
					child.mu.Unlock()
					if !sealed {
						t.Error("reap before seal")
					}
					add("seal.observed")
					add("reap")
					if late {
						_ = child.Abort()
						add("late.abort")
					}
					return nil
				},
				absent: func(int, time.Duration) error { add("probe"); return nil },
			})
			child.terminal = true
			close(child.observerDone)
			close(child.watchDone)
			done := make(chan error, 1)
			if !late {
				abortDone := make(chan struct{})
				go func() { _ = child.Abort(); close(abortDone) }()
				<-entered
				go func() { _, err := child.Finish(time.Second); done <- err }()
				close(release)
				<-abortDone
			} else {
				go func() { _, err := child.Finish(time.Second); done <- err }()
				<-entered
				close(release)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			want := []string{"signal.begin", "signal.end", "seal.observed", "reap", "late.abort", "probe"}
			if !late {
				want = []string{"signal.begin", "signal.end", "signal.begin", "signal.end", "seal.observed", "reap", "probe"}
			}
			if !slices.Equal(trace, want) {
				t.Fatalf("trace %v, want %v", trace, want)
			}
			_ = child.Abort()
			if !slices.Equal(trace, want) {
				t.Fatal("post-result destructive effect")
			}
		})
	}
}

func TestRetainedDelayedObserverAbortAndLostIdentity(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(map[bool]string{false: "delayed_terminal", true: "lost_identity"}[lost], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				entered, release, killed := make(chan struct{}), make(chan struct{}), make(chan struct{})
				releaseObserver := sync.OnceFunc(func() { close(release) })
				defer releaseObserver()
				var once sync.Once
				kills, waits, probes := 0, 0, 0
				child := newChild(123, 1, operations{
					observe: func(int, int) (bool, error) {
						close(entered)
						<-release
						if lost {
							return false, ErrOwnershipLost
						}
						return true, nil
					},
					kill:   func(int) error { kills++; once.Do(func() { close(killed) }); return nil },
					wait:   func() error { waits++; return nil },
					absent: func(int, time.Duration) error { probes++; return nil },
				})
				close(child.watchDone)
				go child.observe()
				<-entered
				if err := child.Abort(); err != nil {
					t.Fatal(err)
				}
				<-killed // Abort made progress without joining the blocked observer.
				done := make(chan error, 1)
				go func() { _, err := child.Finish(time.Second); done <- err }()
				synctest.Wait()
				if len(done) != 0 {
					t.Error("detached observer reported closure")
				}
				releaseObserver()
				err := <-done
				synctest.Wait()
				if lost {
					if !errors.Is(err, ErrOwnershipLost) || kills != 1 || waits != 0 || probes != 0 {
						t.Fatalf("lost authority: %v %d %d %d", err, kills, waits, probes)
					}
				} else if err != nil || kills != 2 || waits != 1 || probes != 1 {
					t.Fatalf("join: %v %d %d %d", err, kills, waits, probes)
				}
			})
		})
	}
}

func TestRetainedObservationFailureDoesNotForgeExit(t *testing.T) {
	for _, failure := range []error{syscall.EIO, ErrOwnershipLost} {
		kills, waits := 0, 0
		child := newChild(123, 1, operations{
			observe: func(int, int) (bool, error) { return false, failure },
			kill:    func(int) error { kills++; return nil },
			wait:    func() error { waits++; return nil },
			absent:  func(int, time.Duration) error { return nil },
		})
		close(child.watchDone)
		go child.observe()
		<-child.Aborted()
		select {
		case <-child.Terminal():
			t.Fatal("error forged terminal")
		default:
		}
		_, err := child.Finish(time.Second)
		if !errors.Is(err, failure) {
			t.Fatal(err)
		}
		if errors.Is(failure, ErrOwnershipLost) && (kills != 0 || waits != 0) {
			t.Fatal("numeric targeting after ownership loss")
		}
		if failure == syscall.EIO && (kills != 2 || waits != 1) {
			t.Fatal("ordinary observation failure lost cleanup")
		}
	}
}

func TestRetainedNativeRepeatedTerminalPreservesExit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	command := exec.Command("/bin/sh", "-c", "exit 17")
	child, err := Start(ctx, command)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-child.Terminal():
	case <-child.Aborted():
	}
	for i := 0; i < 3; i++ {
		terminal, err := observeTerminal(child.pid, child.parent)
		if !terminal || err != nil {
			_ = child.Abort()
			_, _ = child.Finish(time.Second)
			t.Fatalf("retained observation %v %v", terminal, err)
		}
	}
	waitErr, cleanupErr := child.Finish(time.Second)
	var exit *exec.ExitError
	if cleanupErr != nil || !errors.As(waitErr, &exit) || exit.ExitCode() != 17 {
		t.Fatalf("real exit lost: %v %v", waitErr, cleanupErr)
	}
}

func TestRetainedFinalSweepWaitsForTerminalAfterAbort(t *testing.T) {
	entered, pending, terminal := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var child *Child
	calls, kills := 0, 0
	child = newChild(123, 1, operations{
		observe: func(int, int) (bool, error) {
			calls++
			if calls == 1 {
				close(entered)
				<-pending
				return false, nil
			}
			<-terminal
			return true, nil
		},
		kill: func(int) error {
			kills++
			if kills > 1 && !child.terminal {
				t.Error("final sweep preceded retained terminal")
			}
			return nil
		},
		wait:   func() error { return nil },
		absent: func(int, time.Duration) error { return nil },
	})
	close(child.watchDone)
	go child.observe()
	<-entered
	_ = child.Abort()
	done := make(chan error, 1)
	go func() { _, err := child.Finish(time.Second); done <- err }()
	// Force Finish to start while observation is still pending.
	for {
		child.mu.Lock()
		finishing := child.finished
		child.mu.Unlock()
		if finishing {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(pending)
	close(terminal)
	if err := <-done; err != nil || kills != 2 {
		t.Fatalf("final sweep: %v %d", err, kills)
	}
}

func TestRetainedNativePendingStoppedContinued(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	child, err := Start(ctx, exec.Command("/bin/sleep", "2"))
	if err != nil {
		t.Fatal(err)
	}
	joined := false
	t.Cleanup(func() {
		if !joined {
			_ = child.Abort()
			_, _ = child.Finish(time.Second)
		}
	})
	signalOwned := func(signal syscall.Signal) {
		child.mu.Lock()
		defer child.mu.Unlock()
		if child.sealed {
			t.Fatal("test lost retained identity")
		}
		if err := syscall.Kill(child.pid, signal); err != nil {
			t.Fatal(err)
		}
	}
	signalOwned(syscall.SIGSTOP)
	deadline := time.Now().Add(time.Second)
	for {
		stopped, err := ownedStopped(child.pid)
		if err != nil {
			t.Fatal(err)
		}
		if stopped {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned child did not stop")
		}
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 3; i++ {
		terminal, err := observeTerminal(child.pid, child.parent)
		if terminal || err != nil {
			t.Fatalf("stopped admitted terminal: %v %v", terminal, err)
		}
	}
	signalOwned(syscall.SIGCONT)
	terminal, err := observeTerminal(child.pid, child.parent)
	if terminal || err != nil {
		t.Fatalf("continued admitted terminal: %v %v", terminal, err)
	}
	_ = child.Abort()
	waitErr, cleanupErr := child.Finish(time.Second)
	joined = true
	if waitErr == nil || cleanupErr != nil {
		t.Fatalf("native abort/join: %v %v", waitErr, cleanupErr)
	}
}

func TestRetainedRejectsCanceledAndHiddenCopiersBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	command := exec.Command("/bin/sh", "-c", "exit 0")
	if _, err := Start(ctx, command); !errors.Is(err, context.Canceled) || command.Process != nil {
		t.Fatalf("canceled Start: %v", err)
	}
	command = exec.Command("/bin/sh", "-c", "exit 0")
	command.Stdin = strings.NewReader("hidden copier")
	if _, err := Start(t.Context(), command); err == nil || command.Process != nil {
		t.Fatal("hidden copier admitted")
	}
	command = exec.CommandContext(t.Context(), "/bin/sh", "-c", "exit 0")
	if _, err := Start(t.Context(), command); err == nil || command.Process != nil {
		t.Fatal("context watcher admitted")
	}
}
