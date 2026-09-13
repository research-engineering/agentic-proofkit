//go:build darwin || linux

// Package processgroup owns bounded external-process group termination.
package processgroup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const processGroupProbeInterval = 10 * time.Millisecond

// Configure places a command in a new process group and makes context
// cancellation terminate that group.
func Configure(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return Terminate(command) }
}

// Terminate kills the configured command process group. A process that has
// already exited satisfies the termination obligation.
func Terminate(command *exec.Cmd) error {
	if command.Process == nil {
		return nil
	}
	err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

// TerminateAndWait kills a configured process group after the command parent
// has been reaped and proves group absence before returning success.
func TerminateAndWait(command *exec.Cmd, timeout time.Duration) error {
	if command.Process == nil {
		return nil
	}
	return terminateAndWait(command.Process.Pid, timeout, syscall.Kill)
}

func terminateAndWait(processGroupID int, timeout time.Duration, signal func(int, syscall.Signal) error) error {
	if timeout <= 0 {
		return fmt.Errorf("process-group cleanup timeout must be positive")
	}
	deadline := time.Now().Add(timeout)
	terminationErr := signal(-processGroupID, syscall.SIGKILL)
	if errors.Is(terminationErr, syscall.ESRCH) {
		return nil
	}
	// Darwin can return EPERM for a zombie-only group. Only observed absence,
	// not that ambiguous signal result, satisfies the cleanup obligation.
	if terminationErr != nil && !errors.Is(terminationErr, syscall.EPERM) {
		return terminationErr
	}
	for {
		err := signal(-processGroupID, syscall.Signal(0))
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil && !errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("probe process group %d: %w", processGroupID, err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.Join(fmt.Errorf("process group %d remained present after cleanup timeout", processGroupID), terminationErr)
		}
		if remaining > processGroupProbeInterval {
			remaining = processGroupProbeInterval
		}
		time.Sleep(remaining)
	}
}
