//go:build darwin || linux

package processgroup

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

func configure(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return nil
}

func killGroup(pid int) error         { return syscall.Kill(-pid, syscall.SIGKILL) }
func absentSignal(err error) bool     { return errors.Is(err, syscall.ESRCH) }
func permissionSignal(err error) bool { return errors.Is(err, syscall.EPERM) }
func waitAbsent(pid int, timeout time.Duration) error {
	return probeAbsent(pid, timeout, syscall.Kill)
}

// After seal only signal 0 is permitted. Pre-reap ESRCH is not this witness.
func probeAbsent(pid int, timeout time.Duration, signal func(int, syscall.Signal) error) error {
	if timeout <= 0 {
		return fmt.Errorf("process-group cleanup timeout must be positive")
	}
	deadline := time.Now().Add(timeout)
	for {
		err := signal(-pid, 0)
		if absentSignal(err) {
			return nil
		}
		if err != nil && !permissionSignal(err) {
			return fmt.Errorf("probe process group: %w", err)
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.Join(errors.New("process group remained present after cleanup timeout"), err)
		}
		if remaining > observeInterval {
			remaining = observeInterval
		}
		time.Sleep(remaining)
	}
}
