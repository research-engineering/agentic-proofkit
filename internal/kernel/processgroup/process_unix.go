//go:build darwin || linux

// Package processgroup owns bounded external-process group termination.
package processgroup

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

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
