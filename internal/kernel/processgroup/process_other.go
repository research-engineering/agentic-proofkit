//go:build !darwin && !linux

// Package processgroup owns bounded external-process group termination.
package processgroup

import (
	"errors"
	"os"
	"os/exec"
	"time"
)

// Configure retains exec.CommandContext's direct-process cancellation on
// platforms where this package has no process-group primitive.
func Configure(command *exec.Cmd) {}

// Terminate kills the direct child on platforms without a process-group
// primitive.
func Terminate(command *exec.Cmd) error {
	if command.Process == nil {
		return nil
	}
	err := command.Process.Kill()
	if errors.Is(err, os.ErrProcessDone) {
		return nil
	}
	return err
}

// TerminateAndWait terminates the direct child. The caller invokes it after
// exec.Cmd.Run has already waited for that child on unsupported platforms.
func TerminateAndWait(command *exec.Cmd, _ time.Duration) error {
	return Terminate(command)
}
