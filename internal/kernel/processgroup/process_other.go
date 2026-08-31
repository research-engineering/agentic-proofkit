//go:build !darwin && !linux

// Package processgroup owns bounded external-process group termination.
package processgroup

import (
	"errors"
	"os"
	"os/exec"
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
