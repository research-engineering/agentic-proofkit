//go:build !darwin && !linux

package processgroup

import (
	"errors"
	"os/exec"
	"time"
)

var errUnsupported = errors.New("retained process observation requires a qualified Darwin or Linux source host")

func configure(*exec.Cmd) error              { return errUnsupported }
func observeTerminal(int, int) (bool, error) { return false, errUnsupported }
func killGroup(int) error                    { return errUnsupported }
func absentSignal(error) bool                { return false }
func permissionSignal(error) bool            { return false }
func waitAbsent(int, time.Duration) error    { return errUnsupported }
