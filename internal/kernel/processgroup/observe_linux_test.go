package processgroup

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func ownedStopped(pid int) (bool, error) {
	var info unix.Siginfo
	err := unix.Waitid(unix.P_PID, pid, &info, unix.WSTOPPED|unix.WNOWAIT|unix.WNOHANG, nil)
	return err == nil && info.Signo == int32(unix.SIGCHLD) && info.Code == 5, err
}

func TestLinuxObservationClassification(t *testing.T) {
	for _, test := range []struct {
		name                    string
		info                    unix.Siginfo
		err                     error
		terminal, failure, lost bool
	}{
		{name: "pending"},
		{name: "exited", info: unix.Siginfo{Signo: int32(unix.SIGCHLD), Code: 1}, terminal: true},
		{name: "killed", info: unix.Siginfo{Signo: int32(unix.SIGCHLD), Code: 2}, terminal: true},
		{name: "dumped", info: unix.Siginfo{Signo: int32(unix.SIGCHLD), Code: 3}, terminal: true},
		{name: "stopped", info: unix.Siginfo{Signo: int32(unix.SIGCHLD), Code: 5}, failure: true},
		{name: "continued", info: unix.Siginfo{Signo: int32(unix.SIGCHLD), Code: 6}, failure: true},
		{name: "signal", info: unix.Siginfo{Signo: int32(unix.SIGTERM), Code: 1}, failure: true},
		{name: "errno", info: unix.Siginfo{Errno: int32(unix.EIO)}, failure: true},
		{name: "permission", err: unix.EPERM, failure: true},
		{name: "unavailable", err: unix.ENOSYS, failure: true},
		{name: "lost", err: unix.ECHILD, failure: true, lost: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			terminal, err := classifyLinux(test.info, test.err)
			if terminal != test.terminal || (err != nil) != test.failure || errors.Is(err, ErrOwnershipLost) != test.lost {
				t.Fatalf("classification: %v %v", terminal, err)
			}
		})
	}
}
