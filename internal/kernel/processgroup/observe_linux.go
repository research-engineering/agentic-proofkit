package processgroup

import (
	"errors"

	"golang.org/x/sys/unix"
)

func observeTerminal(pid, _ int) (bool, error) {
	for attempt := 0; attempt < 3; attempt++ {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return classifyLinux(info, err)
	}
	return false, unix.EINTR
}

func classifyLinux(info unix.Siginfo, err error) (bool, error) {
	if errors.Is(err, unix.ECHILD) {
		return false, errors.Join(ErrOwnershipLost, err)
	}
	if err != nil {
		return false, err
	}
	if info.Errno != 0 {
		return false, unix.Errno(info.Errno)
	}
	if info.Signo == 0 && info.Code == 0 {
		return false, nil
	}
	// CLD_EXITED, CLD_KILLED, CLD_DUMPED only. No unsafe siginfo union overlay.
	if info.Signo != int32(unix.SIGCHLD) || info.Code < 1 || info.Code > 3 {
		return false, errors.New("unexpected retained child waitid event")
	}
	return true, nil
}
