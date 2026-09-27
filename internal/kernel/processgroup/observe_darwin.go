package processgroup

import (
	"errors"

	"golang.org/x/sys/unix"
)

func observeTerminal(pid, parent int) (bool, error) {
	for attempt := 0; attempt < 3; attempt++ {
		record, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return classifyDarwin(record, err, pid, parent)
	}
	return false, unix.EINTR
}

func classifyDarwin(record *unix.KinfoProc, err error, pid, parent int) (bool, error) {
	// The pinned wrapper rejects short records with EIO before returning one.
	if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ECHILD) {
		return false, errors.Join(ErrOwnershipLost, err)
	}
	if err != nil {
		return false, err
	}
	if record == nil {
		return false, errors.New("missing retained child record")
	}
	if int(record.Proc.P_pid) != pid || int(record.Eproc.Ppid) != parent || int(record.Eproc.Pgid) != pid {
		return false, ErrOwnershipLost
	}
	const zombie = 5 // XNU SZOMB; stopped (4) is not terminal.
	if record.Proc.P_stat <= 0 || record.Proc.P_stat > 6 {
		return false, errors.New("invalid retained child state")
	}
	return record.Proc.P_stat == zombie, nil
}
