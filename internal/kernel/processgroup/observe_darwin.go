package processgroup

import (
	"errors"

	"golang.org/x/sys/unix"
)

// errRecordAbsent distinguishes a zero-length kern.proc.pid answer from a
// short record. SysctlKinfoProc reports both as EIO.
var errRecordAbsent = errors.New("retained child record absent")

func observeTerminal(pid, parent int) (bool, error) {
	for attempt := 0; attempt < 3; attempt++ {
		records, err := unix.SysctlKinfoProcSlice("kern.proc.pid", pid)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return classifyDarwinRecords(records, err, pid, parent)
	}
	return false, unix.EINTR
}

// An unreaped retained child always has a record. A zero-length answer means a
// foreign waiter reaped it, so its numeric identity may already be reused.
func classifyDarwinRecords(records []unix.KinfoProc, err error, pid, parent int) (bool, error) {
	if err != nil {
		return classifyDarwin(nil, err, pid, parent)
	}
	switch len(records) {
	case 0:
		return false, errors.Join(ErrOwnershipLost, errRecordAbsent)
	case 1:
		return classifyDarwin(&records[0], nil, pid, parent)
	default:
		return false, errors.New("ambiguous retained child record")
	}
}

func classifyDarwin(record *unix.KinfoProc, err error, pid, parent int) (bool, error) {
	// A partial-record size error stays ordinary: some record exists, so the
	// unreaped child still pins its identity and retained cleanup applies.
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
