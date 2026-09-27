package processgroup

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func ownedStopped(pid int) (bool, error) {
	record, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	return err == nil && record != nil && record.Proc.P_stat == 4, err
}

func TestDarwinObservationClassification(t *testing.T) {
	valid := unix.KinfoProc{}
	valid.Proc.P_pid, valid.Eproc.Ppid, valid.Eproc.Pgid, valid.Proc.P_stat = 123, 1, 123, 5
	for _, test := range []struct {
		name           string
		change         func(*unix.KinfoProc)
		err            error
		terminal, lost bool
	}{
		{name: "zombie", terminal: true},
		{name: "stopped", change: func(r *unix.KinfoProc) { r.Proc.P_stat = 4 }},
		{name: "running", change: func(r *unix.KinfoProc) { r.Proc.P_stat = 2 }},
		{name: "pid", change: func(r *unix.KinfoProc) { r.Proc.P_pid++ }, lost: true},
		{name: "parent", change: func(r *unix.KinfoProc) { r.Eproc.Ppid++ }, lost: true},
		{name: "group", change: func(r *unix.KinfoProc) { r.Eproc.Pgid++ }, lost: true},
		{name: "short_record", err: unix.EIO}, {name: "permission", err: unix.EPERM},
		{name: "missing_child", err: unix.ECHILD, lost: true}, {name: "no_process", err: unix.ESRCH, lost: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := valid
			if test.change != nil {
				test.change(&r)
			}
			terminal, err := classifyDarwin(&r, test.err, 123, 1)
			if terminal != test.terminal || errors.Is(err, ErrOwnershipLost) != test.lost || test.err != nil && err == nil {
				t.Fatalf("classification: %v %v", terminal, err)
			}
		})
	}
	if terminal, err := classifyDarwin(nil, nil, 123, 1); terminal || err == nil {
		t.Fatal("empty record admitted")
	}
}

func TestRetainedDarwinZombiePermissionThenReapAbsence(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	leader := exec.Command("/bin/cat")
	leader.Stdin = input
	child, err := Start(ctx, leader)
	if err != nil {
		t.Fatal(err)
	}
	finished := false
	var releaseOnce sync.Once
	reapMember, memberDone := make(chan struct{}), make(chan error, 1)
	memberStarted := false
	release := func() { releaseOnce.Do(func() { close(reapMember) }) }
	t.Cleanup(func() {
		_ = writer.Close()
		release()
		if memberStarted {
			if err := <-memberDone; err != nil {
				t.Error(err)
			}
		}
		if !finished {
			_ = child.Abort()
			_, _ = child.Finish(time.Second)
		}
	})
	member := exec.Command("/bin/sh", "-c", "exit 0")
	member.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: child.pid}
	if err := member.Start(); err != nil {
		t.Fatal(err)
	}
	memberStarted = true
	go func() { <-reapMember; memberDone <- member.Wait() }()
	deadline := time.Now().Add(time.Second)
	for {
		record, err := unix.SysctlKinfoProc("kern.proc.pid", member.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		if record != nil && record.Proc.P_pid == int32(member.Process.Pid) && record.Eproc.Ppid == int32(os.Getpid()) && record.Eproc.Pgid == int32(child.pid) && record.Proc.P_stat == 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owned member did not become a retained zombie")
		}
		time.Sleep(time.Millisecond)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-child.Terminal():
	case <-child.Aborted():
		t.Fatal("leader did not reach ordinary terminal")
	}
	// Keep the member unreaped through the leader's sole Wait, so a real
	// post-reap EPERM cannot masquerade as absence. Only probes follow seal.
	child.ops.absent = func(pid int, timeout time.Duration) error {
		permission := unix.Kill(-pid, 0)
		if !errors.Is(permission, unix.EPERM) {
			t.Errorf("owned zombie-only group: %v, want EPERM", permission)
		}
		release()
		if err := <-memberDone; err != nil {
			t.Error(err)
		}
		memberStarted = false
		return waitAbsent(pid, timeout)
	}
	waitErr, cleanupErr := child.Finish(time.Second)
	finished = true
	if waitErr != nil || cleanupErr != nil {
		t.Fatalf("zombie cleanup: %v %v", waitErr, cleanupErr)
	}
	if err := unix.Kill(-child.pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("absence was not established: %v", err)
	}
}
