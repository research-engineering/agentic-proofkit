package processgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
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

func TestDarwinRecordSliceSeparatesAbsenceFromShortRecords(t *testing.T) {
	running := unix.KinfoProc{}
	running.Proc.P_pid, running.Eproc.Ppid, running.Eproc.Pgid, running.Proc.P_stat = 123, 1, 123, 2
	partial := fmt.Errorf("sysctl() returned a size of 12, which is not a multiple of %d", unix.SizeofKinfoProc)
	for _, test := range []struct {
		name          string
		records       []unix.KinfoProc
		err           error
		lost, failure bool
	}{
		{name: "nil_absent", lost: true, failure: true},
		{name: "empty_absent", records: []unix.KinfoProc{}, lost: true, failure: true},
		{name: "one_running", records: []unix.KinfoProc{running}},
		{name: "two_records", records: []unix.KinfoProc{running, running}, failure: true},
		{name: "partial_record", err: partial, failure: true},
		{name: "wrapper_eio", err: unix.EIO, failure: true},
		{name: "permission", err: unix.EPERM, failure: true},
		{name: "no_process", err: unix.ESRCH, lost: true, failure: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			terminal, err := classifyDarwinRecords(test.records, test.err, 123, 1)
			if terminal || (err != nil) != test.failure || errors.Is(err, ErrOwnershipLost) != test.lost {
				t.Fatalf("classification: %v %v", terminal, err)
			}
			if test.lost && test.err == nil && !errors.Is(err, errRecordAbsent) {
				t.Fatalf("absence lost its cause: %v", err)
			}
		})
	}
}

// The production Darwin classifier drives the production lifecycle with fake
// signal, reap and probe operations, so no syscall reaches a reaped identity.
// Absence fails closed without numeric targeting; truncation and permission
// errors keep retained cleanup because the unreaped child still pins its IDs.
func TestDarwinObservationOutcomesDriveRetainedCleanup(t *testing.T) {
	partial := fmt.Errorf("sysctl() returned a size of 12, which is not a multiple of %d", unix.SizeofKinfoProc)
	for _, test := range []struct {
		name    string
		records []unix.KinfoProc
		err     error
		lost    bool
	}{
		{name: "absent_after_foreign_reap", lost: true},
		{name: "no_process", err: unix.ESRCH, lost: true},
		{name: "truncated_record", err: partial},
		{name: "permission_denied", err: unix.EPERM},
		{name: "kernel_eio", err: unix.EIO},
	} {
		t.Run(test.name, func(t *testing.T) {
			kills, waits, probes := 0, 0, 0
			child := newChild(123, 1, operations{
				observe: func(pid, parent int) (bool, error) {
					return classifyDarwinRecords(test.records, test.err, pid, parent)
				},
				kill: func(pid int) error {
					if pid != 123 {
						t.Errorf("signal targeted %d", pid)
					}
					kills++
					return nil
				},
				wait:   func() error { waits++; return nil },
				absent: func(int, time.Duration) error { probes++; return nil },
			})
			close(child.watchDone)
			go child.observe()
			<-child.Aborted()
			_, err := child.Finish(time.Second)
			if test.lost {
				if !errors.Is(err, ErrOwnershipLost) || !strings.Contains(err.Error(), "child cleanup unverified") || kills != 0 || waits != 0 || probes != 0 {
					t.Fatalf("lost ownership: err=%v kills=%d waits=%d probes=%d", err, kills, waits, probes)
				}
				return
			}
			if errors.Is(err, ErrOwnershipLost) || !errors.Is(err, test.err) || kills != 2 || waits != 1 || probes != 1 {
				t.Fatalf("retained cleanup: err=%v kills=%d waits=%d probes=%d", err, kills, waits, probes)
			}
		})
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
