//go:build darwin || linux

package processgroup

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestConfigureTerminatesDescendantOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", "/bin/sleep 2 & wait")
	Configure(command)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	started := time.Now()
	if err := command.Run(); err == nil {
		t.Fatal("canceled process group returned success")
	}
	if elapsed := time.Since(started); elapsed >= time.Second {
		t.Fatalf("process group termination took %s", elapsed)
	}
}

func TestTerminateBeforeStartIsSatisfied(t *testing.T) {
	if err := Terminate(exec.Command("unused")); err != nil {
		t.Fatalf("Terminate before start: %v", err)
	}
}

func TestTerminateAndWaitRequiresObservedAbsence(t *testing.T) {
	cases := []struct {
		name   string
		states []error
	}{
		{name: "already absent", states: []error{syscall.ESRCH}},
		{name: "signal then absent", states: []error{nil, syscall.ESRCH}},
		{name: "permission then absent", states: []error{syscall.EPERM, syscall.ESRCH}},
		{name: "permission then zombie then absent", states: []error{syscall.EPERM, syscall.EPERM, syscall.ESRCH}},
		{name: "permission then present then absent", states: []error{syscall.EPERM, nil, syscall.ESRCH}},
		{name: "signal then present then absent", states: []error{nil, nil, syscall.ESRCH}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			signal := func(pid int, sig syscall.Signal) error {
				t.Helper()
				wantSignal := syscall.Signal(0)
				if calls == 0 {
					wantSignal = syscall.SIGKILL
				}
				if pid != -123 || sig != wantSignal || calls >= len(test.states) {
					t.Fatalf("unexpected signal call: pid=%d signal=%v call=%d", pid, sig, calls)
				}
				state := test.states[calls]
				calls++
				return state
			}
			if err := terminateAndWait(123, time.Second, signal); err != nil {
				t.Fatal(err)
			}
			if calls != len(test.states) {
				t.Fatalf("returned before observed absence: calls=%d, want %d", calls, len(test.states))
			}
		})
	}
}

func TestTerminateAndWaitPreservesFailureAndDeadline(t *testing.T) {
	for _, test := range []struct {
		name      string
		terminate error
		probe     error
		want      error
		timeout   bool
	}{
		{name: "permanent permission", terminate: syscall.EPERM, probe: syscall.EPERM, want: syscall.EPERM, timeout: true},
		{name: "group remains present", timeout: true},
		{name: "signal failure", terminate: syscall.EIO, want: syscall.EIO},
		{name: "probe failure", probe: syscall.EIO, want: syscall.EIO},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := terminateAndWait(123, time.Millisecond, func(pid int, sig syscall.Signal) error {
				if pid != -123 {
					t.Fatalf("unexpected process group: %d", pid)
				}
				if sig == syscall.SIGKILL {
					return test.terminate
				}
				return test.probe
			})
			if err == nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("cleanup failure=%v, want %v", err, test.want)
			}
			if test.timeout && !strings.Contains(err.Error(), "cleanup timeout") {
				t.Fatalf("missing bounded timeout result: %v", err)
			}
		})
	}
	for _, timeout := range []time.Duration{0, -time.Second} {
		if err := terminateAndWait(123, timeout, func(int, syscall.Signal) error {
			t.Fatal("invalid cleanup budget signalled a process group")
			return nil
		}); err == nil {
			t.Fatal("invalid cleanup budget was accepted")
		}
	}
}
