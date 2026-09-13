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
)

func TestTerminateAndWaitAllowsZombieGroupToDisappear(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer output.Close()
	leader := exec.CommandContext(ctx, "/bin/cat")
	leader.Stdin = input
	Configure(leader)
	if err := leader.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if leader.ProcessState == nil {
			_ = leader.Process.Kill()
			_ = leader.Wait()
		}
	})
	member := exec.Command("/bin/sh", "-c", "exit 0")
	member.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: leader.Process.Pid}
	if err := member.Start(); err != nil {
		t.Fatal(err)
	}
	reap := make(chan struct{})
	reaped := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(reap) }) }
	go func() {
		<-reap
		_ = member.Wait()
		close(reaped)
	}()
	t.Cleanup(func() {
		_ = member.Process.Kill()
		release()
		<-reaped
	})
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
	if err := leader.Wait(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for !errors.Is(syscall.Kill(-leader.Process.Pid, 0), syscall.EPERM) {
		if time.Now().After(deadline) {
			t.Fatal("owned zombie-only group did not reach Darwin EPERM state")
		}
		time.Sleep(time.Millisecond)
	}
	// Keep the exited member unreaped until cleanup has an opportunity to wait.
	timer := time.AfterFunc(30*time.Millisecond, release)
	defer timer.Stop()
	if err := TerminateAndWait(leader, time.Second); err != nil {
		t.Fatalf("group disappeared within the cleanup budget: %v", err)
	}
	if err := syscall.Kill(-leader.Process.Pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("cleanup returned without proving absence: %v", err)
	}
}
