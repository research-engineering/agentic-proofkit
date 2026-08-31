//go:build darwin || linux

package processgroup

import (
	"bytes"
	"context"
	"os/exec"
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
