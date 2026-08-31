//go:build darwin || linux

package workflowsmoke_test

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/research-engineering/agentic-proofkit/internal/tools/workflowsmoke"
)

func TestRunProcessTerminatesDescendantsAfterSuccessfulParentExit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, err := workflowsmoke.RunProcess(ctx, helperCarrier("spawn-descendant"), workflowsmoke.Invocation{StdinClass: workflowsmoke.StdinBytes})
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(result.Stdout)))
	if err != nil {
		t.Fatalf("decode descendant PID: %v", err)
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Kill() })
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := process.Signal(syscall.Signal(0))
		if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil {
			t.Fatalf("probe descendant process: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("descendant process %d remained alive after successful carrier return", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
