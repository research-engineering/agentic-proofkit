package childcoverage

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestEnvironmentPreservesExplicitScopeAndIsolatesCoverage(t *testing.T) {
	base := []string{"A=one", "GOCOVERDIR=unowned", "B=two", "GOCOVERDIR=second"}
	before := slices.Clone(base)
	first, second := Environment(t, base), Environment(t, base)
	if !slices.Equal(base, before) || len(first) != 3 || !slices.Equal(first[:2], []string{"A=one", "B=two"}) || first[2] == second[2] {
		t.Fatal("environment scope or coverage ownership changed")
	}
	if empty := Environment(t, nil); len(empty) != 1 || !strings.HasPrefix(empty[0], "GOCOVERDIR=") {
		t.Fatal("nil environment imported ambient values")
	}
	directory := strings.TrimPrefix(first[2], "GOCOVERDIR=")
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		t.Fatalf("owned coverage directory unavailable: %v", err)
	}
}

func TestInstrumentedChildKeepsExactOutput(t *testing.T) {
	if os.Getenv("PROOFKIT_COVERAGE_CHILD") == "1" {
		_, _ = os.Stdout.Write([]byte("child-output\n"))
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInstrumentedChildKeepsExactOutput$")
	child.Env = Environment(t, []string{"PROOFKIT_COVERAGE_CHILD=1"})
	child.WaitDelay = time.Second
	var stdout, stderr bytes.Buffer
	child.Stdout, child.Stderr = &stdout, &stderr
	if err := child.Run(); err != nil || stdout.String() != "child-output\n" || stderr.Len() != 0 {
		t.Fatalf("instrumented child protocol changed: %v stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
}
