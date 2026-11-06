//go:build darwin || linux

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestBuildInputRejectsNPMArchiveFIFOWithoutBlocking(t *testing.T) {
	if args := os.Args; len(args) >= 3 && args[len(args)-2] == "fifo-fixture" {
		input, err := buildInput(args[len(args)-1])
		if err != nil {
			t.Fatal(err)
		}
		assertCriterionStatus(t, input, "proofkit.release_closeout.package_artifacts", "missing_evidence")
		assertCriterionStatus(t, input, "proofkit.release_closeout.manifest_and_sbom", "missing_evidence")
		assertCloseoutOutcome(t, input, 1, "failed")
		return
	}
	root := completeFixture(t)
	path := filepath.Join(root, "artifacts", "package", testNPMTarballName)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBuildInputRejectsNPMArchiveFIFOWithoutBlocking$", "--", "fifo-fixture", root)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("buildInput FIFO subprocess: %v (context: %v)\n%s", err, ctx.Err(), out)
	}
}
