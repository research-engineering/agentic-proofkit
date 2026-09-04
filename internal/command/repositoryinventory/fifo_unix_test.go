//go:build darwin || linux

package repositoryinventory

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const fifoHelperEnvironment = "PROOFKIT_REPOSITORY_INVENTORY_FIFO_HELPER"

func TestScanRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	if os.Getenv(fifoHelperEnvironment) == "1" {
		runFIFOReplacementHelper(t)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestScanRejectsFIFOReplacementWithoutBlocking$")
	command.Env = append(os.Environ(), fifoHelperEnvironment+"=1")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("FIFO replacement was not rejected within the bounded subprocess lifetime: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("FIFO replacement helper failed: %v\n%s", err, output)
	}
}

func runFIFOReplacementHelper(t *testing.T) {
	t.Helper()
	rootPath := t.TempDir()
	path := filepath.Join(rootPath, "README.md")
	if err := os.WriteFile(path, []byte("regular\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	info, err := root.Lstat("README.md")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	value := candidate{info: info, item: catalogItem{Path: "README.md", Role: "human_overview"}}
	if _, err := readCandidate(root, value, MaximumFileBytes, MaximumAggregateBytes); err == nil || !strings.Contains(err.Error(), "recognized repository entry") {
		t.Fatalf("readCandidate() error = %v, want non-regular replacement rejection", err)
	}
}
