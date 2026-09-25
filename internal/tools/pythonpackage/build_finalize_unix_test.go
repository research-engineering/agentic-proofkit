//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestWriteWheelRejectsFilesystemFinalizeFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWheelFilesystemFailureChild$")
	command.Env = append(os.Environ(), "PROOFKIT_WHEEL_FAILURE_CHILD=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("filesystem finalization regression: %v\n%s", err, output)
	}
}

func TestWheelFilesystemFailureChild(t *testing.T) {
	if os.Getenv("PROOFKIT_WHEEL_FAILURE_CHILD") == "" {
		return
	}
	oldMask := syscall.Umask(0o077)
	defer syscall.Umask(oldMask)
	root := t.TempDir()
	privatePath := filepath.Join(root, "private.whl")
	if err := writeWheel(privatePath, nil); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(privatePath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("wheel creation did not preserve restrictive umask: info=%v error=%v", info, err)
	}
	previousPath := filepath.Join(root, "previous.whl")
	if err := os.WriteFile(previousPath, []byte("previous"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"python/agentic_proofkit/__init__.py",
		"python/agentic_proofkit/__main__.py",
		"python/agentic_proofkit/cli.py",
		sourceCLIContractPath, licenseFilename, "binary",
	} {
		absolute := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, []byte("fixture"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	signal.Ignore(syscall.SIGXFSZ)
	defer signal.Reset(syscall.SIGXFSZ)
	limit := old
	limit.Cur = 0
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
			t.Error(err)
		}
	}()
	for _, path := range []string{previousPath, filepath.Join(root, "absent.whl")} {
		if err := writeWheel(path, nil); !errors.Is(err, syscall.EFBIG) {
			t.Fatalf("ZIP central-directory write failure not returned: %v", err)
		}
	}
	content, err := os.ReadFile(previousPath)
	if err != nil || string(content) != "previous" {
		t.Fatalf("previous output changed: %q %v", content, err)
	}
	if _, err := os.Stat(filepath.Join(root, "absent.whl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed wheel remains: %v", err)
	}
	withWorkingDirectory(t, root, func() {
		platform := releaseTargets()[0]
		platform.BinaryPath = "binary"
		record, err := buildWheel(root, testPackageManifest("1.2.3"), platform)
		if !errors.Is(err, syscall.EFBIG) || record != (wheelRecord{}) {
			t.Fatalf("buildWheel emitted success or lost write failure: record=%+v error=%v", record, err)
		}
		if _, err := os.Stat(filepath.Join(root, wheelFilename("1.2.3", platform))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("buildWheel left failed output: %v", err)
		}
	})
	assertNoWheelTemporaryFiles(t, root)
}
