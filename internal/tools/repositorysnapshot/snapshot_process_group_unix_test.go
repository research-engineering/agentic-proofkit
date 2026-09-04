//go:build darwin || linux

package repositorysnapshot

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testCaptureContextTerminatesGitProcessGroupOnOutputOverflow(t *testing.T) {
	if os.Getenv("PROOFKIT_TEST_PROCESS_GROUP_MODE") == "lock-holder" {
		holdProcessGroupOracleLock(t)
		return
	}

	bin := t.TempDir()
	gitPath := filepath.Join(bin, "git")
	oracleDir := t.TempDir()
	lockPath := filepath.Join(oracleDir, "descendant.lock")
	readyPath := filepath.Join(oracleDir, "descendant.ready")
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n\"$PROOFKIT_TEST_BINARY\" -test.run '^TestCaptureContextTerminatesGitProcessGroupOnOutputOverflow$' &\nwhile [ ! -f \"$PROOFKIT_TEST_PROCESS_GROUP_READY\" ]; do /bin/sleep 0.01; done\n/bin/dd if=/dev/zero bs=17825792 count=1 1>&2\nwait\n"
	if err := os.WriteFile(gitPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("PROOFKIT_TEST_BINARY", testBinary)
	t.Setenv("PROOFKIT_TEST_PROCESS_GROUP_MODE", "lock-holder")
	t.Setenv("PROOFKIT_TEST_PROCESS_GROUP_LOCK", lockPath)
	t.Setenv("PROOFKIT_TEST_PROCESS_GROUP_READY", readyPath)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := CaptureContext(ctx, t.TempDir()); err == nil || !strings.Contains(err.Error(), "output exceeds resource limit") {
		t.Fatalf("CaptureContext() error = %v, want output-limit rejection", err)
	}
	lockFile, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open process-group oracle lock: %v", err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("descendant retained process-group oracle lock after output-limit termination: %v", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatalf("release process-group oracle lock: %v", err)
	}
}

func holdProcessGroupOracleLock(t *testing.T) {
	lockFile, err := os.OpenFile(os.Getenv("PROOFKIT_TEST_PROCESS_GROUP_LOCK"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("PROOFKIT_TEST_PROCESS_GROUP_READY"), []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {}
}
