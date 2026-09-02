//go:build darwin || linux

package repositorysnapshot

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCaptureContextTerminatesGitProcessGroupOnOutputOverflow(t *testing.T) {
	bin := t.TempDir()
	gitPath := filepath.Join(bin, "git")
	processGroupPath := filepath.Join(t.TempDir(), "process-group")
	script := "#!/bin/sh\n/bin/sleep 30 &\nprintf '%s\\n' \"$$\" > \"$PROOFKIT_TEST_PROCESS_GROUP\"\n/bin/dd if=/dev/zero bs=17825792 count=1 1>&2\nwait\n"
	if err := os.WriteFile(gitPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("PROOFKIT_TEST_PROCESS_GROUP", processGroupPath)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if _, err := CaptureContext(ctx, t.TempDir()); err == nil || !strings.Contains(err.Error(), "output exceeds resource limit") {
		t.Fatalf("CaptureContext() error = %v, want output-limit rejection", err)
	}
	processGroupBytes, err := os.ReadFile(processGroupPath)
	if err != nil {
		t.Fatalf("read process-group oracle: %v", err)
	}
	processGroupID, err := strconv.Atoi(strings.TrimSpace(string(processGroupBytes)))
	if err != nil || processGroupID <= 0 {
		t.Fatalf("invalid process-group oracle %q", processGroupBytes)
	}
	if err := syscall.Kill(-processGroupID, syscall.Signal(0)); !errors.Is(err, syscall.ESRCH) {
		_ = syscall.Kill(-processGroupID, syscall.SIGKILL)
		t.Fatalf("git process group %d survived output-limit termination: %v", processGroupID, err)
	}
}
