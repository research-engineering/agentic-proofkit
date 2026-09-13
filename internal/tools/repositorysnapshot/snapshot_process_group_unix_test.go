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

func TestGitOutputTerminatesGroupAfterParentExit(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_COUNT", "0")
	for _, test := range []struct {
		name    string
		fail    bool
		control string
	}{
		{name: "success"},
		{name: "signaled parent", fail: true, control: "kill -TERM \"$PPID\"\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := initializeRepository(t)
			writeFile(t, filepath.Join(root, "tracked.txt"), "synthetic\n")
			runGit(t, root, "add", "tracked.txt")
			control := t.TempDir()
			pidPath := filepath.Join(control, "child.pid")
			hook := filepath.Join(control, "fsmonitor")
			t.Setenv("PROOFKIT_TEST_GIT_CHILD_PID", pidPath)
			script := "#!/bin/sh\n/bin/sleep 30 </dev/null >/dev/null 2>&1 &\nprintf '%s' \"$!\" > \"$PROOFKIT_TEST_GIT_CHILD_PID\"\nprintf 'token\\0'\n" + test.control
			if err := os.WriteFile(hook, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			childAbsent := false
			t.Cleanup(func() {
				if childAbsent {
					return
				}
				if data, err := os.ReadFile(pidPath); err == nil {
					if pid, err := strconv.Atoi(string(data)); err == nil && pid > 1 {
						_ = syscall.Kill(pid, syscall.SIGKILL)
					}
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			output, err := gitOutput(ctx, root, "-c", "core.fsmonitor="+hook, "-c", "core.fsmonitorHookVersion=2", "status", "--porcelain=v1")
			if (err != nil) != test.fail {
				t.Fatalf("Git result=%q error=%v, want failure=%v", output, err, test.fail)
			}
			if !test.fail && output != "A  tracked.txt\n" {
				t.Fatalf("Git stdout changed: %q", output)
			}
			if test.fail && (!strings.Contains(err.Error(), " failed") || strings.Contains(err.Error(), "cleanup")) {
				t.Fatalf("Git failure was replaced by a cleanup failure: %v", err)
			}
			data, err := os.ReadFile(pidPath)
			if err != nil {
				t.Fatalf("native Git fsmonitor did not record a child: %v", err)
			}
			pid, err := strconv.Atoi(string(data))
			if err != nil || pid <= 1 {
				t.Fatal("invalid owned child identity")
			}
			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("native Git left its child after terminal return: %v", err)
			}
			childAbsent = true
		})
	}
}

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
