package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPOSIXWrapperExecPreservesProcessIdentityAndSignals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX exec lifecycle is not applicable on Windows")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 unavailable: %v", err)
	}
	root := t.TempDir()
	packageRoot := filepath.Join(root, "agentic_proofkit")
	if err := os.MkdirAll(filepath.Join(packageRoot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	copyFixtureFile(t, filepath.Join("..", "..", "..", "python", "agentic_proofkit", "cli.py"), filepath.Join(packageRoot, "cli.py"))
	copyFixtureFile(t, filepath.Join("..", "..", "..", "python", "agentic_proofkit", "__main__.py"), filepath.Join(packageRoot, "__main__.py"))
	if err := os.WriteFile(filepath.Join(packageRoot, "__init__.py"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(packageRoot, "bin", "agentic-proofkit")
	fakeBinary := `#!/usr/bin/env python3
import os
import signal
import time

def raise_exit():
    raise SystemExit(42)

signal.signal(signal.SIGTERM, lambda _signum, _frame: raise_exit())

pid_path = os.environ["PROOFKIT_TEST_PID_FILE"]
temporary_pid_path = pid_path + ".tmp"
with open(temporary_pid_path, "w", encoding="utf-8") as handle:
    handle.write(str(os.getpid()))
    handle.flush()
    os.fsync(handle.fileno())
os.replace(temporary_pid_path, pid_path)

while True:
    time.sleep(0.1)
`
	if err := os.WriteFile(binary, []byte(fakeBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(root, "child.pid")
	command := exec.Command(python, "-m", "agentic_proofkit")
	command.Env = append(os.Environ(), "PYTHONPATH="+root, "PROOFKIT_TEST_PID_FILE="+pidFile)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_, _ = command.Process.Wait()
		}
	})
	pid := waitForPID(t, pidFile, command.Process.Pid)
	if pid != command.Process.Pid {
		t.Fatalf("wrapper pid=%d embedded CLI pid=%d, want exec-preserved identity", command.Process.Pid, pid)
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = command.Wait()
	exitError, ok := err.(*exec.ExitError)
	if !ok || exitError.ExitCode() != 42 {
		t.Fatalf("signal exit error=%v code=%d, want embedded handler code 42", err, command.ProcessState.ExitCode())
	}
}

func copyFixtureFile(t *testing.T, source string, target string) {
	t.Helper()
	content, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitForPID(t *testing.T, path string, expected int) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		content, err := os.ReadFile(path)
		if err == nil {
			pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
			if err == nil && pid == expected {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(fmt.Errorf("timed out waiting for embedded CLI pid"))
	return 0
}

func TestWaitForPIDIgnoresPartialMalformedAndStaleValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "child.pid")
	expected := 424242
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, content := range []string{"", "not-a-pid", "123", strconv.Itoa(expected)} {
			_ = os.WriteFile(path, []byte(content), 0o600)
			time.Sleep(15 * time.Millisecond)
		}
	}()
	if got := waitForPID(t, path, expected); got != expected {
		t.Fatalf("waitForPID()=%d, want %d", got, expected)
	}
	<-done
}
