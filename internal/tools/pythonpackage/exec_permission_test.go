package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestPOSIXWrapperRepairsOnlyExecutionDenial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX exec permission boundary is not applicable on Windows")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	cli, err := filepath.Abs(filepath.Join("..", "..", "..", "python", "agentic_proofkit", "cli.py"))
	if err != nil {
		t.Fatal(err)
	}
	const script = `import errno
import os
from pathlib import Path
import runpy
import stat
import sys
import tempfile
from unittest.mock import patch

module = runpy.run_path(sys.argv[1])
class Replaced(Exception):
    pass

with tempfile.TemporaryDirectory() as root:
    binary = Path(root) / "bin" / "agentic-proofkit"
    binary.parent.mkdir()
    binary.write_bytes(b"fixture")
    module["main"].__globals__["__file__"] = str(Path(root) / "cli.py")
    for case in ("ready", "repair", "format", "denied-twice", "repair-denied"):
        binary.chmod(0o750 if case == "ready" else 0o644)
        attempts = []
        repairs = []
        failure = OSError(errno.ENOEXEC, "format") if case == "format" else PermissionError("denied")
        original_chmod = Path.chmod
        def chmod(path, mode, **kwargs):
            assert path == binary
            assert case != "ready", "already executable files must not require chmod"
            repairs.append(mode)
            if case == "repair-denied":
                raise failure
            return original_chmod(path, mode, **kwargs)
        def execute(path, argv, environment):
            assert path == str(binary) and argv == [str(binary), "--probe"]
            assert environment["AGENTIC_PROOFKIT_LAUNCHER_PROFILE"] == "python_module"
            attempts.append(path)
            if case != "ready" and len(attempts) == 1 or case == "denied-twice":
                raise failure
            assert stat.S_IMODE(binary.stat().st_mode) == (0o750 if case == "ready" else 0o755)
            raise Replaced()
        expected = Replaced if case in ("ready", "repair") else type(failure)
        with patch.object(os, "execve", execute), patch.object(Path, "chmod", chmod):
            try:
                module["main"](["--probe"])
            except expected as error:
                if expected is not Replaced:
                    assert error is failure
            else:
                raise AssertionError("exec or its error must be terminal")
        assert len(attempts) == (2 if case in ("repair", "denied-twice") else 1), (case, attempts)
        assert len(repairs) == (0 if case in ("ready", "format") else 1), (case, repairs)
`
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, "-B", "-c", script, cli)
	command.WaitDelay = time.Second
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("exec permission state machine: %v\n%s", err, output)
	}
}
