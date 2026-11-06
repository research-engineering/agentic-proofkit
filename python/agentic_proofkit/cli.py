from __future__ import annotations

import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    binary = Path(__file__).with_name("bin") / "agentic-proofkit"
    if not binary.is_file():
        print(
            "agentic-proofkit: missing embedded CLI binary; reinstall the package",
            file=sys.stderr,
        )
        return 127
    command = [str(binary), *argv]
    python_executable = str(Path(sys.executable).absolute())
    environment = os.environ.copy()
    environment["AGENTIC_PROOFKIT_LAUNCHER_PROFILE"] = "python_module"
    environment["AGENTIC_PROOFKIT_PYTHON_EXECUTABLE"] = python_executable
    if os.name != "nt":
        try:
            os.execve(str(binary), command, environment)
        except PermissionError:
            try:
                ensure_executable(binary)
                os.execve(str(binary), command, environment)
            except PermissionError:
                print(
                    "agentic-proofkit: cannot execute embedded CLI binary; check permissions or reinstall the package",
                    file=sys.stderr,
                )
                return 126
        raise AssertionError("os.execve returned unexpectedly")
    ensure_executable(binary)
    import subprocess

    return subprocess.run(command, check=False, env=environment).returncode


def ensure_executable(path: Path) -> None:
    mode = path.stat().st_mode
    wanted = mode | stat.S_IXUSR
    if wanted != mode:
        path.chmod(wanted)
