from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Sequence


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
    ensure_executable(binary)
    command = [str(binary), *argv]
    if os.name != "nt":
        os.execv(str(binary), command)
        raise AssertionError("os.execv returned unexpectedly")
    return subprocess.run(command, check=False).returncode


def ensure_executable(path: Path) -> None:
    mode = path.stat().st_mode
    wanted = mode | stat.S_IXUSR
    if os.name != "nt":
        wanted |= stat.S_IXGRP | stat.S_IXOTH
    if wanted != mode:
        path.chmod(wanted)
