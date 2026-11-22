#!/usr/bin/env python3
"""Run ShellCheck on every repository shell script, fail-closed.

The binary is supplied by the pinned ``shellcheck-py`` wheel. Some Python
installations place console scripts outside ``PATH`` (PEP 668 user sites), so
the wrapper looks in ``PATH``, the user script directory and the interpreter's
``bin`` directory before giving up with an actionable message.
"""

from __future__ import annotations

import shutil
import site
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def find_shellcheck() -> str | None:
    """Locate the ShellCheck binary across supported installation layouts."""
    found = shutil.which("shellcheck")
    if found:
        return found
    candidates = [Path(site.getuserbase()) / "bin" / "shellcheck"]
    candidates.append(Path(sys.executable).parent / "shellcheck")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def main() -> int:
    """ShellCheck every script; return the tool's exit status."""
    binary = find_shellcheck()
    if binary is None:
        print("shellcheck not installed; run `make tools`", file=sys.stderr)
        return 1
    scripts = sorted((ROOT / "scripts").rglob("*.sh"))
    if not scripts:
        print("shellcheck: no shell scripts in this repository")
        return 0
    result = subprocess.run([binary, "-x", *(str(path) for path in scripts)], cwd=ROOT)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
