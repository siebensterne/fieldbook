#!/usr/bin/env python3
"""Verify the local copies of every reference named by ``STYLES.md``.

The mandate names published style guides and expects local copies under
``style/``. This gate checks that each named document exists, is
non-empty, and matches the SHA-256 recorded in ``style/index.md``. It
also checks that the index covers the mandated set exactly. Published guides
are third-party documents; this gate verifies their retention, not their
adoption. Binding rules remain the repository's own checkers and lint config.
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "style" / "index.md"
ROW = re.compile(r"^\| `([^`]+)` \| .* \| `([0-9a-f]{64})` \|$")

# Mirrors the mandatory list in STYLES.md.
MANDATED = frozenset(
    {
        "rustguide.html",
        "rust-coding-guidelines.html",
        "cppguide.html",
        "jsoncguide.html",
        "pyguide.html",
        "shellguide.html",
        "docguide-style.html",
    }
)


def parse_index(text: str) -> dict[str, str]:
    """Return the filename-to-digest mapping from a reference index."""
    rows: dict[str, str] = {}
    for line in text.splitlines():
        match = ROW.match(line)
        if match:
            rows[match.group(1)] = match.group(2)
    return rows


def check(root: Path = ROOT) -> list[str]:
    """Return every reference-integrity error found under ``root``."""
    errors: list[str] = []
    styles = root / "STYLES.md"
    if not styles.is_file():
        return ["STYLES.md is missing"]
    index = root / "style" / "index.md"
    if not index.is_file():
        return ["style/index.md is missing"]
    rows = parse_index(index.read_text(encoding="utf-8"))
    if set(rows) != MANDATED:
        missing = sorted(MANDATED - set(rows))
        extra = sorted(set(rows) - MANDATED)
        if missing:
            errors.append(f"index is missing mandated references: {missing}")
        if extra:
            errors.append(f"index lists unexpected references: {extra}")
    for name, expected in sorted(rows.items()):
        path = root / "style" / name
        if not path.is_file():
            errors.append(f"reference {name} is missing")
            continue
        data = path.read_bytes()
        if not data:
            errors.append(f"reference {name} is empty")
            continue
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            errors.append(
                f"reference {name} digest mismatch: " f"expected {expected}, found {actual}"
            )
    return errors


def main() -> int:
    """Print findings and return a process exit status."""
    findings = check()
    for finding in findings:
        print(f"FAIL: {finding}")
    if findings:
        print(f"style references: {len(findings)} finding(s)")
        return 1
    print(f"PASS: {len(MANDATED)} mandated style references verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
