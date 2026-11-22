#!/usr/bin/env python3
"""Guard this repository's tooling against cross-project pollution.

Scripts here must be project-local: no reference to another repository, no
absolute path outside this checkout, and no import of a sibling project's
modules. This check scans ``scripts/`` and CI workflow files only; historical
documents may legitimately mention other projects.

Run from anywhere; the repository root is derived from this file.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Constructed from parts so this file does not contain the marker it rejects.
FOREIGN_MARKERS = ("nir" + "nay",)
ABSOLUTE_PATH = re.compile(r"(?<![\w/])/(?:Users|home|opt|private|tmp)/")


def scan() -> list[str]:
    """Return every project-local tooling file that references another repo."""
    errors: list[str] = []
    targets = sorted((ROOT / "scripts").rglob("*.py")) + sorted((ROOT / "scripts").rglob("*.sh"))
    targets += sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    for path in targets:
        if path == Path(__file__).resolve():
            continue
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(ROOT).as_posix()
        for number, line in enumerate(text.splitlines(), 1):
            lowered = line.lower()
            for marker in FOREIGN_MARKERS:
                if marker.lower() in lowered:
                    errors.append(f"{relative}:{number}: foreign marker `{marker}`")
            if ABSOLUTE_PATH.search(line):
                errors.append(f"{relative}:{number}: absolute host path")
    return errors


def main() -> int:
    """Report pollution and fail closed."""
    errors = scan()
    for error in errors:
        print(f"FAIL: {error}")
    if errors:
        print(f"cross-pollution: {len(errors)} finding(s)", file=sys.stderr)
        return 1
    print("cross-pollution: scripts and workflows are project-local")
    return 0


if __name__ == "__main__":
    sys.exit(main())
