#!/usr/bin/env python3
"""Fail-closed gate for phase labels in active repository paths."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE = re.compile(r"(?:^|[-_])(?:p|m|h|d|e|v)[0-9]+(?:$|[-_.])", re.IGNORECASE)
ACTIVE_PREFIXES = ("src/", "tests/", "xtask/", "scripts/", "tools/")
EVIDENCE_PREFIXES = ("measurements/", "captures/")
# Canonical golden fixtures are copied byte-identically from the workspace
# manifest, which fixes their filenames (including phase-shaped IDs such as
# P13-INT-SCHEMA). They are conformance evidence, not active code paths, so
# the phase-label convention must not reject the required copies.
GOLDEN_FIXTURE_PREFIXES = ("tests/contract_fixtures/",)


def tracked_paths(root: Path) -> list[str]:
    """Return every path recorded in the Git index."""
    raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
    return [part.decode("utf-8", "surrogateescape") for part in raw.split(b"\0") if part]


def phase_label_findings(paths: list[str]) -> list[str]:
    """Return active paths whose components carry a phase label."""
    findings: list[str] = []
    for rel in paths:
        if rel.startswith(EVIDENCE_PREFIXES):
            continue
        if rel.startswith(GOLDEN_FIXTURE_PREFIXES):
            continue
        if not rel.startswith(ACTIVE_PREFIXES):
            continue
        if any(PHASE.search(component) for component in Path(rel).parts):
            findings.append(rel)
    return findings


def main() -> int:
    """Print findings and return a process exit status."""
    findings = phase_label_findings(tracked_paths(ROOT))
    for item in findings:
        print(f"FAIL: phase label in active path: {item}")
    if findings:
        print(f"naming conventions: {len(findings)} finding(s)")
        return 1
    print("naming conventions: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
