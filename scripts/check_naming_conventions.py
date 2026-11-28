#!/usr/bin/env python3
"""Fail-closed gate for phase labels in active repository paths."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PHASE = re.compile(r"(?:^|[-_])(?:p|m|h|d|e|v)[0-9]+(?:$|[-_.])", re.IGNORECASE)
ACTIVE_PREFIXES = ("src/", "tests/", "xtask/", "scripts/", "tools/")
EVIDENCE_PREFIXES = ("measurements/", "captures/")
FIXTURES_DIR = "tests/contract_fixtures/"
MANIFEST_PATH = "tests/contract_fixtures/manifest.json"


def tracked_paths(root: Path) -> list[str]:
    """Return every path recorded in the Git index."""
    raw = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
    return [part.decode("utf-8", "surrogateescape") for part in raw.split(b"\0") if part]


def fixture_allowlist(root: Path) -> set[str]:
    """Derive the exact permitted fixture-directory contents from the manifest."""
    manifest = json.loads((root / MANIFEST_PATH).read_text(encoding="utf-8"))
    copies = {FIXTURES_DIR + Path(entry["path"]).name for entry in manifest["files"]}
    return copies | {MANIFEST_PATH}


def fixture_directory_findings(paths: list[str], allowed: set[str]) -> list[str]:
    """Return tracked fixture files that are unlisted or listed files that are missing."""
    present = {rel for rel in paths if rel.startswith(FIXTURES_DIR)}
    return sorted((present - allowed) | (allowed - present))


def phase_label_findings(paths: list[str], allowed: set[str] | None = None) -> list[str]:
    """Return active paths whose components carry a phase label."""
    if allowed is None:
        allowed = fixture_allowlist(ROOT)
    findings: list[str] = []
    for rel in paths:
        if rel.startswith(EVIDENCE_PREFIXES):
            continue
        # Manifest-listed copies keep their canonical phase-shaped IDs; the
        # exact membership of this directory is checked separately so an
        # unlisted copy cannot hide behind that exemption.
        if rel.startswith(FIXTURES_DIR):
            continue
        if not rel.startswith(ACTIVE_PREFIXES):
            continue
        if any(PHASE.search(component) for component in Path(rel).parts):
            findings.append(rel)
    return findings


def main() -> int:
    """Print findings and return a process exit status."""
    paths = tracked_paths(ROOT)
    allowed = fixture_allowlist(ROOT)
    labels = phase_label_findings(paths, allowed)
    fixtures = fixture_directory_findings(paths, allowed)
    for item in labels:
        print(f"FAIL: phase label in active path: {item}")
    for item in fixtures:
        print(f"FAIL: fixture directory does not match manifest: {item}")
    if labels or fixtures:
        count = len(labels) + len(fixtures)
        print(f"naming conventions: {count} finding(s)")
        return 1
    print("naming conventions: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
