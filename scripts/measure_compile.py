#!/usr/bin/env python3
"""Measure a clean build in a repository-local target directory.

The script never writes outside this checkout. It records wall-clock time and
the slowest compilation units from Cargo's own ``--timings`` report, then
writes a machine-readable summary under ``.local/perf``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PERF = ROOT / ".local" / "perf"
UNIT_DATA = re.compile(r"const UNIT_DATA = (\[.*?\]);", re.DOTALL)


def parse_timings(directory: Path) -> list[dict]:
    """Return Cargo timing units sorted by duration."""
    reports = sorted((directory / "cargo-timings").glob("cargo-timing-*.html"))
    if not reports:
        return []
    payload = reports[-1].read_text(encoding="utf-8")
    match = UNIT_DATA.search(payload)
    if match is None:
        return []
    units = json.loads(match.group(1))
    return sorted(units, key=lambda unit: unit.get("duration", 0), reverse=True)


def measure(label: str, profile: str, keep: bool) -> dict:
    """Run one clean build and return its measured summary."""
    PERF.mkdir(parents=True, exist_ok=True)
    target = ROOT / ".local" / f"bench-{label}-target"
    if target.exists():
        shutil.rmtree(target)
    command = ["cargo", "build", "--locked", "--timings"]
    if profile == "release":
        command.append("--release")
    started = time.monotonic()
    result = subprocess.run(
        command,
        cwd=ROOT,
        capture_output=True,
        env={**os.environ, "CARGO_TARGET_DIR": str(target)},
        check=False,
    )
    elapsed = time.monotonic() - started
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"build failed: {detail[-2000:]}")
    units = parse_timings(target)
    summary = {
        "label": label,
        "profile": profile,
        "seconds": round(elapsed, 2),
        "units": len(units),
        "slowest": [
            {
                "name": unit.get("name", ""),
                "version": unit.get("version", ""),
                "seconds": round(unit.get("duration", 0), 2),
            }
            for unit in units[:12]
        ],
    }
    (PERF / f"{label}.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if not keep:
        shutil.rmtree(target)
    return summary


def main() -> int:
    """Report the measured clean-build cost."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--profile", choices=("dev", "release"), default="dev")
    parser.add_argument("--keep", action="store_true", help="keep the scratch target")
    arguments = parser.parse_args()
    try:
        summary = measure(arguments.label, arguments.profile, arguments.keep)
    except (OSError, RuntimeError) as error:
        print(f"[FAIL] compile measurement failed: {error}")
        return 1
    print(f"{summary['label']}: {summary['seconds']}s " f"across {summary['units']} units")
    for unit in summary["slowest"][:5]:
        print(f"  {unit['seconds']:6.2f}s  {unit['name']} {unit['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
