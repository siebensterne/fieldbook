#!/usr/bin/env python3
"""Build, verify, destroy and rebuild an HDB release from one Parquet export."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
Q = shutil.which("q")
DATASETS = (
    "journal_observation",
    "sbe_message",
    "sbe_book_level",
    "capture_instrument",
    "capture_price_range",
    "capture_tick_band",
    "capture_run",
)
PASS = "PASS"
FAIL = "FAIL"
NOT_MEASURED = "NOT_MEASURED"
NOT_APPLICABLE = "NOT_APPLICABLE"


def run_q(script: str, *args: str) -> None:
    """Run one q script with a checked return status."""
    if Q is None:
        raise RuntimeError("q is not available")
    command = [
        Q,
        str(ROOT / "analytics" / "q" / script),
        *(str(a) for a in args),
    ]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"q {script} failed: {result.stderr[-2000:]}")


def read_json(path: Path) -> dict:
    """Read one q result file."""
    return json.loads(path.read_text(encoding="utf-8"))


def logical_digest(document: dict) -> str:
    """Hash a canonical serialization of one q result."""
    text = json.dumps(document, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compare(verify: dict, queries: dict, manifest: dict) -> dict[str, str]:
    """Compare q results with the export manifest."""
    rows = manifest["row_counts"]
    checks: dict[str, str] = {}
    checks["q_counts"] = PASS if verify["rows"] == [rows[name] for name in DATASETS] else FAIL
    checks["journal_rows"] = (
        PASS if queries["journal_rows"] == rows["journal_observation"] else FAIL
    )
    checks["message_rows"] = PASS if queries["message_rows"] == rows["sbe_message"] else FAIL
    checks["level_rows"] = PASS if queries["level_rows"] == rows["sbe_book_level"] else FAIL
    checks["instrument_rows"] = (
        PASS if queries["instrument_rows"] == rows["capture_instrument"] else FAIL
    )
    checks["coverage_symbols"] = PASS if queries["coverage_symbols"] > 0 else FAIL
    return checks


def build_and_verify(export: Path, hdb: Path, release: str) -> tuple[dict, dict]:
    """Build one release, then verify and query it in fresh q processes."""
    target = hdb / "releases" / release
    if target.exists():
        shutil.rmtree(target)
    run_q("create-hdb.q", export, target)
    run_q("verify-hdb.q", target, export)
    run_q("hdb-queries.q", target)
    verify = read_json(hdb / "releases" / "hdb-verify.json")
    queries = read_json(hdb / "releases" / "hdb-queries.json")
    return verify, queries


def certify(export: Path, hdb: Path) -> dict:
    """Perform the destroy/rebuild proof and write a certificate."""
    export = export.resolve()
    hdb = hdb.resolve()
    manifest = read_json(export / "export-manifest.json")
    export_id = manifest["export_id"]
    first = build_and_verify(export, hdb, f"build-a-{export_id[:12]}")
    first_digest = (logical_digest(first[0]), logical_digest(first[1]))
    target = hdb / "releases" / f"build-a-{export_id[:12]}"
    if target.exists():
        shutil.rmtree(target)
    second = build_and_verify(export, hdb, f"rebuild-b-{export_id[:12]}")
    second_digest = (logical_digest(second[0]), logical_digest(second[1]))
    checks = compare(first[0], first[1], manifest)
    checks["rebuild_reconciles"] = PASS if first_digest == second_digest else FAIL
    return {
        "certificate": "analytics-hdb",
        "export_id": export_id,
        "status": PASS if all(value == PASS for value in checks.values()) else FAIL,
        "checks": checks,
        "logical_digests": {
            "first": first_digest,
            "rebuild": second_digest,
        },
        "notes": [
            f"concurrent_query_serving: {NOT_APPLICABLE} for a local HDB",
            f"uint64_to_long_range: {NOT_MEASURED} beyond 2^63-1; " "values are checked at import",
        ],
    }


def main() -> int:
    """Write an HDB certificate and exit with a bounded status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export-dir", type=Path, required=True)
    parser.add_argument("--hdb-root", type=Path, default=ROOT / ".local/analytics/hdb")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        certificate = certify(args.export_dir, args.hdb_root)
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"HDB certification failed: {error}", file=sys.stderr)
        return 1
    text = json.dumps(certificate, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        args.out.write_text(text, encoding="utf-8")
    print(text)
    return 0 if certificate["status"] == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
