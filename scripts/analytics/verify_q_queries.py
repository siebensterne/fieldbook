#!/usr/bin/env python3
"""Reconcile KDB-X q query results with a Parquet export manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PASS = "PASS"
FAIL = "FAIL"
NOT_MEASURED = "NOT_MEASURED"
INCOMPLETE = "INCOMPLETE"


def load(path: Path) -> dict:
    """Read one JSON result file."""
    return json.loads(path.read_text(encoding="utf-8"))


def status(ok: bool) -> str:
    """Convert a boolean comparison into a certificate status."""
    return PASS if ok else FAIL


def reconcile(export_dir: Path, result_dir: Path) -> dict:
    """Compare every q result with the export manifest."""
    checks: dict[str, str] = {}
    names = (
        "q-preflight.json",
        "q-capture.json",
        "q-journal.json",
        "q-orderbook.json",
        "q-instruments.json",
    )
    missing = [name for name in names if not (result_dir / name).is_file()]
    if missing:
        return {
            "certificate": "analytics",
            "status": INCOMPLETE,
            "checks": {"q_results": INCOMPLETE},
            "missing": missing,
        }
    manifest = load(export_dir / "export-manifest.json")
    rows = manifest["row_counts"]
    preflight = load(result_dir / "q-preflight.json")
    capture = load(result_dir / "q-capture.json")
    journal = load(result_dir / "q-journal.json")
    orderbook = load(result_dir / "q-orderbook.json")
    instruments = load(result_dir / "q-instruments.json")

    checks["q_version"] = status(str(preflight["q_version"]) == "5")
    checks["preflight_rows"] = status(preflight["journal_rows"] == rows["journal_observation"])
    checks["capture_rows"] = status(capture["rows"] == rows["capture_run"])
    checks["journal_rows"] = status(journal["rows"] == rows["journal_observation"])
    checks["orderbook_messages"] = status(orderbook["messages"] == rows["sbe_message"])
    checks["orderbook_levels"] = status(orderbook["levels"] == rows["sbe_book_level"])
    checks["instrument_rows"] = status(instruments["instruments"] == rows["capture_instrument"])
    checks["instrument_ranges"] = status(instruments["ranges"] == rows["capture_price_range"])
    checks["instrument_bands"] = status(instruments["bands"] == rows["capture_tick_band"])
    checks["legacy_provenance"] = status(
        capture["provenance"] == manifest["journal_provenance_status"] == "legacy_incomplete"
    )
    checks["capture_declared_counts"] = status(
        capture["sbe_messages"] == rows["sbe_message"]
        and capture["journal_records"] == rows["journal_observation"]
    )
    checks["no_timestamp_join"] = status(
        "timestamp_join" not in manifest and "timestamp_join" not in capture
    )
    return {
        "certificate": "analytics",
        "export_id": manifest["export_id"],
        "status": (PASS if all(value == PASS for value in checks.values()) else FAIL),
        "checks": checks,
        "denominators": rows,
        "notes": [
            "Sequence ranges without a source clock are NOT_MEASURED, " "not zero.",
            "Snapshot-only feeds report delta continuity as NOT_APPLICABLE.",
        ],
    }


def main() -> int:
    """Write an analytics certificate and exit with a bounded status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export-dir", type=Path, required=True)
    parser.add_argument("--result-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        certificate = reconcile(args.export_dir, args.result_dir)
    except (OSError, ValueError, KeyError) as error:
        print(f"q reconciliation failed: {error}", file=sys.stderr)
        return 1
    text = json.dumps(certificate, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        args.out.write_text(text, encoding="utf-8")
    print(text)
    return 0 if certificate["status"] == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
