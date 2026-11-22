#!/usr/bin/env python3
"""Independently reconcile one published export and write a certificate.

A certificate cannot override a failed upstream check. Statuses remain
PASS, FAIL, NOT_APPLICABLE, NOT_MEASURED and INCOMPLETE; an absent or failed
input never becomes zero or a passing result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import pyarrow.parquet as pq
from export_parquet import DATASETS, SCHEMAS, canonical_row, sha256_file

PASS = "PASS"
FAIL = "FAIL"
NA = "NOT_APPLICABLE"
NOT_MEASURED = "NOT_MEASURED"
INCOMPLETE = "INCOMPLETE"


def status(ok: bool) -> str:
    """Convert a boolean check result into a certificate status."""
    return PASS if ok else FAIL


def ndjson_logical(path: Path) -> str:
    """Hash canonical rows of one NDJSON interchange file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for line in handle:
            if line.strip():
                digest.update(canonical_row(json.loads(line)))
    return digest.hexdigest()


def verify_export(export_dir: Path) -> dict:
    """Reconcile manifest, source rows and Parquet artifacts independently."""
    manifest_path = export_dir / "export-manifest.json"
    sidecar = export_dir / "export-manifest.sha256"
    checks: dict[str, str] = {}
    details: dict[str, object] = {}

    if not manifest_path.is_file() or not sidecar.is_file():
        return {
            "certificate": "export",
            "status": INCOMPLETE,
            "checks": {"manifest": INCOMPLETE},
            "details": {"reason": "manifest or sidecar missing"},
        }

    recorded = sidecar.read_text(encoding="utf-8").strip()
    actual = sha256_file(manifest_path)
    checks["manifest_digest"] = status(recorded == actual)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    details["export_id"] = manifest.get("export_id")
    details["capture_id"] = manifest.get("capture_id")
    details["journal_provenance_status"] = manifest.get("journal_provenance_status", NOT_MEASURED)

    upstream = manifest.get("verification_results", {})
    checks["upstream_verification"] = status(bool(upstream) and all(upstream.values()))
    checks["journal_provenance_label"] = status(
        manifest.get("journal_provenance_status") == "legacy_incomplete"
    )

    rows_match = True
    artifacts_match = True
    logical_match = True
    readback_match = True
    schema_match = True
    row_counts: dict[str, int] = {}
    for name in DATASETS:
        entry = manifest.get("datasets", {}).get(name)
        if entry is None:
            rows_match = False
            continue
        parquet_path = export_dir / entry["file"]
        source_path = export_dir / f"{name}.ndjson"
        if not parquet_path.is_file() or not source_path.is_file():
            rows_match = False
            continue
        count = pq.read_table(parquet_path).num_rows
        row_counts[name] = count
        rows_match = rows_match and count == entry["rows"]
        artifacts_match = artifacts_match and (sha256_file(parquet_path) == entry["parquet_sha256"])
        logical_match = logical_match and (
            ndjson_logical(source_path) == entry["logical_content_sha256"]
        )
        readback_match = readback_match and (
            entry["logical_content_sha256"] == entry["readback_sha256"]
        )
        schema_match = schema_match and (
            pq.read_schema(parquet_path).remove_metadata() == SCHEMAS[name]
        )
    checks["row_counts"] = status(rows_match)
    checks["artifact_hashes"] = status(artifacts_match)
    checks["logical_digests"] = status(logical_match)
    checks["readback_equality"] = status(readback_match)
    checks["arrow_schemas"] = status(schema_match)
    details["row_counts"] = row_counts

    overall = (
        PASS
        if all(value == PASS for value in checks.values())
        else INCOMPLETE
        if INCOMPLETE in checks.values()
        else FAIL
    )
    return {
        "certificate": "export",
        "export_id": manifest.get("export_id"),
        "capture_id": manifest.get("capture_id"),
        "status": overall,
        "checks": checks,
        "details": details,
    }


def main() -> int:
    """Write an export certificate and exit with a bounded status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    try:
        certificate = verify_export(args.export_dir)
    except (OSError, ValueError, KeyError) as error:
        print(f"export verification failed: {error}", file=sys.stderr)
        return 1
    text = json.dumps(certificate, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        args.out.write_text(text, encoding="utf-8")
    print(text)
    return 0 if certificate["status"] == PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
