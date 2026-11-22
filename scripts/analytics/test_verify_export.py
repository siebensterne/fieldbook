"""Tests for the independent export verifier."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parent
try:
    SPEC = importlib.util.spec_from_file_location("export_parquet", BASE / "export_parquet.py")
    export_parquet = importlib.util.module_from_spec(SPEC)
    sys.modules[SPEC.name] = export_parquet
    SPEC.loader.exec_module(export_parquet)
    SPEC2 = importlib.util.spec_from_file_location("verify_export", BASE / "verify_export.py")
    verify_export = importlib.util.module_from_spec(SPEC2)
    sys.modules[SPEC2.name] = verify_export
    SPEC2.loader.exec_module(verify_export)
except ImportError:
    export_parquet = None
    verify_export = None


def sample_row(schema: export_parquet.pa.Schema) -> dict:
    """Build one minimal row satisfying an Arrow schema."""
    row = {}
    for field in schema:
        kind = field.type
        if export_parquet.pa.types.is_fixed_size_binary(kind):
            row[field.name] = "00" * kind.byte_width
        elif export_parquet.pa.types.is_binary(kind):
            row[field.name] = None
        elif export_parquet.pa.types.is_string(kind):
            row[field.name] = "sample"
        else:
            row[field.name] = 0
    return row


@unittest.skipIf(
    verify_export is None or export_parquet is None,
    "pyarrow is not installed in this environment",
)
class ExportVerifierTests(unittest.TestCase):
    """Model a published export and its corrupted forms."""

    def test_valid_export_certifies(self) -> None:
        """Check that a reconciled export passes certification."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            staging = root / "staging"
            staging.mkdir()
            rows = {}
            for name in export_parquet.DATASETS:
                schema = export_parquet.SCHEMAS[name]
                row = sample_row(schema)
                rows[name] = row
                (staging / f"{name}.ndjson").write_text(json.dumps(row) + "\n", encoding="utf-8")
            manifest = {
                "schema_version": 1,
                "capture_id": "a" * 64,
                "export_id": "b" * 64,
                "journal_provenance_status": "legacy_incomplete",
                "row_counts": dict.fromkeys(export_parquet.DATASETS, 1),
                "verification_results": {"journal": True, "sbe": True},
            }
            (staging / "export-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            exports = root / "exports"
            args = type(
                "Args",
                (),
                {
                    "row_group_size": 1,
                    "batch_rows": 1,
                    "compression": "snappy",
                },
            )()
            export_parquet.publish(staging, exports, args)
            published = exports / manifest["export_id"]
            certificate = verify_export.verify_export(published)
            self.assertEqual(certificate["status"], "PASS")
            self.assertEqual(certificate["checks"]["journal_provenance_label"], "PASS")

    def test_missing_artifact_is_incomplete(self) -> None:
        """Check that a missing artifact never certifies."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "export-manifest.json").write_text("{}", encoding="utf-8")
            (root / "export-manifest.sha256").write_text("0" * 64, encoding="utf-8")
            certificate = verify_export.verify_export(root)
            self.assertEqual(certificate["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
