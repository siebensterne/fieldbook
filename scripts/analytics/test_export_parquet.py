"""Tests for the PyArrow Parquet publisher."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "export_parquet.py"
try:
    SPEC = importlib.util.spec_from_file_location("export_parquet", SCRIPT)
    export_parquet = importlib.util.module_from_spec(SPEC)
    sys.modules[SPEC.name] = export_parquet
    SPEC.loader.exec_module(export_parquet)
except ImportError:
    export_parquet = None


@unittest.skipIf(export_parquet is None, "pyarrow is not installed in this environment")
class ParquetPublisherTests(unittest.TestCase):
    """Model explicit schemas and rejected rows."""

    def test_schemas_cover_all_datasets(self) -> None:
        """Check that every contract dataset has an Arrow schema."""
        self.assertEqual(set(export_parquet.DATASETS), set(export_parquet.SCHEMAS))

    def test_binary_fields_are_fixed_size(self) -> None:
        """Check that digests use a fixed-size binary representation."""
        schema = export_parquet.SCHEMAS["journal_observation"]
        field = schema.field("payload_sha256")
        self.assertEqual(field.type, export_parquet.pa.binary(32))

    def test_unexpected_fields_are_rejected(self) -> None:
        """Check that an unknown NDJSON field cannot enter a dataset."""
        schema = export_parquet.SCHEMAS["capture_run"]
        row = dict.fromkeys(schema.names)
        row["unexpected"] = 1
        with self.assertRaises(ValueError):
            export_parquet.convert_row(row, schema)

    def test_write_and_read_back_round_trip(self) -> None:
        """Check a bounded write and exact readback of one row."""
        schema = export_parquet.SCHEMAS["capture_run"]
        row = {}
        for field in schema:
            if field.name == "payload_sha256":
                row[field.name] = "00" * 32
            elif export_parquet.pa.types.is_string(field.type):
                row[field.name] = "sample"
            else:
                row[field.name] = 0
        row["date"] = 0
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "capture_run.ndjson"
            source.write_text(json.dumps(row) + "\n", encoding="utf-8")
            target = Path(folder) / "capture_run.parquet"
            rows, logical, readback = export_parquet.write_dataset(
                source,
                target,
                schema,
                batch_rows=1,
                row_group_size=1,
                compression="snappy",
            )
            self.assertEqual(rows, 1)
            self.assertEqual(logical, readback)
            self.assertTrue(target.is_file())


if __name__ == "__main__":
    unittest.main()
