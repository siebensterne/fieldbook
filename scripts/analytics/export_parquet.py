#!/usr/bin/env python3
"""Convert verified NDJSON staging rows into typed Parquet datasets.

The Rust exporter owns input verification and row generation. This script
reads its staging directory, applies explicit Arrow schemas, writes bounded
Parquet batches, reads them back, reconciles counts and publishes through an
atomic directory rename. Nothing is written into captures/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import date
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

SCHEMA_VERSION = 1
DATASETS = (
    "journal_observation",
    "sbe_message",
    "sbe_book_level",
    "capture_instrument",
    "capture_price_range",
    "capture_tick_band",
    "capture_run",
)

S = pa.string


def fixed_binary32() -> pa.DataType:
    """Return the fixed-size digest type used by the dataset schemas."""
    return pa.binary(32)


U8 = pa.uint8
U16 = pa.uint16
U32 = pa.uint32
U64 = pa.uint64
I64 = pa.int64
I32 = pa.int32

SCHEMAS: dict[str, pa.Schema] = {
    "journal_observation": pa.schema(
        [
            pa.field("capture_id", S()),
            pa.field("run_id", S()),
            pa.field("journal_schema_version", U16()),
            pa.field("segment_index", U64()),
            pa.field("segment_file", S()),
            pa.field("segment_record_ordinal", U64()),
            pa.field("record_region_offset", U64()),
            pa.field("record_byte_length", U64()),
            pa.field("segment_file_sha256", fixed_binary32()),
            pa.field("source", S()),
            pa.field("shard", U16()),
            pa.field("replica", U16()),
            pa.field("connection_epoch", U64()),
            pa.field("observation_seq", U64()),
            pa.field("receive_seq", U64(), nullable=True),
            pa.field("control_seq", U64(), nullable=True),
            pa.field("clock_source", S()),
            pa.field("direction", S()),
            pa.field("record_kind", S()),
            pa.field("frame_kind", S(), nullable=True),
            pa.field("control_opcode", S(), nullable=True),
            pa.field("signal", S(), nullable=True),
            pa.field("signal_correlation", pa.binary(), nullable=True),
            pa.field("heartbeat_mechanism", S(), nullable=True),
            pa.field("received_at_us", I64()),
            pa.field("date", pa.date32()),
            pa.field("payload_length", U64()),
            pa.field("payload_sha256", fixed_binary32()),
            pa.field("decode_status", S(), nullable=True),
            pa.field("decode_events", U32(), nullable=True),
            pa.field("decode_reason", S(), nullable=True),
            pa.field("decode_category", S(), nullable=True),
            pa.field("send_status", S(), nullable=True),
            pa.field("send_error", S(), nullable=True),
        ]
    ),
    "sbe_message": pa.schema(
        [
            pa.field("capture_id", S()),
            pa.field("sbe_file_sha256", fixed_binary32()),
            pa.field("message_ordinal", U64()),
            pa.field("message_kind", S()),
            pa.field("schema_id", U16()),
            pa.field("schema_version", U16()),
            pa.field("serialization_symbol", S()),
            pa.field("native_symbol", S(), nullable=True),
            pa.field("mapping_status", S()),
            pa.field("received_at_us", I64()),
            pa.field("exchange_timestamp_us", I64()),
            pa.field("date", pa.date32()),
            pa.field("side", S(), nullable=True),
            pa.field("price_mantissa_sbe", I64(), nullable=True),
            pa.field("quantity_mantissa_sbe", I64(), nullable=True),
            pa.field("quantity_semantics", S()),
            pa.field("snapshot_bid_levels", U32()),
            pa.field("snapshot_ask_levels", U32()),
        ]
    ),
    "sbe_book_level": pa.schema(
        [
            pa.field("capture_id", S()),
            pa.field("sbe_file_sha256", fixed_binary32()),
            pa.field("message_ordinal", U64()),
            pa.field("serialization_symbol", S()),
            pa.field("side", S()),
            pa.field("level_ordinal", U32()),
            pa.field("price_mantissa_sbe", I64()),
            pa.field("quantity_mantissa_sbe", I64()),
            pa.field("received_at_us", I64()),
            pa.field("date", pa.date32()),
        ]
    ),
    "capture_instrument": pa.schema(
        [
            pa.field("capture_id", S()),
            pa.field("exchange", S()),
            pa.field("native_symbol", S()),
            pa.field("symbol", S()),
            pa.field("title", S(), nullable=True),
            pa.field("outcome", S(), nullable=True),
            pa.field("exchange_market_id", S(), nullable=True),
            pa.field("close_time_us", I64(), nullable=True),
            pa.field("tick_size_us", I64(), nullable=True),
            pa.field("price_level_structure", S(), nullable=True),
            pa.field("price_scale", U8()),
            pa.field("quantity_scale", U8()),
            pa.field("price_unit_kind", S()),
            pa.field("price_unit_code", S(), nullable=True),
            pa.field("quantity_unit_kind", S()),
            pa.field("quantity_unit_code", S(), nullable=True),
            pa.field("quantity_step", I64(), nullable=True),
            pa.field("lot_size", I64(), nullable=True),
            pa.field("contract_multiplier_num", I64(), nullable=True),
            pa.field("contract_multiplier_den", I64(), nullable=True),
            pa.field("metadata_sha256", S()),
        ]
    ),
    "capture_price_range": pa.schema(
        [
            pa.field("capture_id", S()),
            pa.field("symbol", S()),
            pa.field("ordinal", U32()),
            pa.field("start", I64()),
            pa.field("end", I64()),
            pa.field("step", I64()),
            pa.field("origin", I64()),
        ]
    ),
    "capture_tick_band": pa.schema(
        [
            pa.field("capture_id", S()),
            pa.field("symbol", S()),
            pa.field("ordinal", U32()),
            pa.field("start", I64()),
            pa.field("end", I64()),
            pa.field("step", I64()),
            pa.field("origin", I64()),
        ]
    ),
    "capture_run": pa.schema(
        [
            pa.field("capture_id", S()),
            pa.field("venue", S()),
            pa.field("environment", S()),
            pa.field("started_at_us", I64()),
            pa.field("ended_at_us", I64()),
            pa.field("duration_us", I64()),
            pa.field("journal_run_id", S()),
            pa.field("journal_schema_version", U16()),
            pa.field("journal_code_commit", S()),
            pa.field("journal_provenance_status", S()),
            pa.field("collector_version", S()),
            pa.field("sbe_schema_id", U16()),
            pa.field("sbe_schema_version", U16()),
            pa.field("expected_symbols", U64()),
            pa.field("acknowledged_symbols", U64()),
            pa.field("anchored_symbols", U64()),
            pa.field("exchange_snapshots", U64()),
            pa.field("sbe_messages", U64()),
            pa.field("journal_records", U64()),
            pa.field("capture_verification_status", S()),
            pa.field("export_verification_status", S()),
            pa.field("date", pa.date32()),
        ]
    ),
}

HEX_FIELDS = {"segment_file_sha256", "payload_sha256", "sbe_file_sha256"}


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_default(value: object) -> object:
    """Render a non-JSON value for canonical row hashing."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, date):
        return (value - date(1970, 1, 1)).days
    return value.isoformat()


def canonical_row(row: dict) -> bytes:
    """Serialize one row deterministically for logical digests."""
    text = json.dumps(
        row,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=canonical_default,
    )
    return text.encode("utf-8") + b"\n"


def convert_row(row: dict, schema: pa.Schema) -> dict:
    """Convert one NDJSON row under an explicit Arrow schema."""
    names = set(schema.names)
    unexpected = set(row) - names
    if unexpected:
        raise ValueError(f"unexpected fields: {sorted(unexpected)}")
    result: dict = {}
    for field in schema:
        value = row.get(field.name)
        if field.name in HEX_FIELDS and isinstance(value, str):
            result[field.name] = bytes.fromhex(value)
        else:
            result[field.name] = value
    return result


def write_dataset(
    source: Path,
    target: Path,
    schema: pa.Schema,
    batch_rows: int,
    row_group_size: int,
    compression: str,
) -> tuple[int, str, str]:
    """Write a bounded Parquet dataset and return row and digest values."""
    rows = 0
    logical = hashlib.sha256()
    readback = hashlib.sha256()
    writer = pq.ParquetWriter(
        target,
        schema,
        compression=compression,
        version="2.6",
        write_statistics=True,
    )
    batch: list[dict] = []
    with source.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"{source.name}: row is not an object")
            logical.update(canonical_row(row))
            batch.append(convert_row(row, schema))
            rows += 1
            if len(batch) >= batch_rows:
                table = pa.Table.from_pylist(batch, schema=schema)
                writer.write_table(table, row_group_size=row_group_size)
                for value in table.to_pylist():
                    readback.update(canonical_row(value))
                batch.clear()
    if batch:
        table = pa.Table.from_pylist(batch, schema=schema)
        writer.write_table(table, row_group_size=row_group_size)
        for value in table.to_pylist():
            readback.update(canonical_row(value))
    writer.close()

    round_trip = pq.read_table(target, schema=schema)
    if round_trip.num_rows != rows:
        raise ValueError(f"{source.name}: readback row count mismatch")
    if round_trip.schema.remove_metadata() != schema:
        raise ValueError(f"{source.name}: readback schema mismatch")
    return rows, logical.hexdigest(), readback.hexdigest()


def publish(staging: Path, exports: Path, args: argparse.Namespace) -> dict:
    """Write, verify and atomically publish all Parquet datasets."""
    manifest = json.loads((staging / "export-manifest.json").read_text())
    export_id = manifest["export_id"]
    datasets_dir = staging / "datasets"
    datasets_dir.mkdir(parents=True, exist_ok=True)
    row_counts: dict[str, int] = {}
    logical: dict[str, str] = {}
    readback: dict[str, str] = {}
    artifacts: dict[str, str] = {}
    schemas: dict[str, str] = {}
    for name in DATASETS:
        source = staging / f"{name}.ndjson"
        target = datasets_dir / f"{name}.parquet"
        rows, logical_digest, readback_digest = write_dataset(
            source,
            target,
            SCHEMAS[name],
            args.batch_rows,
            args.row_group_size,
            args.compression,
        )
        expected_rows = manifest["row_counts"][name]
        if rows != expected_rows:
            raise ValueError(f"{name}: staged rows {rows} != manifest {expected_rows}")
        row_counts[name] = rows
        logical[name] = logical_digest
        readback[name] = readback_digest
        artifacts[name] = sha256_file(target)
        schemas[name] = hashlib.sha256(str(SCHEMAS[name]).encode()).hexdigest()

    result = dict(manifest)
    result["format"] = "fieldbook.analytics.export"
    result["dataset_schema_version"] = SCHEMA_VERSION
    result["pyarrow_version"] = pa.__version__
    result["parquet_options"] = {
        "row_group_size": args.row_group_size,
        "batch_rows": args.batch_rows,
        "compression": args.compression,
        "version": "2.6",
        "statistics": True,
    }
    result["dataset_schemas"] = schemas
    result["datasets"] = {
        name: {
            "rows": row_counts[name],
            "logical_content_sha256": logical[name],
            "readback_sha256": readback[name],
            "parquet_sha256": artifacts[name],
            "file": f"datasets/{name}.parquet",
        }
        for name in DATASETS
    }
    result["verification_results"]["parquet_readback"] = all(
        logical[name] == readback[name] for name in DATASETS
    )
    manifest_path = staging / "export-manifest.json"
    manifest_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    manifest_path.with_suffix(".sha256").write_text(sha256_file(manifest_path) + "\n")

    exports.mkdir(parents=True, exist_ok=True)
    destination = exports / export_id
    if destination.exists():
        raise FileExistsError(f"export already published: {destination}")
    os.replace(staging, destination)
    return result


def main() -> int:
    """Parse arguments and run the publisher with a bounded exit status."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging", type=Path, required=True)
    parser.add_argument("--exports", type=Path, required=True)
    parser.add_argument("--row-group-size", type=int, default=131072)
    parser.add_argument("--batch-rows", type=int, default=32768)
    parser.add_argument("--compression", choices=("snappy", "zstd"), default="snappy")
    args = parser.parse_args()
    try:
        result = publish(args.staging, args.exports, args)
    except (OSError, ValueError, KeyError, pa.ArrowException) as error:
        print(f"export rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"export_id": result["export_id"], "status": "published"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
