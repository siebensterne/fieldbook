# Analytics data contract

> **Deprecated 2026-11-23 (RRP-005).** This offline-export contract is retained
> until the approved NDC v2 release publication replaces it. Migration target:
> the approved NDC v2 producer requirements,
> `engineering/ndc-producer-requirements-v2-proposed.md`, and the workspace
> `NDC-REGISTRY.md`. No field in this document is an NDC v2 release field, and
> it grants no right or release acceptance. See
> `docs/documentation-consolidation-2026-11-23.md`.

This is the single versioned contract for offline analytics exports. The Rust
capture engine owns acquisition and evidence; this contract describes typed
projections of that evidence. `EXPORT_SCHEMA_VERSION = 1` in this release.

## Identity rules

`capture_id` is derived from verified input artifacts with domain separation
and length-prefixed fields. It does not contain paths, random values or wall
clock time:

```text
capture_id = SHA256(
    "fieldbook.capture.v1"
    || len(journal_manifest_sha256) || journal_manifest_sha256
    || ordered(len(segment_sha256) || segment_sha256)
    || len(orderbook_sbe_sha256) || orderbook_sbe_sha256
    || len(markets_json_sha256) || markets_json_sha256
    || len(report_json_sha256) || report_json_sha256
)
```

`journal_run_id` is the identity written by the journal writer. `export_id` is
derived from `capture_id`, `export_schema_version`, exporter commit, exporter
binary digest, PyArrow version and the export configuration hash. The three
identities are not interchangeable. A historical capture with
`code_commit = "unknown"` carries `journal_provenance_status =
legacy_incomplete`; the outer evidence source commit is a separate field and
is never used to infer the journal commit.

## Dataset boundaries

| Dataset | Row meaning | Primary identity |
|---|---|---|
| `journal_observation` | One journal record | capture, segment, ordinal |
| `sbe_message` | One decoded SBE message | capture, SBE hash, ordinal |
| `sbe_book_level` | One snapshot level | message, side, level ordinal |
| `capture_instrument` | One metadata instrument | capture, serialization symbol |
| `capture_price_range` | One metadata price range | instrument, range ordinal |
| `capture_tick_band` | One numeric tick band | instrument, band ordinal |
| `capture_run` | One capture summary | capture ID |

Journal observations and SBE projections stay separate. There is no join by
timestamp. `PriceLevelUpdate` carries the absolute quantity after collector
application, with `quantity_semantics = absolute_post_apply`; it is never an
exchange-observed delta. Snapshots use `snapshot_absolute`. Snapshot levels
come only from `Snapshot` messages.

## `journal_observation`

Arrow types follow the source exactly. Nullable fields keep null rather than a
substituted zero or empty string. Payload bytes stay in the journal; Parquet
holds the stable reference and digest.

| Column | Arrow | Nullable |
|---|---|---|
| `capture_id` | string | No |
| `run_id` | string | No |
| `journal_schema_version` | uint16 | No |
| `segment_index` | uint64 | No |
| `segment_file` | string | No |
| `segment_record_ordinal` | uint64 | No |
| `record_region_offset` | uint64 | No |
| `record_byte_length` | uint64 | No |
| `segment_file_sha256` | fixed_size_binary(32) | No |
| `source` | string | No |
| `shard` | uint16 | No |
| `replica` | uint16 | No |
| `connection_epoch` | uint64 | No |
| `observation_seq` | uint64 | No |
| `receive_seq` | uint64 | Yes |
| `control_seq` | uint64 | Yes |
| `clock_source` | string | No |
| `direction` | string | No |
| `record_kind` | string | No |
| `frame_kind` | string | Yes |
| `control_opcode` | string | Yes |
| `signal` | string | Yes |
| `signal_correlation` | binary | Yes |
| `heartbeat_mechanism` | string | Yes |
| `received_at_us` | int64 | No |
| `date` | date32 | No |
| `payload_length` | uint64 | No |
| `payload_sha256` | fixed_size_binary(32) | No |
| `decode_status` | string | Yes |
| `decode_events` | uint32 | Yes |
| `decode_reason` | string | Yes |
| `decode_category` | string | Yes |
| `send_status` | string | Yes |
| `send_error` | string | Yes |

`record_region_offset` is measured from the start of the segment record
region, after the segment header. Ordinals and offsets are zero-based.

## `sbe_message`

| Column | Arrow |
|---|---|
| `capture_id` | string |
| `sbe_file_sha256` | fixed_size_binary(32) |
| `message_ordinal` | uint64 |
| `message_kind` | string |
| `schema_id` | uint16 |
| `schema_version` | uint16 |
| `serialization_symbol` | string |
| `native_symbol` | string (nullable) |
| `mapping_status` | string |
| `received_at_us` | int64 |
| `exchange_timestamp_us` | int64 |
| `date` | date32 |
| `side` | string (nullable) |
| `price_mantissa_sbe` | int64 (nullable) |
| `quantity_mantissa_sbe` | int64 (nullable) |
| `quantity_semantics` | string |
| `snapshot_bid_levels` | uint32 |
| `snapshot_ask_levels` | uint32 |

`message_kind` is `snapshot`, `price_level_update` or `unknown`. An unknown
message keeps its ordinal and header information; a certified export rejects
it. Symbol mapping uses an exact multimap of `MarketInfo.symbol` to
`native_symbol`; duplicates produce `ambiguous`, never a first-match choice.

## `sbe_book_level`

| Column | Arrow |
|---|---|
| `capture_id` | string |
| `sbe_file_sha256` | fixed_size_binary(32) |
| `message_ordinal` | uint64 |
| `serialization_symbol` | string |
| `side` | string |
| `level_ordinal` | uint32 |
| `price_mantissa_sbe` | int64 |
| `quantity_mantissa_sbe` | int64 |
| `received_at_us` | int64 |
| `date` | date32 |

Levels come only from snapshots. Each parent identity resolves to exactly one
`sbe_message` row.

## Instrument metadata

`capture_instrument` preserves the `MarketInfo` fields: `exchange`,
`native_symbol`, `symbol`, `title`, `outcome`, `exchange_market_id`,
`close_time_us`, `tick_size_us`, `price_level_structure`, `price_scale`,
`quantity_scale`, `price_unit_kind`, `price_unit_code`, `quantity_unit_kind`,
`quantity_unit_code`, `quantity_step`, `lot_size`, `contract_multiplier` and
`metadata_sha256`. `price_ranges` and `NumericSpec.tick_schedule` are child
datasets. This is a capture-scoped metadata snapshot, not a historical
reference-data database. Matching symbol strings does not establish permanent
cross-venue identity.

## `capture_run`

`capture_run` carries `capture_id`, `venue`, `environment`, start/end/duration
in microseconds, `journal_run_id`, journal schema version, `journal_code_commit`,
`journal_provenance_status`, collector version, SBE schema ID/version,
expected/acknowledged/anchored symbols, exchange snapshots, SBE messages,
journal records, capture verification status, export verification status and
UTC `date`. The original `report.json`, `evidence.json` and verification
reports remain the authoritative artifacts; this table is a query projection.

## Accounting

For each capture independently:

```text
journal records = sum(segment record counts) = journal_observation rows
journal bytes   = sum(segment record-region bytes)
SBE messages    = snapshots + price updates + unknown
book levels     = sum over snapshots of (bid count + ask count)
instruments     = markets.json market count
```

Certified exports require `unknown = 0`. Every export publishes a manifest
with input hashes, dataset schema fingerprints, row counts, logical content
digests and Parquet artifact digests. Logical and artifact digests are
separate: a file hash alone does not establish logical equality.
