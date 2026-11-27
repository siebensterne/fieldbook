#!/usr/bin/env python3
"""Check source-level architecture invariants without documentation inventories.

Run from any working directory. --check is read-only and is used by CI. The
gate verifies source responsibility coverage, module reachability, runtime
integration anchors and falsifiable source anchors.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def mask_rust(source: str) -> str:
    """Blank comments and string literals, preserving offsets and newlines.

    Architecture anchors describe executable code. Matching the raw text would
    let a commented-out call or a string constant satisfy a requirement, so
    every source used for anchor matching is masked first.
    """
    output = list(source)
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        if char == "/" and source.startswith("//", index):
            end = source.find("\n", index)
            end = length if end == -1 else end
            for position in range(index, end):
                output[position] = " "
            index = end
            continue
        if char == "/" and source.startswith("/*", index):
            depth = 1
            cursor = index + 2
            while cursor < length and depth:
                if source.startswith("/*", cursor):
                    depth += 1
                    cursor += 2
                elif source.startswith("*/", cursor):
                    depth -= 1
                    cursor += 2
                else:
                    cursor += 1
            for position in range(index, cursor):
                if output[position] != "\n":
                    output[position] = " "
            index = cursor
            continue
        if char == "r" and index + 1 < length and source[index + 1] == "#":
            hashes = 0
            cursor = index + 1
            while cursor < length and source[cursor] == "#":
                hashes += 1
                cursor += 1
            if cursor < length and source[cursor] == '"':
                terminator = '"' + "#" * hashes
                end = source.find(terminator, cursor + 1)
                end = length if end == -1 else end + len(terminator)
                for position in range(index, end):
                    if output[position] != "\n":
                        output[position] = " "
                index = end
                continue
        if char == '"':
            cursor = index + 1
            while cursor < length:
                if source[cursor] == "\\":
                    cursor += 2
                    continue
                if source[cursor] == '"':
                    cursor += 1
                    break
                cursor += 1
            for position in range(index, min(cursor, length)):
                if output[position] != "\n":
                    output[position] = " "
            index = cursor
            continue
        index += 1
    return "".join(output)


# Anchors that are legitimately string literals: venue wire field names and an
# explicit fail-closed error message. They describe data/contracts, not calls,
# so matching them against raw source is intentional and narrowly allowed.
LITERAL_ANCHORS = frozenset({"tickSz", "lotSz", "network discovery is not implemented"})

# Every tracked Rust source module must have an assigned responsibility.
SOURCE_RESPONSIBILITIES = {
    "src/storage/application/network_source.rs": "loopback network source reusing the generic line parser, exact duplicate index and resume anchor",
    "src/distribution/cli.rs": "clap command model and CLI-to-settings overrides",
    "src/governance/config.rs": "configuration defaults, deserialization, and validation",
    "src/integrity/completeness.rs": "per-symbol feed-completeness accounting for captures: anchored vs unanchored deltas, quiet intervals",
    "src/integrity/coverage.rs": "per-symbol live-coverage certification: expected vs acknowledged vs snapshot-anchored symbols",
    "src/integrity/conformance.rs": "independent source conformance harness checking declarations, fixtures, typed output, rights and universe disclosure",
    "src/distribution/coordinator.rs": "startup, orchestration loop, discovery reconciliation, controls, shutdown",
    "src/acquisition/egress.rs": "egress policy: direct/proxy routing, fail-closed tunnelling, route provenance and redaction",
    "src/domain/fixed.rs": "fixed-point price/quantity parsing and checked arithmetic",
    "src/market_state/histogram.rs": "fixed-bucket stage-latency histograms, nearest-rank percentiles and unavailable-boundary reporting",
    "src/distribution/inspect.rs": "offline SBE capture inspection command",
    "src/domain/identity.rs": "persistent opaque instrument/venue/listing identities, effective-dated mappings and as-of resolution",
    "src/domain/framed_identity.rs": "versioned length-framed object identity derivation, strict format detection, parsing and fail-closed identity/subject registration",
    "src/integrity/journal.rs": "raw-frame journal writer, segment/manifest format, verification, ordered reading",
    "src/integrity/journal/tests.rs": "journal unit tests for framing, checksums, durability, recovery, and failure handling",
    "src/integrity/latency.rs": "latency experiment orchestration and result output",
    "src/acquisition/mod.rs": "acquisition plane module root for transport, codec, arbiter, packet evidence and supervision",
    "src/distribution/mod.rs": "distribution plane module root for CLI, coordinator, probe, metrics and inspect",
    "src/domain/mod.rs": "financial domain module root for taxonomy, identity, instruments, events and numeric types",
    "src/governance/mod.rs": "governance plane module root for adapter, config, rights and coverage certification",
    "src/integrity/mod.rs": "data integrity plane module root for journal, verification, replay and quality",
    "src/market_state/mod.rs": "market state plane module root for books, collector, recovery and protocol",
    "src/storage/mod.rs": "storage plane module root for archive, event store, analytics and reference application",
    "src/acquisition/transport.rs": "tokio TCP/UDP/multicast transport configuration, bounded datagram receive and packet metadata",
    "src/acquisition/codec.rs": "protocol codec registry with fail-closed decode batches and raw packet identity retention",
    "src/acquisition/evidence.rs": "durable packet evidence extension bound to stable journal positions with verification, durability profiles and staged dispositions",
    "src/acquisition/stream_slice.rs": "integrated source-to-evidence streaming slice with quality transitions, canonical records and journal replay verification",
    "src/acquisition/arbiter.rs": "dual-channel sequence arbitration with duplicate, gap, stale and out-of-order decisions",
    "src/acquisition/packet.rs": "raw packet evidence with payload digests and explicit-source journal mapping",
    "src/acquisition/supervisor.rs": "typed connection supervision with bounded retry and backoff decisions",
    "src/governance/adapter.rs": "universal source connector contract, machine-readable capability manifest with declared modalities, source registry and protocol vocabulary",
    "src/governance/connector_lifecycle.rs": "transport-independent connector lifecycle with rights-gated preflight, ordered phase transitions, quarantine branch, recorded decisions and replay verification",
    "src/governance/source_event.rs": "versioned v1 source-event metadata envelope with canonical JSON SHA-256 digest, typed rejection reasons, quality and continuity rules, quarantine admission gate and per-session sequence monotonicity",
    "src/governance/modality.rs": "typed acquisition ports by modality, declared modality capabilities, validation and independent raw/record envelopes",
    "src/governance/coverage_certification.rs": "ordered coverage statuses, country dossiers, rights- and quality-gated certification and coverage matrix",
    "src/domain/event_model.rs": "universal typed event envelope with multi-role timestamps, provenance, quality state and domain payloads",
    "src/domain/information.rs": "versioned institutional information payloads with bitemporal history, vintages, revisions and domain-specific structures",
    "src/integrity/quality.rs": "universal quality states, reason vocabulary, transition rules and two-sided reconciliation accounting",
    "src/domain/reference_data.rs": "effective-dated entity, venue, listing and specification graph with fail-closed identity resolution",
    "src/domain/reference_core.rs": "canonical object classes with opaque identity, identifier assertions and order-independent fail-closed resolution, append-only bitemporal assertion ledger and exact-dimension coverage cells",
    "src/domain/capability_registry.rs": "evidence-bound source, product and feed capability assertions with separate rights standing, four-outcome resolution, explicit coverage promotion allow-list and per-state coverage counts",
    "src/domain/instrument_terms.rs": "family-typed instrument terms with unit-bearing exact measures, checked integer arithmetic, typed contract families and instances, append-only bitemporal revisions and fail-closed conformance reporting",
    "src/domain/market_registry.rs": "versioned country packs with typed authority, venue, segment and product assertions, reference-validated insertion and four-outcome fail-closed registry resolution",
    "src/governance/rights.rs": "fail-closed licensing registry, typed authorization identity (actor, action, data object kind/id/version, recipient class and identity), action-object applicability matrix, exact versioned universe containment with recorded membership evidence, usage rights, decisions and entitlement authorization",
    "src/governance/egress_intent.rs": "explicit caller-supplied egress intent with typed actor, data object and recipient identity, applicability-conformant source-contact shape, endpoint authority and active authorization lease lifecycle",
    "src/governance/operation_plan.rs": "typed operation plans with independent actor/action/object/scope steps, provider-egress and local-data-use separation, side-effect boundaries, atomic full-plan authorization and step reauthorization",
    "src/domain/taxonomy.rs": "universal asset, instrument, information, depth, frequency and temporal classification with validated country and currency codes",
    "src/lib.rs": "library module exports and public entry points",
    "src/main.rs": "process entry point and collect/discover/replay/inspect/verify/completeness/coverage/latency dispatch",
    "src/distribution/metrics.rs": "metrics registry, Prometheus text encoding, HTTP health/metrics endpoint",
    "src/distribution/ndc_release.rs": "NDC v2 release producer: strict typed manifest and sidecar, RFC 8785 JCS, canonical record streams, dataset digests, injected-key signing, interruption recovery and no-replace durable publication",
    "src/distribution/ndc_wire.rs": "canonical NDC v2 Profile 1 wire mapping: strict typed wire values, byte-derived record ordering, full rights and PROV evidence, registration checks, conformance release assembly and exclusive release writing",
    "src/distribution/ndc_stream.rs": "bounded streaming NDC v2 producer: one-record source and framer, byte-derived incremental order check, stored and expanded digests, deterministic gzip staging, two-intent seal, replay proof and spool quarantine",
    "src/distribution/stream_profile.rs": "immutable versioned resource-profile contract with validated private limits, domain-separated digest, four processing roles and trusted local test-only selection",
    "src/bin/ndc-conformance-producer.rs": "conformance producer executable: abstract spec parsing, fixed test-only Ed25519 seed, canonical release writing and typed nonzero failure",
    "src/domain/model.rs": "normalized market, source, event, control, and output domain types",
    "src/market_state/orderbook.rs": "normalized order-book representation and mutation invariants",
    "src/distribution/probe.rs": "network-probe command: stage-timed egress transport diagnostic and JSON report",
    "src/market_state/protocol.rs": "shared venue-neutral transport vocabulary: frame class/direction, control opcodes, session signals, heartbeat mechanism, send result, and transport observations",
    "src/market_state/recovery.rs": "typed recovery policy: explicit causes, authorized actions, and bounded attempt decisions",
    "src/integrity/replay.rs": "deterministic JSONL replay into the collector/output path",
    "src/storage/report.rs": "market metadata and run-report sidecars; atomic JSON helper",
    "src/acquisition/session.rs": "generic websocket session/factory contract and supervised worker lifecycle",
    "src/domain/side.rs": "normalized buy/sell side semantics",
    "src/integrity/time.rs": "wall-clock and monotonic timing helpers",
    "src/integrity/verify.rs": "SBE delta-to-snapshot self-consistency verification",
    "src/storage/writer.rs": "bounded writer queue, dedicated writer thread, SBE sink lifecycle",
    "src/acquisition/ws.rs": "websocket connection options, source binding and connection experiments",
    "src/storage/capacity.rs": "startup and fixed-topology discovery capacity admission",
    "src/storage/catalog.rs": "versioned discovery checkpoint with integrity envelope, age, and counts",
    "src/storage/persistence.rs": "latest-wins metadata/catalog background writer and lifecycle status",
    "src/domain/products.rs": "typed data-product and source-capability contracts, deterministic subscription keys, and explicit subscription state transitions",
    "src/domain/canonical.rs": "canonical event envelope and normalized event taxonomy with deterministic opaque ids, explicit provenance, schema-versioned fail-closed reading, and a conceptual normalized store contract with a test-only in-memory implementation",
    "src/storage/application.rs": "generic non-market-data source/target reference application: SourceAdapter, JsonlSource with exact bytes/sequence/rejection evidence and duplicate detection, deterministic CanonicalBusinessEvent transform with separate source/receive time, six-category receipts and ExecutionMode, CommitSink seam, DeliveryObligation accounting, quarantine-before-progression runner, and side-effect-free replay connector",
    "src/storage/application/postgres.rs": "parameterized PostgreSQL SQL contract, target-specific idempotency keys, BEGIN/INSERT/UPSERT/COMMIT transcript builder, SqlExecutor seam and deterministic in-memory simulator with idempotency by event id, transaction commit/rollback and unavailable/ack-lost fault injection; no driver or live connection",
    "src/storage/application/file_source.rs": "bounded-memory BufRead line source with exact bytes, physical offsets, registered source identity, one-shot SHA-256 fingerprint, duplicate/schema/malformed evidence and a resume anchor bound to source identity, fingerprint and target",
    "src/storage/application/durable.rs": "local append-only checksummed fsync-capable commit store built on atomic JSON and sha2, one checksummed record carrying ids, dispositions/quarantines and checkpoint, reopen verification with fail-closed truncation/corruption checks, fault injection and a streaming pipeline runner",
    "src/storage/application/durable_segmented.rs": "versioned segmented local durability with explicit finalization and sync boundary, framed segments, checksummed recovery snapshot with bounded Bloom filter, verified archive manifest and restore, exact-scan lookup, fail-closed missing-evidence handling, and verified migration from the legacy commit-file store",
    "src/storage/analytics.rs": "offline analytics input verification, domain-separated capture identity and hash-checked artifact containment",
    "src/storage/analytics/tests.rs": "capture verification tests covering all three retained captures, deterministic identity, modified hashes and path traversal",
    "src/storage/analytics/export.rs": "streaming typed NDJSON export of verified journal observations, SBE projections and capture metadata into staging",
    "src/storage/analytics/export/tests.rs": "export tests for symbol ambiguity, unit parts, UTC dates and staged export of retained captures",
    "src/market_state/collector/mod.rs": "collector core module boundary",
    "src/market_state/collector/state.rs": "serialized per-symbol/source state machine, discovery and failover decisions",
    "src/market_state/collector/state/tests.rs": "collector state-machine tests for discovery, ordering, capabilities, snapshots, recovery, and readiness",
    "src/acquisition/exchange/mod.rs": "exchange capabilities and adapter-independent session factory abstraction",
    "src/util/aligned_sbe_reader.rs": "aligned SBE capture reader",
    "src/util/aligned_sbe_writer.rs": "aligned SBE chunk writer and sink helpers",
    "src/util/build.rs": "build-time SBE DTO/codec generation integration",
    "src/util/dtos.rs": "generated domain DTO bridge for supplied SBE schema",
    "src/util/mod.rs": "SBE utility module exports",
    "src/util/numeric.rs": "exact instrument-scale to SBE numeric conversion",
    "src/util/orderbook_schema.rs": "schema-facing book message definitions/adaptation",
    "src/generated/orderbook.rs": "checked-in SBE codec generated from the supplied schema and verified byte-for-byte by check_sbe_generated.py",
}

# Anchors that make the main structural claims falsifiable against code.
REQUIRED_ANCHORS = {
    "src/main.rs": [
        "Command::Collect",
        "Command::Replay",
        "Command::Inspect",
        "Command::Verify",
        "Command::Latency",
        "Command::Discover",
        "Command::Journal",
    ],
    "src/distribution/coordinator.rs": [
        "run_with_shutdown",
        "discover_with_retry",
        "process_worker_event",
        "dispatch_controls",
        "tokio::select!",
        "core.finalize",
        "writer.shutdown_with_stats",
    ],
    "src/storage/capacity.rs": [
        "derive_shard_count",
        "pub fn plan",
        "CapacityPlan",
    ],
    "src/market_state/collector/state.rs": [
        "apply_discovery",
        "handle_event",
        "handle_snapshot",
        "handle_level_change",
        "handle_lifecycle",
        "handle_stream_reset",
        "handle_status",
        "pub fn tick",
        "pub fn finalize",
        "fn reseat",
    ],
    "src/acquisition/session.rs": [
        "pub trait MarketDataSession",
        "pub trait SessionFactory",
        "pub async fn run_worker",
        "backoff_or_stop",
        "handle_control",
    ],
    "src/storage/writer.rs": [
        "pub struct WriterHandle",
        "pub async fn send",
        "shutdown_inner",
        "blocking_recv",
        "sync_on_close",
    ],
    "src/integrity/verify.rs": ["pub fn run"],
    "src/domain/identity.rs": [
        "pub struct InstrumentId",
        "pub struct ReferenceCatalog",
        "pub fn venue_mappings_from_markets",
    ],
    "src/domain/products.rs": [
        "pub enum DataProduct",
        "pub enum ProductKind",
        "pub struct SubscriptionSet",
        "pub struct SourceCapabilities",
        "pub fn from_legacy",
        "pub enum SubscriptionState",
        "pub struct SubscriptionLease",
    ],
    "src/domain/canonical.rs": [
        "pub const CANONICAL_SCHEMA_VERSION",
        "pub struct EventId",
        "pub struct SequenceMetadata",
        "pub enum CanonicalKind",
        "pub enum CanonicalEvent",
        "pub struct CanonicalEnvelope",
        "pub struct NormalizationContext",
        "pub struct CanonicalReader",
        "pub trait NormalizedStore",
        "pub struct InMemoryNormalizedStore",
    ],
    "src/acquisition/exchange/mod.rs": [
        "pub fn capabilities_for",
        "pub fn source_capabilities_for",
        "fn source_capabilities(&self) -> SourceCapabilities",
    ],
    "src/integrity/journal.rs": [
        "pub struct JournalHandle",
        "pub fn verify_run",
        "pub fn read_records",
        "pub fn read_observations",
        "struct Manifest",
        "struct SegmentFooter",
        "RunState::Finalized",
    ],
    "src/market_state/protocol.rs": [
        "pub enum SessionSignal",
        "pub enum FrameClassification",
        "pub struct TransportObservation",
    ],
    "src/market_state/recovery.rs": [
        "pub enum RecoveryAction",
        "pub enum RecoveryCause",
        "pub fn decide",
        "pub struct RecoveryTarget",
        "pub struct RecoveryFence",
        "pub struct InstrumentRecoveryQueue",
        "pub struct SourceRecoveryQueue",
        "pub struct RecoveryCoordinator",
    ],
    "src/util/build.rs": ["fn main()", "println!"],
    "src/storage/application.rs": [
        "pub trait SourceAdapter",
        "pub trait TargetConnector",
        "pub struct JsonlSource",
        "pub struct RawObservation",
        "pub enum SourceError",
        "pub struct CanonicalBusinessEvent",
        "pub enum DeliveryReceipt",
        "pub struct DeliveryObligation",
        "pub enum DeliveryState",
        "pub struct Checkpoint",
        "pub struct ImportReport",
        "pub struct ReplayConnector",
        "pub fn run_jsonl_to_target",
        "pub fn transform_observation",
        "pub mod postgres",
        "pub mod durable",
        "pub mod file_source",
        "pub enum ExecutionMode",
        "pub enum ReceiptCategory",
        "pub trait CommitSink",
        "pub fn run_jsonl_to_target_with_mode",
    ],
    "src/storage/application/file_source.rs": [
        "pub struct SourceFingerprint",
        "pub struct SourceIdentity",
        "pub struct SourceRegistry",
        "pub struct CheckpointBinding",
        "pub struct DurableCheckpoint",
        "pub struct FileSource",
        "pub enum DuplicatePolicy",
        "pub const MAX_LINE_BYTES",
        "impl<R: BufRead> SourceAdapter for FileSource<R>",
    ],
    "src/storage/application/durable.rs": [
        "pub struct CommitRecord",
        "pub struct CommitEnvelope",
        "pub struct CommitStore",
        "pub enum StoreFault",
        "pub struct DurableState",
        "pub fn open",
        "pub fn commit",
        "pub fn load_state",
        "pub fn run_streaming_pipeline",
        "impl CommitSink for CommitStore",
    ],
    "src/storage/application/postgres.rs": [
        "pub const INSERT_SQL",
        "pub struct ParameterizedStatement",
        "pub enum SqlValue",
        "pub fn generate_insert_statement",
        "pub fn generate_batch_statements",
        "pub enum PostgresFault",
        "pub struct PostgresSimulator",
        "pub struct PostgresTarget",
        "impl TargetConnector for PostgresSimulator",
        "impl TargetConnector for PostgresTarget",
    ],
}

# The P5 reference application must stay independent of market-data modules.
# These tokens are checked only against the two new source files.
REFERENCE_APP_SOURCES = (
    "src/storage/application.rs",
    "src/storage/application/postgres.rs",
    "src/storage/application/file_source.rs",
    "src/storage/application/durable.rs",
)
REFERENCE_APP_FORBIDDEN_TOKENS = (
    "crate::model",
    "crate::coordinator",
    "crate::collector",
    "crate::exchange",
    "crate::journal",
    "crate::replay",
    "crate::catalog",
    "crate::orderbook",
    "crate::writer",
    "crate::products",
    "ExchangeEvent",
    "MarketInfo",
    "MarketDataSession",
    "BookSnapshot",
    "LevelChange",
    "OrderBook",
)

MODULE_DECL_RE = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;\s*(?://.*)?$",
    re.MULTILINE,
)


def collect_module_reachability(root: Path = ROOT) -> set[str]:
    """Return source files reachable through `mod foo;` from lib/bin crate roots.

    This is a conservative source-tree check, not a Rust parser. Inline modules
    are not treated as separate files.
    """
    # `src/util/build.rs` is Cargo's configured build-script crate root (`build = ...` in Cargo.toml).
    roots = [
        root / "src/lib.rs",
        root / "src/main.rs",
        root / "src/util/build.rs",
        root / "src/bin/ndc-conformance-producer.rs",
    ]
    # The checked-in codec is pulled in through a macro-generated `include!`,
    # which this conservative module scanner cannot resolve. It is verified
    # byte-for-byte against the schema by check_sbe_generated.py instead.
    reachable: set[str] = {"src/generated/orderbook.rs"}
    pending = [path for path in roots if path.exists()]
    while pending:
        current = pending.pop()
        rel = current.relative_to(root).as_posix()
        if rel in reachable:
            continue
        reachable.add(rel)
        content = current.read_text(encoding="utf-8")
        if current.name in {"lib.rs", "main.rs", "build.rs", "mod.rs"}:
            module_dir = current.parent
        else:
            module_dir = current.parent / current.stem
        for match in MODULE_DECL_RE.finditer(content):
            name = match.group(1)
            candidates = [
                module_dir / f"{name}.rs",
                module_dir / name / "mod.rs",
            ]
            found = [candidate for candidate in candidates if candidate.exists()]
            if len(found) == 1:
                pending.append(found[0])
    return reachable


def module_integration_errors(root: Path = ROOT) -> list[str]:
    """Check falsifiable runtime call-site integration, not stale verdicts."""
    errors: list[str] = []

    # Check active source files reference missing dependencies
    config = mask_rust((root / "src/governance/config.rs").read_text(encoding="utf-8"))
    capacity_path = root / "src/storage/capacity.rs"
    if capacity_path.exists():
        capacity = mask_rust(capacity_path.read_text(encoding="utf-8"))
        collector_struct = re.search(
            r"pub struct CollectorSettings\s*\{(.*?)\n\}", config, re.DOTALL
        )
        declared = (
            set(re.findall(r"pub\s+(\w+)\s*:", collector_struct.group(1)))
            if collector_struct
            else set()
        )
        referenced = set(re.findall(r"settings\.collector\.(\w+)", capacity))
        for field in sorted(referenced - declared):
            errors.append(
                f"src/storage/capacity.rs references CollectorSettings.{field}, absent from src/governance/config.rs"
            )
    catalog_path = root / "src/storage/catalog.rs"
    catalog = mask_rust(catalog_path.read_text(encoding="utf-8")) if catalog_path.exists() else ""
    if catalog_path.exists() and "util::sha256_hex" in catalog:
        util_text = "\n".join(
            mask_rust(path.read_text(encoding="utf-8"))
            for path in sorted((root / "src/util").rglob("*.rs"))
        )
        if not re.search(r"\bfn\s+sha256_hex\b", util_text):
            errors.append(
                "src/storage/catalog.rs references util::sha256_hex, but no such function exists under src/util/"
            )

    coordinator = mask_rust((root / "src/distribution/coordinator.rs").read_text(encoding="utf-8"))
    required = {
        "capacity startup": "capacity::plan(&settings, &initial_markets)",
        "capacity refresh admission": "capacity::plan_fixed_topology(&settings, &markets, &loads)",
        "catalog loading": "Catalog::load",
        "persistence startup": "PersistenceHandle::start(",
        "persistence submit": "persistence.submit(",
        "persistence final drain": "persistence.submit_final(",
        "persistence shutdown": "persistence.shutdown(send_timeout)",
    }
    for name, anchor in required.items():
        if anchor not in coordinator:
            errors.append(f"runtime integration missing: {name} anchor `{anchor}`")
    return errors


def reference_app_independence_errors(root: Path = ROOT) -> list[str]:
    """Fail if the P5 reference app imports market-data modules or concepts."""
    errors: list[str] = []
    for rel in REFERENCE_APP_SOURCES:
        path = root / rel
        if not path.exists():
            errors.append(f"P5 reference source is missing: {rel}")
            continue
        source = mask_rust(path.read_text(encoding="utf-8"))
        for token in REFERENCE_APP_FORBIDDEN_TOKENS:
            if token in source:
                errors.append(f"{rel} contains market-data dependency token {token!r}")
    return errors


def collect_sources() -> list[str]:
    """Exercise collect sources."""
    return sorted(p.relative_to(ROOT).as_posix() for p in sorted((ROOT / "src").rglob("*.rs")))


def main() -> int:
    """Exercise main."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="check architecture traceability (read-only; used by CI)",
    )
    args = parser.parse_args()
    if not args.check:
        parser.error("this repository only supports read-only architecture checks; use --check")

    errors: list[str] = []
    errors.extend(module_integration_errors())
    errors.extend(reference_app_independence_errors())
    actual_sources = set(collect_sources())
    documented_sources = set(SOURCE_RESPONSIBILITIES)
    missing_docs = sorted(actual_sources - documented_sources)
    stale_docs = sorted(documented_sources - actual_sources)
    reachable = collect_module_reachability()
    unreachable = sorted(actual_sources - reachable)
    if missing_docs:
        errors.append(
            "source files need reviewed responsibility mappings: " + ", ".join(missing_docs)
        )
    if stale_docs:
        errors.append(
            "source responsibility mappings point to removed files: " + ", ".join(stale_docs)
        )
    if unreachable:
        errors.append("unreachable source files: " + ", ".join(unreachable))
    for anchor_path, anchors in REQUIRED_ANCHORS.items():
        file_path = ROOT / anchor_path
        if not file_path.exists():
            errors.append(f"required source anchor file is missing: {anchor_path}")
            continue
        raw_source = file_path.read_text(encoding="utf-8")
        source = mask_rust(raw_source)
        for anchor in anchors:
            literal_match = anchor in LITERAL_ANCHORS and anchor in raw_source
            if anchor not in source and not literal_match:
                errors.append(f"source anchor `{anchor}` not found in `{anchor_path}`")
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    reachable = collect_module_reachability()
    print(
        f"Architecture check passed: {len(actual_sources)} Rust source files, "
        f"{len(reachable)} files reachable from crate roots."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
