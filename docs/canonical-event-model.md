# Canonical event model

> **RRP-003 notice (2026-11-23).** Venue-specific examples and adapter references below describe families retired under RRP-003. They are retained as historical design rationale, not active capability claims. See `product-scope-retirement-2026-11-23.md`.

This document describes the **implemented** canonical event envelope and
normalized event taxonomy in `src/canonical.rs`. It is additive to the existing
challenge collector: the market-specific `ExchangeEvent` in `src/model.rs`
remains the collector/SBE/replay wire contract and is unchanged. Nothing here
changes SBE output, the raw-frame journal, replay JSONL, or catalog checksums.
No dependency is added.

## Why a separate taxonomy

`ExchangeEvent` is narrow by design: `Snapshot`, `LevelChange`, `Lifecycle`,
and `StreamReset`. It is the contract shared by adapters, the collector state
machine, the SBE writer, and replay. The canonical taxonomy separates kinds
that the wire contract cannot express without either mislabelling data or
fabricating an event:

| Canonical kind | Meaning | Source in Phase 1 |
|---|---|---|
| `book_snapshot` | Complete two-sided book anchor | exact `ExchangeEvent::Snapshot` conversion |
| `book_delta` | One level replacement or signed adjustment | exact `ExchangeEvent::LevelChange` conversion |
| `trade` | An executed trade | explicit trade observation only |
| `best_bid_offer` | Top-of-book quote, at most one level per side | explicit BBO observation only; **never** L2 |
| `asset_context` | Asset/venue-wide telemetry or reference context | explicit telemetry/asset observation only; **never** a book delta or anchor |
| `instrument_lifecycle` | Instrument reference-data lifecycle notice | exact `ExchangeEvent::Lifecycle` conversion |
| `stream_gap` | Unexplained missing sequence frame | explicit gap observation only; **never** a reset |
| `stream_reset` | Deliberate invalidation awaiting fresh snapshots | exact `ExchangeEvent::StreamReset` conversion |

The `From<&ExchangeEvent>` mapping is total and exact over the four wire
variants. It never produces a `Trade`, `BestBidOffer`, `AssetContext`, or
`StreamGap`. In particular Hyperliquid `allMids`/`fastAssetCtxs` observations
are `AssetContext`, never `BookDelta` and never a book anchor; Hyperliquid
`trades` are `Trade`, never `BookDelta`; a BBO quote is `BestBidOffer`, never an
L2 snapshot or delta. The tests named in the
[requirement-test matrix](requirement-test-matrix.md) pin each of these
boundaries.

## The envelope

`CanonicalEnvelope<T>` carries:

`event_id` — an opaque deterministic id derived with `OpaqueId::derive` from
  explicit provenance inputs (never a wall clock or display label);
`instrument_id: Option<InstrumentId>` and `feed_id: Option<FeedId>` from
  `src/identity.rs` — resolved identity, not a mutable title or symbol;
`source_id` — an opaque platform-assigned source identity, also from
  `src/identity.rs`;
`connection_epoch` and `sequence: Option<SequenceMetadata>` — local receive
  fence plus optional venue sequence, exchange clock, and receive sequence;
`source_time: Option<i64>` and `receive_time: i64` — copied exactly from the
  event metadata; receive time is never clamped or rewritten;
`raw_observation: Option<String>` — the raw bytes or a stable reference into
  the independent raw journal;
`schema_version` — `CANONICAL_SCHEMA_VERSION`, serialized with every envelope;
`payload: T` — one typed payload from the taxonomy, or the `CanonicalEvent`
  sum type.

`CanonicalEnvelope::from_exchange` copies receive time, connection epoch, and
ordering metadata exactly and takes the otherwise-unavailable identities and
provenance pointer from an explicit `NormalizationContext`. Missing identity
stays `None`; it is never guessed.

## Schema versioning and fail-closed reading

Envelopes serialize with `schema_version`. `CanonicalReader::decode` parses an
envelope and calls `validate()`, which rejects:

any `schema_version` other than `CANONICAL_SCHEMA_VERSION`
  (`UnsupportedSchemaVersion`);
a missing or blank `raw_observation` (`MissingProvenance`).

The same validation is applied by `NormalizedStore::append`, so an untrusted
envelope cannot enter even the test store. No serde attribute or field is added
to `ExchangeEvent` or `MarketInfo`; their formats are untouched.

## Implemented vs planned durability

**Implemented in Phase 1:** the typed taxonomy, the generic envelope, exact
`ExchangeEvent` conversions, schema-versioned serialization with a rejecting
reader, the conceptual `NormalizedStore` trait, and an in-memory
implementation (`InMemoryNormalizedStore`) used for tests. The trait only
defines `append(envelope) -> receipt` and `replay(from) -> iterator/provider`.

**Planned, not implemented:** a normalized durability store that persists
envelopes, supports replay from a durable position, and is reconciled against
the raw journal. PostgreSQL, generic connectors, retention policies, and any
production storage backend are explicitly out of scope. The in-memory store is
not durable, not concurrent, and is not a production subsystem.

## Boundaries and non-claims

- The **raw-frame journal is independent**. It records exact inbound payloads
  with its own format and verification. A canonical envelope carries a pointer
  to raw provenance; it is never the sole copy of the observation, and the
  journal is not derived from canonical events.
- The **SBE writer is one projection** of the collector's normalized book state.
  The canonical model is a separate, additive view; it does not replace or
  change the SBE writer.
No performance, scale, throughput, latency, live-coverage, or production
  readiness claim is made. The evidence is offline and contract-level only.
The collector remains **not a production certification** for order entry,
  execution, or trading. See `docs/architecture.md` and
  `docs/requirement-test-matrix.md` for the surrounding guarantees and evidence.
