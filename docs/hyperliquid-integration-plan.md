# Hyperliquid integration plan

> Retired under RRP-002 (owner directive D11). The synthetic market-data
> assets described below have been removed from the active tree. This text
> is retained only as a historical record; no command or path in it is
> executable. See `docs/synthetic-asset-retirement-2026-11-23.md`.

**Status:** H0 reference data, H1 telemetry, H2 selected books/trades and H3
  capacity expansion (synthetic loopback) implemented. This document defined the
  staging contract before implementation.
**Branch:** `feat/hyperliquid-telemetry` (H1), `feat/hyperliquid-books` (H2), `feat/hyperliquid-capacity` (H3); the plan originated on `docs/hyperliquid-integration-plan`.
- **Scope:** plan the next exchange after the M series on the existing collector
  seams.
- **Reading rule:** every statement below is either labelled **Current**
  (verifiable in this tree) or **Planned** (a decision to implement later).
  H0-H3 are claimed as implemented, but H3 evidence is **synthetic loopback
  only**: no live capture, live certification, latency performance or
  capacity/throughput result is claimed. Where a wire detail is not pinned by a
  checked-in fixture, it is marked **verify at H0** or explicitly deferred.

The collector today ingests Kalshi and Polymarket prediction-market books only.
Hyperliquid
is a different asset class (perpetual and spot crypto), a different
reference-data shape
(DEX scope, token indices, non-.`[0,1]` prices), and a partly different feed model (full-book
snapshots and high-rate statistics rather than deltas). The plan stages that
difference so
that each increment is independently falsifiable.

## 1. Existing adapter seams (Current)

Inventory taken from the code on this branch. These are the only sanctioned
extension points.

| Seam | Exact location | Contract |
|---|---|---|
| `Exchange` trait | `src/exchange/mod.rs` | `name()`, `environment()`, `capabilities()`, `discover_markets(max)`, `discover_markets_with_stats(max)` (default provided), `session_factory(self: Arc<Self>)`, `lifecycle_session_factory()` (default `None`). |
| `ExchangeCapabilities` | `src/exchange/mod.rs` | One field: `has_sequence_clock: bool`; `ExchangeCapabilities::new(bool)`; `capabilities_for(ExchangeKind)` maps Kalshi→`false`, Polymarket→`false`. |
| `DiscoveryResult` / `DiscoveryStats` | `src/exchange/mod.rs` | `markets: Vec<MarketInfo>` plus page/selected/outcome/malformed/retry/duration timestamps. |
| `MarketDataSession` | `src/session.rs` | `heartbeat_spec()`, `connect()`, `apply_subscriptions(&BTreeSet<String>)`, `next_frame()`, `send_keepalive()`, `request_snapshot(&[String])`, `close()`. |
| `SessionFactory` | `src/session.rs` | `create_session(SourceId) -> Box<dyn MarketDataSession>`. |
| `SessionFrame` / `SessionFailure` | `src/session.rs` | Frame carries `events`, `raw: Option<RawFrame>`, `decode`, `signal`, `mechanism`, `observations`, optional `transport_failure`; failures are `Reconnect`, `Decode`, `Protocol`, `Fatal`. |
| `HeartbeatSpec` / `HeartbeatRequest` | `src/session.rs` | Presets `ten_second_application_text()`, `ten_second_websocket_control()`, `disabled()`, plus `validate()`. |
| Supervisor | `src/session.rs` | `run_worker` owns reconnect/backoff, heartbeat tracking, `(connection_epoch, receive_seq)` receive fence, `Control` handling, and emits `WorkerEvent::{Events,Status,Subscribed,RecoveryReady,Fatal,Stopped}`. |
| Protocol vocabulary | `src/protocol.rs` | `FrameKind`, `FrameDirection`, `ControlOpcode`, `FrameClassification`, `HeartbeatMechanism::{ApplicationText,WebSocketControl,Disabled}`, `SessionSignal::{MarketData,HeartbeatRequest,HeartbeatAck{correlation},PeerPing,PeerPong,ProtocolControl}`, `SendResult`, `TransportObservation`. |
| Normalized events | `src/model.rs` | `ExchangeEvent::{Snapshot,LevelChange,Lifecycle,StreamReset}`; `MarketInfo`; `NumericSpec`; `Price`/`Quantity`/`QuantityDelta`; `PriceBand`; `Ratio`; `EventMeta`; `Control::{SetSubscriptions,RequestSnapshot,Recover,Reconnect,Shutdown}`; `OutputMessage`; `SourceId`; `SourceStatus`; continuity/heartbeat state enums. |
| Numeric pipeline | `src/fixed.rs`, `src/util/numeric.rs` | `SCALE = 1_000_000`, `DECIMALS = 6`, `MAX_SCALE = 18`; `parse_scaled`, `rescale_exact`; `price_to_sbe`/`quantity_to_sbe`/`level_to_sbe` rescale exactly and **reject inexact** values. |
| Composition | `src/coordinator.rs`, `src/config.rs` | `build_exchange(settings, require_auth) -> Arc<dyn Exchange>` matches the configured `ExchangeKind`; `ExchangeKind`, `FileConfig`/`Settings`, `COLLECTOR_EXCHANGE` env, per-venue settings. |
| Adapter layout | `src/exchange/kalshi/{mod,auth,codec,discovery,session}.rs`, `src/exchange/polymarket/{mod,codec,discovery,session}.rs` | One module per venue; `codec` decodes wire→`ExchangeEvent`, `discovery` builds `MarketInfo`, `session` implements both session traits. Kalshi additionally provides a credentialed lifecycle plane. |
| Journal | `src/journal.rs` | `JOURNAL_SCHEMA_VERSION = 2`, `DecodeOutcome::{Decoded,Ignored,Rejected}`, `RawFrame`, `JournalHandle`; `read_records()` is data-only, `read_observations()` includes typed data/control observations; checksummed segments and manifest. |
| Recovery | `src/recovery.rs` | `RecoveryAction::{RefreshInstruments,ReconnectSource}`, `RecoveryCause`, `RecoverySignals`, `RecoveryDecision`, pure `decide()`; bounded, fenced by `(source, instrument, generation)`. |
| Evidence | `src/verify.rs`, `src/completeness.rs`, `src/coverage.rs`, `src/capacity.rs`, `src/catalog.rs` | SBE reconstruction; per-symbol anchoring; three-set coverage; capacity `plan`/`count_selected_markets`; checksummed catalog checkpoints. |
| Test harness | `tests/e2e_mock_exchange.rs`, `tests/full_universe_stress.rs`, `tests/lifecycle_churn.rs`, `tests/hyperliquid_capacity.rs`, `tests/stress_support/{mock,hyperliquid}.rs`, `fixtures/kalshi/`, `fixtures/polymarket/`, `fixtures/hyperliquid/`, `fixtures/journal-v*-golden/`, `docs/stress-lab-design.md` | Loopback wire mocks (Kalshi and Hyperliquid), deterministic stress ledger, JSON protocol fixtures, golden journals. |

Dependency direction is fixed: adapters depend on the normalized model and
protocol vocabulary,
`CollectorCore` depends on capabilities and normalized events (not on a websocket library), and
the coordinator owns composition. A new venue must be added behind these seams,
not by branching
the state machine.

## 2. Staged deliverables, gates, and non-goals

| Stage | Deliverable | Evidence gate | Stage non-goals |
|---|---|---|---|
| **H0 — reference data** | `HyperliquidSettings` and `ExchangeKind::Hyperliquid` in `config.rs`; `build_exchange`/`capabilities_for` arms; `src/exchange/hyperliquid/{mod,codec,discovery,session}.rs` skeleton; REST `/info` discovery for `meta` (every configured DEX) and `spotMeta`; emit validated `MarketInfo` with DEX/spot-qualified `native_symbol` and full `NumericSpec`; catalog checkpoint round-trip. | `discover` produces a deterministic catalog; every `MarketInfo` passes `MarketInfo::validate()` and `NumericSpec::validate()`; record/outcome counts reconcile with `DiscoveryStats`; golden `meta`/`spotMeta` fixtures include two DEXs sharing a coin name and spot token-index forms; no socket is opened. | No subscriptions, no book events, no live claim, no ADR-0001 reference-model migration, no spot book. |
| **H1 — low-complexity feeds — IMPLEMENTED** | Subscribe and decode `allMids` and `fastAssetCtxs`; classify as telemetry only; journal typed observation evidence with exact raw bytes; heartbeat policy is `Disabled` (no fixture proves a venue heartbeat, and telemetry must not satisfy one). `assetCtxs` is **not subscribed**: no golden fixture pins its wire shape, so adding it is deferred. | Golden fixtures for mid maps and context arrays with unknown additive fields and malformed numeric values; codec table tests; journal v2 round-trip; **zero** new `Snapshot`/`LevelChange` events and **zero** new coverage anchors proved by `tests/hyperliquid_telemetry.rs`; numeric strings parsed exactly or rejected. | No claim of book coverage, no depth derivation, no market-order/execution view, no synthetic books, no `assetCtxs` subscription. |
| **H2 — selected books/trades — IMPLEMENTED** | 10–20 explicitly selected perpetuals (configurable finite list, default 10, main DEX only); `l2Book` full snapshots → `ExchangeEvent::Snapshot` with exact receive time and advisory feed timestamp; trades parsed as telemetry but kept out of book deltas; exact subscription reconciliation; recovery via existing `Control::{RequestSnapshot,Recover}` fences. | Per-symbol `coverage` certificate for the exact selected set (`expected == acknowledged == anchored`); `completeness` valid (no unanchored deltas); `verify` and `journal verify` pass; one reconnect drill re-anchors with a fresh `l2Book` in a new `connection_epoch`; zero `LevelChange`. Received and feed timestamps are kept as separate `EventMeta` fields with a clockless (receive-fence-only) declaration. | Full universe, spot books, cross-DEX consolidation, order entry, "all coins covered" claims, latency/throughput/capacity results. |
| **H3 — capacity expansion — IMPLEMENTED (synthetic loopback)** | Hyperliquid loopback wire mock in `tests/stress_support/hyperliquid.rs` serving `meta` discovery, subscribe/unsubscribe, `allMids`, `fastAssetCtxs`, `l2Book`, trades and a scripted reconnect; seed-derived workload profiles (mid fan-out, fast-context rate, book refresh cadence, trade bursts, reconnect recovery); reuse of the shared stress ledger, dispositions, three-set hashes, manifest schema and `scenario_version = 16`. | `tests/hyperliquid_capacity.rs` proves exact 10-instrument coverage, a reconciled ledger/dispositions, bounded writer queue, journal/SBE integrity, zero `LevelChange` and recovery under reconnect for three profiles; an ignored reference generator publishes a v16 manifest under `STRESS_MANIFEST_OUT` without overwriting existing evidence. | Production or live certification, order-entry/execution guarantees, spot books, a full-universe subscription, latency percentiles, throughput/capacity results, treating synthetic runs as live evidence. |

Cross-stage non-goals: no trading, positions, strategy or pre-trade risk; no
change to the SBE challenge schema; no silent rounding of precision; no claim
that ADR-0001's instrument/listing model is implemented; no new external
dependency without the existing dependency-governance gate.

### 2.1 H1 implementation notes (Current)

`HyperliquidSettings` carries `ws_url` and a telemetry subscription list, both with defaults
  so H0 configurations still deserialize. The session subscribes to exactly `allMids` and
  `fastAssetCtxs`; `assetCtxs` is rejected by the subscription builder because no golden fixture
  pins its wire shape (§6). Unknown additive wire fields are ignored; recognised
numeric strings
  are parsed at SBE scale 6 or the whole frame is rejected.
`src/exchange/hyperliquid/telemetry.rs` decodes frames into typed mids/context observations
  and returns no `ExchangeEvent`. `src/exchange/hyperliquid/session.rs` wraps each accepted
  payload as a raw journal data frame with `SessionSignal::ProtocolControl`, zero events, and
  `HeartbeatMechanism::Disabled`. Telemetry advances only the data receive fence; it never
  satisfies a heartbeat, anchors a book, or advances instrument activity.
Fixtures: `fixtures/hyperliquid/all_mids{,_malformed}.json`,
  `fast_asset_ctxs{,_malformed}.json`, and `fast_asset_ctxs_wire.json` (an exact frame
  retained from a live mainnet capture). The historical "malformed" fixtures
carry a value
  with seven fractional digits: that is real venue precision, so it is retained
verbatim
  with no SBE coefficient rather than rounded or rejected. Non-decimal strings
and broken
  envelopes are rejected. The wire fixture pins the vendor-published base64 +
raw DEFLATE
  JSON-object format. Additive fields (including high-precision
funding/open-interest
  fields) are present in the valid fixtures and ignored.
Idle/quiet-feed behaviour is unchanged: liveness remains the worker's
  `connection_idle_timeout_secs` plus frame receipt. No latency, capacity or performance claim
  is made by H1.

### 2.2 H2 implementation notes (Current)

`HyperliquidSettings.books.perpetuals` is a configurable finite list of perpetual coin
  names on the main DEX (default ten). H2 subscribes to `l2Book` and `trades` for exactly
  the intersection of the worker's desired set with that list; spot identities
and unlisted
  perps are never subscribed. `native_symbol = hyperliquid:perp:<dex>:<coin>` is inherited
  from H0, and a non-empty wire `dex` stays in scope rather than being consolidated.
`src/exchange/hyperliquid/books.rs` decodes `l2Book` `levels[0]`/`levels[1]` as complete
  bid/ask arrays; every accepted push becomes one `ExchangeEvent::Snapshot` whose
  `EventMeta.received_at_us` is the transport read time and whose `exchange_ts_us` is the
  advisory feed `time` (milliseconds converted to microseconds). There is no venue sequence,
  so `seq`/`clock` stay `None` and `has_sequence_clock` stays `false`; the supervisor stamps
  `(connection_epoch, receive_seq)`. Unknown additive fields are ignored; price/size strings
  are parsed exactly at SBE scale 6 or the whole frame is rejected. Empty and
one-sided books
  are still snapshots and still anchor.
Trades are decoded and validated using the same numeric rules, then surfaced as
a raw
  `SessionSignal::ProtocolControl` observation with zero events. No `LevelChange` is ever
  constructed: the H2 codec has no delta path at all.
`apply_subscriptions` reconciles to the exact desired set (subscribe additions,
  unsubscribe removals); `request_snapshot` maps to unsubscribe/resubscribe of only the
  selected symbols, that is "wait for the next venue-pushed `l2Book`".
`Control::Recover` uses the existing `RecoveryReady` receive fence; with
`reconnect: true` the fresh book arrives in a later connection epoch and is
therefore strictly newer than the acknowledgement.
Fixtures under `fixtures/hyperliquid/` cover two-sided, one-sided, empty and deep books,
  malformed/numeric-boundary cases, unknown additive fields, and trades. `tests/hyperliquid_books.rs`
  drives the real worker/journal against a loopback mock and proves the H2
evidence gate.
  All coverage, completeness, verify and recovery evidence is
loopback/synthetic; there is no
  live venue, latency, throughput or capacity claim.

### 2.3 H3 implementation notes (Current)

`tests/stress_support/hyperliquid.rs` adds a deterministic loopback venue. One
  HTTP endpoint answers `/info` `meta` discovery for the exact ten selected
  perpetuals; the websocket side records subscribe/unsubscribe commands and
  pushes an explicit, seed-derived schedule of `allMids`, `fastAssetCtxs`,
  `l2Book` and `trades` frames. Connection *n* serves epoch *n+1*, so a
  `Control::Recover { reconnect: true }` opens a fresh socket and re-anchors the
  books in a newer connection epoch. The SplitMix64 streams are domain-separated
  so changing one channel's frame count cannot perturb another's values.
Three declared profiles change only frame counts (never wall-clock timing):
  `balanced`, `telemetry_heavy` (high mid/fast-context fan-out) and
  `book_refresh_burst` (fast `l2Book` cadence plus trade bursts). `l2Book` prices
  and sizes are a stable function of the coin, so consecutive full snapshots
  reconstruct identically for `verify`; only the advisory feed `time` advances.
The cell reuses `EventLedger`, `two_sided`, `ledger_acceptance_reasons`,
  `canonical_set_sha256`, `manifest` publication and `SCENARIO_VERSION` (now 16)
  from the shared stress harness. Each accepted `l2Book` snapshot is the unit of
  applied work and its SBE snapshot message is the persistence record; the
  ledger's delta/disposition fields are populated from the real `CollectorStats`
  (they are zero on this venue, not `unavailable`). Telemetry and trades remain
  `ProtocolControl` observations and never produce a book event.
Manifests carry `evidence_class: "synthetic-loopback"`,
  `hyperliquid.live_certification: false` and
  `hyperliquid.latency_or_capacity_claim: false`. **This evidence is not live
  certification and makes no latency, throughput or capacity performance
  claim.** Only a permitted live run may emit live tiers.

## 3. Product-level completeness: what each feed can and cannot prove

The existing evidence tools answer different questions and must not be
substituted for one
another. `coverage.rs` defines **anchored** as "has at least one snapshot in the capture";
`completeness.rs` requires that no delta precedes that baseline; `verify` checks delta→snapshot
reconstruction; the journal records what the wire recorded. A mid price is
none of these.

**`allMids` does not prove book coverage.** It is a venue-wide map of coin→mid price. It
  proves the channel is alive, that coin names are recognized, and that price
strings parse. It does not prove `l2Book` subscription for any coin, that a
two-sided book exists, that any level has depth, or that a single symbol is
anchored. It typically also names coins outside the selected set (other DEXs,
non-canonical spot pairs), so counting mids as coverage would *overstate* the
universe. Planned H1 rule: never emit `Snapshot` or `LevelChange` from
  `allMids`, and never let it advance a book symbol's activity.
**Asset context does not prove depth.** `fastAssetCtxs`/`assetCtxs` carry per-coin statistics
  (mark/oracle prices, funding, open interest, volume, and similar fields —
**verify at H0**)
  at high frequency. There are no price levels, no cumulative quantity, and no
top-of-book
  size. A rapidly updating context is not evidence that a book is fresh,
continuous, or even
  subscribed. Planned rule: context is telemetry; it must not satisfy a
heartbeat, an anchor,
  or a stale-probe budget.
**`l2Book` is the only in-scope Hyperliquid feed that can anchor a book.** It pushes complete
  two-sided level arrays (a snapshot feed, not a delta feed — **verified at H2**
against the
  golden fixtures). Each accepted push maps to `ExchangeEvent::Snapshot`, which seeds/re-anchors
  continuity. Because there is no delta stream, there is no `LevelChange` from Hyperliquid
  books; continuity relies on the supervisor's receive fence plus the existing
freshness
  policy, not on gap detection.
**Trades are prints, not level changes.** Mapping a trade into `LevelChange` would corrupt
  book state and SBE output. H2 rule (implemented): decode trades as telemetry
with
  `SessionSignal::ProtocolControl`; never synthesize book deltas or snapshots from them.
A credible claim therefore requires the conjunction: journal evidence of exact
wire frames,
  `verify` for reconstruction, `completeness` for anchoring, `coverage` for the exact expected
  set, and recovery evidence for continuity across incidents.

## 4. Identity mapping

`native_symbol` is the key of `CollectorCore.markets` and the subscription unit; `symbol` is the
namespaced SBE serialization identity. Neither is an ADR-0001 instrument
identity.

**4.1 Perpetual (DEX + coin).** Identity scope is `(hyperliquid, perp, dex, coin)`. The DEX is
part of the key because the same coin text may exist on more than one DEX; a bare `BTC` would
collide in the book map. `native_symbol = "hyperliquid:perp:<dex>:<coin>"`. Set
`exchange_market_id = None` for perps (there is no parent grouping): `count_selected_markets`
then falls back to `native_symbol` and counts each perpetual once. Only explicitly configured
DEXs are discovered; an unconfigured DEX is out of universe, not silently added.

**4.2 Spot (base/quote).** Identity scope is `(hyperliquid, spot, base, quote)` with token
indices retained as mapping metadata. Wire coins may appear as `<BASE>/<QUOTE>` or as token
indices such as `@<n>` — **verify at H0** against `spotMeta`. Discovery must resolve token index
→ token name and normalize to base/quote. `native_symbol = "hyperliquid:spot:<BASE>/<QUOTE>"`.
Where a base/quote pair has canonical and non-canonical variants, default to
canonical only;
non-canonical pairs are excluded or suffixed with the index — never merged silently. `outcome`
is `None` (this is not a prediction market), and `exchange_market_id` is `None`.

**4.3 Precision and instrument specs.** Map `szDecimals` to `quantity_scale` plus `quantity_step`
(`10^-szDecimals`) and any published minimum to `lot_size`; map the venue price-tick rule to
`price_scale` and one or more `PriceBand`s in `NumericSpec.tick_schedule` (origin and phase
**verify at H0**). Set `price_unit = PriceUnit::Currency("USDC")` for perpetuals and the quote
currency for spot; choose `QuantityUnit::Contracts` versus `Currency(base)`/`Lots` in H0 and
freeze it. Every wire value is parsed with `fixed::parse_scaled` into `i64` and validated by
`NumericSpec::validate()` (scales ≤ `MAX_SCALE = 18`, lot a multiple of step). Output conversion
uses `util/numeric::{price_to_sbe,quantity_to_sbe}`; values not exactly representable at the
canonical `DECIMALS = 6` scale are **rejected with evidence**, never rounded. Perps whose tick
cannot be represented at SBE scale are excluded from H2 selection and recorded
as a precision
non-goal.

**4.4 Output symbol compatibility.** Keep the `<namespace>:<...>` SBE format. Proposed
`symbol` mirrors `native_symbol`: `hyperliquid:perp:<dex>:<coin>` and
`hyperliquid:spot:<BASE>/<QUOTE>`. Bare coin text must not be reused: a multi-venue capture
would then be ambiguous. The output symbol remains a serialization mapping, not
an instrument
identity (ADR-0001). Freeze the format in H0 — later changes invalidate catalog
checksums and
break comparison against earlier evidence.

## 5. Capability declaration for Hyperliquid

**Current:** `ExchangeCapabilities` has only `has_sequence_clock`, and `capabilities_for` is a
two-arm match. Hyperliquid's planned value is `false`: public feeds publish no cross-replica
comparable sequence number (a feed `time` field, **verify at H0**, is advisory and belongs in
`EventMeta.exchange_ts_us`, never in gap detection). The supervisor's
`(connection_epoch, receive_seq)` fence remains the ordering authority.

**Planned extension** (requires editing `exchange/mod.rs`, `capabilities_for`, core config and
their tests; not implemented by this document):

| Dimension | Declaration | Consequence |
|---|---|---|
| Ordering | Receive-fence only; advisory feed timestamp | No sequence-gap discontinuities from venue data; continuity from fences + freshness policy. |
| Snapshot support | Full venue-pushed snapshots on `l2Book`; no request/ack snapshot opcode (**verify at H0**) | `request_snapshot` maps to resubscribe/wait-for-next-push; `Control::Recover` still fences by receive_seq and re-anchors before deltas. |
| Heartbeat | `HeartbeatMechanism::Disabled` unless H0 fixtures prove an application ping/pong; native WS controls handled by `ws.rs`/`protocol.rs` | Liveness from frame receipt + `connection_idle_timeout_secs`; `heartbeat_disabled` prevents `RecoveryCause::HeartbeatFailure` from authorizing a reconnect. |
| Replay | Venue has no public history; journal schema v2 is the sole replay source | `replay` drives the same `CollectorCore` from journal/fixtures; no venue replay claim. |
| Backpressure | Unchanged bounded writer/journal | Frames are journaled before core dispatch; journal enqueue timeout fails the run, never silently drops. |
| Lifecycle plane | No separate lifecycle channel | `lifecycle_session_factory()` returns `None`; `capacity.rs` allocates zero lifecycle replicas; new instruments enter via REST discovery. |
| Subscription scope | Subscribe/unsubscribe by coin within one DEX scope | `apply_subscriptions` reconciles the exact desired set; DEX scoping per source is fixed in H0. |

## 6. Test strategy (H0-H3 implemented)

**Protocol fixtures.** `fixtures/hyperliquid/` mirroring the existing layout: `meta` for two
  DEXs with a shared coin name and `spotMeta` with index and pair forms (`reference.json`, H0),
  plus `all_mids`, `all_mids_malformed`, `fast_asset_ctxs`, and `fast_asset_ctxs_malformed` (H1).
  H1 fixtures include unknown additive fields (ignored, not rejected) and
inexact numeric values
  (rejected, not rounded). Golden bytes are retained for journal replay. H2 adds `l2_book`
  (two-sided/one-sided/empty/deep, malformed numeric, unknown additive fields) and `trades`
  (valid and malformed) fixtures. Venue subscribe/unsubscribe acknowledgement
wire shapes are
  not pinned by a checked-in fixture, so no acknowledgement-specific behaviour
is claimed.
**Numeric precision.** Table-driven boundary values for price and size scales, `szDecimals`
  high-precision cases rejected at SBE scale 6, tick-grid and `NumericSpec::validate()` checks,
  and `price_to_sbe`→`price_from_sbe` round-trips. Negative prices remain valid in the model;
  HL-specific price domains are a fixture assertion, not a global rule.
**Latency.** Record `EventMeta.received_at_us` and the feed timestamp as separate fields with
  an explicit clock type; percentiles over fixed one-second bins per `docs/stress-lab-design.md`
  §6. Latency is reported, never gated in CI.
**Recovery (H2 implemented).** `RecoveryReady` acknowledgements enumerate exact symbols;
  `request_snapshot` resubscribes only selected books; a reconnect drill proves a fresh `l2Book`
  re-anchors in a new `connection_epoch` before any promoted non-snapshot data. The existing
  receive fence and freshness policy remain the ordering authority; no venue
clock is used.
**Journal and evidence (H2 implemented).** `tests/hyperliquid_books.rs` drives the real worker
  with a v2 journal against a loopback mock and proves exact raw bytes, `MarketData` book
  observations, `ProtocolControl` trade observations, zero `LevelChange`, valid `coverage`,
  `completeness` and `verify`, and `journal verify`. `journal verify`/`journal recover` on
  checked-in golden journals and broader replay assertions remain planned; v1
readability remains
  untouched.
**Stress-lab reuse (H3 implemented).** `tests/stress_support/hyperliquid.rs` is
  the HL wire mock per `docs/stress-lab-design.md` §9; it reuses the event ledger,
  disposition accounting, three-set coverage hashes, manifest schema and failure
  classification. HL workload shapes: mid fan-out, fast-context rate, `l2Book`
  refresh cadence, trade bursts and disconnect/recovery. `tests/hyperliquid_capacity.rs`
  certifies the three profiles for the exact ten-instrument universe and an
ignored
  generator emits a versioned manifest under `STRESS_MANIFEST_OUT`. Synthetic
  results never satisfy a live tier and carry no latency/capacity claim.

## 7. Implemented / current versus planned

| Item | Status |
|---|---|
| `Exchange`, `SessionFactory`, `MarketDataSession`, `SessionFrame`, typed protocol/journal vocabulary, `ExchangeCapabilities` (one field), normalized `ExchangeEvent`, `NumericSpec`, exact numeric conversion, catalog, recovery policy, completeness/coverage/verify, stress lab | **Current** — in this tree, cited in §1. |
| Kalshi and Polymarket adapters behind those seams | **Current** — public prediction-market books only. |
| Hyperliquid H0 discovery, settings, adapter module, identity map, reference fixtures | **Current** — deterministic two-DEX `meta`/`spotMeta` discovery behind the existing seams. |
| Hyperliquid H1 telemetry session, codec, golden telemetry fixtures, zero-event journal evidence | **Current** — `allMids`/`fastAssetCtxs` only; `assetCtxs` not subscribed; no book events, anchors, heartbeat satisfaction, live capture, coverage or latency claim. |
| Hyperliquid H2 selected books/trades: exact selected universe, `l2Book` snapshots, trade telemetry, reconciliation, recovery drill, golden fixtures, loopback evidence | **Current** — configurable finite perpetual set (default 10, main DEX only); exact receive timestamps and receive fences; zero `LevelChange`; `coverage`/`completeness`/`verify`/`journal verify` pass on loopback. No spot books, full universe, live venue, latency performance or capacity claim. |
| Hyperliquid H3 capacity expansion: stress wire mock, workload profiles, 10-instrument deterministic cells, v16 manifests | **Current** — seed-derived loopback mock serving `meta`/WS channels/reconnect; balanced, telemetry-heavy and book-refresh-burst profiles; exact coverage, reconciled ledger/dispositions, bounded queues, journal/SBE integrity, zero `LevelChange` and reconnect re-anchoring proved by `tests/hyperliquid_capacity.rs`. Synthetic loopback only: no live capture, no production certification, no latency/throughput/capacity claim. |
| Hyperliquid capability breadth extension and live evidence | **Planned** — not implemented. |
| ADR-0001 instrument/listing reference model | **Accepted design, not implemented**; this plan does not depend on it and does not claim it. |

## 8. Follow-on exchange template (Binance / Coinbase / Kraken / OKX — not implemented)

Reuse this order for each venue; do not implement several at once.

**Config and identity.** Add settings and a connector selector arm; decide the
venue-native
   scope (product type, venue/DEX/market segment, symbol) that must be part of `native_symbol`.
   `ExchangeKind` is a connector selector, not a venue registry (ADR-0001); prefer a shared
   connector for venues with the same protocol instead of one variant per
facility.
**Reference data.** REST discovery → `MarketInfo` + `NumericSpec` for the chosen products;
   define venue-specific identity rules (base/quote vs contract vs token), freeze `symbol`
   format, and validate counts against `DiscoveryStats`.
**Adapter module.** `src/exchange/<venue>/{mod,codec,discovery,session}.rs`; implement both
   session traits and the `Exchange` trait; no state-machine branch.
**Capability declaration.** Fill every dimension in §5: ordering (is there a
   cross-replica sequence or feed clock?), snapshots (request/ack vs streamed vs
   delta-only), heartbeat (text/native/disabled), replay, backpressure,
   lifecycle plane, subscription scope.
**Event mapping.** Only genuine full books become `Snapshot`; only genuine deltas become
   `LevelChange`; statistics/trades are telemetry until a separate normalized event is designed.
   Never manufacture depth.
6. **Evidence plumbing.** JSON protocol fixtures, exact numeric tests, journal
   v2 observations, replay golden cases.
7. **Containment tests.** Per-symbol coverage, completeness, verify, typed
   recovery drills, and a loopback wire mock in the stress lab with the shared
   ledger and manifest schema.
8. **Staged rollout.** Reference → stats → selected books → capacity, each with
   its own gate; live evidence only from a permitted connection, with access
   restrictions respected.

Venue-specific questions to answer before step 2 (not answered here): Binance —
spot vs USDⓈ-M /
COIN-M futures, combined vs raw streams, book tick weights, update-speed
cadence; Coinbase —
product/level versus advanced-trade feeds, sequence numbers, heartbeat channel;
Kraken — asset
pairs versus instrument names, snapshot/delta semantics, sequence/heartbeat
behavior; OKX —
spot/swap/futures `instType` scoping, books/ Books5 versus delta channels, checksum/sequence
support. No endpoint, symbol, or capability is asserted for these venues.

## 9. Key decisions

1. DEX and market type are part of Hyperliquid identity; bare coin text never
   keys a book.
2. H1 statistics are telemetry and must not anchor books or satisfy
   heartbeats/staleness.
3. Only full-book snapshots can anchor; trades never become book deltas.
Precision is exact or rejected at SBE scale 6; no rounding, with unsupported
   ticks excluded.
`has_sequence_clock` stays `false`; capability breadth is a separate, explicit planned change.
6. Each stage has a falsifiable evidence gate; no live or production claim from
   synthetic runs.
7. Venue additions are template-driven behind the existing seams; no
   state-machine changes.
