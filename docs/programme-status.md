# Programme status

This is the definitive status record for the engineering programme. Other
documents may describe design, history or intent; when a status statement here
differs from another document, this file is authoritative.

Status vocabulary is multi-dimensional:

| Column | Meaning |
|---|---|
| Code | Implementation exists in source |
| CI | Passes the repository's required checks on the integrated head |
| Opt-in | A conditional test/measurement was executed by an operator |
| Evidence | A manifest/artifact is retained in this repository with verified hash |
| Live | Validated against a permitted live venue |
| Perf | Throughput/latency/resource claim with reproducible measurements |

`N/A` means the dimension does not apply. `No` means it was not done — never
read `No` as a defect when the milestone did not claim that dimension.

## Crate identity

The crate, binary and Rust module are named `fieldbook`. Historical evidence
and source-export filenames retain the former identity `engineering-challenge`
where it was recorded at capture time. Those files stay byte-exact: rewriting
them would invalidate their SHA-256 hashes and the evidence chain. The SBE
wire identity — `schemaId`, `version`, template IDs and field IDs — is retained.
The package and module names are internal: `orderbook_messages` and `orderbook`.

## Analytics workstream

PR #17 (`3f4312f`) delivered P2.1: the verified streaming journal visitor,
with v1/v2 parity tests and a reader benchmark. P2.1a closes the visitor
metadata and second-pass verification gaps. Analytics milestones from P2.2
use the `AN-` prefix, which keeps them distinct from the existing
JSONL-to-target P5 and durable-file-to-target P6 applications.

## Global data infrastructure target

The V2 target architecture and six mandatory specifications are recorded in
`docs/global-data-architecture.md` and `docs/specifications/`. Additive Rust
modules declare taxonomy, identity, typed events, connector capabilities,
quality, rights and coverage certification. These are declarations with
tests, not claims of global coverage, licensed feeds or exchange-grade
latency. The live collector, SBE wire identity and retained captures remain
unchanged.

## Acquisition engine milestone

The V2 acquisition plane is implemented as additive modules under `src/acquisition/`. Loopback UDP receive, typed codec resolution, dual-channel sequence arbitration, raw packet evidence and bounded connection supervision are tested offline. No live venue, multicast deployment, FIX session, native binary feed, hardware timestamp or latency certification is claimed.

## Integrated acquisition programme

M3.0 (`ac93bbf`, PR #27) established bounded arbitration primitives, a versioned
packet-evidence envelope, fail-closed codec registration, typed normalization,
modality ports, independent coverage dimensions, bitemporal information
payloads and a fixture conformance harness. Those components were contracts
and primitives with deterministic fixture evidence; no production path claimed
them as connected.

M3.1.1 strengthens the governance layer. Authorization is scoped to provider,
source, dataset, product, territory, recipient class, purpose, usage right and
an effective interval. Conflicting decisions are refused at registration,
revocation takes effect at its recorded instant, and public access cannot imply
retention, derived-data use or redistribution. Coverage universes now require
supported identifiers to be a subset of expected identifiers, require an
explicit enumerated or unmeasurable declaration, and use a complete structured
identity key that rejects conflicting records. These are offline properties;
no source onboarding or live entitlement is asserted.

M3.1.2 connects packet capture to the raw-frame journal. A packet is written
as a journal data record with a locally assigned receive sequence before its
versioned extension is persisted. After finalization, extensions bind to the
stable `JournalPosition` of their journal record and verification requires a
one-to-one relationship with matching payload digests. Unknown extension
versions, duplicate bindings and unmatched journal records fail closed.
Durability profiles D1 through D3 are locally achievable; D4 and D5 are
refused rather than claimed without replication. Seven failure points are
exercised with explicit dispositions and accounting. No historical capture or
SBE wire contract changed.

M3.1.3 replaces entry-count limits with byte and entry budgets for every
retained arbiter collection. Arbiter state is private and exposed through
snapshots and metrics. A sequence domain is explicit and arbitration is
applied only to sources that declare compatible streaming sequence semantics.
Identical and conflicting duplicates are distinct verdicts, and every
submitted packet is offered to a raw-evidence sink before arbitration decides.
Restart state is captured and restored with bounds revalidated. Deterministic
reordering tests and injected faults exercise the budget and recovery paths.
Memory figures describe retained payloads and a fixed bookkeeping estimate,
not allocator occupancy or process RSS.

M3.1.4 connects the M3.0 primitives into one streaming slice. Five modality
ports have functional deterministic fixture implementations that declare only
their real capabilities. The slice journals each packet through the evidence
pipeline, orders it with the sequence arbiter, decodes through the codec
registry, produces typed records with a single raw-record reference, records
quality transitions, persists canonical records and replays the journal to
reconcile typed digests. `decode_normalized()` no longer copies raw bytes into
every event. A `std`-only benchmark compares the JSON interchange path with
typed normalization. On this Apple Silicon development host at 50,000
iterations of one fixed trade payload, the interchange path measured 171 ns per
operation and typed normalization measured 1,263 ns per operation. These are
measurements of one workload, not latency targets or production results.

M3.1.5 separates conformance into code-present, fixture-conformant,
integration-conformant, rights-approved, network-validated, live-verified,
history-reconciled and certified states. The harness runs the integrated
fixture path, validates rights and declarations, and reconciles replay against
the journal. External references are recorded as declarations, not passes, so
a fixture run, a successful connection or a successful writer cannot certify a
live dataset. No live collection or rights approval was added.

M3.1.6-A closes the rights and certification review findings. Authorization
revision keys now cover the complete identity rather than only the provider.
Decisions are checked for interval overlap, so non-overlapping permits and
prohibitions coexist while overlapping contradictions fail. Revocation has an
effective time and a later approved revision reauthorizes the source. Audit
evidence shape is validated before a decision is trusted. Coverage has one
evaluation oracle; `certify` stores its result and all certification queries
read that result. Evidence, history, operations, provider identity and universe
requirements cannot be bypassed by a legacy ordinal status.

M3.1.6-B closes arbiter bounded-state findings. The duplicate digest map is
pruned with the seen window and its estimated bytes are reported. Snapshot
restore validates collection sizes, byte totals, sequence uniqueness, digest
consistency and domain identity, then recalculates occupancy from restored
content. The raw-evidence sink is required and fallible; retention failure
stops arbitration and is recorded. Every submitted packet produces a durable
disposition, including duplicates, conflicts and stale packets. The Retain
fault now fires before retention.

M3.1.6-C closes evidence fidelity and acknowledgement findings. Packet
evidence now carries the original frame kind, and both the journal record and
the extension retain it. The extension also persists source protocol, codec
schema identity and version, sequence domain and receive sequence. The journal
returns a per-record acknowledgement tied to a concrete writer counter fence;
D1 waits for write, D2 for flush and D3 for sync, and the stored extension
carries that acknowledgement. D4 and D5 remain refused. Post-run binding uses
an indexed lookup with a fixed entry ceiling instead of nested full scans, and
extension rewrites stream through a bounded writer.

M3.1.6-D closes replay findings. Evidence identity now travels with each
sequence through the arbiter, so buffered drainage no longer reuses the last
arrival's identity. Each raw record produces an explicit processing
disposition covering acceptance, buffering, duplicate classes, stale, gap and
buffer rejection, and decode or normalization rejection. Replay reruns the
same arbitration from journal records and reconciles ordered event identities
and digests against canonical records instead of comparing digest multiplicity.
A reordered duplicate/stale scenario is covered by a reproducer test.

M3.1.6-E closes connector and conformance findings. Streaming fixtures filter
by subscription; snapshot pagination is part of the actual port; document
fixtures verify hashes against original bytes; on-chain fixtures carry parent
continuity and reorganization evidence. The conformance harness invokes an
actual modality connector, requires an explicit code reference, refuses a
vacuous rights check, and rejects observation kinds absent from the declaration
unless a documented policy allows them. Fixture conformance stays separate
from live certification.

M3.1.6-F closes the benchmark-methodology finding. A stage benchmark now
separates framing, protocol decode, typed conversion, identity stamping, raw
digest, arbitration, canonical persistence and evidence journaling. It uses a
payload, event-count and domain matrix with warm-up, repeated trials, median
and spread, allocation counts and peak live bytes. The earlier two-path
result is retained in the historical record, and both sets of numbers are
described as host-specific measurements rather than targets. Cargo profiles
are unchanged.

M3.1.6 is complete. All review findings have reproducer tests. M3.2 has not
started.

## Domain reorganisation

The source tree is organised by the six architectural planes. Modules moved
into domain directories; crate-root re-exports preserve public paths. Gate
maps, documentation references and fixture include paths were updated with the
move. No wire format, evidence artifact or capture changed.

## Integration history (exact commits)

| Commit | Integration |
|---|---|
| `d54aa08` | PR #45 — S1a/S1b, recovery M3/M4 foundation merged |
| `9ba0141` | PR #47 — M5.1 mixed workload evidence |
| `b885644` | PR #48 — M5.1-CERT accounting hardening |
| `aa52203` | PR #49 — CERT.1 event disposition closure |
| `27f8506` | PR #50 — M5.2 burst workloads |
| `14b8a94` | PR #51 — M5.5 backpressure |
| `65c2de1` | PR #52 — platform governance documents |
| `1aff42f` | PR #53 — Hyperliquid integration plan |
| `fdac36d` | PR #54 — M5.4 disconnect sweeps |
| `83c7251` | PR #55 — M5.3 lifecycle churn |
| `0137b95` | PR #56 — M5.6 stage instrumentation |
| `0efc74e` | PR #57 — M5.7 capacity stages |
| `8538cab` | PR #58 — Hyperliquid H0 reference data |
| `4f7ccb0` | PR #59 — Hyperliquid H1 telemetry |
| `d25c784` | PR #60 — Hyperliquid H2 books |
| `372da5b` | PR #61 — Hyperliquid H3 loopback harness |
| `b0885d9` | PR #62 — Coinbase H0 |
| `4088baa` | PR #63 — Kraken H0 |
| `4a68c64` | PR #64 — OKX H0 |
| `1488412` | PR #65 — Binance H0 |
| `9135a11` | PR #66 — GOV-002 programme status reconciliation |
| `432cd32` | PR #67 — Platform M2 persistent identity |
| `69f87c9` | PR #68 — Platform M3 typed data products |
| `a9a6b23` | PR #69 — Platform M4 canonical events |
| `127e926` | PR #70 — P5 JSONL-to-target reference application |
| `339b4ad` | PR #71 — final status reconciliation |
| `56d5960` | PR #72 — comment audit and duplicate roadmap removal |
| `0c669a2` | PR #74 — P6 durable file-to-target pipeline |
| `d856ee7` | PR #76 — xtask, Rust style guides and assurance hardening |
| `e647667` | PR #77 — real Hyperliquid wire decoding and live certification |
| `23fe17c` | PR #78 — live Hyperliquid reconnect recovery drill |
| `1445068` | PR #79 — Google/Linux style gates for all languages |
| `8fd25c0` | PR #80 — documentation opening refresh |
| `219f6c1` | PR #81 — audit anchor masking |
| `e9433fd` | PR #82 — stress drain timeout correction |
| `29456b3` | PR #83 — bounded fingerprint and visible xtask failures |
| `0e69638` | PR #84 — bounded duplicate index |
| `b3c45c4` | PR #85 — generic pipeline, PostgreSQL target and loopback TCP source |
| `ac33b81` | PR #86 — portable policy gates with strict isolation |
| `15d2993` | PR #87 — PostgreSQL checkpoint integrity hardening |
| `7edfb92` | PR #88 — bounded loopback socket waits |
| `a6f9fcb` | PR #89 — reconcile current head and live PostgreSQL evidence |
| `f86592b` | PR #92 — legacy PostgreSQL source-mapping integrity |
| `bc46abe` | PR #1 — canonical repository URL under `siebengestirn/fieldbook` |
| `48a42d7` | PR #2 — canonical repository URL under `siebensterne/fieldbook` |
| `cab6291` | PR #3 — durable runner supplies source position to real PostgreSQL target |
| `276e433` | PR #4 — `FIELDBOOK_TEST_PG_URL` replaces the legacy `nirnay` variable name |

PR #45 is **MERGED** (`d54aa08`); its earlier draft description was obsolete and
GitHub metadata now agrees with the integrated history. It was never merged
twice.

## Previous source export (2026-11-18)

The preceding source export identified `main` at
`e9433fd8ab84c6879399d8449bc8e8093de40d41`, following PR #81 (architecture
anchor masking and polish argument validation) and PR #82 (the bounded D10
reconnect-drain deadline correction). Its verification record reported
`cargo xtask ci` and `scripts/assurance/polish.sh` passing, 850 Rust tests and
37 Python tests passing, and four consecutive locked full-suite runs passing
before the PR #82 merge. Hosted run identifiers were not included. That count
is a historical record of the 2026-11-18 export and is not the current test
count; see `docs/synthetic-test-policy-2026-11-23.md` for the present gate.

## Subsequent integrations (reconciled in canonical Git)

The integration history table above is now sourced from the canonical Git
checkout, not only operator report. PRs #83-#85 added the disk-backed exact
duplicate index, the synchronous PostgreSQL target with migrations and the
opt-in live-server test, and the independent loopback TCP source with
reconnect/accounting tests. PR #86 adopted portable policy gates; PR #87
hardened PostgreSQL checkpoint integrity; PR #88 bounded loopback socket waits;
PR #89 reconciled the head and live evidence records. Each is identified by its
exact merge commit in the table above.

The source export `engineering-challenge-template-ac33b81.zip` has no `.git`
metadata and cannot by itself establish PR merge commits, branch cleanliness or
the operator's PostgreSQL run. Those facts are taken from the canonical Git
checkout and the retained evidence records instead of from the archive.

## Current source export (operator-reported head 169537b)

The operator reports canonical `main` at
`169537bdc931a3f9856d5f9b630efd2d4e0bce9c`, clean and pushed, after PRs #90
and #91. The uploaded `engineering-challenge-template-169537b.zip` contains no
`.git` metadata, so this export cannot independently establish its Git
ancestry, merge commits or working-tree cleanliness. The supplied report says
`cargo xtask ci`, `scripts/assurance/polish.sh` and all PR CI jobs passed.

PR #87 (`15d2993`) hardened PostgreSQL checkpoint integrity: the checksum
binds target, position and the last idempotency key; competing writers cannot
regress a checkpoint; and an event key reused with changed canonical content
fails closed. PR #88 (`7edfb92`) bounded loopback mock-server socket waits so
a loaded host cannot turn a healthy read into an uncertain receipt. PR #89
(`a6f9fcb`) reconciled the prior head and live evidence. PR #90 added
source-scoped durable PostgreSQL delivery. PR #91 excluded operator-local
`.local/` review files from the style scan and retained the merged-head live
PostgreSQL output. The exact PR #90/#91 merge commit IDs are not present in this
source export and are therefore not invented here.

Three retained evidence records are distinguished:

- `measurements/live/2026-11-18-postgres-checkpoint-integrity/` records the
  PASS on the earlier source commit `ac33b81`.
- `measurements/live/2026-11-18-postgres-checkpoint-integrity-head-7edfb92/`
  records the exact command, output and SHA-256 of the rerun from clean
  `main` at `7edfb92`.
- `measurements/live/2026-11-18-postgres-source-scoped/` records the
  source-scoped live test on the PR #90 branch, with `source_commit` naming the
  exact code commit that was executed.

The earlier record does not prove a later head passed; each head-specific
record proves only its own source commit. The merged record at
`measurements/live/2026-11-18-postgres-source-scoped-merged/` identifies test
commit `200bbf141e39002ce2f443679333eeac721b6ef3` and retains the exact
command, output and hashes. Its note states that the subsequent
style-gate/evidence-only change did not modify production source.
The operator reports the later `169537b` head and PR #91 CI as passing; this ZIP
cannot independently verify that Git relationship. None of these records is a
production certification.

## Historical reviewed baseline (operator-reported head f86592b)

The following record describes the reviewed source export that the
PostgreSQL streaming-runner patch was prepared against. It is retained for
provenance; it is not the current canonical head.

The operator reports canonical `main` at
`f86592b0ecd39f1e8501f28996a0a34152c58974`, clean and pushed, after PR #92.
The uploaded `engineering-challenge-template-f86592b.zip` has no `.git`
metadata, so this archive cannot independently establish the merge ancestry,
branch cleanliness or hosted CI result. The operator reports all Rust gates,
the assurance polish loop and the real PostgreSQL 18.6 legacy-mapping test as
passing.

The retained record at
`measurements/live/2026-11-19-postgres-legacy-source-mapping/` must be read
against its own manifest: `evidence.json` names
`169537bdc931a3f9856d5f9b630efd2d4e0bce9c` as `source_commit_at_test`. It
therefore proves the recorded run for that commit; it does not, by itself,
prove that the same test ran against `f86592b` or the PR #92 merge commit. A
separate merged-head record naming the exact tested commit is required before
classifying the final head as live-server tested. This distinction does not
invalidate the operator's report; it records what the retained artifact
currently proves.

## Durable streaming runner driving real PostgreSQL (certified)

The durable file and loopback TCP streaming runner now places an explicit
`SourcePosition` (source id, sequence, end-exclusive source offset) on every
`DeliveryRequest`. `PgTarget` validates that position against its bound source
and commits the exact position with the event and disposition in one
transaction. The separate mutable `set_position` mechanism is removed, so a
delivery always carries the position belonging to the event being delivered.
The runner stops at the first unresolved delivery, failed quarantine or failed
local checkpoint append, so no source position can advance past an unresolved
record. Malformed and transform-rejected records retain their exact raw bytes
in the durable quarantine record.

The opt-in live suite now covers the real file streaming runner driving
`PgTarget`, a committed target event whose local checkpoint append fails,
restart and replay from the earlier local checkpoint, PostgreSQL
deduplication of the already-committed event, and subsequent progression
without duplicate rows. The in-memory JSONL convenience runner is documented
as a simulation-only path and is not presented as a PostgreSQL execution path.

Live certification is retained at
`measurements/live/2026-11-19-postgres-streaming-runner/`. Its manifest names
the exact tested commit, the operator-provisioned PostgreSQL 18.6 server, the
command, and the SHA-256 of the complete test output.

## Bounded, ordered batch delivery (P6.1)

The generic runner can accumulate up to a bounded number of events and a
bounded number of encoded bytes before delivering them as one
`DeliveryBatch`. Each member carries its own source id, sequence and
end-exclusive offset; the batch is rejected if members belong to another
source, are unordered, or exceed the hard limits. The runner flushes a pending
batch before quarantining a malformed record and stops at the first unresolved
transaction or failed local checkpoint append, so no source position overtakes
an unaccounted record.

`PgTarget` commits a whole batch in one transaction: one insert per member,
one disposition per member, and one terminal checkpoint update. The event
table persists each member's source position, so a retry can be checked
against the full persisted canonical content and position rather than only a
final offset. The local `CommitStore` writes one checksummed record per batch,
which removes the per-event local fsync from the batched path.

Simulator evidence: `tests/bounded_batch.rs` covers event/byte limits,
oversize quarantine, one local record per batch and batch-validation failures.
Live evidence: `tests/postgres_batch_live.rs` covers three real-server
scenarios — bounded batch delivery, replay after a failed local append with a
different batch size, and exact retry versus a changed payload — with no
partial rows surviving a conflicting batch. The pre-batching single-event
baseline is retained at `measurements/perf/p6-1-single-event-baseline/`.

## Segmented local durability (P6.2)

The production-shaped runner depends on the `DurableStore` abstraction and
works unchanged with the legacy commit-file store and the segmented store.
File and loopback TCP sources both deliver through the segmented store.

A segment holds multiple framed commits and is bounded by record count and
encoded bytes. Record append, footer, rename and directory sync are separate
operations, and fault injection sits at each boundary. An interrupted segment
is recovered as active (or finalized when its footer is present), never
silently discarded. Snapshot replacement is decoupled from every commit and
replays the tail after its frontier.

Finalized segments rotate into an archive once the hot limit is exceeded. The
archive copy, checksummed manifest and hot removal are ordered so evidence is
verified before the hot copy is removed. Lookup scans both hot and archived
segments; the Bloom filter proves only absence, and an unreadable history
returns an error rather than a negative result. Recovery validates header,
frame, footer, filename and checksum fields and bounds live memory to the
snapshot plus the replay tail. Legacy files migrate explicitly and remain in
place.

Design decisions are in `docs/segmented-durability-design.md`. Real-filesystem tests in
`tests/segmented_durability.rs` and integration tests in
`tests/segmented_runner.rs` cover finalization boundaries, rotation,
archive verification and restore, exact lookup, migration and both source
adapters.

## Source-scoped durable delivery (PR #90, operator-reported merged)

The PostgreSQL target namespaces checkpoints by
`(target_id, source_id, output_contract_version)`. Event and disposition rows
carry source identity, and the checksum binds all three identity dimensions
plus sequence, byte offset and the last idempotency key. `PgTarget::with_source`
rejects an envelope from a different source. Legacy rows stay in an explicit
empty-source namespace and are moved only by the operator-controlled
`assign_legacy_checkpoint_source` procedure. The procedure validates the
historical checksum, re-keys corresponding event/disposition rows, verifies
that their identity sets and the checkpoint's final-event anchor agree, and
rebinds the checksum in one transaction. The operator must assert that the
legacy target/contract stream belonged to one source; a mixed-source legacy
stream cannot be separated safely after the fact. The opt-in live test
exercises two sources on one physical target, per-source restart reload, stale
writers, foreign-source envelopes, exact retries, changed payloads, a failed
checkpoint race, resumable legacy mapping and concurrent writers. Command,
output and hashes are retained in
`measurements/live/2026-11-18-postgres-source-scoped/`. This is an implemented
and live-tested integration, not a production certification or a throughput
claim.

## Milestone status

| Milestone | Code | CI | Opt-in | Evidence | Live | Perf |
|---|---|---|---|---|---|---|
| S1a/S1b journal v2 | Yes | Yes | N/A | Yes (v1/v2 golden fixtures) | N/A | N/A |
| Recovery M3/M4 | Yes | Yes | N/A | Yes (blast-radius tests) | No | No |
| M5.1 mixed workload | Yes | Yes | N/A | Yes (v5 manifests) | No | No |
| M5.1-CERT / CERT.1 | Yes | Yes | N/A | Yes (v5 manifests, disposition tests) | No | No |
| M5.2 burst | Yes | Yes | Reference Step executed | Yes (v16 step manifest in bundle) | No | No |
| M5.3 lifecycle | Yes | Yes | Reference executed | Yes (v16 lifecycle manifest in bundle) | No | No |
| M5.4 disconnect | Yes | Yes | Reference executed | Yes (v16 sweep manifest in bundle) | No | No |
| M5.5 backpressure | Yes | Yes | Reference executed | Yes (v16 profiles bundle) | No | No |
| M5.6 stage timing | Yes | Yes | Workload-dependent | Synthetic stage histograms; no full v16 timing report retained | No | Synthetic measurements only; no performance certificate |
| M5.7 capacity | Stages 4k/10k/25k/50k present | Deterministic selectors CI-tested | 10k short cell executed | Yes (v16 10k manifest in bundle); 25k/50k not executed | No | No capacity claim |
| Hyperliquid H0 | Yes | Yes | N/A | Golden fixture + live REST discovery | Yes (read-only mainnet) | N/A |
| Hyperliquid H1 | Yes | Yes | N/A | Telemetry fixtures + real frames | Yes (read-only mainnet) | No |
| Hyperliquid H2 | Yes | Yes | N/A | Books e2e + retained live captures | Yes (read-only mainnet) | No |
| Hyperliquid H3 | Yes | Yes | Reference executed | Yes (v16 Hyperliquid manifest in bundle) | No | No |
| Coinbase/Kraken/OKX/Binance H0 | Yes | Yes | N/A | Golden reference fixtures | No | No |
| GOV-002 | Yes | Yes | N/A | v16 evidence bundle + ledger | N/A | N/A |
| Platform M2 identity (Phases 1-3) | Yes | Yes | N/A | 11 identity tests | No | N/A |
| Platform M3 products (Phase 1) | Yes | Yes | N/A | Product/capability/state-machine tests | No | N/A |
| Platform M4 canonical events (Phase 1) | Yes | Yes | N/A | Canonical conversion/schema tests | No | N/A |
| P5 JSONL-to-target | Yes (simulator + source-scoped synchronous PostgreSQL `PgTarget`) | Yes | Live source-scoped PostgreSQL test PASS on the PR #90 code commit | Exact command, output and hashes retained in the source-scoped evidence record | Opt-in server test only; no production certification | No |
| P6 durable file-to-target | Yes (local durable store, file source, `PgTarget`, loopback TCP source) | Yes | Source-scoped PostgreSQL test PASS; loopback reconnect tests in CI | Source/tests and source-scoped live DB output retained | Opt-in PostgreSQL test PASS; TCP source remains loopback-only; no production certification | No |

## Contract foundation vs live integration

This table is the authoritative distinction between an implemented contract and
an integrated production path. Do not read a foundation as a production
capability.

| Capability | Contract foundation | Live integration | Production certification |
|---|---|---|---|
| Persistent identity | Implemented (`src/identity.rs`) | Partial/not migrated into collector ownership | No |
| Typed products | Implemented (`src/products.rs`) | Not consumed by legacy session `apply_subscriptions` | No |
| Canonical events | Implemented (`src/canonical.rs`) | Not authoritative live pipeline | No |
| JSONL-to-target | Generic source/target runner with deterministic simulator and source-scoped real `PgTarget` (`postgres::Client`) | Opt-in live source-scoped PostgreSQL PASS with command, output and hashes retained in `measurements/live/2026-11-18-postgres-source-scoped/` | No production certification |
| Local reference commit store | Implemented (`src/application/durable.rs`): append-only checksummed fsync records, reopen verification, fault injection | Single-writer local filesystem only; no replication or multi-host durability | No |
| Streaming file source | Implemented (`src/application/file_source.rs`): bounded `BufRead`, exact bytes/offsets, fingerprint-bound resume | File ingestion plus a loopback TCP source; network-source tests use a local server and do not certify a production network adapter | No |
| PostgreSQL execution | Synchronous `postgres` driver, `PgExecutor`, `PgTarget`, explicit migration and database idempotency/checkpoint tables; bounded ordered single- and multi-event batches in one transaction | Opt-in live server tests PASS for batches, exact retry, changed payload and replay; per-source monotonic checkpoints; no connection pool, failover soak or replication | No |
| Hyperliquid | H0-H3 implemented; H1/H2 wire codecs fixed from real frames | Read-only mainnet captures in `captures/`, including a reconnect drill; no orders | No |
| Additional H0 venues | Reference data only | No live product integration | No |

## Live validation

The operator reports that `captures/INDEX.md` records five real, direct,
read-only Hyperliquid mainnet captures with source commits, configurations,
raw journals, SBE files, verification reports and SHA-256 manifests. Two clean
`HL_LIVE_OK` runs and one `HL_LIVE_RECOVERY_OK` reconnect drill pass all
acceptance criteria: exact selected-universe coverage, exchange-originated
snapshots, valid SBE reconstruction, complete journals, zero decode/writer
errors and reconciled accounting. The two failed captures are retained as
evidence that exposed the wire-shape, precision and accounting defects.

The `captures/` directory is Git-ignored and is not present in this source
export. Consequently, the live evidence and its SHA-256 manifests are not
independently verifiable from this archive; use the evidence-bearing checkout
and validate each manifest before relying on those claims.

Synthetic loopback (`evidence_class = synthetic-loopback`) is not live
evidence. Polymarket live connections remain disabled because permitted access
from the operator's estimated location was not documented; Kalshi remains an
opt-in authenticated read-only test with no live capture claimed.

## Evidence bundle

`measurements/stress/m5-v16-bundle/` contains nine v16 reference manifests and
`ledger.json` with per-file SHA-256, workload, status and provenance fields.
These are deterministic **synthetic loopback** runs: burst, lifecycle churn,
disconnect sweep, backpressure profiles, 10k capacity, Hyperliquid H3, plus
three failed cells. They establish test execution and fail-closed
behavior; they are not live venue or capacity certifications.

The main `measurements/stress/index.json` retains the earlier v2–v5 reference
cells. New v16 evidence is in the bundle, not mixed into that index, so old
hashes remain unchanged.

## Ignored tests

The synthetic live, capacity and reference-generator tests were retired under
RRP-002. Historical counts in this record are immutable; the current permitted
surface and withdrawn coverage are recorded in
`docs/synthetic-asset-retirement-2026-11-23.md`.

## Governance

`main` is protected: PR required, CI required on the exact head, merge commits
only, force push and branch deletion disabled, strict freshness. Local branch
inventory is `main` only; one worktree; zero stashes. See
[`git-workflow.md`](git-workflow.md) and the dated GitHub protection audit.

## Not claimed

Replicated/multi-site durability, end-to-end exactly-once to external targets,
distributed runtime, nanosecond clock accuracy,
or any live venue certification. Platform M2/M3/M4 are additive contract
foundations (Phases 1-3 / Phase 1): they do not yet rewire collector ownership,
subscription consumption or the SBE writer. P5 includes a deterministic
simulator and a real synchronous PostgreSQL `PgTarget` behind the generic
target contract. P6 adds a **real local durable
store**, a streaming file source, and an independent loopback TCP source. The
PostgreSQL driver applies the parameterized transcript with database uniqueness,
transactions and checkpoint progression; its opt-in live test is operator-run
and is not part of CI. The loopback TCP source proves parser reuse, reconnect
resume, malformed-line accounting and a 2,000-record test soak; it is not a
production network-source certification. None of these components is wired
into the market-data collector, and no replication, production deployment or
performance claim is made.
