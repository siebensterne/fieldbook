# FB-B15 — bounded streaming producer lifecycle, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**. Branch `feat/b15-streaming-producer`,
base commit `4e0f2f5`. No commit was created by this work package. This record
states scope, contract coverage and gate evidence. It is not a resource-profile
ratification, a durability certificate, a release, a rights grant, a dataset
acceptance or a verification promotion.

Authority: owner-ratified
`WS-STREAM-001-b15-b16-architecture-ratification.md` (2026-11-25) approves
architecture items A-01 to A-12 at contract level and defers every numeric
maximum. The source design is `b15-streaming-producer-design.md`, which keeps
its `PROPOSED / AWAITING OWNER APPROVAL` status. Both records live in the
siebensterne-workspace repository and are not copied into this one.

## Scope and freeze

The new path is `src/distribution/ndc_stream.rs` and the profile contract in
`src/distribution/stream_profile.rs`. The existing `build_release` interface
keeps its caller-owned `Vec<CanonicalRecord>` input and remains a compatibility
adapter. No claim of memory independence is made for that batch interface.

Rights stay `UNKNOWN`, dataset acceptance stays `BLOCKED`, the budget stays
INR 0, collection stays `DISABLED`, experiments stay `BLOCKED`, live execution
stays `DISABLED` and D11 remains strict. `PUBLICATION_DURABILITY_VERIFIED`
stays `false`. No provider was contacted, no market data was read or created
and no schema, wire byte, manifest field, receipt shape or approved digest was
changed.

## Contract coverage

| Ratified item | Implementation point |
|---|---|
| A-01 | `ArtifactRecordSource` returns one `CanonicalRecord`, reports end of stream and uses `BoundedRecordFramer` with a profile record bound; no whole-artifact slice or caller key |
| A-02 | Per-record processing with scalar counters, two incremental hashers, one predecessor key and one compressor instance |
| A-03 | `PreparationIntent` synced before consumption; `SealedPublicationIntent` synced as the seal; receipt, marker and rename follow the seal |
| A-04 | `parse_canonical_record` and `derive_order_key` recompute the key from emitted bytes; strict duplicate and decreasing rejection without a sort |
| A-05 | Dataset digest over ordered uncompressed streams; manifest and sidecar built by the shared `seal_manifest` step |
| A-06 | Incremental `GzEncoder` with the existing flate2 settings; no byte-pattern classification; unregistered codec identifiers fail closed |
| A-07 | Expanded and stored digests and the dataset accumulator updated over the exact emitted bytes |
| A-08 | Bound checks precede buffer growth; one reusable record buffer; parser bounds come from the profile |
| A-09 | Typed `StreamError` codes, cancellation checks at each boundary and no unearned availability stage |
| A-10 | Operation-scoped spool and staging paths with sealed evidence; `SPOOL_SEALED` is ledger-local evidence and not a third intent |
| A-11 | No shared runtime crate; only the ratified wire mapping and existing publication primitives are reused |
| A-12 | The Fieldbook receipt is built by the existing publication core; no Nirnay admission receipt is created |

## Resource profile

`ResourceProfileId { name, version }`, `ProcessingRole` with the four ratified
roles, `ResourceProfile { id, digest, role, limits }` and `ProfileLimits` are
immutable. Every field is private and is populated by one validating
constructor. Validation rejects zero and inconsistent relations, including a
per-artifact limit above its release limit, a chunk or parser bound above the
record bound, a queue above the record bound and a descriptor count below the
four-descriptor parallel set. The digest uses domain-separated SHA-256 over
every field.

Trusted local policy selects a profile by identifier and version. A producer
selects its own `PRODUCER` role; a verifier or recovery task cannot inherit the
producer profile. A production invocation has no approved profile to select
while the numeric maxima are deferred, so it refuses before any source opens.
Only finite profiles whose name carries `TEST_ONLY` are admitted, and only by
a `TestHarness` invocation. No test-only value is a production maximum or
PERF-001 evidence.

## Lifecycle, replay and quarantine

The `PreparationIntent` binds the operation id, ordered source plan, opaque
source snapshot identity, revision, replayability, role profile identifier and
digest, planned paths, ordering and compression literals and the replay
commitments. It is written and synced before the first record is read.

After every artifact reaches end of stream and the staged manifest and sidecar
are synced, the `SealedPublicationIntent` binds the preparation digest,
manifest, sidecar and dataset digests, the complete artifact inventory, stored
and expanded counts, the expected receipt and both profile identifiers. Only
that seal authorises the rename, receipt and availability stages. A crash or
cancellation before the seal leaves a preparation record and no sealed record;
recovery returns `PreparationOnlyQuarantined` and writes no receipt, marker or
final name.

The replay proof commits `source_content_digest`, record count, first key and
last key. A difference in any member, in the snapshot identity, in the profile
identifiers or in the stored and expanded digests returns
`SourceReplayMismatch` and quarantines before availability. A non-replayable
source is framed and written once to an operation-scoped spool under the
`temp_disk_bytes` bound, and a `SPOOL_SEALED` record carries its digests,
counts and keys. A truncated or altered spool returns `SpoolEvidenceMismatch`,
is retained with its evidence and is not adopted. Retention and purge of a
quarantined spool remain a separate owner decision.

## Compatibility and integration

The streaming path reuses `seal_manifest`, the receipt and evidence builder,
atomic no-replace rename, PUB-019 sync ordering, PUB-020 recovery, PUB-021
no-follow tree validation and the FB-REC-022 bounded readers. Compatibility
stage records are written at the seal for the existing v2 journal. No second
publication state machine, receipt shape or digest framing was introduced.
Byte identity with the registered batch encoder and the Profile 1 conformance
vectors is asserted for gzip, dataset digest, manifest and sidecar.

## Tests and evidence status

The work package adds 25 streaming tests and 8 profile-contract tests. Coverage
includes one-record-at-a-time consumption, a one-byte reader that rules out
unbounded line reads, byte-derived ordering, wrong domain, duplicate and
decreasing rejection, malformed and non-canonical bytes, gzip byte identity
and determinism, manifest and sidecar parity with the batch producer,
dataset-digest compatibility, record, memory-budget and codec boundary
refusals,
cancellation before and after seal, a crash before seal, one replay mismatch
case per committed member, source-identity mismatch, non-replayable spool
quarantine, unregistered codec refusal, production refusal without an approved
profile, a structural no-whole-artifact-vector assertion and a fresh-process
peak-RSS plateau test at 1x, 2x and 4x volume with a finite test-only profile.

The RSS samples are local test observations under a test-only profile. They do
not qualify a platform, filesystem or device tier. `STREAM_RESOURCE_PROFILE_RATIFIED`
is `PENDING`, `PERF_001_QUALIFIED` is `BLOCKED` and `OPERATIONALLY_QUALIFIED`
is `BLOCKED`. No `Implemented` state is promoted to `Verified` by this record.

## Gate evidence

Commands ran in the worktree with no commit. Each gate exited zero.

| Command | Outcome |
|---|---|
| `cargo fmt --all` and `cargo fmt --all -- --check` | applied; check passed |
| `python3 scripts/check_style.py` | clean |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | exit 0 |
| `python3 scripts/check_prose_unified.py --all` | PASS |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps --locked` | passed |
| `python3 scripts/check_rust_style.py` | passed on added lines |
| `cargo xtask fmt`, `lint`, `docs`, `style`, `test`, `verify` | all passed; 2 doc tests passed |
| `cargo test --workspace --all-targets --locked` | 831 library tests and all integration targets passed |
| `python3 scripts/check_architecture.py --check` | passed |
| `python3 scripts/check_naming_conventions.py` | passed |
