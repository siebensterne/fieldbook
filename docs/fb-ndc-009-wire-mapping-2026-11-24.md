# FB-NDC-009 — Canonical NDC v2 Profile 1 wire mapping, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**, 2026-11-24. Branch
`feat/ndc-wire-mapping` at base commit
`2ef88a955f74a7c88e4573683267446e331465e9`. No commit was created by this
work package. This record is a dated scope and gate statement, not a schema
artifact, a release, a rights grant or a verification promotion.

Authority: owner-ratified `WS-NDC-2026-11-24-003` in workspace
`engineering/decisions/WS-NDC-2026-11-24-003-canonical-profile-1-wire-schema.md`
and the canonical schema package in
`engineering/conformance/ndc-v2-schema-profile-1/` (package digest
`6e8c1e48e27289b8c3d3e959a06a805e736d0759b4fb244edbb074f65e107bab`).
The internal Rust types in `src/distribution/ndc_release.rs` are mapping
inputs; the canonical schema is the wire authority. Frozen boundaries remain
unchanged: rights `UNKNOWN`, dataset acceptance `BLOCKED`, budget INR 0,
collection `DISABLED`, experiments `BLOCKED`, live execution `DISABLED` and
D11 strict.

## Scope

One new module `src/distribution/ndc_wire.rs`, its module-root declaration,
one conformance producer executable `src/bin/ndc-conformance-producer.rs`,
one `[[bin]]` registration, an abstract spec vector at
`docs/specifications/ndc-conformance-producer-spec-example-2026-11-24.json`,
one architecture responsibility entry per new source file, a bin reachability
root in `scripts/check_architecture.py`, this dated record and a README
document-map row. No approved byte, historical digest, key, release, dataset,
provider contact, right, experiment, India feed, live route or journal entry
was edited or created. No shared crate was introduced.

## Wire mapping

The internal pre-ratification sections carry opaque references and omit
several required canonical members. The mapping therefore constructs every
wire member explicitly from named values and a typed abstract evidence
supplement. It emits a single root `contract_version`, decimal-string
instants matching `^(0|[1-9][0-9]*)$` within the u64 range, the required
non-empty venue and segment scope, structured performed operations with
operation evidence bound by `operation_ref`, full typed rights evidence with
matching embedded and registered attestations, nine typed coverage dimensions
with declared denominator, count basis and exhaustive arithmetic, complete
PROV lineage with a current revision, an immediate-predecessor `supersedes`
relation and a canonical UTC `invalidated_at_time`, a tagged
`record_order_profile` object, registered string `compression_version`
identifiers and a versioned per-event payload schema registry. A producer
`PASS` is admitted only when the independent arithmetic and evidence checks
agree. Unknown fields, missing fields, duplicate names, wrong types and
unregistered identifiers fail with a typed `WireError`. No implicit default,
coercion or placeholder exists in this path.

The canonicalizer is the existing RFC 8785 JCS implementation in
`src/distribution/ndc_release.rs`; the wire module chooses its own member
names and validates its own values before emitting a `JcsValue`. Counts and
byte sizes use a JSON integer below 2^53 or a decimal string by value. No
binary floating point reaches an exact quantity.

## Byte-derived ordering

`sort_byte_derived` parses each canonical record line, extracts the tagged
`ordering` object, checks its mode, domain and epoch against the containing
artifact profile, derives the key from the parsed values, sorts and returns
the same validated input bytes. The `order_key` member on the internal
`CanonicalRecord` is not read. The abstract spec carries a caller-supplied
`claimed_order_key` that disagrees with the record bytes; the executable
copies it into the internal field only to demonstrate that the derived path
ignores it. Sequenced keys compare sequence numbers numerically; reference
keys compare object identity, revision, knowledge time and assertion
identity. Duplicate keys with differing payloads fail closed. Event time is
not a sort key and no gap is filled or fabricated.

## Conformance producer and signing vector

`cargo run --bin ndc-conformance-producer -- --spec <path> --out <dir>`
parses the abstract spec, maps and signs the release, and writes
`manifest.json`, `signature.json` and `artifacts/`. The spec contains two
artifacts, both ordering profiles, multiple records, one gzip artifact and a
current revision with an immediate predecessor. All values are abstract and
non-market. The executable uses the fixed test-only Ed25519 seed `[0x11; 32]`
via `SigningKey::from_bytes`. That seed is a published conformance vector,
not a production key; no private key bytes are written to the release. The
sidecar has exactly five members and binds `SHA256` of the canonical manifest
bytes through the ratified domain prefix. Any validation failure returns a
nonzero process status.

## Gate evidence

Commands ran in the worktree with no commit. Each gate exited zero.

| Command | Outcome |
|---|---|
| `cargo fmt --all` | applied; `cargo xtask fmt` passed |
| `python3 scripts/check_style.py` | clean: json 14, makefile 1, markdown 58, python 36, shell 7 |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | exit 0; no finding in new files, inherited baseline review candidates only |
| `python3 scripts/check_prose_unified.py --all` | PASS; 541 advisory review candidates |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps` | passed after fixing one intra-doc link |
| `cargo xtask fmt` | passed |
| `cargo xtask lint` | passed |
| `cargo xtask docs` | passed |
| `cargo xtask style` | passed 15 subcommands |
| `cargo xtask test` | passed all-target and doc tests |
| `cargo xtask verify` | passed five subcommands |
| `python3 scripts/check_architecture.py --check` | passed: 90 Rust source files, 90 reachable, 3 diagrams |
| `python3 scripts/check_naming_conventions.py` | passed |

Test totals: `cargo test --workspace --all-targets --locked` reported 812
passed, 0 failed and 12 ignored; the doc-test run reported 1 passed and 0
failed. The new module contributes 33 tests and the executable contributes 9,
covering mapping conformance, the single contract version, decimal instant
grammar and type refusal, required scope, tagged unions, unknown-field
rejection, byte-derived ordering with a disagreeing caller key, both profiles,
duplicate derived keys, digest reproducibility, a two-artifact release,
compression independence, gzip registration, absence of seed bytes, evidence
binding, coverage arithmetic and verdict gating, lineage revision and UTC
grammar, and release writing from a spec into a temporary directory.

## Output paths

The offline run wrote
`/private/var/folders/7c/m_f7hs9n445174c0x3gsy5kw0000gn/T/opencode/ndc-conformance-release/manifest.json`,
`signature.json` and `artifacts/sequenced-abstract.jsonl` plus
`artifacts/reference-abstract.jsonl.gz`. The manifest carried 13 members, the
sidecar 5, and the dataset digest was
`eab26df2624444ce9ca8c93f346b7f5c2b75d68b9324149c021e307ac7f7a18b`. This
run is a local conformance vector only.

## Non-claims

This work does not claim `SCHEMA_CONFORMANT`, `CROSS_EXECUTED`,
`CRYPTOGRAPHICALLY_VERIFIED`, `RIGHTS_ADMITTED` or `DATASET_ACCEPTED`. Schema
mapping is not cryptographic verification, a test signature is not a right,
and a generated release is not dataset acceptance. Wire compatibility remains
NOT_STARTED until paired cross-execution against the B8 package exists.
