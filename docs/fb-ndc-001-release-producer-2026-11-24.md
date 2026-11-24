# FB-NDC-001 — NDC v2 release producer, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**, 2026-11-24. Branch
`feat/ndc-v2-release-producer` at base commit
`01191fba3c91f344c9ec9040ded21b0f42e182b7`. No commit was created by this
work package. This record is a dated scope and gate statement, not a schema
artifact, a release, a rights grant or a verification promotion.

Authority: owner-ratified `WS-NDC-2026-11-24-002` Profile 1 in workspace
`engineering/decisions/WS-NDC-2026-11-24-002-ndc-v2-release-serialization-profile-1.md`
and its Decision A amendment
`engineering/conformance/NDC-D1-AMENDMENT-001.md`
(`a2087aff7bcadb5aae90eea3f7893ac3147e2e8cbecce9fcb9357481e7e49894`).
Approved D0, D1 and D2 bytes and digests remain unchanged.

## Scope

The implementation adds one module, `src/distribution/ndc_release.rs`, its
module-root declaration, one architecture responsibility entry and this dated
record with a README document-map row. No frozen path was edited. No provider
contact, collection, rights grant, dataset acceptance, experiment, India
implementation, live route, journal rewrite or shared crate is involved. All
tests use abstract scalars, arbitrary temporary bytes, injected test keys,
official RFC 8785 vectors and non-market structured records.

## Ratified decisions implemented

| Decision | Implemented behaviour |
|---|---|
| A | Complete typed manifest canonicalized as RFC 8785 JCS; no self-digest and no property-removal rule; `H_M = SHA256(M)`; the five-member sidecar alone carries `manifest_sha256`; `S = Ed25519.Sign(K_private, D \|\| H_M)` with `D = b"NDC-V2-RELEASE-MANIFEST-SHA256-V1\x00"`. |
| B | Sequenced profile `(sequence_domain, sequence_epoch, sequence_number)` and reference profile `(object_id, revision, knowledge_time, assertion_id)`; no event-time fallback, no fabricated position, no cross-domain comparison, gaps retained, duplicate positions rejected. |
| C | One `artifacts[]` inventory with the twelve descriptor members; uniqueness and canonical sort by `(logical_partition_id, shard_ordinal)`; canonical JSONL with one LF and no BOM, CR, blank or incomplete trailing record. |
| D | `data_sha256` over the concatenation of uncompressed streams in canonical artifact order; compression alters stored digest and size alone; one logical shard appears once. |
| E | One `lineage.supersedes`; cycles, self-reference, missing predecessor, revision regression, future knowledge time and mismatched release identity fail closed. |
| F | No manifest `limits`; `ResourcePolicy` carries caller-supplied numeric maxima and is enforced during parsing, records, artifacts, totals, sidecar and manifest publication. No unmeasured production maximum is invented. |
| G | Full publication state machine, exclusive sibling staging, per-file and directory fsync, exclusive final directory creation plus hard-link no-replace primitive, parent fsync, durable receipt, availability marker and evidence-based recovery. |
| H | Out-of-band trust interface shape through injected `SigningKey` and `VerifyingKey`; key id bound to the manifest publisher; the self-check uses an injected key pair. No production key is generated, installed or stored. |
| `I` | Standalone producer module with no shared validator, serializer, digest or rights crate; strict unknown-field handling and exact-file-set checking. |

## Typed surface

`ReleaseManifest`, `ArtifactDescriptor`, `SignatureSidecar`,
`LineageSupersedes`, `PublicationReceipt` and the supporting manifest sections
use serde with `deny_unknown_fields`. `ProducerError` is a typed `thiserror`
enum. `RecordOrderProfile`, `RecordOrderKey`, `CanonicalRecord`,
`ArtifactInput`, `ArtifactCompression`, `ResourcePolicy`, `SignatureConfig`,
`LineageContext`, `BuildRequest`, `BuildOutcome`, `PublicationEvidence`,
`PublicationOperation` and `PublicationState` keep boundaries explicit. The
manifest is assembled from typed fields through a private `ToJcs` conversion;
no `serde_json::Value` holds manifest content.

## Number, Unicode and path restrictions

The canonicalizer sorts object names by UTF-16 code units, emits minimal
ECMAScript number formatting for finite doubles, escapes control characters
with lowercase hex, and rejects NaN, infinity and non-finite values. The
manifest and record paths reject `f64` and `f32` with
`ProducerError::AmbiguousNumber` instead of emitting ambiguous number bytes;
exact decimals and wide integers use JSON strings. Accepted integers stay
within the exact ECMAScript range. Duplicate property names fail closed.

Artifact paths accept the ASCII subset of the contract component alphabet.
Every accepted path is NFC without conversion, and non-ASCII, absolute,
traversal, dot-component, NUL, backslash and nested-depth inputs fail closed.
This removes ambiguous normalized duplicates without a normalization library.

## Publication and platform limitation

True directory `renameat2(RENAME_NOREPLACE)` is Linux-specific and is not
available on this platform. The implementation uses exclusive final-directory
creation followed by `hard_link` of each staged file. Directory creation fails
with `EEXIST` for an existing release identity, and each link fails with
`EEXIST` for an existing target name, so no publication overwrites a file.
Filesystems without hard-link support produce an I/O error and the producer
fails closed. This is an exclusive-create plus hard-link primitive, not a
directory rename; the ratified state name `ATOMIC_NO_REPLACE_RENAME` is kept
as the durable stage label.

A crash after linking and before parent-directory sync is an uncertain
publication. `recover_interrupted()` reads durable stage evidence, verifies the
exact file set and digests, then writes the receipt and availability marker.
A receipt with mismatched binding, a receipt without a final directory, or
absent staging and final evidence fails closed. An interruption before the
staging directory is complete yields a typed artifact-set mismatch; no partial
release is promoted. Manifest presence, directory presence and an
`AVAILABLE` declaration are not durability proof.

## Gate evidence

Commands ran in the worktree with no commit. Each gate exited zero.

| Command | Outcome |
|---|---|
| `cargo fmt --all` | applied; `cargo xtask fmt` passed the check |
| `python3 scripts/check_style.py` | clean: json 13, makefile 1, markdown 57, python 36, shell 7 |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | no tautology finding; review candidates are inherited baseline text |
| `python3 scripts/check_prose_unified.py --all` | no binding finding |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps` | passed |
| `cargo xtask fmt` | passed |
| `cargo xtask lint` | passed |
| `cargo xtask docs` | passed |
| `cargo xtask style` | passed all 15 subcommands |
| `cargo xtask test` | passed all-target and doc tests |
| `cargo xtask verify` | passed all five subcommands |
| `python3 scripts/check_architecture.py --check` | passed: 88 Rust source files, 88 reachable, 3 diagrams |
| `python3 scripts/check_naming_conventions.py` | passed |

Test totals: `cargo test --workspace --all-targets --locked` reported 770
passed, 0 failed and 12 ignored across registered targets; the doc-test run
reported 1 passed and 0 failed. The new inline module contributes 40 tests,
all passing, covering the official JCS sorting, escaping and number vectors,
float refusal, duplicate names, deterministic manifest bytes, digest
tampering, sidecar field set, injected-key signing and self-check, wrong-key
refusal, duplicate and traversal paths, overlength and non-canonical records,
missing artifacts, both ordering profiles, duplicate sequence positions, gap
retention, dataset digest reproducibility, compression independence and gzip
determinism, publication collision, receipt binding, four recovery states, correction
lineage refusals and private-key absence from the release package.

## Non-claims

- `Implemented` only. No `Verified` promotion and no independently reviewed
  evidence package is claimed by this record.
- Publisher integrity proves publisher-key control over the exact signed
  bytes. It proves no source authenticity, coverage, right, dataset
  entitlement or observation truth.
- Rights remain `UNKNOWN`, dataset acceptance stays `BLOCKED`, collection stays
  `DISABLED`, experiments stay `BLOCKED`, live execution stays `DISABLED`,
  budget stays INR 0 and D11 stays strict.
- No production signing key, release, dataset, provider contact, adapter,
  market observation, India implementation or experiment was created.
- The durability claim is bounded by the local-host fault model and the
  hard-link platform primitive. Cross-host replication, backup and restore
  remain a separate durability tier.
