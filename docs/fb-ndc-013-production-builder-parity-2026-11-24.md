# FB-NDC-013 — production builder parity, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**, 2026-11-24. Branch
`fix/ndc-production-builder-parity`, base commit `071da27`. No commit was
created by this work package. This record is a dated scope and gate statement.
It is not a release, a rights grant, a cross-execution certificate or a
verification promotion.

Authority: this record amends the producer and executable paths of
[FB-NDC-001](fb-ndc-001-release-producer-2026-11-24.md) and the wire path of
[FB-NDC-009](fb-ndc-009-wire-mapping-2026-11-24.md) without rewriting those
dated records. The canonical wire authority remains `WS-NDC-2026-11-24-003`
and its schema package. Frozen boundaries remain unchanged: rights `UNKNOWN`,
dataset acceptance `BLOCKED`, budget INR 0, collection `DISABLED`, experiments
`BLOCKED`, live execution `DISABLED`, India feed absent, no journal rewrite and
D11 strict.

## Defects corrected

Two independent release paths existed. The production builder serialized
manifest bytes through its private `ToJcs` path and wrote artifacts with
`path.rsplit('/').next()` into the staging root, while descriptors declared
`artifacts/<name>`. The conformance executable used
`ndc_wire::build_conformance_release` and `ndc_wire::write_release` instead of
the production builder. Artifact-set validation and recovery also reduced
declared paths to basenames. This work unifies both paths.

## One canonical wire path

`ndc_wire` is now the single canonical wire mapping, documented as such at the
head of `src/distribution/ndc_release.rs`. `BuildRequest` carries a typed
`EvidenceSpec` supplement and the observed event-type set, so no global state
is needed. `prepare_release` calls `ndc_wire::map_manifest` with the computed
dataset digest and canonicalizes the returned value with the same strict JCS
canonicalizer. The manifest-specific `ToJcs` implementation and the public
`canonicalize_manifest` helper were removed. Other `ToJcs` implementations
remain for receipts, operations, descriptors and sidecars, none of which are
manifest bytes.

## One artifact layout

The builder creates `staging/artifacts/` and writes each artifact to
`staging.join(<declared relative path>)`. Declared paths are validated as
release-relative paths under `artifacts/` and are never reduced to basenames.
`validate_artifact_set` checks an exact root file set of `manifest.json`,
`signature.json` and `artifacts/`, then an exact artifacts file set equal to
the declared relative paths, and reads each digest from its declared location.
Recovery calls the same validator, so a relocated or extra artifact fails
closed before any receipt or acknowledgement is written.

## Conformance executable on the production core

`src/bin/ndc-conformance-producer.rs` parses the same abstract spec, converts
`spec.artifacts` to `ArtifactInput` through `ndc_wire::spec_to_build_inputs`,
passes `spec.evidence` into the `BuildRequest` supplement, derives order keys
from canonical record bytes and supplies an out-of-band predecessor receipt
for the abstract correction. It constructs a `BuildRequest` with the injected
test seed `[0x11; 32]`, an isolated ledger directory beside `--out`, and calls
`ndc_release::build_release`. `--out` is the release root and the release is
published at `<out>/<release_id>`. `ndc_wire::write_release` is no longer used
by the executable. Nothing modifies the release after publication.

## Cross-execution

The parent session will re-run cross-execution with the actual producer and
Nirnay verifier binaries after merge. The local sequence is: build the
executable, run it with `--spec docs/specifications/ndc-conformance-producer-spec-example-2026-11-24.json`
and `--out <release-root>`, then verify the directory `<release-root>/conformance-release-2`
under the trusted root `<publisher-abstract>/<dataset-abstract>/` with no
post-publication modification. The expected result is the wire-milestone
result: stages 1-5 PASS (structural, manifest, signature, publisher, artifact
and ordering) and stage 6 `REJECT_RIGHTS_EVIDENCE`, with rights `UNKNOWN`.

Local pre-merge evidence supports that expectation without claiming it: the
rebuilt producer ran to completion and its `manifest.json`, `signature.json`
and both artifact files were byte-identical to the wire-milestone release from
FB-NDC-009, including dataset digest
`eab26df2624444ce9ca8c93f346b7f5c2b75d68b9324149c021e307ac7f7a18b`. The
in-repo executable test `final_directory_layout_is_exact` parses the published
file set exactly.

## Tests

Sixteen abstract tests were added. Twelve production-core tests cover the
`artifacts/` layout, declared relative paths without basename flattening,
exact-set rejection of extra and missing files, rejection of paths outside
`artifacts/`, canonical manifest bytes identical to the wire mapping, sidecar
digest and signature agreement with the canonical bytes, wire-only manifest
members, no invented grants, staging layout before rename, recovery with the
new layout and recovery refusal for a relocated artifact. Four executable
tests cover the exact final directory layout, passage through the production
core via durable receipt and stage evidence, manifest and sidecar byte
agreement with the wire path, and injected-seed signature verification.

## Gate evidence

Commands ran in the worktree with no commit. Each gate exited zero.
`cargo test --workspace --all-targets --locked` reported 838 passed, 0 failed
and 12 ignored; the doc-test run reported 1 passed and 0 failed. The
`ndc_release` module contributes 62 tests and the conformance executable
contributes 13 after this work.

| Command | Outcome |
|---|---|
| `cargo fmt --all` and `cargo fmt --all -- --check` | applied; check passed |
| `python3 scripts/check_style.py` | clean: json 14, makefile 1, markdown 61, python 36, shell 7 |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | exit 0; inherited review candidates only, no new finding in changed lines |
| `python3 scripts/check_prose_unified.py --all` | PASS; 550 inherited advisory candidates |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps` | passed |
| `python3 scripts/check_rust_style.py` | PASS on changed lines versus main |
| `cargo xtask fmt` | passed |
| `cargo xtask lint` | passed |
| `cargo xtask docs` | passed |
| `cargo xtask style` | passed all 15 subcommands |
| `cargo xtask test` | passed all-target and doc tests |
| `cargo xtask verify` | passed all five subcommands |
| `python3 scripts/check_architecture.py --check` | passed |
| `python3 scripts/check_naming_conventions.py` | passed |

## Non-claims

- `Implemented` only. No cross-execution, `Verified` promotion or independent
  evidence package is claimed by this record.
- The parent session owns the post-merge cross-execution with the actual
  binaries. This record states the command sequence and expected result.
- A no-replace rename and a canonical manifest constrain bytes and name
  resolution. They prove no source authenticity, coverage, right, dataset
  entitlement or observation truth.
- No production key, release, dataset, provider contact, adapter, market
  observation, India implementation, experiment or live route was created.
- Rights remain `UNKNOWN`, dataset acceptance stays `BLOCKED`, collection stays
  `DISABLED`, experiments stay `BLOCKED`, live execution stays `DISABLED`,
  budget stays INR 0 and D11 stays strict.
