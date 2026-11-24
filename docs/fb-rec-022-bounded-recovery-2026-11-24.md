# FB-REC-022 — bounded Fieldbook recovery reads, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**, 2026-11-24. Branch
`fix/fb-rec-022`, base commit `fd4b542`. No commit was created by this work
package. This record states scope and gate evidence. It is not a durability
certificate, a release, a rights grant or a verification promotion.

Authority: this record tightens the read boundaries of
[FB-PUB-019](fb-pub-019-directory-durability-2026-11-24.md),
[FB-PUB-020](fb-pub-020-restart-independent-recovery-2026-11-24.md) and
[FB-PUB-021](fb-pub-021-artifact-tree-validation-2026-11-24.md) without
rewriting those dated records. `src/distribution/ndc_release.rs` stays the
single producer authority and `ResourcePolicy` stays the caller-owned source of
numeric maxima.

## Defect corrected

Recovery and tree validation read whole files before applying any bound.
`load_intent` called `fs::read` on the ledger intent, then parsed JSON. Tree
validation and intent validation accumulated manifest, sidecar and artifact
bytes into unbounded vectors. `decompress_stream` called `read_to_end` on a
gzip decoder, so a small compressed artifact could expand without an output
limit. Declared stored and uncompressed lengths were compared after the bytes
had been materialized. Journal stage files were read by path with `fs::read`
and no explicit size boundary. An attacker-controlled ledger or release tree
could therefore request an allocation before any policy check ran.

## Correction

1. One `BoundedDescriptorReader` now serves normal tree validation, intent
   recovery validation and bounded ledger reads. It borrows one already-open
   descriptor, obtains the file size with `fstat` on that descriptor, refuses a
   declared size above its limit before allocation, counts every byte read,
   hashes bytes incrementally and rechecks the descriptor after EOF. A file
   that grows past the limit between the size check and the reads is refused
   by the in-loop count check. All `libc` use stays in isolated helpers with
   `SAFETY` comments.
2. `ResourcePolicy` gains `max_intent_bytes`, a caller-supplied maximum on-disk
   intent length. It participates in `resource_profile_id`, so an intent bound
   to one declared profile cannot be replayed under a different intent bound.
   No field was added to the persisted intent or journal structures: their
   deserialization shape is unchanged.
3. The artifact count is checked before the inventory is walked. Every
   declared stored and uncompressed length is checked against its
   per-artifact maximum before any read; aggregate totals use `checked_add`
   and refuse overflow as well as aggregate bounds.
4. `decompress_stream` now streams through a bounded gzip decoder with a fixed
   chunk buffer and an output limit enforced before each chunk is hashed. It
   holds no expanded output buffer, hashes expanded bytes incrementally,
   requires a clean end of stream and refuses trailing bytes.
5. Digests and observed byte counts come from the incremental readers. A
   policy breach or integrity mismatch returns a typed `PolicyExceeded`,
   `UncertainPublication`, `PublicationEvidence` or `PublicationJournal`
   error. Policy breaches join the quarantine conditions; no receipt and no
   availability marker is written when ownership stays unproven.
6. Intent, journal, receipt and marker files are opened with
   `O_NOFOLLOW | O_CLOEXEC` and read through the same bounded reader. The
   ledger is not treated as private; a symlinked intent, journal record or
   receipt fails the no-follow open.

## Limits and qualification

Every numeric maximum in `ResourcePolicy` is caller-supplied; this module
declares no measured production maximum. `resource_profile_id` hashes the
declared maxima so an intent binds to one policy set. A digest identifies a
policy; it does not qualify the limits. Operational qualification of any
maximum stays a separate decision with its own owner and evidence. The test
policy values in this work package bound abstract offline fixtures only.

## Tests and preserved contracts

Twenty-two adversarial tests cover an oversized intent refused before JSON
parsing, too many declared artifacts, an oversized manifest, an oversized
sidecar, a sparse oversized artifact refused by `fstat` size, growth after the
size check, altered stored bytes, the streaming output limit, a gzip expansion
attack, trailing gzip bytes, aggregate overflow, a symlinked intent, a replaced
journal record, a changed journal record, an oversized journal record, a
symlinked receipt, an oversized receipt, an unreadable artifact, a failed
recovery sync, incremental hashing and the two memory-budget checks. One
fresh-process child test supports the memory measurements. Each tree-failure
test asserts quarantine with no receipt and no availability marker.

Peak RSS is measured in a fresh child process with `getrusage(RUSAGE_SELF)` and
compared with a test-local 128 MiB recovery memory budget. The rationale is
recorded beside the constant: the offline policy bounds one stored artifact at
100_000 bytes, expanded bytes stream without an output buffer and the harness
baseline stays far below the bound. Final-run observed peaks were 12_976_128
bytes for the sparse artifact recovery and 18_055_168 bytes for the gzip
expansion case.
These are test observations, not production maxima.

PUB-019 sync ordering, the PUB-020 intent and fresh-process harness, PUB-021
descriptor-relative no-follow validation, atomic no-replace rename, the
`artifacts/` layout and journal v2 are unchanged. No gate was weakened.

## Gate evidence

Commands ran in the worktree with no commit. Each gate exited zero.

| Command | Outcome |
|---|---|
| `cargo fmt --all` and `cargo fmt --all -- --check` | applied; check passed |
| `python3 scripts/check_style.py` | clean: json 14, makefile 1, markdown 68, python 36, shell 7 |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | exit 0; inherited review candidates only |
| `python3 scripts/check_prose_unified.py --all` | PASS; inherited advisory candidates only |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps` | passed |
| `CHALLENGE_STYLE_BASE=fd4b542 python3 scripts/check_rust_style.py` | passed on changed lines |
| `cargo xtask fmt`, `lint`, `docs`, `style`, `test`, `verify` | all passed |
| `cargo xtask test` | 797 library tests, all integration targets and 1 doc test passed |
| `python3 scripts/check_architecture.py --check` | passed: 90 Rust source files, 90 reachable, 3 diagrams |
| `python3 scripts/check_naming_conventions.py` | passed |
