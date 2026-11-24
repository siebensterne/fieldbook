# FB-PUB-014/015/016 — publication recovery correctness, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**, 2026-11-24. Branch
`fix/publication-recovery-correctness`, base commit `5703185`. No commit was
created by this work package. This record is a dated scope and gate statement.
It is not a durability certificate, a release, a rights grant or a verification
promotion.

Authority: this record amends the recovery contract of
[FB-NDC-012](fb-ndc-012-atomic-publication-2026-11-24.md) and the receipt path
of [FB-NDC-013](fb-ndc-013-production-builder-parity-2026-11-24.md) without
rewriting either dated record. `src/distribution/ndc_release.rs` remains the
single authority for the producer surface. The production layout from FB-NDC-013
is unchanged: `manifest.json`, `signature.json` and declared paths under
`artifacts/`.

## Defects corrected

| Defect | Correction |
|---|---|
| The final-directory recovery branch wrote a receipt and marker without syncing the release parent. | Recovery performs `SYNC_RELEASE_PARENT` and reads back the parent-synced stage before any receipt write. A crash between the rename and that sync leaves no acknowledgement. |
| `recovery_receipt` built a sparse receipt with `supersedes_release_id: None` and no schema binding; `receipt_matches` skipped two normative fields. | `PublicationEvidence` carries the receipt produced by `prepare_release` from the complete validated manifest and lineage. Recovery reuses that value. `receipt_matches` compares every receipt field plus the exact receipt-byte digest. |
| The final-directory branch adopted a release from its bytes before establishing which operation reached the rename. | Recovery requires durable stage evidence of the rename for this operation, a final-directory identity bound to that operation, and the absence of a foreign rename claim for the same release. Profile 1 collisions stay with the winning operation. |

## Recovery transition order

The final-directory path emits this ordered sequence through the publication
filesystem boundary:

1. `FINAL_DIRECTORY_FOUND` — observed name, not a durability claim.
2. `VERIFY_FINAL_DIRECTORY` — exact file set and stored-byte digests.
3. `VERIFY_OPERATION_IDENTITY` — stage rank, path identity and foreign-claim scan.
4. `SYNC_RELEASE_PARENT` — performed when the durable stage precedes parent sync.
5. `VERIFY_DURABILITY_TRANSITION` — journal read-back after the parent sync.
6. `COMMIT_RECEIPT` — exclusive create of the exact builder receipt bytes.
7. `SYNC_RECEIPT_LEDGER` — sync after the receipt commit.
8. `COMMIT_AVAILABILITY_MARKER` — exclusive create carrying the operation id.
9. `SYNC_RECEIPT_LEDGER` — sync after the marker commit.
10. `AVAILABLE` — final durable stage.

Existing durable steps are verified and retained; a completed receipt and marker
return `AlreadyAvailable` without rewriting. A partial receipt, a partial marker
or a marker bound to another operation produces `UncertainPublication`.

## Receipt fidelity and operation ownership

`prepare_release` records its receipt in `PublicationEvidence` together with the
digest of the exact bytes committed to disk. Recovery uses that receipt rather
than a narrowed view of the evidence, so schema version and predecessor lineage
survive a restart. A correction release recovered after a crash carries the same
`supersedes_release_id` as the uninterrupted build.

Stage history is validated before use: ordinals form a gap-free sequence, states
follow the ratified order, every stage binds to one operation id, release id,
commit position and digest pair, and no stage claims a transition beyond the
state machine. A rename stage written by a different operation for the same
release causes `UncertainPublication`; content equality cannot transfer
ownership.

## Fault injection and tests

A `PublicationFs` boundary delegates the durable operations to host calls and
records their order. The offline recording implementation injects failures after
the rename syscall, after the rename before its stage, during and after the
parent sync, during receipt creation, during the receipt-ledger sync, during
marker creation and during the marker-ledger sync. Each crash state is restarted
through recovery with an asserted stage, receipt fields and event sequence. Two
operations with one release identity cover strict collision for the winner and
the loser; a forged rename stage covers foreign ownership evidence.

## Gate evidence

Commands ran in the worktree with no commit. Each gate exited zero.

| Command | Outcome |
|---|---|
| `cargo fmt --all` and `cargo fmt --all -- --check` | applied; check passed |
| `python3 scripts/check_style.py` | clean: json 14, makefile 1, markdown 62, python 36, shell 7 |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | exit 0; inherited review candidates only |
| `python3 scripts/check_prose_unified.py --all` | PASS; inherited advisory candidates only |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps` | passed |
| `cargo xtask fmt` | passed |
| `cargo xtask lint` | passed |
| `cargo xtask docs` | passed |
| `cargo xtask style` | passed all subcommands |
| `cargo xtask test` | passed: 850 passed, 0 failed, 12 ignored across all targets; 1 doc test passed |
| `cargo xtask verify` | passed all five subcommands |
| `python3 scripts/check_architecture.py --check` | passed: 90 Rust source files, 90 reachable, 3 diagrams |
| `python3 scripts/check_naming_conventions.py` | passed |

The `ndc_release` module contributes 74 tests. Twelve tests were added for
transition order, boundary crashes, partial-file refusal, operation ownership,
journal rejection and correction lineage.

## Non-claims

- `Implemented` only. No `Verified` promotion or independent evidence package
  is claimed by this record.
- The recorded event order is local durable ordering on the test filesystem.
  Cross-host replication, backup and restore remain a separate durability tier.
- A receipt is a local acknowledgement. It grants no source authenticity,
  coverage, right, dataset entitlement or observation truth.
- Rights remain `UNKNOWN`, dataset acceptance stays `BLOCKED`, collection stays
  `DISABLED`, experiments stay `BLOCKED`, live execution stays `DISABLED`,
  budget stays INR 0, the India feed stays absent, the journal is not rewritten,
  no shared crate is added and D11 stays strict.
