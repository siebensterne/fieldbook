# FB-PUB-019 — bottom-up directory durability, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**, 2026-11-24. Branch
`fix/pub-019-directory-durability`, base commit `475dc34`. No commit was created
by this work package. This record is a scope and gate statement. It is not a
durability certificate, a release, a rights grant or a verification promotion.

Authority: this record amends the stage-evidence contract of
[FB-PUB-017](fb-pub-017-journal-durability-2026-11-24.md) and the publication
contract of [FB-NDC-012](fb-ndc-012-atomic-publication-2026-11-24.md) without
rewriting either dated record. `src/distribution/ndc_release.rs` remains the
single producer authority. The release layout stays `manifest.json`,
`signature.json` and declared paths under `artifacts/`.

## Defects corrected

- Schema v1 wrote `STAGING_CREATED` before syncing the release root. The
  staging name could be absent after restart while a stage claimed it.
- Schema v1 synced the staging directory but not its `artifacts/` child. Syncing
  a parent directory does not persist the entries of a child directory.
- Schema v1 committed `FILES_SYNCED` and `STAGING_DIR_FSYNCED` without exposing
  each file sync, child-directory sync and root sync as separate boundaries.
  A crash between a write and its barrier left no typed, assertable evidence.

The correction is bottom-up: each directory entry is synced before a stage
claims it durable, and each parent sync completes before its successor stage.

## Operation order

The v2 build performs this order. `COMMIT` items are journal records; all other
items are filesystem barriers or checks through `PublicationFs`.

1. `COMMIT OPERATION_INTENT_DURABLE`.
2. `CREATE_STAGING_DIRECTORY`.
3. `SYNC_RELEASE_ROOT`.
4. `COMMIT STAGING_ENTRY_DURABLE`.
5. `CREATE_ARTIFACT_DIRECTORY`.
6. `WRITE_MANIFEST` / `WRITE_SIGNATURE` / `WRITE_ARTIFACTS`.
7. `SYNC_EACH_REGULAR_FILE`.
8. `SYNC_STAGING_ARTIFACT_DIRECTORY`.
9. `SYNC_STAGING_DIRECTORY`.
10. `COMMIT STAGING_TREE_DURABLE`.
11. `VALIDATE_STAGING_TREE`.
12. `ATOMIC_NO_REPLACE_RENAME`.
13. `SYNC_RELEASE_ROOT`.
14. `COMMIT RENAME_DURABLE`.
15. `WRITE_PUBLICATION_RECEIPT`.
16. `SYNC_RECEIPT_FILE`.
17. `SYNC_LEDGER_DIRECTORY`.
18. `WRITE_AVAILABILITY_MARKER`.
19. `SYNC_MARKER_FILE`.
20. `SYNC_LEDGER_DIRECTORY`.
21. `COMMIT AVAILABLE`.

## Journal schema v2

`JOURNAL_SCHEMA_VERSION = 2`. Each record keeps the canonical JSON form, the
trailing LF, the self-consistency digest, the predecessor link, the ordinal and
the ledger directory sync from FB-PUB-017. The v2 state machine has five
records.

| Stage | Guarantee at the moment the record is committed |
|---|---|
| `OPERATION_INTENT_DURABLE` | The operation id, release id, manifest and dataset digests, commit position, staging and final paths and expected receipt digest are durable in the ledger. No release-root entry has been claimed. |
| `STAGING_ENTRY_DURABLE` | The staging directory exists and the release root carrying its entry was synced. No file or child directory is claimed durable. |
| `STAGING_TREE_DURABLE` | The manifest, signature and every declared artifact were written and synced. The `artifacts/` directory and the staging directory were synced. No rename is claimed. |
| `RENAME_DURABLE` | The atomic no-replace rename committed and the release root carrying the final name was synced. The final directory belongs to this operation. |
| `AVAILABLE` | The receipt was written and synced, the ledger was synced, the marker was written and synced, and the ledger was synced again. This is the local acknowledgement. |

A transition claims a filesystem state only after the required sync succeeded.
A failed sync returns a typed error; it is not downgraded to a warning. Stages
`STAGING_ENTRY_DURABLE`, `STAGING_TREE_DURABLE` and `RENAME_DURABLE` are new
schema-v2 variants. `AVAILABLE` is shared with v1 and keeps its rank. No v1
variant is redefined in place.

## Compatibility and migration

- `LEGACY_JOURNAL_SCHEMA_VERSION = 1` is retained. The reader accepts records
  with schema version 1 or 2 and selects the state order from the first record
  of the chain.
- A chain carries one schema version. A record with a different version fails
  the chain check; chains are not mixed.
- Existing v1 records are immutable, readable and auditable as legacy evidence.
  No builder or recovery path rewrites them. Their wire literals, canonical
  digest inputs and ranks stay as published.
- Recovery of a v1 chain applies the v1 barriers (`STAGING_DIR_FSYNCED`,
  `PARENT_DIR_FSYNCED`, `DURABLE_PUBLICATION_RECEIPT`). Recovery of a v2 chain
  applies the v2 barriers (`STAGING_TREE_DURABLE`, `RENAME_DURABLE`).
- New publications write v2 records only. Migration is append-only: a new
  operation id starts a new v2 chain; no old record is converted or deleted.

## Recovery and fault injection

`PublicationFaults` and `PublicationBoundary` cover every new barrier: staging
mkdir, staging-entry root sync, artifacts mkdir, each regular-file write, each
regular-file sync, artifacts-directory sync, staging-directory sync, rename,
rename root sync, receipt write, receipt sync, receipt ledger sync, marker
write, marker sync and marker ledger sync. The recording filesystem logs the
boundaries so tests assert operation order.

Each injected failure asserts the committed stage sequence, operation identity,
`receipt_acknowledged == false`, `available_marker_acknowledged == false` and
`dataset_admitted == false`. Recovery quarantines a final directory without a
durable rename claim: `UncertainPublication` keeps the receipt and marker
absent. Receipt fidelity and operation ownership checks retain the earlier
contract. Eighteen abstract fault and compatibility tests were added.

## Gate evidence

Commands ran in the worktree with no commit. Each gate exited zero.

| Command | Outcome |
|---|---|
| `cargo fmt --all` and `cargo fmt --all -- --check` | applied; check passed |
| `python3 scripts/check_style.py` | clean: json 14, makefile 1, markdown 64, python 36, shell 7 |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | exit 0; inherited review candidates only |
| `python3 scripts/check_prose_unified.py --all` | PASS; inherited advisory candidates only |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps` | passed |
| `python3 scripts/check_rust_style.py` | passed on changed lines |
| `cargo xtask fmt`, `lint`, `docs`, `style` | passed |
| `cargo xtask test` | passed: 739 lib tests and all integration targets; 1 doc test |
| `cargo xtask verify` | passed all five subcommands |
| `python3 scripts/check_architecture.py --check` | passed: 90 Rust source files, 90 reachable, 3 diagrams |
| `python3 scripts/check_naming_conventions.py` | passed |

The `ndc_release` module contributes 98 tests. Eighteen new tests cover the
directory-entry and tree boundaries, the rename and acknowledgement boundaries,
the complete boundary order, schema-v1 readability and mixed-version refusal.

## Non-claims

- `Implemented` only. No `Verified` promotion or independent evidence package
  is claimed by this record.
- Power-loss durability remains unqualified. OS-crash and power-loss behavior
  is a separate D1 filesystem-qualification item; this work establishes
  process-crash evidence ordering on the declared filesystem.
- Cross-host replication, backup and restore remain a separate durability tier.
- A receipt is a local acknowledgement. It grants no source authenticity,
  coverage, right, dataset entitlement or observation truth.
- Rights stay `UNKNOWN`, dataset acceptance stays `BLOCKED`, collection stays
  `DISABLED`, experiments stay `BLOCKED`, live execution stays `DISABLED`,
  budget stays INR 0, the India feed stays absent, the immutable journal is not
  rewritten, no shared crate is added and D11 stays strict.
