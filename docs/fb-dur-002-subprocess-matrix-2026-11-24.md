# FB-DUR-002 — fresh-process crash matrix for every durable boundary, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**, 2026-11-24. Branch
`test/dur-002-subprocess-matrix`, base commit `cabf1be`. No commit was created
by this work package. This record is a scope and evidence statement. It is not
a durability certificate, a release, a rights grant or a verification
promotion.

Authority: this record extends the fresh-process evidence of
[FB-PUB-020](fb-pub-020-restart-independent-recovery-2026-11-24.md) over the
full publisher boundary sequence. `src/distribution/ndc_release.rs` remains
the single producer authority. The dated records for FB-PUB-017, FB-PUB-018,
FB-PUB-019, FB-PUB-020, FB-PUB-021 and FB-REC-022 are not rewritten.

## Failure model

The harness ends one publisher child process with `process::exit` at a chosen
durable boundary. Destructors do not run. The child leaves the host filesystem
and ledger as they stood at that boundary. A second child process reconciles
the operation from root, ledger, operation id and resource profile id alone.

This is **D0 process termination only**. It is not a D1 operating-system
crash, power-loss test or storage-controller qualification. No claim about
write-back caches, rename atomicity under power loss or filesystem recovery
after a host restart follows from this record.

## Expected-outcome table

The table is fixed before the tests run. Each row is one fresh publisher child
and one fresh recovery child. `RECOVERED_*` rows also run a second recovery
child. The three release files are numbered `1` for `manifest.json`, `2` for
`signature.json` and `3` for `artifacts/a.jsonl`.

| Boundary name | Owner boundary | Durable evidence at exit | Expected outcome |
|---|---|---|---|
| `before_intent_creation` | before intent creation | no intent file | `NO_EVIDENCE` |
| `intent_file_written` | after intent file write | intent bytes, no journal stage | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `intent_file_synced` | after intent file sync | intent bytes, no journal stage | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `intent_ledger_synced` | after intent ledger-dir sync | intent bytes, no journal stage | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `staging_mkdir` | after staging mkdir | intent and intent stage, empty staging entry | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `release_root_synced` | after release-root sync | intent and intent stage, empty staging entry | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `staging_entry_durable` | after `STAGING_ENTRY_DURABLE` | staging entry claim, incomplete tree | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `artifact_dir_created` | after artifact-dir creation | empty artifacts entry | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `artifact_write_1` | after every artifact write (1) | manifest bytes, no tree claim | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `artifact_write_2` | after every artifact write (2) | manifest and sidecar bytes, no tree claim | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `artifact_write_3` | after every artifact write (3) | complete tree bytes, no tree claim | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `artifact_sync_1` | after every artifact file sync (1) | synced manifest, no tree claim | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `artifact_sync_2` | after every artifact file sync (2) | synced manifest and sidecar, no tree claim | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `artifact_sync_3` | after every artifact file sync (3) | synced tree bytes, no tree claim | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `artifact_dir_synced` | after artifact-dir sync | synced artifacts entry, no tree claim | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `staging_dir_synced` | after staging-dir sync | synced staging entry, no tree claim | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `staging_tree_durable` | after `STAGING_TREE_DURABLE` | verified staging tree and tree claim | `RECOVERED_STAGED` |
| `staging_validated` | after staging validation | verified staging tree and tree claim | `RECOVERED_STAGED` |
| `rename_committed` | after rename before rename journal commit | final name, no rename claim | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `rename_root_synced` | after release-root sync | final name, no rename claim | `UNCERTAIN_PUBLICATION_QUARANTINED` |
| `rename_durable` | after `RENAME_DURABLE` | final name with durable rename ownership | `RECOVERED_PUBLISHED` |
| `receipt_written` | after receipt write | receipt bytes, no marker | `RECOVERED_PUBLISHED` |
| `receipt_synced` | after receipt sync | synced receipt, no marker | `RECOVERED_PUBLISHED` |
| `receipt_ledger_synced` | after ledger sync for receipt | committed receipt, no marker | `RECOVERED_PUBLISHED` |
| `marker_written` | after marker write | receipt and marker bytes | `RECOVERED_PUBLISHED` |
| `marker_synced` | after marker sync | receipt and synced marker | `RECOVERED_PUBLISHED` |
| `marker_ledger_synced` | after final ledger sync | receipt and committed marker | `RECOVERED_PUBLISHED` |
| `available` | after `AVAILABLE` | receipt, marker and available stage | `ALREADY_AVAILABLE` |

Expectations follow durable evidence and one rule per class: absent intent
gives `NO_EVIDENCE`; missing tree or rename ownership gives quarantine; a
verified staging tree is renamed and acknowledged; a durable rename claim
completes receipt and marker; a committed available stage needs no write. No
boundary collapses into a generic error.

## Child command and protocol

Both child processes run the library test binary with `--exact
distribution::ndc_release::tests::fresh_process_recovery_from_durable_state
--nocapture`. Each child reads its inputs from environment variables and
prints one marker line before `process::exit(0)`.

| Variable | Publisher child | Recovery child |
|---|---|---|
| `FB_PUB020_CHILD_MODE` | `publish_boundary`, a boundary name, or an FB-PUB-020 alias | `recover` |
| `FB_PUB020_BOUNDARY` | one boundary name when the mode is `publish_boundary` | removed |
| `FB_PUB020_ROOT` | release root | release root |
| `FB_PUB020_LEDGER` | ledger directory | ledger directory |
| `FB_PUB020_OPERATION_ID` | operation id | operation id |
| `FB_PUB020_RELEASE_ID` | final release id | removed |
| `FB_PUB020_RESOURCE_PROFILE` | removed | `test-policy-v1` |

A publisher child mode may be one boundary name from the table, or
`publish_boundary` with that name in `FB_PUB020_BOUNDARY`.

The publisher prints `FB_PUB020_PUBLISHER_EXIT=<name>` at its exit point. The
recovery child prints `FB_PUB020_OUTCOME=<label>` with one of `NO_EVIDENCE`,
`RECOVERED_STAGED`, `RECOVERED_PUBLISHED`, `ALREADY_AVAILABLE` or
`UNCERTAIN_PUBLICATION_QUARANTINED`. The publisher returns status 21 if no
exit point was reached. No build outcome, evidence object, receipt object or
other in-memory value crosses a process boundary.

The earlier three modes stay as aliases: `publish_before` ends after
`RenameCommitted`, `publish_staging` after journal commit 3 and
`publish_rename` after journal commit 4. Their original marker strings remain
in use.

## Tests and idempotence

`subprocess_boundary_matrix_exhausts_durable_evidence` runs the table above.
For each `RECOVERED_*` row it runs recovery a second time and checks that the
result is `ALREADY_AVAILABLE`, the receipt bytes and journal chain are
byte-identical, the receipt keeps the original operation id, commit position,
release identity and absent predecessor, the final stage stays `AVAILABLE`,
the final release directory exists and the ledger holds one marker file bound
to the original operation id. Quarantine and no-evidence rows check the single
outcome and leave durable evidence untouched.

`fresh_process_recovery_from_durable_state` keeps the FB-PUB-020 evidence for
the three aliases. In-process fault-injection tests such as
`staging_mkdir_crash_withholds_the_entry_claim`,
`receipt_write_crash_preserves_receipt_fidelity` and
`marker_ledger_sync_crash_preserves_receipt_fidelity` remain separate offline
tests. Their results are reported as injected-error evidence and not counted
as D0 process-termination evidence.

## Unchanged contracts

The bottom-up sync order, atomic no-replace rename, FB-REC-022 bounded reads,
PUB-019 sync ordering, PUB-020 intent and quarantine rules, PUB-021 no-follow
tree validation, PUB-017 and PUB-018 journal chaining, receipt fidelity and
release layout are unchanged. The `after_staging_validation` filesystem hook
has an empty production default; it only ends the publisher child in the
harness. No gate was weakened.

## Gate evidence

Commands ran in the worktree with no commit. Each gate exited zero.

| Command | Outcome |
|---|---|
| `cargo fmt --all` and `cargo fmt --all -- --check` | applied; check passed |
| `python3 scripts/check_style.py` | clean |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | exit 0; inherited review candidates only |
| `python3 scripts/check_prose_unified.py --all` | PASS; inherited advisory candidates only |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps` | passed |
| `python3 scripts/check_rust_style.py` | passed on changed lines |
| `cargo xtask fmt`, `lint`, `docs`, `style` | passed |
| `cargo xtask test` | passed: 798 lib tests (4 ignored), all integration targets and 2 doc tests |
| `cargo xtask verify` | passed all subcommands |
| `python3 scripts/check_architecture.py --check` | passed |
| `python3 scripts/check_naming_conventions.py` | passed |

## Non-claims

- `Implemented` only. No `Verified` promotion or independent evidence package
  is claimed by this record.
- D0 process termination is demonstrated over the table above. D1 power-loss
  durability remains unqualified pending filesystem qualification.
- Cross-host replication, backup and restore remain a separate durability
  tier. A receipt is a local acknowledgement; it grants no source authenticity,
  coverage, right, dataset entitlement or observation truth.
- Rights stay `UNKNOWN`, dataset acceptance stays `BLOCKED`, collection stays
  `DISABLED`, experiments stay `BLOCKED`, live execution stays `DISABLED`,
  budget stays INR 0, the India feed stays absent, the immutable journal is not
  rewritten, no shared crate is added and D11 stays strict.
