# FB-SPOOL-001 — multi-artifact non-replayable spooling, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**. Branch `fix/fb-spool-001`, base
commit `e0d065e`. No commit was created by this work package. This record states
the defect, the spool identity and durability rules, the budget boundary and the
gate evidence. It is not a resource-profile ratification, a durability
certificate, a release, a rights grant, a dataset acceptance or a verification
promotion.

## Scope and freeze

The change is confined to `src/distribution/ndc_stream.rs`, this record and the
README document map. The batch producer, wire mapping, manifest fields, receipt
shape and approved digests are unchanged. Rights stay `UNKNOWN`, dataset
acceptance stays `BLOCKED`, the budget stays INR 0, collection stays `DISABLED`,
experiments stay `BLOCKED`, live execution stays `DISABLED`, D11 stays strict and
`PUBLICATION_DURABILITY_VERIFIED` stays `false`. No provider was contacted, no
market data was read or created and no rights, data or live action occurred.

## Defects corrected

- `PreparationIntent.spool_plan` was an `Option` built with `.next()`, so a
  second non-replayable artifact had no prepared plan. The member is now the
  complete ordered `Vec<SpoolPlan>` in canonical artifact order.
- `spool_non_replayable` named each spool from the operation and binding. Spool
  ids now come from the operation, the canonical artifact ordinal and a digest
  of the opaque binding; the artifact path is evidence only.
- One evidence file path per operation could overwrite a sibling's record. Each
  spool now has its own `SPOOL_SEALED` file keyed by its spool file id.
- `publish_streaming` accumulated spool evidence and then discarded it. The
  complete inventory now lives in the sealed intent and the outcome.
- The spool file was synced but its directory entry was not synced before the
  evidence commit. The directory barrier is now part of the ordered chain.
- Spool verification used path-based `fs::metadata` and `File::open`, which
  follow a final symlink. Verification now uses descriptor-relative no-follow
  opens and reads through the verified descriptor.
- Spool bytes and staging bytes were counted by separate counters. One
  operation-scoped budget now charges both through `checked_add`.

## Spool plan and evidence identity

`SpoolPlan` carries `operation_id`, `artifact_binding_id`, `artifact_path`,
`source_snapshot_id`, `source_revision`, `spool_file_id` and `max_spool_bytes`.
`spool_file_id` accepts only opaque operation and binding tokens, combines them
with the canonical ordinal and a SHA-256 digest, and emits a `.spool` name. No
artifact path component reaches the name or a verification lookup.

`SpoolEvidence` is independent per spool and self-digested. It carries
`spool_file_id`, `operation_id`, `artifact_binding_id`, `source_identity`,
`stored_bytes`, `stored_sha256`, `record_count`, `first_order_key`,
`last_order_key`, `spool_state`, `max_spool_bytes` and
`preparation_intent_sha256`. The preparation inventory, each evidence record and
the sealed inventory are compared in `recover_streaming`; a changed record stops
recovery.

## Durability order

The spool chain is `WRITE_SPOOL` -> `SYNC_SPOOL_FILE` ->
`SYNC_SPOOL_DIRECTORY` -> `COMMIT_SPOOL_EVIDENCE` -> `SYNC_LEDGER_DIRECTORY`.
The ledger commit writes and syncs the evidence file as one step. A fault before
any step returns a typed error, writes a quarantine record and leaves no seal,
receipt, marker or final rename. A file synced without its directory entry, and
a directory entry synced without its evidence, both recover as preparation only.

## Descriptor-relative verification

`verify_spool` opens the spool directory with `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`,
opens the named spool with `openat` and `O_NOFOLLOW`, requires a
regular file with one link through `fstat`, checks the sealed byte and record
counts, and hashes bytes incrementally through that descriptor. The in-loop
byte and terminator checks bound growth after the size check. The verified
descriptor is rewound into the `BoundedRecordFramer` used by publication, so the
hashed bytes and the consumed bytes are the same descriptor. Targets without
the descriptor primitives fail closed.

## Temporary disk budget

One operation-scoped `temp_disk_bytes` budget is shared by every spool, every
staged artifact, the manifest and the sidecar. Each charge uses `checked_add`
and an enforce step; the spool also carries its per-plan bound. Journal,
preparation, sealed and spool-evidence records are **outside** this budget. They
use the separately bounded ledger budget from the profile:
`max_preparation_intent_bytes`, `max_sealed_intent_bytes` and
`max_journal_record_bytes`. Their record lengths are checked before the write;
the existing publication intent writer applies `max_intent_bytes`. The two
budgets are documented as distinct so a ledger record cannot consume temp disk
capacity and a spool cannot consume ledger capacity.

## Tests and preserved contracts

Twenty new tests cover two non-replayable sources with distinct plans, files and
evidence, plan identity fields, path-independent and token-checked spool ids,
durable evidence records, complete sealed inventory binding, tampered evidence
in recovery, corrupted and truncated spool bytes, a changed record count,
symlinked spool file and directory paths, the verified reader's digest, each
spool fault boundary, recovery at the two crash boundaries, aggregate quota
exhaustion, spool and staging sharing one quota and ledger budget separation.
Existing streaming tests remain in place.

Plan/source pairing, the two-intent lifecycle, byte-derived ordering, the
role-profile contract, PUB-019 directory ordering, PUB-020 recovery, PUB-021
tree validation, FB-REC-022 bounded reads and batch byte parity are unchanged.

## Gate evidence

Commands ran in the worktree with no commit.

| Command | Outcome |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `python3 scripts/check_style.py` | clean |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | exit 0 |
| `python3 scripts/check_prose_unified.py --all` | PASS |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps --locked` | passed |
| `python3 scripts/check_rust_style.py` | passed on added lines |
| `cargo xtask fmt`, `lint`, `docs`, `style`, `test`, `verify` | all passed |
| `cargo test --workspace --all-targets --locked` | 883 library tests passed, 4 ignored; all targets passed |
| `cargo test --lib distribution::ndc_stream` | 77 streaming tests passed |
| `python3 scripts/check_architecture.py --check` | passed |
| `python3 scripts/check_naming_conventions.py` | passed |
