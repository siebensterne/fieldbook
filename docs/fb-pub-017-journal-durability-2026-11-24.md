# FB-PUB-017 — publication journal durability, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**, 2026-11-24. Branch
`fix/publication-journal-durability`, base commit `932e34f`. No commit was
created by this work package. This record is a scope and gate statement. It is
not a durability certificate, a release, a rights grant or a verification
promotion.

Authority: this record amends the stage-evidence contract of
[FB-NDC-012](fb-ndc-012-atomic-publication-2026-11-24.md) and the recovery
contract of
[FB-PUB-014/015/016](fb-pub-014-recovery-correctness-2026-11-24.md) without
rewriting either dated record. `src/distribution/ndc_release.rs` remains the
single producer authority. The release layout stays `manifest.json`,
`signature.json` and declared paths under `artifacts/`.

## Defect corrected

`write_stage` synced the stage file but left the ledger directory entry
unsynced. A crash between those barriers could expose a final release name
while the stage evidence for that transition was absent, so recovery reported
`NoEvidence` or `UncertainPublication` for a transition the producer had
recorded. File fsync and directory-entry durability are distinct barriers.

## Journal form

The ledger keeps the existing one-file-per-stage layout. Each stage file is an
immutable, exclusively created (`create_new`) record; the chain of files is the
append-only operation journal. A single append-only file was not adopted:
`src/bin/ndc-conformance-producer.rs` reads `.stage.` evidence files, recovery
tests inspect ordinal files, and an append file would need tail-truncation
recovery for torn writes. Keeping stage files preserves those readers and the
existing ordinal-addressable evidence model.

## Record contract

`JOURNAL_SCHEMA_VERSION = 1`. Every record is RFC 8785 canonical JSON with one
trailing LF. `record_sha256` covers every member except itself; a reader
recomputes the digest and the exact canonical bytes. `JOURNAL_GENESIS_DIGEST`
is the predecessor reference of sequence zero.

| Field | Binding |
|---|---|
| `schema_version` | Journal layout version; unknown versions fail closed. |
| `sequence_number` | Unique, gap-free position in the operation chain; equals the stage ordinal. |
| `previous_record_sha256` | Canonical digest of the preceding record, or the genesis digest. |
| `operation_id` | Operation identity; must match the stage filename. |
| `release_id` | Immutable release identity. |
| `manifest_sha256` | Canonical manifest digest. |
| `data_sha256` | Dataset digest over ordered uncompressed streams. |
| `commit_position` | Commit position bound into the receipt. |
| `staging_directory` | Staging path identity relative to the release root. |
| `final_directory` | Final path identity relative to the release root. |
| `supersedes_release_id` | Immediate predecessor release identity, or null. |
| `expected_receipt_sha256` | Digest of the expected receipt bytes. |
| `stage` | One of the eight ratified `PublicationState` values. |
| `record_sha256` | Self-consistency digest of the canonical record. |

Persistence barriers and recovery interpretation:

1. Provision the ledger and release root: require an existing parent, create
   the target directory, then sync the parent that carries its entry. A missing
   parent is a fail-closed error; syncing a root does not make that root's own
   entry durable in its parent.
2. Commit each stage: `create_new` the record file, sync the file, sync the
   ledger directory. The record is durable evidence only after the directory
   sync returns.
3. Recovery reads the chain, checks canonical bytes, digests, the predecessor
   link, ordinals and states before using any record. A record lost before the
   directory sync is treated as absent; its successor cannot claim the
   transition.
4. Receipt, receipt-ledger sync, marker, marker-ledger sync and the final stage
   keep the order ratified in FB-PUB-014/015/016. A receipt remains the local
   acknowledgement; final-directory presence alone grants no ownership.

Rejected records: duplicate sequence numbers, gaps, state regression,
conflicting operation or release identities, states outside the ratified
order, checksum mismatch, non-canonical bytes, a broken predecessor digest, a
release that declares itself as predecessor, a predecessor conflicting with
the receipt, and a filename operation id that disagrees with the record.

## Tests

The `PublicationFs` boundary now carries `sync_provisioned_parent` and
`commit_journal_record`. The offline recording implementation counts those
barriers and injects faults before and after each journal directory sync and
at each provisioning parent sync. Tests cover all eight committed stages with
a simulated restart and readable, validated evidence; a lost record before
each directory sync with no acknowledgement from the failed run; field binding
and predecessor links; conflicting, missing, regressive and tampered records;
and the provisioning parent-sync requirement. The no-replace rename, recovery
order, receipt fidelity, operation ownership and `artifacts/` layout tests from
earlier packages remain in place and pass.

## Gate evidence

Gates were run in the worktree with no commit. Exact commands and outcomes are
reported with the handover.

## Non-claims

- `Implemented` only. No `Verified` promotion or independent evidence package
  is claimed by this record.
- This establishes process-crash evidence ordering on the declared filesystem.
  It is not OS-crash or power-loss qualification (P-D1) until filesystem
  qualification is performed.
- The recorded event order is local durable ordering. Cross-host replication,
  backup and restore remain a separate durability tier.
- A receipt is a local acknowledgement. It grants no source authenticity,
  coverage, right, dataset entitlement or observation truth.
- Rights stay `UNKNOWN`, dataset acceptance stays `BLOCKED`, collection stays
  `DISABLED`, experiments stay `BLOCKED`, live execution stays `DISABLED`,
  budget stays INR 0, the India feed stays absent, the immutable journal is not
  rewritten, no shared crate is added and D11 stays strict.
