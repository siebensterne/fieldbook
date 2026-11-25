# FB-STREAM-002 — preparation quarantine for bounded streaming, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**. Branch `fix/fb-stream-002`, base
commit `5f3321d`. No commit was created by this work package. This record
states the pre-seal quarantine defect, the typed evidence surface, the state
sequence and the gate record. It is not a resource-profile ratification, a
durability certificate, a release, a rights grant, a dataset acceptance or a
verification promotion.

## Defect and scope

`publish_streaming` wrote and synced the preparation intent, then created the
staging tree. Failure paths for spooling, spool verification, artifact
directories, source reads, record validation, artifact writes, compression,
manifest sealing, receipt construction, manifest and sidecar writes and
directory syncs returned through `?` without durable quarantine. Partial
staging trees and spool objects were left behind with no verifiable record.
Only explicit cancellation before the seal wrote a quarantine file. That file
used string-interpolated JSON, treated an existing path as success without
reading it, did not canonically encode the reason and formed its path from an
unvalidated operation identity. `recover_streaming` returned
`PreparationOnlyQuarantined` without persisting or verifying quarantine
evidence and without enumerating residual objects.

The change is confined to `src/distribution/ndc_stream.rs`, this record and the
README document map. The batch producer, wire mapping, manifest field set,
receipt shape and approved digests are unchanged. No provider contact,
collection, experiment, live routing, rights decision or data action occurred.
Rights stay `UNKNOWN`, dataset acceptance stays `BLOCKED`, budget stays INR 0
and D11 stays strict.

## Explicit state sequence

`PreparationState` names `PREPARATION_INTENT_DURABLE`, `PREPARING`, `SEALED`,
`PREPARATION_FAILED`, `QUARANTINE_COMMIT`, `QUARANTINED_DURABLE` and
`QUARANTINE_PENDING`. The producer enters `PREPARATION_INTENT_DURABLE` when the
preparation record is synced, advances to `PREPARING`, and reaches `SEALED`
when the sealed intent is synced. A first failure in that window moves the
operation to `PREPARATION_FAILED`, then to `QUARANTINE_COMMIT`, and ends in one
of the two terminal quarantine states. `SourceConsumptionState` records
`NOT_STARTED`, `CONSUMING`, `STOPPED` or `COMPLETE`.

`run_preparation` owns every operation between the two durable boundaries and
returns the first typed failure to `publish_streaming`. The caller performs the
quarantine transition, so cleanup cannot replace or mask the first failure.
`finalize_prepared_publication` owns the compatibility intent, late
cancellation check, compatibility stages, artifact-tree validation and shared
publication core after the seal.

## Typed quarantine record

`QuarantineRecord` is versioned at `QUARANTINE_SCHEMA_VERSION` and self-digested
with the existing canonical ledger serialization. It carries `schema_version`,
`operation_id`, `preparation_intent_digest`, `failure_stage`, `failure_code`,
`first_failure`, `staging_directory`, `spool_inventory`,
`partial_artifact_inventory`, `source_consumption_state`, `observed_bytes`,
`expected_bytes`, `quarantine_state` and `record_digest`. The digest covers
every other member. The record is written with create-no-replace and a ledger
directory sync, then read back and verified before a durable state is
reported. An existing record is opened and verified; a corrupt or mismatched
record is refused rather than accepted as success. `validate_operation_id`
refuses empty, oversized and non-opaque identities before any ledger path is
formed.

`PreparationQuarantineReport` preserves the first failure code, stage and text
and reports the quarantine disposition, terminal state and verified record
digest in separate members. `StreamError::PreparationQuarantined` wraps that
report. A refused ledger write, disk error or unverifiable record yields
`QUARANTINE_PENDING` with no record digest; no result claims durable
quarantine without a verified record. Uncertain staging and spool objects are
retained for inspection and are not deleted by this path.

## Recovery evidence

`recover_streaming` now takes the trusted spool directory. With a preparation
record and no seal it enumerates residual staging objects, including nested
artifact files, and operation-scoped spool objects under the artifact-count
bound, sums their observed byte lengths from metadata without reading their
content, and commits or verifies the quarantine record. A corrupt or
mismatched existing record returns `STREAM_QUARANTINE_VERIFICATION` rather
than a success outcome. `PreparationOnlyQuarantined` carries the verified
terminal state, so a pending commit is not reported as durable. A verified
seal still follows the existing two-intent chain check and publication-core
recovery.

## Compatibility and tests

Plan/source pairing, canonical sorting of pairs, bounded one-record reads, the
fixed handoff queue, the two-intent lifecycle, the immutable profile contract
and the shared publication core are unchanged. PUB-019 directory barriers,
PUB-020 recovery and PUB-021 artifact-tree validation continue through the
existing primitives. FB-REC-022 bounded descriptor reads and bounded recovery
inventory are preserved. Manifest and sidecar bytes remain byte-identical to
the batch producer.

Twenty-nine new tests cover a fault after each operation between the
preparation intent and the seal, a table-driven sweep over those stages, a
durable canonical digest, verification rather than replacement of an existing
record, a corrupted record, a record bound to another operation, traversal and
oversized-operation identities, a refused commit yielding pending state,
preservation of the first failure, residual staging and spool enumeration,
stopped source consumption and the absence of quarantine before the intent is
durable. Each injected-failure case calls recovery through a fresh invocation
that reads only durable files. The pre-existing streaming tests remain in
place.
