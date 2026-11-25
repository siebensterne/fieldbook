# FB-STREAM-001 — plan/source pairing through canonical sorting, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**. Branch `fix/fb-stream-001`, base
commit `8216197`. No commit was created by this work package. This record states
the defect, the typed pairing rule, the source-binding evidence and the gate
record. It is not a resource-profile ratification, a durability certificate, a
release, a rights grant, a dataset acceptance or a verification promotion.

## Defect and scope

`StreamingBuildRequest` declares that `sources` are aligned by input position
with `plans`, and that plans may arrive in any order. The streaming producer
cloned and sorted the plans by `(logical_partition_id, shard_ordinal)`, then
paired the sorted plans with the unsorted source list through `zip`. A shuffled
input could therefore stream one artifact's records into another artifact's
path. The snapshot identity check compared only `snapshot_id` and `revision`,
which several streams may share, so a swap could pass identity and be refused
by the replay digest only after the wrong source had been consumed.

The change is confined to `src/distribution/ndc_stream.rs` and this record.
The batch producer, the wire mapping, the manifest field set, the receipt shape
and every approved digest are unchanged. No provider contact, collection,
experiment, live routing, rights decision or data action occurred. Rights stay
`UNKNOWN`, dataset acceptance stays `BLOCKED`, budget stays INR 0, and D11 stays
strict.

## Pairing invariant

`PlannedSource` holds one `ArtifactPlan` and the `Box<dyn ArtifactRecordSource>`
at the same input position. The request's sources are moved into these pairs in
input order before any validation or sorting. Sorting acts on the pair, so a
permutation of canonical order moves each plan with its own source. The
streaming loop consumes pairs, and the request can no longer supply a source
list that drifts from its plans during a sort.

Canonical order remains the byte-derived artifact order
`(logical_partition_id, shard_ordinal)`. Descriptors, replay proofs, source
bindings, the preparation plan and the sealed inventory all follow that order.

## Artifact-source binding

`ArtifactSourceBinding` records the canonical position, path, snapshot id,
revision and a `binding_id` unique across the operation. `ArtifactPlan` declares
the binding; `ArtifactRecordSource::source_binding_id()` reports it.
`BoundedRecordFramer` carries the binding through spooling. Validation rejects
an empty or out-of-alphabet binding and rejects two plans that claim one
binding. Both the direct stream and the spool entry check the binding before
the first record is read. A mismatch returns `STREAM_SOURCE_BINDING` with no
consumption and no seal.

The preparation intent carries the ordered bindings beside the ordered plan.
The sealed intent carries the same binding vector; recovery compares the two
chains before reconciling. `StreamingOutcome` exposes per-artifact bindings in
canonical order, and each `ReplayProof` carries the binding of the source that
produced it. `verify_replay_proof` checks that member as well as the existing
digest, count and key commitments.

Binding-scoped spool names and spool evidence files keep multiple non-replayable
sources distinct within one operation. A spooled source is checked as replayable
after the spool seal; a direct source is checked against its declared
replayability. Both checks run before the first record is read.

## Compatibility and tests

Byte-derived ordering, one-record-at-a-time bounded reads, the fixed handoff
queue, the two-intent lifecycle, cancellation boundaries, the profile contract
and the shared publication core are unchanged. PUB-019 directory barriers,
PUB-020 recovery, PUB-021 artifact-tree validation and FB-REC-022 bounded
reads continue through the existing primitives. Manifest and sidecar bytes stay
byte-identical to the batch producer.

Seventeen new tests cover a four-artifact input in noncanonical order, distinct
record content, a snapshot and revision shared by all four sources, two
non-replayable sources, canonical descriptor and proof order, per-source digest
and count assignment, one end-of-stream pass per source, binding evidence in
both intents, recovery of the binding chain, refusal before consumption,
refusal before spooling, duplicate positions, duplicate bindings, invalid
binding tokens, source-count mismatch, permutation independence, dataset
digest assignment and sealed-inventory parity. The pre-existing streaming tests
remain in place.
