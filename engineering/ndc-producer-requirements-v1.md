# NDC v1 producer requirements (Fieldbook side) — Proposed

<!-- SPDX-License-Identifier: Apache-2.0 -->

- **Status:** Proposed engineering requirements. Not ratified, not accepted
  and not an authorization for provider contact, collection, dataset
  acceptance or an experiment.
- **Version:** `ndc-producer-requirements/v1`. A semantic change requires a
  new version and a migration record; a field rename is a breaking change.
- **Governing decision:** the cross-repository ownership split remains
  Proposed design decision. Fieldbook publishes and versions immutable
  releases; the consumer validates them. This document ratifies no decision
  and grants no right.
- **Owner:** Fieldbook produces the release manifest and the event envelopes.
  Rights stay `UNKNOWN` until a written record is reviewed. Publication is
  not a rights grant.
- **W1 egress governance:** provider activity requires an explicit
  subcommand, rights loaded fail-closed from a local file, venue and operation
  identity, an authorization decision before client construction or websocket
  resolution, and a scoped audit event per decision. `UNKNOWN`, `PENDING`,
  expired, missing and venue-less records are denials. The rules are in
  `docs/live-evidence-runbook.md` and section 11 of `docs/design-decisions.md`.
  W1 adds no collection right and no dataset acceptance.
- **Scope:** the semantic fields a producer publishes on a release manifest
  and on each event envelope, plus producer-side validation and rejection
  behavior.
- **Out of scope:** transport, RPC, serialization framing, storage engine,
  queue, database, credentials, provider endpoints and technology selection.
  Each needs a measured requirement and a separate decision.

## 1. Contract objects

Dataset-wide facts belong in the release manifest; per-observation facts
belong in the event envelope. A fact is not repeated in both objects.

### 1.1 Release manifest

The release manifest is immutable and is versioned with the release. A
consumer validates it before admitting any dataset.

| Group | Required fields | Producer meaning |
|---|---|---|
| Dataset identity and source scope | `dataset_id`, `dataset_version`, `dataset_origin`, `source_scope` (`provider`, `product`, `venue`, `segment`) | Named release identity; source and venue are declared, not inferred from a symbol |
| Rights | `rights.record_reference`, `rights.permission_source`, `rights.operations`, `rights.scope`, `rights.review_date`, `rights.valid_until`, `rights.retention_period` | Written permission reference and exact operations; a registry `UNKNOWN` is not permission |
| Coverage and completeness | `coverage.certificate_reference`, `coverage.valid_until`, `coverage.verdict`, `coverage.completeness`, `coverage.scope`, `coverage.universe_id`, `coverage.as_of_ns` | Passing, unexpired certification over the declared scope and as-of instant; gaps and rejects are declared, not invented |
| Schema versions | contract schema version, normalizer version, payload schema version per event type | Version identity for each transformation applied before publication |
| Retention | `rights.retention_period`, archive closure and deletion basis | Bounded ISO-8601 duration or positive integer days; a missing or open-ended term is a denial |
| Digest | `release.manifest_sha256`, `release.data_sha256`, `release.digest_algorithm` | Immutable digests of the release manifest and canonical dataset content |
| Publication identity | `release.release_id`, `release.publication_identity`, `release.publication_method`, `release.archive_reference` | Immutable release identity and the named publisher of that identity |
| Point-in-time lineage | `lineage.basis`, `lineage.universe_version`, `lineage.universe_source_reference`, `lineage.instrument_identity_source_reference`, `lineage.corporate_action_source_reference`, matching `*_sha256` fields, `lineage.as_of_ns`, `lineage.knowledge_time_ns` | Named universe, instrument-identity and corporate-action provenance with digests and one as-of basis |

The producer emits these facts as declarations. A declaration does not create
a right, a coverage verdict or a research entitlement.

### 1.2 Event envelope

The envelope carries only facts tied to one observation. It references the
release manifest for dataset-wide rights, coverage, retention and publication
identity.

| Group | Required fields | Producer meaning |
|---|---|---|
| Source and instrument identity | provider key, venue, segment, product, canonical instrument id, valid and known intervals | The emitting producer and the canonical identity it maps to |
| Typed payload | event type, typed payload, units, scale, missing-value semantics | Defined payload per event type; null is not zero and a snapshot is not a tape |
| Source and receive timestamps | source timestamp, source timestamp unit, receive timestamp, clock domain and clock identity | Original resolution is preserved; a unit change is not added precision |
| Sequence and continuity | provider sequence where supplied, local sequence, partition scope, gap status | Continuity is scoped to a named producer and partition; a local gap is not a provider continuity claim |
| Raw digest and archive reference | raw byte digest, immutable archive object reference | Link to the exact source bytes without re-normalizing them |
| Correction and as-of lineage | revision, supersession reference, knowledge time, availability time, as-of basis | Select the view known at the as-of instant; a subsequent correction does not rewrite that view |
| Schema versions | contract schema version, normalizer version, payload schema version | Version identity for the record and its payload |

## 2. Producer validation

Validation is ordered and stops at the first refusal. A following check does
not soften an earlier failure.

1. **Contract version.** Emit an exact `contract_version`. An unknown major
   version blocks publication; the producer does not attempt migration.
2. **Required fields.** Emit every field in section 1.1 and the applicable
   fields in section 1.2 with the declared type. Missing, empty, redirected
   and placeholder references block publication.
3. **Verdicts.** Require `PERMITTED` for each listed operation, `PASS` and
   `COMPLETE` for coverage, and an immutable release flag. `UNKNOWN`,
   `PENDING`, `FAILED`, `BLOCKED`, `PROHIBITED`, `DENIED`, `EXPIRED`,
   `REVOKED` and `NO` are denials.
4. **Validity.** Convert `dataset.as_of_ns` to a UTC calendar date. Refuse a
   rights review date, a rights validity bound or a certificate expiry that
   precedes that date. Refuse an unbounded retention term.
5. **Exact operations.** Require the written record to cover `store`,
   `replay`, `internal_analytics` and `retention`, each citing the same
   record. An extra operation is a mismatch.
6. **Scope consistency.** Require rights, coverage, lineage and dataset
   source scope to name the same provider, product, venue and segment, with
   one declared universe id across those sections.
7. **Release digest.** Compute the manifest and data digests and publish them
   with the declared algorithm. A mismatch after publication blocks use of
   the release.
8. **As-of semantics.** Emit one as-of basis and instant. Refuse lineage
   knowledge time after the as-of instant. Do not select a revision by
   arrival order.
9. **Typed payload.** Refuse an unregistered event type, an untyped payload,
   a null presented as zero, or a timestamp with an undeclared unit.
10. **Continuity.** Report gaps against the declared provider and partition
    scope. A declared gap is a bounded coverage claim, not a filled
    observation.
11. **Archive link.** Emit a raw digest and an archive reference on every
    event. Do not create a substitute observation when either is absent.
12. **Publication gate.** Do not publish a release that fails any check above
    or lacks a written rights record. The consumer repeats these checks; a
    producer decision does not replace consumer admission.

Validation reads declarations and digests. It does not acquire provider data,
replay provider traffic or produce a market observation.

## 3. Rejection semantics

| Code | Trigger | Producer behavior |
|---|---|---|
| `REJECT_CONTRACT_VERSION` | Unsupported major version | Stop; publish no release and request a migration record |
| `REJECT_INCOMPLETE` | Missing, empty or mistyped required field | Stop; name the field path |
| `REJECT_VERDICT` | A rights or coverage verdict is not passing | Stop; name the field and observed value |
| `REJECT_VALIDITY` | Review, validity or expiry bound precedes the as-of UTC date | Stop; treat denied, expired and revoked references as refusals |
| `REJECT_RETENTION` | Retention is missing, open-ended or unbounded | Stop; require bounded days or an ISO-8601 duration |
| `REJECT_RIGHTS` | Exact operation set, scope or written reference differs | Stop; infer no operation from another operation |
| `REJECT_DIGEST` | Manifest or data digest mismatch | Stop; withdraw the release identity from publication |
| `REJECT_SCOPE` | Source scope or universe id differs between sections | Stop; do not merge scopes |
| `REJECT_ASOF` | As-of basis or instant differs, or knowledge time leaks | Stop; do not substitute a subsequent revision |
| `REJECT_PAYLOAD_TYPE` | Unknown event type, untyped payload or unit error | Stop; do not coerce a missing value into zero |
| `REJECT_CONTINUITY` | Undeclared gap or sequence discontinuity | Stop; do not interpolate |
| `REJECT_ARCHIVE` | Raw digest or archive reference absent | Stop; do not treat a derived value as raw |
| `REJECT_ADMISSION` | No valid admission receipt for the exact release | Stop; no research use and no experiment registration |

Rules for change over time:

- A new optional field does not change the major version. The producer
  declares it; the consumer reviews and records it before use. Unreviewed
  fields are refused.
- A renamed, removed or retyped required field, a changed verdict vocabulary
  or a changed digest algorithm requires a new major version and a migration
  record.
- A corrected release receives a new release identity. The prior identity is
  retained; a consumer selects a view by as-of instant and knowledge time.
- A rejected release is not partially published. No observation, digest or
  verdict from it enters a research dataset or an experiment record.
- A synthetic or self-attested artifact is not a fallback for a rejected
  release. Absence of an alternative is a blocked state, not a substitution.

## 4. Relation to the repository gate

W1 binds provider activity to explicit authorization, fail-closed rights and
a scoped audit event; it does not grant a collection right. This document
changes no right, no capability record, no claim record and no experiment
state. It selects no transport, queue, database or storage technology. Rights
remain `UNKNOWN` and dataset acceptance remains BLOCKED while the source
rights are unevidenced. The consumer counterpart is Nirnay's
`engineering/ndc-consumer-requirements-v1.md`; the ownership decision and the
NDC semantic definitions remain Proposed until owner ratification.
