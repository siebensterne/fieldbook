# NDC v1 producer requirements (Fieldbook side) — Proposed

<!-- SPDX-License-Identifier: Apache-2.0 -->

- **Status:** Proposed engineering requirements. Not ratified, not accepted
  and not an authorization for provider contact, collection, dataset
  acceptance or an experiment. No NDC v1 final schema is adopted here.
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
  and on each event envelope, the operation sets and rights evidence a release
  depends on, and producer-side validation and rejection behavior.
- **Out of scope:** a final schema, transport, RPC, serialization framing,
  storage engine, queue, database, credentials, provider endpoints, a shared
  crate and any technology selection. Each needs a measured requirement and a
  separate decision.

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
| Producing operations | `release.producing_operations` (canonical operation strings), `rights.operations` | The acquisition and processing operations that produced or maintain the release; each names a permission |
| Coverage and completeness | `coverage.certificate_reference`, `coverage.valid_until`, `coverage.verdict`, `coverage.completeness`, `coverage.scope`, `coverage.universe_id`, `coverage.denominator`, `coverage.as_of_ns` | Passing, unexpired certification over the declared scope and as-of instant; one universe and a denominator define every gap and completeness claim |
| Schema versions | contract schema version, normalizer version, payload schema version per event type | Version identity for each transformation applied before publication |
| Retention | `rights.retention_period`, archive closure and deletion basis | Bounded ISO-8601 duration or positive integer days; a missing or open-ended term is a denial |
| Digest | `release.manifest_sha256`, `release.data_sha256`, `release.digest_algorithm` | Immutable digests of the canonical release manifest and canonical dataset content |
| Publication identity | `release.release_id`, `release.publication_identity`, `release.publication_method`, `release.signing_key_id`, `release.signature_reference`, `release.archive_reference` | Immutable release identity, the named publisher, the declared signing key and the detached signature sidecar |
| Point-in-time lineage | `lineage.basis`, `lineage.universe_version`, `lineage.universe_source_reference`, `lineage.instrument_identity_source_reference`, `lineage.corporate_action_source_reference`, matching `*_sha256` fields, `lineage.as_of_ns`, `lineage.knowledge_time_ns` | Named universe, instrument-identity and corporate-action provenance with digests and one as-of basis |

A coverage claim without a named universe and a denominator is not a claim:
the denominator is the count, or the explicit count basis, of that universe
at `coverage.as_of_ns` against which gaps and completeness are measured.

The producer emits these facts as declarations. A declaration does not create
a right, a coverage verdict, a signature trust or a research entitlement.

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

## 2. Operation sets

The producer and the consumer exercise different operations. This section
defines the two sets and maps both to the canonical rights vocabulary.

### 2.1 Producer operations

These are the operations that occur when Fieldbook creates or maintains a
release. An operation that does not occur is not in the set and needs no
permission entry.

| Producer operation (canonical string) | Role in producing the release |
|---|---|
| `reference_data_retrieval` | Retrieve reference data used to resolve instruments and venues. |
| `historical_data_retrieval` | Retrieve historical observations for a backfill. |
| `real_time_capture` | Capture live observations from the provider feed. |
| `raw_storage` | Store the exact source bytes in the immutable archive. |
| `normalization` | Map source payloads to the typed canonical event vocabulary. |
| `backup` | Maintain a recoverable copy of the archive. |
| `replay` | Re-read stored source bytes to rebuild or verify a release. |
| `retention` | Keep stored material for the bounded retention term. |

Each operation in this set needs its own permission. The canonical `Operation`
enum also contains `source_contact`, `derived_data_creation`, `display`,
`external_redistribution` and `deletion`; none is part of release creation or
maintenance and none is authorized by this document. A permission for one
operation does not cover another.

### 2.2 Consumer operations

These are the operations Nirnay needs to consume an admitted release. The
canonical `Operation` column is the mapping into the typed vocabulary used by
the rights implementation; the consumer-side name is not a new right.

| Consumer operation (Nirnay need) | Canonical `Operation` | Usage right | Usage mode | Recipient |
|---|---|---|---|---|
| `read_release` | `internal_analytics` | `internal_processing` | `non_display` | `internal` |
| `store_permitted_research_copy` | `raw_storage` | `historical_storage` | `non_display` | `internal` |
| `replay` | `replay` | `historical_storage` | `non_display` | `internal` |
| `internal_analytics` | `internal_analytics` | `internal_processing` | `non_display` | `internal` |
| `retain_permitted_derived_data` | `retention` | `derived_data` | `non_display` | `internal` |

The consumer set need not equal the producer set. `read_release` is the
admission-time read of a published artifact and maps to internal analysis;
`store_permitted_research_copy` is a bounded research copy, not a competing
raw archive. An extra grant does not imply unapproved activity: an operation
outside the consumer's needed set, or an extra operation named in a record,
does not authorize that activity. No operation is inferred from another, and
the operation performed is checked at the egress boundary.

### 2.3 Canonical rights vocabulary

Six separate concepts must not be conflated:

- **Operation** is the typed lifecycle action. The `Operation` enum has 14
  values: `source_contact`, `reference_data_retrieval`,
  `historical_data_retrieval`, `real_time_capture`, `raw_storage`,
  `normalization`, `replay`, `backup`, `internal_analytics`,
  `derived_data_creation`, `display`, `external_redistribution`, `retention`,
  `deletion`. A proof names one operation and is not inferred from a command
  name.
- **Usage right** is the class of right exercised. The `UsageRight` values are
  `real_time_access`, `historical_storage`, `internal_processing`,
  `derived_data` and `redistribution`. `historical_storage`, `derived_data`
  and `redistribution` need an explicit grant; public access cannot imply
  them.
- **Usage mode** is how a permitted use is presented, not the right that
  permits it. The `UsageMode` values are `display` and `non_display`.
- **Purpose** is why the right is exercised. The implemented `Purpose` values
  are `internal_analysis`, `display`, `redistribution`, `derived_product`,
  `historical_archive` and `compliance`. The research purpose in this contract
  is proprietary, own-account trading research. The written record states that
  purpose explicitly and records the canonical value `internal_analysis`. The
  purpose must not be characterized as academic or non-commercial research.
- **Recipient** is the class of party exercising the right. The `Recipient`
  classes are `public`, `internal`, `participant`, `customer` and `affiliate`.
- **Licensee** is the named legal entity that holds the licence. A licence
  belongs to no command, process or operator flag. The recipient class that
  exercises it must equal the class recorded in the written permission.

## 3. Rights evidence record

A permission is a written, reviewed record, not a manifest declaration. The
record carries these fields. A missing, blank, malformed or out-of-scope field
is a denial.

| Evidence field | Required content | Code mapping |
|---|---|---|
| `permission_id` | Stable identifier of this permission grant | `decision_key` of the authorization record |
| `provider` | Provider identity of the licensed source | `provider_id` |
| `source_product` | Source product and source identity | `source_id`, `product_id` |
| `venue` | Named venue; an absent venue is a denial | `venue` |
| `segment` | Named data segment | `segment` |
| `instrument_universe_scope` | Instrument set and declared universe id | `instruments`, universe id |
| `field_modality_scope` | Field set and market-depth modality set | `fields`, `modalities` |
| `date_range` | Inclusive data time window covered | `data_time_window` |
| `territory` | Territory of the grant | `territory` |
| `licensee` | Named legal entity holding the licence | `licensee` |
| `recipient` | Class of recipient exercising the right | `recipient` |
| `purpose` | Proprietary own-account trading research, recorded as `internal_analysis` | `purpose` |
| `permitted_operations` | Exact set of canonical operations granted | `operation`, one record per operation |
| `usage_right`, `usage_mode`, `delivery_method` | Right exercised, presentation mode and delivery method | same-named scope fields |
| `retention` | Bounded maximum age and purge rule | `retention` |
| `effective_interval` | Start and optional end of grant validity | `valid_from`, `valid_until` |
| `document_reference` | Reference to the written contract document | `licence_reference` |
| `document_sha256` | Lowercase hex SHA-256 of that document | `licence_document_hash` |
| `contract_revision` | Nonzero contract revision number | `contract_revision` |
| `review_date` | Date on which the written record was reviewed | manifest `rights.review_date` |
| `recording_authority` | Authority that recorded the decision | `authority` |

One evidence record covers one operation. An operation not named in a record
has no permission. This record stands independently of any release signature
and of any admission receipt.

## 4. Trust model and release signature

Fieldbook reuses Nirnay's detached signature envelope at
`schemas/research/dataset-signature.v1.schema.json` (`$id`:
`https://nirnay.dev/schemas/research/dataset-signature.v1.schema.json`). The
envelope is a separate `signature.json` sidecar with exactly five fields:
`schema_version` = 1, `algorithm` = `Ed25519`, `key_id`, `manifest_sha256` and
`signature_b64`.

### 4.1 Signature terms

- **Producer identity** is the named publisher in
  `release.publication_identity`. The signing key must be bound to that
  identity in the consumer's trusted registry.
- **Signing key id** is `key_id`: an Ed25519 key identifier that resolves in
  the consumer's registry to one 32-byte public key.
- **Canonical manifest digest** is `manifest_sha256`: 64 lowercase hex digits
  of the SHA-256 over the canonical manifest bytes defined in section 4.2.
- **Signature** is `signature_b64`: base64 of the 64-byte Ed25519 signature
  over the domain-separated digest defined in section 4.2.
- **Trusted public key** is the 32-byte Ed25519 public key registered for
  `key_id`.
- **Key validity and revocation** are properties of that registry entry. The
  entry must be valid at the verification instant; an unknown, malformed,
  expired or revoked key fails closed.
- **Consumer verification result** reports status `verified_internal_integrity`
  with `cryptographic_signature_verified`, `signature_key_id` and
  `quality_or_entitlement_certified` set to `false`. Any failed check is a
  rejection, not a partial verification.

### 4.2 Hashed bytes

Canonical JSON means object keys sorted in ascending order, no insignificant
whitespace, UTF-8 bytes with non-ASCII characters emitted literally, no NaN or
Infinity, and decimals rendered as fixed-point strings. The hashed bytes carry
no trailing newline.

- The **canonical manifest** is the published manifest object with its
  `dataset`, `artifacts` and `publication` members. Its digest is
  `manifest_sha256`. The file's trailing newline is excluded from the hash.
- The **signature sidecar is self-excluded**: `signature.json` is a detached
  artifact and is not a member of the manifest object, so changing it does not
  change `manifest_sha256`. The manifest does not hash or embed its own
  signature.
- The **canonical data digest** `data_sha256` is SHA-256 over the newline-joined
  canonical bytes of the records in a declared deterministic record order. The
  order key is receive time, canonical instrument id, provider and canonical
  event id. Arrival order is not used.
- The **signed message** is the ASCII domain prefix
  `NIRNAY-PIT-DATASET-MANIFEST-SHA256-V1` followed by one NUL byte (`0x00`) and
  the 32-byte manifest digest. Ed25519 signs those bytes, not the manifest
  text.

### 4.3 Non-claims

A signature proves publisher-key control and manifest integrity only. It does
not prove source authenticity, completeness or permission. Rights evidence in
section 3 stands independently: no signature, digest or admission receipt
creates or proves a right.

## 5. Time semantics

Each timestamp is emitted with its clock domain and identity. The following
times are distinct and are not substituted for one another.

- **Source event time** is the time the source assigns to the observation. Its
  original resolution and unit are preserved; a unit change is not added
  precision.
- **Receive time** is the instant the producer received the observation in the
  producer's clock domain.
- **Valid time** is the interval over which the observation holds, with an
  open end where no end is known.
- **Knowledge time** is the instant at which the producer knew a fact or a
  revision. It drives point-in-time selection at an as-of instant.
- **Availability time** is the instant at which the observation became
  available for publication.

Corporate actions carry announcement time (the knowledge time of the
announcement), record date, ex-date, effective time (when the action applies
to prices or instruments) and revision knowledge time (when a correction to
the action became known). Each is stored with its own knowledge time.

A correction produces a new revision with a new knowledge time and, where
published, a new release identity. The prior revision and its knowledge time
are retained. History is not rewritten, and a view is selected by as-of
instant and knowledge time rather than arrival order.

## 6. Producer validation

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
5. **Exact operations.** Require a permission for every producing operation in
   section 2.1 and for every consumer operation in section 2.2 that the release
   supports, each citing the same written record. Require operation strings to
   be members of the canonical `Operation` enum. An extra operation is a
   mismatch and grants nothing.
6. **Rights evidence.** Require every field in section 3 with its declared
   type and scope. A missing, blank, malformed, out-of-scope or expired record
   is a denial.
7. **Coverage basis.** Require one declared `coverage.universe_id` and a
   `coverage.denominator` with a defined count basis at `coverage.as_of_ns`.
   A gap is measured against that denominator.
8. **Scope consistency.** Require rights, coverage, lineage and dataset
   source scope to name the same provider, product, venue and segment, with
   one declared universe id across those sections.
9. **Release digest.** Compute the manifest and data digests over the canonical
   bytes and deterministic record order in section 4.2, and publish them with
   the declared algorithm. A mismatch after publication blocks use of the
   release.
10. **Signature.** Require a detached sidecar matching the envelope in section
    4, a declared `key_id`, and a `manifest_sha256` equal to the recomputed
    manifest digest. A valid signature is not rights evidence.
11. **As-of semantics.** Emit one as-of basis and instant. Refuse lineage
    knowledge time after the as-of instant. Do not select a revision by
    arrival order.
12. **Typed payload.** Refuse an unregistered event type, an untyped payload,
    a null presented as zero, or a timestamp with an undeclared unit.
13. **Continuity.** Report gaps against the declared provider and partition
    scope. A declared gap is a bounded coverage claim, not a filled
    observation.
14. **Archive link.** Emit a raw digest and an archive reference on every
    event. Do not create a substitute observation when either is absent.
15. **Publication gate.** Do not publish a release that fails any check above
    or lacks a written rights record. The consumer repeats these checks; a
    producer decision does not replace consumer admission.

Validation reads declarations, evidence and digests. It does not acquire
provider data, replay provider traffic or produce a market observation.

## 7. Rejection semantics

| Code | Trigger | Producer behavior |
|---|---|---|
| `REJECT_CONTRACT_VERSION` | Unsupported major version | Stop; publish no release and request a migration record |
| `REJECT_INCOMPLETE` | Missing, empty or mistyped required field | Stop; name the field path |
| `REJECT_VERDICT` | A rights or coverage verdict is not passing | Stop; name the field and observed value |
| `REJECT_VALIDITY` | Review, validity or expiry bound precedes the as-of UTC date | Stop; treat denied, expired and revoked references as refusals |
| `REJECT_RETENTION` | Retention is missing, open-ended or unbounded | Stop; require bounded days or an ISO-8601 duration |
| `REJECT_OPERATIONS` | A producing or consumer operation lacks a permission, or a string is outside the canonical enum | Stop; infer no operation from another operation |
| `REJECT_EVIDENCE` | A rights evidence field is missing, malformed, out of scope or expired | Stop; name the field path |
| `REJECT_COVERAGE_BASIS` | Universe or denominator is absent, undefined or inconsistent | Stop; do not widen a coverage claim |
| `REJECT_SIGNATURE` | Sidecar schema, key, digest or signature mismatch, or an unknown or revoked key | Stop; withdraw the release identity from publication |
| `REJECT_RIGHTS` | Exact operation set, scope or written reference differs | Stop; infer no operation from another operation |
| `REJECT_DIGEST` | Manifest or data digest mismatch | Stop; withdraw the release identity from publication |
| `REJECT_SCOPE` | Source scope or universe id differs between sections | Stop; do not merge scopes |
| `REJECT_ASOF` | As-of basis or instant differs, or knowledge time leaks | Stop; do not substitute a subsequent revision |
| `REJECT_PAYLOAD_TYPE` | Unknown event type, untyped payload or unit error | Stop; do not coerce a missing value into zero |
| `REJECT_CONTINUITY` | Undeclared gap or sequence discontinuity | Stop; do not interpolate |
| `REJECT_ARCHIVE` | Raw digest or archive reference absent | Stop; do not treat a derived value as raw |
| `REJECT_ADMISSION` | No valid admission receipt for the exact release | Stop; no research use and no experiment registration |

A release is admitted or rejected as a whole. The consumer rejects
inconsistent or partially valid releases; no subset of events, fields or
verdicts is admitted, and no value is substituted from another revision.

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

## 8. Relation to the repository gate

W1 binds provider activity to explicit authorization, fail-closed rights and
a scoped audit event; it does not grant a collection right. This document
changes no right, no capability record, no claim record and no experiment
state. It selects no final schema, no transport, no shared crate and no
storage technology. Rights remain `UNKNOWN` and dataset acceptance remains
BLOCKED while the source rights are unevidenced. The consumer counterpart is
Nirnay's `engineering/ndc-consumer-requirements-v1.md`; the ownership decision
and the NDC semantic definitions remain Proposed until owner ratification.
