# NDC v2 producer requirements (Fieldbook side) — Proposed

<!-- SPDX-License-Identifier: Apache-2.0 -->

- **Status:** Proposed engineering requirements. Not ratified, not accepted and
  not authorization for provider contact, collection, dataset acceptance or an
  experiment.
- **Version:** `ndc-producer-requirements/v2-proposed`. A semantic change needs
  a new version and a migration record; a field rename is a breaking change.
- **Supersedes:** the operation mapping in
  `engineering/ndc-producer-requirements-v1.md`. This document retires that
  mapping without editing or re-digesting the v1 file. See section 1.
- **Governing source:** `NDC-SEMANTIC-MODEL-V2-PROPOSED.md` (C0, Proposed).
  Implementation records consulted: `docs/scope-containment-2026-11-23.md`,
  `docs/rights-enforcement-2026-11-23.md` and
  `docs/egress-intent-2026-11-23.md`. The consumer counterpart is
  `engineering/ndc-consumer-use-v2-proposed.md` in the Nirnay workspace.
- **Rights effect:** none. All source rights remain `UNKNOWN`. A declaration,
  digest or signature in a release does not create or prove a right.
- **Scope:** the semantic sections a Fieldbook producer publishes on a release,
  the action and object vocabulary, the rights evidence a release depends on,
  the egress-intent boundary, the three independent proofs, coverage
  denominators and producer validation and rejection behavior.
- **Non-goals:** a final NDC JSON schema, transport, storage engine, shared
  crate, release or data object. See section 10.

## 1. Status and relation to v1

This document is a new Proposed document. It does not amend the historical v1
requirements document. The v1 file at the base of this branch
(`33c11faf62f6afb5b55a1974eecc104e58fc0aa2`) has SHA-256:

```text
592a1c9043ed2756a3f9d938dbe6e2ee80007166b440cf6f2709d5de11424c33
```

That digest is preserved. The v1 file is retained byte-for-byte and is not
reformatted, reworded or re-digested here. The only v1 content retired by this
revision is the consumer-use to producer-operation mapping in v1 section 2.2
and the purpose alias in v1 sections 2.3 and 3. The v1 signature envelope,
time semantics and validation order are not redefined by this document; where
C0 states a stricter canonicalization rule, section 7 of this document follows
C0.

## 2. Four-concept semantic core

The producer model uses four separable concepts. No concept is inferred from
another.

| Concept | Question answered | Producer-side form |
|---|---|---|
| Technical action | What does the software perform on an object? | one value of the Fieldbook 14-value `Operation` enum, stored as the enum value |
| Data object | What does the action act upon? | an explicit object class: source reference record, raw source record, canonical observation, release, raw archive, research copy or derived artifact |
| Legal permission grant | What does the written agreement allow for that action and object? | one reviewed `PERMIT` grant per action, object and identity, with a written evidence reference |
| Purpose | Why is the action performed? | the exact string `proprietary_own_account_trading_research` from the written permission |

A capability is not a permission. A permission is not an action. An action on a
raw source record is not the same action on a research copy. A signature is not
a licence.

Every authorization and every grant carries the following attributes. None has
a runtime default and none is supplied by a command name or an existing proof.

| Attribute | Binding |
|---|---|
| `actor` | Fieldbook producer, Nirnay consumer, rights authority or signer, named per declaration |
| `licensee` | the named individual or legal entity in the written permission; no command, process or operator flag substitutes for it |
| `recipient` | a named recipient class and a named recipient; the requested class equals the class in the grant |
| `scope` | source scope (provider, source product, venue, segment, dataset), subject scope (instruments, fields, modality, universe version) and the observed data-time interval |
| `validity` | operational `effective_from` / `effective_until`, decision state, registry revision, immutable grant snapshot identity, lease and renewal; data time and operational time are independent intervals with `from <= to` |
| `delivery` | the declared delivery method (API, multicast, file or specified method) and the endpoint identity accepted for egress |
| `retention` | a typed policy with a maximum duration and a purge rule; a bounded grant covers a narrower request, and an indefinite request is not covered by a bounded grant |
| `evidence` | document reference, clause, document digest, review authority and review date; a performed action carries a separate audit record or durable receipt |

## 3. Technical action vocabulary

C0 defines canonical action labels to keep actor and object semantics explicit,
then maps them to the authoritative Fieldbook enum. Neither enum is renamed and
no label is stored in place of an enum value.

| Canonical action | Typical object class |
|---|---|
| `source_contact` | endpoint, no data object |
| `reference_data_retrieval` | source reference records |
| `historical_data_retrieval` | historical observations |
| `real_time_capture` | source stream observations |
| `store` | raw source record, release, research copy, derived artifact |
| `normalize` | canonical observations |
| `backup` | raw archive |
| `replay` | raw archive, research copy |
| `analyze` | admitted research dataset |
| `create_derived` | derived research artifact |
| `retain` | raw archive, release, derived artifact |
| `delete` | any retained object |
| `display` | display-form data |
| `redistribute` | external report or dataset |

| Canonical action | Fieldbook `Operation` (14 values) |
|---|---|
| `source_contact` | `SourceContact` |
| `reference_data_retrieval` | `ReferenceDataRetrieval` |
| `historical_data_retrieval` | `HistoricalDataRetrieval` |
| `real_time_capture` | `RealTimeCapture` |
| `store` (raw object) | `RawStorage` |
| `normalize` | `Normalization` |
| `backup` | `Backup` |
| `replay` (producer) | `Replay` |
| `retain` | `Retention` |
| `delete` | `Deletion` |
| `analyze` | `InternalAnalytics` |
| `create_derived` | `DerivedDataCreation` |
| `display` | `Display` |
| `redistribute` | `ExternalRedistribution` |

The 14-value `Operation` enum is the authority for producer actions. An
implementation stores the enum value. `source_contact` is an egress prerequisite
and is not a data-producing operation; it enters `producer_activity` only when
it itself produced retained data. The purpose is the exact string
`proprietary_own_account_trading_research`. It is not `academic_research`,
`non_commercial_research`, `internal_analysis` or `historical_archive`, and no
other value replaces it. The licensee is the named individual or legal entity
from the written permission, not an inferred operator identity.

## 4. Removed v1 mapping

The v1 section 2.2 table mapped Nirnay consumer needs into Fieldbook's producer
`Operation` enum. That table is removed and is not carried into this revision:

| Removed v1 row | Removed v1 target |
|---|---|
| `read_release` | `internal_analytics` |
| `store_permitted_research_copy` | `raw_storage` |
| `replay` | `replay` |
| `internal_analytics` | `internal_analytics` |
| `retain_permitted_derived_data` | `retention` |

A consumer use is declared by Nirnay and evaluated against permission grants.
It is not inferred from a producer operation, and no producer operation is
mapped from a consumer use. Nirnay's `CONSUMER_OPERATIONS`
(`read_release`, `store_permitted_research_copy`, `replay`,
`internal_analytics`, `retain_permitted_derived_data`) stays authoritative and
unchanged. Derived-data creation is the separate requested action
`create_derived`, which is not a value of `CONSUMER_OPERATIONS` and is not
implied by a retention grant. The declaration and evaluation rules are in
`research/python/src/quantlab/consumer_use.py` and
`engineering/ndc-consumer-use-v2-proposed.md` in the Nirnay workspace. A
release manifest names no consumer use and grants nothing to a consumer.

## 5. Release structure

A release is a set of distinct sections. A fact appears in one section only.

### 5.1 release_identity

| Field | Meaning |
|---|---|
| `release_id` | immutable identity of this release; a correction receives a new identity |
| `contract_version` | exact contract major and minor version |
| `release_version` | version of the release within the identity |
| `as_of_ns` | point-in-time instant for revision selection |
| `publication_state` | declared publication state of the identity |

### 5.2 source_scope

| Field | Meaning |
|---|---|
| `provider_id` | named provider |
| `source_product_id` | named source product |
| `venue_id` | named venue; an absent venue is a denial |
| `segment_id` | named venue market segment, not an operational placeholder |
| `dataset_id` | named dataset |

Source scope is declared, not inferred from an instrument symbol or a command.

### 5.3 producer_activity

This section has exactly two members. It contains no permission, grant,
purpose, licensee, recipient, coverage verdict or signature.

| Member | Meaning |
|---|---|
| `performed_operations` | actions Fieldbook performed to create or maintain the release, each with its object class; producer actions are `reference_data_retrieval`, `historical_data_retrieval`, `real_time_capture`, `store` of exact source bytes, `normalize`, `backup`, `replay` of the raw archive and `retain` |
| `operation_evidence` | for each performed action, a link to its audit record or durable receipt with event identity, run identity, UTC instant, decision key and digest |

An operation that did not occur is not listed. A listed operation grants itself
and no other operation. The matching permission is declared in `rights`, not in
`producer_activity`.

### 5.4 rights

| Member | Meaning |
|---|---|
| `permission_grants` | one grant per action, object and identity, with `grant_id`, enum value, object class, `PERMIT` or `DENY` decision, actor, licensee, recipient, scope, validity interval, delivery method and typed retention |
| `document_references` | written agreement reference, clause, lowercase hex document digest, contract revision, review date and review authority |
| `reviewed_attestations` | the exact purpose string, usage right, usage mode, territory and scope assertions, with the named reviewer and review authority |

A grant with `DENY`, a missing grant, two grants for one action or an ambiguous
grant denies. An attestation records that a written record was reviewed; it is
not a permission for an action absent from a grant.

### 5.5 coverage

Each of the nine dimensions in section 8 carries its own named universe,
denominator, count basis, `as_of_ns` and verdict. A single count does not
establish coverage across dimensions, and a passing verdict in one dimension
does not imply a verdict in another.

### 5.6 lineage

Lineage follows W3C PROV-O: Entity (source record, release, research copy),
Activity (retrieval, normalization, publication), Agent (producer, consumer,
rights authority, signer), with `wasDerivedFrom`, `wasRevisionOf`,
`hadPrimarySource`, `generatedAtTime`, `invalidatedAtTime` and qualified
attribution. It carries the raw archive reference, its digest and the
transformation record. A correction produces a new revision and a new release
identity; the prior revision and its knowledge time stay in lineage. A view is
selected by as-of instant and knowledge time, not by arrival order. PROV
semantics describe lineage; they establish permission and truth for nothing.

### 5.7 schema_versions

| Field | Meaning |
|---|---|
| `contract_version` | identity of the release contract |
| `normalizer_version` | identity of the transformation applied before publication |
| `payload_schema_version` | version per event type |
| `envelope_version` | version of the event envelope |

### 5.8 digests

| Field | Meaning |
|---|---|
| `manifest_sha256` | SHA-256 over the RFC 8785 canonical manifest bytes |
| `data_sha256` | SHA-256 over canonical records in a declared deterministic order |
| `digest_algorithm` | named algorithm of the published digests |
| `artifact_digests` | digests of the published artifacts |

Exact financial decimals and arbitrary-precision integers are JSON strings.
Arrival order is not the deterministic record order. A mismatch after publication blocks use of
the release.

### 5.9 publication_identity

| Field | Meaning |
|---|---|
| `publisher_identity` | named publisher bound to the signing key in the trusted registry |
| `signing_key_id` | key identifier resolving to one public key in that registry |
| `signature_reference` | detached signature sidecar reference |
| `archive_reference` | immutable archive reference |

Key validity and revocation belong to the registry entry. An unknown,
malformed, expired or revoked key fails closed.

## 6. Egress intent

The caller supplies the actual request. The authorization gate does not
reconstruct it from an installed proof or a declaration in a release.

```text
EgressIntent
├── provider_id, source_product_id, venue_id, segment_id, dataset_id
├── operation, purpose, usage_mode, licensee, recipient, territory
├── instruments, fields, modalities
├── data_time_window
├── endpoint_identity
└── retention_request
```

The gate requires every exact dimension to be equal and every scoped dimension
to lie inside the grant. No generic default such as territory `US`, licensee
`fieldbook-operator`, product `market-data-feed` or segment `history` produces
a permission.

- **Endpoint authority.** `endpoint_identity` must be a member of the grant's
  approved endpoint set. An empty approved set covers no real endpoint. An
  endpoint outside that set is a denial, not a permission.
- **Checkpoint order.** Authorization is checked before DNS, TCP, TLS and any
  protocol upgrade. An HTTP redirect to a different authority is reauthorized;
  an unparseable URL, a changed venue, an endpoint outside the approved set or
  a failed gate stops the redirect. A widened WebSocket subscription is
  reauthorized, and a session checkpoint is the mid-session stop point when a
  lease is invalidated.
- **Lease and revocation.** The rights registry carries a monotonic revision;
  a proof carries that revision and an immutable grant snapshot identity. A
  short-lived lease has a declared maximum duration; the C2 record declares a
  15-minute ceiling. A session carries its identity, expiry and renewal count.
  Revision changes and snapshot revocations cancel the session. A failed
  authority refresh denies. The maximum revocation propagation time equals the
  lease duration; an instantaneous claim requires a separate, tested rapid
  notification channel.
- **Mandatory audit.** A permitted decision is committed durably before the
  caller may contact a provider. An audit write failure prevents installation
  and egress. A denial stays a denial when audit writing fails. Audit events
  carry the actual operation, the full identity and scope, the decision, the
  reason, the licence reference and digest, the recording authority, the
  registry revision and the grant snapshot identity.

## 7. Three independent proofs

Each proof establishes one thing and not the others. The publication key and
the rights-review authority are separate trust relationships.

### 7.1 Publisher integrity

A detached signature sidecar carries the signature alongside the manifest; the
signature is not a property inside the manifest object. The Ed25519 signature
is over a domain-separated digest of the canonical manifest bytes. Verification
requires a key bound to the named publisher in the trusted registry, a valid
and unrevoked key at the verification instant, and a recomputed digest equal to
the declared digest. A failed check rejects the release; there is no partial
verification.

### 7.2 Canonical bytes

RFC 8785 JSON Canonicalization Scheme is applied to the manifest object itself.
No property removal is needed because no signature property exists in that
object. The rules applied here are:

- the `I-JSON` subset, with no duplicate property names and Unicode strings
  preserved as-is;
- no whitespace between tokens and recursive property-name sorting by UTF-16
  code units;
- array order preserved, so a semantically unordered set requires a defined
  deterministic order before canonicalization;
- UTF-8 output;
- exact financial decimals and arbitrary-precision integers rendered as JSON
  strings, not IEEE 754 numbers;
- NaN, Infinity and lone surrogates terminate the operation;
- the detached signature sidecar is outside the canonicalized bytes and does
  not enter the manifest digest.

### 7.3 Source lineage

Source lineage is the raw archive reference, the exact source-byte digests, the
transformation record and the point-in-time revision chain in section 5.6. It
binds a release to the bytes it was produced from.

### 7.4 Rights attestation

Rights evidence is the reviewed written agreement, the exact action, object,
scope, purpose, licensee, recipient, retention and validity in its grants, the
document digest and the review authority and date. A grant decision stands
independently of the release signature and of any admission receipt.

### 7.5 Non-claims

| Proof | Establishes | Does not establish |
|---|---|---|
| Publisher integrity | trusted signing key control and unchanged signed manifest bytes | source authenticity, coverage or permission |
| Source lineage | raw archive reference, digests and transformation record | truth of the observations |
| Rights attestation | reviewed written agreement, exact scope and document digest | permission for an unlisted action, object, purpose or recipient |

## 8. Coverage dimensions

One count cannot establish all coverage. Each dimension has its own universe
and denominator.

| Dimension | Denominator |
|---|---|
| Instrument coverage | declared point-in-time instrument universe |
| Listing / identity coverage | declared listing and identifier assertions |
| Contract coverage | declared derivative or commodity contract set |
| Corporate-action coverage | declared action universe per instrument and period |
| Session / time coverage | declared venue calendar and session intervals |
| Trade-event coverage | declared trades in scope |
| Quote / depth coverage | declared BBO or MBP levels and snapshots |
| MBO coverage | declared order lifecycle events |
| Sequence continuity | declared sequence ranges and gap policy |

Passing one dimension implies nothing about another. A gap is measured against
the denominator of its own dimension at its own as-of instant.

## 9. Producer conformance and typed rejection

### 9.1 Conformance matrix

| Area | Producer obligation | Checked evidence | Rejection on failure |
|---|---|---|---|
| Release identity | emit one immutable `release_id` and exact contract version | `release_identity` | `REJECT_RELEASE_IDENTITY` |
| Four concepts | declare action, object, grant and purpose as separate facts | `rights`, `producer_activity` | `REJECT_CONCEPT_CONFLATION` |
| Action vocabulary | store the 14-value enum value, with an explicit canonical label mapping | `performed_operations` | `REJECT_OPERATION_ENUM` |
| Purpose | preserve `proprietary_own_account_trading_research` verbatim | `reviewed_attestations` | `REJECT_PURPOSE` |
| Licensee | name the legal entity from the written permission | `permission_grants` | `REJECT_LICENSEE` |
| Producer activity | list only actions performed, with evidence and no permissions | `operation_evidence` | `REJECT_PRODUCER_ACTIVITY` |
| Rights | one decision and one written evidence reference per grant | `document_references` | `REJECT_RIGHTS_EVIDENCE` |
| Grant ambiguity | no duplicate, conflicting or overlapping grants for one action | `permission_grants` | `REJECT_AMBIGUOUS_GRANTS` |
| Consumer uses | map no consumer use into the producer enum and infer no operation | release sections | `REJECT_CONSUMER_USE_MAPPING` |
| Coverage | name all nine denominators and their count bases | `coverage` | `REJECT_COVERAGE_DENOMINATOR` |
| Lineage | name raw archive digests, transformation record and PROV relations | `lineage` | `REJECT_SOURCE_LINEAGE` |
| Digests | publish JCS manifest and deterministic data digests | `digests` | `REJECT_DIGEST` |
| Publication | bind the signing key to the publisher and keep the sidecar detached | `publication_identity` | `REJECT_SIGNATURE` |
| Egress intent | require a caller-supplied intent, endpoint authority, reauthorization and lease | authorization audit events | `REJECT_EGRESS_INTENT` |
| Scope containment | contain every exact and scoped dimension; bounded grants cannot cover unbounded requests | grants versus intent | `REJECT_SCOPE` |
| Retention | use a typed bounded policy with a purge rule | grants and intent | `REJECT_RETENTION` |
| Completeness | emit every required field with its declared type | all sections | `REJECT_INCOMPLETE` |

### 9.2 Typed rejection semantics

Validation is ordered and stops at the first refusal. A subsequent check does
not soften an earlier failure. A release is admitted or rejected as a whole.

| Code | Trigger | Producer behavior |
|---|---|---|
| `REJECT_INCOMPLETE` | a required field is missing, empty or mistyped | stop and name the field path |
| `REJECT_AMBIGUOUS_GRANTS` | duplicate, conflicting or overlapping grants for one action | stop; ambiguity denies; infer no decision |
| `REJECT_AMBIGUOUS_RELEASE` | sections name different identities, scopes, purposes or as-of instants | stop; merge no scopes and select no revision by arrival order |
| `REJECT_RELEASE_IDENTITY` | release identity or contract version is absent or unsupported | stop; request a migration record for an unknown major version |
| `REJECT_CONCEPT_CONFLATION` | a permission is placed in `producer_activity` or an operation is inferred from another | stop; declare the fact in its own section |
| `REJECT_OPERATION_ENUM` | an operation value is outside the 14-value enum | stop; infer no operation from a label or command |
| `REJECT_PURPOSE` | purpose wording differs from the reviewed string | stop; substitute no nearby purpose label |
| `REJECT_LICENSEE` | licensee is missing or differs from the written permission | stop; accept no operator identity |
| `REJECT_PRODUCER_ACTIVITY` | a listed action was not performed or has no operation evidence | stop; grant nothing to the listed action |
| `REJECT_RIGHTS_EVIDENCE` | grant evidence, decision or validity is missing, expired or revoked | stop; name the grant and field |
| `REJECT_CONSUMER_USE_MAPPING` | a consumer use is mapped into the producer enum | stop; evaluate consumer use against grants instead |
| `REJECT_COVERAGE_DENOMINATOR` | a named universe, denominator, count basis or verdict is absent | stop; widen no coverage claim |
| `REJECT_SOURCE_LINEAGE` | raw archive digest, transformation record or PROV relation is absent | stop; treat no derived value as raw |
| `REJECT_DIGEST` | manifest or data digest does not match the recomputed digest | stop; withdraw the release identity from publication |
| `REJECT_SIGNATURE` | sidecar, key, digest or signature binding fails | stop; withdraw the release identity from publication |
| `REJECT_EGRESS_INTENT` | request is inferred, endpoint is unapproved or a checkpoint is missing | stop; no egress before an authorized decision and durable audit |
| `REJECT_SCOPE` | an exact dimension differs or a scoped request exceeds the grant | stop; merge no scopes |
| `REJECT_RETENTION` | retention is missing, open-ended or exceeds the grant | stop; require a bounded maximum and purge rule |

A rejected release is not partially published. No observation, digest, verdict
or grant from it enters a research dataset or an experiment record. A synthetic
or self-attested artifact is not a fallback. A correction receives a new release
identity and the prior identity stays in lineage. A new optional field does not
change the major version; a renamed, removed or retyped required field, a
changed verdict vocabulary or a changed digest algorithm requires a new major
version and a migration record.

## 10. Non-goals and non-claims

This document creates no final NDC JSON schema, no transport, no storage
choice, no shared crate, no release and no data object. It selects no
technology and changes no right, capability record, claim record, experiment
state or dataset acceptance. All source rights remain `UNKNOWN`; a successful
connection, a token or a checksum grants no retention, replay, analytics or
redistribution right. No provider is contacted, no market-data API is called
and no market observation is created by this document.

## 11. External references

| Source | Use |
|---|---|
| RFC 8785, JSON Canonicalization Scheme | canonical manifest bytes for signing (https://www.rfc-editor.org/rfc/rfc8785.txt) |
| W3C PROV-O Recommendation 2013-04-30 | provenance vocabulary for `lineage` (https://www.w3.org/TR/prov-o/) |
| Fieldbook `Operation` enum (W1.1-C) | producer action authority |
| Nirnay `CONSUMER_OPERATIONS` | consumer use authority, unchanged |
