# Fieldbook B1 authorization identity — 2026-11-23

<!-- SPDX-License-Identifier: Apache-2.0 -->

**Record:** `docs/authorization-identity-2026-11-23.md`
**Date:** 2026-11-23
**Work item:** W2.1 STEP 3 — Fieldbook B1: actor, action, object and recipient identity
**Branch:** `feat/w21-b1` on base `d686067`
**Status:** Proposed implementation of a Proposed model; not a ratified contract
**Rights effect:** none. No right is granted, changed, reviewed or exercised.

## 1. Governing sources

- `NDC-SEMANTIC-MODEL-V2-PROPOSED.md` (C0), sections 2, 2.1, 2.4 and 9.
- `engineering/ndc-producer-requirements-v2-proposed.md`, sections 2, 3, 6 and 9.
- `docs/rights-enforcement-2026-11-23.md` and
  `docs/egress-intent-2026-11-23.md` remain the historical records for the
  earlier rights and lifecycle work.

This record adds typed identity to the existing authorization gate. It does not
publish a release, accept a dataset or change a documentation digest.

## 2. Semantics

### 2.1 Typed actor

`Actor` has exactly four values: `FieldbookProducer`, `NirnayConsumer`,
`RightsAuthority` and `SigningAuthority`. It is a required field of
`AuthorizationScope`, `EgressIntent`, the request builder and the audit event.
An actor is declared by the caller; a command name, transport action, proof or
existing permission never supplies one.

### 2.2 Typed data object

`ObjectKind` covers `SourceReferenceRecord`, `RawSourceRecord`,
`CanonicalObservation`, `RawArchive`, `NdcRelease`, `ResearchCopy`,
`ResearchDataset` and `DerivedArtifact`. `DataObject` binds a kind to two
further required components: `ObjectIdentity` (`id`) and `ObjectVersion`
(`version`), each validated as non-blank. A kind alone is not an object:
`RawArchive("archive-a", "v1")` and `RawArchive("archive-b", "v1")` are
different objects, and a new version of one identity is a different object.

The authorization tuple binds the action and the full object together. The
existing 14-value `Operation` enum remains the only producer action enum; no
second producer enum and no canonical label are stored in its place. A
source-contact probe also supplies an explicit object identity; its
`NotApplicable` scope sets and zero retention do not imply a data right.

### 2.3 Recipient class and recipient identity

`RecipientClass` is the class of recipient. `Internal` is a class and is not a
named recipient. `RecipientIdentity` is a separate, required, non-blank named
identity. Both are bound to grants, intents, comparison, decision keys and
audit events. The historical `Recipient` name is retained as an alias of
`RecipientClass` so existing call sites do not invent a second class enum.

### 2.4 Full tuple binding

`AuthorizationScope` and `EgressIntent` carry actor, action, object kind and
object identity and version, recipient class and identity, purpose and scope.
The tuple is compared by `AuthorizationScope::exact_match`,
`AuthorizationScope::matches_request`, `AuthorizationIdentity::matches`,
`LicensingRegistry::authorize`, `AuthorizationGate::check_active` and
`AuthorizationGate::require_egress`. It also forms part of the immutability
key (`decision_key`) and of the grant snapshot identity.

`AuthorizationScope::request()` and `EgressIntent::builder()` fail on the first
omitted required value. Blank object id, object version or recipient identity
is rejected; no placeholder, operator identity or command-derived value is
substituted. A grant for an unrelated object never widens a request: a match
requires all three object components and every other exact dimension.

### 2.5 Audit evidence

Each `DecisionAuditEvent` records the exact evaluated actor string, data object
(its kind, id and version), recipient class and named recipient identity, in
addition to the pre-existing operation, scope, decision and reason. Written
evidence is recorded twice in distinct forms: `reference` carries the licence
reference, `grant_evidence_reference` carries `licence_reference#contract_revision`,
`evidence_digest` carries the document digest, and `grant_snapshot_id` carries
the immutable grant snapshot identity. A snapshot identity is not written
evidence, and written evidence is not a permission.

## 3. Test inventory

All new tests are abstract-value tests in `src/governance/rights.rs`. They use
scalar identifiers such as `object-a`, `archive-a`, `v1` and `recipient-b`,
abstract instants and temporary directories. No market observation, synthetic
price, universe, order book, strategy return or provider response exists.

| Test | Case |
|---|---|
| `same_action_different_actor_is_denied` | same action, different actor |
| `object_kind_alone_is_not_an_object_identity` | `RawArchive` kind with different identities |
| `different_object_kind_is_denied` | same id and version, different kind |
| `same_object_kind_different_identity_is_denied` | same kind and version, different identity |
| `different_object_version_is_denied` | same kind and id, different version |
| `same_recipient_class_different_identity_is_denied` | same class, different named recipient |
| `named_licensee_mismatch_denies` | wrong licensee |
| `wrong_purpose_denies_even_with_an_otherwise_exact_grant` | wrong purpose |
| `missing_actor_object_or_recipient_identity_is_rejected` | missing and blank identity fields |
| `unrelated_extra_grants_do_not_extend_a_request` | an extra grant for another object |
| `audit_event_carries_evaluated_identities_and_grant_evidence` | audit identities and evidence reference |
| `producer_operation_enum_has_fourteen_distinct_values` | one 14-value operation enum |

Supporting fixtures in `src/governance/coverage_certification.rs`,
`src/integrity/conformance.rs`, `tests/egress_governance.rs` and
`tests/egress_intent_lifecycle.rs` now supply the required typed values. The
example files `rights.example.toml` and `egress-intent.example.toml` name the
new fields without supplying a real right.

## 4. Architecture and gates

No Rust module was added: the typed identities live in the existing
`src/governance/rights.rs` and `src/governance/egress_intent.rs` modules. The
architecture responsibility mapping for those two modules was updated to
name the new responsibility. No mapping or gate was weakened.

The gates were run with the `market-shaped-tests` feature disabled:
`cargo xtask fmt`, `cargo xtask lint`, `cargo xtask docs`, `cargo xtask style`,
`cargo xtask test` and `cargo xtask verify`, plus
`python3 scripts/check_architecture.py --check`. The complete gate result,
including counts and skipped tests, is reported in the delivery message.

## 5. Non-claims

- All source rights remain `UNKNOWN`. This record and its tests grant nothing.
- No provider was contacted, no market-data API was called, no market
  observation was created and no artifact was collected.
- No dataset acceptance, experiment, live route, order submission or
  collection command is authorised by this change.
- Revocation remains bounded by the declared lease; no instantaneous
  revocation is claimed.
- The NDC v2 model and producer requirements remain Proposed. This record does
  not ratify a final schema, transport, storage choice or shared crate.
- No commit or push was made in this worktree.
