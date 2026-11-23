# Fieldbook B2 universe containment and applicability — 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

**Record:** `docs/universe-containment-2026-11-24.md`
**Date:** 2026-11-24
**Work item:** W2.1 STEP 4 — Fieldbook B2: universe containment and applicability
**Branch:** `feat/w21-b2` on base `8bba094`
**Status:** Proposed implementation of a Proposed model; not a ratified contract
**Rights effect:** none. No right is granted, changed, reviewed or exercised.

## 1. Governing sources

- `NDC-SEMANTIC-MODEL-V2-PROPOSED.md` (C0, Proposed), sections 2, 2.4, 5.6
  and 9.
- `engineering/ndc-producer-requirements-v2-proposed.md`, sections 2, 3, 5.6,
  6 and 9.
- `docs/authorization-identity-2026-11-23.md` (B1) for the eight typed
  `ObjectKind` values.
- `docs/scope-containment-2026-11-23.md` for the baseline scope-set states.

B2 adds versioned universe identity and an operation-object applicability
matrix to the existing authorization gate. It publishes no release and accepts
no dataset.

## 2. Versioned universe reference

`UniverseRef` replaces the former bare `Universe(String)` label. Every field is
explicit and validated; none is inferred from a command, a clock or a symbol
that exists today.

| Field | Binding |
|---|---|
| `universe_id` | stable identity of the universe, independent of a version |
| `version` | exact version; a different version is a different set |
| `digest` | lowercase hex SHA-256 of the exact version's membership bytes |
| `membership_source` | named source that produced the membership facts |
| `valid_time` | data-time interval for which the version may be consulted |
| `knowledge_time` | knowledge-time interval in which the version was known |
| `revision` | nonzero declaration revision |

`ScopeSet::contains_all` now covers a universe only when the reference is
exactly equal. The former rule that admitted every named request from any
universe has been removed. Named-member containment is available only through
`contains_universe_member` with a recorded `UniverseMembershipRegistry` and an
explicit `MembershipTime` (data-as-of and knowledge-as-of). Every requested
name must have a recorded fact for the exact reference and both instants. An
unknown name, a different version, a different digest or a different instant
denies. No present-day symbol resolution is performed.

## 3. Applicability matrix

`applicability_for(operation, object_kind)` is the single matrix. An unlisted
action-object pair is prohibited. `validate_applicability` is called from
`AuthorizationScope::validate`, which both grants and requests pass before any
containment comparison.

Dimension levels are `Required`, `Optional`, `Inherited`, `NotApplicable` and
`Prohibited`. Provider, venue and segment remain explicit: a blank value is a
missing required dimension, never `NotApplicable`. Scope representations are
`named`, `universe` and `all`; `all` is allowed only where the matrix declares
it and is never a runtime default.

| Operation | Permitted object kinds | Sets | Data time | Retention | Representations |
|---|---|---|---|---|---|
| source_contact | source reference record, raw source record | NotApplicable | NotApplicable | NotApplicable | none |
| reference_data_retrieval | source reference record | Required | Required | Inherited | named, universe |
| historical_data_retrieval | canonical observation, raw archive | Required | Required | Required | named, universe |
| real_time_capture | raw source record | Required | Inherited | Inherited | named, universe |
| raw_storage | raw source record, raw archive | Inherited | Inherited | Required | named, universe |
| normalization | raw source record, canonical observation | Inherited | Inherited | Inherited | named, universe |
| replay | raw archive, research copy | Inherited | Required | Inherited | named, universe |
| backup | raw archive | Inherited | Inherited | Required | named, universe |
| internal_analytics | research dataset | Inherited | Inherited | Inherited | named, universe |
| derived_data_creation | derived artifact | Inherited | Inherited | Inherited | named, universe |
| display | ndc release | Inherited | Optional | Inherited | named, universe, all |
| external_redistribution | ndc release, derived artifact | Inherited | Inherited | Required | named, universe, all |
| retention | raw archive, ndc release, derived artifact | Inherited | Inherited | Required | named, universe |
| deletion | raw archive, ndc release, research copy, research dataset, derived artifact | NotApplicable | NotApplicable | Prohibited | none |

The 14-value operation enum and the eight-value object-kind enum are the only
vocabularies. The matrix contains 26 permitted pairs out of 112 combinations;
the other 86 pairs deny before containment.

## 4. Four distinct states

`NotApplicable`, `Named`, `Universe` and `All` remain four states. An empty
`Named` set is rejected by validation and never becomes `All`. A missing value
never becomes `NotApplicable`. Runtime requests are built explicitly and do
not receive `All` by default. A bounded grant cannot cover an unbounded
request; retention remains a typed, scoped dimension.

## 5. Audit

Every `DecisionAuditEvent` now records `applicability_decision` (`applicable`,
`not_applicable`, `prohibited` or `invalid`) and the exact `universe_digest`
when the scope names a universe. The applicability decision is computed before
containment; a scope that cannot be applied is recorded as `invalid` or
`prohibited`, never as applicable.

## 6. Test inventory

Twelve abstract-value tests were added in `src/governance/rights.rs`. None
uses a market observation, a real universe or a provider response.

| Test | Case |
|---|---|
| `applicability_matrix_covers_every_action_object_pair` | all 14 x 8 pairs and the 26 valid shapes |
| `missing_required_dimension_is_denied` | missing provider, venue and segment |
| `incorrect_not_applicable_shape_is_denied` | wrong NotApplicable on both sides |
| `empty_named_set_is_denied` | empty Named and builder default |
| `explicit_all_is_limited_to_permitted_operations` | All prohibited and permitted |
| `exact_universe_containment_is_version_and_digest_strict` | exact reference only |
| `named_member_inside_and_outside_universe` | recorded member versus outside member |
| `unknown_membership_denies` | no recorded membership |
| `wrong_universe_version_or_digest_denies` | wrong version or digest |
| `historical_membership_mismatch_denies` | wrong instants and present-day lookup |
| `gate_universe_member_containment_uses_recorded_evidence` | egress evidence path |
| `audit_event_records_applicability_and_universe_digest` | audit decision and digest |

## 7. Architecture and gates

No Rust module was added. The responsibility mapping for
`src/governance/rights.rs` and `src/governance/egress_intent.rs` in
`scripts/check_architecture.py` now names the new responsibility. No mapping
or gate was weakened. The gates were run with the `market-shaped-tests`
feature disabled; exact commands, exit statuses and counts are reported in the
delivery message.

## 8. Non-claims

- All source rights remain `UNKNOWN`. This record and its tests grant nothing.
- No provider was contacted, no market-data API was called, no market
  observation was created and no artifact was collected.
- No dataset acceptance, experiment, live route, order submission or
  collection command is authorized by this change.
- The NDC v2 model and producer requirements remain Proposed. This record does
  not ratify a final schema, transport, storage choice or shared crate.
- No commit or push was made in this worktree.
