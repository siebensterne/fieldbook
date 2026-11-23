# Fieldbook B3 operation plan authorization — 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

**Record:** `docs/operation-plan-authorization-2026-11-24.md`
**Date:** 2026-11-24
**Work item:** W2.1 STEP 5 — Fieldbook B3: operation plan authorization
**Branch:** `feat/w21-b3` on base `3c353b7`
**Status:** Proposed implementation of a Proposed model; not a ratified contract
**Rights effect:** none. No right is granted, changed, reviewed or exercised.

## 1. Governing sources

- `NDC-SEMANTIC-MODEL-V2-PROPOSED.md` (C0, Proposed), sections 2, 5.6 and 9.
- `engineering/ndc-producer-requirements-v2-proposed.md`, sections 2, 3, 5.6,
  6 and 9.
- `docs/authorization-identity-2026-11-23.md` (B1) for typed actor, action,
  data object and recipient identity.
- `docs/universe-containment-2026-11-24.md` (B2) for the applicability matrix
  and exact scoped containment.
- `docs/egress-intent-2026-11-23.md` for endpoint authority, checkpoints and
  mandatory audit.

A listed operation grants itself and no other operation. This record adds a
plan container around those decisions; it does not publish a release, accept a
dataset or change a documentation digest.

## 2. Typed plan

`src/governance/operation_plan.rs` defines `OperationPlan`, `PlanStep`,
`PlanRequest`, `PlanDecision`, `SourceScope`, `OperationClass` and
`SideEffectBoundary`. Each step binds:

| Field | Binding |
|---|---|
| `step_id` | caller-declared, non-blank and unique within the plan |
| `request` | `Egress(EgressIntent)` or `Local(AuthorizationRequest)` |
| actor / action / object | carried by the request: typed actor, the existing 14-value `Operation`, and `DataObject` kind, id and version |
| source scope | provider, source product, venue, segment and dataset from the request |
| `grant_reference` | caller-declared written-evidence reference; never a permission |
| `decision` | `Pending` until the whole plan commits, then `Permitted` |
| `audit_reference` | id of the committed decision event for that step |
| `side_effect_boundary` | the one side effect the step permits |

No step is derived from a command name, a clock, a proof or another step. A
plan with duplicate step identities, duplicate operations, an empty identity, a
missing grant reference, a request in the wrong plane or a boundary that does
not match the operation is refused before any gate check. Loading
`operation-plan.example.toml` validates its shape; it grants nothing.

## 3. Atomic full-plan authorization and reauthorization

`authorize_plan_on` authorizes every step against the runtime rights file,
commits one audit event per step, and then installs all proofs through
`AuthorizationGate::install_batch`. Batch validation, duplicate detection and
audit commits complete before any gate state is mutated: a later failing step
cannot leave an earlier step active. A failure after earlier audit commits
writes a `plan_rollback` event when a sink is available. `authorize_requests`
uses the same atomic path.

`require_plan_step` reauthorizes a step immediately before its side effect.
It requires a `Permitted` step, the exact boundary, and a live full-scope gate
decision. Provider steps call `require_egress`; local steps call the new
`check_scope_active`, which has no endpoint and cannot contact a provider. The
binary builds the plan from `--operation-plan-file`, requires a step for every
provider and local operation the command may perform, authorizes the full plan
before dispatch, and rechecks the relevant step at each command boundary.
Capture without a permitted `raw_storage` step therefore creates no archive.

## 4. Plane separation

Provider-egress operations are `source_contact`,
`reference_data_retrieval`, `historical_data_retrieval` and `real_time_capture`.
Local-data-use operations are `raw_storage`, `normalization`, `backup`,
`replay`, `internal_analytics`, `derived_data_creation`, `retention`,
`deletion`, `display` and `external_redistribution`. `class_for` is the single
partition and `required_boundary` is the single boundary mapping.

`provider_egress_operations` and `local_data_operations` name the two command
sets. Replay, inspect, verify, completeness, coverage, journal,
analytics-verify and analytics-export use only the local gate. Reading a
release manifest for signature verification is `Display`; it does not
authorize `Replay` of an event payload. A denied local replay reads no archive
and a denied export publishes no files.

## 5. Request-bound HTTP and WebSocket dispatch

`HttpEgressRequest` binds provider, source product, operation and full scope
through the caller's intent, plus the actual URL, HTTP method, approved
resource class and approved method. `http_request_for_plan_step` derives the
approved class and method from the declared step and reauthorizes it first.
`authorize_http_request` checks the
provider-egress class, class and method equality, exact endpoint identity from
the actual URL, and the live gate before any client exists.
`dispatch_http_request` calls authorization before its injected `send`
closure. `http_client_with` now disables automatic redirects; redirects are
followed only by `http_client_with_authorized_redirects`, which reauthorizes
every target. A different authority, a changed path shape, an unparseable URL
or a failed gate stops the redirect.

`ws::send_subscription_authorized` and `ws::send_plan_subscription` reauthorize
a scope-widening subscription before the injected `send` closure runs, building
on the existing endpoint and modality target comparison. Denials occur before
DNS, TCP, TLS, the protocol upgrade, file publication or archive reads;
injected resolver/transport counters stay at zero.

## 6. Audit

Every `DecisionAuditEvent` now carries optional `plan_id`, `step_id` and
`side_effect_boundary` fields. They are set from the plan step at grant and at
each reauthorization, so an audit record names the declared plan and the exact
boundary it permitted. No credential, proxy URL, header or payload byte is
recorded.

## 7. Test inventory

Thirteen abstract-value tests were added in `tests/operation_plan.rs`: one valid
step does not authorize another; incomplete plan blocks startup; capture
without storage persists nothing; reference retrieval does not imply capture;
raw storage does not imply replay; wrong HTTP resource path and URL and a
method outside the declared step are denied before dispatch; redirect to an
unapproved authority is denied; a wider
subscription is denied before send; denied local replay reads no archive;
denied export publishes no files; and a denied websocket reaches no DNS, TCP,
TLS or upgrade layer. Two module tests cover the plane/boundary partition and
the checked-in example. One `rights.rs` test proves batch atomicity on a later
duplicate step. One audit test checks plan, step and boundary fields. All
network and file side effects are injected closures or reserved `.invalid`
hosts; `market-shaped-tests` stays off.

## 8. Architecture and gates

`src/governance/operation_plan.rs` is a new module registered in
`src/governance/mod.rs`, `src/lib.rs` and the responsibility mapping in
`scripts/check_architecture.py`. No gate was weakened. The gate commands and
their results are reported in the delivery message.

## 9. Non-claims

- All source rights remain `UNKNOWN`. This record and its tests grant nothing.
- No provider was contacted, no market-data API was called, no market
  observation was created and no artifact was collected.
- No dataset acceptance, experiment, live route, order submission or
  collection command is authorized by this change.
- The NDC v2 model and producer requirements remain Proposed. This record does
  not ratify a final schema, transport, storage choice or shared crate.
- No commit or push was made in this worktree.
