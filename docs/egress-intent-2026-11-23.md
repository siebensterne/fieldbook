# Egress intent and active authorization — 2026-11-23

**Record:** `docs/egress-intent-2026-11-23.md`
**Date:** 2026-11-23
**Work item:** W1.2 C2 (Fieldbook egress intent and active authorization lifecycle)
**Branch:** `fix/w12-c2-egress-intent` on base `8a300bb`
**Normative model:** `NDC-SEMANTIC-MODEL-V2-PROPOSED.md`, sections 2.4 and 2.5
(proposed, not ratified)
**Rights effect:** none. No right, dataset, provider operation or experiment is
granted or changed by this record. All source rights remain `UNKNOWN`.

## 1. Caller-supplied request

`EgressIntent` in `src/governance/egress_intent.rs` is the actual request. The
caller supplies every field explicitly: provider, source record, source product,
venue, segment, dataset, operation, purpose, usage right, usage mode, licensee,
recipient, territory, instrument/field/modality scopes, data-time window,
retention request, delivery method and endpoint identity. The builder has no
defaults and `build()` returns `MissingField` for the first omission.

`AuthorizationGate::require_egress(&EgressIntent, at_us)` replaces the former
`require_egress(venue, operation, at_us)`. It converts the intent to a scope
only for comparison and never reads an installed proof to construct the
request. The comparison requires every exact dimension to be equal and every
scoped dimension to lie inside the grant, plus an explicit endpoint check:

- `provider_id`, `source_id`, `source_product_id`, `venue_id`, `segment_id`,
  `dataset_id`, `operation`, `purpose`, `usage_right`, `usage_mode`, `licensee`,
  `recipient`, `territory` and `delivery_method` are exact;
- instrument, field and modality sets must be contained;
- the data-time window and retention request must be contained;
- `intent.endpoint_identity` must be a member of the grant's
  `approved_endpoints`. An empty approved set covers no real endpoint.

Ambiguous, conflicting or contradictory grants deny. A scope-matching grant with
an endpoint outside its approved set produces `EndpointNotApproved`; a request
that matches no grant produces `ScopeMismatch`. Neither is a permission.

## 2. Instance-scoped gate and fail-closed default

`AuthorizationGate` holds a vector of independent active authorizations behind
an `Arc<Mutex<GateState>>` and is cheaply cloneable. Different providers, source
products, venues, segments and operations coexist in one gate. An identity that
is already installed is refused rather than widened; the gate is empty by
default and denies every egress. The binary keeps one shared instance for its
one-command-per-process entry point; library callers construct their own.

## 3. Active authorization lifecycle

- `LicensingRegistry` carries a monotonically increasing revision. Every
  registration advances it.
- `AuthorizationProof` carries `registry_revision` and a `grant_snapshot_id`
  derived from the winning record's identity, audit digest and recording
  authority. The snapshot identity is immutable once issued.
- `GrantSnapshot` enforces a declared maximum lease of 15 minutes. A zero or
  longer lease is refused at installation. `AuthorizationSession` carries the
  session id, expiry and renewal count.
- `AuthorityRefresh` is consulted at each `require_egress`, `check_active` and
  `renew_lease` checkpoint. The in-process `InMemoryAuthority` can advance the
  revision, revoke a snapshot or fail a refresh. A failed refresh denies.
- Lease expiry cancels the session and emits `lease_expired`. A revision change
  or snapshot revocation cancels it and emits `grant_revoked`. `cancel()` emits
  `session_cancelled`. `renew_lease()` emits `lease_renewed`. Grant issuance
  emits `grant`; egress emits `egress_permitted` or `egress_denied`.

**Maximum revocation propagation time is the lease duration: 15 minutes by the
declared ceiling.** A shorter lease propagates within that shorter interval.
There is no instantaneous revocation claim and no faster notification channel
is implemented or tested in this work item. A fast revocation mechanism would
require a separate, named implementation and test.

## 4. Transport binding

HTTP clients are built only after `require_provider_egress(&intent)` returns
`Ok`. `http_client_with` verifies the intent venue matches the transport venue
and installs a redirect policy that reauthorizes every destination through
`authorize_redirect_on`; an unparseable URL, a changed venue, an endpoint outside
the approved set or a failed gate stops the redirect. A permitted host cannot
carry a request into a different unchecked authority.

WebSocket `connect` parses and checks the endpoint, compares the intent's
venue, operation and endpoint with the target, and calls
`require_provider_egress` before DNS, TCP, TLS or the upgrade. `ConnectOptions`
carries the declared intent. `recheck_subscription` reauthorizes widened
modality scopes and `session_checkpoint` is the mid-session stop point when a
lease is invalidated. `DenialTransport` is an injected, fail-closed probe: if a
denial test reaches DNS, TCP, TLS or the upgrade, a counter increments and the
call returns an error, so a bypass cannot pass silently.

## 5. Root rights-file consistency and recording authority

`RightsContext::load` refuses a file whose records contradict the top-level
licensee or territory rather than treating those fields as decoration. Decision
evidence and audit events carry the record's `audit.authority` value (for
example `contract-registry`); the literal `rights-file` is no longer written as
an authority. The mandatory W1.1-C audit-before-egress boundary is unchanged: a
permitted egress event is committed before the caller may contact the provider,
an audit failure prevents installation and egress, and a denial never becomes a
permission.

## 6. Test inventory

All tests use scalar identifiers, abstract instants, temporary directories or
reserved `.invalid` hosts. No market observation is created, no provider is
contacted and `market-shaped-tests` stays off.

### 6.1 New abstract-value tests — `tests/egress_intent_lifecycle.rs`

| Test | Required case |
|---|---|
| `exact_grant_permits_and_audits_before_egress` | exact grant permit; grant and egress events committed |
| `every_declared_dimension_mismatch_denies` | operation, provider, source, product, segment, dataset, venue, instrument, field, modality, time window, purpose, recipient, territory, licensee, usage right, usage mode, delivery and endpoint mismatch deny |
| `missing_licensee_is_rejected_before_any_gate_check` | missing licensee denied by the builder |
| `expired_grant_and_missing_audit_never_permit` | unapproved endpoint and absent proof deny |
| `audit_failure_prevents_installation_and_egress` | unwritable audit sink prevents grant installation |
| `retention_exceed_denies_but_narrower_request_permits` | narrower retention fits; indefinite request exceeds bounded grant |
| `lease_expiry_renewal_and_authority_failure_are_audited` | renewal, expiry, unreachable authority, revision invalidation, revoke and cancellation audit labels |
| `cancellation_removes_the_active_session` | explicit cancellation stops the session |
| `two_independent_authorizations_coexist_in_one_gate` | two independent providers/products/operations; cross-provider borrow denied |
| `redirect_to_unapproved_authority_is_denied` | same-authority redirect reauthorized; different authority and malformed URL denied |
| `subscription_widening_is_reauthorized` | same modalities permit, widened modalities deny |
| `denial_never_reaches_dns_tcp_tls_or_upgrade` | injected transport counters stay at zero on a gate denial |
| `rights_file_root_consistency_and_actual_recording_authority` | contradictory root licensee refused; actual recording authority preserved |

### 6.2 Carried-forward tests

The 39 module tests in `src/governance/rights.rs`, 9 tests in
`tests/egress_governance.rs` and 19 tests in `tests/egress_lab.rs` were updated
to pass explicit intents and still run. No test target was removed and no
assertion was deleted.

## 7. Gate result

cargo xtask fmt, lint, docs, style and test pass with market-shaped-tests off.
`cargo test --workspace --all-targets --locked` reports 561 passed, 0 failed,
12 ignored; the doc test reports 1 passed. The new lifecycle suite is 13/13.
No result here is a claim of data rights, provider contact or live readiness.

## 8. Non-claims

No live venue was contacted, no market observation was used, no right was
granted and no artefact was collected. No commit or push was made in this
worktree. A timed-out or refused transport is not a data licence. The production
command path stays fail-closed until an operator supplies a rights file, an
audit directory and an explicit egress-intent declaration.
