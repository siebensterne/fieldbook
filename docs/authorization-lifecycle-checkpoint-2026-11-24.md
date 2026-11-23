# Fieldbook B4 authorization lease, checkpoint and revocation — 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

**Record:** `docs/authorization-lifecycle-checkpoint-2026-11-24.md`
**Date:** 2026-11-24
**Work item:** W2.1 STEP 6 — Fieldbook B4: lease/checkpoint/revocation in the actual session
**Branch:** `feat/w21-b4` on base `272504c`
**Status:** Proposed implementation of a Proposed model; not a ratified contract
**Rights effect:** none. No right is granted, changed, reviewed or exercised.

## 1. Governing sources

- `NDC-SEMANTIC-MODEL-V2-PROPOSED.md` (C0, Proposed), section 2.5. C0 is an
  external proposed model and is not carried in this repository; this record
  relies on the in-repository readings in
  `docs/authorization-identity-2026-11-23.md` section 2.5 and
  `docs/egress-intent-2026-11-23.md`.
- `docs/operation-plan-authorization-2026-11-24.md` (B3) for full-plan
  authorization and step reauthorization.
- `docs/rights-enforcement-2026-11-23.md` and `docs/egress-intent-2026-11-23.md`
  for fail-closed rights and audit-commit semantics.

## 2. Declared timing contract

All four terms are client policy in monotonic time. They are defined once in
`src/governance/egress_intent.rs` and are not venue guarantees.

| Term | Constant | Value |
|---|---|---|
| `T_checkpoint` | `CHECKPOINT_INTERVAL` | 1 s |
| `T_refresh` | `AUTHORITY_REFRESH_TIMEOUT` | 500 ms |
| `T_scheduler` | `MAX_SCHEDULER_LATENCY` | 250 ms |
| `T_cancel` | `MAX_CANCEL_LATENCY` | 250 ms |
| lease ceiling | `MAX_LEASE_DURATION` | 15 min |
| renewal margin | `LEASE_RENEWAL_MARGIN` | 30 s |

`revocation_propagation_bound()` (`egress_intent.rs:98`) publishes

```text
T_stop <= T_checkpoint + T_refresh + T_scheduler + T_cancel
        = 1 s + 0.5 s + 0.25 s + 0.25 s = 2 s
T_stop_effective = min(2 s, remaining lease at revocation)
```

A lease expiring earlier stops the session by itself, so no longer bound is
claimed. The shortest possible lease is bounded by the same ceiling; a longer
eviction bound is never asserted.

Wall-clock microseconds decide contract validity: a rights record's effective
interval and an audit event's `recorded_at_us` are calendar facts. Monotonic
microseconds decide lease deadlines: `DecisionTime::lease_expired`
(`egress_intent.rs`) prefers `monotonic_deadline_us` whenever present, and the
wall-clock expiry is only a compatibility fallback for legacy proofs installed
without a monotonic lease. Moving the wall clock in either direction cannot
extend or shorten a monotonic lease.

## 3. Runtime lifecycle

`main.rs:81` builds a `SessionAuthorization` from the B3 `PlanAuthorization`
and passes it to `coordinator::run`; `coordinator.rs:484` shares one instance
with every source worker. The authority handle is retained in
`PlanAuthorization.live_authority` and is the same `Arc` installed in the gate,
so `advance_revision`, `revoke` and `set_failing` are observed at the next
checkpoint rather than being frozen in a static snapshot.

- `operation_plan.rs:721` reauthorizes every step of the active plan, checks
  the monotonic deadline, enforces the refresh timeout, renews inside the
  margin, and commits one `authorization_checkpoint` audit event.
- `session.rs:793` checks the checkpoint at the top of every receive-loop
  iteration; `session.rs:900` checks it again after a read and before the frame
  is journaled or emitted. `next_checkpoint` is also in the `select!` wake
  (`session.rs`), so an idle socket still wakes on schedule. A continuously
  ready socket cannot starve either check.
- `session.rs:1243` rechecks a `SetSubscriptions` request against the live gate
  before `apply_subscriptions`; a widened set is denied before the transport
  sees it.
- `session.rs:1352` cancels the shared session, commits final audit state and
  emits `AuthorizationHalted` with buffered-frame and uncommitted-event counts.
  `coordinator.rs:1145` fails the run closed instead of committing more records.
- `SessionAuthorization::resume` reauthorizes every step before a process may
  resume; a stale authority is denied.

## 4. Audit and transaction ordering

`renew_lease_with_time` (`rights.rs:3746`) follows one order: validate authority,
calculate the proposed lease, commit `lease_renewed`, then apply the state
transition. A failed audit commit returns an error and leaves wall expiry,
monotonic deadline and lease epoch unchanged.

`audited_removal` (`rights.rs:2993`) applies one rule to revocation, expiry and
cancel: commit the audit event first; on failure remove the session from the
active set, retain the full decision in `reconciliation_evidence()`, and return
the error. No session that failed its audit can authorize further activity, and
its decision is preserved for reconciliation.

Audit events now carry `lease_id`, `lease_epoch`, `monotonic_deadline_us`,
`event_kind` (`renewal`, `checkpoint`, `revocation`, `cancellation`, `expiry`)
and `grant_identity`, in addition to the B3 actor/object/plan/step fields.

## 5. Measured abstract timings

`tests/session_authorization_lifecycle.rs` uses an injected `MarketDataSession`,
an injected `AbstractClock` and abstract idle frames. With a 100 000 µs abstract
clock advance per frame, revocation was applied after 4 frames and the stop was
observed at 600 000 µs after revocation in the measured run. That is inside the
2 000 000 µs bound and far inside the 900 000 000 µs lease ceiling. The same
suite measures: checkpoint firing under a continuously ready socket, lease
expiry after a large wall-clock jump plus a monotonic advance, authority
unavailable, audit-failure renewal with no extension, cancel/revocation audit
ordering, restart reauthorization and widened-subscription denial. All timings
are abstract; no real clock duration or provider latency was measured.

## 6. Call-site proof

| Claim | Call site |
|---|---|
| bound formula | `src/governance/egress_intent.rs:98` |
| gate transaction rule | `src/governance/rights.rs:2993` |
| renewal ordering | `src/governance/rights.rs:3746` |
| plan checkpoint | `src/governance/operation_plan.rs:721` |
| final halt audit | `src/governance/operation_plan.rs:832` |
| subscription recheck | `src/governance/operation_plan.rs:890` |
| loop-top checkpoint | `src/acquisition/session.rs:793` |
| pre-frame checkpoint | `src/acquisition/session.rs:900` |
| worker halt/report | `src/acquisition/session.rs:1352` |
| coordinator fail-closed | `src/distribution/coordinator.rs:1145` |
| main threads the lifecycle | `src/main.rs:81` |

## 7. Non-claims

- All source rights remain `UNKNOWN`. This record and its tests grant nothing.
- No provider was contacted, no market-data API was called, no market
  observation was created and no artifact was collected. Test endpoints are
  reserved `.invalid` hosts and the transport is injected.
- No dataset acceptance, experiment, live route, order submission or
  collection command is authorized by this change.
- `T_scheduler` and `T_cancel` are declared policy assumptions, not measured
  production latencies; the measured number in section 5 is an abstract-clock
  result only.
- The NDC v2 model and producer requirements remain Proposed. This record does
  not ratify a final schema, transport, storage choice or shared crate.
- No commit or push was made in this worktree.
