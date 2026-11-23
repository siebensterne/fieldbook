# M5 workload specification

> Retired under RRP-002 (owner directive D11). The synthetic market-data
> assets described below have been removed from the active tree. This text
> is retained only as a historical record; no command or path in it is
> executable. See `docs/synthetic-asset-retirement-2026-11-23.md`.

This document freezes the M5 workloads before results are collected. It
describes what the harness produces, not what has been measured. M5.2 adds
deterministic burst schedules without changing the frozen 4,000-instrument
exact/weighted workload, its seed, its hot-set definition or its event budget;
M5.5 adds backpressure boundary profiles that constrain admission and
terminal dispositions without changing that frozen workload either. The
stress laboratory design is in [`stress-lab-design.md`](stress-lab-design.md).
Capacity stages and their opt-in rules are summarised in this document; status
and retained evidence are in [`programme-status.md`](programme-status.md).

The current combined scenario schema is **v16** (M5.2 burst = 6, M5.3 = 7, M5.4
= 8, M5.5 backpressure = 9, M5.6 stage timing = 10, M5.7 capacity = 11, M5.8 =
12; v13 was the combined integrated schema that folded the lifecycle scenarios
and universe-epoch coverage together with the disconnect, burst, backpressure
and capacity profiles; v14 additionally carried the M5.6 stage-timing
performance block; v15 folds in the M5.7 capacity characterization stages, the
three workload models and their manifest evidence; v16 integrates the
Hyperliquid H3 synthetic loopback capacity cells on the same manifest schema).
Earlier v3-v15 evidence files are retained byte-for-byte and are never
overwritten by a v16 run; cell ids carry the scenario version suffix.

## Invariants

Synthetic generation passes through the **production** ingestion path: loopback
  Kalshi REST discovery, real `KalshiExchange`, real coordinator, real SBE writer
  and real journal. The harness never calls `CollectorCore` directly.
- One root seed drives distinct derived streams for universe generation, book
  seeding, and publishing. Changing workload shape must not perturb the other
  streams.
Workload roles are assigned by the harness, never inferred from payload bytes
  by the collector.
Acceptance is fail-closed. A cell may only publish `success` when anchoring,
  drain, exact coverage, SBE verification, completeness, journal finalization,
  decoy exclusion and the two-sided event ledger all pass inside the runner.
Stage timing is measured only at boundaries that exist in the current code,
  with `Instant`, one shared fixed-bucket histogram per boundary, and explicit
  sample counts. Unexercised boundaries stay `unavailable` with a reason, never
  zero. CPU, throughput, RSS and disk fields remain `unavailable`. Synthetic
  mock send timestamps are not used as measured latency. See
  [`performance-methodology.md`](performance-methodology.md).
Backpressure admission is boundary-specific. A cell declares its boundary
  before the run; the manifest records capacity, admission rule, timeout,
  drop/reject policy, recovery path and five distinct terminal-state counters.
  `accepted_but_waiting`, `rejected`, `dropped`, `completed` and
  `uncertain_acknowledgement` are never collapsed into a generic error. A cell
  whose declared disposition cannot be evidenced is rejected by the same
  fail-closed path as a ledger gap.
A backpressure cell that dies before capture verification still publishes a
  failure manifest: the journal rejection latch is preserved as a journal
  `failed` state with the collector's terminal error, and unavailable SBE
  evidence is rendered as an explicit `unavailable` marker rather than zero.

## Profiles

| Profile | Status | Definition |
|---|---|---|
| `uniform` | Existing baseline | All eligible instruments have equal selection weight. |
| `zipf_hot_pair` | Existing legacy fixture-only profile | First 10% of markets receive 80% of events; retained for compatibility, not an M5 characterization profile. |
| `hot_quiet` weighted | **Implemented, corrected in M5.1** | Exactly 5% of eligible instruments are designated hot by a derived PRNG stream. Hot and cold indices are disjoint and exhaustive; 80% of draws select from the hot set and 20% from the cold set, so no hot instrument can be chosen through the cold branch. The realized share varies within a finite run. |
| `hot_quiet` exact | **Implemented in M5.1** | Same roles, but event assignment is an exact shuffled quota: 320 of 400 deltas are hot and 80 are cold, reproducible under the seed. Used as the frozen reference profile. |
| `burst` | **Implemented in M5.2** | Four deterministic profiles (`step`, `impulse`, `repeated_impulses`, `ramp`) that partition the same 400 logical deltas into publish phases. No sleeps, timing instrumentation or performance claims. |
| `lifecycle` | **Implemented in M5.3** | Typed L1-L10 churn driven by a seed + explicit event sequence over the mock's `market_lifecycle_v2` channel; retired instruments are epoch-scoped, not permanent coverage obligations. |
| `disconnect` | **Implemented in M5.4** | Seed-derived explicit fault schedule (D1-D10) that closes replicas/sockets through the mock's `close_book_connections()` / `close_all_connections()`, measures incident-detection → valid re-anchor, and records the schedule in the manifest. |
| `backpressure` | **Implemented in M5.5; carried into combined `scenario_version = 16`** | Five independent boundary profiles: mock outbound queue, writer queue, slow downstream, journal/storage admission and shutdown-before-drain. |
| `mixed` | Planned | Combined hot/quiet, lifecycle, disconnect and backpressure in one cell (M5.5 adds only the single-injection hot/quiet + writer-queue cell, not the full mixed profile). |
| `fixed_per_instrument` | Implemented in M5.7 | Capacity workload model: `instruments × 1` uniform deltas, so offered load scales with the stage. |
| `fixed_aggregate` | Implemented in M5.7 | Capacity workload model: a fixed 400 uniform deltas regardless of instrument count. |
| `skewed_hot_quiet` | Implemented in M5.7 | Capacity workload model: a fixed 400 deltas routed 80/20 to a deterministic 5% hot set via the existing exact-quota assignment. |
| `hyperliquid_h3` | **Implemented in H3 (`scenario_version = 16`)** | Venue-specific synthetic loopback profiles over the exact ten selected perpetuals: `balanced`, `telemetry_heavy` (mid fan-out + fast-context rate) and `book_refresh_burst` (`l2Book` cadence + trade bursts), each with a scripted reconnect. No deltas, no latency/capacity claim. |

## M5.2 burst profiles

A burst profile changes only the **phase decomposition** of the logical-event
budget. The seed, universe, hot set, role selection, topology, journal and
400-event budget are identical to the frozen M5.1 exact workload. The schedule
is defined by exact event counts; no sleep, wall-clock rate control, timing
measurement or throughput claim is part of this increment.

| Profile | Phase event counts (400 total) | Declared rate multipliers | Meaning |
|---|---|---|---|
| `step` | 100 / 200 / 100 (baseline / burst / recovery) | 1 / 2 / 1 | One sustained doubling of the declared rate. |
| `impulse` | 40 / 280 / 80 (baseline / impulse / recovery) | 1 / 5 / 1 | One concentrated spike followed by a quiet tail. |
| `repeated_impulses` | 80 / 80 / 80 / 80 / 80 | 1 / 3 / 3 / 3 / 1 | Several equally sized impulses separated by quiet phases. |
| `ramp` | 40 / 80 / 80 / 80 / 120 | 1 / 1 / 2 / 3 / 1 | Rising declared multipliers, then a larger recovery phase. |

Counts are derived deterministically by integer weights and always sum to the
configured event budget; an indivisible remainder is assigned to the
highest-weight phase (`tests/stress_support/runner.rs` unit tests pin the
partition). The `target_rate_per_tick` and `rate_multiplier` fields are
**declared schedule labels** recorded so a manifest reader can reproduce the
intended shape. They are not measured rates, not latency figures, and not
performance evidence. The manifest states this under
`workload_schedule.rate_semantics`; all performance fields remain
`unavailable`.

Publishing is phased: each phase publishes its exact count, then the existing
drain barrier waits until every production counter reaches the **cumulative**
expected count (plus the mock's decoded-frame catch-up) before the next phase
is published. This is implemented in `run_cell_inner` with `await_drain`; the
existing one-shot workload is the single `steady` phase with `burst = None`.
The final event ledger, disposition accounting, coverage and SBE verification
still run once over the whole cell, so no check is weakened.

The manifest records the explicit schedule under `workload_schedule`:

`workload_id` — `{profile}-seed-{seed:04x}-{symbols}`;
`profile` — `steady | step | impulse | repeated_impulses | ramp`;
`seed`, `instrument_count`, `eligible_count`;
`hot_set` — `fraction_ppm`, `member_count`, `selection`, `event_share_pct` and
  the canonical `sha256` of the sorted hot set;
`phases` — per-phase `name`, `events`, `target_rate_per_tick`,
  `rate_multiplier`;
`expected_total_events` — sum of all phase counts;
`fault_schedule` — empty for M5.2 burst cells (no fault injection is
  scheduled);
`delivery.phases` — actual per-phase `published_events`,
  `cumulative_expected` and `drain_completed`.

Scenario `scenario_version` was bumped to **6** for the burst increment
(superseded by the combined integrated schema at **16**); burst cell IDs carry
the profile label so two profiles never overwrite one another in the index. The
v5 disposition-certified manifests remain immutable historical evidence.

Capacity stages are selector modes for the existing generator and publish
scheduler, not new generators. They are opt-in and never run at 50k in CI.

## Frozen first workload

| Parameter | Value |
|---|---|
| Seed | `23` for weighted, `29` for exact-quota reference |
| Eligible instruments | 4,000 (`decoy_fraction_ppm = 20_000`) |
| Hot instruments | 200 (5% of eligible, `hot_fraction_ppm = 50_000`) |
| Hot event share | 80% (`hot_event_share_pct = 80`); exact mode pins 320/400 |
| Selection mode | `hot_selection = weighted` or `exact_quota` (frozen workload; current manifests are emitted at `scenario_version = 16`, the combined schema: 6=burst schedules (M5.2), 7=lifecycle (M5.3), 8=disconnect (M5.4), 9=backpressure (M5.5), 10=stage-timing evidence (M5.6), 11=capacity stages and workload models (M5.7), 12=increments, 13=integrated schema, 14=integrated schema plus stage timing, 15=integrated schema plus capacity characterization, 16=Hyperliquid H3 synthetic loopback cells) |
| Logical deltas | 400 |
| Topology | 2 shards × 2 replicas + 1 lifecycle connection |
| Journal | enabled |
| Timeouts | anchor 45 s, drain 10 s (runner cell limits) |

The hot set is exact, deterministic under the seed, disjoint from MVE/closed
decoys, and reproducible by
`SyntheticUniverse::generate(seed, symbols, decoys).hot_tickers(50_000)`.
Bumping the generator or scenario schema version is required before changing the
semantics of this table.

## Backpressure profiles (M5.5; manifests now emitted at `scenario_version = 16`)

Each profile is one boundary, one injection and one terminal disposition. The
runner derives the profile from `CellConfig` before the run, reconciles the five
observed states from independent counters, and refuses a success verdict when
the observed disposition does not match the declared one.

| Profile | Boundary | Capacity | Admission | Timeout | Drop / reject policy | Recovery | Declared disposition |
|---|---|---|---|---|---|---|---|
| `mock_queue_saturation` | Mock websocket outbound queue | `FailInject::MockQueueSaturate.capacity` (fixture: 8) | non-blocking `try_send`, one queue per connection | cell drain limit (fixture: 2 s) | full queue increments `queue_saturated`; an explicit drop, never retried and never silent | none in-run: forwarder is stalled until shutdown | `dropped` |
| `writer_queue_saturation` | Production SBE writer queue | `CellConfig.writer_queue` (fixture: 128) | bounded `send().await` | `writer_send_timeout_secs` (10 s) | a timed-out send never enters the queue and returns an error | shutdown closes admission and drains every accepted message | `completed` |
| `slow_downstream` | Socket consumer after mock admission | mock default outbound capacity (4,096) | ordinary bounded enqueue; completion delayed after admission | cell drain limit (fixture: 2 s) | no drop and no rejection: frames remain in flight and are counted as accepted-but-waiting | queue drains after the injected delay; this cell cuts at the drain barrier | `accepted_but_waiting` |
| `journal_storage_pressure` | Raw-frame journal admission / durable write | `queue_capacity` (fixture: 1 record) | bounded `send_timeout` with an fsync per record | `enqueue_timeout_ms` (fixture: 1 ms) | enqueue timeout rejects the record and latches the run failed; the frame is not silently discarded | latched failure is terminal; accepted records drain at finalization | `rejected` |
| `shutdown_uncertain_acknowledgement` | Shutdown before the drain barrier | not applicable | normal admission until shutdown is signalled | 0 (no drain wait) | no drop policy can be verified because observation ends at shutdown | none in this cell; the outcome stays uncertain by contract | `uncertain_acknowledgement` |

### State semantics

**accepted_but_waiting** — admitted to a bounded queue; `in_flight` or
  `writer.queue_depth` shows it has not completed. Not a drop.
**rejected** — the boundary refused admission and returned an error (journal
  enqueue timeout, writer send timeout). Not a completed write.
**dropped** — accepted for transmission but discarded with a counter
  (`queue_saturated`). Not a rejection and not an acknowledgement.
- **completed** — socket send, writer message or journal record completed and
  was independently observed.
- **uncertain_acknowledgement** — shutdown ended observation before the fate of
  an offered frame could be established. Never claimed as dropped or completed.

### Evidence contract

Every profile manifest carries a `backpressure` object with the frozen policy
fields, the five state counters, boundary-specific evidence (queue high-water,
forwarder delay, journal rejection detail, applied shortfall), journal state
and SBE verification verdicts. Profile-specific required fields are checked in
addition to the global manifest fields before a success verdict is kept. The
ordinary event ledger and disposition reconciliation still apply: a profile
cannot pass on the strength of its own counters alone.

Journal/storage limitation: this harness does not inject kernel ENOSPC. The
journal profile shrinks the admission queue to one record, shortens the
enqueue timeout to 1 ms and forces an fsync per record, which reliably latches
a real journal rejection before any capture is produced. Durable-media fault
injection remains covered by the offline journal fault-hook tests in
`src/journal/tests.rs`; no new ENOSPC claim is made here.

Combined workload: `backpressure_combined_hot_quiet_writer_queue_4000_certifies`
runs the 4,000-instrument hot/quiet profile with a single writer-queue bound
injection and no lifecycle, disconnect or chaos injection. It is added only
after all five individual profile gates pass.

## Capacity characterization (M5.7, `scenario_version = 16`)

The capacity scaffold keeps the generator, scheduler and certification path
above unchanged and selects only two knobs: a stage (4,000 / 10,000 / 25,000 /
50,000 eligible instruments) and one of the three workload models added to the
profile table. The selection is deterministic and is pinned by
`capacity_stage_and_workload_model_selection_is_deterministic`, the manifest
contract test `capacity_manifest_records_stage_model_and_unavailable_reasons`,
and the 200-instrument `capacity_workload_models_reconcile_at_small_scale` cell;
all run in default CI. The 10k/25k/50k short correctness cells are `#[ignore]`d and
opt-in via `STRESS_CAPACITY_STAGE` / `STRESS_MANIFEST_OUT`; 50k is never run in
CI. Manifests carry a `capacity` object with stage, instrument count, workload
model, expected events, coverage, journal/SBE verification, host resources and
explicit `unavailable` reasons. These are short correctness cells, not
capacity certification.

**Discovery success is not capacity certification.** Pagination of the full
universe establishes metadata coverage only; it does not establish that a
stage's books can be anchored, its deltas applied, or its events persisted. All
capacity evidence is synthetic/loopback, bounded to one stage and one
observation window, and makes no throughput claim.

## Stage accounting

The ledger must distinguish, at minimum:

```text
generated -> transmitted -> received -> decoded -> applied
          -> writer accepted -> SBE persisted -> journaled
```

The certified accounting model uses monotonic counters sampled at baseline and
final, with both directional discrepancies computed for every comparable stage
pair:

`shortfall = max(0, expected - observed)`
`excess = max(0, observed - expected)`

Missing evidence stays `None` and blocks certification; it is never zero.

Independently sourced counters:

`enqueued_deltas` — mock outbound-queue admission counter.
`transmitted_deltas` — mock websocket send completion counter.
`received_frames` — `collector_data_frames_received_total`, accumulated in
  the collector core across reconnects.
`delta_events_decoded` — `collector_delta_events_decoded_total`, one count
  per decoded `LevelChange` event, also core-accumulated.
`writer_delta_admissions` — `collector_writer_delta_admissions_total`, the
  queue-admission boundary.
`writer_delta_writes` — `collector_writer_delta_messages_total`, successful
  SBE delta writes. This is distinct from total writer messages because the
  output also contains snapshots.
`sbe_deltas` — independent decode of the persisted capture.
`journaled_records` — independent journal verification.

Certified adjacent gaps:

`enqueue_transmit_shortfall` / `enqueue_transmit_excess`
`transmit_decode_shortfall` / `transmit_decode_excess`
`writer_admission_shortfall` / `writer_admission_excess`
`writer_write_shortfall` / `writer_write_excess`

Replica fan-out appears on both transmit and decode sides, so no dedup
arithmetic is needed for that comparison. Duplicate suppression remains a
separately recorded downstream signal. A nonzero decode error count, missing
receive/decode/writer evidence, or any reversed counter discrepancy fails the
actual `CellAcceptance` path through `ledger_acceptance_reasons`, not only the
`EventLedger::reconciled()` helper.

Historical note: `failed-v3-seed-000b-200-coverage_set_mismatch.json` recorded
zero received frames because the earlier sampler read per-source status gauges
that reset across reconnects. The artifact is retained unchanged as superseded
evidence; a diagnostic regression test pins it. Current certification uses
core-accumulated monotonic counters.

Stage-latency instrumentation now exists for the five boundaries defined in
[`performance-methodology.md`](performance-methodology.md): core processing,
writer queue wait, SBE write, flush and journal append. Each publishes raw
bucket counts, explicit sample counts and nearest-rank percentiles, with build
and clock provenance. CPU, peak RSS, throughput and disk latency remain
unavailable and still block **performance** certification; they are never
substituted with zero.

## Terminal delta disposition (v5)

The v5 ledger certifies that every decoded delta has exactly one terminal
outcome. `DeltaDisposition` defines eleven mutually exclusive variants, and
`CollectorStats` carries a counter for each. The acceptance path verifies:

```text
decoded deltas = emitted + suppressed replica + no active source
               + unknown symbol + non-live + unassigned source
               + invalid book + shadow clock regression
               + apply rejected + zero noop + SBE conversion failed
```

Transport counters are owned by the session worker and include malformed
frames; core-ingress counters are sampled separately under distinct metric
names. The full contract is in
[`event-accounting-contract.md`](event-accounting-contract.md).

## Disconnect fault matrix (M5.4; manifests now emitted at `scenario_version = 16`)

The disconnect sweep is an **explicit, seed-derived schedule**, not random
chaos. `tests/stress_support/faults.rs` derives a `Vec<FaultStep>` from the cell
seed via a dedicated PRNG stream; each step is replayed in order by
`tests/stress_support/runner.rs` and copied verbatim into the manifest's
`fault_schedule` field. Every step records: fault ID, affected source and
instruments, start epoch, failure time (offset from anchor completion), fault
type, expected action and outcome, and deadline. An empty `fault_schedule`
means the cell ran no faults.

Recovery is measured as **incident detection → valid re-anchor**, never as a
socket reconnect alone. The runner samples the existing production counters
`collector_discontinuity_incidents_total` (detection) and
`collector_failover_snapshots_total` plus `collector_symbols_resyncing == 0`
and full `collector_symbols_anchored` (valid re-anchor). The manifest's
`recovery` array exports both endpoints, the observed connection count, and a
duration in milliseconds. The poll granularity is 25 ms, so a zero duration
means "within one poll". When no valid re-anchor occurs (or a standby loss
opens no incident), `duration_ms` is `null` with an explicit
`duration_unavailable_reason` — it is never fabricated as zero.

| ID | Scenario | Mock action | Expected action / outcome | Harness status |
|---|---|---|---|---|
| D1 | Standby replica loss | Close the newest book socket | Surviving active book keeps the symbol anchored; replacement socket is opened. No continuity incident is expected, so duration may be unavailable with a reason. | Driven |
| D2 | Active replica loss | Close the oldest book socket | One discontinuity incident; shadow truth promoted by one failover snapshot; ledger reconciles. | Driven |
| D3 | Both replicas lost | `close_book_connections()` | Incident per previously active symbol; fresh snapshots re-anchor every book with new epochs. | Driven |
| D4 | Reconnect new epoch | Close one replica after recovery | New connection id/epoch; stale frames cannot satisfy the fence. | Driven |
| D5 | Delayed old snapshot | None (reference-only) | Old-epoch snapshot rejected before any book or incident mutation. | Honest regression against the production core |
| D6 | Delayed old delta | None (reference-only) | Same fence contract for a stale delta. | Honest regression |
| D7 | Many instruments requiring recovery | `close_book_connections()` on a 500-symbol cell | All 500 instruments re-anchor; exact coverage certifies with no drops. | Driven |
| D8 | Recovery timeout | `close_book_connections()` + reject replacements | Run is incomplete with resyncing symbols and unexplained drops; no silent success. | Driven |
| D9 | Recovery exhaustion | None (reference-only) | Bounded attempt budget is an explicit, non-escalating outcome. | Honest regression |
| D10 | Repeated reconnects | Cycle all sockets repeatedly | Independent generations, bounded queues, healthy instruments, monotonic SBE receive times, reconciled accounting/dispositions. | Driven |

The first-connected book socket deterministically wins the active-source race
(the mock delays later sockets' initial snapshots), so D1 and D2 target stable
roles. The mock venue clock is monotonic across connection epochs while
per-socket `seq` resets, matching a real exchange and preventing a false
maintenance-epoch reconnect storm.

Limitations: D5, D6 and D9 are not synthesized on the stress harness wire; the
loopback mock cannot inject a stale-epoch frame or drive the recovery attempt
budget. They are recorded as `reference_only` steps and certified by named
regression tests against the production recovery/fence machinery. No
performance, latency or throughput claim is made by this matrix.

## Lifecycle scenarios (M5.3, integrated at `scenario_version = 13`)

`CellConfig::lifecycle_scenario` is a typed selector. A scenario is a seed plus
an explicit event sequence (`tests/stress_support/lifecycle.rs`): every entry
pins its venue timestamp, target instrument, catalog effect and required
counter effect. The mock publishes it with `publish_lifecycle_at` to all
lifecycle replicas; the runner reconciles the observed `core` counters against
the schedule before it can certify a cell.

| ID | Scenario | Current contract / evidence |
|---|---|---|
| L1 | Add/activate | A REST-backed market becomes subscribed and snapshot-anchored; an `activated` event is applied. `tests/lifecycle_churn.rs::lifecycle_add_activate_proves_exact_coverage` |
| L2 | Subscribe | Exactly `lifecycle_replicas` sockets subscribe to `market_lifecycle_v2`; book sockets never do. `tests/kalshi_lifecycle_plane.rs::book_sockets_carry_no_lifecycle_subscription_and_the_plane_is_accounted` |
| L3 | Snapshot anchor | The lifecycle-added market is in the expected, acknowledged and anchored sets. `tests/lifecycle_churn.rs::lifecycle_add_activate_proves_exact_coverage` |
| L4 | Metadata change | `metadata_updated` and `price_level_structure_updated` mutate tracked metadata; a stale REST round cannot overwrite newer lifecycle state. `src/collector/state/tests.rs::reconciliation_older_round_keeps_lifecycle_metadata` |
| L5 | Retire/settle | A terminal `settled` removes the market once and emits the final empty snapshot. `tests/lifecycle_churn.rs::lifecycle_retire_is_not_a_permanent_coverage_obligation`, `tests/kalshi_lifecycle_plane.rs::terminal_settled_retires_the_market_exactly_once` |
| L6 | Duplicate lifecycle event | The (market, kind, exchange timestamp, payload fingerprint) key suppresses an identical redelivery. `tests/lifecycle_churn.rs::lifecycle_duplicate_event_is_deduped`, `src/collector/state/tests.rs::lifecycle_terminal_is_applied_once_across_connections` |
| L7 | Out-of-order lifecycle event | A nonterminal notification older than the per-market high-water mark is dropped; terminal notifications still apply. `tests/lifecycle_churn.rs::lifecycle_out_of_order_event_is_dropped`, `src/collector/state/tests.rs::out_of_order_nonterminal_lifecycle_is_dropped_not_applied`, `src/collector/state/tests.rs::stale_terminal_lifecycle_is_still_applied` |
| L8 | Conflicting replica updates | Two different payloads with the same kind and timestamp are distinct updates; the later one wins. `tests/lifecycle_churn.rs::lifecycle_conflicting_replica_updates_keep_newer_payload`, `src/collector/state/tests.rs::two_different_payloads_with_same_kind_and_timestamp_are_both_applied` |
| L9 | Reappearance after retirement | A discovery round started before the terminal notification is vetoed; a later round re-adds. Proven as a focused contract test because a full cell that retires and re-adds the same market exposes an existing pending-recovery limitation. `src/collector/state/tests.rs::l9_reappearance_after_retirement_needs_a_later_discovery_round` |
| L10 | Churn under load | Add, metadata, duplicate, stale and retire events interleaved with the 4k/400 delta workload; all coverage, ledger, SBE and journal gates still pass. `tests/lifecycle_churn.rs::lifecycle_churn_under_load_reconciles_and_certifies` |

Terminal retirement is published after the delta drain barrier: the
coordinator's shutdown drain applies it, and the empty snapshot becomes a
`coverage.anchored_not_expected` entry rather than a failed expected symbol.
Retiring an instrument also prunes it from pending recovery batches
(`src/collector/state/tests.rs::retirement_prunes_the_instrument_from_pending_recovery`),
so a retired market is never a permanent snapshot-request obligation.

## Universe epochs and retired coverage obligations

Each schedule carries `UniverseEpoch` records: epoch 0 is the startup eligible
set; an `Add` or `Retire` catalog effect creates a new epoch with an explicit
expected set, a required-anchored set and a retired set. The manifest publishes
these under `coverage.per_epoch` with the same canonical set hash as the
coverage certificate, and the scenario block records the seed, event count and
expected applied/duplicate/stale counts.

The final certificate remains authoritative: expected, acknowledged and
snapshot-anchored sets must be identical for the *final* epoch. Extra anchored
symbols are accepted only when the schedule retired them — their final empty
snapshot is a retirement boundary, not an obligation to keep covering. The
`coverage.retired_not_expected` field carries the certified diagnostic. No
separate coverage oracle is invented for intermediate epochs; they are the
harness's declared plan, checked against the final certified set.

## Acceptance gates for this increment

| Gate | Proof |
|---|---|
| Correctness | `EventLedger::reconciled()` is true; `unexplained_drops = 0`; `persistence_gap = 0` |
| Workload semantics | `hot_set ∩ cold_set = ∅`, `hot_set ∪ cold_set = eligible_set`; exact mode pins 320 hot / 80 cold events |
| Coverage | expected, acknowledged and anchored symbol sets are identical at 4,000 |
| Continuity | no decoy appears in the capture; journal finalizes completely |
| Determinism | hot-role unit test pins the 200/4,000 split and rejects a different seed |
| Capacity scaffold (M5.7) | stage/model selection pins 4k/10k/25k/50k and all three workloads; 200-instrument cells reconcile for each model; 10k/25k/50k stage cells are ignored and opt-in; manifests use `scenario_version = 16` |
| Hyperliquid H3 (synthetic) | `tests/hyperliquid_capacity.rs::{h3_balanced_cell_certifies_every_evidence_gate, h3_telemetry_heavy_profile_keeps_telemetry_out_of_books, h3_book_refresh_burst_profile_reconciles_and_recovers}` prove exact 10-instrument three-set coverage, a reconciled ledger/dispositions, bounded writer queue, journal/SBE integrity, zero `LevelChange` and reconnect re-anchoring; `h3_schedule_is_seed_deterministic_and_profile_distinct` pins the explicit schedule; `reference_hyperliquid_manifest_is_versioned` is ignored and publishes a v16 manifest under `STRESS_MANIFEST_OUT` without overwriting evidence |
| Evidence | `mixed_hot_quiet_4000_cell_reconciles_and_certifies` passes offline; `reference_mixed_hot_quiet_manifest_is_reproducible` emits a versioned manifest when run explicitly with `STRESS_MANIFEST_OUT` |
| M5.2 burst phases | `burst_step_cell_reconciles_all_phases` and `burst_impulse_cell_reconciles_all_phases` prove acceptance, exact per-phase counts (100/200/100 and 40/280/80), cumulative drain completion, reconciled ledger, exact 4,000 coverage, SBE/completeness/journal verification, empty fault schedule and a manifest carrying the full workload schedule |
| M5.2 determinism | `burst_profiles_partition_the_budget_exactly_and_deterministically` and `burst_profile_counts_are_pinned` pin the four partitions; `schedule_records_id_seed_hot_definition_and_empty_faults` pins the recorded schedule fields |
| Backpressure fail-closed | each `*_profile_fails_closed*` cell names its boundary class and does not certify: `mock_outbound_queue_dropped`, `slow_downstream_accepted_waiting`, `journal_pressure_rejected`, `uncertain_acknowledgement`; the writer profile reconciles with a bounded queue |
| Bounded queues | mock `queue_high_water <= capacity`; writer `queue_high_water <= capacity + 1` (one-slot counter lag); journal queue fixed at one record |
| Disposition reconciliation | the five manifest state counters are distinct and the dominant state matches the declared disposition; ledger gaps and disposition gaps still block certification |
| Journal / SBE | every profile manifest records journal state and SBE verdicts; a journal rejection preserves the collector error rather than reporting a generic failure |
| Disconnect recovery | `disconnect_standby_replica_loss_recovers_and_reconciles`, `disconnect_active_replica_loss_recovers_and_reconciles`, `disconnect_both_replicas_lost_reanchors_all_instruments`, `disconnect_many_instruments_reanchor_certifies_coverage`, `disconnect_recovery_timeout_surfaces_as_incomplete`, `disconnect_recovery_storm_preserves_generations_and_accounting`, `disconnect_delayed_old_epoch_frames_are_rejected_by_the_recovery_fence` pass offline |
| Lifecycle semantics | `core.lifecycle_events`, `lifecycle_duplicates` and `lifecycle_stale_dropped` equal the explicit schedule's applied/duplicate/stale counts; added markets are anchored, retired markets are not expected |
| Lifecycle epochs | `coverage.per_epoch` records expected/anchored/retired set hashes per epoch; the final certificate is unchanged and extra anchors are permitted only for scheduled retirements |
| Lifecycle evidence | add/activate, retire, duplicate, out-of-order and churn-under-load cells pass offline (exact coverage, reconciled ledger, SBE verification, journal finalization); `reference_lifecycle_churn_manifest_is_versioned` emits a v16 manifest when run explicitly with `STRESS_MANIFEST_OUT` |
| Stage instrumentation | `stage_timing_cell_records_real_writer_write_latency` records non-zero SBE write, queue-wait and journal-append samples in a real cell; histogram unit tests pin percentile correctness, sample counts and merge-by-raw-counts |

The earlier `seed-0017-4000-hotquiet.json` manifest was generated by the
pre-correction sampler (residual draws could include hot instruments, giving
about 81% hot events in expectation). It is retained unchanged as historical
evidence, explicitly superseded by `scenario_version = 5`. The corrected v3
reference artifacts are retained as historical evidence. The certified v4
artifacts are `seed-0007-4000-uniform-v4.json`,
`seed-0017-4000-hotquiet-v4.json`, `seed-001d-4000-hotquiet-v4.json`, and
`failed-v4-seed-000b-200-coverage_set_mismatch.json`, v4 tied to `3f22f47`; the v5 disposition-certified artifacts
`seed-0007-4000-uniform-v5.json`, `seed-0017-4000-hotquiet-v5.json`,
`seed-001d-4000-hotquiet-v5.json` and
`failed-v5-seed-000b-200-coverage_set_mismatch.json` are tied to `5bb54e6`. Do not use the v2 manifest for comparative
workload claims. The M5.5 v9 manifests are generated only into a caller-supplied
`STRESS_MANIFEST_OUT` directory and are not copied over the v3-v5 artifacts;
the combined v16 manifests extend the same publication protocol.

### Stage timing contract (introduced at v10; carried into combined v16)

`performance.stage_timing` carries one `StageHistogram` per measured boundary,
with `sample_count`, `min_ns`, `max_ns`, p50/p90/p95/p99/p99.9, an optional
p99.99 at 10,000+ samples, and raw bucket counts. Percentiles are nearest-rank
estimates from merged bucket counts, never averages of worker percentiles. The
host clock step (`clock_resolution_ns`), build profile, target triple and
scenario version are published alongside the counts. Nanoseconds are the
storage unit, not an accuracy claim. `lifecycle`, `disconnect` and combined
The combined `mixed` profile is not certified as one run; `lifecycle` (M5.3), `disconnect` (M5.4),
`burst` (M5.2) and `backpressure` (M5.5) are implemented workload profiles
carried into the combined v16 schema. Hyperliquid H3 adds synthetic loopback
capacity cells at ten instruments only; it makes **no** capacity, throughput,
latency or live performance claim.

`stage_timing_cell_records_real_writer_write_latency` proves the writer SBE
write and journal append boundaries record non-zero samples in a real cell;
the histogram unit tests in `src/histogram.rs` pin percentile correctness,
merge-by-raw-counts and sample-count rules. Previously published v3/v4/v5
manifests remain unchanged as
historical evidence; v16 manifests use a new cell-id suffix and never overwrite
them.

## Reproduce

```bash
cargo test --test full_universe_stress mixed_hot_quiet_4000_cell_reconciles_and_certifies
cargo test --test full_universe_stress mixed_hot_quiet_exact_4000_cell_assigns_320_hot_events
cargo test --test full_universe_stress stress_support::runner::tests::hot_cold_partition_is_exhaustive_and_disjoint
cargo test --test full_universe_stress stress_support::runner::tests::exact_event_targets_have_an_exact_quota_and_are_reproducible
cargo test --test full_universe_stress stress_support::universe::tests::hot_quiet_roles_are_exact_deterministic_and_free_of_decoys
cargo test --test full_universe_stress burst_step_cell_reconciles_all_phases
cargo test --test full_universe_stress burst_impulse_cell_reconciles_all_phases
cargo test --test full_universe_stress stress_support::runner::tests::burst_profiles_partition_the_budget_exactly_and_deterministically

STRESS_MANIFEST_OUT=/tmp/stress-v6 \
  cargo test --release --locked --test full_universe_stress -- \
  --ignored reference_burst_step_manifest_is_reproducible --test-threads=1 --nocapture

# M5.5 boundary profiles (non-ignored)
cargo test --test full_universe_stress profile_ -- --test-threads=1
cargo test --test full_universe_stress backpressure_combined_hot_quiet_writer_queue_4000_certifies

STRESS_MANIFEST_OUT=/tmp/stress-v3 \
  cargo test --release --locked --test full_universe_stress -- \
  --ignored reference_exact_hot_quiet_manifest_is_reproducible --test-threads=1 --nocapture

STRESS_MANIFEST_OUT=/tmp/stress-v16 \
  cargo test --release --locked --test full_universe_stress -- \
  --ignored reference_backpressure_profiles_manifest_is_reproducible --test-threads=1 --nocapture

# M5.4 disconnect sweeps (non-ignored)
cargo test --test full_universe_stress disconnect_ -- --test-threads=1

STRESS_MANIFEST_OUT=/tmp/stress-disconnect-v16 \
  cargo test --release --locked --test full_universe_stress -- \
  --ignored reference_disconnect_sweep_manifest --test-threads=1 --nocapture

# M5.3 lifecycle churn (non-ignored)
cargo test --test lifecycle_churn

STRESS_MANIFEST_OUT=/tmp/stress-lifecycle-v16 \
  cargo test --release --locked --test lifecycle_churn -- \
  --ignored reference_lifecycle_churn_manifest_is_versioned --test-threads=1 --nocapture
```

Limitations: the slow-downstream delay is fixed per delta frame and is not a
bandwidth or latency model; the journal profile does not inject ENOSPC; the
writer profile uses the production 10 s send timeout rather than measuring a
queue-wait distribution. None of these profiles produces performance claims.

All lifecycle evidence above is synthetic loopback evidence. No live Kalshi
lifecycle notification has been observed or claimed in this increment; the
dedicated control-plane tests exercise a loopback mock of `market_lifecycle_v2`.
The v16 cell ids (`*-lifecycle-<scenario>-v16`,
`hyperliquid-<profile>-v16-seed-<seed>`) are distinct from the retained v3-v15
manifests, so no existing artifact is overwritten. All Hyperliquid H3 cells are
synthetic loopback evidence and make no live, latency or capacity claim.
