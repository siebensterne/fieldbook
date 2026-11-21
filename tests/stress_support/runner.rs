//! Cell runner for the stress laboratory. Drives the production collector
//! against the loopback Kalshi mock and produces one machine-readable cell
//! outcome: a result *and* an explicit acceptance verdict, computed inside
//! the runner before any manifest is written. Everything here runs inside the
//! test process; no production code changes for the harness.
//!
//! Acceptance is fail-closed: a manifest with `run_status: success` can only
//! exist when anchoring, drain, coverage, SBE verification, completeness,
//! journal finalization, decoy exclusion and independent event accounting all
//! passed inside `run_cell` itself.

use std::{
    collections::{BTreeSet, HashMap},
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use serde_json::{Map, Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Notify,
    time::sleep,
};

use fieldbook::{
    Side, completeness,
    config::{ExchangeKind, JournalSyncMode, Settings},
    coordinator, coverage,
    report::RunReport,
    util::sha256_hex,
    verify,
};

use super::{
    capacity::{
        AGGREGATE_EVENTS, CapacityCell, HOT_EVENT_SHARE_PCT, HOT_FRACTION_PPM,
        PER_INSTRUMENT_EVENTS, WorkloadModel,
    },
    faults::{FaultSchedule, FaultStep, SweepProfile},
    host::HostInfo,
    lifecycle::{
        CatalogEffect, LIFECYCLE_SCHEDULE_VERSION, LifecycleScenario, LifecycleSchedule,
        UniverseEpoch,
    },
    mock::{MockKalshi, MockLedger},
    rng::SplitMix64,
    universe::SyntheticUniverse,
};

const ANCHOR_LIMIT: Duration = Duration::from_secs(45);
const FINISH_LIMIT: Duration = Duration::from_secs(60);
const DRAIN_LIMIT: Duration = Duration::from_secs(30);
const BASELINE_LIMIT: Duration = Duration::from_secs(5);
const METRICS_POLL: Duration = Duration::from_millis(25);
/// Once anchoring has started (`anchored > 0`), a window with zero progress
/// means the missing-anchor state has been reached; waiting for the full
/// deadline would only burn CI time. The hard deadline remains the backstop.
const ANCHOR_PLATEAU: Duration = Duration::from_secs(3);

/// Scenario schema version. Bumped when workload semantics or the manifest
/// evidence contract change so a corrected generator never silently replaces
/// an earlier manifest. v6 added explicit phased burst schedules; v7-v8
/// carried the M5.3 lifecycle-churn and M5.4 disconnect stress increments;
/// v9 added the M5.5 backpressure boundary profiles and their manifest
/// evidence; v10 added the M5.6 stage-timing histograms, provenance and
/// evidence contract. v13 was the combined integrated schema folding in the
/// lifecycle scenarios and universe-epoch coverage alongside the burst,
/// disconnect, backpressure and capacity profiles; v14 is the integrated
/// schema that additionally carries the M5.6 stage-timing performance block.
/// v15 folds in the M5.7 capacity characterization (4k/10k/25k/50k stages and
/// the fixed-per-instrument, fixed-aggregate and skewed hot/quiet workload
/// models) with its own manifest evidence block. v16 integrates the Hyperliquid
/// H3 capacity profile (loopback wire mock, mid/fast-context/book/trade
/// workload shapes and reconnect recovery) under the same manifest schema.
/// Earlier version-certified cell IDs remain immutable historical evidence.
pub const SCENARIO_VERSION: u32 = 16;

/// Failure-injection knobs for harness self-tests. Each variant maps to one
/// named failure mode with a distinct `failure_class` in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailInject {
    /// Skip the snapshot for one eligible market (by 1-based ordinal).
    MissingSnapshot { skip_one: usize },
    /// Skip the snapshot for one eligible market *and* publish exactly one
    /// delta for it: the symbol is observed but never snapshot-anchored.
    UpdateOnly { skip_one: usize },
    /// Drop the first `n` delta frames before the wire (no sequence number
    /// consumed; protocol-invisible loss only event accounting can catch).
    DroppedFrames { count: usize },
    /// Bound the mock's outbound queue hard and stall the forwarder so the
    /// drain barrier cannot complete in time. Frames admitted before the
    /// bound are completed; the rest are explicit drops (`queue_saturated`).
    MockQueueSaturate { capacity: usize },
    /// Delay each delta frame on the wire after admission. The bounded queue
    /// holds accepted-but-waiting work; no frame is dropped or rejected, and
    /// the drain barrier must not certify the run before completion.
    SlowDownstream { delay_ms: u64 },
    /// Shrink the raw-frame journal's admission queue to its minimum, shorten
    /// its enqueue timeout and force an fsync per record. A burst then makes
    /// journal admission reject records and latch the run failed.
    JournalQueuePressure {
        queue_capacity: usize,
        enqueue_timeout_ms: u64,
    },
    /// Publish each logical delta a second time on the wire. A dedup-correct
    /// collector still applies exactly one copy; the extra application is the
    /// over-application the ledger must detect.
    OverApplication { duplicates: usize },
    /// Notify shutdown immediately after publishing, without any drain wait.
    ShutdownBeforeDrain,
}

/// How hot instruments are selected for each published delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotSelection {
    /// Each draw independently chooses the hot/cold branch with the configured
    /// share; the realized proportion varies within a finite run.
    Weighted,
    /// The run contains an exact integer quota of hot and cold events, with a
    /// deterministic order derived from the workload seed. Used for the
    /// frozen reference profiles so event assignment itself is reproducible.
    ExactQuota,
}

/// Deterministic burst-workload shape (M5.2).
///
/// A profile changes only how the fixed logical-event budget is partitioned
/// across publish phases. It never introduces sleeps, wall-clock timing,
/// throughput instrumentation or latency claims: the schedule is defined by
/// exact event counts, and the rate fields are declared intensity labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BurstProfile {
    /// One sustained step: baseline, a doubled-rate burst, then recovery.
    Step,
    /// One concentrated spike: small baseline, large impulse, quiet recovery.
    Impulse,
    /// Several decreasing impulses separated by quiet recovery phases.
    RepeatedImpulses,
    /// A rising sequence of declared rate multipliers across the burst window.
    Ramp,
}

impl BurstProfile {
    /// Stable manifest label. `None` in `CellConfig` maps to `"steady"`.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Step => "step",
            Self::Impulse => "impulse",
            Self::RepeatedImpulses => "repeated_impulses",
            Self::Ramp => "ramp",
        }
    }
}

/// One declared phase of a workload schedule.
///
/// `events` is an exact logical-delta count and is the primary schedule
/// definition. `target_rate_per_tick` and `rate_multiplier` are dimensionless,
/// declared labels derived from the profile: they are never measured rates,
/// latency figures or performance results. No timing instrumentation exists in
/// this increment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadPhase {
    pub name: &'static str,
    pub events: usize,
    pub target_rate_per_tick: u32,
    pub rate_multiplier: u32,
}

/// How the hot instrument set is defined for one workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotSetDefinition {
    pub fraction_ppm: u32,
    pub member_count: usize,
    pub selection: &'static str,
    pub event_share_pct: u32,
    /// Canonical SHA-256 of the sorted hot ticker set; `None` when the cell
    /// failed before the universe was generated.
    pub sha256: Option<String>,
}

/// Explicit, deterministic workload schedule recorded in every manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadSchedule {
    pub workload_id: String,
    pub profile: &'static str,
    pub seed: u64,
    pub instrument_count: usize,
    pub eligible_count: usize,
    pub hot_set: HotSetDefinition,
    pub phases: Vec<WorkloadPhase>,
    pub expected_total_events: usize,
    /// Fault IDs scheduled for this workload; empty for M5.2 burst profiles.
    pub fault_schedule: Vec<String>,
}

/// Split `total` across integer `weights` so the parts sum to exactly `total`.
/// Leftover units are assigned to the highest-weight phase (ties broken by
/// index), which keeps the allocation deterministic for a given profile.
fn partition_events(total: usize, weights: &[usize]) -> Vec<usize> {
    let weight_sum: usize = weights.iter().sum();
    debug_assert!(weight_sum > 0);
    let mut parts: Vec<usize> = weights
        .iter()
        .map(|weight| ((total as u128 * *weight as u128) / weight_sum as u128) as usize)
        .collect();
    let mut order: Vec<usize> = (0..weights.len()).collect();
    order.sort_by_key(|&index| (std::cmp::Reverse(weights[index]), index));
    let mut leftover = total.saturating_sub(parts.iter().sum());
    let mut cursor = 0usize;
    while leftover > 0 && !order.is_empty() {
        parts[order[cursor % order.len()]] += 1;
        leftover -= 1;
        cursor += 1;
    }
    parts
}

/// Deterministic phase decomposition for one burst profile.
fn profile_phases(profile: BurstProfile, total: usize) -> Vec<WorkloadPhase> {
    let (names, weights, rates, multipliers): (&[&str], &[usize], &[u32], &[u32]) = match profile {
        BurstProfile::Step => (
            &["baseline", "burst", "recovery"],
            &[25, 50, 25],
            &[1, 2, 1],
            &[1, 2, 1],
        ),
        BurstProfile::Impulse => (
            &["baseline", "impulse", "recovery"],
            &[10, 70, 20],
            &[1, 5, 1],
            &[1, 5, 1],
        ),
        BurstProfile::RepeatedImpulses => (
            &[
                "baseline",
                "impulse-1",
                "impulse-2",
                "impulse-3",
                "recovery",
            ],
            &[20, 20, 20, 20, 20],
            &[1, 3, 3, 3, 1],
            &[1, 3, 3, 3, 1],
        ),
        BurstProfile::Ramp => (
            &["baseline", "ramp-1", "ramp-2", "ramp-3", "recovery"],
            &[10, 20, 20, 20, 30],
            &[1, 1, 2, 3, 1],
            &[1, 1, 2, 3, 1],
        ),
    };
    let counts = partition_events(total, weights);
    (0..names.len())
        .map(|index| WorkloadPhase {
            name: names[index],
            events: counts[index],
            target_rate_per_tick: rates[index],
            rate_multiplier: multipliers[index],
        })
        .collect()
}

/// The single-phase schedule used when no burst profile is configured. It is
/// equivalent to the pre-M5.2 workload: one `steady` phase with
/// every logical delta.
fn steady_phases(total: usize) -> Vec<WorkloadPhase> {
    vec![WorkloadPhase {
        name: "steady",
        events: total,
        target_rate_per_tick: 1,
        rate_multiplier: 1,
    }]
}

/// Build the explicit workload schedule from configuration. `hot_sha256` is
/// supplied once the universe exists; failure cells before that point record
/// `None` and do not claim a hot-set certificate.
fn build_schedule(config: &CellConfig, hot_sha256: Option<String>) -> WorkloadSchedule {
    let profile = config.burst.map(BurstProfile::label).unwrap_or("steady");
    let phases = match config.burst {
        Some(burst) => profile_phases(burst, config.events),
        None => steady_phases(config.events),
    };
    let expected_total_events = phases.iter().map(|phase| phase.events).sum();
    let workload_id = format!("{profile}-seed-{:04x}-{}", config.seed, config.symbols);
    let hot_count = if config.hot_fraction_ppm == 0 {
        0
    } else {
        config
            .symbols
            .saturating_mul(config.hot_fraction_ppm as usize)
            .div_ceil(1_000_000)
            .min(config.symbols)
    };
    let fault_schedule = config
        .fail_inject
        .map(|fault| vec![format!("{fault:?}")])
        .unwrap_or_default();
    WorkloadSchedule {
        workload_id,
        profile,
        seed: config.seed,
        instrument_count: config.symbols,
        eligible_count: config.symbols,
        hot_set: HotSetDefinition {
            fraction_ppm: config.hot_fraction_ppm,
            member_count: hot_count,
            selection: match config.hot_selection {
                HotSelection::Weighted => "weighted",
                HotSelection::ExactQuota => "exact_quota",
            },
            event_share_pct: config.hot_event_share_pct,
            sha256: hot_sha256,
        },
        phases,
        expected_total_events,
        fault_schedule,
    }
}

/// One experiment cell.
#[derive(Debug, Clone)]
pub struct CellConfig {
    pub seed: u64,
    pub symbols: usize,
    pub decoy_fraction_ppm: u32,
    /// `None` derives shards via `capacity::plan` (settings.shards = 0).
    pub shards: Option<usize>,
    pub replicas: usize,
    pub lifecycle_replicas: usize,
    /// Number of order-book deltas to publish after anchoring.
    pub events: usize,
    /// Legacy binary skew: the first 10% of markets receive 80% of events.
    pub hot_pair: bool,
    /// Equal-weight baseline marker retained for workload provenance.
    pub uniform_spread: bool,
    /// Portion of eligible instruments designated hot, in parts per million.
    /// Zero keeps the legacy `hot_pair`/uniform behavior.
    pub hot_fraction_ppm: u32,
    /// Share of published deltas routed to designated hot instruments.
    pub hot_event_share_pct: u32,
    /// Weighted stochastic selection or exact deterministic quota.
    pub hot_selection: HotSelection,
    /// Optional deterministic burst shape. `None` keeps the pre-M5.2 single
    /// `steady` phase workload unchanged.
    pub burst: Option<BurstProfile>,
    pub journal: bool,
    /// Overrides `ANCHOR_LIMIT`/`DRAIN_LIMIT` for fast failure tests.
    pub limits: Option<(u64, u64)>,
    /// Forces a capacity rejection (budget of 1 connection).
    pub force_capacity_reject: bool,
    /// One named failure-injection mode; `None` for ordinary cells.
    pub fail_inject: Option<FailInject>,
    /// Typed lifecycle-churn scenario. `None` keeps the pre-M5.3 workload.
    pub lifecycle_scenario: LifecycleScenario,
    /// Override the writer queue bound (harness self-test knob).
    pub writer_queue: Option<usize>,
    /// Repository directory the clean-worktree gate inspects. Defaults to the
    /// crate root; fixtures point this at a scratch git repository.
    pub worktree_dir: Option<PathBuf>,
    /// `Some(true)` enforces the clean-worktree gate regardless of the
    /// `STRESS_REQUIRE_CLEAN` environment variable.
    pub require_clean_worktree: Option<bool>,
    /// Deterministic disconnect/recovery fault schedule. `None` for ordinary
    /// cells; derived explicitly from the seed by the disconnect profiles.
    pub fault_schedule: Option<FaultSchedule>,
    /// Capacity characterization selection. `None` for ordinary stress cells;
    /// when present the manifest records stage, model and expected events.
    pub capacity: Option<CapacityCell>,
}

impl Default for CellConfig {
    fn default() -> Self {
        Self {
            seed: 1,
            symbols: 1_000,
            decoy_fraction_ppm: 20_000,
            shards: None,
            replicas: 2,
            lifecycle_replicas: 1,
            events: 300,
            hot_pair: false,
            uniform_spread: true,
            hot_fraction_ppm: 0,
            hot_event_share_pct: 0,
            hot_selection: HotSelection::Weighted,
            burst: None,
            journal: true,
            limits: None,
            force_capacity_reject: false,
            fail_inject: None,
            lifecycle_scenario: LifecycleScenario::None,
            writer_queue: None,
            worktree_dir: None,
            require_clean_worktree: None,
            fault_schedule: None,
            capacity: None,
        }
    }
}

impl CellConfig {
    /// Build a cell configured for one deterministic disconnect sweep profile.
    #[must_use]
    pub fn for_sweep(base: CellConfig, profile: SweepProfile) -> Self {
        Self {
            fault_schedule: Some(super::faults::derive_schedule(profile, base.seed)),
            ..base
        }
    }
}

/// Put injected boundary evidence ahead of collector symptoms.
///
/// The boundary-class reason names the physical condition under test. A drain
/// or delivery symptom can appear or disappear with scheduling, so it must not
/// decide the primary failure class when a boundary reason is present.
fn order_acceptance_reasons(boundary: Vec<String>, observed: Vec<String>) -> Vec<String> {
    let mut ordered = boundary;
    ordered.extend(observed);
    ordered
}

/// Acceptance verdict for one cell. Any failure lists every reason found; the
/// first reason is the primary machine-readable `failure_class`.
#[derive(Debug, Clone)]
pub struct CellAcceptance {
    pub valid: bool,
    pub reasons: Vec<String>,
    /// Primary machine-readable failure class for the manifest.
    pub failure_class: Option<String>,
}

impl CellAcceptance {
    fn valid() -> Self {
        Self {
            valid: true,
            reasons: Vec::new(),
            failure_class: None,
        }
    }
    fn from_reasons(reasons: Vec<String>) -> Self {
        let failure_class = reasons.first().cloned();
        Self {
            valid: false,
            reasons,
            failure_class,
        }
    }

    /// Design vocabulary: `success | failed | incomplete | interrupted`.
    /// `interrupted` is reserved for supervisor finalization of a run whose
    /// process died; everything the runner itself observes is `failed` unless
    /// every reason is a timeout-class observation, which is `incomplete`.
    #[must_use]
    pub fn status(&self) -> &'static str {
        if self.valid {
            return "success";
        }
        const TIMEOUT_CLASSES: [&str; 3] = ["anchor_timeout", "anchor_plateau", "drain_incomplete"];
        if self
            .reasons
            .iter()
            .all(|reason| TIMEOUT_CLASSES.contains(&reason.as_str()))
        {
            "incomplete"
        } else {
            "failed"
        }
    }
}

/// Recovery measurement for one injected disconnect fault. Recovery is
/// measured as *incident detection -> valid re-anchor*, not as a socket
/// reconnect: a reconnect that never produces an accepted snapshot is not a
/// recovery. Durations are sampled at the 25 ms metrics poll, so a zero value
/// means "within one poll", not "instantaneous".
#[derive(Debug, Clone, Default)]
pub struct RecoveryEvidence {
    pub fault_id: String,
    /// Observed epoch of the first replacement connection after the fault.
    pub observed_epoch: Option<usize>,
    pub incidents_before: Option<u64>,
    pub incidents_after: Option<u64>,
    pub failover_snapshots_before: Option<u64>,
    pub failover_snapshots_after: Option<u64>,
    /// Mock websocket connection count observed when the step finished. A
    /// strictly increasing count across storm rounds proves each round opened
    /// fresh sockets rather than reusing a stale generation.
    pub connections_after: Option<usize>,
    /// Milliseconds from anchor completion at which the incident was first
    /// observed (a discontinuity counter increase or a resyncing symbol).
    pub detected_at_ms: Option<u64>,
    /// Milliseconds from anchor completion at which a valid re-anchor was
    /// observed (failover snapshot accepted and no resyncing symbols).
    pub reanchored_at_ms: Option<u64>,
    /// `reanchored_at_ms - detected_at_ms`, when both observations exist.
    pub duration_ms: Option<u64>,
    /// Why a duration could not be measured. `None` when it was measured.
    pub duration_unavailable_reason: Option<String>,
}

/// Incident counters scraped from the collector's `/metrics` endpoint at the
/// end of the run. `None` means the evidence is unavailable, not zero.
#[derive(Debug, Clone, Copy, Default)]
pub struct IncidentCounters {
    pub discontinuity_incidents: Option<u64>,
    pub unquantifiable_gaps: Option<u64>,
    pub suppressed_replica_duplicates: Option<u64>,
}

/// Per-stage event accounting, derived from independent counters:
/// the harness publish loop, the mock transmit ledger, the collector's
/// `/metrics` counters and the decoded SBE capture. Nothing here is
/// hard-coded to success; a stage that cannot be observed stays `None` and
/// makes the cell uncertifiable.
#[derive(Debug, Clone, Default)]
pub struct EventLedger {
    /// Logical deltas the harness generated and offered to the mock.
    pub generated_events: u64,
    /// Applied count the ledger expects from the injection arithmetic.
    pub expected_applied: u64,
    /// `collector_deltas_emitted_total` increase observed by the runner.
    /// `None` when the metrics evidence is unavailable.
    pub applied_events: Option<u64>,
    /// Delta messages in the decoded SBE capture. `None` on scan failure.
    pub sbe_deltas: Option<u64>,
    /// Delta frames accepted into the mock's outbound queue.
    pub enqueued_deltas: Option<u64>,
    /// Delta frames whose websocket send completed.
    pub transmitted_deltas: Option<u64>,
    /// Data frames read at the ingress boundary (snapshots and deltas).
    pub received_frames: Option<u64>,
    /// Order-book delta frames successfully decoded at the source boundary.
    pub delta_events_decoded: Option<u64>,
    /// Decode failures reported by production source metrics.
    pub decode_errors: Option<u64>,
    /// Core-ingress boundary, distinct from the transport boundary.
    pub core_ingress_events: Option<u64>,
    pub core_delta_events: Option<u64>,
    /// Terminal delta dispositions not covered by emitted / suppressed.
    pub no_active_source: Option<u64>,
    pub unknown_symbol: Option<u64>,
    pub non_live: Option<u64>,
    pub unassigned_source: Option<u64>,
    pub invalid_book: Option<u64>,
    pub shadow_clock_regression: Option<u64>,
    pub zero_noop: Option<u64>,
    pub sbe_conversion_failed: Option<u64>,
    /// Sum of all terminal dispositions versus decoded deltas.
    pub disposition_shortfall: Option<u64>,
    pub disposition_excess: Option<u64>,
    /// Order-book deltas admitted to the writer queue.
    pub writer_delta_admissions: Option<u64>,
    /// Order-book deltas successfully written to SBE.
    pub writer_delta_writes: Option<u64>,
    /// Journal record count when the journal is enabled.
    pub journaled_records: Option<u64>,
    /// Frames the mock dropped before the wire (injected fixture).
    pub injected_pre_wire_drops: u64,
    /// Deltas applied to a non-active replica and suppressed from output.
    /// `None` when the dedup counter could not be scraped. This is a
    /// transport duplicate, not a duplicate application.
    pub suppressed_replica_duplicates: Option<u64>,
    /// `generated - applied`, derived; `None` when applied is unobservable.
    /// This coarse residual also absorbs injected pre-wire drops.
    pub unexplained_drops: Option<u64>,
    /// `expected_applied - applied`: the downward half of the application
    /// balance. `Some(0)` is the only acceptable value.
    pub application_shortfall: Option<u64>,
    /// `applied - expected_applied`: the upward half. A positive value means
    /// one logical event was applied more than once.
    pub over_applied: Option<u64>,
    /// `applied - sbe_deltas`, derived; `None` when either side is missing.
    pub persistence_gap: Option<u64>,
    /// `sbe_deltas - applied`: persistence cannot contain more records than
    /// were applied. `Some(0)` is the only acceptable value.
    pub persistence_excess: Option<u64>,
    /// `enqueued - transmitted`; nonzero means pre-wire loss.
    pub enqueue_transmit_shortfall: Option<u64>,
    /// `transmitted - enqueued`; nonzero means an over-count or reset.
    pub enqueue_transmit_excess: Option<u64>,
    /// `decoded_deltas - applied`; nonzero means decoded data never applied.
    pub transmit_decode_shortfall: Option<u64>,
    /// `applied - decoded_deltas`; nonzero means application without decoding.
    pub transmit_decode_excess: Option<u64>,
    /// `applied - writer_delta_admissions`; nonzero means writer rejection.
    pub writer_admission_shortfall: Option<u64>,
    /// `writer_delta_admissions - applied`; nonzero means extra admissions.
    pub writer_admission_excess: Option<u64>,
    /// `writer_delta_admissions - writer_delta_writes`; nonzero means a write failure.
    pub writer_write_shortfall: Option<u64>,
    /// `writer_delta_writes - writer_delta_admissions`; nonzero means extra writes.
    pub writer_write_excess: Option<u64>,
    /// Decode errors observed during the window. `Some(0)` is clean.
    pub decode_failure_count: Option<u64>,
}

/// Compute both directional discrepancies for independently sourced counts.
/// `None` on either side stays `None`: unavailable evidence is never zero.
pub fn two_sided(expected: Option<u64>, observed: Option<u64>) -> (Option<u64>, Option<u64>) {
    match (expected, observed) {
        (Some(expected), Some(observed)) => (
            Some(expected.saturating_sub(observed)),
            Some(observed.saturating_sub(expected)),
        ),
        _ => (None, None),
    }
}

/// Ledger-construction helper for the transmit -> decode boundary. The wire
/// frame is the expected count and the decoded event is the observed count,
/// so a dropped decode is a shortfall and an extra decode is an excess.
pub fn transmit_decode_gaps(
    transmitted: Option<u64>,
    decoded: Option<u64>,
) -> (Option<u64>, Option<u64>) {
    two_sided(transmitted, decoded)
}

/// Difference of one metric between two scrapes. Missing evidence stays
/// `None`; a decreasing counter is treated as an explicit reset failure by the
/// caller rather than silently clamped to zero.
pub fn metric_window_delta(before: Option<u64>, after: Option<u64>) -> Option<u64> {
    match (before, after) {
        (Some(before), Some(after)) if after >= before => Some(after - before),
        _ => None,
    }
}

impl EventLedger {
    /// A ledger reconciles only when every stage is observed and every
    /// two-sided derived gap is exactly zero. Saturating arithmetic is never
    /// used here to hide a negative difference: each direction is its own
    /// field, so over-application cannot pass as a clean run.
    #[must_use]
    pub fn reconciled(&self) -> bool {
        self.unexplained_drops == Some(0)
            && self.application_shortfall == Some(0)
            && self.over_applied == Some(0)
            && self.persistence_gap == Some(0)
            && self.persistence_excess == Some(0)
            && self.enqueue_transmit_shortfall == Some(0)
            && self.enqueue_transmit_excess == Some(0)
            && self.transmit_decode_shortfall == Some(0)
            && self.transmit_decode_excess == Some(0)
            && self.writer_admission_shortfall == Some(0)
            && self.writer_admission_excess == Some(0)
            && self.writer_write_shortfall == Some(0)
            && self.writer_write_excess == Some(0)
            && self.decode_failure_count == Some(0)
            && self.disposition_shortfall == Some(0)
            && self.disposition_excess == Some(0)
            && self.no_active_source.is_some()
            && self.unknown_symbol.is_some()
            && self.non_live.is_some()
            && self.unassigned_source.is_some()
            && self.invalid_book.is_some()
            && self.shadow_clock_regression.is_some()
            && self.zero_noop.is_some()
            && self.sbe_conversion_failed.is_some()
            && self.received_frames.is_some_and(|count| count > 0)
            && self.delta_events_decoded.is_some_and(|count| count > 0)
            && self.writer_delta_admissions.is_some()
            && self.writer_delta_writes.is_some()
    }
}

/// Translate every ledger condition into an attributable acceptance reason.
/// This is the certification path used by the runner, not a helper used only
/// by unit tests.
pub fn ledger_acceptance_reasons(ledger: &EventLedger, queue_saturated: u64) -> Vec<String> {
    let mut reasons = Vec::new();
    if ledger.unexplained_drops.is_none() {
        reasons.push("event_accounting_unavailable".to_owned());
    }
    if let Some(value) = ledger.unexplained_drops
        && value > 0
    {
        reasons.push("unexplained_drops".to_owned());
    }
    if let Some(value) = ledger.application_shortfall
        && value > 0
    {
        reasons.push("application_shortfall".to_owned());
    }
    if let Some(value) = ledger.over_applied
        && value > 0
    {
        reasons.push("over_application".to_owned());
        reasons.push("duplicate_application".to_owned());
    }
    if let Some(value) = ledger.persistence_gap
        && value > 0
    {
        reasons.push("persistence_gap".to_owned());
    }
    if let Some(value) = ledger.persistence_excess
        && value > 0
    {
        reasons.push("persistence_excess".to_owned());
    }
    if ledger.received_frames.is_none() || ledger.received_frames == Some(0) {
        reasons.push("receive_evidence_missing".to_owned());
    }
    if ledger.delta_events_decoded.is_none() {
        reasons.push("decode_evidence_missing".to_owned());
    }
    if ledger.suppressed_replica_duplicates.is_none() {
        reasons.push("replica_duplicate_evidence_missing".to_owned());
    }
    if ledger.writer_delta_admissions.is_none() {
        reasons.push("writer_admission_evidence_missing".to_owned());
    }
    if ledger.writer_delta_writes.is_none() {
        reasons.push("writer_write_evidence_missing".to_owned());
    }
    if ledger.decode_errors.is_none() {
        reasons.push("decode_error_evidence_missing".to_owned());
    }
    for (value, reason) in [
        (ledger.no_active_source, "disposition_evidence_missing"),
        (ledger.unknown_symbol, "disposition_evidence_missing"),
        (ledger.non_live, "disposition_evidence_missing"),
        (ledger.unassigned_source, "disposition_evidence_missing"),
        (ledger.invalid_book, "disposition_evidence_missing"),
        (
            ledger.shadow_clock_regression,
            "disposition_evidence_missing",
        ),
        (ledger.zero_noop, "disposition_evidence_missing"),
        (ledger.sbe_conversion_failed, "disposition_evidence_missing"),
    ] {
        if value.is_none() {
            reasons.push(reason.to_owned());
        }
    }
    if let Some(value) = ledger.disposition_shortfall
        && value > 0
    {
        reasons.push("disposition_shortfall".to_owned());
    }
    if let Some(value) = ledger.disposition_excess
        && value > 0
    {
        reasons.push("disposition_excess".to_owned());
    }
    if let Some(value) = ledger.decode_failure_count
        && value > 0
    {
        reasons.push("decode_failures".to_owned());
    }
    for (shortfall, excess, shortfall_class, excess_class, missing_class) in [
        (
            ledger.enqueue_transmit_shortfall,
            ledger.enqueue_transmit_excess,
            "pre_wire_loss",
            "enqueue_excess",
            "enqueue_transmit_evidence_missing",
        ),
        (
            ledger.transmit_decode_shortfall,
            ledger.transmit_decode_excess,
            "transmit_decode_shortfall",
            "transmit_decode_excess",
            "transmit_decode_evidence_missing",
        ),
        (
            ledger.writer_admission_shortfall,
            ledger.writer_admission_excess,
            "writer_admission_shortfall",
            "writer_admission_excess",
            "writer_admission_evidence_missing",
        ),
        (
            ledger.writer_write_shortfall,
            ledger.writer_write_excess,
            "writer_write_shortfall",
            "writer_write_excess",
            "writer_write_evidence_missing",
        ),
    ] {
        match (shortfall, excess) {
            (None, _) | (_, None) => reasons.push(missing_class.to_owned()),
            (Some(s), Some(e)) => {
                if s > 0 {
                    reasons.push(shortfall_class.to_owned());
                }
                if e > 0 {
                    reasons.push(excess_class.to_owned());
                }
            }
        }
    }
    if !ledger.reconciled() && reasons.is_empty() {
        reasons.push("event_ledger_unreconciled".to_owned());
    }
    if queue_saturated > 0 {
        reasons.push("mock_throughput_limited".to_owned());
        reasons.push("mock_queue_saturation".to_owned());
    }
    reasons
}

/// Publish and drain evidence for one schedule phase. The cumulative expected
/// count is the drain barrier's target at the end of this phase.
#[derive(Debug, Clone)]
pub struct PhaseOutcome {
    pub name: &'static str,
    pub published: usize,
    pub cumulative_expected: u64,
    pub drain_completed: bool,
}

/// Full result of one cell run — raw verifier digests included for the manifest.
pub struct CellOutput {
    pub report: RunReport,
    pub coverage: Option<coverage::CoverageSummary>,
    pub coverage_error: Option<String>,
    pub completeness_error: Option<String>,
    pub verify_error: Option<String>,
    pub completeness_valid: bool,
    pub verify_valid: bool,
    pub anchored_time: Duration,
    pub harness_process_rss_sample_bytes: Option<u64>,
    /// Independently generated eligible universe.
    pub expected_symbols: BTreeSet<String>,
    /// Symbols the collector acknowledged via the report.
    pub acknowledged_symbols: BTreeSet<String>,
    /// Symbols with any snapshot or price-level update in the capture.
    pub observed_symbols: BTreeSet<String>,
    /// Symbols anchored by at least one *snapshot* (never by deltas alone).
    pub anchored_symbols: BTreeSet<String>,
    pub eligible_count: usize,
    /// Number of eligible instruments assigned the hot workload role.
    pub hot_tickers: usize,
    /// Logical deltas assigned to hot instruments.
    pub hot_events: usize,
    /// Logical deltas assigned to the disjoint cold instruments.
    pub cold_events: usize,
    pub decoy_absent: bool,
    pub journal_complete: bool,
    pub journaled_records: Option<u64>,
    /// Mock transmit-side counters (enqueued vs socket-written vs in flight).
    pub mock: MockLedger,
    /// Frames whose websocket send completed (= `mock.sent`).
    pub transmitted_frames: u64,
    pub events_published: usize,
    pub applied_events: Option<u64>,
    pub capacity_connections: usize,
    pub anchor_wait_expired: bool,
    pub drain_completed: bool,
    pub drain_detail: Option<String>,
    pub sbe_deltas: u64,
    pub sbe_snapshots: u64,
    pub sbe_messages: u64,
    /// Production writer queue high-water mark (from `WriterStats`).
    pub writer_queue_high_water: u64,
    /// Continuity incidents observed at the end of the run.
    pub incidents: IncidentCounters,
    pub ledger: EventLedger,
    /// Explicit deterministic workload schedule used by this run.
    pub schedule: WorkloadSchedule,
    /// Per-phase publish + drain evidence (one entry for a steady workload).
    pub phase_results: Vec<PhaseOutcome>,
    /// Incident-detection -> valid-re-anchor evidence per injected fault.
    pub recovery: Vec<RecoveryEvidence>,
    /// Total websocket connections accepted by the mock (including reconnects).
    pub ws_connections: usize,
    /// Book subscription entries accepted by the mock (including resubscribes).
    pub book_subscriptions: usize,
    /// Resolved lifecycle schedule (seed + explicit event sequence).
    pub lifecycle_schedule: LifecycleSchedule,
    /// Application-side lifecycle counters from the run report.
    pub lifecycle_applied: u64,
    pub lifecycle_duplicates: u64,
    pub lifecycle_stale_dropped: u64,
    pub lifecycle_unknown_symbols: u64,
    pub lifecycle_discovery_vetoes: u64,
    /// Lifecycle frames written to every replica by the mock.
    pub lifecycle_sent_frames: u64,
    pub lifecycle_subscribed: usize,
    pub lifecycle_barrier_completed: bool,
    pub lifecycle_barrier_detail: Option<String>,
    pub anchored_extras_ok: bool,
}

/// One finished cell: output plus the runner's acceptance verdict plus the
/// worktree provenance captured before the run started.
pub struct CellOutcome {
    pub output: Option<CellOutput>,
    pub acceptance: CellAcceptance,
    pub provenance: Option<WorktreeProvenance>,
}

/// Worktree provenance recorded for every manifest. Untracked files are
/// counted informationally; the gate only ever considers tracked changes.
#[derive(Debug, Clone, Default)]
pub struct WorktreeProvenance {
    pub commit: Option<String>,
    /// `Some(false)` when tracked files differ from `HEAD`.
    pub tracked_clean: Option<bool>,
    pub tracked_modified: Vec<String>,
    /// SHA-256 of `git diff HEAD` output while the worktree is dirty.
    pub tracked_diff_sha256: Option<String>,
    pub untracked_count: Option<usize>,
    pub error: Option<String>,
}

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// Inspect `repo` and record provenance. Never fails the run by itself.
#[must_use]
pub fn worktree_provenance(repo: &Path) -> WorktreeProvenance {
    let commit = git(repo, &["rev-parse", "HEAD"]);
    let tracked_status = git(repo, &["status", "--porcelain", "--untracked-files=no"]);
    let full_status = git(repo, &["status", "--porcelain"]);
    let diff = git(repo, &["diff", "HEAD"]);
    let error = if commit.is_none() && tracked_status.is_none() {
        Some("git unavailable or not a repository".to_owned())
    } else {
        None
    };
    let tracked_modified: Vec<String> = tracked_status
        .as_ref()
        .map(|text| {
            text.lines()
                .filter(|line| !line.trim().is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let tracked_clean = tracked_status.map(|_| tracked_modified.is_empty());
    let tracked_diff_sha256 = diff
        .filter(|text| !text.is_empty())
        .map(|text| sha256_hex(text.as_bytes()));
    let untracked_count =
        full_status.map(|text| text.lines().filter(|line| line.starts_with("?? ")).count());
    WorktreeProvenance {
        commit,
        tracked_clean,
        tracked_modified,
        tracked_diff_sha256,
        untracked_count,
        error,
    }
}

fn require_clean_flag(config: &CellConfig) -> bool {
    config
        .require_clean_worktree
        .unwrap_or_else(|| std::env::var("STRESS_REQUIRE_CLEAN").is_ok_and(|v| v == "1"))
}

/// Preflight gate. Fails closed when a clean worktree is required and the
/// tracked state is dirty — or cannot be verified at all.
fn worktree_preflight(config: &CellConfig) -> (WorktreeProvenance, Option<String>) {
    let repo = config
        .worktree_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let provenance = worktree_provenance(&repo);
    if !require_clean_flag(config) {
        return (provenance, None);
    }
    if provenance.error.is_some() {
        return (provenance, Some("worktree_unverifiable".to_owned()));
    }
    if provenance.tracked_clean == Some(false) {
        return (provenance, Some("dirty_worktree".to_owned()));
    }
    (provenance, None)
}

fn unused_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binding an ephemeral port");
    listener
        .local_addr()
        .expect("reading the ephemeral address")
}

fn write_test_key(directory: &Path) -> PathBuf {
    let key_path = directory.join("stress-key.pem");
    let signing = SigningKey::from_bytes(&[0x5A; 32]);
    fs::write(
        &key_path,
        ed25519_dalek::pkcs8::EncodePrivateKey::to_pkcs8_pem(
            &signing,
            ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF,
        )
        .unwrap(),
    )
    .unwrap();
    key_path
}

fn settings_for(mock: &MockKalshi, directory: &Path, config: &CellConfig) -> Settings {
    let mut settings = Settings::for_exchange(ExchangeKind::Kalshi);
    settings.kalshi.rest_url = Some(mock.http_url());
    settings.kalshi.ws_url = Some(mock.ws_url());
    settings.kalshi.key_id = "stress-key".to_owned();
    settings.kalshi.private_key_path = Some(write_test_key(directory));
    settings.kalshi.discovery_page_size = 1_000;
    settings.kalshi.discovery_page_delay_ms = 0;
    settings.kalshi.request_timeout_secs = 5;
    settings.kalshi.batch_size = 500;

    settings.collector.shards = config.shards.unwrap_or(0);
    settings.collector.replicas = config.replicas;
    settings.collector.lifecycle_replicas = config.lifecycle_replicas;
    settings.collector.discovery_interval_secs = 3_600;
    settings.collector.reconnect_after_secs = 1_800;
    settings.collector.connection_idle_timeout_secs = 45;
    settings.collector.stale_probe_after_secs = 120;
    settings.collector.probe_interval_secs = 30;
    // Disconnect sweeps exercise transport loss, not stale-probe escalation.
    // Disabling probe escalation keeps the recovery signal attributable to the
    // injected disconnect instead of to a later symbol-scoped probe budget.
    settings.collector.max_probes = if config.fault_schedule.is_some() {
        1
    } else {
        3
    };
    settings.collector.max_markets = 0;
    settings.collector.duration_secs = 0;
    settings.collector.writer_queue = config.writer_queue.unwrap_or(4_096);
    // This timeout governs every writer/metadata/journal shutdown deadline,
    // including journal finalization: producer quiescence, the finalize
    // command, the segment fsync + rename and the manifest rewrite. A
    // 1-second bound passed on a quiet workstation but failed under
    // GitHub-hosted CI, where dozens of these cells run in parallel on a
    // 4-vCPU runner and finalization legitimately takes longer. The value is
    // still far below the harness's own finish deadline; fixture failures
    // come from the fixtures, never from this deadline.
    settings.collector.writer_send_timeout_secs = 10;
    settings.collector.max_total_connections = if config.force_capacity_reject { 1 } else { 512 };
    settings.collector.max_shards = 256;
    settings.collector.max_estimated_book_memory_mb = 4_096;
    settings.collector.max_snapshot_bytes_per_sec = 64 << 20;
    settings.collector.final_snapshots = true;
    settings.output.path = directory.join("orderbook.sbe").display().to_string();
    settings.output.chunk_size = 16 * 1024;
    settings.output.metadata_path = Some(directory.join("markets.json"));
    settings.output.report_path = Some(directory.join("report.json"));
    settings.output.sync_on_close = false;
    settings.metrics.listen = Some(unused_address());
    settings.journal.directory = if config.journal {
        Some(directory.join("journal"))
    } else {
        None
    };
    // A one-record queue and the configured enqueue timeout make admission
    // failure observable. Always-sync mode requests an fsync for each record.
    if let Some(FailInject::JournalQueuePressure {
        queue_capacity,
        enqueue_timeout_ms,
    }) = config.fail_inject
    {
        settings.journal.queue_capacity = queue_capacity.max(1);
        settings.journal.enqueue_timeout_ms = enqueue_timeout_ms.max(1);
        settings.journal.sync_mode = JournalSyncMode::Always;
    }
    settings.network = Default::default();
    settings
}

/// Outcome of reading one metric family from a scrape.
#[derive(Debug, Clone, Copy, PartialEq)]
enum MetricRead {
    Present(f64),
    Absent,
    Malformed,
}

/// One parsed `/metrics` body. Labeled families are folded to the family name;
/// a family that cannot be parsed is recorded as malformed instead of being
/// treated as zero.
#[derive(Debug, Default, Clone)]
struct MetricSample {
    values: HashMap<String, f64>,
    malformed: BTreeSet<String>,
    /// Raw body, retained so labelled series of the same metric (one per
    /// source) can be summed independently of the collapsed lookup map.
    raw: String,
}

impl MetricSample {
    fn read(&self, name: &str) -> MetricRead {
        if let Some(value) = self.values.get(name) {
            return MetricRead::Present(*value);
        }
        if self.malformed.contains(name) {
            return MetricRead::Malformed;
        }
        MetricRead::Absent
    }

    /// A required metric is an error when it is absent or unparseable. This is
    /// the difference between "the collector emitted zero" and "the evidence
    /// path is broken".
    fn required(&self, name: &str) -> Result<f64, String> {
        match self.read(name) {
            MetricRead::Present(value) => Ok(value),
            MetricRead::Absent => Err(format!("required metric `{name}` is absent")),
            MetricRead::Malformed => Err(format!("required metric `{name}` is malformed")),
        }
    }

    /// Sum every labelled series of `name`. `None` when any series is absent
    /// or malformed, so a partial scrape can never be mistaken for a count.
    fn count_sum(&self, name: &str) -> Option<u64> {
        let mut total = 0.0f64;
        let mut seen = 0usize;
        for line in self.raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((series, value)) = line.split_once(' ') else {
                continue;
            };
            let base = series.split('{').next().unwrap_or(series);
            if base != name {
                continue;
            }
            let parsed = value.trim().parse::<f64>().ok()?;
            if !parsed.is_finite() || parsed < 0.0 || parsed.fract() != 0.0 {
                return None;
            }
            total += parsed;
            seen += 1;
        }
        (seen > 0).then_some(total as u64)
    }

    /// An exact non-negative count, or `None` when the sample is not one.
    fn count(&self, name: &str) -> Option<u64> {
        match self.read(name) {
            MetricRead::Present(value)
                if value.is_finite() && value >= 0.0 && value.fract() == 0.0 =>
            {
                Some(value as u64)
            }
            _ => None,
        }
    }
}

fn parse_metrics(body: &str) -> MetricSample {
    let mut sample = MetricSample::default();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once(' ') else {
            continue;
        };
        let name = name.split('{').next().unwrap_or(name);
        match value.trim().parse::<f64>() {
            Ok(parsed) => {
                sample.values.insert(name.to_owned(), parsed);
            }
            Err(_) => {
                sample.malformed.insert(name.to_owned());
            }
        }
    }
    sample
}

/// Scrape every plain metric sample from the collector's `/metrics` endpoint.
async fn scrape_metrics(address: SocketAddr) -> Option<MetricSample> {
    let mut stream = TcpStream::connect(address).await.ok()?;
    let request = format!("GET /metrics HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await.ok()?;
    let body = response.split_once("\r\n\r\n")?.1;
    let mut sample = parse_metrics(body);
    sample.raw = body.to_owned();
    Some(sample)
}

async fn scrape_metric(address: SocketAddr, metric: &str) -> Option<f64> {
    match scrape_metrics(address).await?.read(metric) {
        MetricRead::Present(value) => Some(value),
        _ => None,
    }
}

fn rss_sample_bytes() -> Option<u64> {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.trim()
        .parse::<u64>()
        .ok()
        .map(|kilobytes| kilobytes * 1024)
}

/// The eligible market a snapshot-skip injection targets, resolved through
/// the eligible universe (1-based ordinal), never a raw universe index.
fn skip_target(config: &CellConfig, tickers: &[String]) -> Option<String> {
    match config.fail_inject {
        Some(FailInject::MissingSnapshot { skip_one })
        | Some(FailInject::UpdateOnly { skip_one }) => {
            tickers.get(skip_one.saturating_sub(1)).cloned()
        }
        _ => None,
    }
}

fn apply_failure_injection(mock: &MockKalshi, config: &CellConfig, tickers: &[String]) {
    match config.fail_inject {
        Some(FailInject::MissingSnapshot { .. }) | Some(FailInject::UpdateOnly { .. }) => {
            if let Some(ticker) = skip_target(config, tickers)
                && let Some(index) = mock.state().market_index(&ticker)
            {
                mock.state().set_skip_snapshots([index]);
            }
        }
        Some(FailInject::DroppedFrames { count }) => {
            mock.state().set_drop_delta_count(count as u64);
        }
        Some(FailInject::MockQueueSaturate { capacity }) => {
            mock.state().set_outbound_capacity(capacity);
            mock.state().stall_forwarder();
        }
        Some(FailInject::SlowDownstream { delay_ms }) => {
            mock.state().set_forwarder_delay(delay_ms);
        }
        Some(FailInject::JournalQueuePressure { .. })
        | Some(FailInject::OverApplication { .. })
        | Some(FailInject::ShutdownBeforeDrain)
        | None => {}
    }
}

fn publish_delta_event(mock: &MockKalshi, ticker: &str, rng: &mut SplitMix64) {
    let side = if rng.below(2) == 0 {
        Side::Buy
    } else {
        Side::Sell
    };
    let price = 400_000 + i64::try_from(rng.below(200_000 / 10_000)).unwrap_or(0) * 10_000;
    let delta = 2_000_000 + i64::try_from(rng.below(3_000_000)).unwrap_or(0);
    mock.state().publish_delta(ticker, side, price, delta);
}

/// Fixture-aware publish plan. `expected_applied` is derived from the
/// injection arithmetic before the run observes anything:
///
/// - `UpdateOnly`: exactly one delta hits the unanchored market (silently
///   dropped by the collector's continuity guard) plus `events - 1` normal
///   deltas on publishable markets;
/// - `MissingSnapshot`: all deltas avoid the skip target;
/// - `DroppedFrames { count }`: the first `count` frames are dropped before
///   the wire in replica-pair order, so `count / replicas` events vanish;
/// - `OverApplication { duplicates }`: `duplicates` extra delta frames are
///   published for already-generated logical events, so `expected_applied`
///   stays correct while a dedup regression applies more than expected.
struct PublishPlan {
    generated: usize,
    /// Logical deltas assigned to designated hot instruments.
    hot_events: usize,
    /// Logical deltas assigned to the disjoint cold set.
    cold_events: usize,
    /// The count a dedup-correct collector must apply. This is the ledger
    /// baseline, not the number of wire frames.
    expected_applied: u64,
    /// The count the drain barrier waits for. It exceeds `expected_applied`
    /// only for a fixture that publishes extra frames.
    drain_target: u64,
}

/// Partition publishable indices into disjoint hot and cold collections.
/// Every publishable index appears in exactly one collection, so a cold draw
/// can never select a hot instrument.
fn workload_partition(tickers: &[&str], hot: &BTreeSet<String>) -> (Vec<usize>, Vec<usize>) {
    let mut hot_indices = Vec::new();
    let mut cold_indices = Vec::new();
    for (index, ticker) in tickers.iter().enumerate() {
        if hot.contains(*ticker) {
            hot_indices.push(index);
        } else {
            cold_indices.push(index);
        }
    }
    (hot_indices, cold_indices)
}

/// Deterministically place an exact quota of hot events in a shuffled order.
fn exact_event_targets(events: usize, hot_share_pct: u32, rng: &mut SplitMix64) -> Vec<bool> {
    let hot_count =
        ((events as u64).saturating_mul(u64::from(hot_share_pct.min(100))) / 100) as usize;
    let mut targets = vec![true; hot_count];
    targets.resize(events, false);
    for index in (1..targets.len()).rev() {
        let other = rng.below_usize(index + 1);
        targets.swap(index, other);
    }
    targets
}

/// Publish exactly `events` logical deltas and return the derived plan. The RNG
/// is threaded through phases so the whole workload is one deterministic stream
/// derived from the seed; phase boundaries do not reset it.
#[expect(
    clippy::too_many_arguments,
    reason = "the publish call threads the workload, cumulative lifecycle base and callback explicitly so each evidence input is visible at the call site"
)]
fn publish_events(
    mock: &MockKalshi,
    tickers: &[String],
    hot: &BTreeSet<String>,
    config: &CellConfig,
    events: usize,
    rng: &mut SplitMix64,
    skip_ticker: Option<&str>,
    published_base: usize,
    mut on_publish: impl FnMut(usize),
) -> PublishPlan {
    // Fire schedule entries pinned to the start of this phase before any new
    // delta exists, so an added market is anchored before it can be targeted.
    // The base is the cumulative logical-delta count across earlier phases.
    on_publish(published_base);
    let mut generated = 0usize;
    if matches!(config.fail_inject, Some(FailInject::UpdateOnly { .. }))
        && let Some(ticker) = skip_ticker
    {
        publish_delta_event(mock, ticker, rng);
        generated += 1;
    }
    let publishable: Vec<&str> = tickers
        .iter()
        .map(String::as_str)
        .filter(|ticker| Some(*ticker) != skip_ticker)
        .collect();
    let hot_cut = (publishable.len() / 10).max(2);
    let (hot_indices, cold_indices) = workload_partition(&publishable, hot);
    let role_based =
        config.hot_fraction_ppm > 0 && !hot_indices.is_empty() && !cold_indices.is_empty();
    let exact_targets = (role_based && config.hot_selection == HotSelection::ExactQuota)
        .then(|| exact_event_targets(events, config.hot_event_share_pct, rng));
    let initial_generated = generated;
    let mut hot_events = 0usize;
    let mut cold_events: usize =
        if matches!(config.fail_inject, Some(FailInject::UpdateOnly { .. }))
            && skip_ticker.is_some()
        {
            1
        } else {
            0
        };
    while generated < events {
        let draw = generated - initial_generated;
        let index = if role_based {
            let use_hot = exact_targets.as_ref().is_some_and(|targets| targets[draw])
                || exact_targets.is_none()
                    && rng.below(100) < u64::from(config.hot_event_share_pct.min(100));
            if use_hot {
                hot_indices[rng.below_usize(hot_indices.len())]
            } else {
                cold_indices[rng.below_usize(cold_indices.len())]
            }
        } else if config.hot_pair {
            if rng.below(100) < 80 {
                rng.below_usize(hot_cut)
            } else {
                rng.below_usize(publishable.len())
            }
        } else {
            rng.below_usize(publishable.len())
        };
        if hot.contains(publishable[index]) {
            hot_events = hot_events.saturating_add(1);
        } else {
            cold_events = cold_events.saturating_add(1);
        }
        publish_delta_event(mock, publishable[index], rng);
        generated += 1;
        on_publish(published_base + generated);
    }
    on_publish(published_base + events);
    // Over-application fixture: publish the same logical events again without
    // increasing `generated`. The expected ledger stays correct; a collector
    // that applies both copies exceeds it and must fail two-sided accounting.
    if let Some(FailInject::OverApplication { duplicates }) = config.fail_inject {
        for _ in 0..duplicates {
            if publishable.is_empty() {
                break;
            }
            let index = rng.below_usize(publishable.len());
            publish_delta_event(mock, publishable[index], rng);
        }
    }
    let injected_frames = match config.fail_inject {
        Some(FailInject::DroppedFrames { count }) => count as u64,
        _ => 0,
    };
    let replicas = (config.replicas.max(1)) as u64;
    let unanchored_update = u64::from(matches!(
        config.fail_inject,
        Some(FailInject::UpdateOnly { .. })
    ));
    let expected_applied = (generated as u64)
        .saturating_sub(injected_frames / replicas)
        .saturating_sub(unanchored_update);
    let extra_wire_frames = match config.fail_inject {
        Some(FailInject::OverApplication { duplicates }) => duplicates as u64,
        _ => 0,
    };
    PublishPlan {
        generated,
        hot_events,
        cold_events,
        expected_applied,
        // The barrier waits for every frame published by the fixture. An
        // over-application fixture sets a larger drain target so the run
        // finishes before the ledger measures the excess.
        drain_target: expected_applied.saturating_add(extra_wire_frames),
    }
}

/// Writer-side baseline captured after anchoring and before publishing. The
/// writer must be quiescent (queue drained, message count stable across two
/// polls) so the drain barrier can attribute every later message to the
/// published workload.
#[derive(Debug, Clone, Copy, Default)]
struct DrainBaselines {
    deltas_emitted: f64,
    writer_messages: f64,
    writer_errors: f64,
    suppressed_replica_duplicates: Option<u64>,
    /// Sum of `collector_source_decode_errors` across all sources.
    source_decode_errors: Option<u64>,
    data_frames_received: Option<u64>,
    delta_events_decoded: Option<u64>,
    core_ingress_events: Option<u64>,
    core_delta_events: Option<u64>,
    no_active_source: Option<u64>,
    unknown_symbol: Option<u64>,
    non_live: Option<u64>,
    unassigned_source: Option<u64>,
    invalid_book: Option<u64>,
    shadow_clock_regression: Option<u64>,
    zero_noop: Option<u64>,
    sbe_conversion_failed: Option<u64>,
    writer_delta_admissions: Option<u64>,
    writer_delta_writes: Option<u64>,
}

/// The fixed set of metrics the drain barrier requires. Every field is read
/// explicitly; there is no `unwrap_or(0.0)` on this path.
#[derive(Debug, Clone, Copy)]
struct DrainSample {
    deltas_emitted: f64,
    decoded_delta_events: f64,
    writer_messages: f64,
    writer_queue_depth: f64,
    writer_errors: f64,
}

fn required_drain_sample(sample: &MetricSample) -> Result<DrainSample, String> {
    Ok(DrainSample {
        deltas_emitted: sample.required("collector_deltas_emitted_total")?,
        decoded_delta_events: sample.required("collector_decoded_delta_events_total")?,
        writer_messages: sample.required("collector_writer_messages_total")?,
        writer_queue_depth: sample.required("collector_writer_queue_depth")?,
        writer_errors: sample.required("collector_writer_errors_total")?,
    })
}

/// State of the drain barrier for one scrape.
#[derive(Debug, PartialEq)]
enum BarrierState {
    Satisfied,
    Waiting,
    /// A required metric is absent or malformed. The evidence path is
    /// unavailable; the cell must not report zero and must not certify.
    Unavailable(String),
    /// A counter moved backwards. Distinguishing a reset from absence keeps a
    /// process restart from looking like a slow drain.
    CounterReset(&'static str),
}

fn evaluate_barrier(
    sample: &MetricSample,
    base: &DrainBaselines,
    expected: f64,
    // Wire-frame count the decode and disposition counters must reach. The
    // source counters are per-replica while `expected` is logical, so using
    // the logical count here lets the barrier pass before every replica has
    // decoded its copy (and makes the final sample race the capture).
    expected_frames: f64,
    in_flight: u64,
) -> BarrierState {
    let required = match required_drain_sample(sample) {
        Ok(required) => required,
        Err(error) => return BarrierState::Unavailable(error),
    };
    if required.deltas_emitted < base.deltas_emitted {
        return BarrierState::CounterReset("collector_deltas_emitted_total");
    }
    if required.decoded_delta_events < base.delta_events_decoded.unwrap_or(0) as f64 {
        return BarrierState::CounterReset("collector_decoded_delta_events_total");
    }
    if required.writer_messages < base.writer_messages {
        return BarrierState::CounterReset("collector_writer_messages_total");
    }
    if required.writer_errors < base.writer_errors {
        return BarrierState::CounterReset("collector_writer_errors_total");
    }
    let base_dispositions: u64 = [
        base.deltas_emitted as u64,
        base.suppressed_replica_duplicates.unwrap_or(0),
        base.no_active_source.unwrap_or(0),
        base.unknown_symbol.unwrap_or(0),
        base.non_live.unwrap_or(0),
        base.unassigned_source.unwrap_or(0),
        base.invalid_book.unwrap_or(0),
        base.shadow_clock_regression.unwrap_or(0),
        base.zero_noop.unwrap_or(0),
        base.sbe_conversion_failed.unwrap_or(0),
    ]
    .into_iter()
    .sum();
    let current_dispositions: Option<u64> = [
        "collector_deltas_emitted_total",
        "collector_suppressed_replica_duplicates_total",
        "collector_delta_no_active_source_total",
        "collector_delta_unknown_symbol_total",
        "collector_delta_non_live_total",
        "collector_delta_unassigned_source_total",
        "collector_delta_invalid_book_total",
        "collector_delta_shadow_clock_regression_total",
        "collector_delta_zero_noop_total",
        "collector_delta_sbe_conversion_failed_total",
    ]
    .into_iter()
    .try_fold(0u64, |total, name| {
        let value = match sample.read(name) {
            MetricRead::Present(value) if value >= 0.0 && value.fract() == 0.0 => value as u64,
            _ => 0,
        };
        Some(total.saturating_add(value))
    });
    let dispositions_ready = current_dispositions
        .is_some_and(|current| current >= base_dispositions.saturating_add(expected_frames as u64));
    if in_flight == 0
        && required.deltas_emitted >= base.deltas_emitted + expected
        && required.decoded_delta_events
            >= base.delta_events_decoded.unwrap_or(0) as f64 + expected_frames
        && dispositions_ready
        && required.writer_messages >= base.writer_messages + expected
        && required.writer_queue_depth == 0.0
        && required.writer_errors == base.writer_errors
    {
        BarrierState::Satisfied
    } else {
        BarrierState::Waiting
    }
}

async fn capture_baseline(address: SocketAddr) -> Result<DrainBaselines, String> {
    capture_baseline_until(address, Instant::now() + BASELINE_LIMIT).await
}

async fn capture_baseline_until(
    address: SocketAddr,
    deadline: Instant,
) -> Result<DrainBaselines, String> {
    let mut previous: Option<(f64, f64)> = None;
    let mut last_error = "metrics endpoint unavailable".to_owned();
    loop {
        match scrape_metrics(address).await {
            Some(sample) => match required_drain_sample(&sample) {
                Ok(required) => {
                    if let Some((previous_messages, previous_depth)) = previous
                        && previous_depth == 0.0
                        && required.writer_queue_depth == 0.0
                        && previous_messages == required.writer_messages
                    {
                        return Ok(DrainBaselines {
                            deltas_emitted: required.deltas_emitted,
                            writer_messages: required.writer_messages,
                            writer_errors: required.writer_errors,
                            suppressed_replica_duplicates: sample
                                .count_sum("collector_suppressed_replica_duplicates_total"),
                            source_decode_errors: sample
                                .count_sum("collector_source_decode_errors"),
                            data_frames_received: sample
                                .count_sum("collector_transport_frames_received_total"),
                            delta_events_decoded: sample
                                .count_sum("collector_decoded_delta_events_total"),
                            core_ingress_events: sample
                                .count_sum("collector_core_ingress_events_total"),
                            core_delta_events: sample
                                .count_sum("collector_core_delta_events_total"),
                            no_active_source: sample
                                .count_sum("collector_delta_no_active_source_total"),
                            unknown_symbol: sample
                                .count_sum("collector_delta_unknown_symbol_total"),
                            non_live: sample.count_sum("collector_delta_non_live_total"),
                            unassigned_source: sample
                                .count_sum("collector_delta_unassigned_source_total"),
                            invalid_book: sample.count_sum("collector_delta_invalid_book_total"),
                            shadow_clock_regression: sample
                                .count_sum("collector_delta_shadow_clock_regression_total"),
                            zero_noop: sample.count_sum("collector_delta_zero_noop_total"),
                            sbe_conversion_failed: sample
                                .count_sum("collector_delta_sbe_conversion_failed_total"),
                            writer_delta_admissions: sample
                                .count_sum("collector_writer_delta_admissions_total"),
                            writer_delta_writes: sample
                                .count_sum("collector_writer_delta_messages_total"),
                        });
                    }
                    previous = Some((required.writer_messages, required.writer_queue_depth));
                }
                Err(error) => {
                    previous = None;
                    last_error = error;
                }
            },
            None => {
                previous = None;
                last_error = "metrics endpoint unavailable".to_owned();
            }
        }
        if Instant::now() >= deadline {
            return Err(last_error);
        }
        sleep(METRICS_POLL).await;
    }
}

/// Outcome of one drain barrier invocation. `completed` is false on a timeout,
/// unavailable evidence or a counter reset; `detail` and `evidence_error`
/// attribute the reason.
struct DrainResult {
    completed: bool,
    detail: Option<String>,
    evidence_error: Option<String>,
    last_deltas: Option<f64>,
}

/// Cumulative counts a phase drain barrier must reach. Grouping them keeps
/// `await_drain` within the argument-count lint while preserving every
/// independent evidence condition.
struct DrainTargets {
    /// Logical/wire-frame count the emission and writer counters must reach.
    /// Cumulative across phases: the baseline is captured once, before any
    /// phase, so a later barrier waits for a larger count.
    expected: u64,
    /// Wire-frame count the decode and disposition counters must reach. The
    /// source counters are per-replica while `expected` is logical, so using
    /// the logical count here lets the barrier pass before every replica has
    /// decoded its copy (and makes the final sample race the capture).
    expected_frames: u64,
    /// Absolute minimum decoded-frame total. The mock's send counter leads the
    /// sampled decode counter, so a logical-event barrier alone can pass while
    /// wire frames are still being decoded; requiring this closes that gap.
    min_decoded_frames: u64,
}

/// Wait until every production counter has caught up with `expected` new
/// deltas since `base` and the mock's outbound queue is empty. No fixed sleep
/// is part of the schedule; `METRICS_POLL` is only the observation cadence.
async fn await_drain(
    addr: SocketAddr,
    base: &DrainBaselines,
    targets: &DrainTargets,
    in_flight: impl Fn() -> u64,
    deadline: Instant,
    mut last_deltas: Option<f64>,
) -> DrainResult {
    let mut unavailable: Option<String> = None;
    loop {
        if let Some(sample) = scrape_metrics(addr).await {
            if let MetricRead::Present(deltas) = sample.read("collector_deltas_emitted_total") {
                last_deltas = Some(deltas);
            }
            match evaluate_barrier(
                &sample,
                base,
                targets.expected as f64,
                targets.expected_frames as f64,
                in_flight(),
            ) {
                BarrierState::Satisfied => {
                    let decoded = sample
                        .count("collector_decoded_delta_events_total")
                        .unwrap_or(u64::MAX);
                    if decoded >= targets.min_decoded_frames {
                        return DrainResult {
                            completed: true,
                            detail: None,
                            evidence_error: None,
                            last_deltas,
                        };
                    }
                    unavailable = None;
                }
                BarrierState::Waiting => unavailable = None,
                BarrierState::Unavailable(error) => unavailable = Some(error),
                BarrierState::CounterReset(metric) => {
                    return DrainResult {
                        completed: false,
                        detail: Some(format!("counter `{metric}` moved backwards during the run")),
                        evidence_error: Some("counter_reset".to_owned()),
                        last_deltas,
                    };
                }
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        sleep(METRICS_POLL).await;
    }
    let (detail, evidence_error) = match unavailable {
        Some(error) => (Some(error), Some("drain_metrics_unavailable".to_owned())),
        None => (
            Some("drain deadline exceeded before every frame was accounted for".to_owned()),
            None,
        ),
    };
    DrainResult {
        completed: false,
        detail,
        evidence_error,
        last_deltas,
    }
}

pub async fn run_cell(
    directory: &Path,
    config: &CellConfig,
    manifest_out: Option<&Path>,
) -> CellOutcome {
    let outcome = run_cell_inner(directory, config).await;
    finalize_outcome(outcome, config, manifest_out)
}

/// The filename carries a filesystem-safe summary; the exact verdict stays in
/// the body and in the index entry.
fn cell_id_for(outcome: &CellOutcome, config: &CellConfig) -> String {
    if outcome.acceptance.valid {
        // Burst cells get a profile-specific ID so two profiles with the same
        // seed and universe cannot overwrite one another in the index.
        let shape = if let Some(burst) = config.burst {
            burst.label().to_owned()
        } else if config.hot_fraction_ppm > 0 {
            "hotquiet".to_owned()
        } else if config.hot_pair {
            "zipf".to_owned()
        } else {
            "uniform".to_owned()
        };
        let lifecycle = if config.lifecycle_scenario == LifecycleScenario::None {
            String::new()
        } else {
            format!("-lifecycle-{}", config.lifecycle_scenario.as_str())
        };
        let suffix = if SCENARIO_VERSION > 2 {
            format!("{shape}{lifecycle}-v{SCENARIO_VERSION}")
        } else {
            format!("{shape}{lifecycle}")
        };
        return format!("seed-{:04x}-{}-{suffix}", config.seed, config.symbols);
    }
    let class = outcome
        .acceptance
        .failure_class
        .as_deref()
        .unwrap_or("unknown");
    let summary: String = class
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect();
    let status = if SCENARIO_VERSION > 2 {
        format!("{}-v{}", outcome.acceptance.status(), SCENARIO_VERSION)
    } else {
        outcome.acceptance.status().to_owned()
    };
    format!(
        "{status}-seed-{:04x}-{}-{summary}",
        config.seed, config.symbols
    )
}

/// Validate the manifest contract, then publish. A success verdict is only
/// kept when every required field is present; a missing field converts the
/// verdict to `manifest_incomplete` and the artifact records that failure.
fn finalize_outcome(
    outcome: CellOutcome,
    config: &CellConfig,
    manifest_out: Option<&Path>,
) -> CellOutcome {
    let cell_id = cell_id_for(&outcome, config);
    let document = build_cell_manifest(&outcome, config, &cell_id);

    if outcome.acceptance.valid {
        let mut missing = super::manifest::missing_required_fields(&document);
        missing.extend(super::backpressure::missing_required_fields(
            config, &document,
        ));
        if !missing.is_empty() {
            let mut reasons = vec!["manifest_incomplete".to_owned()];
            reasons.extend(
                missing
                    .into_iter()
                    .map(|path| format!("missing_field: {path}")),
            );
            let failed = CellOutcome {
                output: outcome.output,
                provenance: outcome.provenance,
                acceptance: CellAcceptance::from_reasons(reasons),
            };
            let failed_id = cell_id_for(&failed, config);
            let failed_document = build_cell_manifest(&failed, config, &failed_id);
            return publish(failed, config, manifest_out, &failed_id, failed_document);
        }
    }
    publish(outcome, config, manifest_out, &cell_id, document)
}

/// Publish index-first through [`super::manifest::publish_cell`]. Recovery of
/// an interrupted earlier attempt runs before the new publication, so a
/// pending entry never survives into the next cell's view of the index.
fn publish(
    outcome: CellOutcome,
    config: &CellConfig,
    manifest_out: Option<&Path>,
    cell_id: &str,
    document: Map<String, Value>,
) -> CellOutcome {
    let Some(out_dir) = manifest_out else {
        return outcome;
    };
    let index_path = out_dir.join("index.json");
    if let Err(error) = super::manifest::recover(&index_path) {
        return with_manifest_failure(outcome, "manifest_index_error", &error);
    }
    let entry = json!({
        "run_status": outcome.acceptance.status(),
        "seed": config.seed,
        "symbols": config.symbols,
    });
    let entry = match entry {
        Value::Object(entry) => entry,
        _ => Map::new(),
    };
    match super::manifest::publish_cell(&index_path, cell_id, entry, &Value::Object(document)) {
        Ok(()) => outcome,
        Err(super::manifest::PublishError::Index { source }) => {
            with_manifest_failure(outcome, "manifest_index_error", &source)
        }
        Err(super::manifest::PublishError::Body { source }) => {
            with_manifest_failure(outcome, "manifest_write_error", &source)
        }
        Err(super::manifest::PublishError::Serialize { source }) => {
            with_manifest_failure(outcome, "manifest_serialize_error", &source)
        }
    }
}

fn with_manifest_failure(
    outcome: CellOutcome,
    class: &str,
    error: &dyn std::fmt::Display,
) -> CellOutcome {
    CellOutcome {
        output: outcome.output,
        provenance: outcome.provenance,
        acceptance: CellAcceptance::from_reasons(vec![class.to_owned(), format!("{error}")]),
    }
}

/// An aborted cell still gets a boundary-specific failure class. The primary
/// collector error is kept in the reason list, but a declared backpressure
/// profile leads so the manifest names the failed boundary.
fn abort_reasons(reasons: Vec<String>, config: &CellConfig) -> Vec<String> {
    let mut classified = super::backpressure::acceptance_reasons(
        config,
        &super::backpressure::BackpressureObservation::default(),
        None,
    );
    classified.extend(reasons);
    classified
}

/// Scrape one plain counter. Missing or malformed evidence stays `None`.
async fn scrape_count(address: Option<SocketAddr>, name: &str) -> Option<u64> {
    scrape_metrics(address?).await?.count(name)
}

/// Apply one driven fault step to the loopback mock. Every mock action is a
/// deterministic consequence of the explicit step type; nothing is chosen at
/// random during the run.
fn apply_fault_step(mock: &MockKalshi, step: &FaultStep) -> Option<usize> {
    use super::faults::FaultType;

    // A step that is not the deliberate outage always re-enables replacements
    // first, so a recovery storm can progress past an earlier timeout step.
    if step.fault_type != FaultType::RejectReconnect {
        mock.state().set_reject_connections(false);
    }
    match step.fault_type {
        FaultType::ReplicaLoss => {
            let ids = mock.state().book_connection_ids();
            let chosen = match step.connection_ordinal {
                Some(super::faults::ConnectionOrdinal::First) => ids.first().copied(),
                Some(super::faults::ConnectionOrdinal::Last) => ids.last().copied(),
                None => None,
            };
            chosen.and_then(|id| mock.state().close_book_connection(id).then_some(id))
        }
        FaultType::BothReplicasLost => {
            mock.state().close_book_connections();
            None
        }
        FaultType::AllConnectionsLost => {
            mock.state().close_all_connections();
            None
        }
        FaultType::RejectReconnect => {
            mock.state().close_book_connections();
            mock.state().set_reject_connections(true);
            None
        }
        FaultType::ReferenceOnly => None,
    }
}

/// Execute the deterministic fault schedule between anchoring and workload
/// publication. Each step is timed from anchor completion and measured as
/// incident detection -> valid re-anchor using the existing production
/// counters; a socket reconnect alone never counts as recovery.
async fn execute_fault_schedule(
    mock: &MockKalshi,
    schedule: &FaultSchedule,
    metrics_addr: Option<SocketAddr>,
    eligible_count: usize,
    anchor_start: Instant,
) -> Vec<RecoveryEvidence> {
    let mut evidence = Vec::new();
    let steps = schedule.driven_steps();
    let step_count = steps.len();
    for (index, step) in steps.into_iter().enumerate() {
        let planned = Duration::from_millis(step.failure_time_ms);
        if let Some(wait) = planned.checked_sub(anchor_start.elapsed()) {
            sleep(wait).await;
        }
        let closed_connection = apply_fault_step(mock, step);
        let mut outcome = RecoveryEvidence {
            fault_id: step.fault_id.as_str().to_owned(),
            observed_epoch: closed_connection,
            incidents_before: scrape_count(metrics_addr, "collector_discontinuity_incidents_total")
                .await,
            failover_snapshots_before: scrape_count(
                metrics_addr,
                "collector_failover_snapshots_total",
            )
            .await,
            ..RecoveryEvidence::default()
        };
        let deadline = Instant::now() + Duration::from_millis(step.deadline_ms.unwrap_or(0));
        let mut detected: Option<u64> = None;
        let mut reanchored: Option<u64> = None;
        loop {
            if let Some(addr) = metrics_addr
                && let Some(sample) = scrape_metrics(addr).await
            {
                let now_ms = anchor_start.elapsed().as_millis() as u64;
                let incidents = sample.count("collector_discontinuity_incidents_total");
                let failover = sample.count("collector_failover_snapshots_total");
                let resyncing = sample.count("collector_symbols_resyncing").unwrap_or(0);
                let anchored = sample.count("collector_symbols_anchored").unwrap_or(0);
                let incident_grew = match (outcome.incidents_before, incidents) {
                    (Some(before), Some(now)) => now > before,
                    _ => false,
                };
                let failover_grew = match (outcome.failover_snapshots_before, failover) {
                    (Some(before), Some(now)) => now > before,
                    _ => false,
                };
                if detected.is_none() && (incident_grew || resyncing > 0) {
                    detected = Some(now_ms);
                }
                if detected.is_some()
                    && reanchored.is_none()
                    && failover_grew
                    && resyncing == 0
                    && anchored >= eligible_count as u64
                {
                    reanchored = Some(now_ms);
                }
                outcome.incidents_after = incidents;
                outcome.failover_snapshots_after = failover;
            }
            if reanchored.is_some() || Instant::now() >= deadline {
                break;
            }
            sleep(METRICS_POLL).await;
        }
        outcome.connections_after = Some(mock.state().ws_connections());
        outcome.detected_at_ms = detected;
        outcome.reanchored_at_ms = reanchored;
        outcome.duration_ms = detected
            .zip(reanchored)
            .map(|(start, end)| end.saturating_sub(start));
        if outcome.duration_ms.is_none() {
            outcome.duration_unavailable_reason = Some(
                "valid re-anchor (failover snapshot + zero resyncing) not observed within the \
                 step deadline at the 25 ms metrics poll"
                    .to_owned(),
            );
        }
        evidence.push(outcome);
        // Let the collector settle before the next fault. Without this gap a
        // later step can close sockets that are still reconnecting, so no new
        // incident is recorded and recovery cannot be measured.
        if index + 1 < step_count {
            sleep(Duration::from_millis(200)).await;
        }
    }
    // The mock is per-cell, so a latched outage (D8) is left set
    // for the rest of this run. Every non-reject step clears it before acting.
    evidence
}

async fn run_cell_inner(directory: &Path, config: &CellConfig) -> CellOutcome {
    // Worktree provenance is captured before anything else runs so it
    // describes the state executed by the cell.
    let (provenance, preflight_error) = worktree_preflight(config);
    if let Some(reason) = preflight_error {
        return CellOutcome {
            output: None,
            provenance: Some(provenance),
            acceptance: CellAcceptance::from_reasons(vec![reason]),
        };
    }

    let universe =
        SyntheticUniverse::generate(config.seed, config.symbols, config.decoy_fraction_ppm);
    let eligible = universe.eligible_tickers_sorted();
    let hot = universe.hot_tickers(config.hot_fraction_ppm);
    let lifecycle_schedule = LifecycleSchedule::build(
        config.lifecycle_scenario,
        config.seed,
        &eligible,
        config.events,
    );
    // Deltas never target a ticker that is retired during this cell, so every
    // published delta remains attributable to a live, anchored book.
    let all_retired: BTreeSet<String> = lifecycle_schedule
        .events
        .iter()
        .filter(|event| event.catalog_effect == CatalogEffect::Retire)
        .map(|event| event.ticker.clone())
        .collect();
    let delta_tickers: Vec<String> = eligible
        .iter()
        .filter(|ticker| !all_retired.contains(*ticker))
        .cloned()
        .collect();
    let mock = MockKalshi::start(universe).await;
    // A reconnect legitimately re-sends one snapshot per instrument on every
    // socket, and a capacity stage's initial snapshot burst scales with the
    // instrument count. The default per-connection mock queue (4096 frames) is
    // sized for the 4k smoke cell; at 10k+ it would manufacture harness-side
    // drops before the collector ever sees a frame. Size the *same* bounded
    // queue for the larger demand so a recovery or snapshot burst is absorbed
    // instead of being misclassified as a throughput fault; the saturation
    // fixture still uses the production default.
    let fault_capacity = config.fault_schedule.is_some().then_some(65_536);
    let stage_capacity = config
        .capacity
        .map(|spec| spec.stage.symbols.saturating_add(4096));
    let outbound_capacity = fault_capacity
        .into_iter()
        .chain(stage_capacity)
        .max()
        .unwrap_or(0);
    if outbound_capacity > 0 {
        mock.state().set_outbound_capacity(outbound_capacity);
    }
    let mut seed_rng = SplitMix64::new(config.seed ^ 0x51E5_ED5E_ED5E_0001);
    for market in mock.state().universe().markets.iter() {
        mock.state().seed_book(&market.ticker, &mut seed_rng);
    }
    apply_failure_injection(&mock, config, &eligible);
    // An added instrument is placed in the startup catalog when the scenario
    // calls for one. The lifecycle `created` event still exercises the channel,
    // while bootstrap discovery anchors the new market without an in-flight
    // reconciliation overlapping later churn.
    if lifecycle_schedule.events.iter().any(|event| {
        event.catalog_effect == CatalogEffect::Add
            && lifecycle_schedule.added_ticker.as_ref() == Some(&event.ticker)
    }) && let Some(record) = lifecycle_schedule.added_record()
    {
        mock.state().add_market(record);
    }

    let settings = settings_for(&mock, directory, config);
    let metrics_addr = settings.metrics.listen;
    let done = Arc::new(Notify::new());
    let done_for_run = Arc::clone(&done);
    let anchor_timeout = config
        .limits
        .map(|(anchor, _)| anchor)
        .unwrap_or(ANCHOR_LIMIT.as_secs());
    let drain_timeout = config
        .limits
        .map(|(_, drain)| drain)
        .unwrap_or(DRAIN_LIMIT.as_secs());
    let anchor_limit = Duration::from_secs(anchor_timeout);
    let drain_limit = Duration::from_secs(drain_timeout);
    let mut handle = tokio::spawn(coordinator::run_with_shutdown(settings, async move {
        tokio::select! {
            _ = done_for_run.notified() => "stress scenario complete".to_owned(),
            _ = sleep(Duration::from_secs(120)) => "stress scenario safety timeout".to_owned(),
        }
    }));

    // Wait until every eligible symbol has an anchored book. A collector that
    // terminates before anchoring is detected immediately so the failure
    // manifest names the real cause. A plateau below the target (the
    // missing-anchor injections) short-circuits the wait; the hard deadline
    // remains the backstop.
    let anchor_start = Instant::now();
    let mut anchor_wait_expired = true;
    let mut anchor_plateau = false;
    let mut last_anchored = 0.0f64;
    let mut last_progress = Instant::now();
    loop {
        if handle.is_finished() {
            let outcome = (&mut handle)
                .await
                .unwrap_or_else(|error| Err(anyhow::anyhow!("collector task failed: {error}")));
            let reason = match outcome {
                Ok(_report) => "collector_terminated_before_anchor".to_owned(),
                Err(error) => format!("collector_terminated_early: {error:#}"),
            };
            return CellOutcome {
                output: None,
                provenance: Some(provenance),
                acceptance: CellAcceptance::from_reasons(abort_reasons(vec![reason], config)),
            };
        }
        if let Some(addr) = metrics_addr
            && let Some(value) = scrape_metric(addr, "collector_symbols_anchored").await
        {
            let lifecycle_ready = config.lifecycle_scenario == LifecycleScenario::None
                || mock.state().lifecycle_subscribed_count() >= config.lifecycle_replicas;
            if value >= eligible.len() as f64 && lifecycle_ready {
                anchor_wait_expired = false;
                break;
            }
            if value > last_anchored {
                last_anchored = value;
                last_progress = Instant::now();
            } else if value > 0.0 && last_progress.elapsed() >= ANCHOR_PLATEAU {
                anchor_plateau = true;
                break;
            }
        }
        if anchor_start.elapsed() >= anchor_limit {
            break;
        }
        sleep(METRICS_POLL).await;
    }
    let anchored_time = anchor_start.elapsed();

    // Writer-side baseline: the writer must be quiescent before the workload
    // is offered so the drain barrier can attribute every message. A missing
    // or malformed mandatory metric is an evidence failure, not a zero.
    let mut baseline_error: Option<String> = None;
    let baseline = if matches!(config.fail_inject, Some(FailInject::ShutdownBeforeDrain)) {
        None
    } else {
        match metrics_addr {
            Some(addr) => match capture_baseline(addr).await {
                Ok(baseline) => Some(baseline),
                Err(error) => {
                    baseline_error = Some(error);
                    None
                }
            },
            None => {
                baseline_error = Some("metrics endpoint is not configured".to_owned());
                None
            }
        }
    };
    // Wire-frame baseline for the decoded-catch-up condition below. The mock
    // increments its send counter synchronously, while the collector's decoded
    // total is refreshed from worker status; the latter can briefly lag even
    // after every logical delta has been applied.
    let baseline_transmitted_deltas = mock.state().ledger_snapshot().deltas_sent;

    // Build the explicit schedule before publishing. Phase event counts are
    // the primary schedule definition: no sleeps or timing instrumentation.
    let schedule = build_schedule(config, Some(canonical_set_sha256(&hot)));

    // Deterministic disconnect sweep: faults happen after anchoring and before
    // the workload so every delta is offered to a fully re-anchored collector.
    // A fault that cannot re-anchor leaves resyncing symbols and the drain
    // barrier below refuses to certify the run.
    let recovery = if let Some(schedule) = &config.fault_schedule {
        let evidence =
            execute_fault_schedule(&mock, schedule, metrics_addr, eligible.len(), anchor_start)
                .await;
        // Let the collector settle before publishing: all replacement sockets
        // must be subscribed, all books anchored and the writer quiescent. The
        // drain barrier then attributes every later delta to the workload.
        let deadline = Instant::now() + Duration::from_secs(10);
        let expected_books = config.replicas;
        let mut last_book_ids: Vec<usize> = Vec::new();
        let mut stable_since: Option<Instant> = None;
        loop {
            let book_ids = mock.state().book_connection_ids();
            let topology_stable = book_ids.len() == expected_books && book_ids == last_book_ids;
            stable_since = if topology_stable {
                Some(stable_since.unwrap_or_else(Instant::now))
            } else {
                None
            };
            last_book_ids = book_ids;
            let mut settled = !mock.state().is_rejecting_connections()
                && mock.state().in_flight() == 0
                && stable_since.is_some_and(|since| since.elapsed() >= Duration::from_millis(500));
            if let Some(addr) = metrics_addr
                && let Some(sample) = scrape_metrics(addr).await
            {
                let resyncing = sample.count("collector_symbols_resyncing").unwrap_or(0);
                let anchored = sample.count("collector_symbols_anchored").unwrap_or(0);
                let depth = sample.count("collector_writer_queue_depth").unwrap_or(1);
                settled &= resyncing == 0 && anchored >= eligible.len() as u64 && depth == 0;
            }
            if settled || Instant::now() >= deadline {
                break;
            }
            sleep(METRICS_POLL).await;
        }
        evidence
    } else {
        Vec::new()
    };

    // Publish the synthetic workload and derive what *must* be applied. The
    // lifecycle callback applies each catalog mutation immediately before its
    // wire event, then publishes the event with its pinned venue timestamp.
    let skip_ticker = skip_target(config, &eligible);
    // Lifecycle churn: the callback applies each catalog mutation immediately
    // before its wire event, then publishes the event with its pinned venue
    // timestamp. `published` is the cumulative logical-delta count so far, so
    // events pinned to a phase boundary fire exactly once across all phases.
    let mut next_lifecycle_event = 0usize;
    let mut lifecycle_sent_frames = 0u64;
    let added_record = lifecycle_schedule.added_record();
    let phase_zero_count = lifecycle_schedule
        .events
        .iter()
        .filter(|event| event.after_deltas == 0)
        .count();
    let mut lifecycle_publisher = |published: usize| {
        while next_lifecycle_event < lifecycle_schedule.events.len()
            && lifecycle_schedule.events[next_lifecycle_event].after_deltas <= published
        {
            let event = &lifecycle_schedule.events[next_lifecycle_event];
            match event.catalog_effect {
                CatalogEffect::None => {}
                CatalogEffect::Retire => mock.state().retire_market(&event.ticker),
                CatalogEffect::Add => {
                    if mock.state().market_index(&event.ticker).is_some() {
                        mock.state().restore_market(&event.ticker);
                    } else if let Some(record) = &added_record
                        && record["ticker"].as_str() == Some(event.ticker.as_str())
                    {
                        mock.state().add_market(record.clone());
                    }
                }
            }
            mock.state().publish_lifecycle_at(
                event.exchange_ts_ms,
                event.event_type,
                &event.ticker,
                event.extra.clone(),
            );
            lifecycle_sent_frames += config.lifecycle_replicas.max(1) as u64;
            next_lifecycle_event += 1;
        }
    };

    // Phase-zero events (normally an add) are published before any delta and
    // their discovery round is allowed to finish. Otherwise a round started
    // before a later retirement can finish after it and re-add the market:
    // venue timestamps from a mock in the past cannot veto a local round.
    lifecycle_publisher(0);
    if config.lifecycle_scenario != LifecycleScenario::None && phase_zero_count > 0 {
        let published = &lifecycle_schedule.events[..phase_zero_count];
        let expected_active = (eligible.len() as i64
            + published
                .iter()
                .filter(|event| event.catalog_effect == CatalogEffect::Add)
                .count() as i64
            - published
                .iter()
                .filter(|event| event.catalog_effect == CatalogEffect::Retire)
                .count() as i64)
            .max(0) as f64;
        let deadline = Instant::now() + drain_limit;
        loop {
            let active = match metrics_addr {
                Some(addr) => scrape_metric(addr, "collector_symbols_active").await,
                None => None,
            };
            if active == Some(expected_active) {
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            sleep(METRICS_POLL).await;
        }
    }

    // Aggregate plan over all phases. The ledger still reconciles the whole
    // run once, at final, so every existing disposition check is preserved.
    let mut publish_rng = SplitMix64::new(config.seed ^ 0xBEE7_6F00_0D15_EA5E);
    let mut plan = PublishPlan {
        generated: 0,
        hot_events: 0,
        cold_events: 0,
        expected_applied: 0,
        drain_target: 0,
    };
    let mut phase_results: Vec<PhaseOutcome> = Vec::new();
    let mut cumulative_expected = 0u64;
    let mut cumulative_extra_frames = 0u64;
    let mut cumulative_published = 0usize;

    let skip_drain = matches!(config.fail_inject, Some(FailInject::ShutdownBeforeDrain))
        || baseline_error.is_some();
    let mut drain_completed = !skip_drain;
    let mut drain_detail: Option<String> = None;
    let mut drain_evidence_error: Option<String> = None;
    let mut last_deltas = baseline.map(|base| base.deltas_emitted);
    // Transport/decoder aggregates are high-water marks over per-source status
    // values that reset on reconnect. Sampling only the final scrape can miss
    // the peak when a source reconnects late, so keep the runner-observed max.
    let mut max_decoded = baseline.and_then(|base| base.delta_events_decoded);
    let mut max_received = baseline.and_then(|base| base.data_frames_received);
    if matches!(config.fail_inject, Some(FailInject::ShutdownBeforeDrain)) {
        drain_detail = Some("shutdown requested before the drain barrier".to_owned());
    } else if let Some(error) = &baseline_error {
        drain_detail = Some(format!("writer baseline unavailable: {error}"));
        drain_evidence_error = Some("drain_metrics_unavailable".to_owned());
    }

    // Publish each phase, then drain with a cumulative expected count before
    // the next phase begins. The baseline is captured once at the start, so a
    // later barrier waits for every event from all preceding phases plus this
    // one; a burst cannot leave a queue unreconciled into the next phase.
    for phase in &schedule.phases {
        let phase_plan = publish_events(
            &mock,
            &delta_tickers,
            &hot,
            config,
            phase.events,
            &mut publish_rng,
            skip_ticker.as_deref(),
            cumulative_published,
            &mut lifecycle_publisher,
        );
        cumulative_published = cumulative_published.saturating_add(phase_plan.generated);
        plan.generated = plan.generated.saturating_add(phase_plan.generated);
        plan.hot_events = plan.hot_events.saturating_add(phase_plan.hot_events);
        plan.cold_events = plan.cold_events.saturating_add(phase_plan.cold_events);
        plan.expected_applied = plan
            .expected_applied
            .saturating_add(phase_plan.expected_applied);
        cumulative_expected = cumulative_expected.saturating_add(phase_plan.expected_applied);
        cumulative_extra_frames = cumulative_extra_frames.saturating_add(
            phase_plan
                .drain_target
                .saturating_sub(phase_plan.expected_applied),
        );
        let target = cumulative_expected.saturating_add(cumulative_extra_frames);

        let completed = if !skip_drain && let (Some(addr), Some(base)) = (metrics_addr, baseline) {
            let transmitted_now = mock.state().ledger_snapshot().deltas_sent;
            let min_decoded = baseline
                .map(|base| {
                    base.delta_events_decoded
                        .unwrap_or(0)
                        .saturating_add(transmitted_now.saturating_sub(baseline_transmitted_deltas))
                })
                .unwrap_or(0);
            let result = await_drain(
                addr,
                &base,
                &DrainTargets {
                    expected: target,
                    // Per-replica decode/disposition evidence: the mock's send
                    // counter is logical, but the collector counts every replica.
                    expected_frames: target.saturating_mul(config.replicas.max(1) as u64),
                    min_decoded_frames: min_decoded,
                },
                || mock.state().in_flight(),
                Instant::now() + drain_limit,
                last_deltas,
            )
            .await;
            last_deltas = result.last_deltas;
            // M5.4 high-water evidence: transport/decoder aggregates are
            // high-water marks over per-source status values that reset on
            // reconnect. Sample during the active run so a late reconnect
            // cannot hide the peak from the final evidence scrape.
            if let Some(sample) = scrape_metrics(addr).await {
                if let Some(value) = sample.count_sum("collector_decoded_delta_events_total") {
                    max_decoded = Some(max_decoded.map_or(value, |peak| peak.max(value)));
                }
                if let Some(value) = sample.count_sum("collector_transport_frames_received_total") {
                    max_received = Some(max_received.map_or(value, |peak| peak.max(value)));
                }
            }
            if !result.completed && drain_detail.is_none() {
                drain_detail = result.detail;
                drain_evidence_error = result.evidence_error;
            }
            result.completed
        } else {
            false
        };
        drain_completed &= completed;
        phase_results.push(PhaseOutcome {
            name: phase.name,
            published: phase_plan.generated,
            cumulative_expected: target,
            drain_completed: completed,
        });
    }
    plan.drain_target = cumulative_expected.saturating_add(cumulative_extra_frames);

    // Lifecycle delivery barrier: every non-terminal notification must be
    // written to each lifecycle replica and the active-symbol gauge must reach
    // the final epoch's expected set. Metadata-only events are confirmed later
    // from the run report's lifecycle counters, not inferred here.
    let mut lifecycle_barrier_completed = config.lifecycle_scenario == LifecycleScenario::None;
    let mut lifecycle_barrier_detail: Option<String> = None;
    if !lifecycle_barrier_completed {
        let deadline = Instant::now() + drain_limit;
        let pre_drain: Vec<_> = lifecycle_schedule
            .events
            .iter()
            .filter(|event| event.after_deltas != usize::MAX)
            .collect();
        let expected_active = (eligible.len() as i64
            + pre_drain
                .iter()
                .filter(|event| event.catalog_effect == CatalogEffect::Add)
                .count() as i64
            - pre_drain
                .iter()
                .filter(|event| event.catalog_effect == CatalogEffect::Retire)
                .count() as i64)
            .max(0) as f64;
        let expected_wire = pre_drain.len() as u64 * config.lifecycle_replicas.max(1) as u64;
        loop {
            let sent = mock.state().ledger_snapshot().lifecycle_sent;
            let active = match metrics_addr {
                Some(addr) => scrape_metric(addr, "collector_symbols_active").await,
                None => None,
            };
            if sent >= expected_wire && active == Some(expected_active) {
                lifecycle_barrier_completed = true;
                break;
            }
            if Instant::now() >= deadline {
                lifecycle_barrier_detail = Some(format!(
                    "lifecycle barrier: wire={sent}/{expected_wire}, active={active:?}/{expected_active}"
                ));
                break;
            }
            sleep(METRICS_POLL).await;
        }
    }

    // The decoder counter is derived from per-source status values at the
    // metrics registry's refresh cadence, so it can briefly lag the applied
    // and wire counters after the drain barrier passes. Sample until the
    // settled values agree before taking the final evidence snapshot; this
    // keeps a refresh edge from looking like a disposition or transmit/decode
    // defect. Failure fixtures consume the bounded wait and are
    // still evaluated on their real evidence below.
    if !matches!(config.fail_inject, Some(FailInject::ShutdownBeforeDrain)) {
        let settle_deadline = Instant::now() + Duration::from_secs(3);
        let mut previous: Option<(u64, u64)> = None;
        loop {
            let sample = match metrics_addr {
                Some(addr) => scrape_metrics(addr).await,
                None => None,
            };
            let decoded = sample
                .as_ref()
                .and_then(|sample| sample.count_sum("collector_decoded_delta_events_total"));
            let applied = sample
                .as_ref()
                .and_then(|sample| sample.count("collector_deltas_emitted_total"));
            let transmitted = mock.state().ledger_snapshot().deltas_sent;
            let stable = previous.is_some_and(|(before_decoded, before_transmitted)| {
                Some(before_decoded) == decoded && before_transmitted == transmitted
            });
            let settled = matches!((decoded, applied), (Some(decoded), Some(applied))
                if decoded >= applied && decoded >= transmitted)
                && stable;
            if settled || Instant::now() >= settle_deadline {
                break;
            }
            if let (Some(decoded), Some(_)) = (decoded, applied) {
                previous = Some((decoded, transmitted));
            }
            sleep(METRICS_POLL).await;
        }
    }

    // Final scrape before shutdown: applied counter and incident counters.
    let final_sample = match metrics_addr {
        Some(addr) => scrape_metrics(addr).await,
        None => None,
    };
    if let Some(deltas) = final_sample.as_ref().and_then(|sample| {
        match sample.read("collector_deltas_emitted_total") {
            MetricRead::Present(value) => Some(value),
            _ => None,
        }
    }) {
        last_deltas = Some(deltas);
    }
    if let Some(sample) = &final_sample {
        if let Some(value) = sample.count_sum("collector_decoded_delta_events_total") {
            max_decoded = Some(max_decoded.map_or(value, |peak| peak.max(value)));
        }
        if let Some(value) = sample.count_sum("collector_transport_frames_received_total") {
            max_received = Some(max_received.map_or(value, |peak| peak.max(value)));
        }
    }
    let incidents = IncidentCounters {
        discontinuity_incidents: final_sample
            .as_ref()
            .and_then(|sample| sample.count("collector_discontinuity_incidents_total")),
        unquantifiable_gaps: final_sample
            .as_ref()
            .and_then(|sample| sample.count("collector_unquantifiable_gaps_total")),
        suppressed_replica_duplicates: final_sample
            .as_ref()
            .and_then(|sample| sample.count("collector_suppressed_replica_duplicates_total")),
    };

    // Terminal events are published after the delta drain barrier. The
    // coordinator's shutdown drain still applies them, and keeping the
    // retirement outside the workload avoids an in-flight recovery batch that
    // would otherwise ask for snapshots of an already retired instrument.
    if config.lifecycle_scenario != LifecycleScenario::None {
        lifecycle_publisher(usize::MAX);
        let expected_wire =
            lifecycle_schedule.events.len() as u64 * config.lifecycle_replicas.max(1) as u64;
        let final_active = (eligible.len() as i64
            + lifecycle_schedule
                .events
                .iter()
                .map(|event| match event.catalog_effect {
                    crate::stress_support::lifecycle::CatalogEffect::Add => 1,
                    crate::stress_support::lifecycle::CatalogEffect::Retire => -1,
                    crate::stress_support::lifecycle::CatalogEffect::None => 0,
                })
                .sum::<i64>())
        .max(0) as f64;
        let deadline = Instant::now() + drain_limit;
        loop {
            let sent = mock.state().ledger_snapshot().lifecycle_sent;
            let active = match metrics_addr {
                Some(addr) => scrape_metric(addr, "collector_symbols_active").await,
                None => None,
            };
            if sent >= expected_wire && active == Some(final_active) {
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            sleep(METRICS_POLL).await;
        }
    }

    done.notify_one();
    let report = match tokio::time::timeout(FINISH_LIMIT, &mut handle).await {
        Ok(Ok(Ok(report))) => report,
        Ok(Ok(Err(error))) => {
            return CellOutcome {
                output: None,
                provenance: Some(provenance),
                acceptance: CellAcceptance::from_reasons(abort_reasons(
                    vec![format!("collector_task_failed: {error:#}")],
                    config,
                )),
            };
        }
        Ok(Err(error)) => {
            return CellOutcome {
                output: None,
                provenance: Some(provenance),
                acceptance: CellAcceptance::from_reasons(abort_reasons(
                    vec![format!("collector_task_join_failed: {error}")],
                    config,
                )),
            };
        }
        Err(_) => {
            return CellOutcome {
                output: None,
                provenance: Some(provenance),
                acceptance: CellAcceptance::from_reasons(abort_reasons(
                    vec!["collector_did_not_stop_within_limit".to_owned()],
                    config,
                )),
            };
        }
    };

    let capture = PathBuf::from(&report.output_path);
    let metadata_path = directory.join("markets.json");
    let report_path = directory.join("report.json");
    let coverage_result = coverage::run(&capture, &metadata_path, &report_path, "auto");
    let completeness_result = completeness::run(&capture, "auto", false);
    let verify_result = verify::run(&capture, "auto");
    let completeness_valid = completeness_result
        .as_ref()
        .map(|summary| summary.valid)
        .unwrap_or(false);
    let verify_valid = verify_result
        .as_ref()
        .map(|summary| summary.valid)
        .unwrap_or(false);
    let coverage_error = coverage_result.as_ref().err().map(|e| format!("{e:#}"));
    let completeness_error = completeness_result.as_ref().err().map(|e| format!("{e:#}"));
    let verify_error = verify_result.as_ref().err().map(|e| format!("{e:#}"));

    // Decode the capture for the observed (any message) and snapshot-anchored
    // symbol sets, mirroring the definitions in `coverage.rs`.
    let mut observed = BTreeSet::new();
    let mut anchored = BTreeSet::new();
    let mut sbe_deltas = 0u64;
    let mut sbe_snapshots = 0u64;
    let mut sbe_messages = 0u64;
    let scan = (|| -> anyhow::Result<()> {
        use fieldbook::util::AlignedSbeReader;
        use fieldbook::util::OrderbookSchema;
        use fieldbook::util::dtos::orderbook::AnyMessage;
        let mut reader = AlignedSbeReader::<OrderbookSchema>::open_auto(&capture)?;
        while let Some(message) = reader.read_msg()? {
            sbe_messages += 1;
            match message {
                AnyMessage::Snapshot(decoder) => {
                    sbe_snapshots += 1;
                    let snapshot =
                        fieldbook::util::dtos::orderbook::SnapshotDomain::try_from_decoder(
                            decoder,
                        )?;
                    observed.insert(snapshot.symbol.clone());
                    anchored.insert(snapshot.symbol);
                }
                AnyMessage::PriceLevelUpdate(decoder) => {
                    sbe_deltas += 1;
                    let update =
                        fieldbook::util::dtos::orderbook::PriceLevelUpdateDomain::try_from_decoder(
                            decoder,
                        )?;
                    observed.insert(update.symbol);
                }
                AnyMessage::Unknown { .. } => {}
                _ => {}
            }
        }
        Ok(())
    })();
    let sbe_scan_ok = scan.is_ok();
    let sbe_scan_error = scan.as_ref().err().map(|e| format!("{e:#}"));

    let decoy_absent = mock
        .state()
        .universe()
        .excluded_tickers_sorted()
        .iter()
        .all(|ticker| !observed.contains(ticker));

    let journal_enabled = report.journal.is_some();
    let journal_complete = if journal_enabled {
        report
            .journal_verification
            .as_ref()
            .map(|verification| verification.complete)
            .unwrap_or(false)
    } else {
        true
    };
    let journaled_records = if journal_enabled {
        report
            .journal_verification
            .as_ref()
            .map(|verification| verification.record_count)
    } else {
        None
    };

    // Event accounting: derived from the publish plan, the mock ledger, the
    // collector's metric counters and the decoded capture. No count is
    // hard-coded to success.
    let transmit = mock.state().ledger_snapshot();
    let applied_events = match (baseline, last_deltas) {
        (Some(base), Some(final_deltas)) => {
            Some(((final_deltas - base.deltas_emitted).max(0.0)) as u64)
        }
        _ => None,
    };
    let sbe_deltas_observed = if sbe_scan_ok { Some(sbe_deltas) } else { None };
    let final_count = |name: &str| -> Option<u64> {
        final_sample
            .as_ref()
            .and_then(|sample| sample.count_sum(name))
    };
    let received_frames = match baseline {
        Some(base) => metric_window_delta(base.data_frames_received, max_received),
        None => None,
    };
    let delta_events_decoded = match baseline {
        Some(base) => metric_window_delta(base.delta_events_decoded, max_decoded),
        None => None,
    };
    let decode_errors = match &baseline {
        Some(base) => metric_window_delta(
            base.source_decode_errors,
            final_count("collector_source_decode_errors"),
        ),
        None => None,
    };
    // Core-ingress counters are sampled separately and are never presented as
    // transport or decoder evidence.
    let core_ingress_events = match &baseline {
        Some(base) => metric_window_delta(
            base.core_ingress_events,
            final_count("collector_core_ingress_events_total"),
        ),
        None => None,
    };
    let core_delta_events = match &baseline {
        Some(base) => metric_window_delta(
            base.core_delta_events,
            final_count("collector_core_delta_events_total"),
        ),
        None => None,
    };
    let no_active_source = match &baseline {
        Some(base) => metric_window_delta(
            base.no_active_source,
            final_count("collector_delta_no_active_source_total"),
        ),
        None => None,
    };
    let unknown_symbol = match &baseline {
        Some(base) => metric_window_delta(
            base.unknown_symbol,
            final_count("collector_delta_unknown_symbol_total"),
        ),
        None => None,
    };
    let non_live = match &baseline {
        Some(base) => {
            metric_window_delta(base.non_live, final_count("collector_delta_non_live_total"))
        }
        None => None,
    };
    let unassigned_source = match &baseline {
        Some(base) => metric_window_delta(
            base.unassigned_source,
            final_count("collector_delta_unassigned_source_total"),
        ),
        None => None,
    };
    let invalid_book = match &baseline {
        Some(base) => metric_window_delta(
            base.invalid_book,
            final_count("collector_delta_invalid_book_total"),
        ),
        None => None,
    };
    let shadow_clock_regression = match &baseline {
        Some(base) => metric_window_delta(
            base.shadow_clock_regression,
            final_count("collector_delta_shadow_clock_regression_total"),
        ),
        None => None,
    };
    let zero_noop = match &baseline {
        Some(base) => metric_window_delta(
            base.zero_noop,
            final_count("collector_delta_zero_noop_total"),
        ),
        None => None,
    };
    let sbe_conversion_failed = match &baseline {
        Some(base) => metric_window_delta(
            base.sbe_conversion_failed,
            final_count("collector_delta_sbe_conversion_failed_total"),
        ),
        None => None,
    };
    let writer_delta_admissions = match &baseline {
        Some(base) => metric_window_delta(
            base.writer_delta_admissions,
            final_count("collector_writer_delta_admissions_total"),
        ),
        None => None,
    };
    let writer_delta_writes = match &baseline {
        Some(base) => metric_window_delta(
            base.writer_delta_writes,
            final_count("collector_writer_delta_messages_total"),
        ),
        None => None,
    };
    let enqueued_deltas = Some(transmit.enqueued_deltas);
    let transmitted_deltas = Some(transmit.deltas_sent);
    let (enqueue_transmit_shortfall, enqueue_transmit_excess) =
        two_sided(enqueued_deltas, transmitted_deltas);
    let (transmit_decode_shortfall, transmit_decode_excess) =
        transmit_decode_gaps(transmitted_deltas, delta_events_decoded);
    let (writer_admission_shortfall, writer_admission_excess) =
        two_sided(applied_events, writer_delta_admissions);
    let (writer_write_shortfall, writer_write_excess) =
        two_sided(writer_delta_admissions, writer_delta_writes);
    // Every decoded delta must have exactly one terminal disposition.
    let disposition_total = [
        applied_events,
        incidents.suppressed_replica_duplicates,
        no_active_source,
        unknown_symbol,
        non_live,
        unassigned_source,
        invalid_book,
        shadow_clock_regression,
        zero_noop,
        sbe_conversion_failed,
    ]
    .into_iter()
    .collect::<Option<Vec<u64>>>()
    .map(|values| values.into_iter().sum());
    let (disposition_shortfall, disposition_excess) =
        two_sided(delta_events_decoded, disposition_total);
    let ledger = EventLedger {
        generated_events: plan.generated as u64,
        expected_applied: plan.expected_applied,
        applied_events,
        enqueued_deltas,
        transmitted_deltas,
        received_frames,
        delta_events_decoded,
        decode_errors,
        core_ingress_events,
        core_delta_events,
        no_active_source,
        unknown_symbol,
        non_live,
        unassigned_source,
        invalid_book,
        shadow_clock_regression,
        zero_noop,
        sbe_conversion_failed,
        disposition_shortfall,
        disposition_excess,
        writer_delta_admissions,
        writer_delta_writes,
        sbe_deltas: sbe_deltas_observed,
        journaled_records,
        injected_pre_wire_drops: transmit.injected_pre_wire_drops,
        suppressed_replica_duplicates: incidents.suppressed_replica_duplicates,
        unexplained_drops: applied_events
            .map(|applied| (plan.generated as u64).saturating_sub(applied)),
        application_shortfall: applied_events
            .map(|applied| plan.expected_applied.saturating_sub(applied)),
        over_applied: applied_events.map(|applied| applied.saturating_sub(plan.expected_applied)),
        persistence_gap: match (applied_events, sbe_deltas_observed) {
            (Some(applied), Some(sbe)) => Some(applied.saturating_sub(sbe)),
            _ => None,
        },
        persistence_excess: match (applied_events, sbe_deltas_observed) {
            (Some(applied), Some(sbe)) => Some(sbe.saturating_sub(applied)),
            _ => None,
        },
        enqueue_transmit_shortfall,
        enqueue_transmit_excess,
        transmit_decode_shortfall,
        transmit_decode_excess,
        writer_admission_shortfall,
        writer_admission_excess,
        writer_write_shortfall,
        writer_write_excess,
        decode_failure_count: decode_errors,
    };

    // Exact three-way set comparison against the epoch-aware expected universe.
    // For lifecycle cells the expected set is the final epoch, not the startup
    // catalog. Extra anchored symbols are permitted only when the lifecycle
    // schedule retired them: their final empty snapshot is a retirement
    // boundary, not a permanent coverage obligation.
    let expected_set: BTreeSet<String> = if config.lifecycle_scenario == LifecycleScenario::None {
        eligible.iter().cloned().collect()
    } else {
        lifecycle_schedule.final_expected().clone()
    };
    let acknowledged_set: BTreeSet<String> = report.acknowledged_symbols.iter().cloned().collect();
    let anchored_expected: BTreeSet<String> =
        anchored.intersection(&expected_set).cloned().collect();
    let anchored_extras: BTreeSet<String> = anchored.difference(&expected_set).cloned().collect();
    let retired_all: BTreeSet<String> = lifecycle_schedule
        .events
        .iter()
        .filter(|event| event.catalog_effect == CatalogEffect::Retire)
        .map(|event| event.ticker.clone())
        .collect();
    let anchored_extras_ok = if config.lifecycle_scenario == LifecycleScenario::None {
        anchored_extras.is_empty()
    } else {
        anchored_extras.is_subset(&retired_all)
    };
    let set_mismatch = expected_set != acknowledged_set
        || expected_set != anchored_expected
        || !anchored_extras_ok;

    // The report's core counters are the independent application-side witness
    // for the schedule's explicit dedup/ordering expectations.
    let lifecycle_applied = report.core.lifecycle_events;
    let lifecycle_duplicates = report.core.lifecycle_duplicates;
    let lifecycle_stale = report.core.lifecycle_stale_dropped;
    let lifecycle_unknown = report.core.lifecycle_unknown_symbols;
    let lifecycle_vetoes = report.core.lifecycle_discovery_vetoes;
    let lifecycle_counters_ok = lifecycle_applied == lifecycle_schedule.expected_applied()
        && lifecycle_duplicates == lifecycle_schedule.expected_duplicates()
        && lifecycle_stale == lifecycle_schedule.expected_stale();

    let capacity_connections = report
        .capacity
        .as_ref()
        .map(|plan| plan.total_connections)
        .unwrap_or(0);
    let rss_sample = rss_sample_bytes();

    // Compose the acceptance verdict: every condition must pass. Data-integrity
    // reasons come first so `failure_class` names the real cause; timeout
    // observations come last.
    let mut reasons: Vec<String> = Vec::new();
    if set_mismatch {
        reasons.push("coverage_set_mismatch".to_owned());
    }
    if !lifecycle_barrier_completed {
        reasons.push("lifecycle_delivery_incomplete".to_owned());
    }
    if !lifecycle_counters_ok {
        reasons.push("lifecycle_application_mismatch".to_owned());
    }
    match &coverage_result {
        Ok(summary) if summary.valid => {}
        Ok(_) => reasons.push("coverage_invalid".to_owned()),
        Err(_) => reasons.push("coverage_unreadable".to_owned()),
    }
    match &completeness_result {
        Ok(summary) if summary.valid => {}
        Ok(_) => reasons.push("completeness_invalid".to_owned()),
        Err(_) => reasons.push("completeness_unreadable".to_owned()),
    }
    match &verify_result {
        Ok(summary) if summary.valid => {}
        Ok(_) => reasons.push("sbe_invalid".to_owned()),
        Err(_) => reasons.push("sbe_unreadable".to_owned()),
    }
    if !decoy_absent {
        reasons.push("decoy_present".to_owned());
    }
    if !journal_complete {
        reasons.push("journal_incomplete".to_owned());
    }
    reasons.extend(ledger_acceptance_reasons(&ledger, transmit.queue_saturated));
    if let Some(error) = &sbe_scan_error {
        reasons.push(format!("sbe_scan_error: {error}"));
    }
    if anchor_plateau {
        reasons.push("anchor_plateau".to_owned());
    } else if anchor_wait_expired {
        reasons.push("anchor_timeout".to_owned());
    }
    if !drain_completed {
        match &drain_evidence_error {
            Some(class) => reasons.push(class.clone()),
            None => reasons.push("drain_incomplete".to_owned()),
        }
    }

    let output = CellOutput {
        writer_queue_high_water: report.writer.queue_high_water,
        report,
        coverage: coverage_result.ok(),
        coverage_error,
        completeness_error,
        verify_error,
        completeness_valid,
        verify_valid,
        anchored_time,
        harness_process_rss_sample_bytes: rss_sample,
        expected_symbols: expected_set,
        acknowledged_symbols: acknowledged_set,
        observed_symbols: observed,
        anchored_symbols: anchored,
        eligible_count: eligible.len(),
        hot_tickers: hot.len(),
        decoy_absent,
        journal_complete,
        journaled_records,
        transmitted_frames: transmit.sent,
        events_published: plan.generated,
        hot_events: plan.hot_events,
        cold_events: plan.cold_events,
        applied_events,
        capacity_connections,
        anchor_wait_expired,
        drain_completed,
        drain_detail,
        sbe_deltas,
        sbe_snapshots,
        sbe_messages,
        incidents,
        ledger,
        schedule,
        phase_results,
        recovery,
        ws_connections: mock.state().ws_connections(),
        book_subscriptions: mock.state().book_subscribed_count(),
        mock: transmit,
        lifecycle_schedule,
        lifecycle_applied,
        lifecycle_duplicates,
        lifecycle_stale_dropped: lifecycle_stale,
        lifecycle_unknown_symbols: lifecycle_unknown,
        lifecycle_discovery_vetoes: lifecycle_vetoes,
        lifecycle_sent_frames,
        lifecycle_subscribed: mock.state().lifecycle_subscribed_count(),
        lifecycle_barrier_completed,
        lifecycle_barrier_detail,
        anchored_extras_ok,
    };

    // Backpressure evidence is derived after the output exists. A reconciled
    // ledger alone never certifies a bounded-queue boundary. The injected
    // physical boundary is the real cause; collector drain symptoms are
    // downstream effects and must not lead the machine-readable failure class.
    let profile = super::backpressure::BackpressureProfile::from_config(config);
    let observation = super::backpressure::observe(profile.as_ref(), Some(&output));
    let boundary_reasons =
        super::backpressure::acceptance_reasons(config, &observation, Some(&output));
    reasons = order_acceptance_reasons(boundary_reasons, reasons);

    let acceptance = if reasons.is_empty() {
        CellAcceptance::valid()
    } else {
        CellAcceptance::from_reasons(reasons)
    };
    CellOutcome {
        provenance: Some(provenance),
        acceptance,
        output: Some(output),
    }
}

// ---------- manifest writer ----------

/// Canonical set SHA-256 (sorted, newline-separated, trailing newline) — the
/// same definition as `coverage.rs`.
#[must_use]
pub fn canonical_set_sha256(values: &BTreeSet<String>) -> String {
    let mut text = String::new();
    for value in values {
        text.push_str(value);
        text.push('\n');
    }
    sha256_hex(text.as_bytes())
}

/// Manifest view of one universe epoch. Both the expected and the required
/// anchored sets are hashed with the same canonical function as `coverage`, so
/// a reader can compare an epoch's requirement to the certified final set.
fn epoch_json(epoch: &UniverseEpoch) -> Value {
    json!({
        "epoch": epoch.index,
        "label": epoch.label,
        "expected_count": epoch.expected.len(),
        "expected_set_sha256": canonical_set_sha256(&epoch.expected),
        "required_anchored_count": epoch.required_anchors.len(),
        "required_anchored_set_sha256": canonical_set_sha256(&epoch.required_anchors),
        "retired_count": epoch.retired.len(),
        "retired_set_sha256": canonical_set_sha256(&epoch.retired),
        "added_count": epoch.added.len(),
        "added_set_sha256": canonical_set_sha256(&epoch.added),
    })
}

fn harness_binary_sha256() -> Option<String> {
    let path = std::env::current_exe().ok()?;
    fs::read(&path).ok().map(|bytes| sha256_hex(&bytes))
}

/// The build profile of the running harness binary, derived from the actual
/// compilation — never hard-coded.
fn build_profile() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    }
}

fn target_triple() -> String {
    if let Ok(compilation) = std::process::Command::new("rustc").arg("-vV").output() {
        let text = String::from_utf8_lossy(&compilation.stdout);
        if let Some(host) = text.lines().find_map(|line| line.strip_prefix("host: ")) {
            return host.to_owned();
        }
    }
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn run_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    format!("stress-{millis}-{}", std::process::id())
}

fn host_json(host: &HostInfo) -> Value {
    json!({
        "os": host.os.as_deref().map(Value::from).unwrap_or_else(|| super::manifest::unavailable("uname -sr failed")),
        "kernel": host.kernel.as_deref().map(Value::from).unwrap_or_else(|| super::manifest::unavailable("uname -r failed")),
        "cpu_model": host.cpu_model.as_deref().map(Value::from).unwrap_or_else(|| super::manifest::unavailable("cpu model unavailable")),
        "cpu_count": host.cpu_count.map(Value::from).unwrap_or_else(|| super::manifest::unavailable("available_parallelism failed")),
        "ram_mb": host.ram_mb.map(Value::from).unwrap_or_else(|| super::manifest::unavailable("ram unavailable")),
        "fd_limit": host.fd_limit.map(Value::from).unwrap_or_else(|| super::manifest::unavailable("ulimit -n unavailable")),
        "disk_free_bytes": host.disk_free_bytes.map(Value::from).unwrap_or_else(|| super::manifest::unavailable(host.disk_free_reason.clone().unwrap_or_else(|| "df unavailable".to_owned()).as_str())),
        "target_triple": target_triple(),
        "rustc_version": host.rustc_version.as_deref().map(Value::from).unwrap_or_else(|| super::manifest::unavailable("rustc unavailable")),
        "clock_source": host.clock_source.clone().map(Value::from).unwrap_or_else(|| super::manifest::unavailable("clock source unavailable")),
        "clock_resolution_ns": host.clock_resolution_ns.map(Value::from).unwrap_or_else(|| {
            super::manifest::unavailable(
                host.clock_resolution_reason
                    .as_deref()
                    .unwrap_or("clock resolution could not be measured"),
            )
        }),
    })
}

/// Stage-timing evidence for a manifest: raw per-boundary histograms plus the
/// build/environment provenance needed to interpret them. The host clock step
/// is recorded separately from the measured durations: a nanosecond storage
/// unit is not a nanosecond accuracy claim.
fn stage_timing_json(output: Option<&CellOutput>, host: &HostInfo) -> Value {
    let boundaries = output
        .and_then(|output| output.report.stage_timing.as_ref())
        .and_then(|report| serde_json::to_value(report).ok())
        .unwrap_or_else(|| super::manifest::unavailable("run report did not carry stage timing"));
    json!({
        "boundaries": boundaries,
        "duration_unit": "nanoseconds",
        "percentile_method": "nearest_rank_from_merged_bucket_counts",
        "p9999_min_samples": 10_000,
        "resolution_vs_accuracy": "Duration values are stored in nanoseconds, but Instant resolution and scheduling/instrumentation overhead bound real accuracy; see docs/PERFORMANCE_METHODOLOGY.md",
        "provenance": {
            "clock_source": host.clock_source.clone().map(Value::from).unwrap_or_else(|| super::manifest::unavailable("clock source unavailable")),
            "clock_resolution_ns": host.clock_resolution_ns.map(Value::from).unwrap_or_else(|| {
                super::manifest::unavailable(
                    host.clock_resolution_reason
                        .as_deref()
                        .unwrap_or("clock resolution could not be measured"),
                )
            }),
            "build_profile": build_profile(),
            "target_triple": target_triple(),
            "scenario_version": SCENARIO_VERSION,
        },
    })
}

fn provenance_json(provenance: Option<&WorktreeProvenance>) -> Value {
    let Some(provenance) = provenance else {
        return json!({
            "tracked_clean": super::manifest::unavailable("provenance not captured"),
        });
    };
    if let Some(error) = &provenance.error {
        return json!({
            "commit": provenance.commit,
            "tracked_clean": super::manifest::unavailable(error),
            "untracked_file_count": Value::Null,
        });
    }
    json!({
        "commit": provenance.commit,
        "tracked_clean": provenance.tracked_clean,
        "tracked_modified_files": provenance.tracked_modified,
        "tracked_diff_sha256": provenance.tracked_diff_sha256,
        "untracked_file_count": provenance.untracked_count,
        "clean_run_required": require_clean_flag_from_env_note(),
    })
}

/// Whether the *last* preflight enforced cleanliness. The gate itself reads
/// the config/env at run time; manifests only record the environment default.
fn require_clean_flag_from_env_note() -> bool {
    std::env::var("STRESS_REQUIRE_CLEAN").is_ok_and(|v| v == "1")
}

/// Render the explicit workload schedule into its manifest form. Rate fields
/// are declared schedule labels; the document states that explicitly so no
/// reader can mistake them for measured throughput or latency.
fn schedule_json(schedule: &WorkloadSchedule) -> Value {
    json!({
        "workload_id": schedule.workload_id,
        "profile": schedule.profile,
        "seed": schedule.seed,
        "instrument_count": schedule.instrument_count,
        "eligible_count": schedule.eligible_count,
        "hot_set": {
            "fraction_ppm": schedule.hot_set.fraction_ppm,
            "member_count": schedule.hot_set.member_count,
            "selection": schedule.hot_set.selection,
            "event_share_pct": schedule.hot_set.event_share_pct,
            "sha256": schedule.hot_set.sha256,
        },
        "phases": schedule.phases.iter().map(|phase| json!({
            "name": phase.name,
            "events": phase.events,
            "target_rate_per_tick": phase.target_rate_per_tick,
            "rate_multiplier": phase.rate_multiplier,
        })).collect::<Vec<_>>(),
        "expected_total_events": schedule.expected_total_events,
        "fault_schedule": schedule.fault_schedule,
        "rate_semantics": "declared schedule labels, not measured rates; no timing instrumentation",
    })
}

/// Capacity characterization evidence for one cell. Every count comes from
/// the cell's own output. A resource that cannot be measured is reported with
/// an explicit `unavailable` object, never as zero; the same applies to every
/// ordinary (non-capacity) cell so the field is always present and auditable.
fn capacity_json(config: &CellConfig, outcome: &CellOutcome, output: Option<&CellOutput>) -> Value {
    let Some(spec) = config.capacity else {
        return super::manifest::unavailable("not a capacity characterization cell");
    };
    let host = HostInfo::probe();
    let coverage = output.and_then(|cell| cell.coverage.as_ref());
    let skewed = spec.model == WorkloadModel::SkewedHotQuiet;
    let per_instrument = spec.model == WorkloadModel::FixedPerInstrument;
    json!({
        "stage": spec.stage.label,
        "instruments": spec.stage.symbols,
        "eligible_instruments": output.map(|cell| cell.eligible_count),
        "workload_model": spec.model.as_str(),
        "expected_events": spec.expected_events(),
        "workload": {
            "events_per_instrument": if per_instrument {
                json!(PER_INSTRUMENT_EVENTS)
            } else {
                Value::Null
            },
            "aggregate_events": if per_instrument {
                Value::Null
            } else {
                json!(AGGREGATE_EVENTS)
            },
            "hot_fraction_ppm": if skewed { json!(HOT_FRACTION_PPM) } else { Value::Null },
            "hot_event_share_pct": if skewed { json!(HOT_EVENT_SHARE_PCT) } else { Value::Null },
            "hot_selection": if skewed { json!("exact_quota") } else { Value::Null },
        },
        "coverage": {
            "expected": coverage.map(|summary| summary.expected),
            "acknowledged": coverage.map(|summary| summary.acknowledged),
            "anchored": coverage.map(|summary| summary.anchored),
            "expected_set_sha256": output
                .map(|cell| canonical_set_sha256(&cell.expected_symbols)),
            "anchored_set_sha256": output
                .map(|cell| canonical_set_sha256(&cell.anchored_symbols)),
            "valid": coverage.map(|summary| summary.valid),
        },
        "verification": {
            "sbe_valid": output.map(|cell| cell.verify_valid),
            "completeness_valid": output.map(|cell| cell.completeness_valid),
            "coverage_valid": coverage.map(|summary| summary.valid),
            "journal_complete": output.map(|cell| cell.journal_complete),
            "journal_record_count": output.and_then(|cell| cell.journaled_records),
        },
        "resources": {
            "harness_rss_bytes": output
                .and_then(|cell| cell.harness_process_rss_sample_bytes)
                .map(Value::from)
                .unwrap_or_else(|| super::manifest::unavailable("rss not readable on this host")),
            "cpu_seconds": super::manifest::unavailable(
                "cpu_seconds not measured (no libc dependency)"
            ),
            "cpu_count": host
                .cpu_count
                .map(Value::from)
                .unwrap_or_else(|| super::manifest::unavailable("available_parallelism failed")),
            "ram_mb": host
                .ram_mb
                .map(Value::from)
                .unwrap_or_else(|| super::manifest::unavailable("ram unavailable")),
            "fd_limit": host
                .fd_limit
                .map(Value::from)
                .unwrap_or_else(|| super::manifest::unavailable("ulimit -n unavailable")),
            "disk_free_bytes": host
                .disk_free_bytes
                .map(Value::from)
                .unwrap_or_else(|| super::manifest::unavailable(
                    host.disk_free_reason.as_deref().unwrap_or("df unavailable")
                )),
        },
        "acceptance": {
            "run_status": outcome.acceptance.status(),
            "ledger_reconciled": output.map(|cell| cell.ledger.reconciled()).unwrap_or(false),
            "reasons": outcome.acceptance.reasons.clone(),
        }
    })
}

/// Build one reference-matrix manifest document for a finished outcome.
pub fn build_cell_manifest(
    outcome: &CellOutcome,
    config: &CellConfig,
    cell_id: &str,
) -> Map<String, Value> {
    let host_info = HostInfo::probe();
    let host = host_json(&host_info);
    let output = outcome.output.as_ref();
    let binary_sha256 = harness_binary_sha256();

    let mut document = Map::new();
    document.insert(
        "schema_version".to_owned(),
        json!(super::manifest::STRESS_MANIFEST_SCHEMA_VERSION),
    );
    document.insert("run_id".to_owned(), json!(run_id()));
    document.insert("cell_id".to_owned(), json!(cell_id));
    document.insert("execution_mode".to_owned(), json!("stress"));
    document.insert("evidence_class".to_owned(), json!("synthetic-loopback"));
    document.insert("run_status".to_owned(), json!(outcome.acceptance.status()));
    document.insert(
        "failure_class".to_owned(),
        outcome
            .acceptance
            .failure_class
            .clone()
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    document.insert(
        "acceptance_reasons".to_owned(),
        Value::Array(
            outcome
                .acceptance
                .reasons
                .iter()
                .cloned()
                .map(Value::from)
                .collect(),
        ),
    );
    document.insert(
        "generator_version".to_owned(),
        json!(super::universe::GENERATOR_VERSION),
    );
    document.insert(
        "prng_algorithm_version".to_owned(),
        json!(super::rng::PRNG_ALGORITHM_VERSION),
    );
    document.insert("scenario_version".to_owned(), json!(SCENARIO_VERSION));
    let schedule = output
        .map(|cell| cell.schedule.clone())
        .unwrap_or_else(|| build_schedule(config, None));
    document.insert("workload_schedule".to_owned(), schedule_json(&schedule));
    document.insert("build_profile".to_owned(), json!(build_profile()));
    document.insert("target_triple".to_owned(), json!(target_triple()));
    document.insert(
        "stress_harness_binary_sha256".to_owned(),
        binary_sha256
            .clone()
            .map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("current_exe unreadable")),
    );
    document.insert(
        "collector_binary_sha256".to_owned(),
        binary_sha256
            .map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("current_exe unreadable")),
    );
    document.insert("host".to_owned(), host);
    document.insert(
        "provenance".to_owned(),
        provenance_json(outcome.provenance.as_ref()),
    );
    document.insert(
        "source_commit".to_owned(),
        json!(
            outcome
                .provenance
                .as_ref()
                .and_then(|provenance| provenance.commit.clone())
                .unwrap_or_else(|| "unknown".to_owned())
        ),
    );
    // The schedule is rebuilt from the seed for cells that failed before a
    // report existed, so even a failed manifest records the exact workload
    // that was intended.
    let lifecycle_schedule = output
        .map(|out| out.lifecycle_schedule.clone())
        .unwrap_or_else(|| {
            let universe =
                SyntheticUniverse::generate(config.seed, config.symbols, config.decoy_fraction_ppm);
            LifecycleSchedule::build(
                config.lifecycle_scenario,
                config.seed,
                &universe.eligible_tickers_sorted(),
                config.events,
            )
        });
    let mut scenario = json!({
        "seed": config.seed,
        "symbols": config.symbols,
        "burst_profile": schedule.profile,
        "eligible_count": output.map(|o| o.eligible_count).unwrap_or(0),
        "events_published": output.map(|o| o.events_published).unwrap_or(0),
        "shards_requested": config.shards.unwrap_or(0),
        "shards_actual": output.and_then(|o| o.report.capacity.as_ref().map(|plan| plan.shards)).unwrap_or(0),
        "replicas_requested": config.replicas,
        "replicas_actual": output.and_then(|o| o.report.capacity.as_ref().map(|plan| plan.replicas)).unwrap_or(0),
        "lifecycle_replicas": config.lifecycle_replicas,
        "distribution": if config.hot_fraction_ppm > 0 {
            "hot_quiet"
        } else if config.hot_pair {
            "zipf_hot_pair"
        } else {
            "uniform"
        },
        "hot_fraction_ppm": config.hot_fraction_ppm,
        "hot_event_share_pct": config.hot_event_share_pct,
        "hot_selection": match config.hot_selection {
            HotSelection::Weighted => "weighted",
            HotSelection::ExactQuota => "exact_quota",
        },
        "hot_tickers": output.map(|o| o.hot_tickers).unwrap_or(0),
        "hot_events": output.map(|o| o.hot_events).unwrap_or(0),
        "cold_events": output.map(|o| o.cold_events).unwrap_or(0),
        "uniform_spread": config.uniform_spread,
        "journal": config.journal,
        "failure_injection": config.fail_inject.map(|f| format!("{f:?}")),
        "lifecycle_scenario": config.lifecycle_scenario.as_str(),
        "lifecycle_scenario_id": config.lifecycle_scenario.scenario_id(),
        "lifecycle_schedule_version": LIFECYCLE_SCHEDULE_VERSION,
        "lifecycle_seed": config.seed,
        "lifecycle_events": lifecycle_schedule.events.len(),
        "lifecycle_expected_applied": lifecycle_schedule.expected_applied(),
        "lifecycle_expected_duplicates": lifecycle_schedule.expected_duplicates(),
        "lifecycle_expected_stale": lifecycle_schedule.expected_stale(),
        "lifecycle_applied": output.map(|o| o.lifecycle_applied).unwrap_or(0),
        "lifecycle_duplicates": output.map(|o| o.lifecycle_duplicates).unwrap_or(0),
        "lifecycle_stale_dropped": output.map(|o| o.lifecycle_stale_dropped).unwrap_or(0),
        "lifecycle_unknown_symbols": output.map(|o| o.lifecycle_unknown_symbols).unwrap_or(0),
        "lifecycle_discovery_vetoes": output.map(|o| o.lifecycle_discovery_vetoes).unwrap_or(0),
        "lifecycle_sent_frames": output.map(|o| o.lifecycle_sent_frames).unwrap_or(0),
        "lifecycle_subscribed": output.map(|o| o.lifecycle_subscribed).unwrap_or(0),
        "lifecycle_barrier_completed": output.map(|o| o.lifecycle_barrier_completed).unwrap_or(false),
        "lifecycle_added_tickers": lifecycle_schedule.added_ticker.iter().cloned().collect::<Vec<_>>(),
        "lifecycle_retired_tickers": lifecycle_schedule.retired_ticker.iter().cloned().collect::<Vec<_>>(),
        "lifecycle_epochs": lifecycle_schedule.epochs.iter().map(epoch_json).collect::<Vec<_>>(),
    });
    let fault_schedule_json = config
        .fault_schedule
        .as_ref()
        .and_then(|schedule| serde_json::to_value(schedule).ok())
        .unwrap_or_else(|| json!({ "steps": [] }));
    if let Value::Object(scenario) = &mut scenario {
        scenario.insert("fault_schedule".to_owned(), fault_schedule_json.clone());
    }
    if let Some(spec) = config.capacity
        && let Value::Object(fields) = &mut scenario
    {
        fields.insert("capacity_stage".to_owned(), json!(spec.stage.label));
        fields.insert(
            "capacity_workload_model".to_owned(),
            json!(spec.model.as_str()),
        );
        fields.insert(
            "capacity_expected_events".to_owned(),
            json!(spec.expected_events()),
        );
    }
    document.insert(
        "configuration_sha256".to_owned(),
        Value::from(sha256_hex(scenario.to_string().as_bytes())),
    );
    document.insert("scenario".to_owned(), scenario);
    // Top-level copy for evidence consumers: the explicit fault matrix with
    // fault id, affected source/instruments, start epoch, failure time, type,
    // expected action/outcome, and deadline for every step.
    document.insert("fault_schedule".to_owned(), fault_schedule_json);
    document.insert(
        "capacity".to_owned(),
        capacity_json(config, outcome, output),
    );

    let desired_topology = json!({
        "shards": config.shards.unwrap_or(0),
        "replicas": config.replicas,
        "lifecycle_replicas": config.lifecycle_replicas,
        "writer_queue": config.writer_queue.unwrap_or(4_096),
    });
    let actual_topology = match output.and_then(|o| o.report.capacity.as_ref()) {
        Some(plan) => json!({
            "shards": plan.shards,
            "replicas": plan.replicas,
            "lifecycle_connections": plan.lifecycle_connections,
            "total_connections": plan.total_connections,
        }),
        None => super::manifest::unavailable("capacity plan unavailable"),
    };
    let capacity_plan = output
        .and_then(|o| o.report.capacity.as_ref())
        .and_then(|plan| serde_json::to_value(plan).ok())
        .unwrap_or_else(|| super::manifest::unavailable("capacity plan unavailable"));
    document.insert(
        "collector".to_owned(),
        json!({
            "desired_topology": desired_topology,
            "actual_topology": actual_topology,
            "capacity_plan": capacity_plan,
            "in_process": true,
        }),
    );

    document.insert(
        "counts".to_owned(),
        json!({
            "generated_events": output.map(|o| o.ledger.generated_events).unwrap_or(0),
            "transmitted_frames": output.map(|o| o.transmitted_frames),
            "applied_events": output.and_then(|o| o.applied_events),
            "writer_messages": output.map(|o| o.report.writer.messages),
            "writer_bytes": output.map(|o| o.report.writer.bytes),
            "sbe_messages": output.map(|o| o.sbe_messages),
            "sbe_deltas": output.map(|o| o.sbe_deltas),
            "sbe_snapshots": output.map(|o| o.sbe_snapshots),
            "journaled_frames": match (config.journal, output.and_then(|o| o.journaled_records)) {
                (false, _) => Value::Null,
                (true, Some(count)) => json!(count),
                (true, None) => super::manifest::unavailable("journal verification unavailable"),
            },
            "unexplained_drops": output.map(|o| o.ledger.unexplained_drops),
            "persistence_gap": output.map(|o| o.ledger.persistence_gap),
            "mock_queue_high_water": output.map(|o| o.mock.queue_high_water),
            "mock_queue_saturated": output.map(|o| o.mock.queue_saturated),
            "writer_queue_high_water": output.map(|o| o.writer_queue_high_water),
        }),
    );

    // Transport-stage distinction required by the design: enqueued vs
    // socket-written vs still in flight, plus every accounted drop.
    document.insert(
        "mock_transport".to_owned(),
        json!({
            "outbound_capacity": output.map(|o| o.mock.outbound_capacity),
            "enqueued": output.map(|o| o.mock.enqueued),
            "socket_written": output.map(|o| o.mock.sent),
            "in_flight_at_end": output.map(|o| o.mock.in_flight),
            "snapshots_sent": output.map(|o| o.mock.snapshots_sent),
            "deltas_sent": output.map(|o| o.mock.deltas_sent),
            "acks_sent": output.map(|o| o.mock.acks_sent),
            "queue_high_water": output.map(|o| o.mock.queue_high_water),
            "queue_saturated": output.map(|o| o.mock.queue_saturated),
            "injected_pre_wire_drops": output.map(|o| o.mock.injected_pre_wire_drops),
            "forwarder_delay_ms": output.map(|o| o.mock.forwarder_delay_ms),
        }),
    );

    let queue_high_water = output
        .map(|output| output.mock.queue_high_water)
        .unwrap_or(0);
    let queue_capacity = output
        .map(|output| output.mock.outbound_capacity)
        .unwrap_or(0);
    let pressure_ppm = queue_high_water
        .saturating_mul(1_000_000)
        .checked_div(queue_capacity)
        .unwrap_or(0);
    document.insert(
        "harness".to_owned(),
        json!({
            "mock_queue_high_water": output.map(|output| output.mock.queue_high_water),
            "mock_queue_capacity": output.map(|output| output.mock.outbound_capacity),
            "mock_queue_pressure_ppm": pressure_ppm,
            "throughput_limited": output
                .map(|output| output.mock.queue_saturated > 0 || pressure_ppm >= 900_000)
                .unwrap_or(false),
        }),
    );

    document.insert("event_ledger".to_owned(), json!({
        "generated_events": output.map(|o| o.ledger.generated_events).unwrap_or(0),
        "expected_applied": output.map(|o| o.ledger.expected_applied).unwrap_or(0),
        "applied_events": output.and_then(|o| o.ledger.applied_events),
        "enqueued_deltas": output.and_then(|o| o.ledger.enqueued_deltas).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("mock enqueue counter unavailable")),
        "transmitted_deltas": output.and_then(|o| o.ledger.transmitted_deltas).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("mock transmit counter unavailable")),
        "received_frames": output.and_then(|o| o.ledger.received_frames).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("source message metric unavailable")),
        "decode_errors": output.and_then(|o| o.ledger.decode_errors).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("decode error metric unavailable")),
        "data_frames_received": output.and_then(|o| o.ledger.received_frames).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("ingress frame metric unavailable")),
        "delta_events_decoded": output.and_then(|o| o.ledger.delta_events_decoded).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("decode metric unavailable")),
        "core_ingress_events": output.and_then(|o| o.ledger.core_ingress_events).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("core ingress metric unavailable")),
        "core_delta_events": output.and_then(|o| o.ledger.core_delta_events).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("core delta metric unavailable")),
        "no_active_source": output.and_then(|o| o.ledger.no_active_source).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("disposition metric unavailable")),
        "unknown_symbol": output.and_then(|o| o.ledger.unknown_symbol).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("disposition metric unavailable")),
        "non_live": output.and_then(|o| o.ledger.non_live).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("disposition metric unavailable")),
        "unassigned_source": output.and_then(|o| o.ledger.unassigned_source).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("disposition metric unavailable")),
        "invalid_book": output.and_then(|o| o.ledger.invalid_book).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("disposition metric unavailable")),
        "shadow_clock_regression": output.and_then(|o| o.ledger.shadow_clock_regression).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("disposition metric unavailable")),
        "zero_noop": output.and_then(|o| o.ledger.zero_noop).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("disposition metric unavailable")),
        "sbe_conversion_failed": output.and_then(|o| o.ledger.sbe_conversion_failed).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("disposition metric unavailable")),
        "disposition_shortfall": output.and_then(|o| o.ledger.disposition_shortfall),
        "disposition_excess": output.and_then(|o| o.ledger.disposition_excess),
        "writer_delta_admissions": output.and_then(|o| o.ledger.writer_delta_admissions).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("writer admission metric unavailable")),
        "writer_delta_writes": output.and_then(|o| o.ledger.writer_delta_writes).map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("writer write metric unavailable")),
        "sbe_deltas": output.and_then(|o| o.ledger.sbe_deltas),
        "journaled_records": match (config.journal, output.and_then(|o| o.ledger.journaled_records)) {
            (false, _) => Value::Null,
            (true, count) => count.map(Value::from).unwrap_or_else(|| {
                super::manifest::unavailable("journal verification unavailable")
            }),
        },
        "injected_pre_wire_drops": output.map(|o| o.ledger.injected_pre_wire_drops).unwrap_or(0),
        "suppressed_replica_duplicates": output
            .and_then(|o| o.ledger.suppressed_replica_duplicates),
        "unexplained_drops": output.and_then(|o| o.ledger.unexplained_drops),
        "application_shortfall": output.and_then(|o| o.ledger.application_shortfall),
        "over_applied": output.and_then(|o| o.ledger.over_applied),
        "persistence_gap": output.and_then(|o| o.ledger.persistence_gap),
        "persistence_excess": output.and_then(|o| o.ledger.persistence_excess),
        "enqueue_transmit_shortfall": output.and_then(|o| o.ledger.enqueue_transmit_shortfall),
        "enqueue_transmit_excess": output.and_then(|o| o.ledger.enqueue_transmit_excess),
        "transmit_decode_shortfall": output.and_then(|o| o.ledger.transmit_decode_shortfall),
        "transmit_decode_excess": output.and_then(|o| o.ledger.transmit_decode_excess),
        "writer_admission_shortfall": output.and_then(|o| o.ledger.writer_admission_shortfall),
        "writer_admission_excess": output.and_then(|o| o.ledger.writer_admission_excess),
        "writer_write_shortfall": output.and_then(|o| o.ledger.writer_write_shortfall),
        "writer_write_excess": output.and_then(|o| o.ledger.writer_write_excess),
        "decode_failure_count": output.and_then(|o| o.ledger.decode_failure_count),
        "reconciled": output.map(|o| o.ledger.reconciled()).unwrap_or(false),
    }));

    let expected_set_sha256 = match output {
        Some(o) => match &o.coverage {
            Some(c) => Value::from(c.expected_set_sha256.clone()),
            None => Value::from(canonical_set_sha256(&o.expected_symbols)),
        },
        None => super::manifest::unavailable("capture not produced"),
    };
    let acknowledged_set_sha256 = output
        .map(|o| Value::from(canonical_set_sha256(&o.acknowledged_symbols)))
        .unwrap_or_else(|| super::manifest::unavailable("capture not produced"));
    let anchored_set_sha256 = output
        .map(|o| Value::from(canonical_set_sha256(&o.anchored_symbols)))
        .unwrap_or_else(|| super::manifest::unavailable("capture not produced"));
    let observed_set_sha256 = output
        .map(|o| Value::from(canonical_set_sha256(&o.observed_symbols)))
        .unwrap_or_else(|| super::manifest::unavailable("capture not produced"));

    document.insert("coverage".to_owned(), json!({
        "expected": output.map(|o| o.coverage.as_ref().map(|c| c.expected)),
        "acknowledged": output.map(|o| o.coverage.as_ref().map(|c| c.acknowledged)),
        "anchored": output.map(|o| o.coverage.as_ref().map(|c| c.anchored)),
        "observed": output.map(|o| o.coverage.as_ref().map(|c| c.observed)),
        "missing_ack": output.and_then(|o| o.coverage.as_ref().map(|c| c.missing_ack.count)),
        "missing_anchor": output.and_then(|o| o.coverage.as_ref().map(|c| c.missing_anchor.count)),
        "expected_set_sha256": expected_set_sha256,
        "acknowledged_set_sha256": acknowledged_set_sha256,
        "anchored_set_sha256": anchored_set_sha256,
        "observed_set_sha256": observed_set_sha256,
        "decoys_absent": output.map(|o| o.decoy_absent),
        "coverage_valid": output.map(|o| o.coverage.as_ref().map(|c| c.valid).unwrap_or(false)),
        "per_epoch": lifecycle_schedule.epochs.iter().map(epoch_json).collect::<Vec<_>>(),
        "retired_not_expected": output.and_then(|o| o.coverage.as_ref()).map(|summary| json!({
            "count": summary.anchored_not_expected.count,
            "sample": summary.anchored_not_expected.sample,
        })).unwrap_or(Value::Null),
        "retired_obligations_rejected": output.map(|o| o.anchored_extras_ok),
    }));

    document.insert("verify".to_owned(), json!({
        "verify_valid": output.map(|o| o.verify_valid),
        "completeness_valid": output.map(|o| o.completeness_valid),
        "coverage_valid": output.map(|o| o.coverage.as_ref().map(|c| c.valid).unwrap_or(false)),
        "verify_error": output.and_then(|o| o.verify_error.clone()).map(Value::from).unwrap_or(Value::Null),
        "completeness_error": output.and_then(|o| o.completeness_error.clone()).map(Value::from).unwrap_or(Value::Null),
        "coverage_error": output.and_then(|o| o.coverage_error.clone()).map(Value::from).unwrap_or(Value::Null),
        "journal_complete": output.map(|o| o.journal_complete),
        "journal_record_count": output.and_then(|o| o.journaled_records).map(Value::from).unwrap_or(Value::Null),
    }));

    let phase_results = output.map(|o| {
        o.phase_results
            .iter()
            .map(|phase| {
                json!({
                    "name": phase.name,
                    "published_events": phase.published,
                    "cumulative_expected": phase.cumulative_expected,
                    "drain_completed": phase.drain_completed,
                })
            })
            .collect::<Vec<_>>()
    });
    document.insert("delivery".to_owned(), json!({
        "anchor_completed": !output.map(|o| o.anchor_wait_expired).unwrap_or(true),
        "anchor_ms": output.map(|o| o.anchored_time.as_millis() as u64),
        "drain_completed": output.map(|o| o.drain_completed).unwrap_or(false),
        "drain_detail": output.and_then(|o| o.drain_detail.clone()).map(Value::from).unwrap_or(Value::Null),
        "capacity_connections": output.map(|o| o.capacity_connections).unwrap_or(0),
        "phases": phase_results.unwrap_or_default(),
        "ws_connections": output.map(|o| o.ws_connections),
        "book_subscriptions": output.map(|o| o.book_subscriptions),
        "lifecycle_barrier_completed": output.map(|o| o.lifecycle_barrier_completed).unwrap_or(false),
        "lifecycle_barrier_detail": output
            .and_then(|o| o.lifecycle_barrier_detail.clone())
            .map(Value::from)
            .unwrap_or(Value::Null),
    }));

    // Recovery is measured as incident detection -> valid re-anchor. Every
    // injected fault exports its observed counters and, when both endpoints
    // were observed, the duration; otherwise an explicit unavailability reason.
    let recovery: Vec<Value> = output
        .map(|output| {
            output
                .recovery
                .iter()
                .map(|evidence| {
                    json!({
                        "fault_id": evidence.fault_id,
                        "observed_epoch": evidence.observed_epoch,
                        "incidents_before": evidence.incidents_before,
                        "incidents_after": evidence.incidents_after,
                        "failover_snapshots_before": evidence.failover_snapshots_before,
                        "failover_snapshots_after": evidence.failover_snapshots_after,
                        "connections_after": evidence.connections_after,
                        "detected_at_ms": evidence.detected_at_ms,
                        "reanchored_at_ms": evidence.reanchored_at_ms,
                        "duration_ms": evidence.duration_ms,
                        "duration_unavailable_reason": evidence.duration_unavailable_reason,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    document.insert("recovery".to_owned(), json!(recovery));

    let incidents = output.map(|output| output.incidents);
    let disk_free = HostInfo::probe().disk_free_bytes;
    document.insert(
        "disk".to_owned(),
        json!({
            "free_bytes_before_start": disk_free
                .map(Value::from)
                .unwrap_or_else(|| super::manifest::unavailable("df unavailable")),
            "bytes_written": output
                .map(|output| output.report.writer.bytes)
                .map(Value::from)
                .unwrap_or_else(|| super::manifest::unavailable("writer report unavailable")),
            "disk_ceiling_bytes": super::manifest::unavailable(
                "STRESS_DISK_CEILING is not configured for this cell"
            ),
            "disk_ceiling_reached": false,
        }),
    );
    document.insert(
        "incidents".to_owned(),
        json!({
            "discontinuity_incidents": incidents
                .and_then(|incidents| incidents.discontinuity_incidents)
                .map(Value::from)
                .unwrap_or_else(|| super::manifest::unavailable(
                    "collector_discontinuity_incidents_total unavailable"
                )),
            "unquantifiable_gaps": incidents
                .and_then(|incidents| incidents.unquantifiable_gaps)
                .map(Value::from)
                .unwrap_or_else(|| super::manifest::unavailable(
                    "collector_unquantifiable_gaps_total unavailable"
                )),
            "queue_saturated_events": output.map(|output| output.mock.queue_saturated),
            "injected_pre_wire_drops": output.map(|output| output.mock.injected_pre_wire_drops),
            "writer_errors": output.map(|output| output.report.writer.errors),
        }),
    );

    let backpressure_profile = super::backpressure::BackpressureProfile::from_config(config);
    let backpressure_observation =
        super::backpressure::observe(backpressure_profile.as_ref(), output);
    document.insert(
        "backpressure".to_owned(),
        super::backpressure::manifest_json(
            backpressure_profile.as_ref(),
            &backpressure_observation,
            output,
            &outcome.acceptance.reasons,
        ),
    );

    document.insert("performance".to_owned(), json!({
        "msgs_per_sec_p50": super::manifest::unavailable("binned throughput lands with the reference matrix"),
        "msgs_per_sec_p95": super::manifest::unavailable("binned throughput lands with the reference matrix"),
        "msgs_per_sec_p99": super::manifest::unavailable("binned throughput lands with the reference matrix"),
        "msgs_per_sec_max": super::manifest::unavailable("binned throughput lands with the reference matrix"),
        "harness_process_rss_sample_bytes": output
            .and_then(|o| o.harness_process_rss_sample_bytes)
            .map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("rss not readable on this host")),
        "snapshot_anchor_ms": output.map(|o| o.anchored_time.as_millis() as u64).unwrap_or(0),
        "writer_queue_high_water_mark": output
            .map(|o| o.writer_queue_high_water)
            .map(Value::from)
            .unwrap_or_else(|| super::manifest::unavailable("writer report unavailable")),
        "cpu_seconds": super::manifest::unavailable("cpu_seconds not measured (no libc dependency)"),
        "stage_timing": stage_timing_json(output, &host_info),
    }));

    document
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn boundary_reason_leads_regardless_of_collector_timing() {
        let ordered = order_acceptance_reasons(
            vec!["journal_pressure_rejected".to_owned()],
            vec!["coverage_invalid".to_owned(), "drain_incomplete".to_owned()],
        );
        assert_eq!(
            ordered.first().map(String::as_str),
            Some("journal_pressure_rejected"),
            "the injected boundary must name the failure class"
        );
        assert_eq!(ordered.len(), 3, "no reason is dropped by reordering");
        let acceptance = CellAcceptance::from_reasons(ordered);
        assert_eq!(
            acceptance.failure_class.as_deref(),
            Some("journal_pressure_rejected"),
            "the failure class follows the boundary reason"
        );
    }

    #[test]
    fn hot_cold_partition_is_exhaustive_and_disjoint() {
        let tickers: Vec<String> = (0..100).map(|i| format!("I{i:03}")).collect();
        let hot: BTreeSet<String> = tickers.iter().take(5).cloned().collect();
        let refs: Vec<&str> = tickers.iter().map(String::as_str).collect();
        let (hot_indices, cold_indices) = workload_partition(&refs, &hot);
        assert_eq!(hot_indices.len(), 5);
        assert_eq!(cold_indices.len(), 95);
        let hot_set: BTreeSet<usize> = hot_indices.iter().copied().collect();
        let cold_set: BTreeSet<usize> = cold_indices.iter().copied().collect();
        assert!(hot_set.is_disjoint(&cold_set));
        let union: BTreeSet<usize> = hot_set.union(&cold_set).copied().collect();
        assert_eq!(union, (0..100).collect());
    }

    #[test]
    fn exact_event_targets_have_an_exact_quota_and_are_reproducible() {
        let first = exact_event_targets(400, 80, &mut SplitMix64::new(23));
        assert_eq!(first.iter().filter(|hot| **hot).count(), 320);
        assert_eq!(first.iter().filter(|hot| !**hot).count(), 80);
        let again = exact_event_targets(400, 80, &mut SplitMix64::new(23));
        assert_eq!(first, again);
        assert_ne!(
            first,
            exact_event_targets(400, 80, &mut SplitMix64::new(24))
        );
    }

    #[test]
    fn burst_profiles_partition_the_budget_exactly_and_deterministically() {
        let profiles = [
            BurstProfile::Step,
            BurstProfile::Impulse,
            BurstProfile::RepeatedImpulses,
            BurstProfile::Ramp,
        ];
        for profile in profiles {
            let phases = profile_phases(profile, 400);
            let total: usize = phases.iter().map(|phase| phase.events).sum();
            assert_eq!(total, 400, "{profile:?} must not lose or invent events");
            assert_eq!(phases, profile_phases(profile, 400));
            assert!(
                phases.iter().all(|phase| phase.events > 0),
                "{profile:?} has an empty phase"
            );
        }
        // The four shapes are genuinely different, not relabeled copies.
        let shapes: Vec<Vec<usize>> = profiles
            .iter()
            .map(|profile| {
                profile_phases(*profile, 400)
                    .into_iter()
                    .map(|phase| phase.events)
                    .collect()
            })
            .collect();
        for (left, right) in shapes.iter().enumerate() {
            for other in shapes.iter().skip(left + 1) {
                assert_ne!(right, other, "distinct profiles must have distinct shapes");
            }
        }
    }

    #[test]
    fn burst_profile_counts_are_pinned() {
        let step: Vec<usize> = profile_phases(BurstProfile::Step, 400)
            .into_iter()
            .map(|phase| phase.events)
            .collect();
        assert_eq!(step, vec![100, 200, 100]);
        let impulse: Vec<usize> = profile_phases(BurstProfile::Impulse, 400)
            .into_iter()
            .map(|phase| phase.events)
            .collect();
        assert_eq!(impulse, vec![40, 280, 80]);
        // A non-divisible budget still sums exactly; the remainder is placed
        // deterministically rather than dropped.
        let ramp: Vec<usize> = profile_phases(BurstProfile::Ramp, 7)
            .into_iter()
            .map(|phase| phase.events)
            .collect();
        assert_eq!(ramp.iter().sum::<usize>(), 7);
    }

    #[test]
    fn schedule_records_id_seed_hot_definition_and_empty_faults() {
        let config = CellConfig {
            seed: 23,
            symbols: 4_000,
            hot_fraction_ppm: 50_000,
            hot_event_share_pct: 80,
            hot_selection: HotSelection::ExactQuota,
            burst: Some(BurstProfile::Step),
            events: 400,
            ..CellConfig::default()
        };
        let schedule = build_schedule(&config, Some("abc".to_owned()));
        assert_eq!(schedule.workload_id, "step-seed-0017-4000");
        assert_eq!(schedule.profile, "step");
        assert_eq!(schedule.seed, 23);
        assert_eq!(schedule.instrument_count, 4_000);
        assert_eq!(schedule.expected_total_events, 400);
        assert_eq!(schedule.hot_set.member_count, 200);
        assert_eq!(schedule.hot_set.sha256.as_deref(), Some("abc"));
        assert_eq!(schedule.hot_set.selection, "exact_quota");
        assert!(schedule.fault_schedule.is_empty());

        let steady = build_schedule(&CellConfig::default(), None);
        assert_eq!(steady.profile, "steady");
        assert_eq!(steady.phases.len(), 1);
        assert_eq!(steady.phases[0].events, CellConfig::default().events);
        assert!(steady.hot_set.sha256.is_none());
    }

    fn base() -> DrainBaselines {
        DrainBaselines {
            deltas_emitted: 0.0,
            writer_messages: 0.0,
            writer_errors: 0.0,
            suppressed_replica_duplicates: Some(0),
            source_decode_errors: Some(0),
            data_frames_received: Some(0),
            delta_events_decoded: Some(0),
            core_ingress_events: Some(0),
            core_delta_events: Some(0),
            no_active_source: Some(0),
            unknown_symbol: Some(0),
            non_live: Some(0),
            unassigned_source: Some(0),
            invalid_book: Some(0),
            shadow_clock_regression: Some(0),
            zero_noop: Some(0),
            sbe_conversion_failed: Some(0),
            writer_delta_admissions: Some(0),
            writer_delta_writes: Some(0),
        }
    }

    #[test]
    fn absent_metric_is_not_zero() {
        let sample = parse_metrics(
            "collector_deltas_emitted_total 5\n\
             collector_decoded_delta_events_total 0\n",
        );
        assert_eq!(
            sample.read("collector_writer_messages_total"),
            MetricRead::Absent
        );
        let error = sample
            .required("collector_writer_messages_total")
            .expect_err("absence must be an error");
        assert!(error.contains("absent"), "{error}");
    }

    #[test]
    fn malformed_metric_is_not_zero() {
        let sample = parse_metrics("collector_writer_messages_total not-a-number\n");
        assert_eq!(
            sample.read("collector_writer_messages_total"),
            MetricRead::Malformed
        );
        let error = sample
            .required("collector_writer_messages_total")
            .expect_err("malformed must be an error");
        assert!(error.contains("malformed"), "{error}");
    }

    #[test]
    fn labeled_families_fold_to_the_family_name() {
        let sample = parse_metrics(
            "collector_deltas_emitted_total{shard=\"0\"} 7\ncollector_decoded_delta_events_total 0\n",
        );
        assert_eq!(
            sample.read("collector_deltas_emitted_total"),
            MetricRead::Present(7.0)
        );
    }

    #[test]
    fn barrier_rejects_a_missing_mandatory_metric() {
        let sample = parse_metrics(
            "collector_deltas_emitted_total 10\n\
             collector_decoded_delta_events_total 0\n\
             collector_writer_queue_depth 0\n\
             collector_writer_errors_total 0\n",
        );
        match evaluate_barrier(&sample, &base(), 10.0, 10.0, 0) {
            BarrierState::Unavailable(message) => {
                assert!(
                    message.contains("collector_writer_messages_total"),
                    "{message}"
                );
            }
            other => panic!("expected unavailable, got {other:?}"),
        }
    }

    #[test]
    fn barrier_rejects_a_malformed_mandatory_metric() {
        let sample = parse_metrics(
            "collector_deltas_emitted_total 10\n\
             collector_decoded_delta_events_total 0\n\
             collector_writer_messages_total nope\n\
             collector_writer_queue_depth 0\n\
             collector_writer_errors_total 0\n",
        );
        assert!(matches!(
            evaluate_barrier(&sample, &base(), 10.0, 10.0, 0),
            BarrierState::Unavailable(_)
        ));
    }

    #[test]
    fn barrier_distinguishes_a_counter_reset() {
        let base = DrainBaselines {
            deltas_emitted: 100.0,
            writer_messages: 100.0,
            writer_errors: 0.0,
            suppressed_replica_duplicates: Some(0),
            source_decode_errors: Some(0),
            data_frames_received: Some(0),
            delta_events_decoded: Some(0),
            core_ingress_events: Some(0),
            core_delta_events: Some(0),
            no_active_source: Some(0),
            unknown_symbol: Some(0),
            non_live: Some(0),
            unassigned_source: Some(0),
            invalid_book: Some(0),
            shadow_clock_regression: Some(0),
            zero_noop: Some(0),
            sbe_conversion_failed: Some(0),
            writer_delta_admissions: Some(0),
            writer_delta_writes: Some(0),
        };
        let sample = parse_metrics(
            "collector_deltas_emitted_total 5\n\
             collector_decoded_delta_events_total 0\n\
             collector_writer_messages_total 5\n\
             collector_writer_queue_depth 0\n\
             collector_writer_errors_total 0\n",
        );
        assert_eq!(
            evaluate_barrier(&sample, &base, 10.0, 10.0, 0),
            BarrierState::CounterReset("collector_deltas_emitted_total")
        );
    }

    #[test]
    fn barrier_satisfies_only_when_every_metric_agrees() {
        let sample = parse_metrics(
            "collector_deltas_emitted_total 10\n\
             collector_decoded_delta_events_total 10\n\
             collector_writer_messages_total 10\n\
             collector_writer_queue_depth 0\n\
             collector_writer_errors_total 0\n",
        );
        assert_eq!(
            evaluate_barrier(&sample, &base(), 10.0, 10.0, 0),
            BarrierState::Satisfied
        );
        assert_eq!(
            evaluate_barrier(&sample, &base(), 10.0, 10.0, 1),
            BarrierState::Waiting
        );
    }

    /// Serve a scripted sequence of `/metrics` bodies, repeating the last body
    /// once the script is exhausted.
    async fn serve_metrics(bodies: Vec<String>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub metrics server");
        let address = listener.local_addr().expect("stub address");
        let bodies = Arc::new(bodies);
        tokio::spawn(async move {
            let mut index = 0usize;
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let body = bodies
                    .get(index)
                    .or_else(|| bodies.last())
                    .cloned()
                    .unwrap_or_default();
                index = index.saturating_add(1);
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        address
    }

    const DELAYED_BODY: &str = "collector_deltas_emitted_total 10\n\
             collector_decoded_delta_events_total 0\n\
        collector_writer_queue_depth 0\n\
        collector_writer_errors_total 0\n";
    const COMPLETE_BODY: &str = "collector_deltas_emitted_total 10\n\
             collector_decoded_delta_events_total 0\n\
        collector_writer_messages_total 20\n\
        collector_writer_queue_depth 0\n\
        collector_writer_errors_total 0\n";
    const MALFORMED_BODY: &str = "collector_deltas_emitted_total 10\n\
             collector_decoded_delta_events_total 0\n\
        collector_writer_messages_total nope\n\
        collector_writer_queue_depth 0\n\
        collector_writer_errors_total 0\n";

    #[tokio::test]
    async fn baseline_fails_closed_on_a_missing_metric() {
        let address = serve_metrics(vec![DELAYED_BODY.to_owned()]).await;
        let error = capture_baseline_until(address, Instant::now() + Duration::from_millis(150))
            .await
            .expect_err("a persistent absence must fail the baseline");
        assert!(error.contains("collector_writer_messages_total"), "{error}");
    }

    #[tokio::test]
    async fn baseline_fails_closed_on_a_malformed_metric() {
        let address = serve_metrics(vec![MALFORMED_BODY.to_owned()]).await;
        let error = capture_baseline_until(address, Instant::now() + Duration::from_millis(150))
            .await
            .expect_err("a malformed metric must fail the baseline");
        assert!(error.contains("malformed"), "{error}");
    }

    #[tokio::test]
    async fn baseline_recovers_from_a_delayed_metric() {
        let address = serve_metrics(vec![
            DELAYED_BODY.to_owned(),
            COMPLETE_BODY.to_owned(),
            COMPLETE_BODY.to_owned(),
        ])
        .await;
        let baseline = capture_baseline_until(address, Instant::now() + Duration::from_secs(2))
            .await
            .expect("a metric that appears later must be accepted");
        assert_eq!(baseline.writer_messages, 20.0);
        assert_eq!(baseline.deltas_emitted, 10.0);
    }
}
