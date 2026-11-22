#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "integration tests drive failure paths with unwrap/expect/panic and print diagnostics"
)]
#![allow(
    clippy::allow_attributes,
    reason = "test crates relax the production lint set wholesale; `expect` cannot express lints that may not fire"
)]

//! Deterministic synthetic full-universe stress laboratory.
//!
//! The synthetic Kalshi venue serves a seeded universe of
//! `STRESS-{seed:04x}-{index:06}` markets (regular challenge-eligible markets
//! plus MVE/closed decoys as negative controls) over real REST pagination
//! and WebSocket subscriptions. Every run drives the production collector
//! path (adapter → discovery → capacity planning → coordinator → books →
//! writer → journal) and is certified with `verify`, `completeness` and
//! `coverage` inside the runner, fail-closed, before any manifest exists.
//!
//! Evidence class: synthetic/loopback. See `docs/stress-lab-design.md`.
//!
//! CI runs the 4k correctness smoke plus deterministic self-tests of the
//! failure fixtures. The full matrix is opt-in (`--ignored`).

#![recursion_limit = "512"]

mod stress_support;

use std::collections::BTreeSet;

use fieldbook::histogram::StageHistogram;
use fieldbook::journal::RunState;

use stress_support::{
    capacity::{
        AGGREGATE_EVENTS, CapacityCell, CapacityStage, HOT_EVENT_SHARE_PCT, HOT_FRACTION_PPM,
        PER_INSTRUMENT_EVENTS, WorkloadModel,
    },
    faults::SweepProfile,
    lifecycle::LifecycleScenario,
    mock::MockKalshi,
    rng::SplitMix64,
    runner::{
        BurstProfile, CellAcceptance, CellConfig, CellOutcome, FailInject, HotSelection,
        build_cell_manifest, canonical_set_sha256, worktree_provenance,
    },
    universe::{GENERATOR_VERSION, SyntheticUniverse},
};

/// Deterministic RNG contract, exercised against pinned vectors.
#[test]
fn splitmix64_is_pinned() {
    let mut rng = SplitMix64::new(0);
    let first: Vec<u64> = (0..4).map(|_| rng.next_u64()).collect();
    assert_eq!(
        first,
        vec![
            0xE220_A839_7B1D_CDAF,
            0x6E78_9E6A_A1B9_65F4,
            0x06C4_5D18_8009_454F,
            0xF88B_B8A8_724C_81EC,
        ]
    );
    assert_eq!(stress_support::rng::PRNG_ALGORITHM_VERSION, 1);
}

/// Universe contract: eligible and decoy sets are disjoint and complete.
#[test]
fn universe_generation_is_disjoint_and_deterministic() {
    let universe = SyntheticUniverse::generate(42, 64, 100_000);
    assert_eq!(GENERATOR_VERSION, 2);
    let eligible = universe.eligible_tickers_sorted();
    let excluded = universe.excluded_tickers_sorted();
    assert_eq!(eligible.len(), 64);
    assert!(!excluded.is_empty());
    for ticker in &excluded {
        assert!(!eligible.contains(ticker));
    }
}

fn headless_cell_config(seed: u64, symbols: usize) -> CellConfig {
    CellConfig {
        seed,
        symbols,
        decoy_fraction_ppm: 20_000,
        shards: Some(1),
        replicas: 2,
        lifecycle_replicas: 1,
        lifecycle_scenario: LifecycleScenario::None,
        events: 40,
        hot_pair: false,
        uniform_spread: true,
        hot_fraction_ppm: 0,
        hot_event_share_pct: 0,
        hot_selection: HotSelection::Weighted,
        burst: None,
        journal: true,
        limits: Some((20, 2)),
        force_capacity_reject: false,
        fail_inject: None,
        writer_queue: None,
        worktree_dir: None,
        require_clean_worktree: None,
        fault_schedule: None,
        capacity: None,
    }
}

/// One small smoke cell: anchor a 4k-eligible-symbol universe through the
/// real pipeline, publish deltas, prove delivery with the drain barrier,
/// stop and certify. This is the CI regression gate — invariants only, no
/// throughput claims.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn smoke_cell_anchors_applies_and_certifies() {
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        seed: 7,
        symbols: 4_000,
        decoy_fraction_ppm: 20_000,
        shards: Some(1),
        replicas: 2,
        lifecycle_replicas: 1,
        lifecycle_scenario: LifecycleScenario::None,
        events: 200,
        hot_pair: false,
        uniform_spread: true,
        hot_fraction_ppm: 0,
        hot_event_share_pct: 0,
        hot_selection: HotSelection::Weighted,
        burst: None,
        journal: true,
        limits: Some((45, 30)),
        force_capacity_reject: false,
        fail_inject: None,
        writer_queue: None,
        worktree_dir: None,
        require_clean_worktree: None,
        fault_schedule: None,
        capacity: None,
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        outcome.acceptance.valid,
        "smoke cell failed acceptance: reasons={:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.expect("valid cell must carry output");

    assert!(
        !output.anchor_wait_expired,
        "anchoring did not complete in time"
    );
    assert!(output.drain_completed, "drain barrier did not complete");
    assert!(
        output.decoy_absent,
        "an MVE/closed decoy entered the capture"
    );
    assert!(output.verify_valid, "SBE verification failed");
    assert!(
        output.completeness_valid,
        "completeness verification failed"
    );
    assert!(
        output.journal_complete,
        "journal did not finalize completely"
    );
    let coverage = output.coverage.as_ref().expect("coverage must be present");
    assert!(coverage.valid, "coverage not valid: {coverage:?}");
    assert_eq!(coverage.expected, output.eligible_count);
    assert_eq!(coverage.anchored, output.eligible_count);
    assert_eq!(output.capacity_connections, 3); // 1 shard x 2 replicas + 1 lifecycle

    // Independent event accounting must reconcile exactly.
    assert_eq!(output.events_published, 200);
    assert_eq!(output.sbe_deltas, 200);
    assert!(output.ledger.reconciled(), "ledger: {:?}", output.ledger);
    assert_eq!(output.ledger.unexplained_drops, Some(0));
    assert_eq!(output.ledger.persistence_gap, Some(0));

    // The three canonical set hashes must agree, and the expected hash must
    // equal the hash of the independently regenerated universe.
    let universe = SyntheticUniverse::generate(7, 4_000, 20_000);
    let independent: BTreeSet<String> = universe.eligible_tickers_sorted().into_iter().collect();
    let expected_hash = canonical_set_sha256(&independent);
    assert_eq!(coverage.expected_set_sha256, expected_hash);
    assert_eq!(
        canonical_set_sha256(&output.acknowledged_symbols),
        expected_hash
    );
    assert_eq!(
        canonical_set_sha256(&output.anchored_symbols),
        expected_hash
    );
}

/// Fixture: one eligible market receives no snapshot. It must never enter the
/// snapshot-anchored set and the cell must fail closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_snapshot_fixture_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        fail_inject: Some(FailInject::MissingSnapshot { skip_one: 1 }),
        events: 30,
        limits: Some((10, 2)),
        ..headless_cell_config(11, 200)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        !outcome.acceptance.valid,
        "missing snapshot must fail acceptance"
    );
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason.contains("anchor") || reason.contains("coverage")),
        "expected anchor/coverage failure, got {:?}",
        outcome.acceptance.reasons
    );
    if let Some(output) = &outcome.output {
        let universe = SyntheticUniverse::generate(11, 200, 20_000);
        let skipped = universe.eligible_tickers_sorted()[0].clone();
        assert!(
            !output.anchored_symbols.contains(&skipped),
            "the skipped market must not be snapshot-anchored"
        );
        assert!(
            output.acknowledged_symbols.contains(&skipped),
            "the skipped market must still be acknowledged"
        );
    }
}

/// Fixture: one market receives a delta but no snapshot. The delta must not
/// anchor it, the applied count must fall by exactly one, and the event
/// ledger must report the gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn update_without_snapshot_fixture_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        fail_inject: Some(FailInject::UpdateOnly { skip_one: 1 }),
        events: 40,
        limits: Some((10, 2)),
        ..headless_cell_config(12, 200)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        !outcome.acceptance.valid,
        "update without anchor must fail acceptance"
    );
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason == "unexplained_drops" || reason.contains("coverage")),
        "expected accounting/coverage failure, got {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.unwrap_or_else(|| {
        panic!(
            "fixture cell must produce output; acceptance reasons: {:?}",
            outcome.acceptance.reasons
        )
    });
    let universe = SyntheticUniverse::generate(12, 200, 20_000);
    let skipped = universe.eligible_tickers_sorted()[0].clone();
    assert!(
        !output.anchored_symbols.contains(&skipped),
        "an update-only symbol must not be counted as snapshot-anchored"
    );
    assert_eq!(
        output.sbe_deltas,
        output.events_published as u64 - 1,
        "exactly the update-only delta must be missing from the capture"
    );
    assert!(
        output
            .ledger
            .unexplained_drops
            .is_some_and(|drops| drops >= 1),
        "ledger must report the unaccounted delta: {:?}",
        output.ledger
    );
}

/// Fixture: delta frames dropped before the wire. With two replicas the
/// first `count` frames vanish in replica-pair order, so exactly
/// `count / 2` events are lost and only event accounting can catch it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_delta_fixture_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        fail_inject: Some(FailInject::DroppedFrames { count: 10 }),
        events: 100,
        ..headless_cell_config(13, 300)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        !outcome.acceptance.valid,
        "dropped frames must fail acceptance"
    );
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason == "unexplained_drops"),
        "expected unexplained_drops, got {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.unwrap_or_else(|| {
        panic!(
            "fixture cell must produce output; acceptance reasons: {:?}",
            outcome.acceptance.reasons
        )
    });
    assert_eq!(
        output.sbe_deltas,
        output.events_published as u64 - 5,
        "exactly the injected events must be missing from the capture"
    );
    assert_eq!(output.mock.injected_pre_wire_drops, 10);
    assert_eq!(output.ledger.unexplained_drops, Some(5));
}

/// Fixture: the production writer queue bound is set to its minimum and the
/// final-snapshot burst must drive it to saturation. The channel bound must
/// hold (the counter observes it with at most one slot of lag), the run must
/// either reconcile under the visible backpressure (success with evidence)
/// or fail — never silently pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writer_queue_saturation_fixture_preserves_accounting() {
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        writer_queue: Some(128),
        events: 2_000,
        hot_pair: true,
        ..headless_cell_config(15, 2_000)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    let output = outcome.output.unwrap_or_else(|| {
        panic!(
            "writer fixture must produce output; acceptance reasons: {:?}",
            outcome.acceptance.reasons
        )
    });
    assert!(
        output.writer_queue_high_water >= 128,
        "the writer queue must reach its configured bound (high-water {})",
        output.writer_queue_high_water
    );
    assert!(
        output.writer_queue_high_water <= 129,
        "the channel bound must hold; only the counter's one-slot \
         observation lag may exceed it (high-water {})",
        output.writer_queue_high_water
    );
    assert_eq!(
        outcome.acceptance.valid,
        output.ledger.reconciled(),
        "valid ⟺ reconciled; reasons={:?} ledger={:?}",
        outcome.acceptance.reasons,
        output.ledger
    );
}

/// Fixture: the mock's outbound queue is bounded hard and the forwarder is
/// stalled. Saturation must be visible and the drain barrier must refuse to
/// certify the run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mock_queue_saturation_fixture_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        fail_inject: Some(FailInject::MockQueueSaturate { capacity: 8 }),
        events: 500,
        limits: Some((8, 2)),
        ..headless_cell_config(14, 200)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        !outcome.acceptance.valid,
        "stalled mock queue must fail acceptance"
    );
    let output = outcome.output.unwrap_or_else(|| {
        panic!(
            "saturation fixture must produce output; acceptance reasons: {:?}",
            outcome.acceptance.reasons
        )
    });
    assert!(
        output.mock.queue_saturated > 0,
        "the bounded queue must record saturation events"
    );
    assert!(
        output.mock.queue_high_water <= 8,
        "the mock queue bound must be respected"
    );
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason == "drain_incomplete"),
        "unexpected reasons: {:?}",
        outcome.acceptance.reasons
    );
}

/// Fixture: shutdown requested before the drain barrier completes. The cell
/// must never certify as success.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_before_drain_fixture_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        fail_inject: Some(FailInject::ShutdownBeforeDrain),
        events: 50,
        ..headless_cell_config(16, 100)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        !outcome.acceptance.valid,
        "shutdown before drain must not produce a success manifest"
    );
    assert!(
        !outcome.acceptance.valid
            && outcome
                .acceptance
                .reasons
                .iter()
                .any(|reason| reason == "drain_incomplete" || reason == "unexplained_drops"),
        "unexpected reasons: {:?}",
        outcome.acceptance.reasons
    );
}

/// Fixture: the index document is corrupt; the cell must not produce a
/// success artifact and the run must fail closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_index_fixture_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("manifests");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("index.json"), b"this is not json").unwrap();

    let config = CellConfig {
        seed: 17,
        symbols: 60,
        decoy_fraction_ppm: 20_000,
        shards: Some(1),
        replicas: 2,
        lifecycle_replicas: 1,
        lifecycle_scenario: LifecycleScenario::None,
        events: 5,
        hot_pair: false,
        uniform_spread: true,
        hot_fraction_ppm: 0,
        hot_event_share_pct: 0,
        hot_selection: HotSelection::Weighted,
        burst: None,
        journal: false,
        limits: Some((20, 2)),
        force_capacity_reject: false,
        fail_inject: None,
        writer_queue: None,
        worktree_dir: None,
        require_clean_worktree: None,
        fault_schedule: None,
        capacity: None,
    };
    let outcome =
        stress_support::runner::run_cell(directory.path(), &config, Some(out.as_path())).await;
    assert!(
        !outcome.acceptance.valid,
        "a corrupt index must flip the cell to a failed artifact, got {:?}",
        outcome.acceptance
    );
    assert_eq!(
        outcome.acceptance.failure_class.as_deref(),
        Some("manifest_index_error"),
        "corrupt index must be reported as manifest_index_error"
    );
    let manifest_files: Vec<_> = std::fs::read_dir(&out)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        manifest_files,
        vec!["index.json".to_owned()],
        "no manifest artifact may be written when the index is malformed"
    );
    let corrupt_index = std::fs::read_to_string(out.join("index.json")).unwrap();
    assert_eq!(
        corrupt_index, "this is not json",
        "corrupt index must not be overwritten"
    );
}

/// The clean-worktree gate must detect tracked modifications and hash the
/// diff, while staying silent about untracked files.
#[test]
fn worktree_gate_detects_dirty_tracked_files() {
    fn git(repo: &std::path::Path, args: &[&str]) {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .status()
            .expect("git must be available");
        assert!(status.success(), "git {args:?} failed");
    }
    let repo = tempfile::tempdir().unwrap();
    git(repo.path(), &["init", "-q"]);
    std::fs::write(repo.path().join("tracked.txt"), "original\n").unwrap();
    git(repo.path(), &["add", "tracked.txt"]);
    git(
        repo.path(),
        &[
            "-c",
            "user.email=stress@example.invalid",
            "-c",
            "user.name=stress",
            "commit",
            "-q",
            "-m",
            "init",
        ],
    );

    let clean = worktree_provenance(repo.path());
    assert_eq!(clean.tracked_clean, Some(true));
    assert!(clean.tracked_modified.is_empty());
    assert!(clean.tracked_diff_sha256.is_none());

    std::fs::write(repo.path().join("tracked.txt"), "modified\n").unwrap();
    let dirty = worktree_provenance(repo.path());
    assert_eq!(dirty.tracked_clean, Some(false));
    assert!(
        dirty
            .tracked_modified
            .iter()
            .any(|entry| entry.contains("tracked.txt"))
    );
    assert!(dirty.tracked_diff_sha256.is_some());
    // Untracked files are recorded but never mark the worktree dirty.
    std::fs::write(repo.path().join("untracked.txt"), "x\n").unwrap();
    let with_untracked = worktree_provenance(repo.path());
    assert_eq!(with_untracked.tracked_clean, Some(false));
    assert_eq!(with_untracked.untracked_count, Some(1));
}

/// Fixture: a run executed from a dirty worktree must refuse to start.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dirty_worktree_fixture_fails_closed() {
    let repo = tempfile::tempdir().unwrap();
    let init = |args: &[&str]| {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(args)
            .status()
            .expect("git must be available");
        assert!(status.success());
    };
    init(&["init", "-q"]);
    std::fs::write(repo.path().join("tracked.txt"), "original\n").unwrap();
    init(&["add", "tracked.txt"]);
    init(&[
        "-c",
        "user.email=stress@example.invalid",
        "-c",
        "user.name=stress",
        "commit",
        "-q",
        "-m",
        "init",
    ]);
    std::fs::write(repo.path().join("tracked.txt"), "dirty\n").unwrap();

    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        symbols: 60,
        events: 5,
        limits: Some((5, 2)),
        worktree_dir: Some(repo.path().to_path_buf()),
        require_clean_worktree: Some(true),
        ..headless_cell_config(18, 60)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        !outcome.acceptance.valid,
        "dirty worktree must fail acceptance"
    );
    assert_eq!(
        outcome.acceptance.failure_class.as_deref(),
        Some("dirty_worktree")
    );
    assert!(
        outcome.output.is_none(),
        "a gated-off cell must not produce collector evidence"
    );
}

/// The same gate must let a clean repository run to completion.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn worktree_gate_accepts_clean_repository() {
    let repo = tempfile::tempdir().unwrap();
    let init = |args: &[&str]| {
        let status = std::process::Command::new("git")
            .arg("-C")
            .arg(repo.path())
            .args(args)
            .status()
            .expect("git must be available");
        assert!(status.success());
    };
    init(&["init", "-q"]);
    std::fs::write(repo.path().join("tracked.txt"), "clean\n").unwrap();
    init(&["add", "tracked.txt"]);
    init(&[
        "-c",
        "user.email=stress@example.invalid",
        "-c",
        "user.name=stress",
        "commit",
        "-q",
        "-m",
        "init",
    ]);

    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        symbols: 60,
        events: 5,
        limits: Some((20, 2)),
        worktree_dir: Some(repo.path().to_path_buf()),
        require_clean_worktree: Some(true),
        ..headless_cell_config(19, 60)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        outcome.acceptance.valid,
        "a clean worktree must pass the gate: {:?}",
        outcome.acceptance.reasons
    );
}

/// Failure reference cell: forces a capacity-plan rejection so
/// a failure manifest is produced on demand (ignored in CI; run locally to
/// regenerate `measurements/stress/reference-*.json`). The manifest preserves
/// the exact planner rejection reason — an infeasible cell is recorded, not
/// silently skipped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "reference artifact generator; run explicitly"]
async fn reference_failed_cell_produces_manifest() {
    assert!(
        std::env::var("STRESS_MANIFEST_OUT").is_ok(),
        "set STRESS_MANIFEST_OUT to produce the artifact"
    );
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        seed: 9,
        symbols: 1_000,
        force_capacity_reject: true,
        ..CellConfig::default()
    };
    let outcome =
        stress_support::runner::run_cell(directory.path(), &config, Some(manifest_out().as_path()))
            .await;
    assert!(
        !outcome.acceptance.valid,
        "capacity rejection must fail acceptance"
    );
    assert!(
        outcome
            .acceptance
            .failure_class
            .as_deref()
            .is_some_and(|class| class.starts_with("collector_terminated")),
        "unexpected failure class: {:?}",
        outcome.acceptance.failure_class
    );
}

/// Reference generator: the successful 4k smoke manifest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "reference artifact generator; run explicitly"]
async fn reference_success_manifest_is_reproducible() {
    assert!(
        std::env::var("STRESS_MANIFEST_OUT").is_ok(),
        "set STRESS_MANIFEST_OUT to produce the artifact"
    );
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        seed: 7,
        symbols: 4_000,
        decoy_fraction_ppm: 20_000,
        shards: Some(1),
        replicas: 2,
        lifecycle_replicas: 1,
        lifecycle_scenario: LifecycleScenario::None,
        events: 200,
        hot_pair: false,
        uniform_spread: true,
        hot_fraction_ppm: 0,
        hot_event_share_pct: 0,
        hot_selection: HotSelection::Weighted,
        burst: None,
        journal: true,
        limits: Some((45, 30)),
        force_capacity_reject: false,
        fail_inject: None,
        writer_queue: None,
        worktree_dir: None,
        require_clean_worktree: None,
        fault_schedule: None,
        capacity: None,
    };
    let outcome =
        stress_support::runner::run_cell(directory.path(), &config, Some(manifest_out().as_path()))
            .await;
    assert!(
        outcome.acceptance.valid,
        "reference smoke must pass: {:?}",
        outcome.acceptance.reasons
    );
}

/// Reference generator: failed manifest for the missing-anchor injection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "reference artifact generator; run explicitly"]
async fn reference_missing_snapshot_manifest() {
    assert!(
        std::env::var("STRESS_MANIFEST_OUT").is_ok(),
        "set STRESS_MANIFEST_OUT to produce the artifact"
    );
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        fail_inject: Some(FailInject::MissingSnapshot { skip_one: 1 }),
        events: 30,
        limits: Some((10, 2)),
        ..headless_cell_config(11, 200)
    };
    let outcome =
        stress_support::runner::run_cell(directory.path(), &config, Some(manifest_out().as_path()))
            .await;
    assert!(!outcome.acceptance.valid);
}

/// Reference generator: failed manifest for the dropped-frame injection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "reference artifact generator; run explicitly"]
async fn reference_dropped_frame_manifest() {
    assert!(
        std::env::var("STRESS_MANIFEST_OUT").is_ok(),
        "set STRESS_MANIFEST_OUT to produce the artifact"
    );
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        fail_inject: Some(FailInject::DroppedFrames { count: 10 }),
        events: 100,
        ..headless_cell_config(13, 300)
    };
    let outcome =
        stress_support::runner::run_cell(directory.path(), &config, Some(manifest_out().as_path()))
            .await;
    assert!(!outcome.acceptance.valid);
}

/// Reference generator: bounded-queue saturation result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "reference artifact generator; run explicitly"]
async fn reference_queue_saturation_manifest() {
    assert!(
        std::env::var("STRESS_MANIFEST_OUT").is_ok(),
        "set STRESS_MANIFEST_OUT to produce the artifact"
    );
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        fail_inject: Some(FailInject::MockQueueSaturate { capacity: 8 }),
        events: 500,
        limits: Some((8, 2)),
        ..headless_cell_config(14, 200)
    };
    let outcome =
        stress_support::runner::run_cell(directory.path(), &config, Some(manifest_out().as_path()))
            .await;
    assert!(!outcome.acceptance.valid);
    let output = outcome.output.unwrap_or_else(|| {
        panic!(
            "saturation fixture must produce output; acceptance reasons: {:?}",
            outcome.acceptance.reasons
        )
    });
    assert!(output.mock.queue_saturated > 0);
}

fn manifest_out() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("STRESS_MANIFEST_OUT").expect("STRESS_MANIFEST_OUT is checked by callers"),
    )
}

/// The success artifact must be complete, indexed and hash-verified before the
/// cell reports success. This is the end-to-end acceptance rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn successful_manifest_is_complete_and_published() {
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("manifests");
    let config = CellConfig {
        seed: 21,
        symbols: 60,
        events: 5,
        limits: Some((20, 2)),
        ..headless_cell_config(21, 60)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, Some(&out)).await;
    assert!(
        outcome.acceptance.valid,
        "reasons={:?}",
        outcome.acceptance.reasons
    );

    let index = stress_support::manifest::read_index(&out.join("index.json")).unwrap();
    let cells = index["cells"].as_object().expect("cells object");
    let (cell_id, entry) = cells.iter().next().expect("one published cell");
    assert_eq!(
        entry["publication_state"].as_str(),
        Some("published"),
        "cell {cell_id} is not published"
    );
    let body_path = out.join(entry["path"].as_str().expect("path"));
    let bytes = std::fs::read(&body_path).unwrap();
    assert_eq!(
        entry["body_sha256"].as_str(),
        Some(fieldbook::util::sha256_hex(&bytes).as_str()),
        "the indexed hash must match the published body"
    );

    let document: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&bytes).unwrap();
    let missing = stress_support::manifest::missing_required_fields(&document);
    assert!(missing.is_empty(), "missing required fields: {missing:?}");
    assert_eq!(document["run_status"].as_str(), Some("success"));
    assert!(
        document["incidents"]["discontinuity_incidents"].is_u64(),
        "incidents.discontinuity_incidents must be an exported count"
    );
}

/// A directory in place of the index is an I/O error, not an empty index, and
/// the cell must publish no body.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn index_directory_fixture_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("manifests");
    std::fs::create_dir_all(out.join("index.json")).unwrap();

    let config = CellConfig {
        seed: 22,
        symbols: 60,
        events: 5,
        limits: Some((20, 2)),
        ..headless_cell_config(22, 60)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, Some(&out)).await;
    assert!(!outcome.acceptance.valid, "an unreadable index must fail");
    assert_eq!(
        outcome.acceptance.failure_class.as_deref(),
        Some("manifest_index_error")
    );
    let entries: Vec<String> = std::fs::read_dir(&out)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        entries,
        vec!["index.json".to_owned()],
        "no body may be published when the index cannot be read"
    );
}

/// A permission error is likewise an error, not an empty index. The test
/// skips itself when the runner is privileged enough to bypass the mode.
#[cfg(unix)]
#[test]
fn unreadable_index_fails_closed() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("index.json");
    std::fs::write(&path, br#"{"schema_version":1,"cells":{}}"#).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read_to_string(&path).is_ok() {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        return;
    }
    let error = stress_support::manifest::read_index(&path)
        .expect_err("an unreadable index must not read as empty");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
}

/// Two-sided accounting: a collector that applies more than the expected
/// ledger must fail with an over-application class. The fixture publishes
/// duplicate wire frames for already-generated logical events; a dedup-correct
/// collector would still apply one copy, so `applied > expected` is exactly
/// the duplicate-application defect the audit describes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn over_application_fixture_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let duplicates = 7usize;
    let config = CellConfig {
        fail_inject: Some(FailInject::OverApplication { duplicates }),
        events: 60,
        // Allow the duplicate frames time to reach both replicas even when
        // the CI machine is loaded by the other cells in this suite.
        limits: Some((20, 15)),
        ..headless_cell_config(16, 200)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        !outcome.acceptance.valid,
        "over-application must fail acceptance: reasons={:?}",
        outcome.acceptance.reasons
    );
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason == "over_application"),
        "expected over_application, got {:?}",
        outcome.acceptance.reasons
    );
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason == "duplicate_application"),
        "expected duplicate_application, got {:?}",
        outcome.acceptance.reasons
    );

    let output = outcome.output.unwrap_or_else(|| {
        panic!(
            "fixture cell must produce output; acceptance reasons: {:?}",
            outcome.acceptance.reasons
        )
    });
    assert_eq!(
        output.ledger.over_applied,
        Some(duplicates as u64),
        "every duplicate frame must be counted as over-application: {:?}",
        output.ledger
    );
    assert_eq!(
        output.ledger.application_shortfall,
        Some(0),
        "the correct ledger was fully applied: {:?}",
        output.ledger
    );
    assert!(
        !output.ledger.reconciled(),
        "an over-applied ledger must not reconcile"
    );
    // Duplicate wire frames are rejected by whichever continuity guard wins
    // the scheduling race: replica suppression or shadow-clock regression.
    // Both are explicit duplicate dispositions; asserting one exact path made
    // this test intermittently fail on a correct collector.
    assert!(
        output
            .ledger
            .suppressed_replica_duplicates
            .unwrap_or(0)
            .saturating_add(output.ledger.shadow_clock_regression.unwrap_or(0))
            > 0,
        "duplicate wire frames must have an explicit dedup disposition: {:?}",
        output.ledger
    );
}

/// The ledger arithmetic is two-sided: a clean ledger reconciles, and each
/// direction of every gap fails independently.
#[test]
fn ledger_reconciliation_is_two_sided() {
    use stress_support::runner::{ledger_acceptance_reasons, two_sided};

    fn ledger(applied: u64, sbe: u64) -> stress_support::runner::EventLedger {
        stress_support::runner::EventLedger {
            generated_events: 100,
            expected_applied: 100,
            applied_events: Some(applied),
            sbe_deltas: Some(sbe),
            suppressed_replica_duplicates: Some(applied),
            unexplained_drops: Some(100u64.saturating_sub(applied)),
            application_shortfall: Some(100u64.saturating_sub(applied)),
            over_applied: Some(applied.saturating_sub(100)),
            persistence_gap: Some(applied.saturating_sub(sbe)),
            persistence_excess: Some(sbe.saturating_sub(applied)),
            enqueued_deltas: Some(100),
            transmitted_deltas: Some(100),
            received_frames: Some(100),
            delta_events_decoded: Some(applied),
            decode_errors: Some(0),
            core_ingress_events: Some(100),
            core_delta_events: Some(applied),
            no_active_source: Some(0),
            unknown_symbol: Some(0),
            non_live: Some(0),
            unassigned_source: Some(0),
            invalid_book: Some(0),
            shadow_clock_regression: Some(0),
            zero_noop: Some(0),
            sbe_conversion_failed: Some(0),
            disposition_shortfall: Some(0),
            disposition_excess: Some(0),
            writer_delta_admissions: Some(applied),
            writer_delta_writes: Some(applied),
            enqueue_transmit_shortfall: Some(0),
            enqueue_transmit_excess: Some(0),
            transmit_decode_shortfall: Some(0),
            transmit_decode_excess: Some(0),
            writer_admission_shortfall: Some(0),
            writer_admission_excess: Some(0),
            writer_write_shortfall: Some(0),
            writer_write_excess: Some(0),
            decode_failure_count: Some(0),
            ..Default::default()
        }
    }

    // Direction arithmetic itself: both sides are computed, not clamped.
    assert_eq!(two_sided(Some(100), Some(100)), (Some(0), Some(0)));
    assert_eq!(two_sided(Some(100), Some(95)), (Some(5), Some(0)));
    assert_eq!(two_sided(Some(100), Some(105)), (Some(0), Some(5)));
    assert_eq!(two_sided(None, Some(100)), (None, None));

    // Real ledger-construction helper, with the wire count first.
    use stress_support::runner::transmit_decode_gaps;
    assert_eq!(
        transmit_decode_gaps(Some(100), Some(100)),
        (Some(0), Some(0))
    );
    assert_eq!(
        transmit_decode_gaps(Some(100), Some(95)),
        (Some(5), Some(0))
    );
    assert_eq!(
        transmit_decode_gaps(Some(100), Some(105)),
        (Some(0), Some(5))
    );

    assert!(ledger(100, 100).reconciled(), "exact accounting reconciles");
    assert!(
        !ledger(90, 90).reconciled(),
        "a shortfall must not reconcile"
    );
    assert!(
        !ledger(110, 110).reconciled(),
        "over-application must not reconcile"
    );
    assert!(
        !ledger(100, 101).reconciled(),
        "persistence excess must not reconcile"
    );
    assert!(
        !ledger(101, 100).reconciled(),
        "persistence gap must not reconcile"
    );

    // The certification path must reject each defect.
    for (mut bad, reason) in [
        (ledger(100, 100), "pre_wire_loss"),
        (ledger(100, 100), "enqueue_excess"),
        (ledger(100, 100), "decode_failures"),
        (ledger(100, 100), "receive_evidence_missing"),
        (ledger(100, 100), "decode_evidence_missing"),
        (ledger(100, 100), "writer_admission_shortfall"),
        (ledger(100, 100), "writer_admission_excess"),
        (ledger(100, 100), "writer_write_shortfall"),
        (ledger(100, 100), "writer_write_excess"),
        (ledger(100, 100), "writer_admission_evidence_missing"),
        (ledger(100, 100), "writer_write_evidence_missing"),
        (ledger(100, 100), "transmit_decode_evidence_missing"),
        (ledger(100, 100), "replica_duplicate_evidence_missing"),
    ] {
        match reason {
            "pre_wire_loss" => bad.enqueue_transmit_shortfall = Some(1),
            "enqueue_excess" => bad.enqueue_transmit_excess = Some(1),
            "decode_failures" => bad.decode_failure_count = Some(1),
            "receive_evidence_missing" => bad.received_frames = None,
            "decode_evidence_missing" => bad.delta_events_decoded = None,
            "writer_admission_shortfall" => bad.writer_admission_shortfall = Some(1),
            "writer_admission_excess" => bad.writer_admission_excess = Some(1),
            "writer_write_shortfall" => bad.writer_write_shortfall = Some(1),
            "writer_write_excess" => bad.writer_write_excess = Some(1),
            "writer_admission_evidence_missing" => bad.writer_delta_admissions = None,
            "writer_write_evidence_missing" => bad.writer_delta_writes = None,
            "transmit_decode_evidence_missing" => bad.transmit_decode_shortfall = None,
            "replica_duplicate_evidence_missing" => bad.suppressed_replica_duplicates = None,
            _ => unreachable!(),
        }
        let reasons = ledger_acceptance_reasons(&bad, 0);
        assert!(
            reasons.iter().any(|found| found == reason),
            "expected {reason} to block certification, got {reasons:?}"
        );
        if reason != "replica_duplicate_evidence_missing" {
            assert!(!bad.reconciled(), "{reason} must not reconcile");
        }
    }
}

#[test]
fn historical_zero_receive_manifest_is_preserved_as_superseded_evidence() {
    // Diagnostic regression: the v3 coverage-mismatch manifest recorded zero
    // received frames because the earlier sampler read per-source status
    // gauges that reset across reconnects. The artifact is immutable evidence;
    // this test pins that it remains byte-for-byte available and is not used
    // as a current certification claim.
    let raw =
        include_str!("../measurements/stress/failed-v3-seed-000b-200-coverage_set_mismatch.json");
    let manifest: serde_json::Value = serde_json::from_str(raw).expect("manifest JSON");
    assert_eq!(manifest["run_status"], "failed");
    assert_eq!(manifest["event_ledger"]["received_frames"], 0);
    assert_eq!(manifest["event_ledger"]["reconciled"], true);
    assert_eq!(manifest["scenario_version"], 3);
}

#[test]
fn counter_reset_never_becomes_a_zero_count() {
    use stress_support::runner::metric_window_delta;
    assert_eq!(metric_window_delta(Some(10), Some(15)), Some(5));
    assert_eq!(metric_window_delta(Some(10), Some(10)), Some(0));
    assert_eq!(metric_window_delta(Some(15), Some(10)), None);
    assert_eq!(metric_window_delta(None, Some(10)), None);
    assert_eq!(metric_window_delta(Some(10), None), None);
}

/// M5 profile: 4,000 instruments with exactly 5% designated hot instruments
/// receiving 80% of deltas. The run must reconcile the full event ledger and
/// certify the exact universe; no throughput claim is made here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_hot_quiet_4000_cell_reconciles_and_certifies() {
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        seed: 23,
        symbols: 4_000,
        decoy_fraction_ppm: 20_000,
        shards: Some(2),
        replicas: 2,
        lifecycle_replicas: 1,
        lifecycle_scenario: LifecycleScenario::None,
        events: 400,
        hot_pair: false,
        uniform_spread: false,
        hot_fraction_ppm: 50_000,
        hot_event_share_pct: 80,
        hot_selection: HotSelection::Weighted,
        burst: None,
        journal: true,
        limits: Some((45, 30)),
        force_capacity_reject: false,
        fail_inject: None,
        writer_queue: None,
        worktree_dir: None,
        require_clean_worktree: None,
        fault_schedule: None,
        capacity: None,
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        outcome.acceptance.valid,
        "mixed hot/quiet cell failed acceptance: reasons={:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.expect("valid cell must carry output");
    assert_eq!(
        output.hot_tickers, 200,
        "5% of 4,000 instruments must be hot"
    );
    assert_eq!(output.events_published, 400);
    assert_eq!(
        output.hot_events + output.cold_events,
        output.events_published,
        "weighted draws must split the workload into disjoint hot/cold sets"
    );
    assert!(output.hot_events > 0 && output.cold_events > 0);
    assert_eq!(output.sbe_deltas, 400);
    assert!(
        output.ledger.reconciled(),
        "ledger must reconcile: {:?}",
        output.ledger
    );
    assert_eq!(output.ledger.unexplained_drops, Some(0));
    assert_eq!(output.ledger.persistence_gap, Some(0));
    let coverage = output.coverage.as_ref().expect("coverage must be present");
    assert_eq!(coverage.expected, 4_000);
    assert_eq!(coverage.anchored, 4_000);
    assert!(output.verify_valid && output.completeness_valid && output.journal_complete);
}

/// Reference generator for the M5 mixed workload manifest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "reference artifact generator; run explicitly"]
async fn reference_mixed_hot_quiet_manifest_is_reproducible() {
    assert!(
        std::env::var("STRESS_MANIFEST_OUT").is_ok(),
        "set STRESS_MANIFEST_OUT to produce the artifact"
    );
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        seed: 23,
        symbols: 4_000,
        decoy_fraction_ppm: 20_000,
        shards: Some(2),
        replicas: 2,
        lifecycle_replicas: 1,
        lifecycle_scenario: LifecycleScenario::None,
        events: 400,
        hot_pair: false,
        uniform_spread: false,
        hot_fraction_ppm: 50_000,
        hot_event_share_pct: 80,
        hot_selection: HotSelection::Weighted,
        burst: None,
        journal: true,
        limits: Some((45, 30)),
        force_capacity_reject: false,
        fail_inject: None,
        writer_queue: None,
        worktree_dir: None,
        require_clean_worktree: None,
        fault_schedule: None,
        capacity: None,
    };
    let outcome =
        stress_support::runner::run_cell(directory.path(), &config, Some(manifest_out().as_path()))
            .await;
    assert!(
        outcome.acceptance.valid,
        "reference mixed cell failed: {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.expect("valid cell must carry output");
    assert_eq!(output.hot_tickers, 200);
    assert!(output.ledger.reconciled());
}

/// M5 exact-quota profile: the 4,000-instrument universe receives 320 hot and
/// 80 cold logical deltas. The seed pins both hot-set membership and event assignment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_hot_quiet_exact_4000_cell_assigns_320_hot_events() {
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        seed: 29,
        symbols: 4_000,
        decoy_fraction_ppm: 20_000,
        shards: Some(2),
        replicas: 2,
        lifecycle_replicas: 1,
        lifecycle_scenario: LifecycleScenario::None,
        events: 400,
        hot_pair: false,
        uniform_spread: false,
        hot_fraction_ppm: 50_000,
        hot_event_share_pct: 80,
        hot_selection: HotSelection::ExactQuota,
        burst: None,
        journal: true,
        limits: Some((45, 30)),
        force_capacity_reject: false,
        fail_inject: None,
        writer_queue: None,
        worktree_dir: None,
        require_clean_worktree: None,
        fault_schedule: None,
        capacity: None,
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        outcome.acceptance.valid,
        "exact-quota cell failed acceptance: {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.expect("valid cell must carry output");
    assert_eq!(output.hot_tickers, 200);
    assert_eq!(
        output.hot_events, 320,
        "exactly 80% of 400 events must be hot"
    );
    assert_eq!(output.cold_events, 80);
    assert_eq!(
        output.hot_events + output.cold_events,
        output.events_published
    );
    assert!(output.ledger.reconciled(), "ledger: {:?}", output.ledger);
    let universe = SyntheticUniverse::generate(29, 4_000, 20_000);
    let hot = universe.hot_tickers(50_000);
    assert_eq!(hot.len(), 200);
    assert!(hot.iter().all(|ticker| ticker.starts_with("STRESS-")));
}

/// Reference generator for the exact-quota M5 profile.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "reference artifact generator; run explicitly"]
async fn reference_exact_hot_quiet_manifest_is_reproducible() {
    assert!(
        std::env::var("STRESS_MANIFEST_OUT").is_ok(),
        "set STRESS_MANIFEST_OUT to produce the artifact"
    );
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        seed: 29,
        symbols: 4_000,
        decoy_fraction_ppm: 20_000,
        shards: Some(2),
        replicas: 2,
        lifecycle_replicas: 1,
        lifecycle_scenario: LifecycleScenario::None,
        events: 400,
        hot_pair: false,
        uniform_spread: false,
        hot_fraction_ppm: 50_000,
        hot_event_share_pct: 80,
        hot_selection: HotSelection::ExactQuota,
        burst: None,
        journal: true,
        limits: Some((45, 30)),
        force_capacity_reject: false,
        fail_inject: None,
        writer_queue: None,
        worktree_dir: None,
        require_clean_worktree: None,
        fault_schedule: None,
        capacity: None,
    };
    let outcome =
        stress_support::runner::run_cell(directory.path(), &config, Some(manifest_out().as_path()))
            .await;
    assert!(outcome.acceptance.valid, "{:?}", outcome.acceptance.reasons);
    let output = outcome.output.expect("valid cell must carry output");
    assert_eq!(output.hot_events, 320);
    assert_eq!(output.cold_events, 80);
}

// ---------- M5.2 deterministic burst workloads ----------

/// The 4,000-instrument exact/role workload reused for burst cells. Only the
/// phase decomposition changes; seed, universe, hot set and event budget stay
/// identical to the frozen M5.1 exact profile.
fn burst_cell_config(profile: BurstProfile, seed: u64, selection: HotSelection) -> CellConfig {
    CellConfig {
        seed,
        symbols: 4_000,
        decoy_fraction_ppm: 20_000,
        shards: Some(2),
        replicas: 2,
        lifecycle_replicas: 1,
        lifecycle_scenario: LifecycleScenario::None,
        events: 400,
        hot_pair: false,
        uniform_spread: false,
        hot_fraction_ppm: 50_000,
        hot_event_share_pct: 80,
        hot_selection: selection,
        burst: Some(profile),
        journal: true,
        limits: Some((45, 30)),
        force_capacity_reject: false,
        fail_inject: None,
        writer_queue: None,
        worktree_dir: None,
        require_clean_worktree: None,
        fault_schedule: None,
        capacity: None,
    }
}

/// Drive one burst cell and prove the full M5.2 contract: acceptance, exact
/// per-phase publication with cumulative drain barriers, reconciled ledger,
/// exact coverage, SBE/completeness/journal verification, empty fault
/// schedule and a manifest that records the explicit workload schedule.
async fn assert_burst_cell(
    profile: BurstProfile,
    seed: u64,
    selection: HotSelection,
    manifest_out: Option<&std::path::Path>,
) -> CellOutcome {
    let directory = tempfile::tempdir().unwrap();
    let scratch_manifests = directory.path().join("manifests");
    let out = manifest_out.unwrap_or(scratch_manifests.as_path());
    let config = burst_cell_config(profile, seed, selection);
    let outcome = stress_support::runner::run_cell(directory.path(), &config, Some(out)).await;
    assert!(
        outcome.acceptance.valid,
        "burst {profile:?} cell failed acceptance: {:?}; ledger={:?}",
        outcome.acceptance.reasons,
        outcome.output.as_ref().map(|o| &o.ledger)
    );
    let phase_count = outcome
        .output
        .as_ref()
        .expect("valid cell must carry output")
        .phase_results
        .len();
    {
        let output = outcome
            .output
            .as_ref()
            .expect("valid cell must carry output");

        // Schedule is explicit, deterministic and fault-free for M5.2.
        assert_eq!(output.schedule.profile, profile.label());
        assert_eq!(output.schedule.seed, seed);
        assert_eq!(output.schedule.instrument_count, 4_000);
        assert_eq!(output.schedule.eligible_count, 4_000);
        assert_eq!(output.schedule.expected_total_events, 400);
        assert!(output.schedule.fault_schedule.is_empty());
        assert_eq!(output.schedule.hot_set.member_count, 200);
        assert_eq!(output.schedule.phases.len(), phase_count);

        // Every phase published its exact declared count, drained, and the
        // cumulative drain target matches the events published so far.
        let mut running = 0u64;
        for (declared, actual) in output.schedule.phases.iter().zip(&output.phase_results) {
            assert_eq!(
                actual.published, declared.events,
                "phase {} count",
                actual.name
            );
            running += actual.published as u64;
            assert_eq!(actual.cumulative_expected, running);
            assert!(
                actual.drain_completed,
                "phase {} did not drain",
                actual.name
            );
        }
        assert_eq!(running, 400);
        let phase_total: usize = output
            .phase_results
            .iter()
            .map(|phase| phase.published)
            .sum();
        assert_eq!(phase_total, 400);
        assert_eq!(output.events_published, 400);
        assert_eq!(output.hot_events + output.cold_events, 400);
        assert!(output.drain_completed, "final drain did not complete");

        // One final ledger reconciles the whole multi-phase run.
        assert!(output.ledger.reconciled(), "ledger: {:?}", output.ledger);
        assert_eq!(output.ledger.unexplained_drops, Some(0));
        assert_eq!(output.ledger.application_shortfall, Some(0));
        assert_eq!(output.ledger.over_applied, Some(0));
        assert_eq!(output.ledger.persistence_gap, Some(0));
        assert_eq!(output.applied_events, Some(400));
        assert_eq!(output.sbe_deltas, 400);

        // Exact coverage and independent verification still hold at final.
        let coverage = output.coverage.as_ref().expect("coverage must be present");
        assert!(coverage.valid, "coverage invalid: {coverage:?}");
        assert_eq!(coverage.expected, 4_000);
        assert_eq!(coverage.acknowledged, 4_000);
        assert_eq!(coverage.anchored, 4_000);
        assert!(output.verify_valid, "SBE verification failed");
        assert!(
            output.completeness_valid,
            "completeness verification failed"
        );
        assert!(output.journal_complete, "journal did not finalize");
        assert!(
            output.decoy_absent,
            "an MVE/closed decoy entered the capture"
        );

        // Queues drained: no mock frame remains in flight and every wire /
        // writer stage reconciles in both directions.
        assert_eq!(output.mock.in_flight, 0);
        assert_eq!(output.ledger.enqueue_transmit_shortfall, Some(0));
        assert_eq!(output.ledger.enqueue_transmit_excess, Some(0));
        assert_eq!(output.ledger.writer_write_shortfall, Some(0));
        assert_eq!(output.ledger.writer_write_excess, Some(0));
    }

    // The manifest carries the declared schedule and per-phase drain evidence.
    let index = stress_support::manifest::read_index(&out.join("index.json")).unwrap();
    let cells = index["cells"].as_object().expect("cells object");
    assert_eq!(cells.len(), 1);
    let (cell_id, entry) = cells.iter().next().expect("one published cell");
    assert_eq!(entry["publication_state"].as_str(), Some("published"));
    assert!(
        cell_id.contains(profile.label()),
        "cell id {cell_id} must carry the profile label"
    );
    let bytes = std::fs::read(out.join(entry["path"].as_str().unwrap())).unwrap();
    let document: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&bytes).unwrap();
    assert!(
        stress_support::manifest::missing_required_fields(&document).is_empty(),
        "burst manifest is incomplete"
    );
    let expected_id = format!("{}-seed-{seed:04x}-4000", profile.label());
    let schedule = &document["workload_schedule"];
    assert_eq!(schedule["workload_id"].as_str(), Some(expected_id.as_str()));
    assert_eq!(schedule["profile"].as_str(), Some(profile.label()));
    assert_eq!(schedule["seed"].as_u64(), Some(seed));
    assert_eq!(schedule["instrument_count"].as_u64(), Some(4_000));
    assert_eq!(schedule["expected_total_events"].as_u64(), Some(400));
    assert_eq!(schedule["phases"].as_array().unwrap().len(), phase_count);
    assert!(schedule["hot_set"]["sha256"].is_string());
    assert_eq!(schedule["fault_schedule"].as_array().unwrap().len(), 0);
    assert_eq!(
        document["delivery"]["phases"].as_array().unwrap().len(),
        phase_count
    );
    assert_eq!(document["scenario_version"].as_u64(), Some(16));
    outcome
}

/// Step: one sustained doubling of the declared rate. Three phases, exact
/// published counts 100 / 200 / 100, fully drained between phases.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn burst_step_cell_reconciles_all_phases() {
    let outcome = assert_burst_cell(BurstProfile::Step, 31, HotSelection::ExactQuota, None).await;
    let counts: Vec<usize> = outcome
        .output
        .as_ref()
        .unwrap()
        .phase_results
        .iter()
        .map(|phase| phase.published)
        .collect();
    assert_eq!(counts, vec![100, 200, 100]);
    let multipliers: Vec<u64> = outcome
        .output
        .as_ref()
        .unwrap()
        .schedule
        .phases
        .iter()
        .map(|phase| u64::from(phase.rate_multiplier))
        .collect();
    assert_eq!(multipliers, vec![1, 2, 1]);
}

/// Impulse: one concentrated spike. Three phases, exact published counts
/// 40 / 280 / 80, fully drained between phases.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn burst_impulse_cell_reconciles_all_phases() {
    let outcome =
        assert_burst_cell(BurstProfile::Impulse, 37, HotSelection::ExactQuota, None).await;
    let counts: Vec<usize> = outcome
        .output
        .as_ref()
        .unwrap()
        .phase_results
        .iter()
        .map(|phase| phase.published)
        .collect();
    assert_eq!(counts, vec![40, 280, 80]);
    let multipliers: Vec<u64> = outcome
        .output
        .as_ref()
        .unwrap()
        .schedule
        .phases
        .iter()
        .map(|phase| u64::from(phase.rate_multiplier))
        .collect();
    assert_eq!(multipliers, vec![1, 5, 1]);
}

/// Ignored reference generator for the Step burst manifest. Run explicitly
/// with `STRESS_MANIFEST_OUT` set; no performance claim is attached to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "reference artifact generator; run explicitly"]
async fn reference_burst_step_manifest_is_reproducible() {
    assert!(
        std::env::var("STRESS_MANIFEST_OUT").is_ok(),
        "set STRESS_MANIFEST_OUT to produce the artifact"
    );
    assert_burst_cell(
        BurstProfile::Step,
        31,
        HotSelection::ExactQuota,
        Some(manifest_out().as_path()),
    )
    .await;
}

// ---------- M5.5 backpressure workload profiles ----------

/// Read the single manifest body published into a scratch directory. The
/// index is the commit point; only published bodies are considered evidence.
fn read_single_manifest(out: &std::path::Path) -> serde_json::Value {
    let index = stress_support::manifest::read_index(&out.join("index.json")).unwrap();
    let cells = index["cells"].as_object().expect("cells object");
    assert_eq!(cells.len(), 1, "one published cell per scratch directory");
    let entry = cells.values().next().expect("one cell");
    assert_eq!(entry["publication_state"].as_str(), Some("published"));
    let body = out.join(entry["path"].as_str().expect("path"));
    serde_json::from_slice(&std::fs::read(body).expect("manifest body")).expect("manifest JSON")
}

fn assert_profile_manifest_shape(document: &serde_json::Value, profile: &str) {
    assert_eq!(document["scenario_version"], 16);
    assert_eq!(document["backpressure"]["profile"], profile);
    let boundary = document["backpressure"]["boundary"].as_str().unwrap_or("");
    assert!(!boundary.is_empty(), "boundary must be named");
    assert!(
        document["backpressure"]["disposition"].is_string(),
        "terminal disposition must be explicit"
    );
    assert!(
        document["backpressure"]["admission"].is_string()
            && document["backpressure"]["drop_reject_policy"].is_string()
            && document["backpressure"]["recovery"].is_string(),
        "capacity/admission/timeout/policy/recovery must all be present"
    );
    assert!(document["backpressure"]["capacity"].is_u64());
    assert!(document["backpressure"]["timeout_ms"].is_u64());
    for state in [
        "accepted_waiting",
        "rejected",
        "dropped",
        "completed",
        "uncertain_acknowledgement",
    ] {
        assert!(
            document["backpressure"]["states"][state].is_u64(),
            "state {state} must be a distinct count"
        );
    }
    assert!(
        document["backpressure"]["journal"]["state"].is_string()
            && document["backpressure"]["journal"]["complete"].is_boolean(),
        "journal evidence must be explicit"
    );
    for field in ["verify_valid", "completeness_valid"] {
        let value = &document["backpressure"]["sbe"][field];
        assert!(
            value.is_boolean() || value["value"].is_null(),
            "SBE evidence for {field} must be a verdict or an explicit unavailable marker"
        );
    }
    assert!(
        stress_support::manifest::missing_required_fields(
            document.as_object().expect("manifest object"),
        )
        .is_empty()
            || document["run_status"].as_str() == Some("failed")
            || document["run_status"].as_str() == Some("incomplete"),
        "a failed cell may carry missing evidence; a success cell may not"
    );
}

/// Boundary 1: the mock outbound queue is bounded hard. Frames that find it
/// full are explicit drops; admitted frames complete only before the stall.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mock_outbound_queue_profile_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("manifests");
    let config = CellConfig {
        seed: 31,
        fail_inject: Some(FailInject::MockQueueSaturate { capacity: 8 }),
        events: 500,
        limits: Some((8, 2)),
        ..headless_cell_config(31, 200)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, Some(&out)).await;
    assert!(
        !outcome.acceptance.valid,
        "a saturated mock queue must not certify: {:?}",
        outcome.acceptance.reasons
    );
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason == "mock_outbound_queue_dropped"),
        "dropped frames must be classified as drops: {:?}",
        outcome.acceptance.reasons
    );
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason == "drain_incomplete"),
        "the stalled boundary must fail the drain barrier: {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.as_ref().expect("saturation cell has output");
    assert!(output.mock.queue_saturated > 0);
    assert!(
        output.mock.queue_high_water <= 8,
        "the configured queue bound must hold"
    );
    assert_eq!(output.ledger.enqueue_transmit_shortfall, Some(0));
    assert!(
        output.verify_valid && output.completeness_valid,
        "SBE verification is independent of transport backpressure"
    );

    let document = read_single_manifest(&out);
    assert_profile_manifest_shape(&document, "mock_queue_saturation");
    assert_eq!(document["backpressure"]["disposition"], "dropped");
    assert_eq!(document["backpressure"]["capacity"], 8);
    assert_eq!(
        document["backpressure"]["states"]["dropped"].as_u64(),
        Some(output.mock.queue_saturated)
    );
    assert_eq!(
        document["backpressure"]["states"]["accepted_waiting"].as_u64(),
        Some(output.mock.in_flight)
    );
    assert_eq!(document["mock_transport"]["forwarder_delay_ms"], 0);
}

/// Boundary 2: the production writer queue is bounded. Admission waits up to
/// the configured timeout; a timed-out send is rejected and never enqueued,
/// while accepted messages drain at shutdown and the ledger still reconciles.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn writer_queue_profile_preserves_accounting() {
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("manifests");
    let config = CellConfig {
        seed: 32,
        writer_queue: Some(128),
        events: 2_000,
        hot_pair: true,
        ..headless_cell_config(32, 2_000)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, Some(&out)).await;
    let output = outcome.output.as_ref().expect("writer cell has output");
    assert!(
        output.writer_queue_high_water >= 128 && output.writer_queue_high_water <= 129,
        "the writer queue must reach and respect its bound: {}",
        output.writer_queue_high_water
    );
    assert_eq!(
        outcome.acceptance.valid,
        output.ledger.reconciled(),
        "reasons={:?} ledger={:?}",
        outcome.acceptance.reasons,
        output.ledger
    );
    assert!(outcome.acceptance.valid, "{:?}", outcome.acceptance.reasons);
    assert!(output.journal_complete, "accepted records must finalize");
    assert!(output.verify_valid && output.completeness_valid);

    let document = read_single_manifest(&out);
    assert_profile_manifest_shape(&document, "writer_queue_saturation");
    assert_eq!(document["backpressure"]["disposition"], "completed");
    assert_eq!(document["backpressure"]["capacity"], 128);
    assert_eq!(document["backpressure"]["timeout_ms"], 10_000);
    assert_eq!(
        document["backpressure"]["states"]["rejected"].as_u64(),
        Some(0),
        "no send may be rejected while the writer drains"
    );
    assert_eq!(
        document["backpressure"]["states"]["dropped"].as_u64(),
        Some(0),
        "the writer never drops silently"
    );
    assert_eq!(document["backpressure"]["journal"]["complete"], true);
}

/// Boundary 3: a slow socket consumer. Frames are admitted into the ordinary
/// bounded queue (no drop, no rejection) but complete after the injected
/// delay, so the queue holds accepted-but-waiting work at the drain deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_downstream_profile_fails_closed_with_accepted_waiting() {
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("manifests");
    let config = CellConfig {
        seed: 33,
        fail_inject: Some(FailInject::SlowDownstream { delay_ms: 20 }),
        events: 300,
        limits: Some((8, 2)),
        ..headless_cell_config(33, 200)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, Some(&out)).await;
    assert!(
        !outcome.acceptance.valid,
        "a slow downstream must not certify: {:?}",
        outcome.acceptance.reasons
    );
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason == "slow_downstream_accepted_waiting"),
        "waiting frames must be classified distinctly: {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.as_ref().expect("slow cell has output");
    assert!(
        output.mock.in_flight > 0,
        "frames must still be waiting at the observation point"
    );
    assert_eq!(
        output.mock.queue_saturated, 0,
        "the slow profile must not silently become a drop profile"
    );
    assert!(
        output.ledger.application_shortfall.unwrap_or(0) > 0,
        "undelivered frames must show as an application shortfall"
    );

    let document = read_single_manifest(&out);
    assert_profile_manifest_shape(&document, "slow_downstream");
    assert_eq!(
        document["backpressure"]["disposition"],
        "accepted_but_waiting"
    );
    assert_eq!(document["mock_transport"]["forwarder_delay_ms"], 20);
    assert!(
        document["backpressure"]["states"]["accepted_waiting"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert_eq!(document["backpressure"]["states"]["dropped"], 0);
    assert_eq!(document["backpressure"]["states"]["rejected"], 0);
}

/// Boundary 4: raw-frame journal admission. A one-record queue plus an fsync
/// per record makes enqueue timeouts reject records; the rejection latches the
/// run failed and stops forwarding before those deltas are applied. ENOSPC is
/// not injected (see the workload spec limitation).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn journal_storage_pressure_profile_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("manifests");
    let config = CellConfig {
        seed: 34,
        fail_inject: Some(FailInject::JournalQueuePressure {
            queue_capacity: 1,
            enqueue_timeout_ms: 1,
        }),
        events: 2000,
        limits: Some((5, 1)),
        ..headless_cell_config(34, 50)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, Some(&out)).await;
    assert!(
        !outcome.acceptance.valid,
        "journal admission rejection must not certify: {:?}",
        outcome.acceptance.reasons
    );
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason == "journal_pressure_rejected"),
        "journal rejection must be named, not folded into a generic error: {:?}",
        outcome.acceptance.reasons
    );
    assert_eq!(
        outcome.acceptance.failure_class.as_deref(),
        Some("journal_pressure_rejected"),
        "the boundary must be the primary class, not the collector symptom"
    );
    // A fatal journal rejection can stop the collector before a capture is
    // produced, or after a report carrying a failed journal verification.
    // Both outcomes are fail-closed; the manifest must still carry the
    // rejection state and the collector's terminal error.
    if let Some(output) = outcome.output.as_ref() {
        let finalized = output
            .report
            .journal_verification
            .as_ref()
            .is_some_and(|verification| {
                verification.state == RunState::Finalized && verification.complete
            });
        if finalized {
            assert!(
                !outcome.acceptance.valid,
                "a finalized journal does not certify a rejected capture"
            );
        } else {
            let invalid = output
                .report
                .journal_verification
                .as_ref()
                .is_some_and(|verification| {
                    verification.state == RunState::Failed || !verification.complete
                });
            let verdict = format!(
                "a fatal journal rejection cannot certify a capture: {:?}",
                output.report.journal_verification
            );
            assert!(invalid, "{verdict}");
        }
    }

    let document = read_single_manifest(&out);
    assert_profile_manifest_shape(&document, "journal_storage_pressure");
    assert_eq!(document["backpressure"]["disposition"], "rejected");
    assert_eq!(document["backpressure"]["capacity"], 1);
    assert_eq!(document["backpressure"]["timeout_ms"], 1);
    assert_eq!(document["backpressure"]["states"]["rejected"], 1);
    assert_eq!(document["backpressure"]["states"]["dropped"], 0);
    assert_eq!(document["backpressure"]["journal"]["state"], "failed");
    assert_eq!(document["backpressure"]["journal"]["complete"], false);
    let errors = document["backpressure"]["journal"]["errors"]
        .as_array()
        .expect("terminal journal errors");
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .is_some_and(|text| text.contains("journal queue stayed full"))),
        "the collector's own rejection detail must survive in the manifest: {errors:?}"
    );
}

/// Boundary 5: shutdown before the drain barrier. The frame's fate was not
/// observable, so it is classified uncertain rather than dropped or completed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shutdown_uncertain_acknowledgement_profile_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("manifests");
    let config = CellConfig {
        seed: 35,
        fail_inject: Some(FailInject::ShutdownBeforeDrain),
        events: 50,
        ..headless_cell_config(35, 100)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, Some(&out)).await;
    assert!(!outcome.acceptance.valid);
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason == "uncertain_acknowledgement"),
        "an unobservable outcome must be classified as uncertain: {:?}",
        outcome.acceptance.reasons
    );
    let document = read_single_manifest(&out);
    assert_profile_manifest_shape(&document, "shutdown_uncertain_acknowledgement");
    assert_eq!(
        document["backpressure"]["disposition"],
        "uncertain_acknowledgement"
    );
    assert!(
        document["backpressure"]["states"]["uncertain_acknowledgement"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert_eq!(document["backpressure"]["states"]["dropped"], 0);
}

/// Combined M5.5 workload: the full 4,000-instrument hot/quiet profile with a
/// single writer-queue bound injection. There is no lifecycle, disconnect or
/// chaos injection; the cell must still certify under the visible backpressure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backpressure_combined_hot_quiet_writer_queue_4000_certifies() {
    let directory = tempfile::tempdir().unwrap();
    let out = directory.path().join("manifests");
    let config = CellConfig {
        seed: 36,
        symbols: 4_000,
        decoy_fraction_ppm: 20_000,
        shards: Some(2),
        replicas: 2,
        lifecycle_replicas: 1,
        events: 400,
        hot_pair: false,
        uniform_spread: false,
        hot_fraction_ppm: 50_000,
        hot_event_share_pct: 80,
        hot_selection: HotSelection::Weighted,
        journal: true,
        limits: Some((45, 10)),
        writer_queue: Some(128),
        ..CellConfig::default()
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, Some(&out)).await;
    assert!(
        outcome.acceptance.valid,
        "combined backpressure cell failed: {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.as_ref().expect("valid cell has output");
    assert_eq!(output.hot_tickers, 200);
    assert_eq!(output.hot_events + output.cold_events, 400);
    assert!(output.hot_events > 0 && output.cold_events > 0);
    assert!(
        output.writer_queue_high_water >= 128 && output.writer_queue_high_water <= 129,
        "the single injection must remain bounded: {}",
        output.writer_queue_high_water
    );
    assert!(output.ledger.reconciled(), "ledger: {:?}", output.ledger);
    assert_eq!(output.sbe_deltas, 400);
    assert!(output.verify_valid && output.completeness_valid && output.journal_complete);
    let coverage = output.coverage.as_ref().expect("coverage");
    assert_eq!(coverage.expected, 4_000);
    assert_eq!(coverage.anchored, 4_000);

    let document = read_single_manifest(&out);
    assert_profile_manifest_shape(&document, "writer_queue_saturation");
    assert_eq!(document["backpressure"]["journal"]["complete"], true);
    assert_eq!(document["backpressure"]["sbe"]["deltas"], 400);
}

/// Ignored reference generator for the M5.5 boundary profiles. Uses the same
/// `STRESS_MANIFEST_OUT` publication protocol and v16 cell ids as the other
/// reference generators; prior evidence is never overwritten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "reference artifact generator; run explicitly"]
async fn reference_backpressure_profiles_manifest_is_reproducible() {
    assert!(
        std::env::var("STRESS_MANIFEST_OUT").is_ok(),
        "set STRESS_MANIFEST_OUT to produce the artifact"
    );
    let out = manifest_out();
    std::fs::create_dir_all(&out).unwrap();
    let profiles = [
        (
            41u64,
            "mock_queue_saturation",
            Some(FailInject::MockQueueSaturate { capacity: 8 }),
            None,
        ),
        (42, "writer_queue_saturation", None, Some(128usize)),
        (
            43,
            "slow_downstream",
            Some(FailInject::SlowDownstream { delay_ms: 20 }),
            None,
        ),
        (
            44,
            "journal_storage_pressure",
            Some(FailInject::JournalQueuePressure {
                queue_capacity: 1,
                enqueue_timeout_ms: 1,
            }),
            None,
        ),
    ];
    for (seed, expected, inject, writer_queue) in profiles {
        let directory = tempfile::tempdir().unwrap();
        let config = CellConfig {
            seed,
            fail_inject: inject,
            writer_queue,
            events: 200,
            limits: Some((20, 2)),
            ..headless_cell_config(seed, 200)
        };
        let outcome =
            stress_support::runner::run_cell(directory.path(), &config, Some(out.as_path())).await;
        let document = build_cell_manifest_for_reference(&out, seed);
        assert_eq!(document["scenario_version"], 16);
        assert_eq!(document["backpressure"]["profile"], expected);
        assert!(
            !outcome.acceptance.valid || expected == "writer_queue_saturation",
            "profile {expected} produced an unexpected verdict: {:?}",
            outcome.acceptance.reasons
        );
    }
}

/// Locate one reference cell by its seed in the published index.
fn build_cell_manifest_for_reference(out: &std::path::Path, seed: u64) -> serde_json::Value {
    let index = stress_support::manifest::read_index(&out.join("index.json")).unwrap();
    let cells = index["cells"].as_object().expect("cells object");
    let entry = cells
        .values()
        .find(|entry| entry["seed"] == seed)
        .unwrap_or_else(|| panic!("no published cell for seed {seed}"));
    let body = out.join(entry["path"].as_str().expect("path"));
    serde_json::from_slice(&std::fs::read(body).expect("manifest body")).expect("manifest JSON")
}

// ---------------------------------------------------------------------------
// M5.4 deterministic disconnect and recovery sweeps (scenario_version 16).
// ---------------------------------------------------------------------------

fn sweep_config(seed: u64, symbols: usize, events: usize, profile: SweepProfile) -> CellConfig {
    let base = CellConfig {
        events,
        // A reconnect storm needs headroom on a loaded host. The wait stays
        // bounded and a real stall still fails the cell.
        limits: Some((60, 60)),
        ..headless_cell_config(seed, symbols)
    };
    CellConfig::for_sweep(base, profile)
}

/// Decode the capture and prove per-symbol SBE receive timestamps never regress.
/// Snapshots and deltas both carry a receive time; a recovered book must have
/// monotonic receive order even across a failover snapshot.
fn assert_sbe_receive_times_monotonic(capture: &std::path::Path) {
    use fieldbook::util::{
        AlignedSbeReader, OrderbookSchema,
        dtos::orderbook::{AnyMessage, PriceLevelUpdateDomain, SnapshotDomain},
    };
    let mut reader = AlignedSbeReader::<OrderbookSchema>::open_auto(capture).unwrap();
    let mut last: std::collections::BTreeMap<String, i64> = std::collections::BTreeMap::new();
    while let Some(message) = reader.read_msg().unwrap() {
        let (symbol, received_at_us) = match message {
            AnyMessage::Snapshot(decoder) => {
                let snapshot = SnapshotDomain::try_from_decoder(decoder).unwrap();
                (snapshot.symbol, snapshot.received_at.timestamp_micros())
            }
            AnyMessage::PriceLevelUpdate(decoder) => {
                let update = PriceLevelUpdateDomain::try_from_decoder(decoder).unwrap();
                (update.symbol, update.received_at.timestamp_micros())
            }
            _ => continue,
        };
        let previous = last.entry(symbol.clone()).or_insert(i64::MIN);
        assert!(
            *previous <= received_at_us,
            "SBE receive time regressed for {symbol}: {previous} -> {received_at_us}"
        );
        *previous = received_at_us;
    }
    assert!(
        !last.is_empty(),
        "capture must carry at least one anchored symbol"
    );
}

fn assert_disconnect_success(output: &stress_support::runner::CellOutput, events: usize) {
    assert!(
        output.ledger.reconciled(),
        "disconnect sweep must reconcile accounting: {:?}",
        output.ledger
    );
    assert_eq!(output.ledger.unexplained_drops, Some(0));
    assert_eq!(output.ledger.persistence_gap, Some(0));
    assert_eq!(output.ledger.disposition_shortfall, Some(0));
    assert_eq!(output.ledger.disposition_excess, Some(0));
    assert_eq!(output.sbe_deltas, events as u64);
    assert!(output.verify_valid, "SBE verify failed after disconnect");
    assert!(
        output.completeness_valid,
        "completeness failed after disconnect"
    );
    assert!(
        output.journal_complete,
        "journal incomplete after disconnect"
    );
    assert!(output.decoy_absent);
    let coverage = output.coverage.as_ref().expect("coverage must be present");
    assert!(
        coverage.valid,
        "coverage invalid after disconnect: {coverage:?}"
    );
    assert_eq!(coverage.expected, coverage.anchored);
    assert!(
        output.writer_queue_high_water <= 4_097,
        "writer queue bound must hold (high-water {})",
        output.writer_queue_high_water
    );
    assert_eq!(output.mock.queue_saturated, 0);
    assert_sbe_receive_times_monotonic(&std::path::PathBuf::from(&output.report.output_path));
}

/// D1: losing the newest (standby-role) replica must open a replacement socket
/// and keep the surviving active book anchored without losing a workload delta.
/// No continuity incident is expected when a standby is the target.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnect_standby_replica_loss_recovers_and_reconciles() {
    let directory = tempfile::tempdir().unwrap();
    let config = sweep_config(31, 200, 60, SweepProfile::StandbyReplicaLoss);
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        outcome.acceptance.valid,
        "single standby replica loss failed: {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.expect("valid cell must carry output");
    assert_eq!(output.recovery.len(), 1);
    let recovery = &output.recovery[0];
    assert_eq!(recovery.fault_id, "D1");
    // A standby replica is not the active source, so no continuity incident is
    // expected: the surviving active book keeps the symbol anchored. The
    // honest contract here is a replacement socket plus uninterrupted service.
    assert!(
        recovery.connections_after.unwrap_or(0) >= 4,
        "the lost book socket must reconnect: {recovery:?}"
    );
    if recovery.incidents_after.unwrap_or(0) > recovery.incidents_before.unwrap_or(0) {
        assert!(
            recovery.duration_ms.is_some(),
            "when an incident did open, its re-anchor must be measured: {recovery:?}"
        );
    } else {
        assert!(
            recovery.duration_unavailable_reason.is_some(),
            "standby loss without an incident must explain the missing duration: {recovery:?}"
        );
    }
    assert!(
        output.ws_connections >= 4,
        "the lost book socket must reconnect (got {} connections)",
        output.ws_connections
    );
    assert_disconnect_success(&output, 60);
}

/// D2: losing the oldest (active-role) replica must promote the shadow book and
/// keep the entire event ledger reconciled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnect_active_replica_loss_recovers_and_reconciles() {
    let directory = tempfile::tempdir().unwrap();
    let config = sweep_config(32, 200, 60, SweepProfile::ActiveReplicaLoss);
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        outcome.acceptance.valid,
        "active replica loss failed: {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.expect("valid cell must carry output");
    let recovery = &output.recovery[0];
    assert_eq!(recovery.fault_id, "D2");
    assert!(
        recovery.incidents_after.unwrap_or(0) > recovery.incidents_before.unwrap_or(0),
        "active loss must open a continuity incident: {recovery:?}"
    );
    assert!(
        recovery.failover_snapshots_after.unwrap_or(0)
            > recovery.failover_snapshots_before.unwrap_or(0),
        "shadow must be promoted by a failover snapshot: {recovery:?}"
    );
    assert!(recovery.duration_ms.is_some(), "{recovery:?}");
    assert!(
        output.report.core.failover_snapshots >= 1,
        "the run report must record the failover snapshot"
    );
    assert!(
        output.report.core.source_switches >= 1,
        "the run report must record the active-source switch"
    );
    assert_disconnect_success(&output, 60);
}

/// D3 + D4: losing both book sockets re-anchors every previously active symbol
/// from fresh snapshots on new connection epochs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnect_both_replicas_lost_reanchors_all_instruments() {
    let directory = tempfile::tempdir().unwrap();
    let config = sweep_config(33, 400, 80, SweepProfile::BothReplicasLost);
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        outcome.acceptance.valid,
        "both replicas lost failed: {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.expect("valid cell must carry output");
    assert_eq!(output.recovery.len(), 2);
    assert_eq!(output.recovery[0].fault_id, "D3");
    assert_eq!(output.recovery[1].fault_id, "D4");
    let full_loss = &output.recovery[0];
    assert!(
        full_loss.incidents_after.unwrap_or(0) > full_loss.incidents_before.unwrap_or(0),
        "a complete book loss must open incidents: {full_loss:?}"
    );
    assert!(
        full_loss.failover_snapshots_after.unwrap_or(0)
            > full_loss.failover_snapshots_before.unwrap_or(0),
        "fresh snapshots must re-anchor the lost books: {full_loss:?}"
    );
    assert!(full_loss.duration_ms.is_some(), "{full_loss:?}");
    // D4 closes one replica after recovery; a standby-role loss need not open
    // an incident, but it must still create a fresh connection generation.
    let single_loss = &output.recovery[1];
    assert!(
        single_loss.connections_after.unwrap_or(0) > full_loss.connections_after.unwrap_or(0),
        "D4 must open a new socket generation: {single_loss:?}"
    );
    assert!(
        output.ws_connections >= 6,
        "both replicas must reconnect twice: {} connections",
        output.ws_connections
    );
    assert_eq!(
        output.coverage.as_ref().unwrap().anchored,
        400,
        "all 400 instruments must be re-anchored"
    );
    assert_disconnect_success(&output, 80);
}

/// D7: a full-universe book loss must re-anchor every eligible instrument and
/// certify exact coverage without any delta being silently dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnect_many_instruments_reanchor_certifies_coverage() {
    let directory = tempfile::tempdir().unwrap();
    let config = sweep_config(37, 500, 100, SweepProfile::ManyInstruments);
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        outcome.acceptance.valid,
        "many-instrument recovery failed: {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.expect("valid cell must carry output");
    let coverage = output.coverage.as_ref().expect("coverage must be present");
    assert_eq!(coverage.expected, 500);
    assert_eq!(coverage.anchored, 500);
    assert!(
        output.recovery.iter().any(|r| r.fault_id == "D7"),
        "the many-instrument profile must include D7"
    );
    assert_disconnect_success(&output, 100);
}

/// D5 + D6: the strongest honest regression for delayed old-epoch frames uses
/// the production core directly. The delayed snapshot is rejected before any
/// book or incident mutation; a frame strictly after the recovery fence repairs
/// the gap. This is the contract the stress mock cannot synthesize on the wire.
#[test]
fn disconnect_delayed_old_epoch_frames_are_rejected_by_the_recovery_fence() {
    use fieldbook::{
        collector::{CollectorCore, CoreConfig},
        config::ExchangeKind,
        exchange::ExchangeCapabilities,
        model::{EventMeta, ExchangeEvent, Level, MarketInfo, SourceId},
    };

    const NOW: i64 = 1_700_000_000_000_000;
    const SOURCE_A: SourceId = SourceId::new(0, 0);
    const SOURCE_B: SourceId = SourceId::new(0, 1);

    let mut settings = fieldbook::config::Settings::for_exchange(ExchangeKind::Polymarket);
    settings.collector.shards = 1;
    settings.collector.replicas = 2;
    let mut core = CollectorCore::new(
        CoreConfig::from_settings(&settings, 1, ExchangeCapabilities::new(false)).unwrap(),
    )
    .unwrap();

    let market = MarketInfo {
        exchange: "test".to_owned(),
        native_symbol: "A".to_owned(),
        symbol: "A".to_owned(),
        title: None,
        outcome: None,
        exchange_market_id: None,
        close_time_us: None,
        tick_size_us: Some(10_000),
        price_ranges: Vec::new(),
        price_level_structure: None,
        numeric_spec: fieldbook::model::NumericSpec::default(),
    };
    core.apply_discovery(NOW, vec![market]).unwrap();
    core.drain_controls();
    for source in [SOURCE_A, SOURCE_B] {
        core.handle_status(
            fieldbook::model::SourceStatus {
                source,
                connected: true,
                ..fieldbook::model::SourceStatus::new(source)
            },
            NOW,
        );
    }
    let snapshot =
        |bid: i64, ask: i64, received: i64, epoch: u64, seq: u64| ExchangeEvent::Snapshot {
            native_symbol: "A".to_owned(),
            book: fieldbook::model::BookSnapshot {
                bids: vec![Level::new(bid, 10_000_000).unwrap()],
                asks: vec![Level::new(ask, 5_000_000).unwrap()],
            },
            meta: EventMeta {
                received_at_us: received,
                exchange_ts_us: Some(received - 1_000),
                seq: Some(1),
                clock: None,
                connection_epoch: epoch,
                receive_seq: seq,
            },
        };
    core.handle_event(SOURCE_A, snapshot(400_000, 600_000, NOW, 1, 1));
    core.handle_event(SOURCE_B, snapshot(405_000, 595_000, NOW + 50, 1, 2));
    core.handle_status(
        fieldbook::model::SourceStatus {
            source: SOURCE_A,
            connected: false,
            ..fieldbook::model::SourceStatus::new(SOURCE_A)
        },
        NOW + 1,
    );
    let generation = core
        .drain_controls()
        .into_iter()
        .find_map(|(source, control)| match control {
            fieldbook::model::Control::Recover { generation, .. } if source == SOURCE_B => {
                Some(generation)
            }
            _ => None,
        })
        .expect("a recovery control must be emitted for the surviving replica");
    core.handle_recovery_ready(SOURCE_B, &["A".to_owned()], generation, 1, 5);

    // Old epoch (1) and old sequence (3) both precede the (2, 5) fence.
    let rejected = core.handle_event(SOURCE_B, snapshot(430_000, 570_000, NOW, 1, 3));
    assert!(
        rejected.is_empty(),
        "a delayed old-epoch frame must not emit"
    );
    assert_eq!(
        core.stats().rejected_recovery_snapshots,
        1,
        "rejection must be counted as evidence"
    );

    // A frame read strictly after the fence repairs the gap.
    let accepted = core.handle_event(SOURCE_B, snapshot(430_000, 570_000, NOW + 10, 1, 6));
    assert_eq!(accepted.len(), 1, "a fresh fenced frame must re-anchor");
}

/// D8: with reconnects refused, recovery cannot complete and the cell must be
/// classified as incomplete rather than silently certified.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnect_recovery_timeout_surfaces_as_incomplete() {
    let directory = tempfile::tempdir().unwrap();
    let config = sweep_config(34, 200, 60, SweepProfile::RecoveryTimeout);
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        !outcome.acceptance.valid,
        "an unrecoverable outage must not certify: {:?}",
        outcome.acceptance
    );
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason == "drain_incomplete"),
        "unexpected reasons: {:?}",
        outcome.acceptance.reasons
    );
    assert!(
        outcome
            .acceptance
            .reasons
            .iter()
            .any(|reason| reason == "unexplained_drops"),
        "an outage with no applied deltas must be reported as unexplained drops: {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome
        .output
        .expect("the runner must still export evidence");
    assert_eq!(output.recovery.len(), 1);
    let recovery = &output.recovery[0];
    assert_eq!(recovery.fault_id, "D8");
    assert!(
        recovery.incidents_after.unwrap_or(0) > recovery.incidents_before.unwrap_or(0),
        "the outage must still be detected: {recovery:?}"
    );
    assert!(
        recovery.duration_ms.is_none() && recovery.duration_unavailable_reason.is_some(),
        "no valid re-anchor means recovery duration is unavailable: {recovery:?}"
    );
}

/// D10: a reconnect storm must keep recovery generations independent, queues
/// bounded, healthy instruments anchored, SBE receive times monotonic, and the
/// full disposition/accounting chain reconciled.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disconnect_recovery_storm_preserves_generations_and_accounting() {
    let directory = tempfile::tempdir().unwrap();
    let config = sweep_config(35, 300, 100, SweepProfile::RepeatedReconnects);
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        outcome.acceptance.valid,
        "reconnect storm failed: {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome.output.expect("valid cell must carry output");
    assert_eq!(output.recovery.len(), 3);
    assert!(
        output
            .recovery
            .iter()
            .all(|recovery| recovery.fault_id == "D10"),
        "all storm steps must be D10"
    );
    assert!(
        output
            .recovery
            .iter()
            .all(|recovery| recovery.duration_ms.is_some()),
        "every storm round must have an incident->re-anchor duration: {:?}",
        output.recovery
    );
    // Independent generations: each round observes a strictly larger mock
    // connection count, proving fresh sockets rather than a reused generation.
    let connection_counts: Vec<usize> = output
        .recovery
        .iter()
        .map(|recovery| recovery.connections_after.unwrap_or(0))
        .collect();
    assert!(
        connection_counts.windows(2).all(|pair| pair[0] < pair[1]),
        "storm rounds must open fresh sockets; counts={connection_counts:?}"
    );
    assert!(
        output.ws_connections >= 7,
        "three storm rounds must create independent connections: {}",
        output.ws_connections
    );
    assert!(
        output.book_subscriptions >= 300 * 2,
        "reconnected replicas must resubscribe the full universe"
    );
    assert_disconnect_success(&output, 100);
    assert_eq!(output.coverage.as_ref().unwrap().anchored, 300);
}

/// Ignored reference generator for the timeout-plus-storm profile. Proves the
/// recovery evidence exports both an unavailable duration (D8) and successful
/// re-anchors (D10) in one manifest.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "reference artifact generator; run explicitly"]
async fn reference_disconnect_storm_manifest() {
    assert!(
        std::env::var("STRESS_MANIFEST_OUT").is_ok(),
        "set STRESS_MANIFEST_OUT to produce the artifact"
    );
    let directory = tempfile::tempdir().unwrap();
    let config = sweep_config(38, 400, 80, SweepProfile::RecoveryStorm);
    let outcome =
        stress_support::runner::run_cell(directory.path(), &config, Some(manifest_out().as_path()))
            .await;
    let output = outcome
        .output
        .expect("the reference cell must export evidence");
    assert_eq!(output.recovery.len(), 4);
    assert_eq!(output.recovery[0].fault_id, "D8");
    assert!(output.recovery[0].duration_ms.is_none());
    assert!(
        output.recovery[1..]
            .iter()
            .all(|recovery| recovery.fault_id == "D10")
    );
}

/// The schedule itself is a seed-derived artifact; this test pins that every
/// declared step carries the manifest's fault-matrix fields.
#[test]
fn disconnect_fault_steps_carry_full_matrix_evidence() {
    use stress_support::faults::{AffectedInstruments, FaultType};

    let schedule = stress_support::faults::derive_schedule(SweepProfile::FullMatrix, 42);
    assert_eq!(schedule.steps.len(), 10);
    for step in &schedule.steps {
        assert!(!step.expected_action.is_empty());
        assert!(!step.expected_outcome.is_empty());
        assert!(step.start_epoch >= 1);
        assert!(step.failure_time_ms <= 160);
        match step.fault_type {
            FaultType::ReplicaLoss | FaultType::ReferenceOnly => {}
            _ => assert!(step.deadline_ms.is_some()),
        }
        if step.reference_only {
            assert_eq!(step.affected_instruments, AffectedInstruments::One);
        }
    }
}

/// Ignored reference generator for the disconnect sweep manifest. Run with
/// `STRESS_MANIFEST_OUT` set to a fresh directory; prior evidence is never
/// overwritten because v16 cell ids are content-addressed by seed and verdict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "reference artifact generator; run explicitly"]
async fn reference_disconnect_sweep_manifest() {
    assert!(
        std::env::var("STRESS_MANIFEST_OUT").is_ok(),
        "set STRESS_MANIFEST_OUT to produce the artifact"
    );
    let directory = tempfile::tempdir().unwrap();
    let config = sweep_config(36, 2_000, 200, SweepProfile::FullMatrix);
    let outcome =
        stress_support::runner::run_cell(directory.path(), &config, Some(manifest_out().as_path()))
            .await;
    let output = outcome
        .output
        .expect("the reference cell must export evidence");
    assert_eq!(output.recovery.len(), 7);
    assert!(
        output
            .recovery
            .iter()
            .any(|recovery| recovery.fault_id == "D10")
    );
}

/// The typed selector covers L1-L10 and derives a complete explicit schedule
/// from the seed. This is a contract test for the selector itself, not a live
/// validation: it never opens a connection or publishes an event.
#[test]
fn lifecycle_scenario_variants_are_typed_and_deterministic() {
    use stress_support::lifecycle::{LifecycleScenario, LifecycleSchedule};

    let eligible: Vec<String> = (0..16).map(|index| format!("S-{index:03}")).collect();
    let all = [
        LifecycleScenario::None,
        LifecycleScenario::AddActivate,
        LifecycleScenario::Subscribe,
        LifecycleScenario::SnapshotAnchor,
        LifecycleScenario::MetadataChange,
        LifecycleScenario::RetireSettle,
        LifecycleScenario::Duplicate,
        LifecycleScenario::OutOfOrder,
        LifecycleScenario::ConflictingReplica,
        LifecycleScenario::Reappearance,
        LifecycleScenario::ChurnUnderLoad,
    ];
    let mut ids = std::collections::BTreeSet::new();
    for scenario in all {
        let schedule = LifecycleSchedule::build(scenario, 41, &eligible, 200);
        assert_eq!(schedule.scenario, scenario);
        assert_eq!(schedule.seed, 41);
        assert!(schedule.base_ts_ms >= 1_700_000_000_000);
        assert_eq!(
            schedule.final_expected(),
            &schedule.epochs.last().expect("initial epoch").expected
        );
        if let Some(record) = schedule.added_record() {
            assert_eq!(record["status"], "active");
        }
        if let Some(id) = scenario.scenario_id() {
            assert!(ids.insert(id), "scenario id {id} must be unique");
        }
        assert!(!scenario.as_str().is_empty());
    }
    assert_eq!(ids.len(), 10);
}

/// The default-timestamp wrapper remains callable for ad-hoc probes. Scheduled
/// cells use `publish_lifecycle_at` so dedup and ordering are pinned by the
/// schedule rather than by wire arrival order.
#[tokio::test]
async fn mock_publish_lifecycle_wrapper_is_callable_without_subscribers() {
    let universe = SyntheticUniverse::generate(3, 8, 100_000);
    let ticker = universe.eligible_tickers_sorted()[0].clone();
    let mock = MockKalshi::start(universe).await;
    mock.state()
        .publish_lifecycle("created", &ticker, serde_json::json!({}));
    assert_eq!(mock.state().ledger_snapshot().lifecycle_sent, 0);
}

/// M5.6 evidence cell: a real in-process run records at least one measured
/// stage boundary with non-zero samples. This proves the instrumentation is
/// wired into the production path; it does not claim a throughput number.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stage_timing_cell_records_real_writer_write_latency() {
    let directory = tempfile::tempdir().unwrap();
    let config = CellConfig {
        seed: 31,
        symbols: 200,
        events: 40,
        limits: Some((20, 2)),
        ..headless_cell_config(31, 200)
    };
    let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
    assert!(
        outcome.acceptance.valid,
        "stage-timing cell failed acceptance: {:?}",
        outcome.acceptance.reasons
    );
    let output = outcome
        .output
        .as_ref()
        .expect("valid cell must carry output");
    let timing = output
        .report
        .stage_timing
        .as_ref()
        .expect("run report must carry stage timing");
    let write = match &timing.sbe_write {
        StageHistogram::Measured { report } => report,
        StageHistogram::Unavailable { reason } => {
            panic!("writer write latency must be measured: {reason}")
        }
    };
    assert!(
        write.sample_count >= output.sbe_messages,
        "every persisted SBE message must contribute a write sample: {:?}",
        write
    );
    assert!(write.min_ns <= write.max_ns);
    assert_eq!(
        write.buckets.len(),
        fieldbook::histogram::BUCKET_COUNT,
        "histogram bucket count must equal the configured value"
    );

    match &timing.writer_queue_wait {
        StageHistogram::Measured { report } => assert!(report.sample_count > 0),
        StageHistogram::Unavailable { reason } => panic!("queue wait must be measured: {reason}"),
    }
    match &timing.journal_append {
        StageHistogram::Measured { report } => assert!(report.sample_count > 0),
        StageHistogram::Unavailable { reason } => {
            panic!("journal append must be measured: {reason}")
        }
    }

    let manifest =
        stress_support::runner::build_cell_manifest(&outcome, &config, "stage-timing-cell");
    let stage = &manifest["performance"]["stage_timing"];
    assert_eq!(stage["boundaries"]["sbe_write"]["state"], "measured");
    assert!(
        stage["boundaries"]["sbe_write"]["report"]["sample_count"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );
    assert_eq!(stage["provenance"]["scenario_version"], 16);
    assert!(stage["provenance"]["clock_source"].is_string());
    assert!(
        stage["boundaries"]["sbe_write"]["report"]["buckets"]
            .as_array()
            .is_some_and(|buckets| !buckets.is_empty())
    );
    assert!(stage["resolution_vs_accuracy"].is_string());
    assert!(
        stress_support::manifest::missing_required_fields(&manifest).is_empty(),
        "stage timing must satisfy the manifest contract"
    );
}

// ---------- M5.7 capacity characterization ----------

/// Pure selection contract. Every stage/model combination resolves to an
/// exact instrument count and event budget, and the same selection always
/// produces the same cell configuration regardless of seed.
#[test]
fn capacity_stage_and_workload_model_selection_is_deterministic() {
    for stage in CapacityStage::ALL {
        let per_instrument = CapacityCell {
            stage,
            model: WorkloadModel::FixedPerInstrument,
        };
        let aggregate = CapacityCell {
            stage,
            model: WorkloadModel::FixedAggregate,
        };
        let skewed = CapacityCell {
            stage,
            model: WorkloadModel::SkewedHotQuiet,
        };

        assert_eq!(
            per_instrument.expected_events(),
            stage.symbols * PER_INSTRUMENT_EVENTS,
            "fixed per-instrument rate must scale with the stage"
        );
        assert_eq!(aggregate.expected_events(), AGGREGATE_EVENTS);
        assert_eq!(skewed.expected_events(), AGGREGATE_EVENTS);

        let per_config = per_instrument.cell_config(7);
        let aggregate_config = aggregate.cell_config(7);
        let skewed_config = skewed.cell_config(7);

        assert_eq!(per_config.capacity, Some(per_instrument));
        assert_eq!(aggregate_config.capacity, Some(aggregate));
        assert_eq!(skewed_config.capacity, Some(skewed));
        for config in [&per_config, &aggregate_config, &skewed_config] {
            assert_eq!(config.symbols, stage.symbols);
            assert_eq!(config.shards, None, "capacity shards must be derived");
            assert!(config.journal);
        }
        assert_eq!(per_config.events, stage.symbols);
        assert_eq!(per_config.hot_fraction_ppm, 0);
        assert!(per_config.uniform_spread);
        assert_eq!(aggregate_config.events, AGGREGATE_EVENTS);
        assert_eq!(aggregate_config.hot_fraction_ppm, 0);
        assert!(aggregate_config.uniform_spread);
        assert_eq!(skewed_config.events, AGGREGATE_EVENTS);
        assert!(!skewed_config.uniform_spread);
        assert_eq!(skewed_config.hot_fraction_ppm, HOT_FRACTION_PPM);
        assert_eq!(skewed_config.hot_event_share_pct, HOT_EVENT_SHARE_PCT);
        assert_eq!(skewed_config.hot_selection, HotSelection::ExactQuota);

        // The selection, not the seed, owns the shape; changing only the seed
        // must leave every count and every workload-model knob unchanged.
        let reseeded = per_instrument.cell_config(9);
        assert_eq!(reseeded.symbols, per_config.symbols);
        assert_eq!(reseeded.events, per_config.events);
        assert_eq!(reseeded.hot_fraction_ppm, per_config.hot_fraction_ppm);
        assert_eq!(reseeded.hot_event_share_pct, per_config.hot_event_share_pct);
        assert_eq!(reseeded.hot_selection, per_config.hot_selection);
        assert_eq!(reseeded.shards, per_config.shards);
        assert_eq!(reseeded.journal, per_config.journal);
    }

    assert_eq!(
        CapacityStage::ALL.map(|stage| stage.symbols),
        [4_000, 10_000, 25_000, 50_000]
    );
    assert_eq!(
        WorkloadModel::parse("fixed_per_instrument"),
        Some(WorkloadModel::FixedPerInstrument)
    );
    assert_eq!(
        WorkloadModel::parse("fixed_aggregate"),
        Some(WorkloadModel::FixedAggregate)
    );
    assert_eq!(
        WorkloadModel::parse("skewed_hot_quiet"),
        Some(WorkloadModel::SkewedHotQuiet)
    );
}

/// The manifest contract is checked without a long run: a capacity cell
/// records stage, instrument count, model, expected events and an explicit
/// `unavailable(reason)` for resources the host cannot measure.
#[test]
fn capacity_manifest_records_stage_model_and_unavailable_reasons() {
    let spec = CapacityCell {
        stage: CapacityStage::TEN_K,
        model: WorkloadModel::SkewedHotQuiet,
    };
    let config = spec.cell_config(7);
    let outcome = CellOutcome {
        output: None,
        acceptance: CellAcceptance {
            valid: true,
            reasons: Vec::new(),
            failure_class: None,
        },
        provenance: None,
    };
    let document = build_cell_manifest(&outcome, &config, "capacity-cell");
    let capacity = &document["capacity"];
    assert_eq!(document["scenario_version"], 16);
    assert_eq!(document["scenario"]["capacity_stage"], "10k");
    assert_eq!(
        document["scenario"]["capacity_workload_model"],
        "skewed_hot_quiet"
    );
    assert_eq!(document["scenario"]["capacity_expected_events"], 400);
    assert_eq!(capacity["stage"], "10k");
    assert_eq!(capacity["instruments"], 10_000);
    assert_eq!(capacity["workload_model"], "skewed_hot_quiet");
    assert_eq!(capacity["expected_events"], 400);
    assert_eq!(capacity["workload"]["hot_fraction_ppm"], HOT_FRACTION_PPM);
    assert_eq!(
        capacity["workload"]["hot_event_share_pct"],
        HOT_EVENT_SHARE_PCT
    );
    assert!(
        capacity["resources"]["cpu_seconds"]["value"].is_null(),
        "unmeasured CPU time must never be reported as zero"
    );
    assert!(
        capacity["resources"]["cpu_seconds"]["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "every unavailable resource must carry an explicit reason"
    );

    let ordinary = build_cell_manifest(&outcome, &CellConfig::default(), "ordinary-cell");
    assert!(
        ordinary["capacity"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("not a capacity characterization cell")),
        "non-capacity cells must name why the capacity fields are unavailable"
    );
}

/// Non-ignored small-scale execution of all three models. The same runner,
/// generator and scheduler used by the 4k smoke cell must produce the exact
/// symbol/event counts and a reconciled two-sided ledger at 200 instruments.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capacity_workload_models_reconcile_at_small_scale() {
    let stage = CapacityStage {
        label: "test-200",
        symbols: 200,
    };
    for model in [
        WorkloadModel::FixedPerInstrument,
        WorkloadModel::FixedAggregate,
        WorkloadModel::SkewedHotQuiet,
    ] {
        let spec = CapacityCell { stage, model };
        let config = spec.cell_config(31);
        let directory = tempfile::tempdir().unwrap();
        let outcome = stress_support::runner::run_cell(directory.path(), &config, None).await;
        assert!(
            outcome.acceptance.valid,
            "{} cell failed: reasons={:?}",
            model.as_str(),
            outcome.acceptance.reasons
        );
        let output = outcome.output.expect("valid cell must carry output");

        assert_eq!(output.eligible_count, 200, "{}", model.as_str());
        assert_eq!(
            output.events_published,
            spec.expected_events(),
            "{}",
            model.as_str()
        );
        assert_eq!(
            output.sbe_deltas,
            spec.expected_events() as u64,
            "{}",
            model.as_str()
        );
        assert!(
            output.ledger.reconciled(),
            "{} ledger: {:?}",
            model.as_str(),
            output.ledger
        );
        assert_eq!(output.ledger.unexplained_drops, Some(0));
        assert_eq!(output.ledger.persistence_gap, Some(0));

        let coverage = output.coverage.as_ref().expect("coverage must be present");
        assert_eq!(coverage.expected, 200, "{}", model.as_str());
        assert_eq!(coverage.anchored, 200, "{}", model.as_str());
        assert!(
            output.verify_valid && output.completeness_valid && output.journal_complete,
            "{} verification incomplete",
            model.as_str()
        );

        if model == WorkloadModel::SkewedHotQuiet {
            assert_eq!(output.hot_tickers, 10, "5% of 200 instruments");
            assert_eq!(output.hot_events, 320);
            assert_eq!(output.cold_events, 80);
        } else {
            assert_eq!(output.hot_tickers, 0);
            assert_eq!(output.hot_events, 0);
            assert_eq!(output.cold_events, output.events_published);
        }
    }
}

/// Execute one opt-in short correctness cell. Both `STRESS_CAPACITY_STAGE`
/// (matching the test's stage) and `STRESS_MANIFEST_OUT` are required; the
/// workload model is selected by `STRESS_WORKLOAD_MODEL` and defaults to the
/// skewed hot/quiet profile so the run stays short at every stage.
async fn run_short_capacity_cell(stage: CapacityStage) {
    let requested = std::env::var("STRESS_CAPACITY_STAGE").unwrap_or_default();
    assert_eq!(
        CapacityStage::from_env(),
        Some(stage),
        "set STRESS_CAPACITY_STAGE={} to run this cell (got `{requested}`)",
        stage.label
    );
    let manifest_out =
        std::path::PathBuf::from(std::env::var("STRESS_MANIFEST_OUT").unwrap_or_else(|_| {
            panic!("set STRESS_MANIFEST_OUT to publish the capacity manifest")
        }));
    let model = WorkloadModel::from_env_or_default();
    let spec = CapacityCell { stage, model };
    let config = spec.cell_config(0x5EED_0000 + stage.symbols as u64);
    let directory = tempfile::tempdir().unwrap();
    let outcome =
        stress_support::runner::run_cell(directory.path(), &config, Some(manifest_out.as_path()))
            .await;
    assert!(
        outcome.acceptance.valid,
        "{} capacity cell failed: reasons={:?}",
        stage.label, outcome.acceptance.reasons
    );
    let output = outcome.output.expect("valid cell must carry output");
    assert_eq!(output.eligible_count, stage.symbols);
    assert_eq!(output.events_published, spec.expected_events());
    assert_eq!(output.sbe_deltas, spec.expected_events() as u64);
    assert!(output.ledger.reconciled(), "ledger: {:?}", output.ledger);
    let coverage = output.coverage.as_ref().expect("coverage must be present");
    assert_eq!(coverage.expected, stage.symbols);
    assert_eq!(coverage.anchored, stage.symbols);
    assert!(output.verify_valid && output.completeness_valid && output.journal_complete);
}

/// 10k short correctness run. Evidence class: synthetic loopback; this is not
/// a throughput or discovery-capacity certificate.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "capacity characterization; set STRESS_CAPACITY_STAGE=10k and STRESS_MANIFEST_OUT"]
async fn capacity_stage_10k_short_correctness() {
    run_short_capacity_cell(CapacityStage::TEN_K).await;
}

/// 25k short correctness run. Opt-in only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "capacity characterization; set STRESS_CAPACITY_STAGE=25k and STRESS_MANIFEST_OUT"]
async fn capacity_stage_25k_short_correctness() {
    run_short_capacity_cell(CapacityStage::TWENTY_FIVE_K).await;
}

/// 50k short correctness run. Opt-in only; never executed by default CI.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "capacity characterization; set STRESS_CAPACITY_STAGE=50k and STRESS_MANIFEST_OUT"]
async fn capacity_stage_50k_short_correctness() {
    run_short_capacity_cell(CapacityStage::FIFTY_K).await;
}
