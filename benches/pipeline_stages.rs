// SPDX-License-Identifier: Apache-2.0
//! Stage-level acquisition benchmark methodology.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "benchmarks print measured timings and use deterministic fixtures"
)]
#![allow(
    clippy::allow_attributes,
    reason = "benchmark crates relax the production lint set wholesale"
)]
#![allow(
    unsafe_code,
    reason = "a counting global allocator is required to measure allocations without a new dependency"
)]

//! Run with `cargo bench --bench pipeline_stages`. Each stage is timed
//! separately over a payload, event-count and domain matrix with warm-up and
//! repeated trials. Allocation counts and peak live bytes are reported from a
//! counting allocator. Numbers are measurements of this host and workload,
//! not performance targets. The earlier two-path result in
//! `benches/codec_normalization.rs` remains in the historical record.

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::atomic::{AtomicI64, AtomicU64, Ordering},
    time::{Duration, Instant},
};

use fieldbook::{
    acquisition::{
        arbiter::{ArbiterLimits, BoundedMemorySink, FeedArbiter, SequenceDomain, SequencedPacket},
        codec::{CodecRegistry, DecodeStatus, DecodedObservation, FeedCodec},
        evidence::{
            CanonicalEvidenceRecord, CanonicalSink, DurabilityProfile, EvidenceContext,
            EvidencePipeline, EvidenceStore,
        },
        packet::PacketEvidence,
    },
    canonical::EventId,
    integrity::journal::{JournalConfig, JournalHandle, JournalMeta, SyncMode},
    model::SourceId,
    util::sha256_hex,
};

struct CountingAllocator;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static LIVE_BYTES: AtomicI64 = AtomicI64::new(0);
static PEAK_BYTES: AtomicI64 = AtomicI64::new(0);

// SAFETY: delegation to `System` preserves the global allocator contract.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: `layout` is supplied by the allocator API contract.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
            let live = LIVE_BYTES.fetch_add(layout.size() as i64, Ordering::Relaxed)
                + layout.size() as i64;
            PEAK_BYTES.fetch_max(live, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE_BYTES.fetch_sub(layout.size() as i64, Ordering::Relaxed);
        // SAFETY: `pointer` came from this allocator with the same layout.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

struct StageCodec {
    version: u32,
    events: usize,
    kind: &'static str,
}

impl FeedCodec for StageCodec {
    fn decode(&self, _payload: &[u8]) -> anyhow::Result<Vec<DecodedObservation>> {
        (0..self.events)
            .map(|index| {
                Ok(DecodedObservation {
                    packet_id: String::new(),
                    source: String::new(),
                    schema_version: 0,
                    kind: self.kind.to_owned(),
                    payload_json: match self.kind {
                        "equity_quote" => format!(
                            "{{\"bid_mantissa\":{index},\"ask_mantissa\":{},\"bid_quantity\":2,\"ask_quantity\":3,\"price_scale\":6,\"quantity_scale\":6}}",
                            index + 1
                        ),
                        "economic_observation" => format!(
                            "{{\"release_id\":\"bench-{index}\",\"value_mantissa\":{index},\"revision\":1}}"
                        ),
                        _ => format!(
                            "{{\"trade_id\":\"bench-{index}\",\"price_mantissa\":{index},\"quantity_mantissa\":2}}"
                        ),
                    },
                    status: DecodeStatus::Decoded,
                    reason: None,
                })
            })
            .collect()
    }

    fn schema_version(&self) -> u32 {
        self.version
    }
}

#[derive(Debug, Clone)]
struct Measurement {
    median_ns: u128,
    spread_ns: u128,
    allocations: u64,
    peak_bytes: i64,
}

fn measure<F: FnMut()>(iterations: usize, warmup: usize, mut operation: F) -> Measurement {
    for _ in 0..warmup {
        operation();
    }
    ALLOCATIONS.store(0, Ordering::Relaxed);
    LIVE_BYTES.store(0, Ordering::Relaxed);
    PEAK_BYTES.store(0, Ordering::Relaxed);
    let mut samples = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        operation();
        samples.push(started.elapsed().as_nanos());
    }
    samples.sort_unstable();
    let median_ns = samples[samples.len() / 2];
    let spread_ns = samples.last().copied().unwrap_or(0) - samples.first().copied().unwrap_or(0);
    Measurement {
        median_ns,
        spread_ns,
        allocations: ALLOCATIONS.load(Ordering::Relaxed),
        peak_bytes: PEAK_BYTES.load(Ordering::Relaxed),
    }
}

struct Sink;

impl CanonicalSink for Sink {
    fn persist(&self, _record: &CanonicalEvidenceRecord) -> anyhow::Result<()> {
        Ok(())
    }
}

fn journal_config(directory: &std::path::Path) -> JournalConfig {
    JournalConfig {
        directory: directory.to_path_buf(),
        queue_capacity: 256,
        enqueue_timeout: Duration::from_millis(250),
        flush_interval: Duration::from_millis(10),
        sync_interval: Duration::from_millis(20),
        segment_max_bytes: 0,
        segment_max_seconds: 0,
        sync_mode: SyncMode::Interval,
    }
}

fn main() {
    let trials: usize = std::env::var("STAGE_BENCH_TRIALS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(3);
    let iterations: usize = std::env::var("STAGE_BENCH_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(2_000);
    let warmup = iterations / 10;
    let sizes = [("small", 64_usize), ("medium", 1_024), ("large", 16_384)];
    let event_counts = [1_usize, 4];
    let kinds = ["trade", "equity_quote", "economic_observation"];

    println!("trials={trials} iterations={iterations} warmup={warmup}");
    println!("stage,size,events,kind,median_ns,spread_ns,allocations,peak_bytes");

    for (size_name, size) in sizes {
        for events in event_counts {
            for kind in kinds {
                let payload = vec![b'x'; size];
                let raw_digest = sha256_hex(&payload);
                let record_id = "bench-record";
                let mut registry = CodecRegistry::new();
                registry
                    .register(
                        "bench",
                        Box::new(StageCodec {
                            version: 1,
                            events,
                            kind,
                        }),
                    )
                    .expect("codec registered");
                let decoded = registry
                    .decode("bench", "bench", 1, &payload)
                    .expect("decode");
                let observation = decoded.accepted[0].clone();
                let context = EvidenceContext {
                    sequence_domain_id: "bench-domain".to_owned(),
                    source_schema_id: "bench-schema".to_owned(),
                    source_schema_version: 1,
                    receive_sequence: 1,
                };

                let mut stages: Vec<(&str, Measurement)> = Vec::new();
                stages.push((
                    "input_framing",
                    measure(iterations, warmup, || {
                        let frame = payload.clone();
                        std::hint::black_box(frame);
                    }),
                ));
                stages.push((
                    "protocol_decode",
                    measure(iterations, warmup, || {
                        std::hint::black_box(
                            registry
                                .decode("bench", "bench", 1, &payload)
                                .expect("decode"),
                        );
                    }),
                ));
                stages.push((
                    "typed_conversion",
                    measure(iterations, warmup, || {
                        std::hint::black_box(
                            observation
                                .try_normalize(&payload, record_id)
                                .expect("normalize"),
                        );
                    }),
                ));
                stages.push((
                    "identity_stamping",
                    measure(iterations, warmup, || {
                        std::hint::black_box(EventId::derive("bench", "source", "key"));
                    }),
                ));
                stages.push((
                    "raw_digest",
                    measure(iterations, warmup, || {
                        std::hint::black_box(sha256_hex(&payload));
                    }),
                ));
                stages.push((
                    "arbitration",
                    measure(iterations, warmup, || {
                        let mut arbiter = FeedArbiter::new(
                            SequenceDomain::new("bench", 1),
                            1,
                            ArbiterLimits::default(),
                            Box::new(BoundedMemorySink::new(16)),
                        )
                        .expect("arbiter");
                        arbiter.submit(SequencedPacket {
                            channel: fieldbook::acquisition::arbiter::FeedChannel::Primary,
                            sequence: 1,
                            payload: payload.clone(),
                            received_at_us: 1_000,
                        });
                    }),
                ));
                stages.push((
                    "canonical_persist",
                    measure(iterations, warmup, || {
                        Sink.persist(&CanonicalEvidenceRecord {
                            evidence_id: record_id.to_owned(),
                            source: "bench".to_owned(),
                            schema_version: 1,
                            kind: kind.to_owned(),
                            payload_type: "trade".to_owned(),
                            payload_digest: raw_digest.clone(),
                        })
                        .expect("persist");
                    }),
                ));

                let directory = tempfile::tempdir().expect("tempdir");
                let journal = JournalHandle::start(
                    journal_config(directory.path()),
                    JournalMeta {
                        run_id: format!("bench-{size_name}-{events}-{kind}"),
                        venue: "bench".to_owned(),
                        code_commit: "bench".to_owned(),
                        route: None,
                        config_sha256: "bench".to_owned(),
                    },
                )
                .expect("journal started");
                let store =
                    EvidenceStore::new(directory.path(), "evidence.jsonl").expect("store created");
                let pipeline = EvidencePipeline::new(journal, store, DurabilityProfile::D1)
                    .expect("pipeline created");
                let packet = PacketEvidence::new(
                    "bench",
                    fieldbook::acquisition::arbiter::FeedChannel::Primary,
                    1,
                    Some(1),
                    "bench",
                    payload.clone(),
                    1_000,
                    "lab",
                    "bench-decoder",
                );
                stages.push((
                    "evidence_journaling",
                    measure(iterations.min(500), warmup.min(50), || {
                        std::hint::black_box(pipeline.ingest(
                            &packet,
                            SourceId::new(1, 0),
                            &context,
                        ));
                    }),
                ));
                pipeline
                    .shutdown(Duration::from_secs(10))
                    .expect("journal closed");

                for trial in 0..trials {
                    for (stage, value) in &stages {
                        println!(
                            "{stage},{size_name},{events},{kind},{},{},{},{}",
                            value.median_ns, value.spread_ns, value.allocations, value.peak_bytes
                        );
                        let _ = trial;
                    }
                }
            }
        }
    }
}
