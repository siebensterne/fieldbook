// SPDX-License-Identifier: Apache-2.0
//! Neutral-workload measurements of REAL Fieldbook production components.
//!
//! This harness does not reimplement any production path. It calls the durable
//! aligned SBE writer (`append` / `flush` / `sync_data` / `sync_all`), the real
//! aligned SBE reader, the real streaming `FileSource` replay, the real journal
//! `replay` / `replay_with_interrupt` and `StreamCheckpoint` paths in
//! `file_source`, and the real `SessionAuthorization::checkpoint` path in
//! `governance::operation_plan`. Each stage timer wraps exactly one production
//! call so stages stay separate.
//!
//! The workload is deliberately neutral: opaque byte payloads derived from a
//! seed and monotonically increasing `u64` sequences. No instrument, quote,
//! book, price, trade, strategy or market-shaped event is generated. Governance
//! scaffolding (venue/provider/modality enum values) exists only because the
//! real checkpoint API requires a written authorization scope; it carries no
//! measurement meaning and is identical in every repetition.
//!
//! IMPORTANT: these are neutral-workload measurements of real components. They
//! are NOT a production latency or throughput certificate, NOT nanosecond/HFT
//! timing, NOT horizontal-scale evidence, and NO resource maxima are set.
//! A faster path that changes event order, journal bytes or replayed state is a
//! failure: the same correctness checks run before and after the measured pass
//! and their digests must be identical.
//!
//! RAW EVIDENCE DIGEST INPUT FORMAT (byte-exact; `scripts/verify_benchmark_evidence.py`
//! reimplements this independently): for one stage, build a UTF-8 byte string by
//! concatenating one line per raw observation, ordered by process index ascending
//! (the order of processes in an aggregated evidence file), then repetition index
//! ascending, then the observation order recorded in that repetition's `raw_ns`
//! array. A line is exactly
//! `stage_id|repetition_index|process_index|observation_ns_integer` followed by a
//! single LF (`\n`), including after the final line. `stage_id` is the exact stage
//! name, and all indices and nanosecond values are unsigned decimal integers with
//! no leading zeros (zero is `0`). The lowercase-hex SHA-256 of that byte string
//! is `raw_observations_sha256`. The untimed correctness pre-pass is never sampled;
//! write, replay/recovery and total stages keep separate stage ids and are never
//! merged into one digest. No performance gate or resource maximum is implied.

#![expect(
    clippy::print_stdout,
    reason = "a benchmark harness emits its JSON artifact on stdout"
)]

use std::{
    env,
    fmt::Write as FmtWrite,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    sync::Arc,
    time::Instant,
};

use fieldbook::{
    config::Settings,
    governance::{
        egress_intent::{AbstractClock, Clock, EgressIntent},
        operation_plan::{
            OperationPlan, PlanDecision, PlanRequest, PlanStep, SessionAuthorization,
            SideEffectBoundary, authorize_plan_with_clock,
        },
        rights::{
            Actor, AuthorizationGate, AuthorizationIdentity, AuthorizationRecord,
            AuthorizationScope, DataObject, DecisionAudit, DeliveryMethod, Licensee, Modality,
            ObjectKind, Operation, Purpose, RecipientClass, RecipientIdentity, Retention,
            RightDecision, RightsFile, ScopeSet, TimeWindow, UsageMode, UsageRight,
        },
    },
    storage::application::{
        SourceAdapter,
        file_source::{
            CheckpointBinding, GENESIS_CHECKPOINT, JournalEvent, Mutation, ReplayError,
            SourceIdentity, StreamCheckpoint, replay, replay_with_interrupt,
        },
    },
    taxonomy::CountryCode,
    util::{
        AlignedSbeReader, AlignedSbeSchema, AlignedSbeWriter, dtos::SbeEncode, hex_lower,
        sha256_hex,
    },
};

const SCHEMA_VERSION: u32 = 1;
const SBE_SCHEMA_ID: u16 = 0x4250;
const SBE_SCHEMA_VERSION: u16 = 1;
const SBE_TEMPLATE_ID: u16 = 1;
const SBE_HEADER_BYTES: usize = 8;
const SBE_SEQUENCE_BYTES: usize = 8;
const SBE_CHECKSUM_BYTES: usize = 8;
const DISCLAIMER: &str = "neutral-workload measurements of real Fieldbook components; not a production latency/throughput certificate, not nanosecond/HFT, not horizontal scale, and no resource maxima are set";
const WARMUP_POLICY: &str = "one untimed correctness pre-pass immediately before the measured pass; no per-stage untimed warm-up";
const QUANTILE_METHOD: &str = "nearest-rank: sorted samples, rank=floor(N*p) clamped to [0,N-1], zero-indexed; units nanoseconds";
const DIGEST_INPUT_FORMAT: &str = "sha256 over UTF-8 bytes of newline-delimited stage_id|repetition_index|process_index|observation_ns_integer lines, in process order then within-process repetition order then observation order; each line ends with one LF, including the last";

#[derive(Debug, Clone)]
struct Config {
    events: usize,
    payload_bytes: usize,
    batch: usize,
    chunk_bytes: usize,
    seed: u64,
    reps: usize,
    label: String,
    output: Option<PathBuf>,
    // Actual load average captured by the caller at process start, passed
    // through verbatim. Never synthesised: absent means `null` in the artifact.
    start_load_average: Option<String>,
}

impl Config {
    fn default_run() -> Self {
        Self {
            events: 1024,
            payload_bytes: 64,
            batch: 8,
            chunk_bytes: 4096,
            seed: 0x50_52_4f_44,
            reps: 1,
            label: "local".to_owned(),
            output: None,
            start_load_average: None,
        }
    }

    fn self_test() -> Self {
        Self {
            events: 8,
            payload_bytes: 16,
            batch: 4,
            chunk_bytes: 1024,
            seed: 0x5e_1f_57,
            reps: 1,
            label: "self-test".to_owned(),
            output: None,
            start_load_average: None,
        }
    }

    fn validate(&self) -> Result<(), String> {
        if self.events == 0 || self.batch == 0 || self.reps == 0 {
            return Err("counts must be positive".to_owned());
        }
        if self.payload_bytes == 0 || self.payload_bytes > u16::MAX as usize {
            return Err("payload_bytes must fit the SBE block length".to_owned());
        }
        if !self.chunk_bytes.is_power_of_two() || self.chunk_bytes < 1024 {
            return Err("chunk_bytes must be a power of two >= 1024".to_owned());
        }
        if SBE_HEADER_BYTES + SBE_SEQUENCE_BYTES + self.payload_bytes + SBE_CHECKSUM_BYTES
            >= self.chunk_bytes - SBE_HEADER_BYTES
        {
            return Err("one message must fit inside a chunk".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct Bindings {
    source_sha: String,
    binary_digest: String,
    toolchain: String,
    rustc_verbose: String,
    target_triple: String,
    compiler_flags: String,
    build_profile: String,
    debug_assertions: bool,
    os: String,
    cpu: String,
    machine: String,
    filesystem: String,
    workload_digest: String,
    seed: u64,
    start_load_average: Option<String>,
    event_count: u64,
    warmup_policy: String,
    duration_ns: u64,
    repetitions: u64,
    quantile_method: String,
    payload_bytes: u64,
    batch_size: u64,
    chunk_bytes: u64,
    interrupt_at: u64,
}

#[derive(Debug, Clone)]
struct SampleSet {
    samples: Vec<u64>,
}

impl SampleSet {
    fn percentile(&self, numerator: u64, denominator: u64) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let rank =
            (sorted.len() as u128 * u128::from(numerator) / u128::from(denominator)) as usize;
        sorted[rank.min(sorted.len() - 1)]
    }

    fn beyond(&self, value: u64) -> u64 {
        self.samples
            .iter()
            .filter(|sample| **sample > value)
            .count() as u64
    }

    fn max(&self) -> u64 {
        self.samples.iter().copied().max().unwrap_or(0)
    }

    fn total(&self) -> u128 {
        self.samples.iter().map(|value| u128::from(*value)).sum()
    }

    fn digest(&self) -> String {
        let mut bytes = Vec::with_capacity(self.samples.len() * 8);
        for sample in &self.samples {
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        format!("fnv1a128:{}", fnv1a128_hex(&bytes))
    }
}

#[derive(Debug, Clone)]
struct StageResult {
    name: String,
    count: u64,
    total_ns: u64,
    p50_ns: u64,
    p90_ns: u64,
    p95_ns: u64,
    p99_ns: u64,
    p999_ns: u64,
    max_ns: u64,
    beyond_p50: u64,
    beyond_p90: u64,
    beyond_p95: u64,
    beyond_p99: u64,
    beyond_p999: u64,
    beyond_max: u64,
    throughput_per_s: u64,
    bytes_per_s: u64,
    stage_bytes: u64,
    raw_result_digest: String,
    raw_ns: Vec<u64>,
}

impl StageResult {
    fn from_samples(name: &str, samples: &SampleSet, stage_bytes: u64) -> Self {
        let total = samples.total();
        let total_ns = u64::try_from(total).unwrap_or(u64::MAX);
        let p50 = samples.percentile(50, 100);
        let p90 = samples.percentile(90, 100);
        let p95 = samples.percentile(95, 100);
        let p99 = samples.percentile(99, 100);
        let p999 = samples.percentile(999, 1000);
        let max = samples.max();
        let throughput = (u128::from(samples.samples.len() as u64) * 1_000_000_000)
            .checked_div(total.max(1))
            .and_then(|value| u64::try_from(value).ok())
            .unwrap_or(0);
        let bytes_rate = (u128::from(stage_bytes) * 1_000_000_000)
            .checked_div(total.max(1))
            .and_then(|value| u64::try_from(value).ok())
            .unwrap_or(0);
        Self {
            name: name.to_owned(),
            count: samples.samples.len() as u64,
            total_ns,
            p50_ns: p50,
            p90_ns: p90,
            p95_ns: p95,
            p99_ns: p99,
            p999_ns: p999,
            max_ns: max,
            beyond_p50: samples.beyond(p50),
            beyond_p90: samples.beyond(p90),
            beyond_p95: samples.beyond(p95),
            beyond_p99: samples.beyond(p99),
            beyond_p999: samples.beyond(p999),
            beyond_max: samples.beyond(max),
            throughput_per_s: throughput,
            bytes_per_s: bytes_rate,
            stage_bytes,
            raw_result_digest: samples.digest(),
            raw_ns: samples.samples.clone(),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct Counters {
    offered: u64,
    appended: u64,
    flushed: u64,
    synced_data: u64,
    synced_all: u64,
    sbe_replayed: u64,
    file_source_replayed: u64,
    journal_replayed: u64,
    interrupt_replayed: u64,
    stream_checkpointed: u64,
    authorization_checkpointed: u64,
    errors: u64,
    bytes_written: u64,
    source_bytes: u64,
    journal_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Correctness {
    event_order_digest: String,
    journal_bytes_digest: String,
    replayed_state_digest: String,
    stream_checkpoint_digest: String,
    writer_checksum: String,
    file_sha256: String,
    sbe_replayed: u64,
    file_source_replayed: u64,
    journal_replayed: u64,
    errors: u64,
}

#[derive(Debug, Clone)]
struct PassResult {
    stages: Vec<(String, Vec<u64>)>,
    stage_bytes: Vec<u64>,
    duration_ns: u64,
    counters: Counters,
    correctness: Correctness,
}

#[derive(Debug, Clone)]
struct Artifact {
    repetition_index: usize,
    bindings: Bindings,
    config: Config,
    results: Vec<StageResult>,
    counters: Counters,
    before: Correctness,
    after: Correctness,
    checks: Vec<Check>,
}

#[derive(Debug, Clone)]
struct Check {
    name: String,
    passed: bool,
}

fn now_ns(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn fnv1a64_offset(bytes: &[u8], offset: u64) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325 ^ offset;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn fnv1a128_hex(bytes: &[u8]) -> String {
    format!(
        "{:016x}{:016x}",
        fnv1a64(bytes),
        fnv1a64_offset(bytes, 0x9e37_79b9_7f4a_7c15)
    )
}

fn u64_seq_digest(values: &[u64]) -> String {
    let mut bytes = Vec::with_capacity(values.len() * 8);
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    format!("fnv1a128:{}", fnv1a128_hex(&bytes))
}

fn make_payload(seed: u64, sequence: u64, length: usize) -> Vec<u8> {
    let mut state = seed
        ^ sequence.wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ (length as u64).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    let mut payload = Vec::with_capacity(length);
    for _ in 0..length {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        payload.push((state >> 24) as u8);
    }
    payload
}

/// Layout: standard 8-byte SBE header, `u64` sequence, opaque payload, `u64`
/// FNV-1a trailer. The header carries the schema id/version the real reader
/// checks, plus the payload block length.
struct OpaqueSbeMessage<'a> {
    sequence: u64,
    payload: &'a [u8],
}

impl SbeEncode for OpaqueSbeMessage<'_> {
    fn encoded_length_with_header(&self) -> anyhow::Result<usize> {
        Ok(SBE_HEADER_BYTES + SBE_SEQUENCE_BYTES + self.payload.len() + SBE_CHECKSUM_BYTES)
    }

    fn encode(&self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let length = self.payload.len();
        let total = SBE_HEADER_BYTES + SBE_SEQUENCE_BYTES + length + SBE_CHECKSUM_BYTES;
        anyhow::ensure!(buf.len() >= total, "short SBE encode buffer");
        let block = length + SBE_SEQUENCE_BYTES;
        let block_length = u16::try_from(block)?;
        buf[0..2].copy_from_slice(&block_length.to_le_bytes());
        buf[2..4].copy_from_slice(&SBE_TEMPLATE_ID.to_le_bytes());
        buf[4..6].copy_from_slice(&SBE_SCHEMA_ID.to_le_bytes());
        buf[6..8].copy_from_slice(&SBE_SCHEMA_VERSION.to_le_bytes());
        buf[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        buf[16..16 + length].copy_from_slice(self.payload);
        buf[16 + length..total].copy_from_slice(&fnv1a64(self.payload).to_le_bytes());
        Ok(total)
    }
}

struct OpaqueDecoded<'a> {
    sequence: u64,
    payload: &'a [u8],
    checksum: u64,
}

struct OpaqueSchema;

impl AlignedSbeSchema for OpaqueSchema {
    const SCHEMA_ID: u16 = SBE_SCHEMA_ID;
    const SCHEMA_VERSION: u16 = SBE_SCHEMA_VERSION;

    type Message<'buf> = OpaqueDecoded<'buf>;

    fn try_decode<'buf>(buffer: &'buf [u8], offset: usize) -> anyhow::Result<Self::Message<'buf>> {
        let minimum = offset
            .checked_add(SBE_HEADER_BYTES + SBE_SEQUENCE_BYTES + SBE_CHECKSUM_BYTES)
            .ok_or_else(|| anyhow::anyhow!("SBE offset overflow"))?;
        anyhow::ensure!(buffer.len() >= minimum, "truncated SBE message");
        let block_length = usize::from(u16::from_le_bytes([buffer[offset], buffer[offset + 1]]));
        anyhow::ensure!(block_length >= SBE_SEQUENCE_BYTES, "short SBE block");
        let body = offset + SBE_HEADER_BYTES;
        let end = body
            .checked_add(block_length)
            .ok_or_else(|| anyhow::anyhow!("SBE body overflow"))?;
        let checksum_at = end
            .checked_add(SBE_CHECKSUM_BYTES)
            .ok_or_else(|| anyhow::anyhow!("SBE checksum overflow"))?;
        anyhow::ensure!(buffer.len() >= checksum_at, "truncated SBE checksum");
        let sequence = u64::from_le_bytes(
            buffer[body..body + SBE_SEQUENCE_BYTES]
                .try_into()
                .map_err(|_| anyhow::anyhow!("short SBE sequence"))?,
        );
        let payload = &buffer[body + SBE_SEQUENCE_BYTES..end];
        let checksum = u64::from_le_bytes(
            buffer[end..checksum_at]
                .try_into()
                .map_err(|_| anyhow::anyhow!("short SBE checksum"))?,
        );
        Ok(OpaqueDecoded {
            sequence,
            payload,
            checksum,
        })
    }

    fn encoded_length(message: &Self::Message<'_>) -> anyhow::Result<usize> {
        Ok(SBE_HEADER_BYTES + SBE_SEQUENCE_BYTES + message.payload.len() + SBE_CHECKSUM_BYTES)
    }

    fn expected_block_length(message: &Self::Message<'_>) -> anyhow::Result<usize> {
        Ok(SBE_SEQUENCE_BYTES + message.payload.len())
    }
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (!text.is_empty()).then_some(text)
}

fn filesystem_type(directory: &Path, os: &str) -> String {
    let path = directory.to_string_lossy();
    if os == "macos" {
        command_output("mount", &[]).and_then(|text| {
            text.lines()
                .filter_map(|line| {
                    let (_, rest) = line.split_once(" on ")?;
                    let (mountpoint, attributes) = rest.split_once(" (")?;
                    if !path.starts_with(mountpoint) {
                        return None;
                    }
                    let filesystem = attributes.split(',').next()?.trim().to_owned();
                    (!filesystem.is_empty()).then_some((mountpoint.to_owned(), filesystem))
                })
                .max_by(|left, right| left.0.len().cmp(&right.0.len()))
                .map(|(_, filesystem)| filesystem)
        })
    } else {
        command_output("stat", &["-f", "-c", "%T", &path])
    }
    .unwrap_or_else(|| "unknown".to_owned())
}

fn collect_bindings(config: &Config, duration_ns: u64, workload_digest: &str) -> Bindings {
    let compiler_flags = env::var("CARGO_ENCODED_RUSTFLAGS")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| env::var("RUSTFLAGS").ok())
        .unwrap_or_else(|| "(none)".to_owned());
    let rustc_verbose = command_output("rustc", &["-vV"]).unwrap_or_else(|| "unknown".to_owned());
    let target_triple = rustc_verbose
        .lines()
        .find_map(|line| line.strip_prefix("host: ").map(str::to_owned))
        .unwrap_or_else(|| "unknown".to_owned());
    let toolchain = command_output("rustc", &["--version"]).unwrap_or_else(|| "unknown".to_owned());
    let os = env::consts::OS.to_owned();
    let binary_digest = env::current_exe()
        .ok()
        .and_then(|path| fs::read(path).ok())
        .map(|bytes| format!("sha256:{}", sha256_hex(&bytes)))
        .unwrap_or_else(|| "unknown".to_owned());
    Bindings {
        source_sha: command_output("git", &["rev-parse", "HEAD"])
            .unwrap_or_else(|| "unknown".to_owned()),
        binary_digest,
        toolchain,
        rustc_verbose,
        target_triple,
        compiler_flags,
        build_profile: "release (cargo bench); lto=thin, codegen-units=8, panic=abort".to_owned(),
        debug_assertions: cfg!(debug_assertions),
        os: os.clone(),
        cpu: command_output("sysctl", &["-n", "machdep.cpu.brand_string"])
            .or_else(|| command_output("uname", &["-p"]))
            .unwrap_or_else(|| "unknown".to_owned()),
        machine: command_output("hostname", &[]).unwrap_or_else(|| "unknown".to_owned()),
        filesystem: filesystem_type(&env::temp_dir(), &os),
        workload_digest: workload_digest.to_owned(),
        seed: config.seed,
        start_load_average: config.start_load_average.clone(),
        event_count: config.events as u64,
        warmup_policy: WARMUP_POLICY.to_owned(),
        duration_ns,
        repetitions: config.reps as u64,
        quantile_method: QUANTILE_METHOD.to_owned(),
        payload_bytes: config.payload_bytes as u64,
        batch_size: config.batch as u64,
        chunk_bytes: config.chunk_bytes as u64,
        interrupt_at: (config.events / 2) as u64,
    }
}

fn workload_digest(config: &Config, payloads: &[Vec<u8>]) -> String {
    let mut text = String::new();
    let _ = FmtWrite::write_fmt(
        &mut text,
        format_args!(
            "v{}|{}|{}|{}|{}|{}|{}",
            SCHEMA_VERSION,
            config.seed,
            config.events,
            config.payload_bytes,
            config.batch,
            config.chunk_bytes,
            config.reps
        ),
    );
    for (index, payload) in payloads.iter().enumerate() {
        text.push_str(&hex_lower(payload));
        text.push('|');
        text.push_str(&format!("{:016x}", index as u64));
    }
    format!("fnv1a128:{}", fnv1a128_hex(text.as_bytes()))
}

fn source_line(sequence: u64, payload: &[u8]) -> String {
    format!(
        "{{\"id\":\"opaque-{sequence}\",\"payload\":{{\"blob\":\"{}\"}}}}",
        hex_lower(payload)
    )
}

fn build_session(directory: &Path) -> Result<SessionAuthorization, String> {
    let scope = AuthorizationScope::request()
        .actor(Actor::FieldbookProducer)
        .data_object(
            DataObject::new(ObjectKind::RawSourceRecord, "opaque-object", "v1")
                .map_err(|error| format!("building opaque data object: {error}"))?,
        )
        .licensee(Licensee::new("opaque-licensee").map_err(|error| format!("licensee: {error}"))?)
        .venue("opaque-venue")
        .provider_id("opaque-provider")
        .source_id("opaque-source")
        .dataset_id("opaque-dataset")
        .product_id("opaque-product")
        .segment("opaque-segment")
        .territory(CountryCode::new("US").map_err(|error| format!("country: {error}"))?)
        .operation(Operation::RealTimeCapture)
        .usage_right(UsageRight::HistoricalStorage)
        .usage_mode(UsageMode::NonDisplay)
        .recipient_class(RecipientClass::Internal)
        .recipient_identity(
            RecipientIdentity::new("opaque-recipient")
                .map_err(|error| format!("recipient: {error}"))?,
        )
        .purpose(Purpose::InternalAnalysis)
        .delivery_method(DeliveryMethod::Stream)
        .retention(Retention::bounded(86_400))
        .instruments(ScopeSet::Named(vec!["opaque-dimension".to_owned()]))
        .fields(ScopeSet::Named(vec!["opaque-field".to_owned()]))
        .modalities(ScopeSet::Named(vec![Modality::L1]))
        .data_time_window(TimeWindow {
            from_us: Some(1_000),
            to_us: Some(9_000),
        })
        .endpoint("wss://opaque.invalid:443")
        .map_err(|error| format!("reserved endpoint: {error}"))?
        .build()
        .map_err(|error| format!("building opaque authorization scope: {error}"))?;

    let intent = EgressIntent::builder()
        .provider_id(scope.provider_id.clone())
        .source_id(scope.source_id.clone())
        .source_product_id(scope.product_id.clone())
        .venue_id(scope.venue.clone())
        .segment_id(scope.segment.clone())
        .dataset_id(scope.dataset_id.clone())
        .actor(scope.actor)
        .operation(scope.operation)
        .data_object(scope.data_object.clone())
        .purpose(scope.purpose)
        .usage_mode(scope.usage_mode)
        .usage_right(scope.usage_right)
        .licensee(scope.licensee.clone())
        .recipient_class(scope.recipient_class)
        .recipient_identity(scope.recipient_identity.clone())
        .territory(scope.territory.clone())
        .instruments(scope.instruments.clone())
        .fields(scope.fields.clone())
        .modalities(scope.modalities.clone())
        .data_time_window(scope.data_time_window)
        .retention_request(scope.retention)
        .delivery_method(scope.delivery_method)
        .endpoint_identity(
            scope
                .approved_endpoints
                .first()
                .cloned()
                .ok_or_else(|| "no reserved endpoint in opaque scope".to_owned())?,
        )
        .build()
        .map_err(|error| format!("building opaque intent: {error}"))?;

    let step = PlanStep {
        step_id: "opaque-step".to_owned(),
        request: PlanRequest::Egress(intent),
        grant_reference: "opaque-contract/1".to_owned(),
        approved_resource_class: Some("neutral/opaque".to_owned()),
        approved_http_method: Some("GET".to_owned()),
        decision: PlanDecision::Pending,
        audit_reference: None,
        side_effect_boundary: SideEffectBoundary::ProviderContact,
    };
    let rights = RightsFile {
        schema_version: 1,
        licensee: Licensee::new("opaque-licensee").map_err(|error| format!("licensee: {error}"))?,
        territory: "US".to_owned(),
        recipient_class: RecipientClass::Internal,
        recipient_identity: RecipientIdentity::new("opaque-recipient")
            .map_err(|error| format!("recipient: {error}"))?,
        rights: vec![AuthorizationRecord {
            identity: AuthorizationIdentity {
                scope,
                valid_from: 0,
                valid_until: None,
            },
            decision: RightDecision::Permitted,
            audit: DecisionAudit {
                licence_reference: "opaque-contract/1".to_owned(),
                licence_document_hash: "a".repeat(64),
                contract_revision: 1,
                recorded_at_us: 0,
                authority: "opaque-registry".to_owned(),
            },
        }],
    };
    let rights_path = directory.join("rights.toml");
    fs::write(
        &rights_path,
        toml::to_string(&rights).map_err(|error| format!("serializing opaque rights: {error}"))?,
    )
    .map_err(|error| format!("writing opaque rights: {error}"))?;

    let mut settings = Settings::for_venue("opaque-venue");
    settings.governance.rights_file = Some(rights_path);
    settings.governance.audit_dir = Some(directory.join("audit"));
    let clock = Arc::new(AbstractClock::new(1_700_000_000_000_000, 1_000));
    let gate = AuthorizationGate::new();
    let mut plan = OperationPlan::new("opaque-plan", vec![step])
        .map_err(|error| format!("building opaque plan: {error}"))?;
    let authorization = authorize_plan_with_clock(&settings, &mut plan, &gate, clock.as_ref())
        .map_err(|error| format!("authorizing opaque plan: {error}"))?;
    SessionAuthorization::new(authorization, Arc::clone(&clock) as Arc<dyn Clock>)
        .map_err(|error| format!("building session authorization: {error}"))
}

fn source_text(payloads: &[Vec<u8>]) -> String {
    let mut text = String::new();
    for (index, payload) in payloads.iter().enumerate() {
        text.push_str(&source_line(index as u64 + 1, payload));
        text.push('\n');
    }
    text
}

fn run_pass(config: &Config, directory: &Path) -> Result<PassResult, String> {
    let payloads: Vec<Vec<u8>> = (1..=config.events as u64)
        .map(|sequence| make_payload(config.seed, sequence, config.payload_bytes))
        .collect();
    let text = source_text(&payloads);
    let source_path = directory.join("source.jsonl");
    fs::write(&source_path, &text).map_err(|error| format!("writing opaque source: {error}"))?;
    let source_bytes = fs::metadata(&source_path)
        .map_err(|error| format!("stat opaque source: {error}"))?
        .len();

    let journal_events: Vec<JournalEvent> = (1..=config.events as u64)
        .map(|sequence| JournalEvent {
            sequence,
            offset: sequence.saturating_mul(16),
            mutation: Mutation::NoOp,
        })
        .collect();

    let mut session = build_session(directory)?;
    let mut stages: Vec<(String, Vec<u64>)> = Vec::new();
    let mut stage_bytes: Vec<u64> = Vec::new();
    let mut counters = Counters::default();

    // Real durable writer: append, visible-byte flush, periodic sync and final
    // sync. Every call below is a production method, not a harness analogue.
    let journal_path = directory.join("journal.sbe");
    let mut writer = AlignedSbeWriter::create_new(&journal_path, config.chunk_bytes)
        .map_err(|error| format!("creating aligned SBE writer: {error}"))?;
    writer
        .enable_checksum()
        .map_err(|error| format!("enabling SBE checksum: {error}"))?;
    let mut appended_ns = Vec::with_capacity(config.events);
    let mut flushed_ns = Vec::new();
    let mut synced_data_ns = Vec::new();
    let mut synced_all_ns = Vec::new();
    let mut batch_bytes = 0u64;
    let started = Instant::now();
    for (index, payload) in payloads.iter().enumerate() {
        let sequence = index as u64 + 1;
        let at = Instant::now();
        writer
            .write_msg(&OpaqueSbeMessage { sequence, payload })
            .map_err(|error| format!("appending SBE message: {error}"))?;
        appended_ns.push(now_ns(at));
        counters.appended = counters.appended.saturating_add(1);
        batch_bytes = batch_bytes.saturating_add((24 + payload.len()) as u64);
        if (index + 1) % config.batch == 0 {
            let at = Instant::now();
            writer
                .flush()
                .map_err(|error| format!("flushing aligned SBE writer: {error}"))?;
            flushed_ns.push(now_ns(at));
            let at = Instant::now();
            writer
                .sync_data()
                .map_err(|error| format!("syncing aligned SBE data: {error}"))?;
            synced_data_ns.push(now_ns(at));
            let at = Instant::now();
            writer
                .sync_all()
                .map_err(|error| format!("syncing aligned SBE file: {error}"))?;
            synced_all_ns.push(now_ns(at));
            counters.flushed = counters.flushed.saturating_add(1);
            counters.synced_data = counters.synced_data.saturating_add(1);
            counters.synced_all = counters.synced_all.saturating_add(1);
        }
    }
    if !config.events.is_multiple_of(config.batch) {
        let at = Instant::now();
        writer
            .flush()
            .map_err(|error| format!("flushing final SBE batch: {error}"))?;
        flushed_ns.push(now_ns(at));
        let at = Instant::now();
        writer
            .sync_data()
            .map_err(|error| format!("syncing final SBE data: {error}"))?;
        synced_data_ns.push(now_ns(at));
        let at = Instant::now();
        writer
            .sync_all()
            .map_err(|error| format!("syncing final SBE file: {error}"))?;
        synced_all_ns.push(now_ns(at));
        counters.flushed = counters.flushed.saturating_add(1);
        counters.synced_data = counters.synced_data.saturating_add(1);
        counters.synced_all = counters.synced_all.saturating_add(1);
    }
    let writer_checksum = writer
        .checksum_hex()
        .ok_or_else(|| "SBE checksum was not enabled".to_owned())?;
    let journal_bytes =
        fs::read(&journal_path).map_err(|error| format!("reading journal bytes: {error}"))?;
    let file_sha256 = format!("sha256:{}", sha256_hex(&journal_bytes));
    if writer_checksum != file_sha256.trim_start_matches("sha256:") {
        return Err("writer checksum does not match persisted journal bytes".to_owned());
    }

    // Real aligned reader: decode every message back in production order.
    let mut reader =
        AlignedSbeReader::<OpaqueSchema>::open_with_chunk_size(&journal_path, config.chunk_bytes)
            .map_err(|error| format!("opening aligned SBE reader: {error}"))?;
    let mut sbe_replayed_ns = Vec::with_capacity(config.events);
    let mut sbe_order: Vec<u64> = Vec::with_capacity(config.events);
    loop {
        let at = Instant::now();
        let message = reader
            .read_msg()
            .map_err(|error| format!("reading aligned SBE message: {error}"))?;
        sbe_replayed_ns.push(now_ns(at));
        let Some(message) = message else { break };
        let expected = payloads
            .get(sbe_order.len())
            .ok_or_else(|| "SBE replay produced more messages than events".to_owned())?;
        if message.sequence != sbe_order.len() as u64 + 1
            || message.payload != expected.as_slice()
            || message.checksum != fnv1a64(expected)
        {
            counters.errors = counters.errors.saturating_add(1);
        }
        sbe_order.push(message.sequence);
    }
    if sbe_order.len() != config.events {
        return Err(format!(
            "SBE replay saw {} messages, expected {}",
            sbe_order.len(),
            config.events
        ));
    }

    // Real streaming source replay: fingerprint + bounded line reads.
    let mut source = fieldbook::storage::application::file_source::FileSource::open(
        &source_path,
        "opaque-source",
    )
    .map_err(|error| format!("opening streaming source: {error}"))?;
    let mut file_replayed_ns = Vec::with_capacity(config.events);
    let mut file_order: Vec<u64> = Vec::with_capacity(config.events);
    loop {
        let at = Instant::now();
        let observation = source
            .read_one()
            .map_err(|error| format!("reading streaming source: {error}"))?;
        file_replayed_ns.push(now_ns(at));
        let Some(observation) = observation else {
            break;
        };
        let expected = payloads
            .get(file_order.len())
            .ok_or_else(|| "source replay produced more observations than events".to_owned())?;
        if observation.sequence != file_order.len() as u64 + 1
            || observation.raw_bytes != source_line(observation.sequence, expected).as_bytes()
        {
            counters.errors = counters.errors.saturating_add(1);
        }
        file_order.push(observation.sequence);
    }
    if file_order.len() != config.events {
        return Err(format!(
            "streaming replay saw {} observations, expected {}",
            file_order.len(),
            config.events
        ));
    }

    // Real journal replay and interruptible replay on batch-boundary prefixes.
    let mut journal_replayed_ns = Vec::new();
    let mut interrupt_ns = Vec::new();
    let mut stream_checkpoint_ns = Vec::new();
    let identity = SourceIdentity::register("opaque-source", text.as_bytes());
    let binding = CheckpointBinding::new(&identity, "opaque-target");
    let interrupt_at = config.events / 2;
    let mut final_state_digest = String::new();
    let mut final_checkpoint_digest = String::new();
    let mut prefix = config.batch;
    while prefix <= config.events {
        let at = Instant::now();
        let state = replay(&journal_events[..prefix])
            .map_err(|error| format!("journal replay failed: {error}"))?;
        journal_replayed_ns.push(now_ns(at));
        if state.applied.len() != prefix || state.last_offset != prefix as u64 * 16 {
            counters.errors = counters.errors.saturating_add(1);
        }
        final_state_digest = state.digest();

        let at = Instant::now();
        match replay_with_interrupt(
            &journal_events[..prefix],
            Some(interrupt_at.min(prefix - 1)),
        ) {
            Err(ReplayError::Interrupted { at: stopped }) => {
                if stopped != interrupt_at.min(prefix - 1) {
                    counters.errors = counters.errors.saturating_add(1);
                }
            }
            _ => counters.errors = counters.errors.saturating_add(1),
        }
        interrupt_ns.push(now_ns(at));

        let at = Instant::now();
        let checkpoint = StreamCheckpoint::create(
            binding.clone(),
            "opaque-partition",
            1,
            GENESIS_CHECKPOINT.to_owned(),
            &journal_events[..prefix],
            None,
        )
        .map_err(|error| format!("stream checkpoint failed: {error}"))?;
        stream_checkpoint_ns.push(now_ns(at));
        if checkpoint.last_sequence != prefix as u64 {
            counters.errors = counters.errors.saturating_add(1);
        }
        final_checkpoint_digest = checkpoint.digest();
        prefix = prefix.saturating_add(config.batch);
    }

    // Real authorization checkpoint from the operation-plan module.
    let mut authorization_ns = Vec::with_capacity(config.events);
    for _ in 0..config.events {
        let at = Instant::now();
        let outcome = session
            .checkpoint()
            .map_err(|error| format!("authorization checkpoint failed: {error}"))?;
        authorization_ns.push(now_ns(at));
        let _ = outcome;
        if session.is_halted() {
            counters.errors = counters.errors.saturating_add(1);
        }
    }

    let duration_ns = now_ns(started);
    counters.offered = config.events as u64;
    counters.bytes_written = writer.bytes_written();
    counters.source_bytes = source_bytes;
    counters.journal_bytes = journal_bytes.len() as u64;
    counters.sbe_replayed = sbe_order.len() as u64;
    counters.file_source_replayed = file_order.len() as u64;
    let journal_replay_count = journal_replayed_ns.len() as u64;
    counters.journal_replayed = journal_replay_count;
    counters.interrupt_replayed = interrupt_ns.len() as u64;
    counters.stream_checkpointed = stream_checkpoint_ns.len() as u64;
    counters.authorization_checkpointed = authorization_ns.len() as u64;

    stages.push(("sbe_append".to_owned(), appended_ns));
    stage_bytes.push(batch_bytes);
    stages.push(("sbe_flush".to_owned(), flushed_ns));
    stage_bytes.push(batch_bytes);
    stages.push(("sbe_sync_data".to_owned(), synced_data_ns));
    stage_bytes.push(batch_bytes);
    stages.push(("sbe_sync_all".to_owned(), synced_all_ns));
    stage_bytes.push(journal_bytes.len() as u64);
    stages.push(("sbe_replay".to_owned(), sbe_replayed_ns));
    stage_bytes.push(batch_bytes);
    stages.push(("file_source_replay".to_owned(), file_replayed_ns));
    stage_bytes.push(source_bytes);
    stages.push(("journal_replay".to_owned(), journal_replayed_ns));
    stage_bytes.push(0);
    stages.push(("journal_replay_interrupt".to_owned(), interrupt_ns));
    stage_bytes.push(0);
    stages.push(("stream_checkpoint".to_owned(), stream_checkpoint_ns));
    stage_bytes.push(0);
    stages.push(("authorization_checkpoint".to_owned(), authorization_ns));
    stage_bytes.push(0);
    stages.push(("pipeline_total".to_owned(), vec![duration_ns]));
    stage_bytes.push(journal_bytes.len() as u64);

    let correctness = Correctness {
        event_order_digest: u64_seq_digest(&sbe_order),
        journal_bytes_digest: format!("fnv1a128:{}", fnv1a128_hex(&journal_bytes)),
        replayed_state_digest: final_state_digest,
        stream_checkpoint_digest: final_checkpoint_digest,
        writer_checksum,
        file_sha256,
        sbe_replayed: sbe_order.len() as u64,
        file_source_replayed: file_order.len() as u64,
        journal_replayed: journal_replay_count,
        errors: counters.errors,
    };

    Ok(PassResult {
        stages,
        stage_bytes,
        duration_ns,
        counters,
        correctness,
    })
}

fn make_checks(
    config: &Config,
    before: &Correctness,
    after: &Correctness,
    results: &[StageResult],
    bindings: &Bindings,
) -> Vec<Check> {
    let mut checks = Vec::new();
    let mut push = |name: &str, passed: bool| {
        checks.push(Check {
            name: name.to_owned(),
            passed,
        });
    };
    push(
        "event_order_identical",
        before.event_order_digest == after.event_order_digest,
    );
    push(
        "journal_bytes_identical",
        before.journal_bytes_digest == after.journal_bytes_digest,
    );
    push(
        "replayed_state_identical",
        before.replayed_state_digest == after.replayed_state_digest,
    );
    push(
        "stream_checkpoint_identical",
        before.stream_checkpoint_digest == after.stream_checkpoint_digest,
    );
    push(
        "writer_checksum_stable",
        before.writer_checksum == after.writer_checksum,
    );
    push(
        "file_sha256_stable",
        before.file_sha256 == after.file_sha256,
    );
    push(
        "sbe_replay_count_stable",
        before.sbe_replayed == after.sbe_replayed,
    );
    push(
        "file_replay_count_stable",
        before.file_source_replayed == after.file_source_replayed,
    );
    push(
        "journal_replay_count_stable",
        before.journal_replayed == after.journal_replayed,
    );
    push(
        "no_verification_errors",
        after.errors == 0 && before.errors == 0,
    );
    push(
        "event_count_preserved",
        after.sbe_replayed == config.events as u64,
    );
    push(
        "all_samples_present",
        results.iter().all(|result| result.count > 0),
    );
    push(
        "percentiles_ordered",
        results.iter().all(|result| {
            result.p50_ns <= result.p90_ns
                && result.p90_ns <= result.p95_ns
                && result.p95_ns <= result.p99_ns
                && result.p99_ns <= result.p999_ns
                && result.p999_ns <= result.max_ns
        }),
    );
    push(
        "beyond_max_is_zero",
        results.iter().all(|result| result.beyond_max == 0),
    );
    push(
        "raw_digests_present",
        results
            .iter()
            .all(|result| result.raw_result_digest.starts_with("fnv1a128:")),
    );
    push(
        "bindings_present",
        !bindings.source_sha.is_empty()
            && !bindings.binary_digest.is_empty()
            && !bindings.toolchain.is_empty()
            && !bindings.target_triple.is_empty()
            && !bindings.compiler_flags.is_empty()
            && !bindings.build_profile.is_empty()
            && !bindings.os.is_empty()
            && !bindings.cpu.is_empty()
            && !bindings.machine.is_empty()
            && !bindings.filesystem.is_empty()
            && !bindings.workload_digest.is_empty(),
    );
    checks
}

fn run_bench(config: &Config) -> Result<Vec<Artifact>, String> {
    config.validate()?;
    let mut artifacts = Vec::with_capacity(config.reps);
    for repetition_index in 0..config.reps {
        let before_directory = tempfile::tempdir()
            .map_err(|error| format!("creating pre-check directory: {error}"))?;
        let before = run_pass(config, before_directory.path())?;
        let measured_directory =
            tempfile::tempdir().map_err(|error| format!("creating measured directory: {error}"))?;
        let measured = run_pass(config, measured_directory.path())?;
        if before.correctness != measured.correctness {
            return Err(
                "correctness pre-pass and measured pass disagree on event order, journal bytes or replayed state"
                    .to_owned(),
            );
        }
        let bindings = collect_bindings(
            config,
            measured.duration_ns,
            &workload_digest(
                config,
                &(1..=config.events as u64)
                    .map(|sequence| make_payload(config.seed, sequence, config.payload_bytes))
                    .collect::<Vec<_>>(),
            ),
        );
        let results = measured
            .stages
            .iter()
            .zip(measured.stage_bytes.iter())
            .map(|((name, samples), bytes)| {
                StageResult::from_samples(
                    name,
                    &SampleSet {
                        samples: samples.clone(),
                    },
                    *bytes,
                )
            })
            .collect::<Vec<_>>();
        let checks = make_checks(
            config,
            &before.correctness,
            &measured.correctness,
            &results,
            &bindings,
        );
        artifacts.push(Artifact {
            repetition_index,
            bindings,
            config: config.clone(),
            results,
            counters: measured.counters,
            before: before.correctness,
            after: measured.correctness,
            checks,
        });
    }
    if artifacts.is_empty() {
        return Err("no benchmark repetition was recorded".to_owned());
    }
    Ok(artifacts)
}

fn jstr(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if other.is_control() => {
                let _ = FmtWrite::write_fmt(&mut out, format_args!("\\u{:04x}", u32::from(other)));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn binding_json(binding: &Bindings) -> String {
    format!(
        concat!(
            "{{\"source_sha\":{source_sha},\"binary_digest\":{binary_digest},",
            "\"toolchain\":{toolchain},\"rustc_verbose\":{rustc_verbose},",
            "\"target_triple\":{target_triple},\"compiler_flags\":{compiler_flags},",
            "\"build_profile\":{build_profile},\"debug_assertions\":{debug_assertions},",
            "\"os\":{os},\"cpu\":{cpu},\"machine\":{machine},\"filesystem\":{filesystem},",
            "\"workload_digest\":{workload},\"seed\":{seed},",
            "\"start_load_average\":{start_load},\"event_count\":{events},",
            "\"warmup_policy\":{warmup},\"duration_ns\":{duration},\"repetitions\":{reps},",
            "\"quantile_method\":{quantile},\"payload_bytes\":{payload},",
            "\"batch_size\":{batch},\"chunk_bytes\":{chunk},\"interrupt_at\":{interrupt}}}"
        ),
        source_sha = jstr(&binding.source_sha),
        binary_digest = jstr(&binding.binary_digest),
        toolchain = jstr(&binding.toolchain),
        rustc_verbose = jstr(&binding.rustc_verbose),
        target_triple = jstr(&binding.target_triple),
        compiler_flags = jstr(&binding.compiler_flags),
        build_profile = jstr(&binding.build_profile),
        debug_assertions = binding.debug_assertions,
        os = jstr(&binding.os),
        cpu = jstr(&binding.cpu),
        machine = jstr(&binding.machine),
        filesystem = jstr(&binding.filesystem),
        workload = jstr(&binding.workload_digest),
        seed = binding.seed,
        start_load = binding
            .start_load_average
            .as_deref()
            .map(jstr)
            .unwrap_or_else(|| "null".to_owned()),
        events = binding.event_count,
        warmup = jstr(&binding.warmup_policy),
        duration = binding.duration_ns,
        reps = binding.repetitions,
        quantile = jstr(&binding.quantile_method),
        payload = binding.payload_bytes,
        batch = binding.batch_size,
        chunk = binding.chunk_bytes,
        interrupt = binding.interrupt_at,
    )
}

fn counters_json(counters: &Counters, duration_ns: u64) -> String {
    let offered_rate = (u128::from(counters.offered) * 1_000_000_000)
        .checked_div(u128::from(duration_ns).max(1))
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0);
    let bytes_rate = (u128::from(counters.bytes_written) * 1_000_000_000)
        .checked_div(u128::from(duration_ns).max(1))
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0);
    format!(
        concat!(
            "{{\"offered\":{offered},\"appended\":{appended},\"flushed\":{flushed},",
            "\"synced_data\":{synced_data},\"synced_all\":{synced_all},",
            "\"sbe_replayed\":{sbe_replayed},\"file_source_replayed\":{file_replayed},",
            "\"journal_replayed\":{journal_replayed},\"interrupt_replayed\":{interrupt},",
            "\"stream_checkpointed\":{stream_cp},\"authorization_checkpointed\":{auth_cp},",
            "\"errors\":{errors},\"bytes_written\":{bytes},\"source_bytes\":{source},",
            "\"journal_bytes\":{journal},\"offered_events_per_s\":{orate},",
            "\"bytes_per_s\":{brate}}}"
        ),
        offered = counters.offered,
        appended = counters.appended,
        flushed = counters.flushed,
        synced_data = counters.synced_data,
        synced_all = counters.synced_all,
        sbe_replayed = counters.sbe_replayed,
        file_replayed = counters.file_source_replayed,
        journal_replayed = counters.journal_replayed,
        interrupt = counters.interrupt_replayed,
        stream_cp = counters.stream_checkpointed,
        auth_cp = counters.authorization_checkpointed,
        errors = counters.errors,
        bytes = counters.bytes_written,
        source = counters.source_bytes,
        journal = counters.journal_bytes,
        orate = offered_rate,
        brate = bytes_rate,
    )
}

fn correctness_json(correctness: &Correctness) -> String {
    format!(
        concat!(
            "{{\"event_order_digest\":{order},\"journal_bytes_digest\":{journal},",
            "\"replayed_state_digest\":{state},\"stream_checkpoint_digest\":{checkpoint},",
            "\"writer_checksum\":{writer},\"file_sha256\":{file},",
            "\"sbe_replayed\":{sbe},\"file_source_replayed\":{source},",
            "\"journal_replayed\":{replayed},\"errors\":{errors}}}"
        ),
        order = jstr(&correctness.event_order_digest),
        journal = jstr(&correctness.journal_bytes_digest),
        state = jstr(&correctness.replayed_state_digest),
        checkpoint = jstr(&correctness.stream_checkpoint_digest),
        writer = jstr(&correctness.writer_checksum),
        file = jstr(&correctness.file_sha256),
        sbe = correctness.sbe_replayed,
        source = correctness.file_source_replayed,
        replayed = correctness.journal_replayed,
        errors = correctness.errors,
    )
}

fn result_json(result: &StageResult, binding: &str) -> String {
    let raw = result
        .raw_ns
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        concat!(
            "{{\"name\":{name},\"count\":{count},\"total_ns\":{total},",
            "\"p50_ns\":{p50},\"p90_ns\":{p90},\"p95_ns\":{p95},",
            "\"p99_ns\":{p99},\"p99_9_ns\":{p999},\"max_ns\":{max},",
            "\"beyond\":{{\"p50\":{b50},\"p90\":{b90},\"p95\":{b95},",
            "\"p99\":{b99},\"p99_9\":{b999},\"max\":{bmax}}},",
            "\"throughput_per_s\":{throughput},\"bytes_per_s\":{bytes_per_s},",
            "\"stage_bytes\":{stage_bytes},\"raw_result_digest\":{digest},",
            "\"binding\":{binding},\"raw_ns\":[{raw}]}}"
        ),
        name = jstr(&result.name),
        count = result.count,
        total = result.total_ns,
        p50 = result.p50_ns,
        p90 = result.p90_ns,
        p95 = result.p95_ns,
        p99 = result.p99_ns,
        p999 = result.p999_ns,
        max = result.max_ns,
        b50 = result.beyond_p50,
        b90 = result.beyond_p90,
        b95 = result.beyond_p95,
        b99 = result.beyond_p99,
        b999 = result.beyond_p999,
        bmax = result.beyond_max,
        throughput = result.throughput_per_s,
        bytes_per_s = result.bytes_per_s,
        stage_bytes = result.stage_bytes,
        digest = jstr(&result.raw_result_digest),
        binding = binding,
        raw = raw,
    )
}

fn checks_json(checks: &[Check]) -> String {
    let entries = checks
        .iter()
        .map(|check| {
            format!(
                "{{\"name\":{name},\"passed\":{passed}}}",
                name = jstr(&check.name),
                passed = check.passed
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!("[{entries}]")
}

fn artifact_json(artifact: &Artifact) -> String {
    let binding = binding_json(&artifact.bindings);
    let results = artifact
        .results
        .iter()
        .map(|result| result_json(result, &binding))
        .collect::<Vec<_>>()
        .join(",");
    let passed = artifact.checks.iter().all(|check| check.passed);
    format!(
        concat!(
            "{{\"schema_version\":{schema},\"harness\":\"production_components\",",
            "\"mode\":\"bench\",\"label\":{label},\"repetition_index\":{repetition},",
            "\"disclaimer\":{disclaimer},",
            "\"stage_separation\":\"each stage timer wraps exactly one production call; pipeline_total wraps the whole measured pass\",",
            "\"checks_passed\":{passed},\"checks\":{checks},",
            "\"binding\":{binding},\"counters\":{counters},",
            "\"correctness_before\":{before},\"correctness_after\":{after},",
            "\"results\":[{results}]}}"
        ),
        schema = SCHEMA_VERSION,
        label = jstr(&artifact.config.label),
        repetition = artifact.repetition_index,
        disclaimer = jstr(DISCLAIMER),
        passed = passed,
        checks = checks_json(&artifact.checks),
        binding = binding,
        counters = counters_json(&artifact.counters, artifact.bindings.duration_ns),
        before = correctness_json(&artifact.before),
        after = correctness_json(&artifact.after),
        results = results,
    )
}

fn self_test_json(config: &Config, checks: &[Check], passed: bool) -> String {
    format!(
        concat!(
            "{{\"schema_version\":{schema},\"harness\":\"production_components\",",
            "\"mode\":\"self_test\",\"events\":{events},\"payload_bytes\":{payload},",
            "\"batch\":{batch},\"chunk_bytes\":{chunk},\"seed\":{seed},",
            "\"passed\":{passed},\"checks\":{checks},\"disclaimer\":{disclaimer}}}"
        ),
        schema = SCHEMA_VERSION,
        events = config.events,
        payload = config.payload_bytes,
        batch = config.batch,
        chunk = config.chunk_bytes,
        seed = config.seed,
        passed = passed,
        checks = checks_json(checks),
        disclaimer = jstr(DISCLAIMER),
    )
}

fn self_test() -> Result<String, String> {
    let config = Config::self_test();
    config.validate()?;
    let directory =
        tempfile::tempdir().map_err(|error| format!("creating self-test directory: {error}"))?;
    let pass = run_pass(&config, directory.path())?;
    let checks = vec![
        Check {
            name: "sbe_messages_match_events".to_owned(),
            passed: pass.correctness.sbe_replayed == config.events as u64,
        },
        Check {
            name: "file_source_matches_events".to_owned(),
            passed: pass.correctness.file_source_replayed == config.events as u64,
        },
        Check {
            name: "no_verification_errors".to_owned(),
            passed: pass.correctness.errors == 0,
        },
        Check {
            name: "writer_checksum_matches_file".to_owned(),
            passed: pass.correctness.writer_checksum
                == pass.correctness.file_sha256.trim_start_matches("sha256:"),
        },
        Check {
            name: "all_stages_have_samples".to_owned(),
            passed: pass.stages.iter().all(|(_, samples)| !samples.is_empty()),
        },
        Check {
            name: "journal_prefix_replayed".to_owned(),
            passed: pass.correctness.journal_replayed > 0
                && !pass.correctness.replayed_state_digest.is_empty(),
        },
        Check {
            name: "checkpoint_digest_present".to_owned(),
            passed: !pass.correctness.stream_checkpoint_digest.is_empty(),
        },
        Check {
            name: "error_counter_zero".to_owned(),
            passed: pass.counters.errors == 0,
        },
    ];
    let passed = checks.iter().all(|check| check.passed);
    Ok(self_test_json(&config, &checks, passed))
}

fn json_well_formed(text: &str) -> bool {
    let mut stack: Vec<char> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for character in text.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        match character {
            '"' => in_string = true,
            '{' | '[' => stack.push(character),
            '}' if stack.pop() != Some('{') => return false,
            ']' if stack.pop() != Some('[') => return false,
            '}' | ']' => {}
            _ => {}
        }
    }
    !in_string && stack.is_empty()
}

fn parse_args(args: &[String]) -> Result<(bool, bool, Config), String> {
    let mut self_test = false;
    let mut help = false;
    let mut config = Config::default_run();
    for arg in args {
        let (key, value) = arg.split_once('=').unwrap_or((arg.as_str(), ""));
        match key {
            "--self-test" => self_test = true,
            "--help" => help = true,
            "--events" => config.events = parse_usize(value, key)?,
            "--payload" => config.payload_bytes = parse_usize(value, key)?,
            "--batch" => config.batch = parse_usize(value, key)?,
            "--chunk" => config.chunk_bytes = parse_usize(value, key)?,
            "--seed" => {
                config.seed = value
                    .parse::<u64>()
                    .map_err(|_| "invalid --seed".to_owned())?
            }
            "--reps" => config.reps = parse_usize(value, key)?,
            "--start-load-average" => config.start_load_average = Some(value.to_owned()),
            "--label" => config.label = value.to_owned(),
            "--output" => config.output = Some(PathBuf::from(value)),
            other => return Err(format!("unknown option `{other}`")),
        }
    }
    Ok((self_test, help, config))
}

fn parse_usize(value: &str, key: &str) -> Result<usize, String> {
    value.parse::<usize>().map_err(|_| format!("invalid {key}"))
}

fn run() -> Result<String, String> {
    // Cargo appends its own bench/test flags when it launches a custom-harness
    // binary. Drop those so user-facing options stay strict. A bare invocation
    // (including `cargo test --all-targets`) runs only the tiny self-test: no
    // performance measurement ever becomes a CI side effect.
    let args: Vec<String> = env::args()
        .skip(1)
        .filter(|arg| {
            arg != "--bench"
                && arg != "production_components"
                && arg != "--test"
                && arg != "--nocapture"
        })
        .collect();
    let (self_test_requested, help, config) = parse_args(&args)?;
    if help {
        return Ok(concat!(
            "{\"schema_version\":1,\"harness\":\"production_components\",",
            "\"mode\":\"usage\",\"options\":[\"--self-test\",\"--events=N\",",
            "\"--payload=N\",\"--batch=N\",\"--chunk=N\",\"--seed=N\",",
            "\"--reps=N\",\"--start-load-average=STR\",\"--label=STR\",",
            "\"--output=PATH\",\"--help\"]}"
        )
        .to_owned());
    }
    if self_test_requested || args.is_empty() {
        return self_test();
    }
    let artifacts = run_bench(&config)?;
    let passed = artifacts
        .iter()
        .all(|artifact| artifact.checks.iter().all(|check| check.passed));
    // Every executed repetition is retained as a full artifact. The top-level
    // single-pass fields remain as a compatible view of repetition 0, while
    // `artifacts` carries all repetitions for independent verification.
    let first = &artifacts[0];
    let binding = binding_json(&first.bindings);
    let results = first
        .results
        .iter()
        .map(|result| result_json(result, &binding))
        .collect::<Vec<_>>()
        .join(",");
    let artifacts_json = artifacts
        .iter()
        .map(artifact_json)
        .collect::<Vec<_>>()
        .join(",");
    let text = format!(
        concat!(
            "{{\"schema_version\":{schema},\"harness\":\"production_components\",",
            "\"mode\":\"bench\",\"label\":{label},\"disclaimer\":{disclaimer},",
            "\"stage_separation\":\"each stage timer wraps exactly one production call; pipeline_total wraps the whole measured pass\",",
            "\"checks_passed\":{passed},\"checks\":{checks},",
            "\"binding\":{binding},\"counters\":{counters},",
            "\"correctness_before\":{before},\"correctness_after\":{after},",
            "\"results\":[{results}],\"repetitions_executed\":{executed},",
            "\"repetitions_retained\":{retained},\"digest_input_format\":{digest_format},",
            "\"artifacts\":[{artifacts}]}}"
        ),
        schema = SCHEMA_VERSION,
        label = jstr(&config.label),
        disclaimer = jstr(DISCLAIMER),
        passed = passed,
        checks = checks_json(&first.checks),
        binding = binding,
        counters = counters_json(&first.counters, first.bindings.duration_ns),
        before = correctness_json(&first.before),
        after = correctness_json(&first.after),
        results = results,
        executed = artifacts.len(),
        retained = artifacts.len(),
        digest_format = jstr(DIGEST_INPUT_FORMAT),
        artifacts = artifacts_json,
    );
    if let Some(path) = &config.output {
        fs::write(path, format!("{text}\n"))
            .map_err(|error| format!("writing artifact to {}: {error}", path.display()))?;
    }
    Ok(format!(
        "{{\"schema_version\":1,\"harness\":\"production_components\",\"mode\":\"bench\",\"artifact_digest\":\"sha256:{}\",\"passed\":{},\"repetitions_executed\":{},\"repetitions_retained\":{}}}",
        sha256_hex(format!("{text}\n").as_bytes()),
        passed,
        artifacts.len(),
        artifacts.len()
    ))
}

fn main() -> ExitCode {
    match run() {
        Ok(json) => {
            if !json_well_formed(&json) {
                eprintln!("{{\"error\":\"generated output is not well-formed JSON\"}}");
                return ExitCode::FAILURE;
            }
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{{\"error\":{}}}", jstr(&error));
            ExitCode::FAILURE
        }
    }
}
