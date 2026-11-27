// SPDX-License-Identifier: Apache-2.0
//! Neutral, reusable pipeline benchmark harness.
//!
//! This harness measures isolated stages of an append-only record pipeline using
//! workload material that carries no market meaning: opaque byte payloads and
//! monotonically increasing test sequence values only. It uses the standard
//! library alone and emits one machine-readable JSON artifact on stdout.
//!
//! Measured stages: serialization, queue admission, journal `written`,
//! journal `flushed`, journal `synced`, replay, checkpoint, service and
//! end-to-end. No source, right, data or execution policy is changed here.

#![expect(
    clippy::print_stdout,
    reason = "a benchmark harness emits its JSON artifact on stdout"
)]

use std::{
    collections::{HashSet, VecDeque},
    env,
    fmt::Write as FmtWrite,
    fs::{self, File},
    io::{BufReader, BufWriter, Read, Write as IoWrite},
    path::Path,
    process::{Command, ExitCode},
    sync::{Arc, Condvar, Mutex},
    thread,
    time::Instant,
};

const SCHEMA_VERSION: u32 = 1;
const FRAME_MAGIC: [u8; 4] = *b"NB01";
const TRAILER_BYTES: usize = 8;
const SUPPORTED_PAYLOADS: [usize; 4] = [64, 256, 1024, 4096];
const SUPPORTED_BATCHES: [usize; 4] = [1, 8, 32, 128];
const SUPPORTED_QUEUES: [usize; 4] = [8, 64, 256, 1024];
const SUPPORTED_PRODUCERS: [usize; 4] = [1, 2, 4, 8];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arrival {
    Open,
    Closed,
}

impl Arrival {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct Config {
    payload_bytes: usize,
    batch: usize,
    queue_capacity: usize,
    producers: usize,
    arrival: Arrival,
    seed: u64,
    events: usize,
    reps: usize,
    label: String,
}

impl Config {
    fn default_run() -> Self {
        Self {
            payload_bytes: 256,
            batch: 8,
            queue_capacity: 64,
            producers: 2,
            arrival: Arrival::Closed,
            seed: 0x4e_42_50_4c,
            events: 256,
            reps: 1,
            label: "local".to_owned(),
        }
    }

    fn self_test(arrival: Arrival) -> Self {
        Self {
            payload_bytes: 64,
            batch: 8,
            queue_capacity: 8,
            producers: 1,
            arrival,
            seed: 0x5e_1f_57,
            events: 8,
            reps: 1,
            label: "self-test".to_owned(),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct Bindings {
    source_sha: String,
    toolchain: String,
    compiler_flags: String,
    os: String,
    arch: String,
    cpu: String,
    machine: String,
    filesystem: String,
}

#[derive(Debug, Clone)]
struct SampleSet {
    samples: Vec<u64>,
}

impl SampleSet {
    fn new(samples: Vec<u64>) -> Self {
        Self { samples }
    }

    fn percentile(&self, numerator: u64, denominator: u64) -> u64 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let rank = (sorted.len() as u128 * numerator as u128 / denominator as u128) as usize;
        let index = rank.min(sorted.len() - 1);
        sorted[index]
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

    fn digest(&self) -> String {
        let mut bytes = Vec::with_capacity(self.samples.len() * 8);
        for sample in &self.samples {
            bytes.extend_from_slice(&sample.to_le_bytes());
        }
        fnv1a128_hex(&bytes)
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
    raw_result_digest: String,
}

impl StageResult {
    fn from_samples(name: &str, samples: &SampleSet) -> Self {
        let total = samples
            .samples
            .iter()
            .map(|value| u128::from(*value))
            .sum::<u128>();
        let p50 = samples.percentile(50, 100);
        let p90 = samples.percentile(90, 100);
        let p95 = samples.percentile(95, 100);
        let p99 = samples.percentile(99, 100);
        let p999 = samples.percentile(999, 1000);
        let max = samples.max();
        Self {
            name: name.to_owned(),
            count: samples.samples.len() as u64,
            total_ns: u64::try_from(total).unwrap_or(u64::MAX),
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
            raw_result_digest: samples.digest(),
        }
    }

    fn to_json(&self, binding: &str) -> String {
        format!(
            concat!(
                "{{\"name\":{name},\"count\":{count},\"total_ns\":{total},",
                "\"p50_ns\":{p50},\"p90_ns\":{p90},\"p95_ns\":{p95},",
                "\"p99_ns\":{p99},\"p99_9_ns\":{p999},\"max_ns\":{max},",
                "\"beyond\":{{\"p50\":{b50},\"p90\":{b90},\"p95\":{b95},",
                "\"p99\":{b99},\"p99_9\":{b999},\"max\":{bmax}}},",
                "\"raw_result_digest\":{digest},{binding}}}"
            ),
            name = jstr(&self.name),
            count = self.count,
            total = self.total_ns,
            p50 = self.p50_ns,
            p90 = self.p90_ns,
            p95 = self.p95_ns,
            p99 = self.p99_ns,
            p999 = self.p999_ns,
            max = self.max_ns,
            b50 = self.beyond_p50,
            b90 = self.beyond_p90,
            b95 = self.beyond_p95,
            b99 = self.beyond_p99,
            b999 = self.beyond_p999,
            bmax = self.beyond_max,
            digest = jstr(&self.raw_result_digest),
            binding = binding,
        )
    }
}

#[derive(Debug, Default, Clone)]
struct Counters {
    offered: u64,
    accepted: u64,
    rejected: u64,
    written: u64,
    flushed: u64,
    synced: u64,
    replayed: u64,
    checkpointed: u64,
    errors: u64,
    bytes_written: u64,
    allocation_bytes: u64,
    allocation_calls: u64,
    queue_depth_max: u64,
    queue_depth_mean: u64,
    queue_depth_samples: u64,
}

#[derive(Debug, Clone)]
struct Artifact {
    bindings: Bindings,
    config: Config,
    workload_digest: String,
    duration_ns: u64,
    offered_rate_per_s: u64,
    bytes_per_s: u64,
    results: Vec<StageResult>,
    counters: Counters,
}

#[derive(Debug, Clone)]
struct Check {
    name: String,
    passed: bool,
}

struct RawRecord {
    sequence: u64,
    payload: Vec<u8>,
    created_ns: u64,
}

struct QueueState {
    items: VecDeque<RawRecord>,
    depth_samples: Vec<u64>,
    closed: bool,
}

struct BoundedQueue {
    capacity: usize,
    state: Mutex<QueueState>,
    not_empty: Condvar,
    not_full: Condvar,
}

impl BoundedQueue {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(QueueState {
                items: VecDeque::new(),
                depth_samples: Vec::new(),
                closed: false,
            }),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
        }
    }

    fn try_push(&self, record: RawRecord) -> Result<(), RawRecord> {
        let mut state = lock(&self.state);
        if state.closed || state.items.len() >= self.capacity {
            return Err(record);
        }
        state.items.push_back(record);
        let depth = state.items.len() as u64;
        state.depth_samples.push(depth);
        drop(state);
        self.not_empty.notify_one();
        Ok(())
    }

    fn push(&self, record: RawRecord) -> Result<(), RawRecord> {
        let mut state = lock(&self.state);
        loop {
            if state.closed {
                return Err(record);
            }
            if state.items.len() < self.capacity {
                state.items.push_back(record);
                let depth = state.items.len() as u64;
                state.depth_samples.push(depth);
                drop(state);
                self.not_empty.notify_one();
                return Ok(());
            }
            let guard = self
                .not_full
                .wait(state)
                .unwrap_or_else(|poison| poison.into_inner());
            state = guard;
        }
    }

    fn pop(&self) -> Option<RawRecord> {
        let mut state = lock(&self.state);
        loop {
            if let Some(record) = state.items.pop_front() {
                drop(state);
                self.not_full.notify_one();
                return Some(record);
            }
            if state.closed {
                return None;
            }
            let guard = self
                .not_empty
                .wait(state)
                .unwrap_or_else(|poison| poison.into_inner());
            state = guard;
        }
    }

    fn close(&self) {
        let mut state = lock(&self.state);
        state.closed = true;
        drop(state);
        self.not_empty.notify_all();
        self.not_full.notify_all();
    }

    fn abort(&self) {
        self.close();
    }

    fn depth_samples(&self) -> Vec<u64> {
        lock(&self.state).depth_samples.clone()
    }
}

#[derive(Debug, Default, Clone)]
struct ProducerStats {
    offered: u64,
    accepted: u64,
    rejected: u64,
    admission_ns: Vec<u64>,
}

#[derive(Debug, Default)]
struct WriterStats {
    serialization_ns: Vec<u64>,
    written_ns: Vec<u64>,
    flushed_ns: Vec<u64>,
    synced_ns: Vec<u64>,
    checkpoint_ns: Vec<u64>,
    service_ns: Vec<u64>,
    end_to_end_ns: Vec<u64>,
    written: u64,
    flushed: u64,
    synced: u64,
    checkpointed: u64,
    bytes_written: u64,
    allocation_bytes: u64,
    allocation_calls: u64,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poison| poison.into_inner())
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

fn fnv1a128(bytes: &[u8]) -> [u64; 2] {
    [fnv1a64(bytes), fnv1a64_offset(bytes, 0x9e37_79b9_7f4a_7c15)]
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
    let parts = fnv1a128(bytes);
    format!("{:016x}{:016x}", parts[0], parts[1])
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

fn serialize(record: &RawRecord) -> Vec<u8> {
    let mut frame =
        Vec::with_capacity(FRAME_MAGIC.len() + 8 + 4 + record.payload.len() + TRAILER_BYTES);
    frame.extend_from_slice(&FRAME_MAGIC);
    frame.extend_from_slice(&record.sequence.to_le_bytes());
    let length = u32::try_from(record.payload.len()).unwrap_or(u32::MAX);
    frame.extend_from_slice(&length.to_le_bytes());
    frame.extend_from_slice(&record.payload);
    frame.extend_from_slice(&fnv1a64(&record.payload).to_le_bytes());
    frame
}

fn config_digest(config: &Config) -> String {
    let mut text = String::new();
    let _ = write!(
        &mut text,
        "v{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        SCHEMA_VERSION,
        config.payload_bytes,
        config.batch,
        config.queue_capacity,
        config.producers,
        config.arrival.as_str(),
        config.seed,
        config.events,
        config.reps,
        config.label
    );
    for sequence in 1..=config.events as u64 {
        let payload = make_payload(config.seed, sequence, config.payload_bytes);
        let _ = write!(&mut text, "|{}", fnv1a128_hex(&payload));
    }
    fnv1a128_hex(text.as_bytes())
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
        command_output("mount", &[])
            .and_then(|text| {
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
            .unwrap_or_else(|| "unknown".to_owned())
    } else {
        command_output("stat", &["-f", "-c", "%T", &path]).unwrap_or_else(|| "unknown".to_owned())
    }
}

fn collect_bindings(directory: &Path) -> Bindings {
    let compiler_flags = env::var("CARGO_ENCODED_RUSTFLAGS")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| env::var("RUSTFLAGS").ok())
        .unwrap_or_else(|| "(none)".to_owned());
    let os = env::consts::OS.to_owned();
    let filesystem = filesystem_type(directory, &os);
    Bindings {
        source_sha: command_output("git", &["rev-parse", "HEAD"])
            .unwrap_or_else(|| "unknown".to_owned()),
        toolchain: command_output("rustc", &["--version"]).unwrap_or_else(|| "unknown".to_owned()),
        compiler_flags,
        os,
        arch: env::consts::ARCH.to_owned(),
        cpu: command_output("sysctl", &["-n", "machdep.cpu.brand_string"])
            .or_else(|| command_output("uname", &["-p"]))
            .unwrap_or_else(|| "unknown".to_owned()),
        machine: command_output("hostname", &[])
            .or_else(|| env::var("HOSTNAME").ok())
            .unwrap_or_else(|| "unknown".to_owned()),
        filesystem,
    }
}

fn run_directory(seed: u64) -> Result<std::path::PathBuf, String> {
    let directory = env::temp_dir().join(format!(
        "fieldbook-neutral-bench-{seed}-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)
        .map_err(|error| format!("creating benchmark directory: {error}"))?;
    Ok(directory)
}

fn produce(
    config: Config,
    first: usize,
    last: usize,
    start: Instant,
    queue: Arc<BoundedQueue>,
    stats: Arc<Mutex<ProducerStats>>,
) -> Result<(), String> {
    for sequence in first..=last {
        let sequence = sequence as u64 + 1;
        let record = RawRecord {
            sequence,
            payload: make_payload(config.seed, sequence, config.payload_bytes),
            created_ns: now_ns(start),
        };
        let admitted_at = Instant::now();
        let outcome = match config.arrival {
            Arrival::Open => queue.try_push(record),
            Arrival::Closed => queue.push(record),
        };
        let wait = u64::try_from(admitted_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
        let mut shared = lock(&stats);
        shared.offered = shared.offered.saturating_add(1);
        match outcome {
            Ok(()) => {
                shared.accepted = shared.accepted.saturating_add(1);
                shared.admission_ns.push(wait);
            }
            Err(_) => {
                shared.rejected = shared.rejected.saturating_add(1);
            }
        }
    }
    Ok(())
}

fn flush_batch(
    writer: &mut BufWriter<File>,
    batch: &[RawRecord],
    checkpoint: &Path,
    checkpoint_value: &str,
    start: Instant,
    stats: &mut WriterStats,
) -> Result<(), String> {
    let flush_at = Instant::now();
    writer
        .flush()
        .map_err(|error| format!("flushing journal buffer: {error}"))?;
    let flushed = u64::try_from(flush_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let sync_at = Instant::now();
    writer
        .get_ref()
        .sync_all()
        .map_err(|error| format!("syncing journal: {error}"))?;
    let synced = u64::try_from(sync_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let checkpoint_at = Instant::now();
    let mut sink = BufWriter::new(
        File::create(checkpoint).map_err(|error| format!("creating checkpoint: {error}"))?,
    );
    let last_sequence = batch.last().map(|record| record.sequence).unwrap_or(0);
    let _ = writeln!(&mut sink, "{last_sequence} {checkpoint_value}");
    sink.flush()
        .map_err(|error| format!("flushing checkpoint: {error}"))?;
    sink.get_ref()
        .sync_all()
        .map_err(|error| format!("syncing checkpoint: {error}"))?;
    let checkpointed = u64::try_from(checkpoint_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
    stats.flushed_ns.push(flushed);
    stats.synced_ns.push(synced);
    stats.checkpoint_ns.push(checkpointed);
    for record in batch {
        stats.flushed = stats.flushed.saturating_add(1);
        stats.synced = stats.synced.saturating_add(1);
        stats.checkpointed = stats.checkpointed.saturating_add(1);
        let completed = now_ns(start);
        let elapsed = completed.saturating_sub(record.created_ns);
        stats.end_to_end_ns.push(elapsed);
    }
    Ok(())
}

fn write_journal(
    config: Config,
    directory: &Path,
    start: Instant,
    queue: Arc<BoundedQueue>,
) -> Result<WriterStats, String> {
    let journal_path = directory.join("journal.nb");
    let checkpoint_path = directory.join("checkpoint.nb");
    let checkpoint_value = config_digest(&config);
    let mut writer = BufWriter::new(
        File::create(&journal_path).map_err(|error| format!("creating journal: {error}"))?,
    );
    let mut stats = WriterStats::default();
    let mut batch: Vec<RawRecord> = Vec::with_capacity(config.batch);
    let result = (|| -> Result<(), String> {
        while let Some(record) = queue.pop() {
            let serialize_at = Instant::now();
            let frame = serialize(&record);
            let serialized = u64::try_from(serialize_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
            let write_at = Instant::now();
            writer
                .write_all(&frame)
                .map_err(|error| format!("writing journal frame: {error}"))?;
            let written = u64::try_from(write_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
            stats.serialization_ns.push(serialized);
            stats.written_ns.push(written);
            stats.service_ns.push(serialized.saturating_add(written));
            stats.written = stats.written.saturating_add(1);
            stats.bytes_written = stats.bytes_written.saturating_add(frame.len() as u64);
            stats.allocation_bytes = stats
                .allocation_bytes
                .saturating_add(frame.capacity() as u64);
            stats.allocation_calls = stats.allocation_calls.saturating_add(1);
            batch.push(record);
            if batch.len() == config.batch {
                flush_batch(
                    &mut writer,
                    &batch,
                    &checkpoint_path,
                    &checkpoint_value,
                    start,
                    &mut stats,
                )?;
                batch.clear();
            }
        }
        if !batch.is_empty() {
            flush_batch(
                &mut writer,
                &batch,
                &checkpoint_path,
                &checkpoint_value,
                start,
                &mut stats,
            )?;
        }
        writer
            .flush()
            .map_err(|error| format!("final flush: {error}"))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|error| format!("final sync: {error}"))?;
        Ok(())
    })();
    queue.abort();
    result.map(|()| stats)
}

fn read_frame(reader: &mut BufReader<File>) -> Result<Option<(u64, Vec<u8>)>, String> {
    let mut magic = [0u8; FRAME_MAGIC.len()];
    let first = reader
        .read(&mut magic[..1])
        .map_err(|error| format!("reading frame boundary: {error}"))?;
    if first == 0 {
        return Ok(None);
    }
    if first != 1 {
        return Err("partial frame boundary".to_owned());
    }
    reader
        .read_exact(&mut magic[1..])
        .map_err(|error| format!("reading frame magic: {error}"))?;
    if magic != FRAME_MAGIC {
        return Err("frame magic mismatch".to_owned());
    }
    let mut sequence = [0u8; 8];
    reader
        .read_exact(&mut sequence)
        .map_err(|error| format!("reading frame sequence: {error}"))?;
    let mut length = [0u8; 4];
    reader
        .read_exact(&mut length)
        .map_err(|error| format!("reading frame length: {error}"))?;
    let length = u32::from_le_bytes(length) as usize;
    let mut payload = vec![0u8; length];
    reader
        .read_exact(&mut payload)
        .map_err(|error| format!("reading frame payload: {error}"))?;
    let mut trailer = [0u8; TRAILER_BYTES];
    reader
        .read_exact(&mut trailer)
        .map_err(|error| format!("reading frame trailer: {error}"))?;
    let expected = fnv1a64(&payload);
    if u64::from_le_bytes(trailer) != expected {
        return Err("frame trailer mismatch".to_owned());
    }
    Ok(Some((u64::from_le_bytes(sequence), payload)))
}

fn replay_journal(
    config: &Config,
    directory: &Path,
    expected: u64,
) -> Result<(Vec<u64>, u64), String> {
    let path = directory.join("journal.nb");
    let mut reader = BufReader::new(
        File::open(&path).map_err(|error| format!("opening journal for replay: {error}"))?,
    );
    let mut samples = Vec::new();
    let mut seen = HashSet::new();
    let mut errors = 0u64;
    while let Some((sequence, payload)) = read_frame(&mut reader)? {
        let at = Instant::now();
        let valid = sequence >= 1
            && sequence <= config.events as u64
            && seen.insert(sequence)
            && payload.len() == config.payload_bytes
            && payload == make_payload(config.seed, sequence, config.payload_bytes);
        if !valid {
            errors = errors.saturating_add(1);
        }
        samples.push(u64::try_from(at.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }
    if seen.len() as u64 != expected {
        return Err(format!(
            "replay saw {} distinct sequences, expected {}",
            seen.len(),
            expected
        ));
    }
    Ok((samples, errors))
}

fn run_once(config: &Config) -> Result<Artifact, String> {
    let directory = run_directory(config.seed)?;
    let bindings = collect_bindings(&directory);
    let digest = config_digest(config);
    let start = Instant::now();
    let queue = Arc::new(BoundedQueue::new(config.queue_capacity));
    let producers_stats = Arc::new(Mutex::new(ProducerStats::default()));
    let writer_queue = Arc::clone(&queue);
    let writer_config = config.clone();
    let writer_start = start;
    let writer_directory = directory.clone();
    let writer = thread::Builder::new()
        .name("neutral-journal-writer".to_owned())
        .spawn(move || write_journal(writer_config, &writer_directory, writer_start, writer_queue))
        .map_err(|error| format!("spawning writer thread: {error}"))?;
    let mut producer_handles = Vec::new();
    let chunk = config.events.div_ceil(config.producers);
    for index in 0..config.producers {
        let first = index * chunk;
        let last = ((index + 1) * chunk).min(config.events);
        if first >= last {
            continue;
        }
        let producer_config = config.clone();
        let producer_queue = Arc::clone(&queue);
        let producer_stats = Arc::clone(&producers_stats);
        let handle = thread::Builder::new()
            .name(format!("neutral-producer-{index}"))
            .spawn(move || {
                produce(
                    producer_config,
                    first,
                    last - 1,
                    start,
                    producer_queue,
                    producer_stats,
                )
            })
            .map_err(|error| format!("spawning producer thread: {error}"))?;
        producer_handles.push(handle);
    }
    for handle in producer_handles {
        handle
            .join()
            .map_err(|_| "producer thread failed".to_owned())??;
    }
    queue.close();
    let writer_stats = writer
        .join()
        .map_err(|_| "writer thread failed".to_owned())??;
    let producer_stats = lock(&producers_stats).clone();
    let (replay_ns, replay_errors) = replay_journal(config, &directory, producer_stats.accepted)?;
    let duration_ns = now_ns(start);
    let depth_samples = queue.depth_samples();
    let depth_max = depth_samples.iter().copied().max().unwrap_or(0);
    let depth_sum: u128 = depth_samples.iter().map(|value| u128::from(*value)).sum();

    let counters = Counters {
        offered: producer_stats.offered,
        accepted: producer_stats.accepted,
        rejected: producer_stats.rejected,
        written: writer_stats.written,
        flushed: writer_stats.flushed,
        synced: writer_stats.synced,
        replayed: replay_ns.len() as u64,
        checkpointed: writer_stats.checkpointed,
        errors: replay_errors,
        bytes_written: writer_stats.bytes_written,
        allocation_bytes: writer_stats.allocation_bytes,
        allocation_calls: writer_stats.allocation_calls,
        queue_depth_max: depth_max,
        queue_depth_mean: u64::try_from(depth_sum / (depth_samples.len() as u128).max(1))
            .unwrap_or(0),
        queue_depth_samples: depth_samples.len() as u64,
    };
    let offered_rate = (u128::from(counters.offered) * 1_000_000_000)
        .checked_div(u128::from(duration_ns).max(1))
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0);
    let bytes_rate = (u128::from(counters.bytes_written) * 1_000_000_000)
        .checked_div(u128::from(duration_ns).max(1))
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0);

    let samples = vec![
        (
            "serialization",
            SampleSet::new(writer_stats.serialization_ns),
        ),
        (
            "queue_admission",
            SampleSet::new(producer_stats.admission_ns),
        ),
        ("journal_written", SampleSet::new(writer_stats.written_ns)),
        ("journal_flushed", SampleSet::new(writer_stats.flushed_ns)),
        ("journal_synced", SampleSet::new(writer_stats.synced_ns)),
        ("replay", SampleSet::new(replay_ns)),
        ("checkpoint", SampleSet::new(writer_stats.checkpoint_ns)),
        ("service", SampleSet::new(writer_stats.service_ns)),
        ("end_to_end", SampleSet::new(writer_stats.end_to_end_ns)),
    ];
    let results = samples
        .into_iter()
        .map(|(name, set)| StageResult::from_samples(name, &set))
        .collect();

    Ok(Artifact {
        bindings,
        config: config.clone(),
        workload_digest: digest,
        duration_ns,
        offered_rate_per_s: offered_rate,
        bytes_per_s: bytes_rate,
        results,
        counters,
    })
}

fn check_artifact(artifact: &Artifact, name: &str) -> Vec<Check> {
    let mut checks = Vec::new();
    let mut push = |label: &str, passed: bool| {
        checks.push(Check {
            name: format!("{name}:{label}"),
            passed,
        });
    };
    push(
        "offered_equals_accepted_plus_rejected",
        artifact.counters.offered == artifact.counters.accepted + artifact.counters.rejected,
    );
    push("no_rejections_in_tiny_run", artifact.counters.rejected == 0);
    push(
        "accepted_equals_written",
        artifact.counters.accepted == artifact.counters.written,
    );
    push(
        "written_equals_flushed",
        artifact.counters.written == artifact.counters.flushed,
    );
    push(
        "flushed_equals_synced",
        artifact.counters.flushed == artifact.counters.synced,
    );
    push(
        "synced_equals_replayed",
        artifact.counters.synced == artifact.counters.replayed,
    );
    push(
        "synced_equals_checkpointed",
        artifact.counters.synced == artifact.counters.checkpointed,
    );
    push("no_errors", artifact.counters.errors == 0);
    push("duration_recorded", artifact.duration_ns > 0);
    push(
        "sample_counts_positive",
        artifact.results.iter().all(|result| result.count > 0),
    );
    push(
        "percentiles_ordered",
        artifact.results.iter().all(|result| {
            result.p50_ns <= result.p90_ns
                && result.p90_ns <= result.p95_ns
                && result.p95_ns <= result.p99_ns
                && result.p99_ns <= result.p999_ns
                && result.p999_ns <= result.max_ns
        }),
    );
    push(
        "beyond_max_is_zero",
        artifact.results.iter().all(|result| result.beyond_max == 0),
    );
    push(
        "raw_digests_present",
        artifact
            .results
            .iter()
            .all(|result| result.raw_result_digest.len() == 32),
    );
    push(
        "binding_fields_present",
        !artifact.bindings.source_sha.is_empty()
            && !artifact.bindings.toolchain.is_empty()
            && !artifact.bindings.compiler_flags.is_empty()
            && !artifact.bindings.os.is_empty()
            && !artifact.bindings.arch.is_empty()
            && !artifact.bindings.cpu.is_empty()
            && !artifact.bindings.machine.is_empty()
            && !artifact.bindings.filesystem.is_empty(),
    );
    push(
        "workload_digest_present",
        artifact.workload_digest.len() == 32,
    );
    push(
        "event_count_preserved",
        artifact.counters.offered == artifact.config.events as u64,
    );
    checks
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
                let _ = write!(&mut out, "\\u{:04x}", u32::from(other));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
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

fn binding_json(bindings: &Bindings, artifact: &Artifact) -> String {
    format!(
        concat!(
            "\"source_sha\":{sha},\"toolchain\":{toolchain},",
            "\"compiler_flags\":{flags},\"os\":{os},\"arch\":{arch},",
            "\"cpu\":{cpu},\"machine\":{machine},\"filesystem\":{fs},",
            "\"workload_digest\":{workload},\"seed\":{seed},",
            "\"event_count\":{events},\"warmup_policy\":{warmup},",
            "\"duration_ns\":{duration},\"repetitions\":{reps},",
            "\"arrival\":{arrival},\"payload_bytes\":{payload},",
            "\"batch\":{batch},\"queue_capacity\":{queue},\"producers\":{producers}"
        ),
        sha = jstr(&bindings.source_sha),
        toolchain = jstr(&bindings.toolchain),
        flags = jstr(&bindings.compiler_flags),
        os = jstr(&bindings.os),
        arch = jstr(&bindings.arch),
        cpu = jstr(&bindings.cpu),
        machine = jstr(&bindings.machine),
        fs = jstr(&bindings.filesystem),
        workload = jstr(&artifact.workload_digest),
        seed = artifact.config.seed,
        events = artifact.config.events,
        warmup = jstr("none: single deterministic measured pass"),
        duration = artifact.duration_ns,
        reps = artifact.config.reps,
        arrival = jstr(artifact.config.arrival.as_str()),
        payload = artifact.config.payload_bytes,
        batch = artifact.config.batch,
        queue = artifact.config.queue_capacity,
        producers = artifact.config.producers,
    )
}

fn counters_json(counters: &Counters, offered_rate: u64, bytes_rate: u64) -> String {
    format!(
        concat!(
            "\"counters\":{{\"offered\":{offered},\"accepted\":{accepted},",
            "\"rejected\":{rejected},\"written\":{written},\"flushed\":{flushed},",
            "\"synced\":{synced},\"replayed\":{replayed},\"checkpointed\":{checkpointed},",
            "\"errors\":{errors},\"queue_depth_max\":{qmax},",
            "\"queue_depth_mean\":{qmean},\"queue_depth_samples\":{qsamples},",
            "\"bytes_written\":{bytes},\"allocation_bytes\":{abytes},",
            "\"allocation_calls\":{acalls},\"offered_events_per_s\":{orate},",
            "\"bytes_per_s\":{brate}}}"
        ),
        offered = counters.offered,
        accepted = counters.accepted,
        rejected = counters.rejected,
        written = counters.written,
        flushed = counters.flushed,
        synced = counters.synced,
        replayed = counters.replayed,
        checkpointed = counters.checkpointed,
        errors = counters.errors,
        qmax = counters.queue_depth_max,
        qmean = counters.queue_depth_mean,
        qsamples = counters.queue_depth_samples,
        bytes = counters.bytes_written,
        abytes = counters.allocation_bytes,
        acalls = counters.allocation_calls,
        orate = offered_rate,
        brate = bytes_rate,
    )
}

fn artifact_json(artifact: &Artifact) -> String {
    let binding = binding_json(&artifact.bindings, artifact);
    let results = artifact
        .results
        .iter()
        .map(|result| result.to_json(&binding))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"label\":{label},\"dimensions\":{dimensions},\"binding\":{{{binding}}},{counters},\"results\":[{results}]}}",
        label = jstr(&artifact.config.label),
        dimensions = dimensions_json(),
        binding = binding,
        counters = counters_json(
            &artifact.counters,
            artifact.offered_rate_per_s,
            artifact.bytes_per_s
        ),
        results = results,
    )
}

fn dimensions_json() -> String {
    let payloads = SUPPORTED_PAYLOADS.map(|value| value.to_string()).join(",");
    let batches = SUPPORTED_BATCHES.map(|value| value.to_string()).join(",");
    let queues = SUPPORTED_QUEUES.map(|value| value.to_string()).join(",");
    let producers = SUPPORTED_PRODUCERS.map(|value| value.to_string()).join(",");
    format!(
        "{{\"payload_bytes\":[{payloads}],\"batch\":[{batches}],\"queue_capacity\":[{queues}],\"producers\":[{producers}],\"arrival\":[\"open\",\"closed\"]}}"
    )
}

fn usage_json() -> String {
    "{\"schema_version\":1,\"harness\":\"neutral_pipeline\",\"mode\":\"usage\",\"options\":[\"--self-test\",\"--payload=N\",\"--batch=N\",\"--queue=N\",\"--producers=N\",\"--arrival=open|closed\",\"--events=N\",\"--reps=N\",\"--seed=N\",\"--label=STR\",\"--help\"]}".to_owned()
}

fn parse_args(args: &[String]) -> Result<(bool, Config, bool), String> {
    let mut self_test = false;
    let mut help = false;
    let mut config = Config::default_run();
    for arg in args {
        let (key, value) = arg.split_once('=').unwrap_or((arg.as_str(), ""));
        match key {
            "--self-test" => self_test = true,
            "--help" => help = true,
            "--payload" => config.payload_bytes = parse_usize(value, key)?,
            "--batch" => config.batch = parse_usize(value, key)?,
            "--queue" => config.queue_capacity = parse_usize(value, key)?,
            "--producers" => config.producers = parse_usize(value, key)?,
            "--events" => config.events = parse_usize(value, key)?,
            "--reps" => config.reps = parse_usize(value, key)?,
            "--seed" => config.seed = value.parse::<u64>().map_err(|_| format!("invalid {key}"))?,
            "--label" => config.label = value.to_owned(),
            "--arrival" => {
                config.arrival = Arrival::parse(value).ok_or_else(|| format!("invalid {key}"))?;
            }
            other => return Err(format!("unknown option `{other}`")),
        }
    }
    if config.payload_bytes == 0 || config.batch == 0 || config.queue_capacity == 0 {
        return Err("dimensions must be positive".to_owned());
    }
    if config.producers == 0 || config.reps == 0 || config.events == 0 {
        return Err("counts must be positive".to_owned());
    }
    Ok((self_test, config, help))
}

fn parse_usize(value: &str, key: &str) -> Result<usize, String> {
    value.parse::<usize>().map_err(|_| format!("invalid {key}"))
}

fn run() -> Result<String, String> {
    // Cargo appends its own `--bench <target>` arguments when it launches a
    // custom-harness bench binary. Drop those so user-facing options stay strict.
    let args: Vec<String> = env::args()
        .skip(1)
        .filter(|arg| arg != "--bench" && arg != "neutral_pipeline")
        .collect();
    let (self_test, config, help) = parse_args(&args)?;
    if help {
        return Ok(usage_json());
    }
    // A bare invocation happens when `cargo test --all-targets` runs bench
    // binaries. Keep it idle so no performance run becomes a CI side effect.
    if args.is_empty() {
        return Ok(concat!(
            "{\"schema_version\":1,\"harness\":\"neutral_pipeline\",",
            "\"mode\":\"idle\",\"hint\":\"pass --self-test or explicit dimensions\"}"
        )
        .to_owned());
    }
    let mut checks = Vec::new();
    let mut artifacts = Vec::new();
    let configs: Vec<Config> = if self_test {
        vec![
            Config::self_test(Arrival::Closed),
            Config::self_test(Arrival::Open),
        ]
    } else {
        vec![config]
    };
    for (index, item) in configs.iter().enumerate() {
        for _ in 0..item.reps {
            let artifact = run_once(item)?;
            if self_test {
                checks.extend(check_artifact(&artifact, &format!("case-{index}")));
            }
            artifacts.push(artifact_json(&artifact));
        }
    }
    let (mode, self_test_json) = if self_test {
        let passed = checks.iter().all(|check| check.passed);
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
        (
            "self_test",
            format!(
                ",\"self_test\":{{\"passed\":{passed},\"checks\":[{entries}]}}",
                passed = passed,
                entries = entries
            ),
        )
    } else {
        ("bench", String::new())
    };
    Ok(format!(
        "{{\"schema_version\":{schema},\"harness\":\"neutral_pipeline\",\"mode\":{mode},\"dimensions\":{dimensions},\"artifacts\":[{artifacts}]{self_test}}}",
        schema = SCHEMA_VERSION,
        mode = jstr(mode),
        dimensions = dimensions_json(),
        artifacts = artifacts.join(","),
        self_test = self_test_json,
    ))
}

fn main() -> ExitCode {
    match run() {
        Ok(json) => {
            if !json_well_formed(&json) {
                eprintln!("{{\"error\":\"generated artifact is not well-formed JSON\"}}");
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
