//! Append-only journal for raw public market-data frames.
//!
//! The journal preserves the exact bytes read from a public websocket before
//! normalization, including frames the decoder rejects. It is independent of
//! the SBE capture: the SBE schema and its on-disk representation are
//! unchanged.
//!
//! # Durability states
//!
//! A record advances through observable stages:
//!
//! * `queued` — accepted into the bounded channel owned by the writer thread;
//! * `written` — handed to the operating system file buffer;
//! * `flushed` — removed from the process buffer with [`std::io::Write::flush`];
//! * `synced` — persisted with [`std::fs::File::sync_all`];
//! * `finalized` — covered by a segment footer and a manifest entry after the
//!   partial file was renamed.
//!
//! A record reported as `written` is not durable across a process or host
//! failure. The manifest names the configured policy, and the final run state
//! distinguishes a completed capture from an interrupted one.
//!
//! # File layout
//!
//! A run directory contains `manifest.json` and numbered segment files. A
//! segment is created as `<index>.pmj.partial`, receives a header, records,
//! and a footer, then is synced and renamed to `<index>.pmj`. The manifest is
//! rewritten through the atomic JSON helper after each finalized segment and at
//! shutdown. A crash can leave a partial segment and an open manifest, but
//! verification reports that state instead of treating it as complete.
//!
//! Segment header and footer contain a SHA-256 checksum. Every record carries a
//! checksum trailer over its framing, JSON header, and payload. Verification
//! recomputes every checksum, rejects truncated records, and compares the
//! footer and manifest counts, byte ranges, timestamps, and sequence ranges.
//!
//! # Backpressure
//!
//! The caller blocks on a full queue for `enqueue_timeout`. Exceeding that
//! deadline marks the run failed and returns an error. Write, flush, sync, or
//! rename failures follow the same rule: the writer stops, the status becomes
//! failed, and shutdown returns an error.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Condvar, Mutex,
        mpsc::{Sender, channel},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use crossbeam::channel::{Receiver, Sender as QueueSender, bounded, select, tick};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    histogram::Histogram,
    model::SourceId,
    protocol::{
        ControlOpcode, FrameClassification, FrameDirection, HeartbeatMechanism, SendResult,
        SessionSignal,
    },
    report::write_json_atomic,
    time::now_us,
    util::sha256_hex,
};

/// The frame kind is part of the shared protocol vocabulary; re-exported so
/// existing `journal::FrameKind` paths keep working.
pub use crate::protocol::FrameKind;

/// Current journal schema version written by this build.
pub const JOURNAL_SCHEMA_VERSION: u32 = 2;

/// Oldest schema version this build can read.
pub const JOURNAL_MIN_READABLE_SCHEMA_VERSION: u32 = 1;

const RECORD_MAGIC: [u8; 4] = *b"PMR1";
const SEGMENT_MAGIC: [u8; 8] = *b"PMJSEG01";
const FOOTER_MAGIC: [u8; 8] = *b"PMJEND01";
const CHECKSUM_BYTES: usize = 64;
const RECORD_FRAMING_BYTES: usize = 4 + 4 + 4;
const PARTIAL_SUFFIX: &str = ".pmj.partial";
const FINAL_SUFFIX: &str = ".pmj";
const MANIFEST_FILE: &str = "manifest.json";
const MAX_RECORD_BYTES: usize = 64 << 20;
const MAX_HEADER_BYTES: usize = 1 << 20;

/// Outcome of decoding one frame, recorded without altering the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DecodeOutcome {
    /// The decoder produced normalized events.
    Decoded { events: u32 },
    /// The frame was accepted but produced no events (control frame, empty
    /// payload, or an unknown additive event type).
    Ignored { reason: String },
    /// The decoder rejected the frame. `category` is a stable label.
    Rejected { category: String },
}

impl DecodeOutcome {
    #[must_use]
    pub fn decoded(events: usize) -> Self {
        Self::Decoded {
            events: u32::try_from(events).unwrap_or(u32::MAX),
        }
    }

    #[must_use]
    pub fn ignored(reason: &str) -> Self {
        Self::Ignored {
            reason: reason.to_owned(),
        }
    }

    #[must_use]
    pub fn rejected(category: &str) -> Self {
        Self::Rejected {
            category: category.to_owned(),
        }
    }
}

impl Default for DecodeOutcome {
    fn default() -> Self {
        Self::Ignored {
            reason: "no_data_frame".to_owned(),
        }
    }
}

/// One raw websocket payload with its transport kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFrame {
    pub kind: FrameKind,
    pub payload: Vec<u8>,
}

impl RawFrame {
    #[must_use]
    pub fn text(text: String) -> Self {
        Self {
            kind: FrameKind::Text,
            payload: text.into_bytes(),
        }
    }

    #[must_use]
    pub fn binary(payload: Vec<u8>) -> Self {
        Self {
            kind: FrameKind::Binary,
            payload,
        }
    }
}

/// Flush and sync policy for the writer thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    /// Flush and `fsync` every record.
    Always,
    /// Flush and `fsync` on the configured intervals and at finalization.
    Interval,
}

/// Journal writer configuration.
#[derive(Debug, Clone)]
pub struct JournalConfig {
    /// Root directory. Each run writes a new subdirectory named by run id.
    pub directory: PathBuf,
    /// Bound on queued records between the session supervisor and writer.
    pub queue_capacity: usize,
    /// Maximum time a caller waits for queue space before the run fails.
    pub enqueue_timeout: Duration,
    /// Maximum time records may sit in the process buffer.
    pub flush_interval: Duration,
    /// Maximum time between storage syncs in interval mode.
    pub sync_interval: Duration,
    /// Rotate after this many record bytes. Zero disables size rotation.
    pub segment_max_bytes: u64,
    /// Rotate after this many seconds. Zero disables time rotation.
    pub segment_max_seconds: u64,
    pub sync_mode: SyncMode,
}

impl JournalConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.directory.as_os_str().is_empty(),
            "journal directory must not be empty"
        );
        anyhow::ensure!(
            self.queue_capacity >= 1,
            "journal queue_capacity must be >= 1"
        );
        anyhow::ensure!(
            !self.enqueue_timeout.is_zero(),
            "journal enqueue_timeout must be greater than zero"
        );
        anyhow::ensure!(
            !self.flush_interval.is_zero(),
            "journal flush_interval must be greater than zero"
        );
        anyhow::ensure!(
            !self.sync_interval.is_zero(),
            "journal sync_interval must be greater than zero"
        );
        anyhow::ensure!(
            self.segment_max_bytes == 0 || self.segment_max_bytes >= 4096,
            "journal segment_max_bytes must be zero or at least 4096"
        );
        Ok(())
    }
}

/// Values pinned into the run manifest.
#[derive(Debug, Clone)]
pub struct JournalMeta {
    pub run_id: String,
    pub venue: String,
    /// Source commit of the running binary, or `unknown` when not injected.
    pub code_commit: String,
    /// SHA-256 of the serialized configuration that affects capture.
    pub config_sha256: String,
    /// Non-secret route provenance: mode, kind, route identity, and DNS mode.
    /// Never contains credentials.
    pub route: Option<crate::egress::RouteProvenance>,
}

impl JournalMeta {
    /// Build metadata for a new run. The run id combines wall-clock
    /// microseconds and the process id; the run directory is created
    /// exclusively.
    #[must_use]
    pub fn new(
        venue: &str,
        code_commit: &str,
        config_sha256: &str,
        route: Option<crate::egress::RouteProvenance>,
    ) -> Self {
        let now = now_us().unwrap_or(0);
        Self {
            run_id: format!("{now:x}-{:x}", std::process::id()),
            venue: venue.to_owned(),
            code_commit: code_commit.to_owned(),
            config_sha256: config_sha256.to_owned(),
            route,
        }
    }
}

/// State of one journal run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Starting,
    Open,
    Finalized,
    Incomplete,
    Failed,
}

impl RunState {
    #[must_use]
    pub fn is_active(self) -> bool {
        matches!(self, Self::Starting | Self::Open)
    }
}

/// Counters shared between the writer thread and callers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JournalCounters {
    /// Records accepted into the writer queue.
    pub queued: u64,
    /// Records handed to the file buffer.
    pub written: u64,
    /// Records whose bytes were flushed from the process buffer.
    pub flushed: u64,
    /// Records covered by a completed `sync_all`.
    pub synced: u64,
    /// Records inside segments that were renamed and recorded in the manifest.
    pub finalized: u64,
    /// Finalized segments.
    pub segments: u64,
    /// Current queue depth.
    pub queue_depth: u64,
    /// Record-region bytes written in the active and finalized segments.
    pub bytes: u64,
}

/// Snapshot of journal health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalStatus {
    pub run_id: String,
    pub run_directory: String,
    pub state: RunState,
    pub counters: JournalCounters,
    pub durability: DurabilityPolicy,
    pub last_error: Option<String>,
}

impl JournalStatus {
    #[must_use]
    pub fn healthy(&self) -> bool {
        self.state.is_active() && self.last_error.is_none()
    }
}

/// Configured flush and sync behavior, pinned in the manifest and reports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurabilityPolicy {
    pub sync_mode: SyncMode,
    pub flush_interval_ms: u64,
    pub sync_interval_ms: u64,
    pub queue_capacity: usize,
    pub enqueue_timeout_ms: u64,
}

/// Durability boundary a producer waits for after queueing a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalAckLevel {
    /// Record admitted to the bounded writer queue; the writer owns it. No
    /// bytes have been appended and no storage durability is claimed.
    Queued,
    /// Record passed to the writer layer and appended to the open segment's
    /// userspace buffer. A process failure before a later boundary can lose it.
    Written,
    /// Record included in a completed `flush` of the userspace buffer to the
    /// operating system. The bytes are not yet synced to stable storage.
    Flushed,
    /// Record included in a completed `sync_all`.
    Synced,
}

impl JournalAckLevel {
    /// Return the stable contract string for this acknowledgement level.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Written => "written",
            Self::Flushed => "flushed",
            Self::Synced => "synced",
        }
    }
}

/// Acknowledgement tied to a concrete writer counter fence and record.
///
/// A fence is a queue-admission ordinal. The identity fields are what prove a
/// caller was acknowledged for the record it actually submitted; callers must
/// compare them against their own record before treating an ack as success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalAck {
    pub run_id: String,
    pub level: JournalAckLevel,
    /// Monotonic writer counter value the record reached.
    pub fence: u64,
    pub state: RunState,
    /// Source of the record the fence was reserved for.
    #[serde(default)]
    pub source: SourceId,
    /// Connection epoch of the record the fence was reserved for.
    #[serde(default)]
    pub connection_epoch: u64,
    /// Receive sequence of the record the fence was reserved for.
    #[serde(default)]
    pub receive_seq: u64,
}

/// Result of an orderly finalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalSummary {
    pub run_id: String,
    pub run_directory: String,
    pub state: RunState,
    pub record_count: u64,
    pub segment_count: u64,
    pub bytes: u64,
}

struct Inner {
    run_directory: PathBuf,
    run_id: String,
    durability: DurabilityPolicy,
    status: Mutex<JournalStatus>,
    queue: QueueSender<Command>,
    join: Mutex<Option<JoinHandle<()>>>,
    shutdown: Mutex<bool>,
    admission: Mutex<Admission>,
    /// Serializes fence reservation with the enqueue that consumes it. A fence
    /// sampled outside this mutex could belong to a concurrent producer's
    /// record. The status lock is never held while waiting for queue space.
    submit: Mutex<()>,
    admission_cv: Condvar,
    /// Wakes producers waiting for a per-record durability boundary.
    ack_cv: Condvar,
    /// Shared journal-append latency histogram, when instrumentation is
    /// requested by the caller. Read only by the writer thread.
    append_latency: Option<Arc<Histogram>>,
    #[cfg(test)]
    record_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

/// Producer admission control. Closing admission before finalization prevents a
/// record from entering the queue behind the Finalize command.
struct Admission {
    accepting: bool,
    active: usize,
}

/// Keeps a producer counted as active until the whole record operation —
/// enqueue, failure latching, and counter updates — has completed.
///
/// Dropping the guard is the only place that decrements the active producer
/// count, so shutdown and abort cannot observe quiescence while a producer is
/// still about to mark the journal failed.
struct AdmissionGuard<'a> {
    inner: &'a Inner,
}

impl Drop for AdmissionGuard<'_> {
    fn drop(&mut self) {
        let mut admission = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug_assert!(admission.active > 0, "producer admission count underflowed");
        admission.active = admission.active.saturating_sub(1);
        if admission.active == 0 {
            self.inner.admission_cv.notify_all();
        }
    }
}

/// Cloneable handle to the journal writer.
#[derive(Clone)]
pub struct JournalHandle {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for JournalHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JournalHandle")
            .field("run_id", &self.inner.run_id)
            .field("run_directory", &self.inner.run_directory)
            .finish()
    }
}

impl JournalHandle {
    /// Create the run directory, manifest, and writer thread.
    pub fn start(config: JournalConfig, meta: JournalMeta) -> anyhow::Result<Self> {
        Self::start_inner(config, meta, None)
    }

    /// Start with a shared append-latency histogram. The same counters are
    /// later read by the coordinator's stage-timing report.
    pub fn start_with_timing(
        config: JournalConfig,
        meta: JournalMeta,
        append_latency: Arc<Histogram>,
    ) -> anyhow::Result<Self> {
        Self::start_inner_timed(config, meta, None, Some(append_latency))
    }

    fn start_inner(
        config: JournalConfig,
        meta: JournalMeta,
        fault: Option<FaultHook>,
    ) -> anyhow::Result<Self> {
        Self::start_inner_timed(config, meta, fault, None)
    }

    fn start_inner_timed(
        config: JournalConfig,
        meta: JournalMeta,
        fault: Option<FaultHook>,
        append_latency: Option<Arc<Histogram>>,
    ) -> anyhow::Result<Self> {
        config.validate()?;
        anyhow::ensure!(!meta.run_id.is_empty(), "journal run id must not be empty");
        let run_directory = config.directory.join(&meta.run_id);
        fs::create_dir_all(&run_directory)
            .with_context(|| format!("creating journal directory `{}`", run_directory.display()))?;
        anyhow::ensure!(
            !run_directory.join(MANIFEST_FILE).exists(),
            "journal run `{}` already has a manifest",
            meta.run_id
        );
        let durability = DurabilityPolicy {
            sync_mode: config.sync_mode,
            flush_interval_ms: duration_ms(config.flush_interval),
            sync_interval_ms: duration_ms(config.sync_interval),
            queue_capacity: config.queue_capacity,
            enqueue_timeout_ms: duration_ms(config.enqueue_timeout),
        };
        let manifest = Manifest::new(&meta, &durability);
        run_fault(fault.as_ref(), FaultPoint::ManifestWrite)
            .context("injecting initial journal manifest write")?;
        write_manifest(&run_directory, &manifest)?;

        let (queue, queue_rx) = bounded(config.queue_capacity);
        let inner = Arc::new(Inner {
            run_directory: run_directory.clone(),
            run_id: meta.run_id.clone(),
            durability: durability.clone(),
            status: Mutex::new(JournalStatus {
                run_id: meta.run_id.clone(),
                run_directory: run_directory.display().to_string(),
                state: RunState::Starting,
                counters: JournalCounters::default(),
                durability,
                last_error: None,
            }),
            queue,
            join: Mutex::new(None),
            shutdown: Mutex::new(false),
            admission: Mutex::new(Admission {
                accepting: true,
                active: 0,
            }),
            submit: Mutex::new(()),
            admission_cv: Condvar::new(),
            ack_cv: Condvar::new(),
            append_latency,
            #[cfg(test)]
            record_hook: Mutex::new(None),
        });
        let worker_inner = Arc::clone(&inner);
        let join = std::thread::Builder::new()
            .name("raw-journal".to_owned())
            .spawn(move || {
                run_writer(worker_inner, queue_rx, config, meta, manifest, fault);
            })
            .context("spawning journal writer")?;
        *inner
            .join
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(join);
        set_state(&inner, RunState::Open, None);
        Ok(Self { inner })
    }

    /// Enqueue one inbound application data record (schema v2).
    ///
    /// The call blocks for at most `enqueue_timeout` while the queue is full.
    /// A timeout or a stopped writer marks the run failed and returns an error;
    /// the frame is not silently dropped while the capture remains complete.
    pub fn record(&self, record: DataRecord) -> anyhow::Result<()> {
        self.enqueue(Self::data_job(record))
    }

    fn data_job(record: DataRecord) -> RecordJob {
        RecordJob {
            source: record.source,
            connection_epoch: record.connection_epoch,
            observation_seq: 0,
            control_seq: None,
            receive_seq: Some(record.receive_seq),
            direction: FrameDirection::Inbound,
            received_at_us: record.received_at_us,
            classification: FrameClassification::Data {
                frame_kind: record.frame.kind,
            },
            signal: record.signal,
            mechanism: record.mechanism,
            payload: record.frame.payload,
            outcome: Some(record.outcome),
            send_result: None,
        }
    }

    /// Queue one record and wait for a concrete writer durability boundary.
    ///
    /// The fence is reserved under the submit mutex immediately before the
    /// enqueue that increments `queued`, and the returned acknowledgement names
    /// the submitted record. No other producer can claim the same ordinal.
    pub fn record_ack(
        &self,
        record: DataRecord,
        level: JournalAckLevel,
        timeout: Duration,
    ) -> anyhow::Result<JournalAck> {
        let (source, connection_epoch, receive_seq) =
            (record.source, record.connection_epoch, record.receive_seq);
        let fence = self.enqueue_with_fence(Self::data_job(record))?;
        let deadline = Instant::now() + timeout;
        loop {
            let status = self
                .inner
                .status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if status.last_error.is_some() || status.state == RunState::Failed {
                let reason = status
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "journal failed".to_owned());
                anyhow::bail!("journal failed before {}: {reason}", level.as_str());
            }
            let reached = match level {
                JournalAckLevel::Queued => status.counters.queued,
                JournalAckLevel::Written => status.counters.written,
                JournalAckLevel::Flushed => status.counters.flushed,
                JournalAckLevel::Synced => status.counters.synced,
            };
            if reached >= fence {
                return Ok(JournalAck {
                    run_id: status.run_id.clone(),
                    level,
                    fence,
                    state: status.state,
                    source,
                    connection_epoch,
                    receive_seq,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                anyhow::bail!("journal {} acknowledgement timed out", level.as_str());
            }
            let (guard, _) = self
                .inner
                .ack_cv
                .wait_timeout(status, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            drop(guard);
        }
    }

    /// Enqueue one retained inbound or outbound observation (schema v2).
    ///
    /// `observation_seq` and native `control_seq` are assigned by the writer in
    /// enqueue order, which is the order the source worker retained the
    /// observations. Data records are never enqueued through this method.
    pub fn observe(&self, observation: ObservationRecord) -> anyhow::Result<()> {
        let job = RecordJob {
            source: observation.source,
            connection_epoch: observation.connection_epoch,
            observation_seq: 0,
            control_seq: None,
            receive_seq: None,
            direction: observation.direction,
            received_at_us: observation.received_at_us,
            classification: observation.classification,
            signal: observation.signal,
            mechanism: observation.mechanism,
            payload: observation.payload,
            outcome: None,
            send_result: observation.send_result,
        };
        self.enqueue(job)
    }

    fn enqueue(&self, job: RecordJob) -> anyhow::Result<()> {
        // The guard spans the entire operation. Shutdown and abort wait for it
        // to drop, which happens only after a queue failure has been latched
        // and accepted records have updated their counters.
        let _admission = self.admit()?;
        let _submit = self
            .inner
            .submit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.submit(job)
    }

    /// Reserve an admission fence and submit this record under one mutex.
    ///
    /// Every enqueue takes the same mutex, so the sampled `queued` counter
    /// plus one is the exact ordinal this record will obtain when `submit`
    /// increments the counter. A queue failure returns an error and consumes
    /// no fence. The status lock is held neither across the queue wait nor
    /// across the acknowledgement wait, so the writer's condvar cannot
    /// deadlock with the submit mutex.
    fn enqueue_with_fence(&self, job: RecordJob) -> anyhow::Result<u64> {
        let _admission = self.admit()?;
        let _submit = self
            .inner
            .submit
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let fence = {
            let status = self
                .inner
                .status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            status
                .counters
                .queued
                .checked_add(1)
                .context("journal queued counter exhausted")?
        };
        self.submit(job)?;
        Ok(fence)
    }

    fn submit(&self, job: RecordJob) -> anyhow::Result<()> {
        let timeout = Duration::from_millis(self.inner.durability.enqueue_timeout_ms);
        let result = self.inner.queue.send_timeout(Command::Record(job), timeout);
        #[cfg(test)]
        {
            // A deterministic test gate between the queue decision and the
            // failure latch. It makes the admission-ordering regression
            // reproducible instead of relying on scheduler timing.
            let hook = self
                .inner
                .record_hook
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if let Some(hook) = hook {
                hook();
            }
        }
        match result {
            Ok(()) => {
                if let Some(reason) = self.failure_reason() {
                    bail!("journal failed while accepting a record: {reason}");
                }
                let mut status = self
                    .inner
                    .status
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                status.counters.queued = status.counters.queued.checked_add(1).context(
                    "journal queued counter exhausted; no further record may be admitted",
                )?;
                status.counters.queue_depth = self.inner.queue.len() as u64;
                drop(status);
                self.inner.ack_cv.notify_all();
                Ok(())
            }
            Err(error) => {
                let reason = match error {
                    crossbeam::channel::SendTimeoutError::Timeout(_) => format!(
                        "journal queue stayed full for {} ms",
                        self.inner.durability.enqueue_timeout_ms
                    ),
                    crossbeam::channel::SendTimeoutError::Disconnected(_) => {
                        "journal writer stopped".to_owned()
                    }
                };
                self.mark_failed(&reason);
                bail!("{reason}")
            }
        }
    }

    fn admit(&self) -> anyhow::Result<AdmissionGuard<'_>> {
        let mut admission = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        anyhow::ensure!(
            admission.accepting,
            "journal is not accepting records: {}",
            self.failure_reason()
                .unwrap_or_else(|| "shutdown in progress".to_owned())
        );
        admission.active = admission.active.saturating_add(1);
        Ok(AdmissionGuard { inner: &self.inner })
    }

    #[cfg(test)]
    fn set_record_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        *self
            .inner
            .record_hook
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(hook);
    }

    #[must_use]
    pub fn status(&self) -> JournalStatus {
        self.inner
            .status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn failure_reason(&self) -> Option<String> {
        run_failure(&self.inner)
    }

    fn mark_failed(&self, reason: &str) {
        let mut status = self
            .inner
            .status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if status.state == RunState::Finalized {
            return;
        }
        status.state = RunState::Failed;
        status.last_error = Some(reason.to_owned());
    }

    /// Finalize every segment, write the run manifest, and join the writer.
    ///
    /// The timeout bounds producer quiescence, command delivery, response
    /// waiting, and writer observation. A deadline expiry returns an error and
    /// leaves the run failed or incomplete; it does not claim finalization.
    pub fn shutdown(&self, timeout: Duration) -> anyhow::Result<JournalSummary> {
        let deadline = Instant::now() + timeout;
        {
            let mut shutdown = self
                .inner
                .shutdown
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            anyhow::ensure!(!*shutdown, "journal shutdown was already requested");
            *shutdown = true;
        }
        if self.status().state == RunState::Incomplete {
            bail!("journal run is incomplete and cannot be finalized");
        }

        self.close_admission_and_wait(deadline, timeout, "shutdown")?;

        if let Some(reason) = self.failure_reason() {
            let _ = self.send_control(Command::Abort, deadline);
            self.join_writer(deadline);
            bail!("journal run failed: {reason}");
        }

        let (reply_tx, reply_rx) = channel();
        if let Err(error) = self.send_control(Command::Finalize(reply_tx), deadline) {
            self.mark_failed(&format!("journal finalization command failed: {error:#}"));
            self.join_writer(deadline);
            return Err(error);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let result = if remaining.is_zero() {
            Err(anyhow::anyhow!("journal finalization timed out"))
        } else {
            match reply_rx.recv_timeout(remaining) {
                Ok(Ok(summary)) => Ok(summary),
                Ok(Err(error)) => Err(anyhow::anyhow!("{error}")),
                Err(_) => Err(anyhow::anyhow!(
                    "journal finalization timed out after {timeout:?}"
                )),
            }
        };
        if result.is_err() && self.status().state != RunState::Finalized {
            self.mark_failed("journal finalization timed out or failed");
        }
        self.join_writer(deadline);
        result
    }

    /// Stop the writer without finalizing.
    ///
    /// The open segment stays as a `.partial` file and the manifest keeps its
    /// open or failed state. Verification reports the run as incomplete; no
    /// footer or manifest entry is fabricated. The timeout bounds producer
    /// quiescence, command delivery, and writer observation; it cannot
    /// interrupt a write that the operating system is already performing.
    pub fn abort(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        // Abort shares shutdown's producer-quiescence contract: the writer
        // must not receive the stop command while a producer is still inside
        // `record`.
        if self
            .close_admission_and_wait(deadline, timeout, "abort")
            .is_err()
        {
            self.join_writer(deadline);
            return;
        }
        if self.send_control(Command::Abort, deadline).is_err() {
            self.mark_failed("journal abort command could not be delivered");
        }
        self.join_writer(deadline);
    }

    /// Close admission and wait until every admitted producer has completed,
    /// within the absolute deadline shared with the caller.
    fn close_admission_and_wait(
        &self,
        deadline: Instant,
        timeout: Duration,
        operation: &str,
    ) -> anyhow::Result<()> {
        let mut admission = self
            .inner
            .admission
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        admission.accepting = false;
        while admission.active > 0 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                drop(admission);
                let reason =
                    format!("journal {operation} timed out waiting for producers for {timeout:?}");
                self.mark_failed(&reason);
                return Err(anyhow::anyhow!("{reason}"));
            }
            admission = self
                .inner
                .admission_cv
                .wait_timeout(admission, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
        Ok(())
    }

    fn send_control(&self, command: Command, deadline: Instant) -> anyhow::Result<()> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        anyhow::ensure!(
            !remaining.is_zero(),
            "journal control deadline expired before delivery"
        );
        self.inner
            .queue
            .send_timeout(command, remaining)
            .map_err(|error| match error {
                crossbeam::channel::SendTimeoutError::Timeout(_) => {
                    anyhow::anyhow!("journal control command timed out after {remaining:?}")
                }
                crossbeam::channel::SendTimeoutError::Disconnected(_) => {
                    anyhow::anyhow!("journal writer is not running")
                }
            })
    }

    fn join_writer(&self, deadline: Instant) {
        let join = self
            .inner
            .join
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        let Some(join) = join else {
            return;
        };
        while !join.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        if join.is_finished() {
            let _ = join.join();
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        let _ = self.queue.try_send(Command::Abort);
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn set_state(inner: &Inner, state: RunState, error: Option<String>) {
    let mut status = inner
        .status
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    status.state = state;
    if error.is_some() {
        status.last_error = error;
    }
}

fn run_failure(inner: &Inner) -> Option<String> {
    let status = inner
        .status
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    (status.state == RunState::Failed).then(|| {
        status
            .last_error
            .clone()
            .unwrap_or_else(|| "failed".to_owned())
    })
}

/// One inbound application data record to persist.
#[derive(Debug, Clone)]
pub struct DataRecord {
    pub source: SourceId,
    pub connection_epoch: u64,
    pub receive_seq: u64,
    pub received_at_us: i64,
    pub frame: RawFrame,
    pub outcome: DecodeOutcome,
    /// Adapter-assigned interpretation of this payload.
    pub signal: SessionSignal,
    /// Venue heartbeat mechanism, recorded as typed evidence.
    pub mechanism: HeartbeatMechanism,
}

/// One retained inbound or outbound transport observation.
#[derive(Debug, Clone)]
pub struct ObservationRecord {
    pub source: SourceId,
    pub connection_epoch: u64,
    pub received_at_us: i64,
    pub direction: FrameDirection,
    pub classification: FrameClassification,
    pub signal: SessionSignal,
    pub mechanism: HeartbeatMechanism,
    pub payload: Vec<u8>,
    /// `Some` on outbound observations only.
    pub send_result: Option<SendResult>,
}

/// Internal writer job. The writer assigns the observation and control
/// sequences in enqueue order.
struct RecordJob {
    source: SourceId,
    connection_epoch: u64,
    observation_seq: u64,
    control_seq: Option<u64>,
    receive_seq: Option<u64>,
    direction: FrameDirection,
    received_at_us: i64,
    classification: FrameClassification,
    signal: SessionSignal,
    mechanism: HeartbeatMechanism,
    payload: Vec<u8>,
    outcome: Option<DecodeOutcome>,
    send_result: Option<SendResult>,
}

/// Per-source, per-epoch sequence allocation owned by the writer thread.
#[derive(Default)]
struct SequenceState {
    observation_seq: u64,
    control_seq: u64,
}

impl RecordJob {
    /// Assign the sequence domains this record belongs to.
    fn assign_sequences(
        &mut self,
        sequences: &mut BTreeMap<(SourceId, u64), SequenceState>,
    ) -> anyhow::Result<()> {
        let state = sequences
            .entry((self.source, self.connection_epoch))
            .or_default();
        state.observation_seq = state.observation_seq.saturating_add(1);
        self.observation_seq = state.observation_seq;
        if self.classification.is_control() {
            anyhow::ensure!(
                self.receive_seq.is_none(),
                "a native control observation cannot consume the data receive fence"
            );
            state.control_seq = state.control_seq.saturating_add(1);
            self.control_seq = Some(state.control_seq);
        } else {
            anyhow::ensure!(
                self.receive_seq.is_some() == (self.direction == FrameDirection::Inbound),
                "an inbound data observation requires a receive fence and an outbound one must not have it"
            );
        }
        Ok(())
    }
}

enum Command {
    Record(RecordJob),
    Finalize(Sender<Result<JournalSummary, String>>),
    Abort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecordKind {
    Data,
    Control,
}

/// Schema v2 record header written by this build.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordHeaderV2 {
    schema_version: u32,
    source: String,
    shard: u16,
    replica: u16,
    connection_epoch: u64,
    observation_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receive_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    control_seq: Option<u64>,
    received_at_us: i64,
    clock_source: String,
    record_kind: RecordKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    frame_kind: Option<FrameKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    opcode: Option<ControlOpcode>,
    direction: FrameDirection,
    signal: SessionSignal,
    mechanism: HeartbeatMechanism,
    payload_len: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decode: Option<DecodeOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    send_result: Option<SendResult>,
}

/// Schema v1 record header, retained for reading legacy journals.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecordHeaderV1 {
    schema_version: u32,
    source: String,
    shard: u16,
    replica: u16,
    connection_epoch: u64,
    receive_seq: u64,
    received_at_us: i64,
    clock_source: String,
    frame_kind: FrameKind,
    payload_len: u64,
    decode: DecodeOutcome,
}

/// Version-independent view of one record header.
#[derive(Debug, Clone)]
struct RecordHeader {
    schema_version: u32,
    source: String,
    shard: u16,
    replica: u16,
    clock_source: String,
    connection_epoch: u64,
    /// `observation_seq` for v2; the legacy receive fence for v1.
    observation_seq: u64,
    receive_seq: Option<u64>,
    control_seq: Option<u64>,
    received_at_us: i64,
    classification: FrameClassification,
    direction: FrameDirection,
    /// `None` for v1: those facts were never stored, and replay must not
    /// fabricate them.
    signal: Option<SessionSignal>,
    mechanism: Option<HeartbeatMechanism>,
    outcome: Option<DecodeOutcome>,
    send_result: Option<SendResult>,
    payload_len: u64,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct HeaderVersionProbe {
    schema_version: u32,
}

impl RecordHeader {
    fn parse(json: &[u8]) -> anyhow::Result<Self> {
        let probe: HeaderVersionProbe =
            serde_json::from_slice(json).context("parsing record header version")?;
        match probe.schema_version {
            1 => {
                let header: RecordHeaderV1 =
                    serde_json::from_slice(json).context("parsing v1 record header")?;
                Ok(Self {
                    schema_version: header.schema_version,
                    source: header.source,
                    shard: header.shard,
                    replica: header.replica,
                    clock_source: header.clock_source,
                    connection_epoch: header.connection_epoch,
                    observation_seq: header.receive_seq,
                    receive_seq: Some(header.receive_seq),
                    control_seq: None,
                    received_at_us: header.received_at_us,
                    classification: FrameClassification::Data {
                        frame_kind: header.frame_kind,
                    },
                    direction: FrameDirection::Inbound,
                    signal: None,
                    mechanism: None,
                    outcome: Some(header.decode),
                    send_result: None,
                    payload_len: header.payload_len,
                })
            }
            JOURNAL_SCHEMA_VERSION => {
                let header: RecordHeaderV2 =
                    serde_json::from_slice(json).context("parsing v2 record header")?;
                let classification = match (header.record_kind, header.frame_kind, header.opcode) {
                    (RecordKind::Data, Some(frame_kind), None) => {
                        FrameClassification::Data { frame_kind }
                    }
                    (RecordKind::Control, None, Some(opcode)) => {
                        FrameClassification::Control { opcode }
                    }
                    _ => bail!("record classification fields are inconsistent"),
                };
                anyhow::ensure!(
                    header.receive_seq.is_some()
                        == matches!(
                            (classification, header.direction),
                            (FrameClassification::Data { .. }, FrameDirection::Inbound)
                        ),
                    "receive fence presence does not match the record classification"
                );
                anyhow::ensure!(
                    header.control_seq.is_some() == classification.is_control(),
                    "control sequence presence does not match the record classification"
                );
                Ok(Self {
                    schema_version: header.schema_version,
                    source: header.source,
                    shard: header.shard,
                    replica: header.replica,
                    clock_source: header.clock_source,
                    connection_epoch: header.connection_epoch,
                    observation_seq: header.observation_seq,
                    receive_seq: header.receive_seq,
                    control_seq: header.control_seq,
                    received_at_us: header.received_at_us,
                    classification,
                    direction: header.direction,
                    signal: Some(header.signal),
                    mechanism: Some(header.mechanism),
                    outcome: header.decode,
                    send_result: header.send_result,
                    payload_len: header.payload_len,
                })
            }
            version => bail!(
                "unsupported journal record schema {version} (this build reads {JOURNAL_MIN_READABLE_SCHEMA_VERSION}..={JOURNAL_SCHEMA_VERSION})"
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SegmentHeader {
    schema_version: u32,
    run_id: String,
    venue: String,
    code_commit: String,
    config_sha256: String,
    segment_index: u64,
    created_at_us: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SegmentFooter {
    schema_version: u32,
    finalized: bool,
    record_count: u64,
    byte_count: u64,
    checksum: String,
    first_received_at_us: Option<i64>,
    last_received_at_us: Option<i64>,
    sources: Vec<SourceRange>,
}

/// Per-source receive range inside a segment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceRange {
    source: String,
    first_epoch: u64,
    last_epoch: u64,
    first_seq: u64,
    last_seq: u64,
    records: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    schema_version: u32,
    run_id: String,
    venue: String,
    code_commit: String,
    config_sha256: String,
    /// Non-secret egress provenance. Absent in journals written before
    /// route provenance existed; verification tolerates either shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    route: Option<crate::egress::RouteProvenance>,
    created_at_us: i64,
    state: RunState,
    durability: DurabilityPolicy,
    failure: Option<String>,
    finalized_at_us: Option<i64>,
    segments: Vec<ManifestSegment>,
}

impl Manifest {
    fn new(meta: &JournalMeta, durability: &DurabilityPolicy) -> Self {
        Self {
            schema_version: JOURNAL_SCHEMA_VERSION,
            run_id: meta.run_id.clone(),
            venue: meta.venue.clone(),
            code_commit: meta.code_commit.clone(),
            config_sha256: meta.config_sha256.clone(),
            route: meta.route.clone(),
            created_at_us: now_us().unwrap_or(0),
            state: RunState::Open,
            durability: durability.clone(),
            failure: None,
            finalized_at_us: None,
            segments: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManifestSegment {
    index: u64,
    file: String,
    state: String,
    record_count: u64,
    byte_count: u64,
    checksum: String,
    first_received_at_us: Option<i64>,
    last_received_at_us: Option<i64>,
    sources: Vec<SourceRange>,
}

struct SegmentWriter {
    index: u64,
    partial_path: PathBuf,
    final_path: PathBuf,
    file: BufWriter<File>,
    hasher: Sha256,
    bytes: u64,
    records: u64,
    first_received_at_us: Option<i64>,
    last_received_at_us: Option<i64>,
    sources: BTreeMap<String, SourceRange>,
    opened_at: Instant,
}

impl SegmentWriter {
    fn open(run_directory: &Path, index: u64, meta: &JournalMeta) -> anyhow::Result<Self> {
        let partial_path = run_directory.join(format!("{index:08}{PARTIAL_SUFFIX}"));
        let final_path = run_directory.join(format!("{index:08}{FINAL_SUFFIX}"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial_path)
            .with_context(|| format!("creating journal segment `{}`", partial_path.display()))?;
        let mut writer = Self {
            index,
            partial_path,
            final_path,
            file: BufWriter::new(file),
            hasher: Sha256::new(),
            bytes: 0,
            records: 0,
            first_received_at_us: None,
            last_received_at_us: None,
            sources: BTreeMap::new(),
            opened_at: Instant::now(),
        };
        writer.write_header(meta)?;
        Ok(writer)
    }

    fn write_header(&mut self, meta: &JournalMeta) -> anyhow::Result<()> {
        let header = SegmentHeader {
            schema_version: JOURNAL_SCHEMA_VERSION,
            run_id: meta.run_id.clone(),
            venue: meta.venue.clone(),
            code_commit: meta.code_commit.clone(),
            config_sha256: meta.config_sha256.clone(),
            segment_index: self.index,
            created_at_us: now_us().unwrap_or(0),
        };
        let json = serde_json::to_vec(&header).context("serializing segment header")?;
        let length = u32::try_from(json.len()).context("segment header exceeds u32")?;
        let mut framed = Vec::with_capacity(SEGMENT_MAGIC.len() + 4 + json.len());
        framed.extend_from_slice(&SEGMENT_MAGIC);
        framed.extend_from_slice(&length.to_le_bytes());
        framed.extend_from_slice(&json);
        self.file
            .write_all(&framed)
            .context("writing segment header")?;
        self.file
            .write_all(sha256_hex(&framed).as_bytes())
            .context("writing segment header checksum")?;
        self.file.flush().context("flushing segment header")?;
        self.file
            .get_ref()
            .sync_all()
            .context("syncing segment header")?;
        Ok(())
    }

    /// Append one record and return its framed length.
    fn write_record(&mut self, job: &RecordJob) -> anyhow::Result<u64> {
        let (record_kind, frame_kind, opcode) = match job.classification {
            FrameClassification::Data { frame_kind } => (RecordKind::Data, Some(frame_kind), None),
            FrameClassification::Control { opcode } => (RecordKind::Control, None, Some(opcode)),
        };
        let header = RecordHeaderV2 {
            schema_version: JOURNAL_SCHEMA_VERSION,
            source: job.source.to_string(),
            shard: job.source.shard,
            replica: job.source.replica,
            connection_epoch: job.connection_epoch,
            observation_seq: job.observation_seq,
            receive_seq: job.receive_seq,
            control_seq: job.control_seq,
            received_at_us: job.received_at_us,
            clock_source: "unix_epoch_microseconds".to_owned(),
            record_kind,
            frame_kind,
            opcode,
            direction: job.direction,
            signal: job.signal.clone(),
            mechanism: job.mechanism,
            payload_len: u64::try_from(job.payload.len()).unwrap_or(u64::MAX),
            decode: job.outcome.clone(),
            send_result: job.send_result.clone(),
        };
        let header_json = serde_json::to_vec(&header).context("serializing record header")?;
        let header_len = u32::try_from(header_json.len()).context("record header exceeds u32")?;
        let payload_len = u32::try_from(job.payload.len()).context("record payload exceeds u32")?;
        let record_len = u32::try_from(8 + header_json.len() + job.payload.len() + CHECKSUM_BYTES)
            .context("record exceeds u32")?;
        let mut record = Vec::with_capacity(RECORD_FRAMING_BYTES + record_len as usize);
        record.extend_from_slice(&RECORD_MAGIC);
        record.extend_from_slice(&record_len.to_le_bytes());
        record.extend_from_slice(&header_len.to_le_bytes());
        record.extend_from_slice(&payload_len.to_le_bytes());
        record.extend_from_slice(&header_json);
        record.extend_from_slice(&job.payload);
        record.extend_from_slice(sha256_hex(&record).as_bytes());
        let framed = u64::try_from(record.len()).unwrap_or(u64::MAX);
        self.file
            .write_all(&record)
            .context("writing journal record")?;
        self.hasher.update(&record);
        self.bytes = self.bytes.saturating_add(framed);
        self.records = self.records.saturating_add(1);
        self.first_received_at_us = self.first_received_at_us.or(Some(job.received_at_us));
        self.last_received_at_us = Some(job.received_at_us);
        let source = job.source.to_string();
        self.sources
            .entry(source.clone())
            .and_modify(|range| {
                range.last_epoch = job.connection_epoch;
                range.last_seq = job.observation_seq;
                range.records = range.records.saturating_add(1);
            })
            .or_insert(SourceRange {
                source,
                first_epoch: job.connection_epoch,
                last_epoch: job.connection_epoch,
                first_seq: job.observation_seq,
                last_seq: job.observation_seq,
                records: 1,
            });
        Ok(framed)
    }

    fn finalize(mut self, fault: Option<&FaultHook>) -> anyhow::Result<ManifestSegment> {
        self.file.flush().context("flushing journal segment")?;
        self.file
            .get_ref()
            .sync_all()
            .context("syncing journal segment")?;
        let checksum = hex_of(&self.hasher.clone().finalize());
        let footer = SegmentFooter {
            schema_version: JOURNAL_SCHEMA_VERSION,
            finalized: true,
            record_count: self.records,
            byte_count: self.bytes,
            checksum: checksum.clone(),
            first_received_at_us: self.first_received_at_us,
            last_received_at_us: self.last_received_at_us,
            sources: self.sources.values().cloned().collect(),
        };
        let json = serde_json::to_vec(&footer).context("serializing segment footer")?;
        let length = u32::try_from(json.len()).context("segment footer exceeds u32")?;
        let mut framed = Vec::with_capacity(FOOTER_MAGIC.len() + 4 + json.len());
        framed.extend_from_slice(&FOOTER_MAGIC);
        framed.extend_from_slice(&length.to_le_bytes());
        framed.extend_from_slice(&json);
        self.file
            .write_all(&framed)
            .context("writing segment footer")?;
        self.file
            .write_all(sha256_hex(&framed).as_bytes())
            .context("writing segment footer checksum")?;
        self.file
            .into_inner()
            .map_err(|error| error.into_error())
            .context("closing journal segment")?
            .sync_all()
            .context("syncing journal segment footer")?;
        run_fault(fault, FaultPoint::SegmentRename)?;
        fs::rename(&self.partial_path, &self.final_path).with_context(|| {
            format!(
                "renaming journal segment `{}` to `{}`",
                self.partial_path.display(),
                self.final_path.display()
            )
        })?;
        run_fault(fault, FaultPoint::AfterSegmentRename)?;
        if let Some(parent) = self.final_path.parent() {
            run_fault(fault, FaultPoint::DirectorySync)?;
            sync_directory(parent)?;
        }
        Ok(ManifestSegment {
            index: self.index,
            file: self
                .final_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_owned(),
            state: "finalized".to_owned(),
            record_count: footer.record_count,
            byte_count: footer.byte_count,
            checksum,
            first_received_at_us: footer.first_received_at_us,
            last_received_at_us: footer.last_received_at_us,
            sources: footer.sources,
        })
    }
}

fn hex_of(bytes: &[u8]) -> String {
    crate::util::hex_lower(bytes)
}

type FaultHook = Arc<dyn Fn(FaultPoint) -> anyhow::Result<()> + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultPoint {
    Write,
    Flush,
    Sync,
    Finalize,
    ManifestWrite,
    SegmentRename,
    DirectorySync,
    AfterRecordWrite,
    AfterSegmentRename,
    AfterManifestUpdate,
    AfterFinalManifestUpdate,
}

fn run_fault(hook: Option<&FaultHook>, point: FaultPoint) -> anyhow::Result<()> {
    match hook {
        Some(hook) => hook(point),
        None => Ok(()),
    }
}

fn run_writer(
    inner: Arc<Inner>,
    queue: Receiver<Command>,
    config: JournalConfig,
    meta: JournalMeta,
    mut manifest: Manifest,
    fault: Option<FaultHook>,
) {
    let mut segment = match SegmentWriter::open(&inner.run_directory, 0, &meta) {
        Ok(segment) => segment,
        Err(error) => {
            fail(&inner, &mut manifest, &error);
            return;
        }
    };
    let mut next_index = 1u64;
    let mut sequences: BTreeMap<(SourceId, u64), SequenceState> = BTreeMap::new();
    let tick_period = config.flush_interval.min(config.sync_interval);
    let ticks = tick(tick_period);
    let mut last_flush = Instant::now();
    let mut last_sync = Instant::now();

    loop {
        if let Some(reason) = run_failure(&inner) {
            fail_reason(&inner, &mut manifest, &reason);
            return;
        }
        select! {
            recv(queue) -> message => match message {
                Ok(Command::Record(mut job)) => {
                    let sequenced = job
                        .assign_sequences(&mut sequences)
                        .and_then(|()| run_fault(fault.as_ref(), FaultPoint::Write));
                    // Measure only the segment append itself: sequencing and
                    // fault-injection hooks are not production I/O latency.
                    let result = match sequenced {
                        Ok(()) => {
                            let append_started = Instant::now();
                            let appended = segment.write_record(&job);
                            if let Some(histogram) = inner.append_latency.as_ref() {
                                histogram.record(append_started.elapsed());
                            }
                            appended
                        }
                        Err(error) => Err(error),
                    };
                    match result {
                        Ok(framed) => {
                            {
                                let mut status = inner
                                    .status
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                status.counters.written =
                                    status.counters.written.saturating_add(1);
                                status.counters.bytes =
                                    status.counters.bytes.saturating_add(framed);
                                status.counters.queue_depth = queue.len() as u64;
                            }
                            inner.ack_cv.notify_all();
                            if let Err(error) =
                                run_fault(fault.as_ref(), FaultPoint::AfterRecordWrite)
                            {
                                fail(&inner, &mut manifest, &error);
                                return;
                            }
                            if config.sync_mode == SyncMode::Always {
                                if let Err(error) =
                                    flush_and_sync(&inner, &mut segment, fault.as_ref())
                                {
                                    fail(&inner, &mut manifest, &error);
                                    return;
                                }
                                last_flush = Instant::now();
                                last_sync = last_flush;
                            }
                            let rotate = (config.segment_max_bytes > 0
                                && segment.bytes >= config.segment_max_bytes)
                                || (config.segment_max_seconds > 0
                                    && segment.opened_at.elapsed()
                                        >= Duration::from_secs(config.segment_max_seconds));
                            if rotate
                                && let Err(error) = rotate_segment(
                                    &inner,
                                    &mut manifest,
                                    &mut segment,
                                    next_index,
                                    &meta,
                                    fault.as_ref(),
                                )
                            {
                                fail(&inner, &mut manifest, &error);
                                return;
                            }
                            if rotate {
                                next_index = next_index.saturating_add(1);
                            }
                        }
                        Err(error) => {
                            fail(&inner, &mut manifest, &error);
                            return;
                        }
                    }
                }
                Ok(Command::Finalize(reply)) => {
                    let result = finalize_run(&inner, &mut manifest, segment, fault.as_ref());
                    match result {
                        Ok(summary) => {
                            let _ = reply.send(Ok(summary));
                        }
                        Err(error) => {
                            fail(&inner, &mut manifest, &error);
                            let _ = reply.send(Err(format!("{error:#}")));
                        }
                    }
                    return;
                }
                Ok(Command::Abort) => {
                    if let Some(reason) = run_failure(&inner) {
                        fail_reason(&inner, &mut manifest, &reason);
                    } else {
                        mark_incomplete(
                            &inner,
                            &mut manifest,
                            "journal stopped without finalization",
                        );
                    }
                    return;
                }
                Err(_) => {
                    mark_incomplete(
                        &inner,
                        &mut manifest,
                        "journal writer lost all handles before finalization",
                    );
                    return;
                }
            },
            recv(ticks) -> _ => {
                let now = Instant::now();
                if now.duration_since(last_flush) >= config.flush_interval {
                    if let Err(error) = flush_only(&inner, &mut segment, fault.as_ref()) {
                        fail(&inner, &mut manifest, &error);
                        return;
                    }
                    last_flush = now;
                }
                if now.duration_since(last_sync) >= config.sync_interval {
                    if let Err(error) = sync_only(&inner, &mut segment, fault.as_ref()) {
                        fail(&inner, &mut manifest, &error);
                        return;
                    }
                    last_sync = now;
                }
            },
        }
    }
}

fn flush_only(
    inner: &Inner,
    segment: &mut SegmentWriter,
    fault: Option<&FaultHook>,
) -> anyhow::Result<()> {
    run_fault(fault, FaultPoint::Flush)?;
    segment.file.flush().context("flushing journal segment")?;
    let mut status = inner
        .status
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    status.counters.flushed = status.counters.written;
    drop(status);
    inner.ack_cv.notify_all();
    Ok(())
}

fn sync_only(
    inner: &Inner,
    segment: &mut SegmentWriter,
    fault: Option<&FaultHook>,
) -> anyhow::Result<()> {
    run_fault(fault, FaultPoint::Sync)?;
    segment
        .file
        .get_ref()
        .sync_all()
        .context("syncing journal segment")?;
    let mut status = inner
        .status
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    status.counters.synced = status.counters.written;
    drop(status);
    inner.ack_cv.notify_all();
    Ok(())
}

fn flush_and_sync(
    inner: &Inner,
    segment: &mut SegmentWriter,
    fault: Option<&FaultHook>,
) -> anyhow::Result<()> {
    flush_only(inner, segment, fault)?;
    sync_only(inner, segment, fault)
}

fn rotate_segment(
    inner: &Inner,
    manifest: &mut Manifest,
    segment: &mut SegmentWriter,
    next_index: u64,
    meta: &JournalMeta,
    fault: Option<&FaultHook>,
) -> anyhow::Result<()> {
    run_fault(fault, FaultPoint::Finalize)?;
    let replacement = SegmentWriter::open(&inner.run_directory, next_index, meta)?;
    let previous = std::mem::replace(segment, replacement);
    let entry = previous.finalize(fault)?;
    let count = entry.record_count;
    // Publish the manifest before recording the segment in memory. A failed
    // manifest write must leave the renamed segment uncommitted, so the run
    // cannot later be reported complete from an in-memory entry.
    run_fault(fault, FaultPoint::ManifestWrite)?;
    manifest.segments.push(entry);
    write_manifest(&inner.run_directory, manifest)?;
    run_fault(fault, FaultPoint::AfterManifestUpdate)?;
    let mut status = inner
        .status
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    status.counters.finalized = status.counters.finalized.saturating_add(count);
    status.counters.segments = manifest.segments.len() as u64;
    Ok(())
}

fn finalize_run(
    inner: &Inner,
    manifest: &mut Manifest,
    segment: SegmentWriter,
    fault: Option<&FaultHook>,
) -> anyhow::Result<JournalSummary> {
    if let Some(reason) = run_failure(inner) {
        fail_reason(inner, manifest, &reason);
        bail!("journal run failed before finalization: {reason}");
    }
    run_fault(fault, FaultPoint::Finalize)?;
    let entry = segment.finalize(fault)?;
    if let Some(reason) = run_failure(inner) {
        manifest.segments.push(entry);
        fail_reason(inner, manifest, &reason);
        bail!("journal run failed during finalization: {reason}");
    }
    manifest.segments.push(entry);
    manifest.state = RunState::Finalized;
    manifest.finalized_at_us = Some(now_us().unwrap_or(0));
    run_fault(fault, FaultPoint::ManifestWrite)?;
    write_manifest(&inner.run_directory, manifest)?;
    // This is a process-crash boundary, not a failure of finalization. Once
    // the finalized manifest is durable, a later hook error must not rewrite
    // the committed run as Failed. The subprocess test exits here directly.
    let _ = run_fault(fault, FaultPoint::AfterFinalManifestUpdate);
    let record_count = manifest
        .segments
        .iter()
        .map(|entry| entry.record_count)
        .sum();
    let bytes = manifest
        .segments
        .iter()
        .map(|entry| entry.byte_count)
        .sum::<u64>();
    let segment_count = manifest.segments.len() as u64;
    let mut status = inner
        .status
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    status.state = RunState::Finalized;
    status.counters.finalized = status.counters.written;
    // Segment finalization flushed and synced every written record before the
    // rename, so the durability counters must not lag the footer.
    status.counters.flushed = status.counters.written;
    status.counters.synced = status.counters.written;
    status.counters.segments = segment_count;
    status.counters.bytes = bytes;
    status.counters.queue_depth = 0;
    Ok(JournalSummary {
        run_id: inner.run_id.clone(),
        run_directory: inner.run_directory.display().to_string(),
        state: RunState::Finalized,
        record_count,
        segment_count,
        bytes,
    })
}

fn mark_incomplete(inner: &Inner, manifest: &mut Manifest, reason: &str) {
    manifest.state = RunState::Incomplete;
    manifest.failure = Some(reason.to_owned());
    match write_manifest(&inner.run_directory, manifest) {
        Ok(()) => set_state(inner, RunState::Incomplete, Some(reason.to_owned())),
        Err(error) => set_state(
            inner,
            RunState::Failed,
            Some(format!(
                "{reason}; persisting incomplete journal state failed: {error:#}"
            )),
        ),
    }
}

fn fail(inner: &Inner, manifest: &mut Manifest, error: &anyhow::Error) {
    let message = format!("{error:#}");
    fail_reason(inner, manifest, &message);
}

fn fail_reason(inner: &Inner, manifest: &mut Manifest, message: &str) {
    manifest.state = RunState::Failed;
    manifest.failure = Some(message.to_owned());
    let _ = write_manifest(&inner.run_directory, manifest);
    set_state(inner, RunState::Failed, Some(message.to_owned()));
    inner.ack_cv.notify_all();
}

fn write_manifest(directory: &Path, manifest: &Manifest) -> anyhow::Result<()> {
    write_json_atomic(&directory.join(MANIFEST_FILE), manifest)
        .with_context(|| format!("writing journal manifest in `{}`", directory.display()))
}

fn sync_directory(path: &Path) -> anyhow::Result<()> {
    let directory = File::open(path)
        .with_context(|| format!("opening directory `{}` for sync", path.display()))?;
    directory
        .sync_all()
        .with_context(|| format!("syncing directory `{}`", path.display()))
}

/// Result of verifying one run directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalVerification {
    pub schema_version: u32,
    pub run_id: String,
    pub state: RunState,
    pub complete: bool,
    pub record_count: u64,
    pub segment_count: u64,
    pub errors: Vec<String>,
    pub segments: Vec<SegmentVerification>,
}

/// Per-segment verification detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentVerification {
    pub file: String,
    pub state: String,
    pub record_count: u64,
    pub byte_count: u64,
    pub checksum: String,
    pub first_received_at_us: Option<i64>,
    pub last_received_at_us: Option<i64>,
    pub sources: Vec<SourceRange>,
}

/// Reconcile a run left by process termination.
///
/// The caller MUST first establish that the process which owned this run has
/// terminated. Recovery does not take a cross-process lease and must not race
/// a live writer.
///
/// Recovery does not promote a `.partial`
/// segment or an unmanifested `.pmj` file into the run. `Starting` and `Open`
/// manifests become `Incomplete`; terminal states are left unchanged. Repeated
/// calls are idempotent because an `Incomplete`, `Failed`, or `Finalized`
/// manifest is never rewritten.
pub fn recover_incomplete_run(run_directory: &Path) -> anyhow::Result<JournalVerification> {
    let manifest_path = run_directory.join(MANIFEST_FILE);
    let bytes = fs::read(&manifest_path).with_context(|| {
        format!(
            "reading manifest `{}` for recovery",
            manifest_path.display()
        )
    })?;
    let mut manifest: Manifest = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parsing manifest `{}` for recovery",
            manifest_path.display()
        )
    })?;
    anyhow::ensure!(
        (JOURNAL_MIN_READABLE_SCHEMA_VERSION..=JOURNAL_SCHEMA_VERSION)
            .contains(&manifest.schema_version),
        "unsupported journal manifest schema {} (this build reads {}..={})",
        manifest.schema_version,
        JOURNAL_MIN_READABLE_SCHEMA_VERSION,
        JOURNAL_SCHEMA_VERSION
    );
    if matches!(manifest.state, RunState::Starting | RunState::Open) {
        manifest.state = RunState::Incomplete;
        manifest.failure.get_or_insert_with(|| {
            "process ended before journal finalization; recovery did not promote partial or orphan segments".to_owned()
        });
        write_manifest(run_directory, &manifest)
            .context("persisting incomplete disposition during journal recovery")?;
    }
    verify_run(run_directory)
}

/// Verify one run directory against its manifest, segment footers, and record
/// checksums. A missing, partial, truncated, reordered, or checksum-mismatched
/// artifact makes `complete` false.
pub fn verify_run(run_directory: &Path) -> anyhow::Result<JournalVerification> {
    let manifest_path = run_directory.join(MANIFEST_FILE);
    let bytes = fs::read(&manifest_path)
        .with_context(|| format!("reading manifest `{}`", manifest_path.display()))?;
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing manifest `{}`", manifest_path.display()))?;
    anyhow::ensure!(
        (JOURNAL_MIN_READABLE_SCHEMA_VERSION..=JOURNAL_SCHEMA_VERSION)
            .contains(&manifest.schema_version),
        "unsupported journal manifest schema {} (this build reads {}..={})",
        manifest.schema_version,
        JOURNAL_MIN_READABLE_SCHEMA_VERSION,
        JOURNAL_SCHEMA_VERSION
    );
    let mut errors = Vec::new();
    if manifest.state != RunState::Finalized {
        errors.push(format!("run state is {:?}", manifest.state));
    }
    if let Some(failure) = &manifest.failure {
        errors.push(format!("run failure: {failure}"));
    }
    let mut segments = Vec::new();
    let mut record_count = 0u64;
    let mut previous_ranges: BTreeMap<String, SourceRange> = BTreeMap::new();
    let mut cursors: BTreeMap<String, SequenceCursor> = BTreeMap::new();
    for expected in &manifest.segments {
        match verify_segment(run_directory, &manifest, expected, &mut cursors) {
            Ok((segment, count)) => {
                for range in &segment.sources {
                    if let Some(previous) = previous_ranges.get(&range.source) {
                        let ordered = range.first_epoch > previous.last_epoch
                            || (range.first_epoch == previous.last_epoch
                                && range.first_seq > previous.last_seq);
                        if !ordered {
                            errors.push(format!(
                                "segment {}: record order regressed for {}: ({}, {}) then ({}, {})",
                                expected.file,
                                range.source,
                                previous.last_epoch,
                                previous.last_seq,
                                range.first_epoch,
                                range.first_seq,
                            ));
                        }
                    }
                }
                for range in &segment.sources {
                    previous_ranges.insert(range.source.clone(), range.clone());
                }
                record_count = record_count.saturating_add(count);
                segments.push(segment);
            }
            Err(error) => errors.push(format!("segment {}: {error}", expected.file)),
        }
    }
    match fs::read_dir(run_directory) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        let name = entry.file_name();
                        let name = name.to_string_lossy();
                        if name.ends_with(PARTIAL_SUFFIX) {
                            errors.push(format!("unfinalized segment `{name}`"));
                        } else if name.ends_with(FINAL_SUFFIX)
                            && !manifest.segments.iter().any(|segment| segment.file == name)
                        {
                            errors.push(format!("segment `{name}` is absent from the manifest"));
                        }
                    }
                    Err(error) => {
                        errors.push(format!("reading journal directory entry failed: {error}"))
                    }
                }
            }
        }
        Err(error) => errors.push(format!(
            "reading journal directory `{}` failed: {error}",
            run_directory.display()
        )),
    }
    Ok(JournalVerification {
        schema_version: JOURNAL_SCHEMA_VERSION,
        run_id: manifest.run_id,
        state: manifest.state,
        complete: errors.is_empty(),
        record_count,
        segment_count: manifest.segments.len() as u64,
        errors,
        segments,
    })
}

/// Check that a run report describes the same journal state and committed
/// segments as the manifest verifier.
///
/// A finalized report must reconcile every accepted record, segment, and byte.
/// An incomplete or failed report may contain queued or active-segment records,
/// but its finalized counters must match the committed manifest prefix.
///
/// The report's free-form `last_error` string is not compared
/// byte-for-byte to the manifest's `failure` field. The manifest records the
/// first writer error that failed the run, while `last_error` is overwritten
/// by later symptoms such as "journal writer stopped" when a second record is
/// attempted after the writer has exited. For a failed run the report must
/// still record an error; for a finalized run it must record none.
pub fn validate_report_status(
    status: &JournalStatus,
    verification: &JournalVerification,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        status.run_id == verification.run_id,
        "journal report run id `{}` does not match manifest run id `{}`",
        status.run_id,
        verification.run_id
    );
    anyhow::ensure!(
        status.state == verification.state,
        "journal report state {:?} does not match manifest state {:?}",
        status.state,
        verification.state
    );
    anyhow::ensure!(
        status.counters.segments == verification.segment_count,
        "journal report segment count {} does not match manifest segment count {}",
        status.counters.segments,
        verification.segment_count
    );
    anyhow::ensure!(
        status.counters.finalized == verification.record_count,
        "journal report finalized count {} does not match manifest record count {}",
        status.counters.finalized,
        verification.record_count
    );
    let manifest_failure = verification
        .errors
        .iter()
        .find_map(|error| error.strip_prefix("run failure: "));
    // Only Finalized runs must carry no failure. An Incomplete or Failed
    // manifest always records a reason in `failure`; the free-form report
    // string is not compared byte-for-byte because later symptoms can
    // overwrite it after the original cause is persisted.
    anyhow::ensure!(
        (status.state == RunState::Finalized) == (manifest_failure.is_none()),
        "journal report state {:?} disagrees with manifest failure {:?}",
        status.state,
        manifest_failure
    );
    if status.state == RunState::Failed {
        anyhow::ensure!(
            status.last_error.is_some(),
            "failed journal report records no error"
        );
    }

    if status.state == RunState::Finalized {
        let verified_bytes = verification
            .segments
            .iter()
            .map(|segment| segment.byte_count)
            .sum::<u64>();
        anyhow::ensure!(
            status.last_error.is_none(),
            "finalized journal report contains an error: {:?}",
            status.last_error
        );
        anyhow::ensure!(
            verification.complete,
            "journal report claims Finalized but manifest verification is incomplete: {}",
            verification.errors.join("; ")
        );
        anyhow::ensure!(
            status.counters.queued == status.counters.written
                && status.counters.written == verification.record_count,
            "finalized journal counters do not reconcile: queued={}, written={}, verified={}",
            status.counters.queued,
            status.counters.written,
            verification.record_count
        );
        anyhow::ensure!(
            status.counters.flushed == status.counters.written
                && status.counters.synced == status.counters.written,
            "finalized journal durability counters do not reconcile: written={}, flushed={}, synced={}",
            status.counters.written,
            status.counters.flushed,
            status.counters.synced
        );
        anyhow::ensure!(
            status.counters.bytes == verified_bytes,
            "journal report byte count {} does not match verified byte count {}",
            status.counters.bytes,
            verified_bytes
        );
        anyhow::ensure!(
            status.counters.queue_depth == 0,
            "finalized journal report has queue depth {}",
            status.counters.queue_depth
        );
    } else {
        anyhow::ensure!(
            !verification.complete,
            "non-final journal report is paired with a complete manifest"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
struct SequenceCursor {
    epoch: u64,
    observation: u64,
    receive: u64,
    control: u64,
}

fn verify_segment(
    run_directory: &Path,
    manifest: &Manifest,
    expected: &ManifestSegment,
    previous: &mut BTreeMap<String, SequenceCursor>,
) -> anyhow::Result<(SegmentVerification, u64)> {
    verify_segment_visiting(
        run_directory,
        manifest,
        expected,
        previous,
        MAX_RECORD_BYTES,
        None,
    )
}

/// Verify one segment and optionally deliver each record to a visitor.
///
/// Verification checks and the visitor see the same parsed bytes from one file
/// traversal, so a mutation after an earlier `verify_run` is rejected.
fn verify_segment_visiting(
    run_directory: &Path,
    manifest: &Manifest,
    expected: &ManifestSegment,
    previous: &mut BTreeMap<String, SequenceCursor>,
    max_record_bytes: usize,
    mut visitor: Option<&mut dyn JournalVisitor>,
) -> anyhow::Result<(SegmentVerification, u64)> {
    anyhow::ensure!(
        expected.state == "finalized",
        "manifest state is `{}`",
        expected.state
    );
    let path = run_directory.join(&expected.file);
    let file =
        File::open(&path).with_context(|| format!("opening segment `{}`", path.display()))?;
    let mut reader = JournalReader::with_limit(file, max_record_bytes);
    let header = read_segment_header(&mut reader.reader)?;
    anyhow::ensure!(
        header.run_id == manifest.run_id,
        "segment run id does not match the manifest"
    );
    anyhow::ensure!(
        header.segment_index == expected.index,
        "segment index does not match the manifest"
    );
    anyhow::ensure!(
        header.code_commit == manifest.code_commit
            && header.config_sha256 == manifest.config_sha256,
        "segment provenance does not match the manifest"
    );
    let segment_schema = header.schema_version;
    anyhow::ensure!(
        segment_schema == manifest.schema_version,
        "segment schema {segment_schema} does not match the manifest schema {}",
        manifest.schema_version
    );
    let mut hasher = Sha256::new();
    let mut records = 0u64;
    let mut first_us: Option<i64> = None;
    let mut last_us: Option<i64> = None;
    let mut ranges: BTreeMap<String, SourceRange> = BTreeMap::new();
    let mut body_bytes = 0u64;
    let mut segment_ordinal = 0u64;
    let mut segment_offset = 0u64;
    loop {
        let Some(magic) = reader.marker()? else {
            bail!("segment has no footer");
        };
        if magic == RECORD_MAGIC {
            let parsed = reader.read_record()?;
            anyhow::ensure!(
                parsed.header.schema_version == segment_schema,
                "record schema {} does not match the segment schema {segment_schema}",
                parsed.header.schema_version
            );
            let framed =
                u64::try_from(parsed.raw.len()).context("record length does not fit u64")?;
            let record_byte_offset = segment_offset;
            segment_offset = segment_offset
                .checked_add(framed)
                .context("record offset overflow")?;
            body_bytes = body_bytes
                .checked_add(framed)
                .context("segment byte count overflow")?;
            hasher.update(parsed.raw);
            records = records.checked_add(1).context("record count overflow")?;
            if let Some(visitor) = &mut visitor {
                let entry = JournalEntry {
                    position: JournalPosition {
                        run_id: manifest.run_id.clone(),
                        segment_index: expected.index,
                        segment_file: expected.file.clone(),
                        segment_record_ordinal: segment_ordinal,
                        record_byte_offset,
                        record_byte_length: framed,
                    },
                    schema_version: parsed.header.schema_version,
                    source: &parsed.header.source,
                    shard: parsed.header.shard,
                    replica: parsed.header.replica,
                    clock_source: &parsed.header.clock_source,
                    connection_epoch: parsed.header.connection_epoch,
                    observation_seq: parsed.header.observation_seq,
                    receive_seq: parsed.header.receive_seq,
                    control_seq: parsed.header.control_seq,
                    direction: parsed.header.direction,
                    classification: parsed.header.classification,
                    signal: parsed.header.signal.as_ref(),
                    mechanism: parsed.header.mechanism.as_ref(),
                    received_at_us: parsed.header.received_at_us,
                    payload: parsed.payload,
                    payload_sha256: sha256_hex(parsed.payload),
                    outcome: parsed.header.outcome.as_ref(),
                    send_result: parsed.header.send_result.as_ref(),
                };
                visitor.visit(&entry)?;
            }
            segment_ordinal = segment_ordinal
                .checked_add(1)
                .context("record ordinal overflow")?;
            let header = parsed.header;
            first_us = Some(first_us.map_or(header.received_at_us, |value| {
                value.min(header.received_at_us)
            }));
            last_us = Some(last_us.map_or(header.received_at_us, |value| {
                value.max(header.received_at_us)
            }));
            let source = header.source.clone();
            let cursor = previous.get(&source).copied().unwrap_or_default();
            anyhow::ensure!(
                header.connection_epoch >= cursor.epoch,
                "record order regressed for {source}: epoch {} after {}",
                header.connection_epoch,
                cursor.epoch
            );
            let same_epoch = header.connection_epoch == cursor.epoch;
            if same_epoch {
                anyhow::ensure!(
                    header.observation_seq
                        == cursor
                            .observation
                            .checked_add(1)
                            .context("observation sequence overflow")?,
                    "observation sequence for {source} is not contiguous in epoch {}: {} then {}",
                    header.connection_epoch,
                    cursor.observation,
                    header.observation_seq
                );
                if let Some(receive_seq) = header.receive_seq {
                    anyhow::ensure!(
                        receive_seq
                            == cursor
                                .receive
                                .checked_add(1)
                                .context("receive sequence overflow")?,
                        "receive sequence for {source} is not contiguous in epoch {}: {} then {receive_seq}",
                        header.connection_epoch,
                        cursor.receive
                    );
                }
                if let Some(control_seq) = header.control_seq {
                    anyhow::ensure!(
                        control_seq
                            == cursor
                                .control
                                .checked_add(1)
                                .context("control sequence overflow")?,
                        "control sequence for {source} is not contiguous in epoch {}: {} then {control_seq}",
                        header.connection_epoch,
                        cursor.control
                    );
                }
            } else {
                anyhow::ensure!(
                    header.observation_seq == 1,
                    "a new epoch for {source} must start at observation sequence 1, got {}",
                    header.observation_seq
                );
                anyhow::ensure!(
                    header.receive_seq.is_none_or(|seq| seq == 1),
                    "a new epoch for {source} must start its receive sequence at 1"
                );
                anyhow::ensure!(
                    header.control_seq.is_none_or(|seq| seq == 1),
                    "a new epoch for {source} must start its control sequence at 1"
                );
            }
            previous.insert(
                source.clone(),
                SequenceCursor {
                    epoch: header.connection_epoch,
                    observation: header.observation_seq,
                    // A sequence domain that has not appeared yet in this epoch
                    // continues from zero, not from the previous epoch.
                    receive: header.receive_seq.unwrap_or(if same_epoch {
                        cursor.receive
                    } else {
                        0
                    }),
                    control: header.control_seq.unwrap_or(if same_epoch {
                        cursor.control
                    } else {
                        0
                    }),
                },
            );
            ranges
                .entry(source.clone())
                .and_modify(|range| {
                    range.last_epoch = header.connection_epoch;
                    range.last_seq = header.observation_seq;
                    range.records = range.records.saturating_add(1);
                })
                .or_insert(SourceRange {
                    source,
                    first_epoch: header.connection_epoch,
                    last_epoch: header.connection_epoch,
                    first_seq: header.observation_seq,
                    last_seq: header.observation_seq,
                    records: 1,
                });
            continue;
        }
        if magic == FOOTER_MAGIC[..4] {
            let mut rest = [0u8; 4];
            reader
                .reader
                .read_exact(&mut rest)
                .context("reading footer magic")?;
            anyhow::ensure!(
                rest == FOOTER_MAGIC[4..],
                "segment footer magic is not recognized"
            );
            let footer = read_footer(&mut reader.reader)?;
            let checksum = hex_of(&hasher.clone().finalize());
            anyhow::ensure!(
                footer.finalized,
                "segment footer does not declare finalization"
            );
            anyhow::ensure!(
                footer.checksum == checksum,
                "segment checksum mismatch: footer {} computed {}",
                footer.checksum,
                checksum
            );
            anyhow::ensure!(
                footer.record_count == records,
                "footer record count {} does not match {}",
                footer.record_count,
                records
            );
            anyhow::ensure!(
                footer.byte_count == body_bytes,
                "footer byte count {} does not match {}",
                footer.byte_count,
                body_bytes
            );
            anyhow::ensure!(
                footer.checksum == expected.checksum,
                "footer checksum does not match the manifest"
            );
            anyhow::ensure!(
                footer.record_count == expected.record_count
                    && footer.byte_count == expected.byte_count,
                "footer counts do not match the manifest"
            );
            anyhow::ensure!(
                footer.first_received_at_us == expected.first_received_at_us
                    && footer.last_received_at_us == expected.last_received_at_us,
                "footer timestamps do not match the manifest"
            );
            let mut trailing = [0u8; 1];
            anyhow::ensure!(
                reader
                    .reader
                    .read(&mut trailing)
                    .context("reading segment tail")?
                    == 0,
                "segment contains bytes after the footer"
            );
            let source_ranges: Vec<SourceRange> = ranges.values().cloned().collect();
            anyhow::ensure!(
                source_ranges == expected.sources,
                "source ranges do not match the manifest"
            );
            let verification = SegmentVerification {
                file: expected.file.clone(),
                state: expected.state.clone(),
                record_count: records,
                byte_count: body_bytes,
                checksum,
                first_received_at_us: first_us,
                last_received_at_us: last_us,
                sources: source_ranges,
            };
            return Ok((verification, records));
        }
        bail!("unknown framing marker in segment");
    }
}

fn read_segment_header<R: Read>(file: &mut R) -> anyhow::Result<SegmentHeader> {
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic)
        .context("reading segment header magic")?;
    anyhow::ensure!(
        magic == SEGMENT_MAGIC,
        "segment header magic is not recognized"
    );
    let json = read_json_block(file).context("reading segment header")?;
    let mut framed = Vec::with_capacity(SEGMENT_MAGIC.len() + 4 + json.len());
    framed.extend_from_slice(&SEGMENT_MAGIC);
    framed.extend_from_slice(
        &u32::try_from(json.len())
            .context("segment header exceeds u32")?
            .to_le_bytes(),
    );
    framed.extend_from_slice(&json);
    let mut expected_hash = [0u8; CHECKSUM_BYTES];
    file.read_exact(&mut expected_hash)
        .context("reading segment header checksum")?;
    anyhow::ensure!(
        expected_hash == sha256_hex(&framed).as_bytes(),
        "segment header checksum mismatch"
    );
    let header: SegmentHeader = serde_json::from_slice(&json).context("parsing segment header")?;
    anyhow::ensure!(
        (JOURNAL_MIN_READABLE_SCHEMA_VERSION..=JOURNAL_SCHEMA_VERSION)
            .contains(&header.schema_version),
        "unsupported journal segment schema {}",
        header.schema_version
    );
    Ok(header)
}

fn read_json_block<R: Read>(file: &mut R) -> anyhow::Result<Vec<u8>> {
    let mut length = [0u8; 4];
    file.read_exact(&mut length)
        .context("reading block length")?;
    let length = u32::from_le_bytes(length) as usize;
    anyhow::ensure!(
        length <= MAX_HEADER_BYTES,
        "block length {length} exceeds limit"
    );
    let mut json = vec![0u8; length];
    file.read_exact(&mut json).context("reading block body")?;
    Ok(json)
}

/// One framed record parsed in place from a reusable buffer.
#[derive(Debug)]
struct ParsedRecordRef<'a> {
    raw: &'a [u8],
    header: RecordHeader,
    payload: &'a [u8],
}

/// Reusable, bounded record reader shared by verification and streaming.
struct JournalReader<R: Read> {
    reader: R,
    buffer: Vec<u8>,
    max_record_bytes: usize,
}

impl<R: Read> JournalReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            buffer: Vec::new(),
            max_record_bytes: MAX_RECORD_BYTES,
        }
    }

    fn with_limit(reader: R, max_record_bytes: usize) -> Self {
        Self {
            reader,
            buffer: Vec::new(),
            max_record_bytes,
        }
    }

    /// Read the next four-byte framing marker. `None` means clean EOF.
    ///
    /// A single `read` may legally return fewer than four bytes even when more
    /// bytes follow, so partial reads are accumulated until the marker is
    /// complete or the stream ends.
    fn marker(&mut self) -> anyhow::Result<Option<[u8; 4]>> {
        let mut marker = [0u8; 4];
        let mut filled = 0usize;
        while filled < marker.len() {
            let read = self
                .reader
                .read(&mut marker[filled..])
                .context("reading segment framing")?;
            if read == 0 {
                break;
            }
            filled = filled
                .checked_add(read)
                .context("framing read counter overflow")?;
        }
        if filled == 0 {
            return Ok(None);
        }
        anyhow::ensure!(filled == 4, "segment ends inside a framing marker");
        Ok(Some(marker))
    }

    /// Parse one framed record without copying its body or payload.
    fn read_record(&mut self) -> anyhow::Result<ParsedRecordRef<'_>> {
        let mut length = [0u8; 4];
        self.reader
            .read_exact(&mut length)
            .context("reading record length")?;
        let record_len = u32::from_le_bytes(length) as usize;
        anyhow::ensure!(
            (8 + CHECKSUM_BYTES..=self.max_record_bytes).contains(&record_len),
            "record length {record_len} is outside the configured bound"
        );
        // The checksum covers magic, encoded length and the full body. The  # prose-audit-ignore: binary format magic-number field
        // two header-length fields already live inside that body.
        let total = RECORD_MAGIC.len() + 4 + record_len;
        self.buffer.resize(total, 0);
        self.buffer[..4].copy_from_slice(&RECORD_MAGIC);
        self.buffer[4..8].copy_from_slice(&length);
        self.reader
            .read_exact(&mut self.buffer[8..total])
            .context("reading record body")?;
        let header_len = u32::from_le_bytes(
            self.buffer[8..12]
                .try_into()
                .context("reading record header length")?,
        ) as usize;
        anyhow::ensure!(
            header_len <= MAX_HEADER_BYTES,
            "record header length {header_len} exceeds limit"
        );
        let payload_len = u32::from_le_bytes(
            self.buffer[12..16]
                .try_into()
                .context("reading record payload length")?,
        ) as usize;
        anyhow::ensure!(
            header_len
                .checked_add(payload_len)
                .and_then(|value| value.checked_add(8 + CHECKSUM_BYTES))
                == Some(record_len),
            "record length fields are inconsistent"
        );
        let payload_start = 16 + header_len;
        let checksum_start = total - CHECKSUM_BYTES;
        let expected = sha256_hex(&self.buffer[..checksum_start]);
        anyhow::ensure!(
            &self.buffer[checksum_start..] == expected.as_bytes(),
            "record checksum mismatch"
        );
        let header = RecordHeader::parse(&self.buffer[16..payload_start])?;
        anyhow::ensure!(
            header.payload_len == payload_len as u64,
            "record payload length does not match its header"
        );
        Ok(ParsedRecordRef {
            raw: &self.buffer,
            header,
            payload: &self.buffer[payload_start..checksum_start],
        })
    }
}

fn read_footer<R: Read>(file: &mut R) -> anyhow::Result<SegmentFooter> {
    let json = read_json_block(file).context("reading segment footer")?;
    let mut framed = Vec::with_capacity(FOOTER_MAGIC.len() + 4 + json.len());
    framed.extend_from_slice(&FOOTER_MAGIC);
    framed.extend_from_slice(
        &u32::try_from(json.len())
            .context("segment footer exceeds u32")?
            .to_le_bytes(),
    );
    framed.extend_from_slice(&json);
    let mut expected = [0u8; CHECKSUM_BYTES];
    file.read_exact(&mut expected)
        .context("reading segment footer checksum")?;
    anyhow::ensure!(
        expected == sha256_hex(&framed).as_bytes(),
        "segment footer checksum mismatch"
    );
    serde_json::from_slice(&json).context("parsing segment footer")
}

/// One journal data record, including the original payload bytes.
///
/// This is the v1-compatible view returned by [`read_records`]: inbound
/// application data only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalRecord {
    pub schema_version: u32,
    pub source: String,
    pub connection_epoch: u64,
    pub receive_seq: u64,
    pub received_at_us: i64,
    pub frame_kind: FrameKind,
    pub payload: Vec<u8>,
    pub outcome: DecodeOutcome,
}

/// One retained observation, data or native control.
///
/// `signal` and `mechanism` are `None` for v1 records: those facts were never
/// stored, and a reader must not fabricate them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalObservation {
    pub schema_version: u32,
    pub source: String,
    pub connection_epoch: u64,
    pub observation_seq: u64,
    pub receive_seq: Option<u64>,
    pub control_seq: Option<u64>,
    pub direction: FrameDirection,
    pub classification: FrameClassification,
    pub signal: Option<SessionSignal>,
    pub mechanism: Option<HeartbeatMechanism>,
    pub received_at_us: i64,
    pub payload: Vec<u8>,
    pub outcome: Option<DecodeOutcome>,
    pub send_result: Option<SendResult>,
}

/// Read every application data record from the finalized segments of one run
/// in file order. Native control observations are excluded by contract.
pub fn read_records(run_directory: &Path) -> anyhow::Result<Vec<JournalRecord>> {
    Ok(read_observations(run_directory)?
        .into_iter()
        .filter_map(|observation| {
            let receive_seq = observation.receive_seq?;
            if !observation
                .classification
                .is_inbound_data(observation.direction)
            {
                return None;
            }
            let FrameClassification::Data { frame_kind } = observation.classification else {
                return None;
            };
            Some(JournalRecord {
                schema_version: observation.schema_version,
                source: observation.source,
                connection_epoch: observation.connection_epoch,
                receive_seq,
                received_at_us: observation.received_at_us,
                frame_kind,
                payload: observation.payload,
                outcome: observation.outcome.unwrap_or_default(),
            })
        })
        .collect())
}

fn observation_from(header: &RecordHeader, payload: &[u8]) -> JournalObservation {
    JournalObservation {
        schema_version: header.schema_version,
        source: header.source.clone(),
        connection_epoch: header.connection_epoch,
        observation_seq: header.observation_seq,
        receive_seq: header.receive_seq,
        control_seq: header.control_seq,
        direction: header.direction,
        classification: header.classification,
        signal: header.signal.clone(),
        mechanism: header.mechanism,
        received_at_us: header.received_at_us,
        payload: payload.to_vec(),
        outcome: header.outcome.clone(),
        send_result: header.send_result.clone(),
    }
}

/// Read every retained observation (application data and native controls) from
/// the finalized segments of one run in file order, preserving the order the
/// source worker retained them.
///
/// This compatibility API materializes the whole run. Exporters use
/// [`visit_observations`] instead.
pub fn read_observations(run_directory: &Path) -> anyhow::Result<Vec<JournalObservation>> {
    let verification = verify_run(run_directory)?;
    anyhow::ensure!(
        verification.complete,
        "journal run is not complete: {}",
        verification.errors.join("; ")
    );
    let manifest: Manifest = serde_json::from_slice(&fs::read(run_directory.join(MANIFEST_FILE))?)?;
    let mut observations = Vec::new();
    for segment in &manifest.segments {
        let file = File::open(run_directory.join(&segment.file))?;
        let mut reader = JournalReader::new(file);
        read_segment_header(&mut reader.reader)?;
        loop {
            let Some(magic) = reader.marker()? else {
                bail!("segment has no footer");
            };
            if magic == RECORD_MAGIC {
                let parsed = reader.read_record()?;
                observations.push(observation_from(&parsed.header, parsed.payload));
                continue;
            }
            if magic == FOOTER_MAGIC[..4] {
                break;
            }
            bail!("unknown framing marker while reading records");
        }
    }
    Ok(observations)
}

/// Stable storage position of one journal observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalPosition {
    pub run_id: String,
    pub segment_index: u64,
    pub segment_file: String,
    /// Zero-based record ordinal within the segment.
    pub segment_record_ordinal: u64,
    /// Zero-based byte offset from the start of the segment record region,
    /// after the segment header.
    pub record_byte_offset: u64,
    /// Length of the complete framed record, including magic, lengths and  # prose-audit-ignore: binary format magic-number field
    /// checksum. The offset is relative to the segment record region.
    pub record_byte_length: u64,
}

/// One observation delivered to a streaming visitor.
///
/// The payload borrows the reader's reusable buffer. A visitor that needs to
/// retain it must copy it explicitly; the journal is the authoritative copy.
#[derive(Debug)]
pub struct JournalEntry<'a> {
    pub position: JournalPosition,
    pub schema_version: u32,
    pub source: &'a str,
    pub shard: u16,
    pub replica: u16,
    pub clock_source: &'a str,
    pub connection_epoch: u64,
    pub observation_seq: u64,
    pub receive_seq: Option<u64>,
    pub control_seq: Option<u64>,
    pub direction: FrameDirection,
    pub classification: FrameClassification,
    pub signal: Option<&'a SessionSignal>,
    pub mechanism: Option<&'a HeartbeatMechanism>,
    pub received_at_us: i64,
    pub payload: &'a [u8],
    pub payload_sha256: String,
    pub outcome: Option<&'a DecodeOutcome>,
    pub send_result: Option<&'a SendResult>,
}

/// Consumer of streamed journal observations.
pub trait JournalVisitor {
    fn visit(&mut self, entry: &JournalEntry<'_>) -> anyhow::Result<()>;
}

impl<F> JournalVisitor for F
where
    F: for<'a> FnMut(&JournalEntry<'a>) -> anyhow::Result<()>,
{
    fn visit(&mut self, entry: &JournalEntry<'_>) -> anyhow::Result<()> {
        self(entry)
    }
}

/// Bound on a single framed record accepted by the streaming reader.
#[derive(Debug, Clone, Copy)]
pub struct JournalStreamConfig {
    pub max_record_bytes: usize,
}

impl Default for JournalStreamConfig {
    fn default() -> Self {
        Self {
            max_record_bytes: MAX_RECORD_BYTES,
        }
    }
}

/// Row accounting for one completed streaming traversal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalStreamSummary {
    pub run_id: String,
    pub segments: u64,
    pub records: u64,
    pub record_bytes: u64,
}

/// Visit every retained observation in file order with bounded memory.
///
/// Verification runs first through the same record parser. The visitor holds
/// one record at a time; the payload borrows a reusable buffer.
pub fn visit_observations(
    run_directory: &Path,
    visitor: &mut impl JournalVisitor,
) -> anyhow::Result<JournalStreamSummary> {
    visit_observations_with_config(run_directory, &JournalStreamConfig::default(), visitor)
}

/// Bounded variant of [`visit_observations`] with an explicit record limit.
pub fn visit_observations_with_config(
    run_directory: &Path,
    config: &JournalStreamConfig,
    visitor: &mut impl JournalVisitor,
) -> anyhow::Result<JournalStreamSummary> {
    let verification = verify_run(run_directory)?;
    anyhow::ensure!(
        verification.complete,
        "journal run is not complete: {}",
        verification.errors.join("; ")
    );
    let manifest: Manifest = serde_json::from_slice(&fs::read(run_directory.join(MANIFEST_FILE))?)?;
    let mut previous: BTreeMap<String, SequenceCursor> = BTreeMap::new();
    let mut summary = JournalStreamSummary {
        run_id: manifest.run_id.clone(),
        segments: 0,
        records: 0,
        record_bytes: 0,
    };
    for segment in &manifest.segments {
        let (verified, records) = verify_segment_visiting(
            run_directory,
            &manifest,
            segment,
            &mut previous,
            config.max_record_bytes,
            Some(&mut *visitor),
        )?;
        summary.records = summary
            .records
            .checked_add(records)
            .context("streamed record count overflow")?;
        summary.record_bytes = summary
            .record_bytes
            .checked_add(verified.byte_count)
            .context("streamed byte count overflow")?;
        summary.segments = summary
            .segments
            .checked_add(1)
            .context("streamed segment count overflow")?;
    }
    anyhow::ensure!(
        summary.records == verification.record_count
            && summary.segments == verification.segment_count
            && summary.record_bytes
                == verification
                    .segments
                    .iter()
                    .map(|segment| segment.byte_count)
                    .sum::<u64>(),
        "streamed row accounting does not match verification"
    );
    Ok(summary)
}

#[cfg(test)]
mod tests;
