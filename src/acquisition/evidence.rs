// SPDX-License-Identifier: Apache-2.0
//! Durable acquisition evidence bound to the raw-frame journal.
//!
//! The journal remains the evidence authority. A packet is written to the
//! journal before its versioned evidence extension is persisted. Once the run
//! is closed, the extension is bound to the stable [`JournalPosition`] of its
//! journal record and both are verified as one evidence relationship. A
//! mismatch, an absent extension or an ambiguous position fails closed.
//!
//! Durability boundaries are explicit rather than implied by `sync_all`:
//! - A file `sync_all` persists that file's bytes on filesystems that honour
//!   the call. It does not persist the containing directory entry and does not
//!   cover an interruption before the call returns.
//! - The containing directory is synced after store creation and after atomic
//!   replacement where the platform supports directory sync. Where it does
//!   not, only file-content durability is claimed: a creation or rename can
//!   still be lost on power failure.
//! - Every handle for one path shares one writer and one poison state. An
//!   ambiguous write, flush, sync, rename or directory-sync outcome poisons
//!   the store until [`EvidenceStore::recover`] verifies the reopened state.
//!   The failure class survived is process-level interruption between
//!   operations: no partial write or replacement is ever reported as success.
//!   Zero data loss is not claimed for power loss, unreliable storage or
//!   concurrent processes.

use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, OnceLock},
    time::Duration,
};

use serde::Deserialize;
use serde::Serialize;

use crate::{
    acquisition::codec::CodecRegistry,
    acquisition::packet::PacketEvidence,
    integrity::journal::{
        DataRecord, DecodeOutcome, JournalAckLevel, JournalHandle, JournalPosition,
        JournalStreamConfig, JournalVisitor, RawFrame, visit_observations_with_config,
    },
    protocol::{HeartbeatMechanism, SessionSignal},
    util::sha256_hex,
};

/// Schema version of the evidence extension contract.
pub const EVIDENCE_EXTENSION_SCHEMA_VERSION: u32 = 1;

/// Upper bound on post-run binding work for one evidence store.
pub const MAX_BINDING_ENTRIES: usize = 1_000_000;

/// Stage at which an ingest may be interrupted in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailurePoint {
    /// Payload arrived at the receive boundary.
    Receive,
    /// Journal submission failed.
    JournalSubmit,
    /// Journal write failed after submission.
    JournalPersist,
    /// Evidence extension write failed.
    EvidencePersist,
    /// Codec decode failed.
    Decode,
    /// Typed normalization failed.
    Normalize,
    /// Canonical persistence failed.
    CanonicalPersist,
}

impl FailurePoint {
    /// Return the stable contract string for this stage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Receive => "receive",
            Self::JournalSubmit => "journal_submit",
            Self::JournalPersist => "journal_persist",
            Self::EvidencePersist => "evidence_persist",
            Self::Decode => "decode",
            Self::Normalize => "normalize",
            Self::CanonicalPersist => "canonical_persist",
        }
    }
}

impl fmt::Display for FailurePoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Acknowledgement boundary reached by one record.
///
/// The variants are ordered from weakest to strongest. Each name promises the
/// exact boundary reached by the journal writer, not a general durability
/// claim:
/// - [`Self::Received`]: the payload was accepted at the ingest boundary, but
///   no journal record was admitted.
/// - [`Self::Journalled`]: the record was admitted to the authoritative
///   journal's bounded queue and the writer owns it. This is not durable
///   storage; a process failure before a later boundary can lose the record.
/// - [`Self::Written`]: the record was passed to the writer layer and appended
///   to the open segment's userspace buffer.
/// - [`Self::Flushed`]: the userspace buffer was flushed to the operating
///   system. The bytes are not yet synced to stable storage.
/// - [`Self::Synced`]: a requested file sync completed for the record.
/// - [`Self::Replicated`]: remote copies acknowledged the record. No local
///   replication exists, so no profile may claim this boundary.
/// - [`Self::Finalized`]: the segment was finalized with its footer and
///   manifest metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityAck {
    Received,
    Journalled,
    Written,
    Flushed,
    Synced,
    Replicated,
    Finalized,
}

impl DurabilityAck {
    /// Return the stable contract string for this acknowledgement.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Journalled => "journalled",
            Self::Written => "written",
            Self::Flushed => "flushed",
            Self::Synced => "synced",
            Self::Replicated => "replicated",
            Self::Finalized => "finalized",
        }
    }

    /// Journal writer boundary that establishes this public acknowledgement.
    ///
    /// `Journalled` is queue admission with writer ownership, not a write: the
    /// writer has taken the record but has not touched stable storage yet.
    /// Boundaries with no journal equivalent (receive, replication and segment
    /// finalization) are not producer-waitable and return `None`.
    #[must_use]
    pub(crate) const fn journal_level(self) -> Option<JournalAckLevel> {
        match self {
            Self::Journalled => Some(JournalAckLevel::Queued),
            Self::Written => Some(JournalAckLevel::Written),
            Self::Flushed => Some(JournalAckLevel::Flushed),
            Self::Synced => Some(JournalAckLevel::Synced),
            Self::Received | Self::Replicated | Self::Finalized => None,
        }
    }

    /// Public acknowledgement achieved by a journal writer boundary.
    ///
    /// This is the exact inverse of [`Self::journal_level`] for every level a
    /// producer can wait on, so a profile's declaration and the acknowledgement
    /// actually returned after ingest cannot drift apart.
    #[must_use]
    pub(crate) const fn from_journal_level(level: JournalAckLevel) -> Self {
        match level {
            JournalAckLevel::Queued => Self::Journalled,
            JournalAckLevel::Written => Self::Written,
            JournalAckLevel::Flushed => Self::Flushed,
            JournalAckLevel::Synced => Self::Synced,
        }
    }
}

/// Local durability profile requested for a source class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityProfile {
    D1,
    D2,
    D3,
    D4,
    D5,
}

impl DurabilityProfile {
    /// Acknowledgement boundary this profile requires.
    #[must_use]
    pub const fn required_ack(self) -> DurabilityAck {
        match self {
            Self::D1 => DurabilityAck::Journalled,
            Self::D2 => DurabilityAck::Flushed,
            Self::D3 => DurabilityAck::Synced,
            Self::D4 | Self::D5 => DurabilityAck::Replicated,
        }
    }

    /// Whether this profile can be reached by a single local process.
    #[must_use]
    pub const fn locally_achievable(self) -> bool {
        matches!(self, Self::D1 | Self::D2 | Self::D3)
    }
}

/// Disposition of one received payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EvidenceDisposition {
    Received,
    Journalled,
    EvidencePersisted,
    Decoded,
    Normalized,
    CanonicalPersisted,
    Rejected { at: FailurePoint, reason: String },
    Quarantined { at: FailurePoint, reason: String },
}

impl EvidenceDisposition {
    /// Return the stable contract label for this disposition.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Journalled => "journalled",
            Self::EvidencePersisted => "evidence_persisted",
            Self::Decoded => "decoded",
            Self::Normalized => "normalized",
            Self::CanonicalPersisted => "canonical_persisted",
            Self::Rejected { .. } => "rejected",
            Self::Quarantined { .. } => "quarantined",
        }
    }
}

/// Versioned evidence extension for one raw journal observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceExtension {
    pub schema_version: u32,
    /// Stable identity derived from immutable source inputs.
    pub evidence_id: String,
    pub source_text: String,
    pub source_shard: u16,
    pub source_replica: u16,
    pub connection_epoch: u64,
    pub sequence: Option<u64>,
    pub channel: String,
    pub protocol: String,
    pub source_protocol: String,
    pub frame_kind: String,
    pub source_schema_id: String,
    pub source_schema_version: u32,
    pub sequence_domain_id: String,
    pub receive_sequence: u64,
    pub capture_location: String,
    pub decoder_version: String,
    pub received_at_us: i64,
    pub payload_sha256: String,
    /// Acknowledgement returned by the journal writer for this record.
    #[serde(default)]
    pub journal_ack: Option<crate::integrity::journal::JournalAck>,
    /// Bound after the journal run is closed.
    #[serde(default)]
    pub position: Option<JournalPosition>,
}

/// Source decoding context that must travel with durable evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceContext {
    pub sequence_domain_id: String,
    pub source_schema_id: String,
    pub source_schema_version: u32,
    pub receive_sequence: u64,
}

impl EvidenceExtension {
    /// Build an extension from packet evidence and an explicit journal source.
    #[must_use]
    pub fn from_packet(evidence: &PacketEvidence, source: crate::model::SourceId) -> Self {
        Self {
            schema_version: EVIDENCE_EXTENSION_SCHEMA_VERSION,
            evidence_id: Self::derive_id(evidence, source),
            source_text: evidence.source.clone(),
            source_shard: source.shard,
            source_replica: source.replica,
            connection_epoch: evidence.connection_epoch,
            sequence: evidence.sequence,
            channel: evidence.channel.as_str().to_owned(),
            protocol: evidence.protocol.clone(),
            source_protocol: evidence.protocol.clone(),
            frame_kind: format!("{:?}", evidence.frame_kind).to_ascii_lowercase(),
            source_schema_id: String::new(),
            source_schema_version: 0,
            sequence_domain_id: String::new(),
            receive_sequence: 0,
            capture_location: evidence.capture_location.clone(),
            decoder_version: evidence.decoder_version.clone(),
            received_at_us: evidence.received_at_us,
            payload_sha256: evidence.payload_sha256(),
            journal_ack: None,
            position: None,
        }
    }

    /// Attach source decoding context before persistence.
    #[must_use]
    pub fn with_context(mut self, context: &EvidenceContext) -> Self {
        self.source_schema_id = context.source_schema_id.clone();
        self.source_schema_version = context.source_schema_version;
        self.sequence_domain_id = context.sequence_domain_id.clone();
        self.receive_sequence = context.receive_sequence;
        self
    }

    /// Derive a stable identity from immutable receive inputs.
    #[must_use]
    pub fn derive_id(evidence: &PacketEvidence, source: crate::model::SourceId) -> String {
        let mut text = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            source.shard,
            source.replica,
            evidence.source,
            evidence.connection_epoch,
            evidence.sequence.unwrap_or(u64::MAX),
            evidence.channel.as_str(),
            evidence.received_at_us,
            evidence.payload_sha256()
        );
        text.push('|');
        text.push_str(&sha256_hex(&evidence.payload));
        format!("ev-{}", sha256_hex(text.as_bytes()))
    }

    /// Validate the extension contract before persisting it.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema_version == EVIDENCE_EXTENSION_SCHEMA_VERSION,
            "unsupported evidence extension version {}",
            self.schema_version
        );
        anyhow::ensure!(!self.evidence_id.is_empty(), "empty evidence id");
        anyhow::ensure!(!self.source_text.is_empty(), "empty evidence source");
        anyhow::ensure!(
            self.payload_sha256.len() == 64,
            "payload digest is not a SHA-256 hex string"
        );
        Ok(())
    }
}

/// Boundary at which an evidence store write may be interrupted in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFaultPoint {
    /// Before bytes are handed to the sink.
    Write,
    /// Before buffered bytes are flushed to the file.
    Flush,
    /// Before the file is synced to stable storage.
    Sync,
    /// Before the temporary file replaces the store.
    Rename,
    /// Before the containing directory is synced.
    DirectorySync,
}

impl StoreFaultPoint {
    /// Return the stable contract string for this boundary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Flush => "flush",
            Self::Sync => "sync",
            Self::Rename => "rename",
            Self::DirectorySync => "directory_sync",
        }
    }
}

impl fmt::Display for StoreFaultPoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Write serialization and poison state shared by every handle to one file.
#[derive(Debug, Default)]
struct StoreState {
    /// Set when an outcome may have partially changed the store on disk.
    poisoned: bool,
}

/// Handles created independently for the same path must serialize together.
static STORE_STATES: OnceLock<Mutex<BTreeMap<PathBuf, Arc<Mutex<StoreState>>>>> = OnceLock::new();

fn shared_state(path: &Path) -> Arc<Mutex<StoreState>> {
    let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let registry = STORE_STATES.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut registry = registry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Arc::clone(registry.entry(key).or_default())
}

const POISON_MESSAGE: &str =
    "evidence store is poisoned after an ambiguous write; call recover() to verify state";

fn ensure_writable(state: &StoreState) -> anyhow::Result<()> {
    anyhow::ensure!(!state.poisoned, "{POISON_MESSAGE}");
    Ok(())
}

fn injected(point: StoreFaultPoint) -> anyhow::Error {
    anyhow::anyhow!("injected failure at {} boundary", point.as_str())
}

fn poison_after(
    state: &mut StoreState,
    point: StoreFaultPoint,
    error: impl fmt::Display,
) -> anyhow::Error {
    state.poisoned = true;
    anyhow::anyhow!("ambiguous {} failure: {error}", point.as_str())
}

fn directory_sync_unavailable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::Unsupported
            | std::io::ErrorKind::InvalidInput
            | std::io::ErrorKind::PermissionDenied
            | std::io::ErrorKind::IsADirectory
    )
}

/// Sync the directory entry, reporting unsupported platforms by skipping it.
fn sync_parent_directory(path: &Path) -> anyhow::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let directory = File::open(parent)
        .map_err(|error| anyhow::anyhow!("open containing directory for sync: {error}"))?;
    match directory.sync_all() {
        Ok(()) => Ok(()),
        // Windows and some filesystems cannot sync a directory handle. The
        // caller proceeds without claiming directory-entry durability there.
        Err(error) if directory_sync_unavailable(&error) => Ok(()),
        Err(error) => Err(anyhow::anyhow!("sync containing directory: {error}")),
    }
}

fn read_extensions(path: &Path) -> anyhow::Result<Vec<EvidenceExtension>> {
    let file = File::open(path)?;
    let mut extensions = Vec::new();
    for (line_number, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let extension: EvidenceExtension = serde_json::from_str(&line)
            .map_err(|error| anyhow::anyhow!("line {}: {}", line_number + 1, error))?;
        extension.validate()?;
        extensions.push(extension);
    }
    Ok(extensions)
}

/// Append-only NDJSON store of evidence extensions.
#[derive(Debug, Clone)]
pub struct EvidenceStore {
    path: PathBuf,
    /// Shared across clones and independent handles for the same path so
    /// appends and replacements cannot interleave or race.
    shared: Arc<Mutex<StoreState>>,
    /// One-shot deterministic interruption installed by tests.
    fault: Arc<Mutex<Option<StoreFaultPoint>>>,
}

impl EvidenceStore {
    /// Open or create a store in `directory`.
    pub fn new(directory: &Path, name: &str) -> anyhow::Result<Self> {
        std::fs::create_dir_all(directory)?;
        let path = directory.join(name);
        if !path.exists() {
            let file = File::create(&path)?;
            file.sync_all()?;
            drop(file);
            sync_parent_directory(&path)?;
        }
        Ok(Self {
            shared: shared_state(&path),
            path,
            fault: Arc::new(Mutex::new(None)),
        })
    }

    /// Return the store file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock_state(&self) -> MutexGuard<'_, StoreState> {
        self.shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn fault_here(&self, point: StoreFaultPoint) -> bool {
        let mut fault = self
            .fault
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *fault == Some(point) {
            *fault = None;
            true
        } else {
            false
        }
    }

    /// Install a one-shot write interruption at `point` for deterministic tests.
    pub fn with_injected_fault(self, point: StoreFaultPoint) -> Self {
        *self
            .fault
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(point);
        self
    }

    /// Whether an ambiguous write has left this store unavailable for writes.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.lock_state().poisoned
    }

    /// Verify the reopened state and clear poison after an ambiguous outcome.
    ///
    /// This is the explicit recovery step: a poisoned store refuses writes
    /// until every line on disk has been read and validated again. An orphan
    /// temporary file left by an interrupted replacement is removed here.
    pub fn recover(&self) -> anyhow::Result<()> {
        let mut state = self.lock_state();
        read_extensions(&self.path)?;
        let temporary = self.path.with_extension("tmp");
        if temporary.exists() {
            std::fs::remove_file(&temporary).map_err(|error| {
                anyhow::anyhow!("recover cannot remove orphan temporary file: {error}")
            })?;
        }
        state.poisoned = false;
        Ok(())
    }

    /// Append one validated extension.
    pub fn append(&self, extension: &EvidenceExtension) -> anyhow::Result<()> {
        extension.validate()?;
        let line =
            serde_json::to_string(extension).map_err(|error| anyhow::anyhow!(error.to_string()))?;
        let mut payload = line.into_bytes();
        payload.push(b'\n');
        let mut state = self.lock_state();
        ensure_writable(&state)?;

        if self.fault_here(StoreFaultPoint::Write) {
            return Err(poison_after(
                &mut state,
                StoreFaultPoint::Write,
                injected(StoreFaultPoint::Write),
            ));
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|error| anyhow::anyhow!("open evidence store for append: {error}"))?;
        if let Err(error) = file.write_all(&payload) {
            return Err(poison_after(&mut state, StoreFaultPoint::Write, error));
        }
        if self.fault_here(StoreFaultPoint::Flush) {
            return Err(poison_after(
                &mut state,
                StoreFaultPoint::Flush,
                injected(StoreFaultPoint::Flush),
            ));
        }
        if let Err(error) = file.flush() {
            return Err(poison_after(&mut state, StoreFaultPoint::Flush, error));
        }
        if self.fault_here(StoreFaultPoint::Sync) {
            return Err(poison_after(
                &mut state,
                StoreFaultPoint::Sync,
                injected(StoreFaultPoint::Sync),
            ));
        }
        if let Err(error) = file.sync_all() {
            return Err(poison_after(&mut state, StoreFaultPoint::Sync, error));
        }
        Ok(())
    }

    /// Load every extension, failing closed on an unsupported version.
    ///
    /// Reading is allowed while the store is poisoned so callers can verify
    /// state before invoking [`EvidenceStore::recover`].
    pub fn load(&self) -> anyhow::Result<Vec<EvidenceExtension>> {
        let _state = self.lock_state();
        read_extensions(&self.path)
    }

    /// Rewrite the store with bound extensions.
    pub fn write_all(&self, extensions: &[EvidenceExtension]) -> anyhow::Result<()> {
        // Validate and serialize before any I/O: these failures cannot leave
        // the live store in an ambiguous state.
        let mut payload = Vec::new();
        for extension in extensions {
            extension.validate()?;
            let line = serde_json::to_string(extension)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;
            payload.extend_from_slice(line.as_bytes());
            payload.push(b'\n');
        }
        let mut state = self.lock_state();
        ensure_writable(&state)?;
        let temporary = self.path.with_extension("tmp");

        if self.fault_here(StoreFaultPoint::Write) {
            return Err(poison_after(
                &mut state,
                StoreFaultPoint::Write,
                injected(StoreFaultPoint::Write),
            ));
        }
        let mut file = File::create(&temporary)
            .map_err(|error| anyhow::anyhow!("create evidence temporary file: {error}"))?;
        if let Err(error) = file.write_all(&payload) {
            return Err(poison_after(&mut state, StoreFaultPoint::Write, error));
        }
        if self.fault_here(StoreFaultPoint::Flush) {
            return Err(poison_after(
                &mut state,
                StoreFaultPoint::Flush,
                injected(StoreFaultPoint::Flush),
            ));
        }
        if let Err(error) = file.flush() {
            return Err(poison_after(&mut state, StoreFaultPoint::Flush, error));
        }
        if self.fault_here(StoreFaultPoint::Sync) {
            return Err(poison_after(
                &mut state,
                StoreFaultPoint::Sync,
                injected(StoreFaultPoint::Sync),
            ));
        }
        if let Err(error) = file.sync_all() {
            return Err(poison_after(&mut state, StoreFaultPoint::Sync, error));
        }
        drop(file);

        if self.fault_here(StoreFaultPoint::Rename) {
            return Err(poison_after(
                &mut state,
                StoreFaultPoint::Rename,
                injected(StoreFaultPoint::Rename),
            ));
        }
        if let Err(error) = std::fs::rename(&temporary, &self.path) {
            return Err(poison_after(&mut state, StoreFaultPoint::Rename, error));
        }

        if self.fault_here(StoreFaultPoint::DirectorySync) {
            return Err(poison_after(
                &mut state,
                StoreFaultPoint::DirectorySync,
                injected(StoreFaultPoint::DirectorySync),
            ));
        }
        if let Err(error) = sync_parent_directory(&self.path) {
            return Err(poison_after(
                &mut state,
                StoreFaultPoint::DirectorySync,
                error,
            ));
        }
        Ok(())
    }
}

/// Journal-side reference used to bind an extension to a stable position.
#[derive(Debug, Clone, PartialEq, Eq)]
struct JournalEvidenceRef {
    source_shard: u16,
    source_replica: u16,
    connection_epoch: u64,
    received_at_us: i64,
    payload_sha256: String,
    position: JournalPosition,
}

struct PositionCollector {
    refs: Vec<JournalEvidenceRef>,
}

impl JournalVisitor for PositionCollector {
    fn visit(&mut self, entry: &crate::integrity::journal::JournalEntry<'_>) -> anyhow::Result<()> {
        if entry.direction != crate::protocol::FrameDirection::Inbound {
            return Ok(());
        }
        self.refs.push(JournalEvidenceRef {
            source_shard: entry.shard,
            source_replica: entry.replica,
            connection_epoch: entry.connection_epoch,
            received_at_us: entry.received_at_us,
            payload_sha256: entry.payload_sha256.clone(),
            position: entry.position.clone(),
        });
        Ok(())
    }
}

/// Result of binding extensions to journal positions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBindReport {
    pub extensions: usize,
    pub journal_records: usize,
    pub bound: usize,
    pub unbound: Vec<String>,
    pub unmatched_journal: usize,
    pub conflicts: Vec<String>,
    pub valid: bool,
}

impl EvidenceBindReport {
    /// Whether journal and extensions form one complete evidence relationship.
    #[must_use]
    pub fn reconciled(&self) -> bool {
        self.valid
            && self.unbound.is_empty()
            && self.conflicts.is_empty()
            && self.unmatched_journal == 0
            && self.bound == self.extensions
    }
}

/// Bind extensions to journal positions and verify their digests.
pub fn bind_and_verify(
    journal_directory: &Path,
    store: &EvidenceStore,
) -> anyhow::Result<EvidenceBindReport> {
    let mut collector = PositionCollector { refs: Vec::new() };
    visit_observations_with_bounded_records(journal_directory, &mut collector)?;
    let mut extensions = store.load()?;
    anyhow::ensure!(
        collector.refs.len() <= MAX_BINDING_ENTRIES && extensions.len() <= MAX_BINDING_ENTRIES,
        "binding workload exceeds the configured entry bound"
    );
    let mut used = vec![false; collector.refs.len()];
    let mut conflicts = Vec::new();
    let mut unbound = Vec::new();
    let mut index: BTreeMap<(u16, u16, u64, i64, String), Vec<usize>> = BTreeMap::new();
    for (position, reference) in collector.refs.iter().enumerate() {
        index
            .entry((
                reference.source_shard,
                reference.source_replica,
                reference.connection_epoch,
                reference.received_at_us,
                reference.payload_sha256.clone(),
            ))
            .or_default()
            .push(position);
    }

    for extension in &mut extensions {
        let key = (
            extension.source_shard,
            extension.source_replica,
            extension.connection_epoch,
            extension.received_at_us,
            extension.payload_sha256.clone(),
        );
        let matches = index.get(&key).map_or(&[][..], Vec::as_slice);
        match matches.len() {
            0 => unbound.push(extension.evidence_id.clone()),
            1 => {
                let index = matches[0];
                if used[index] {
                    conflicts.push(extension.evidence_id.clone());
                    continue;
                }
                used[index] = true;
                extension.position = Some(collector.refs[index].position.clone());
            }
            _ => conflicts.push(extension.evidence_id.clone()),
        }
    }
    let unmatched_journal = used.iter().filter(|was_used| !**was_used).count();
    let bound = extensions
        .iter()
        .filter(|extension| extension.position.is_some())
        .count();
    let report = EvidenceBindReport {
        extensions: extensions.len(),
        journal_records: collector.refs.len(),
        bound,
        unbound,
        unmatched_journal,
        conflicts,
        valid: true,
    };
    if report.reconciled() {
        store.write_all(&extensions)?;
    }
    Ok(report)
}

fn visit_observations_with_bounded_records(
    journal_directory: &Path,
    visitor: &mut impl JournalVisitor,
) -> anyhow::Result<()> {
    let config = JournalStreamConfig {
        max_record_bytes: usize::MAX,
    };
    visit_observations_with_config(journal_directory, &config, visitor)?;
    Ok(())
}

/// Typed canonical record reference passed to a canonical sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalEvidenceRecord {
    pub evidence_id: String,
    pub source: String,
    pub schema_version: u32,
    pub kind: String,
    pub payload_type: String,
    pub payload_digest: String,
}

/// Persistence port for canonical records, kept separate from raw evidence.
pub trait CanonicalSink: Send + Sync {
    /// Persist one canonical record reference.
    fn persist(&self, record: &CanonicalEvidenceRecord) -> anyhow::Result<()>;
}

/// Failure at one processing stage with a machine-readable point.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{point} stage failed: {reason}")]
pub struct StageError {
    pub point: FailurePoint,
    pub reason: String,
}

/// Real decode, normalization and canonical persistence stages.
pub struct ProcessingStages {
    codecs: CodecRegistry,
    sink: Box<dyn CanonicalSink>,
}

impl ProcessingStages {
    /// Construct stages from a codec registry and a canonical sink.
    #[must_use]
    pub fn new(codecs: CodecRegistry, sink: Box<dyn CanonicalSink>) -> Self {
        Self { codecs, sink }
    }

    /// Run decode, typed normalization and canonical persistence.
    pub fn run(
        &self,
        evidence_id: &str,
        source: &str,
        schema_version: u32,
        payload: &[u8],
    ) -> Result<(), StageError> {
        let events = self
            .codecs
            .decode_normalized(evidence_id, source, schema_version, payload)
            .map_err(|error| StageError {
                point: FailurePoint::Decode,
                reason: error.to_string(),
            })?;
        for event in events {
            let typed = event.payload.ok_or_else(|| StageError {
                point: FailurePoint::Normalize,
                reason: "no typed payload for a decoded observation".to_owned(),
            })?;
            let body = serde_json::to_string(&typed.payload).map_err(|error| StageError {
                point: FailurePoint::Normalize,
                reason: error.to_string(),
            })?;
            self.sink
                .persist(&CanonicalEvidenceRecord {
                    evidence_id: evidence_id.to_owned(),
                    source: source.to_owned(),
                    schema_version,
                    kind: event.kind,
                    payload_type: typed.payload_type,
                    payload_digest: sha256_hex(body.as_bytes()),
                })
                .map_err(|error| StageError {
                    point: FailurePoint::CanonicalPersist,
                    reason: error.to_string(),
                })?;
        }
        Ok(())
    }
}

/// Receipt returned for one ingested payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReceipt {
    pub evidence_id: String,
    pub disposition: EvidenceDisposition,
    pub ack: DurabilityAck,
}

/// Receive-sequence state for one source and connection epoch.
///
/// The journal verifier requires receive sequences to start at 1 and remain
/// contiguous per source and epoch. A new epoch is a new map key, so its
/// counter starts from zero independently of the previous connection.
type ReceiveSequences = BTreeMap<(crate::model::SourceId, u64), u64>;

/// Ingestion path that journals raw bytes before persisting their extension.
pub struct EvidencePipeline {
    journal: JournalHandle,
    store: EvidenceStore,
    profile: DurabilityProfile,
    injected_failure: Option<FailurePoint>,
    stages: Option<ProcessingStages>,
    receive_sequences: Mutex<ReceiveSequences>,
    /// Test-only override for the writer acknowledgement deadline. Production
    /// always uses the fixed deadline set in `new`.
    #[cfg(test)]
    ack_timeout: Duration,
}

impl EvidencePipeline {
    /// Construct a pipeline for a locally achievable durability profile.
    pub fn new(
        journal: JournalHandle,
        store: EvidenceStore,
        profile: DurabilityProfile,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            profile.locally_achievable(),
            "profile {} requires replication that is not implemented",
            profile.as_str_label()
        );
        Ok(Self {
            journal,
            store,
            profile,
            injected_failure: None,
            stages: None,
            receive_sequences: Mutex::new(ReceiveSequences::new()),
            #[cfg(test)]
            ack_timeout: Duration::from_secs(5),
        })
    }

    /// Shorten the writer acknowledgement deadline for deterministic timeout
    /// tests. The acknowledgement contract is unchanged; only the wait is.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_ack_timeout(mut self, timeout: Duration) -> Self {
        self.ack_timeout = timeout;
        self
    }

    /// Install real decode, normalization and canonical persistence stages.
    #[must_use]
    pub fn with_stages(mut self, stages: ProcessingStages) -> Self {
        self.stages = Some(stages);
        self
    }

    /// Install a deterministic failure point for tests.
    #[must_use]
    pub fn with_injected_failure(mut self, point: FailurePoint) -> Self {
        self.injected_failure = Some(point);
        self
    }

    /// Return the configured durability profile.
    #[must_use]
    pub const fn profile(&self) -> DurabilityProfile {
        self.profile
    }

    /// Return the current journal status for diagnostics.
    #[must_use]
    pub fn status(&self) -> crate::integrity::journal::JournalStatus {
        self.journal.status()
    }

    /// Finalize the journal so its records can be bound and verified.
    pub fn shutdown(
        self,
        timeout: Duration,
    ) -> anyhow::Result<crate::integrity::journal::JournalSummary> {
        self.journal.shutdown(timeout)
    }

    fn rejected(evidence_id: String, at: FailurePoint, reason: &str) -> EvidenceReceipt {
        EvidenceReceipt {
            evidence_id,
            disposition: EvidenceDisposition::Rejected {
                at,
                reason: reason.to_owned(),
            },
            ack: DurabilityAck::Received,
        }
    }

    /// Ingest one packet through the raw-evidence boundary.
    pub fn ingest(
        &self,
        evidence: &PacketEvidence,
        source: crate::model::SourceId,
        context: &EvidenceContext,
    ) -> EvidenceReceipt {
        let mut extension = EvidenceExtension::from_packet(evidence, source).with_context(context);
        extension.receive_sequence = context.receive_sequence;
        let evidence_id = extension.evidence_id.clone();
        if self.injected_failure == Some(FailurePoint::Receive) {
            return Self::rejected(
                evidence_id,
                FailurePoint::Receive,
                "receive boundary refused",
            );
        }
        if self.injected_failure == Some(FailurePoint::JournalSubmit) {
            return Self::rejected(
                evidence_id,
                FailurePoint::JournalSubmit,
                "journal submission interrupted",
            );
        }
        // The journal verifier requires contiguous receive sequences per source
        // and epoch. Hold the reservation lock across journal submission so the
        // sequence order and the journal's admission order cannot diverge. A
        // new epoch is a new key, so its sequence restarts at one.
        let epoch = evidence.connection_epoch;
        let mut sequences = self
            .receive_sequences
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current = sequences.get(&(source, epoch)).copied().unwrap_or(0);
        let Some(receive_seq) = current.checked_add(1) else {
            return Self::rejected(
                evidence_id,
                FailurePoint::JournalSubmit,
                "receive sequence exhausted for source and connection epoch",
            );
        };
        let record = DataRecord {
            source,
            connection_epoch: epoch,
            receive_seq,
            received_at_us: evidence.received_at_us,
            frame: RawFrame {
                kind: evidence.frame_kind,
                payload: evidence.payload.clone(),
            },
            outcome: DecodeOutcome::ignored("raw_evidence_before_arbitration"),
            signal: SessionSignal::MarketData,
            mechanism: HeartbeatMechanism::Disabled,
        };
        // Derive the journal boundary from the profile's public declaration.
        // There is no second profile-to-level table that could drift from it:
        // a locally achievable profile always declares a waitable boundary,
        // and D4/D5 are refused by `EvidencePipeline::new` before ingest.
        let required = self.profile.required_ack();
        let Some(ack_level) = required.journal_level() else {
            return Self::rejected(
                evidence_id,
                FailurePoint::JournalSubmit,
                "profile declares no local journal acknowledgement boundary",
            );
        };
        #[cfg(test)]
        let ack_deadline = self.ack_timeout;
        #[cfg(not(test))]
        let ack_deadline = Duration::from_secs(5);
        let ack_result = self.journal.record_ack(record, ack_level, ack_deadline);
        // Commit even when acknowledgement failed. The record may already be
        // queued; reusing its sequence would duplicate a journal fence. A
        // record that never reached the journal leaves a gap, and verification
        // then fails closed instead of claiming a complete capture.
        sequences.insert((source, epoch), receive_seq);
        drop(sequences);
        let ack = match ack_result {
            Ok(ack) => ack,
            Err(error) => {
                return Self::rejected(
                    evidence_id,
                    FailurePoint::JournalPersist,
                    &format!("journal acknowledgement failed: {error}"),
                );
            }
        };
        if ack.source != source || ack.connection_epoch != epoch || ack.receive_seq != receive_seq {
            return Self::rejected(
                evidence_id,
                FailurePoint::JournalPersist,
                "acknowledgement does not identify the submitted record",
            );
        }
        extension.journal_ack = Some(ack.clone());
        if self.injected_failure == Some(FailurePoint::JournalPersist) {
            return EvidenceReceipt {
                evidence_id,
                disposition: EvidenceDisposition::Quarantined {
                    at: FailurePoint::JournalPersist,
                    reason: "journal persistence interrupted".to_owned(),
                },
                ack: required,
            };
        }
        if self.injected_failure == Some(FailurePoint::EvidencePersist) {
            return EvidenceReceipt {
                evidence_id,
                disposition: EvidenceDisposition::Quarantined {
                    at: FailurePoint::EvidencePersist,
                    reason: "evidence extension write interrupted".to_owned(),
                },
                ack: required,
            };
        }
        if let Err(error) = self.store.append(&extension) {
            return Self::rejected(
                evidence_id,
                FailurePoint::EvidencePersist,
                &format!("evidence extension write failed: {error}"),
            );
        }
        for point in [
            FailurePoint::Decode,
            FailurePoint::Normalize,
            FailurePoint::CanonicalPersist,
        ] {
            if self.injected_failure == Some(point) {
                return EvidenceReceipt {
                    evidence_id,
                    disposition: EvidenceDisposition::Quarantined {
                        at: point,
                        reason: format!("{point:?} interrupted"),
                    },
                    ack: required,
                };
            }
        }
        if let Some(stages) = &self.stages
            && let Err(error) = stages.run(
                &evidence_id,
                &evidence.source,
                context.source_schema_version,
                &evidence.payload,
            )
        {
            return EvidenceReceipt {
                evidence_id,
                disposition: EvidenceDisposition::Quarantined {
                    at: error.point,
                    reason: error.reason,
                },
                ack: required,
            };
        }
        // `record_ack` returns only after the record reached the fence at the
        // journal level derived from the declared contract, and the identity
        // check above ties that fence to this record. `from_journal_level` is
        // the exact counterpart of `journal_level`, so the reported boundary
        // is anchored both to the writer's level and to the declaration.
        let achieved = DurabilityAck::from_journal_level(ack.level);
        EvidenceReceipt {
            evidence_id,
            disposition: EvidenceDisposition::EvidencePersisted,
            ack: achieved,
        }
    }
}

impl DurabilityProfile {
    /// Return a human-readable profile label for error messages.
    #[must_use]
    pub const fn as_str_label(self) -> &'static str {
        match self {
            Self::D1 => "D1",
            Self::D2 => "D2",
            Self::D3 => "D3",
            Self::D4 => "D4",
            Self::D5 => "D5",
        }
    }
}

/// Reconciliation counts for one evidence path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceLedger {
    pub received: u64,
    pub persisted: u64,
    pub rejected: u64,
    pub quarantined: u64,
}

impl EvidenceLedger {
    /// Record one receipt in the accounting ledger.
    pub fn apply(&mut self, receipt: &EvidenceReceipt) {
        self.received = self.received.saturating_add(1);
        match receipt.disposition {
            EvidenceDisposition::Rejected { .. } => {
                self.rejected = self.rejected.saturating_add(1);
            }
            EvidenceDisposition::Quarantined { .. } => {
                self.quarantined = self.quarantined.saturating_add(1);
            }
            _ => {
                self.persisted = self.persisted.saturating_add(1);
            }
        }
    }

    /// Check the evidence accounting invariant.
    #[must_use]
    pub fn reconciled(&self) -> bool {
        self.received == self.persisted + self.rejected + self.quarantined
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;
    use crate::{
        acquisition::arbiter::FeedChannel,
        integrity::journal::read_records,
        integrity::journal::verify_run,
        integrity::journal::{JournalConfig, JournalMeta, SyncMode},
        model::SourceId,
    };
    fn config(directory: &Path) -> JournalConfig {
        JournalConfig {
            directory: directory.to_path_buf(),
            queue_capacity: 16,
            enqueue_timeout: Duration::from_millis(250),
            flush_interval: Duration::from_millis(10),
            sync_interval: Duration::from_millis(20),
            segment_max_bytes: 0,
            segment_max_seconds: 0,
            sync_mode: SyncMode::Interval,
        }
    }

    fn meta(run_id: &str) -> JournalMeta {
        JournalMeta {
            run_id: run_id.to_owned(),
            venue: "fixture".to_owned(),
            code_commit: "test".to_owned(),
            route: None,
            config_sha256: "test".to_owned(),
        }
    }

    fn evidence(sequence: u64, payload: &[u8]) -> PacketEvidence {
        PacketEvidence::new(
            "fixture",
            FeedChannel::Primary,
            1,
            Some(sequence),
            "fixture-codec",
            payload.to_vec(),
            1_700_000_000_000_000 + sequence as i64,
            "lab",
            "decoder-1",
        )
    }

    #[test]
    fn evidence_id_is_stable_and_conflict_sensitive() {
        let first = evidence(1, b"payload-a");
        let copy = evidence(1, b"payload-a");
        let changed = evidence(1, b"payload-b");
        assert_eq!(
            EvidenceExtension::derive_id(&first, SourceId::new(1, 0)),
            EvidenceExtension::derive_id(&copy, SourceId::new(1, 0)),
            "immutable inputs derive the same id"
        );
        assert_ne!(
            EvidenceExtension::derive_id(&first, SourceId::new(1, 0)),
            EvidenceExtension::derive_id(&changed, SourceId::new(1, 0)),
            "a different payload changes the id"
        );
    }

    #[test]
    fn unsupported_extension_version_fails_closed() {
        let store_path =
            std::env::temp_dir().join(format!("evidence-version-{}", std::process::id()));
        let store = EvidenceStore::new(&store_path, "evidence.jsonl").expect("store created");
        let mut extension = EvidenceExtension::from_packet(&evidence(1, b"x"), SourceId::new(1, 0));
        extension.schema_version = 99;
        assert!(
            store.append(&extension).is_err(),
            "an unsupported version must be refused"
        );
        std::fs::remove_dir_all(&store_path).expect("cleanup");
    }

    #[test]
    fn accounting_invariant_holds_for_all_dispositions() {
        let mut ledger = EvidenceLedger {
            received: 0,
            persisted: 0,
            rejected: 0,
            quarantined: 0,
        };
        for disposition in [
            EvidenceDisposition::EvidencePersisted,
            EvidenceDisposition::Rejected {
                at: FailurePoint::Decode,
                reason: "bad".to_owned(),
            },
            EvidenceDisposition::Quarantined {
                at: FailurePoint::Normalize,
                reason: "uncertain".to_owned(),
            },
        ] {
            ledger.apply(&EvidenceReceipt {
                evidence_id: "ev-1".to_owned(),
                disposition,
                ack: DurabilityAck::Received,
            });
        }
        assert_eq!(ledger.received, 3, "every receipt counted");
        assert!(ledger.reconciled(), "all dispositions accounted");
    }

    #[test]
    fn empty_journal_finalizes() {
        let directory = tempfile::tempdir().expect("tempdir");
        let journal =
            JournalHandle::start(config(directory.path()), meta("empty")).expect("journal started");
        journal
            .shutdown(Duration::from_secs(10))
            .expect("empty journal closed");
    }

    #[test]
    fn extension_binds_to_stable_journal_position() {
        let directory = tempfile::tempdir().expect("tempdir");
        let journal =
            JournalHandle::start(config(directory.path()), meta("run")).expect("journal started");
        let store = EvidenceStore::new(directory.path(), "evidence.jsonl").expect("store created");
        let pipeline = EvidencePipeline::new(journal, store.clone(), DurabilityProfile::D1)
            .expect("pipeline created");
        let packet = evidence(7, b"bound-payload");
        let context = EvidenceContext {
            sequence_domain_id: "fixture-feed".to_owned(),
            source_schema_id: "fixture-schema".to_owned(),
            source_schema_version: 1,
            receive_sequence: 1,
        };
        let receipt = pipeline.ingest(&packet, SourceId::new(3, 1), &context);
        assert_eq!(
            receipt.disposition,
            EvidenceDisposition::EvidencePersisted,
            "raw evidence and extension must both persist"
        );
        let status = pipeline.status();
        assert_ne!(
            status.state,
            crate::integrity::journal::RunState::Failed,
            "journal must stay healthy: {status:?}"
        );
        pipeline
            .shutdown(Duration::from_secs(10))
            .expect("journal closed");
        let report =
            bind_and_verify(&directory.path().join("run"), &store).expect("binding verified");
        assert_eq!(report.bound, 1, "extension bound to one journal record");
        assert!(report.reconciled(), "journal and extension reconcile");
        let extensions = store.load().expect("extensions reload");
        assert!(
            extensions[0].position.is_some(),
            "stable position retained on restart"
        );
    }

    #[test]
    fn replicated_profiles_are_refused_locally() {
        assert!(
            !DurabilityProfile::D4.locally_achievable(),
            "D4 needs replication"
        );
        assert!(
            !DurabilityProfile::D5.locally_achievable(),
            "D5 needs replication"
        );
        assert!(DurabilityProfile::D3.locally_achievable(), "D3 is local");
    }

    #[test]
    fn declared_ack_round_trips_through_the_journal_boundary() {
        for (profile, expected_level) in [
            (DurabilityProfile::D1, Some(JournalAckLevel::Queued)),
            (DurabilityProfile::D2, Some(JournalAckLevel::Flushed)),
            (DurabilityProfile::D3, Some(JournalAckLevel::Synced)),
        ] {
            let declared = profile.required_ack();
            assert_eq!(
                declared.journal_level(),
                expected_level,
                "declared boundary for {profile:?} maps to its journal level"
            );
            let achieved = DurabilityAck::from_journal_level(
                declared
                    .journal_level()
                    .expect("locally achievable profile has a journal level"),
            );
            assert_eq!(
                achieved, declared,
                "declaration and acknowledgement are one mapping for {profile:?}"
            );
        }
        for profile in [DurabilityProfile::D4, DurabilityProfile::D5] {
            assert_eq!(
                profile.required_ack().journal_level(),
                None,
                "replication has no local journal boundary for {profile:?}"
            );
        }
    }

    fn context(sequence: u64) -> EvidenceContext {
        EvidenceContext {
            sequence_domain_id: "fixture-feed".to_owned(),
            source_schema_id: "fixture-schema".to_owned(),
            source_schema_version: 1,
            receive_sequence: sequence,
        }
    }

    fn pipeline_for(directory: &Path, run_id: &str) -> (EvidencePipeline, EvidenceStore) {
        let journal =
            JournalHandle::start(config(directory), meta(run_id)).expect("journal started");
        let store = EvidenceStore::new(directory, "evidence.jsonl").expect("store created");
        let pipeline = EvidencePipeline::new(journal, store.clone(), DurabilityProfile::D1)
            .expect("pipeline created");
        (pipeline, store)
    }

    #[test]
    fn ingest_ack_matches_declared_contract_for_every_profile() {
        for (profile, declared, journal_level) in [
            (
                DurabilityProfile::D1,
                DurabilityAck::Journalled,
                JournalAckLevel::Queued,
            ),
            (
                DurabilityProfile::D2,
                DurabilityAck::Flushed,
                JournalAckLevel::Flushed,
            ),
            (
                DurabilityProfile::D3,
                DurabilityAck::Synced,
                JournalAckLevel::Synced,
            ),
        ] {
            let directory = tempfile::tempdir().expect("tempdir");
            let journal = JournalHandle::start(config(directory.path()), meta("ack-contract"))
                .expect("journal started");
            let store =
                EvidenceStore::new(directory.path(), "evidence.jsonl").expect("store created");
            let pipeline =
                EvidencePipeline::new(journal, store.clone(), profile).expect("pipeline created");
            let receipt = pipeline.ingest(
                &evidence(1, b"ack-contract-payload"),
                SourceId::new(1, 0),
                &context(1),
            );
            assert_eq!(
                receipt.disposition,
                EvidenceDisposition::EvidencePersisted,
                "ingest must persist evidence for {profile:?}"
            );
            assert_eq!(
                profile.required_ack(),
                declared,
                "declared contract for {profile:?}"
            );
            assert_eq!(
                receipt.ack, declared,
                "actual acknowledgement after ingest must equal the declared boundary for {profile:?}"
            );
            assert_eq!(
                receipt.ack,
                profile.required_ack(),
                "achieved acknowledgement must equal the declared contract for {profile:?}"
            );
            let extensions = store.load().expect("extensions reload");
            assert_eq!(extensions.len(), 1, "one extension for {profile:?}");
            let ack = extensions[0]
                .journal_ack
                .as_ref()
                .expect("journal ack recorded on the extension");
            assert_eq!(
                ack.level, journal_level,
                "journal writer boundary for {profile:?}"
            );
            pipeline
                .shutdown(Duration::from_secs(10))
                .expect("journal closed");
        }
    }

    #[test]
    fn ingest_failure_paths_keep_declared_ack_for_every_profile() {
        for profile in [
            DurabilityProfile::D1,
            DurabilityProfile::D2,
            DurabilityProfile::D3,
        ] {
            for point in [
                FailurePoint::JournalPersist,
                FailurePoint::EvidencePersist,
                FailurePoint::Decode,
                FailurePoint::Normalize,
                FailurePoint::CanonicalPersist,
            ] {
                let directory = tempfile::tempdir().expect("tempdir");
                let journal = JournalHandle::start(config(directory.path()), meta("ack-failure"))
                    .expect("journal started");
                let store =
                    EvidenceStore::new(directory.path(), "evidence.jsonl").expect("store created");
                let pipeline = EvidencePipeline::new(journal, store, profile)
                    .expect("pipeline created")
                    .with_injected_failure(point);
                let receipt = pipeline.ingest(
                    &evidence(1, b"quarantine-payload"),
                    SourceId::new(1, 0),
                    &context(1),
                );
                assert!(
                    matches!(
                        receipt.disposition,
                        EvidenceDisposition::Quarantined { at, .. } if at == point
                    ),
                    "an injected {point:?} must quarantine for {profile:?}"
                );
                assert_eq!(
                    receipt.ack,
                    profile.required_ack(),
                    "quarantine after journal acknowledgement must still report the achieved boundary for {profile:?}/{point:?}"
                );
                pipeline
                    .shutdown(Duration::from_secs(10))
                    .expect("journal closed");
            }
        }
    }

    #[test]
    fn ingest_rejection_paths_claim_no_durability_for_every_profile() {
        for profile in [
            DurabilityProfile::D1,
            DurabilityProfile::D2,
            DurabilityProfile::D3,
        ] {
            for point in [FailurePoint::Receive, FailurePoint::JournalSubmit] {
                let directory = tempfile::tempdir().expect("tempdir");
                let journal = JournalHandle::start(config(directory.path()), meta("ack-rejected"))
                    .expect("journal started");
                let store =
                    EvidenceStore::new(directory.path(), "evidence.jsonl").expect("store created");
                let pipeline = EvidencePipeline::new(journal, store, profile)
                    .expect("pipeline created")
                    .with_injected_failure(point);
                let receipt = pipeline.ingest(
                    &evidence(1, b"rejected-payload"),
                    SourceId::new(1, 0),
                    &context(1),
                );
                assert!(
                    matches!(
                        receipt.disposition,
                        EvidenceDisposition::Rejected { at, .. } if at == point
                    ),
                    "an injected {point:?} must reject for {profile:?}"
                );
                assert_eq!(
                    receipt.ack,
                    DurabilityAck::Received,
                    "a rejected record claims no durability for {profile:?}/{point:?}"
                );
                assert_eq!(
                    pipeline.status().counters.queued,
                    0,
                    "a rejected record was never admitted for {profile:?}/{point:?}"
                );
                pipeline
                    .shutdown(Duration::from_secs(10))
                    .expect("journal closed");
            }
        }
    }

    #[test]
    fn ingest_ack_timeout_never_over_reports_durability() {
        for (profile, immediate) in [
            (DurabilityProfile::D1, Some(DurabilityAck::Journalled)),
            (DurabilityProfile::D2, None),
            (DurabilityProfile::D3, None),
        ] {
            let directory = tempfile::tempdir().expect("tempdir");
            let mut journal_config = config(directory.path());
            journal_config.flush_interval = Duration::from_secs(60);
            journal_config.sync_interval = Duration::from_secs(60);
            let journal =
                JournalHandle::start(journal_config, meta("ack-timeout")).expect("journal started");
            let store =
                EvidenceStore::new(directory.path(), "evidence.jsonl").expect("store created");
            let pipeline = EvidencePipeline::new(journal, store, profile)
                .expect("pipeline created")
                .with_ack_timeout(Duration::from_millis(100));
            let receipt = pipeline.ingest(
                &evidence(1, b"timeout-payload"),
                SourceId::new(1, 0),
                &context(1),
            );
            match immediate {
                Some(ack) => {
                    assert_eq!(
                        receipt.disposition,
                        EvidenceDisposition::EvidencePersisted,
                        "queue admission needs no flush for {profile:?}"
                    );
                    assert_eq!(
                        receipt.ack, ack,
                        "the declared boundary is reached immediately for {profile:?}"
                    );
                }
                None => {
                    assert!(
                        matches!(
                            receipt.disposition,
                            EvidenceDisposition::Rejected {
                                at: FailurePoint::JournalPersist,
                                ..
                            }
                        ),
                        "an unreached declared boundary must be rejected for {profile:?}"
                    );
                    assert_eq!(
                        receipt.ack,
                        DurabilityAck::Received,
                        "a timed-out acknowledgement claims no durability for {profile:?}"
                    );
                }
            }
            assert_eq!(
                pipeline.status().counters.queued,
                1,
                "the record was admitted before the acknowledgement wait for {profile:?}"
            );
            pipeline
                .shutdown(Duration::from_secs(10))
                .expect("journal closed");
        }
    }

    #[test]
    fn two_sources_get_independent_contiguous_receive_sequences() {
        let directory = tempfile::tempdir().expect("tempdir");
        let (pipeline, store) = pipeline_for(directory.path(), "two-sources");
        for sequence in 1..=3u64 {
            let current = context(sequence);
            for source in [SourceId::new(0, 0), SourceId::new(0, 1)] {
                let packet = evidence(sequence, format!("{source}-{sequence}").as_bytes());
                let receipt = pipeline.ingest(&packet, source, &current);
                assert_eq!(
                    receipt.disposition,
                    EvidenceDisposition::EvidencePersisted,
                    "both sources must persist evidence"
                );
            }
        }
        let summary = pipeline
            .shutdown(Duration::from_secs(10))
            .expect("journal closed");
        let run_directory = Path::new(&summary.run_directory);
        let records = read_records(run_directory).expect("records");
        for source in ["s0r0", "s0r1"] {
            let received: Vec<_> = records
                .iter()
                .filter(|record| record.source == source)
                .map(|record| record.receive_seq)
                .collect();
            assert_eq!(received, vec![1, 2, 3], "per-source receive sequence");
        }
        let verification = verify_run(run_directory).expect("verify");
        if !verification.complete {
            eprintln!("journal verification errors: {:?}", verification.errors);
        }
        assert!(verification.complete, "journal verification incomplete");
        let extensions = store.load().expect("extensions reload");
        let contexts: Vec<_> = extensions
            .iter()
            .map(|extension| extension.receive_sequence)
            .collect();
        assert_eq!(
            contexts,
            vec![1, 1, 2, 2, 3, 3],
            "context semantics retained"
        );
    }

    #[test]
    fn new_connection_epoch_resets_the_receive_sequence() {
        let directory = tempfile::tempdir().expect("tempdir");
        let (pipeline, _store) = pipeline_for(directory.path(), "new-epoch");
        let source = SourceId::new(0, 0);
        let mut first = evidence(1, b"epoch-1-first");
        let mut second = evidence(2, b"epoch-1-second");
        let mut third = evidence(3, b"epoch-2-first");
        let mut fourth = evidence(4, b"epoch-2-second");
        first.connection_epoch = 1;
        second.connection_epoch = 1;
        third.connection_epoch = 2;
        fourth.connection_epoch = 2;
        for (index, packet) in [&first, &second, &third, &fourth].into_iter().enumerate() {
            let receipt = pipeline.ingest(packet, source, &context(index as u64 + 1));
            assert_eq!(
                receipt.disposition,
                EvidenceDisposition::EvidencePersisted,
                "each epoch must persist evidence"
            );
        }
        let summary = pipeline
            .shutdown(Duration::from_secs(10))
            .expect("journal closed");
        let run_directory = Path::new(&summary.run_directory);
        let records = read_records(run_directory).expect("records");
        let identity: Vec<_> = records
            .iter()
            .map(|record| (record.connection_epoch, record.receive_seq))
            .collect();
        assert_eq!(
            identity,
            vec![(1, 1), (1, 2), (2, 1), (2, 2)],
            "receive sequence restarts at one for a new epoch"
        );
        let verification = verify_run(run_directory).expect("verify");
        if !verification.complete {
            eprintln!("journal verification errors: {:?}", verification.errors);
        }
        assert!(verification.complete, "journal verification incomplete");
    }

    #[test]
    fn concurrent_ingest_for_one_source_epoch_is_contiguous() {
        const WORKERS: u64 = 8;
        let directory = tempfile::tempdir().expect("tempdir");
        let (pipeline, store) = pipeline_for(directory.path(), "concurrent-source");
        let pipeline = Arc::new(pipeline);
        let barrier = Arc::new(Barrier::new(WORKERS as usize));
        let source = SourceId::new(0, 0);
        let workers: Vec<_> = (1..=WORKERS)
            .map(|sequence| {
                let pipeline = Arc::clone(&pipeline);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    let packet = evidence(sequence, format!("concurrent-{sequence}").as_bytes());
                    pipeline.ingest(&packet, source, &context(sequence))
                })
            })
            .collect();
        for worker in workers {
            let receipt = worker.join().expect("worker joined");
            assert_eq!(
                receipt.disposition,
                EvidenceDisposition::EvidencePersisted,
                "all concurrent ingests must persist"
            );
        }
        let pipeline = Arc::try_unwrap(pipeline).unwrap_or_else(|_| panic!("sole pipeline owner"));
        let summary = pipeline
            .shutdown(Duration::from_secs(10))
            .expect("journal closed");
        let run_directory = Path::new(&summary.run_directory);
        let records = read_records(run_directory).expect("records");
        let mut sequences: Vec<_> = records.iter().map(|record| record.receive_seq).collect();
        sequences.sort_unstable();
        assert_eq!(
            sequences,
            (1..=WORKERS).collect::<Vec<_>>(),
            "concurrent admissions receive a contiguous range"
        );
        let verification = verify_run(run_directory).expect("verify");
        if !verification.complete {
            eprintln!("journal verification errors: {:?}", verification.errors);
        }
        assert!(verification.complete, "journal verification incomplete");
        let extensions = store.load().expect("extensions reload");
        assert_eq!(
            extensions.len(),
            WORKERS as usize,
            "one extension per packet"
        );
    }

    #[test]
    fn receive_sequence_exhaustion_fails_closed() {
        let directory = tempfile::tempdir().expect("tempdir");
        let (pipeline, store) = pipeline_for(directory.path(), "exhausted");
        let source = SourceId::new(0, 0);
        {
            let mut sequences = pipeline.receive_sequences.lock().expect("sequencer lock");
            sequences.insert((source, 1), u64::MAX);
        }
        let receipt = pipeline.ingest(&evidence(1, b"exhausted"), source, &context(1));
        assert!(
            matches!(
                receipt.disposition,
                EvidenceDisposition::Rejected {
                    at: FailurePoint::JournalSubmit,
                    ..
                }
            ),
            "exhaustion must reject before submission"
        );
        assert_eq!(
            receipt.ack,
            DurabilityAck::Received,
            "no durability is claimed on exhaustion"
        );
        assert_eq!(
            pipeline.status().counters.queued,
            0,
            "no record was submitted"
        );
        let summary = pipeline
            .shutdown(Duration::from_secs(10))
            .expect("journal closed");
        assert_eq!(summary.record_count, 0, "exhaustion wrote no record");
        assert!(
            store.load().expect("extensions reload").is_empty(),
            "exhaustion wrote no extension"
        );
    }

    #[test]
    fn interrupted_journal_submission_never_reports_success() {
        let directory = tempfile::tempdir().expect("tempdir");
        let (journal, _store) = pipeline_for(directory.path(), "submit-interrupted");
        let pipeline = journal.with_injected_failure(FailurePoint::JournalSubmit);
        let source = SourceId::new(0, 0);
        let receipt = pipeline.ingest(&evidence(1, b"interrupted"), source, &context(1));
        assert!(
            matches!(
                receipt.disposition,
                EvidenceDisposition::Rejected {
                    at: FailurePoint::JournalSubmit,
                    ..
                }
            ),
            "an interrupted submission must be rejected"
        );
        assert_eq!(
            receipt.ack,
            DurabilityAck::Received,
            "no acknowledgement is claimed"
        );
        let summary = pipeline
            .shutdown(Duration::from_secs(10))
            .expect("journal closed");
        assert_eq!(summary.record_count, 0, "nothing was admitted");
    }

    #[test]
    fn interrupted_persistence_never_reports_success() {
        let directory = tempfile::tempdir().expect("tempdir");
        let (journal, store) = pipeline_for(directory.path(), "persist-interrupted");
        let pipeline = journal.with_injected_failure(FailurePoint::JournalPersist);
        let source = SourceId::new(0, 0);
        let receipt = pipeline.ingest(&evidence(1, b"quarantined"), source, &context(1));
        assert!(
            matches!(
                receipt.disposition,
                EvidenceDisposition::Quarantined {
                    at: FailurePoint::JournalPersist,
                    ..
                }
            ),
            "an interrupted persistence must be quarantined"
        );
        assert!(
            store.load().expect("extensions reload").is_empty(),
            "no extension was persisted"
        );
        let summary = pipeline
            .shutdown(Duration::from_secs(10))
            .expect("journal closed");
        assert_eq!(summary.record_count, 1, "the raw frame remains journaled");
    }

    fn extension(sequence: u64, payload: &[u8]) -> EvidenceExtension {
        EvidenceExtension::from_packet(&evidence(sequence, payload), SourceId::new(1, 0))
    }

    fn reopen(directory: &Path) -> (EvidenceStore, Vec<EvidenceExtension>) {
        let store = EvidenceStore::new(directory, "evidence.jsonl").expect("store reopened");
        let extensions = store.load().expect("reopened store loads");
        (store, extensions)
    }

    fn ids(extensions: &[EvidenceExtension]) -> Vec<String> {
        extensions
            .iter()
            .map(|extension| extension.evidence_id.clone())
            .collect()
    }

    #[test]
    fn injected_append_faults_poison_until_recovery() {
        let first = extension(1, b"first");
        let second = extension(2, b"second");
        let third = extension(3, b"third");
        for point in [
            StoreFaultPoint::Write,
            StoreFaultPoint::Flush,
            StoreFaultPoint::Sync,
        ] {
            let directory = tempfile::tempdir().expect("tempdir");
            let store =
                EvidenceStore::new(directory.path(), "evidence.jsonl").expect("store created");
            store.append(&first).expect("seed append");
            store.clone().with_injected_fault(point);

            let error = store.append(&second).expect_err("injected append fault");
            assert!(
                error.to_string().contains(point.as_str()),
                "error names the failing boundary: {error}"
            );
            assert!(store.is_poisoned(), "{point:?} must poison the store");
            assert!(
                store.append(&third).is_err(),
                "a poisoned store must refuse appends"
            );

            let (reopened, loaded) = reopen(directory.path());
            assert!(reopened.is_poisoned(), "poison follows the store path");
            let expected = match point {
                StoreFaultPoint::Write => vec![first.evidence_id.clone()],
                StoreFaultPoint::Flush | StoreFaultPoint::Sync => {
                    vec![first.evidence_id.clone(), second.evidence_id.clone()]
                }
                StoreFaultPoint::Rename | StoreFaultPoint::DirectorySync => Vec::new(),
            };
            assert_eq!(
                ids(&loaded),
                expected,
                "reopened state matches the injected boundary"
            );

            reopened
                .recover()
                .expect("recovery verifies the reopened state");
            assert!(
                !reopened.is_poisoned(),
                "recovery clears poison after verification"
            );
            reopened.append(&third).expect("append after recovery");
            let (_, after) = reopen(directory.path());
            assert!(
                ids(&after).contains(&third.evidence_id),
                "replayed append is visible after recovery"
            );
        }
    }

    #[test]
    fn injected_replacement_faults_poison_until_recovery() {
        let first = extension(1, b"first");
        let second = extension(2, b"second");
        for point in [
            StoreFaultPoint::Write,
            StoreFaultPoint::Flush,
            StoreFaultPoint::Sync,
            StoreFaultPoint::Rename,
            StoreFaultPoint::DirectorySync,
        ] {
            let directory = tempfile::tempdir().expect("tempdir");
            let store =
                EvidenceStore::new(directory.path(), "evidence.jsonl").expect("store created");
            store.append(&first).expect("seed append");
            store.clone().with_injected_fault(point);

            let error = store
                .write_all(std::slice::from_ref(&second))
                .expect_err("injected replacement fault");
            assert!(
                error.to_string().contains(point.as_str()),
                "error names the failing boundary: {error}"
            );
            assert!(store.is_poisoned(), "{point:?} must poison the store");
            assert!(
                store.write_all(std::slice::from_ref(&second)).is_err(),
                "a poisoned store must refuse replacement"
            );

            let (reopened, loaded) = reopen(directory.path());
            assert!(reopened.is_poisoned(), "poison follows the store path");
            // A directory-sync fault happens after the rename; every earlier
            // boundary leaves the previous file in place.
            let expected = match point {
                StoreFaultPoint::DirectorySync => vec![second.evidence_id.clone()],
                StoreFaultPoint::Write
                | StoreFaultPoint::Flush
                | StoreFaultPoint::Sync
                | StoreFaultPoint::Rename => vec![first.evidence_id.clone()],
            };
            assert_eq!(
                ids(&loaded),
                expected,
                "{point:?}: a replacement never partially applies"
            );

            reopened
                .recover()
                .expect("recovery verifies the reopened state");
            assert!(
                !reopened.is_poisoned(),
                "recovery clears poison after verification"
            );
            reopened
                .write_all(std::slice::from_ref(&second))
                .expect("replacement after recovery");
            let (_, after) = reopen(directory.path());
            assert_eq!(
                ids(&after),
                vec![second.evidence_id.clone()],
                "replacement replayed after recovery"
            );
        }
    }

    #[test]
    fn independent_handles_share_serialized_writer_and_poison() {
        let directory = tempfile::tempdir().expect("tempdir");
        let writer = EvidenceStore::new(directory.path(), "evidence.jsonl").expect("first handle");
        let observer =
            EvidenceStore::new(directory.path(), "evidence.jsonl").expect("second handle");
        let extension = extension(1, b"shared");

        observer.clone().with_injected_fault(StoreFaultPoint::Write);
        assert!(
            observer.append(&extension).is_err(),
            "an interrupted write on one handle fails"
        );
        assert!(writer.is_poisoned(), "peer observes poison");
        assert!(observer.is_poisoned(), "both handles share poison state");

        let (reopened, loaded) = reopen(directory.path());
        assert!(
            loaded.is_empty(),
            "no bytes are written before an injected write fault"
        );
        observer.recover().expect("peer recovers shared state");
        assert!(
            !writer.is_poisoned(),
            "recovery on any handle clears shared poison"
        );
        writer
            .append(&extension)
            .expect("write after peer recovery");
        let (_, after) = reopen(directory.path());
        assert_eq!(
            ids(&after),
            vec![extension.evidence_id.clone()],
            "the shared writer resumes after recovery"
        );
        assert!(
            reopened.path() == writer.path(),
            "reopened handle addresses the same store file"
        );
    }
}
