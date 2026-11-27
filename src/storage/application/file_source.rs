//! Streaming file source with bounded I/O buffers (Platform P6).
//!
//! This is a second source implementation for the non-market-data reference
//! application. Unlike the in-memory `JsonlSource`, it reads a `BufRead` one
//! physical line at a time through a fixed-capacity buffer, retains the exact
//! bytes of each line, and reports the physical byte offset of every line. A
//! SHA-256 fingerprint of the complete source bytes is computed once with a
//! fixed-size read buffer, before streaming, so a resume anchor can be bound to
//! the exact content that was originally read. Exact duplicate-id detection
//! uses a bounded-memory, disk-backed hash index: the in-memory state is a
//! fixed-size bucket-head table, and entry chains live in a scratch file that
//! is removed when the source is dropped. No probabilistic filter is used, so
//! a duplicate is reported only after the full identifier matches.
//!
//! No clock, randomness or network is read. The scratch directory comes from
//! the platform temporary directory; apart from that the module imports only
//! the generic application contract, the opaque identity newtype and the
//! standard library plus `serde`/`sha2`. It does not depend on any market-data
//! module or on any storage implementation.

use std::{
    collections::BTreeMap,
    fmt::Write as FmtWrite,
    io::{BufRead, Read, Seek, SeekFrom, Write as IoWrite},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    application::{JSONL_SCHEMA_VERSION, RawObservation, SourceAdapter, SourceError},
    identity::OpaqueId,
};

/// Schema version of the recorded source identity and resume anchor.
pub const FILE_SCHEMA_VERSION: u32 = 1;

/// Hard cap on one physical line. The reader's reusable buffer never grows
/// beyond this bound plus the single line delimiter, so each physical line
/// is processed with a bounded reusable buffer. Duplicate-id state is separate.
pub const MAX_LINE_BYTES: usize = 1 << 20;

/// Fixed read size used to fingerprint a file without loading it into memory.
const FINGERPRINT_BUFFER_BYTES: usize = 64 * 1024;

/// Number of hash buckets. The in-memory head table is fixed at this size, so
/// duplicate state never grows with the number of unique record identifiers.
/// Longer chains cost bounded sequential reads from the scratch file.
const DUPLICATE_BUCKETS: usize = 1 << 18;

/// Bytes in one overflow entry header: next offset, first line, hash, id len.
const DUPLICATE_HEADER_BYTES: usize = 28;

static DUPLICATE_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn le_u64(bytes: &[u8]) -> Result<u64, std::io::Error> {
    let array: [u8; 8] = bytes.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "short duplicate-index entry",
        )
    })?;
    Ok(u64::from_le_bytes(array))
}

fn le_u32(bytes: &[u8]) -> Result<u32, std::io::Error> {
    let array: [u8; 4] = bytes.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "short duplicate-index entry",
        )
    })?;
    Ok(u32::from_le_bytes(array))
}

/// Deterministic FNV-1a hash. Only the bucket choice uses it; identity is
/// always confirmed by comparing the full stored identifier, so a collision
/// cannot produce a false duplicate.
fn duplicate_hash(id: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3_u64);
    }
    hash
}

/// Exact duplicate-id index with constant in-memory state.
///
/// Bucket heads are held in a fixed array. Entries are appended to one scratch
/// file as `(next, first_line, hash, id_len, id_bytes)` records. Lookup follows
/// the chain and compares the complete identifier, so the result is exact.
/// The scratch file is created on first write and removed on drop.
#[derive(Debug)]
struct DuplicateIndex {
    heads: Vec<u64>,
    overflow: Option<std::fs::File>,
    path: Option<PathBuf>,
}

impl Default for DuplicateIndex {
    fn default() -> Self {
        Self::with_buckets(DUPLICATE_BUCKETS)
    }
}

impl DuplicateIndex {
    fn with_buckets(buckets: usize) -> Self {
        Self {
            heads: vec![u64::MAX; buckets.max(1)],
            overflow: None,
            path: None,
        }
    }

    fn ensure_open(&mut self) -> Result<&mut std::fs::File, std::io::Error> {
        if self.overflow.is_none() {
            let unique = DUPLICATE_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fieldbook-duplicate-index-{}-{unique}",
                std::process::id()
            ));
            let file = std::fs::OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&path)?;
            self.overflow = Some(file);
            self.path = Some(path);
        }
        self.overflow
            .as_mut()
            .ok_or_else(|| std::io::Error::other("index not open"))
    }

    /// Return the first line of `id`, or `None` when it has not been seen.
    fn lookup(&mut self, id: &str) -> Result<Option<usize>, std::io::Error> {
        let Some(file) = self.overflow.as_mut() else {
            return Ok(None);
        };
        let hash = duplicate_hash(id);
        let bucket = (hash as usize) % self.heads.len();
        let mut offset = self.heads[bucket];
        let mut header = [0_u8; DUPLICATE_HEADER_BYTES];
        while offset != u64::MAX {
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut header)?;
            let next = le_u64(&header[0..8])?;
            let line = le_u64(&header[8..16])?;
            let stored_hash = le_u64(&header[16..24])?;
            let length = le_u32(&header[24..28])? as usize;
            let mut stored = vec![0_u8; length];
            file.read_exact(&mut stored)?;
            if stored_hash == hash && stored == id.as_bytes() {
                return usize::try_from(line).map(Some).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "line overflow")
                });
            }
            offset = next;
        }
        Ok(None)
    }

    /// Record `id` at `line`. Insertion is append-only and O(1) memory.
    fn insert(&mut self, id: &str, line: usize) -> Result<(), std::io::Error> {
        let hash = duplicate_hash(id);
        let bucket = (hash as usize) % self.heads.len();
        let head = self.heads[bucket];
        let file = self.ensure_open()?;
        let offset = file.stream_position()?;
        let mut header = Vec::with_capacity(DUPLICATE_HEADER_BYTES);
        header.extend_from_slice(&head.to_le_bytes());
        header.extend_from_slice(&(line as u64).to_le_bytes());
        header.extend_from_slice(&hash.to_le_bytes());
        header.extend_from_slice(&(id.len() as u32).to_le_bytes());
        file.write_all(&header)?;
        file.write_all(id.as_bytes())?;
        self.heads[bucket] = offset;
        Ok(())
    }

    /// Fixed in-memory footprint, exposed for a regression test.
    #[cfg(test)]
    fn memory_bytes(&self) -> usize {
        self.heads.len() * size_of::<u64>()
    }
}

impl Drop for DuplicateIndex {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// SHA-256 of the complete bytes of a source, computed once before streaming.
/// The text form is `sha256:<64 lowercase hex digits>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SourceFingerprint(String);

impl SourceFingerprint {
    #[must_use]
    pub fn compute(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        Self::from_digest(&digest)
    }

    /// Hash a reader using a fixed-size buffer. Interrupted reads are retried;
    /// every other I/O error is returned without producing a partial digest.
    pub fn compute_reader<R: Read>(reader: &mut R) -> Result<Self, std::io::Error> {
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; FINGERPRINT_BUFFER_BYTES];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => hasher.update(&buffer[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        let digest = hasher.finalize();
        Ok(Self::from_digest(&digest))
    }

    fn from_digest(digest: &[u8]) -> Self {
        let mut text = String::with_capacity("sha256:".len() + digest.len() * 2);
        let _ = FmtWrite::write_str(&mut text, "sha256:");
        for byte in digest {
            // Writing into a String cannot fail; the guarded branch keeps this
            // total without `unwrap` in non-test code.
            if FmtWrite::write_fmt(&mut text, format_args!("{byte:02x}")).is_err() {
                return Self(String::new());
            }
        }
        Self(text)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Registered identity of a streaming source. The id is derived from the
/// registration name only; the fingerprint is derived from the exact bytes.
/// A changed file keeps the same registered id but gets a new fingerprint,
/// which is what makes a stale resume anchor detectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceIdentity {
    pub name: String,
    pub source_id: OpaqueId,
    pub fingerprint: SourceFingerprint,
}

impl SourceIdentity {
    #[must_use]
    pub fn register(name: &str, bytes: &[u8]) -> Self {
        Self::register_with_fingerprint(name, SourceFingerprint::compute(bytes))
    }

    /// Register a network source from an operator-declared stream token. The
    /// token is a content identity, not a whole-stream hash; a resume anchor
    /// binds to it rather than claiming completeness of a live stream.
    #[must_use]
    pub fn register_token(name: &str, token: &str) -> Self {
        Self::register_with_fingerprint(name, SourceFingerprint::compute(token.as_bytes()))
    }

    fn register_with_fingerprint(name: &str, fingerprint: SourceFingerprint) -> Self {
        Self {
            name: name.to_owned(),
            source_id: OpaqueId::derive("jsonl", "file-source", "registered", name),
            fingerprint,
        }
    }

    #[must_use]
    pub const fn source_id(&self) -> &OpaqueId {
        &self.source_id
    }

    #[must_use]
    pub const fn fingerprint(&self) -> &SourceFingerprint {
        &self.fingerprint
    }
}

/// Explicit registry of named sources. Registration is deterministic: the
/// same name and bytes always yield the same identity.
#[derive(Debug, Default)]
pub struct SourceRegistry {
    by_name: BTreeMap<String, SourceIdentity>,
}

impl SourceRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a source once. A later registration of the same name returns
    /// the original identity, so registration cannot silently rebind an id.
    pub fn register(&mut self, name: &str, bytes: &[u8]) -> &SourceIdentity {
        let identity = SourceIdentity::register(name, bytes);
        self.by_name.entry(name.to_owned()).or_insert(identity)
    }

    #[must_use]
    pub fn resolve(&self, name: &str) -> Option<&SourceIdentity> {
        self.by_name.get(name)
    }
}

/// The three values a durable checkpoint is bound to: source identity,
/// source fingerprint and target identity. A mismatch on any field invalidates
/// a resume anchor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointBinding {
    pub source_id: String,
    pub source_fingerprint: String,
    pub target_id: String,
}

impl CheckpointBinding {
    #[must_use]
    pub fn new(identity: &SourceIdentity, target_id: &str) -> Self {
        Self {
            source_id: identity.source_id.as_str().to_owned(),
            source_fingerprint: identity.fingerprint.as_str().to_owned(),
            target_id: target_id.to_owned(),
        }
    }

    #[must_use]
    pub fn matches(&self, identity: &SourceIdentity, target_id: &str) -> bool {
        self.source_id == identity.source_id.as_str()
            && self.source_fingerprint == identity.fingerprint.as_str()
            && self.target_id == target_id
    }
}

/// Durable resume anchor. It records the last terminal sequence, its line and
/// its physical byte offset, together with the binding that proves which
/// source bytes and which target it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableCheckpoint {
    pub schema_version: u32,
    pub source_id: String,
    pub source_fingerprint: String,
    pub target_id: String,
    pub last_committed_sequence: u64,
    pub last_committed_line: usize,
    pub last_committed_offset: u64,
}

impl DurableCheckpoint {
    /// Initial anchor for a fresh import of the bound source/target pair.
    #[must_use]
    pub fn new(binding: &CheckpointBinding) -> Self {
        Self {
            schema_version: FILE_SCHEMA_VERSION,
            source_id: binding.source_id.clone(),
            source_fingerprint: binding.source_fingerprint.clone(),
            target_id: binding.target_id.clone(),
            last_committed_sequence: 0,
            last_committed_line: 0,
            last_committed_offset: 0,
        }
    }

    /// Advance an anchor to a newly terminal sequence and physical offset.
    #[must_use]
    pub fn advanced(self, sequence: u64, offset: u64) -> Self {
        Self {
            last_committed_sequence: sequence,
            last_committed_line: sequence as usize,
            last_committed_offset: offset,
            ..self
        }
    }

    #[must_use]
    pub fn binding(&self) -> CheckpointBinding {
        CheckpointBinding {
            source_id: self.source_id.clone(),
            source_fingerprint: self.source_fingerprint.clone(),
            target_id: self.target_id.clone(),
        }
    }

    /// Fail-closed verification before this anchor may be used to resume.
    pub fn verify_against(
        &self,
        identity: &SourceIdentity,
        target_id: &str,
    ) -> Result<(), ResumeError> {
        if self.schema_version != FILE_SCHEMA_VERSION {
            return Err(ResumeError::UnsupportedSchemaVersion {
                found: self.schema_version,
                expected: FILE_SCHEMA_VERSION,
            });
        }
        if self.source_id != identity.source_id.as_str() {
            return Err(ResumeError::SourceIdentityMismatch {
                expected: self.source_id.clone(),
                found: identity.source_id.as_str().to_owned(),
            });
        }
        if self.source_fingerprint != identity.fingerprint.as_str() {
            return Err(ResumeError::FingerprintMismatch {
                expected: self.source_fingerprint.clone(),
                found: identity.fingerprint.as_str().to_owned(),
            });
        }
        if self.target_id != target_id {
            return Err(ResumeError::TargetMismatch {
                expected: self.target_id.clone(),
                found: target_id.to_owned(),
            });
        }
        Ok(())
    }
}

/// Fail-closed reasons a resume anchor is refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ResumeError {
    #[error("resume anchor schema version {found} is unsupported (expected {expected})")]
    UnsupportedSchemaVersion { found: u32, expected: u32 },
    #[error("resume anchor source id {expected} does not match registered id {found}")]
    SourceIdentityMismatch { expected: String, found: String },
    #[error("resume anchor fingerprint {expected} does not match current bytes {found}")]
    FingerprintMismatch { expected: String, found: String },
    #[error("resume anchor target {expected} does not match current target {found}")]
    TargetMismatch { expected: String, found: String },
}

/// Explicit reference to the checkpoint that precedes a stream checkpoint.
pub const GENESIS_CHECKPOINT: &str = "genesis";

/// Schema version of the extended stream checkpoint binding.
pub const STREAM_CHECKPOINT_SCHEMA_VERSION: u32 = 1;

/// One ordered mutation in a replayable journal. Sequences and physical offsets
/// are supplied explicitly so restoration can refuse a non-contiguous tail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEvent {
    pub sequence: u64,
    pub offset: u64,
    pub mutation: Mutation,
}

/// Mutation carried by one journal event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Mutation {
    Put { key: String, value: i64 },
    Delete { key: String },
    NoOp,
}

/// Complete deterministic state reconstructed from a journal prefix.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReplayedState {
    pub values: BTreeMap<String, i64>,
    pub applied: Vec<u64>,
    pub last_offset: u64,
}

impl ReplayedState {
    /// Apply one ordered event, refusing a gap or a non-advancing offset.
    fn apply(&mut self, event: &JournalEvent) -> Result<(), ReplayError> {
        let previous = self.applied.last().copied();
        if previous.is_some_and(|last| event.sequence != last.saturating_add(1)) {
            return Err(ReplayError::NonContiguous {
                expected: previous.map(|last| last.saturating_add(1)),
                found: event.sequence,
            });
        }
        if event.offset <= self.last_offset {
            return Err(ReplayError::OffsetNotAdvancing {
                previous: self.last_offset,
                found: event.offset,
            });
        }
        match &event.mutation {
            Mutation::Put { key, value } => {
                let _ = self.values.insert(key.clone(), *value);
            }
            Mutation::Delete { key } => {
                let _ = self.values.remove(key);
            }
            Mutation::NoOp => {}
        }
        self.applied.push(event.sequence);
        self.last_offset = event.offset;
        Ok(())
    }

    /// Stable digest over every reconstructed field.
    pub fn digest(&self) -> String {
        let mut text = String::new();
        let _ = FmtWrite::write_fmt(&mut text, format_args!("offset:{};", self.last_offset));
        for (key, value) in &self.values {
            let _ = FmtWrite::write_fmt(&mut text, format_args!("{key}={value};"));
        }
        for sequence in &self.applied {
            let _ = FmtWrite::write_fmt(&mut text, format_args!("seq:{sequence};"));
        }
        SourceFingerprint::compute(text.as_bytes())
            .as_str()
            .to_owned()
    }
}

/// Fail-closed reason a journal replay was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReplayError {
    #[error("journal sequence {found} is not contiguous after {expected:?}")]
    NonContiguous { expected: Option<u64>, found: u64 },
    #[error("journal offset {found} does not advance past {previous}")]
    OffsetNotAdvancing { previous: u64, found: u64 },
    #[error("journal replay interrupted at event {at}")]
    Interrupted { at: usize },
}

fn apply_events(
    state: &mut ReplayedState,
    events: &[JournalEvent],
    interrupt_at: Option<usize>,
) -> Result<(), ReplayError> {
    for (index, event) in events.iter().enumerate() {
        if interrupt_at == Some(index) {
            return Err(ReplayError::Interrupted { at: index });
        }
        state.apply(event)?;
    }
    Ok(())
}

/// Deterministic digest of a journal head over sequence, offset and mutation.
#[must_use]
pub fn journal_head_digest(events: &[JournalEvent]) -> String {
    let mut text = String::new();
    for event in events {
        let _ = FmtWrite::write_fmt(
            &mut text,
            format_args!("{}:{}:{:?};", event.sequence, event.offset, event.mutation),
        );
    }
    SourceFingerprint::compute(text.as_bytes())
        .as_str()
        .to_owned()
}

/// Replay a complete journal prefix J0:n into reconstructed state.
pub fn replay(events: &[JournalEvent]) -> Result<ReplayedState, ReplayError> {
    replay_with_interrupt(events, None)
}

/// Replay with an explicit interruption point for fail-closed testing.
pub fn replay_with_interrupt(
    events: &[JournalEvent],
    interrupt_at: Option<usize>,
) -> Result<ReplayedState, ReplayError> {
    let mut state = ReplayedState::default();
    apply_events(&mut state, events, interrupt_at)?;
    Ok(state)
}

/// Checkpoint bound to a stream identity, partition, epoch, journal head and
/// reconstructed state. It is additive to the legacy `CheckpointBinding`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamCheckpoint {
    pub binding: CheckpointBinding,
    pub partition: String,
    pub owner_epoch: u64,
    pub schema_version: u32,
    pub last_sequence: u64,
    pub last_offset: u64,
    pub previous_checkpoint: String,
    pub journal_head_digest: String,
    pub state: ReplayedState,
    pub state_digest: String,
}

impl StreamCheckpoint {
    /// Build a checkpoint for J0:n. Every binding must be present; an
    /// interruption at any named stage returns an error and emits no checkpoint.
    pub fn create(
        binding: CheckpointBinding,
        partition: &str,
        owner_epoch: u64,
        previous_checkpoint: String,
        events: &[JournalEvent],
        interrupted_after: Option<&'static str>,
    ) -> Result<Self, CheckpointError> {
        if interrupted_after == Some("binding") {
            return Err(CheckpointError::Interrupted { field: "binding" });
        }
        if binding.source_id.is_empty()
            || binding.source_fingerprint.is_empty()
            || binding.target_id.is_empty()
        {
            return Err(CheckpointError::Incomplete { field: "binding" });
        }
        if interrupted_after == Some("partition") {
            return Err(CheckpointError::Interrupted { field: "partition" });
        }
        if partition.is_empty() {
            return Err(CheckpointError::Incomplete { field: "partition" });
        }
        if interrupted_after == Some("owner_epoch") {
            return Err(CheckpointError::Interrupted {
                field: "owner_epoch",
            });
        }
        if owner_epoch == 0 {
            return Err(CheckpointError::Incomplete {
                field: "owner_epoch",
            });
        }
        if previous_checkpoint.is_empty() {
            return Err(CheckpointError::Incomplete {
                field: "previous_checkpoint",
            });
        }
        let state = replay(events)?;
        if interrupted_after == Some("state") {
            return Err(CheckpointError::Interrupted { field: "state" });
        }
        let last_sequence: u64 = state.applied.last().copied().unwrap_or_default();
        let last_offset = state.last_offset;
        let state_digest = state.digest();
        if interrupted_after == Some("journal_head") {
            return Err(CheckpointError::Interrupted {
                field: "journal_head",
            });
        }
        Ok(Self {
            binding,
            partition: partition.to_owned(),
            owner_epoch,
            schema_version: STREAM_CHECKPOINT_SCHEMA_VERSION,
            last_sequence,
            last_offset,
            previous_checkpoint,
            journal_head_digest: journal_head_digest(events),
            state,
            state_digest,
        })
    }

    /// Stable identity of this checkpoint, suitable as a predecessor reference.
    pub fn digest(&self) -> String {
        let mut text = String::new();
        let _ = FmtWrite::write_fmt(
            &mut text,
            format_args!(
                "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                self.binding.source_id,
                self.binding.source_fingerprint,
                self.binding.target_id,
                self.partition,
                self.owner_epoch,
                self.schema_version,
                self.last_sequence,
                self.last_offset,
                self.previous_checkpoint,
                self.journal_head_digest,
                self.state_digest
            ),
        );
        SourceFingerprint::compute(text.as_bytes())
            .as_str()
            .to_owned()
    }

    /// Advance to the next checkpoint with an explicit predecessor reference.
    pub fn advance(
        &self,
        previous_checkpoint: String,
        events: &[JournalEvent],
    ) -> Result<Self, CheckpointError> {
        Self::create(
            self.binding.clone(),
            &self.partition,
            self.owner_epoch,
            previous_checkpoint,
            events,
            None,
        )
    }
}

/// Fail-closed reason a checkpoint or restore was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CheckpointError {
    #[error("checkpoint is incomplete: {field}")]
    Incomplete { field: &'static str },
    #[error("checkpoint creation interrupted before {field}")]
    Interrupted { field: &'static str },
    #[error("checkpoint schema version {found} is unsupported (expected {expected})")]
    UnsupportedSchemaVersion { found: u32, expected: u32 },
    #[error("checkpoint stream binding does not match the requested stream")]
    BindingMismatch,
    #[error("checkpoint partition {expected} does not match {found}")]
    PartitionMismatch { expected: String, found: String },
    #[error("checkpoint owner epoch {expected} does not match {found}")]
    OwnerEpochMismatch { expected: u64, found: u64 },
    #[error("journal head digest mismatch at sequence {sequence}")]
    JournalHeadMismatch { sequence: u64 },
    #[error("reconstructed state digest mismatch at sequence {sequence}")]
    StateDigestMismatch { sequence: u64 },
    #[error("multiple checkpoints are eligible; refusing to choose a largest offset")]
    AmbiguousCheckpoints,
    #[error("checkpoint replay failed: {0}")]
    Replay(#[from] ReplayError),
}

/// Restore state from Kn and the tail Jn+1:m, verifying every bound field.
pub fn restore(
    checkpoint: &StreamCheckpoint,
    binding: &CheckpointBinding,
    partition: &str,
    owner_epoch: u64,
    prefix: &[JournalEvent],
    tail: &[JournalEvent],
) -> Result<ReplayedState, CheckpointError> {
    restore_with_interrupt(
        checkpoint,
        binding,
        partition,
        owner_epoch,
        prefix,
        tail,
        None,
    )
}

/// Restore with an explicit interruption point for fail-closed testing.
pub fn restore_with_interrupt(
    checkpoint: &StreamCheckpoint,
    binding: &CheckpointBinding,
    partition: &str,
    owner_epoch: u64,
    prefix: &[JournalEvent],
    tail: &[JournalEvent],
    interrupt_at: Option<usize>,
) -> Result<ReplayedState, CheckpointError> {
    if checkpoint.schema_version != STREAM_CHECKPOINT_SCHEMA_VERSION {
        return Err(CheckpointError::UnsupportedSchemaVersion {
            found: checkpoint.schema_version,
            expected: STREAM_CHECKPOINT_SCHEMA_VERSION,
        });
    }
    if checkpoint.binding != *binding
        || checkpoint.previous_checkpoint.is_empty()
        || checkpoint.journal_head_digest.is_empty()
        || checkpoint.state_digest.is_empty()
    {
        return Err(CheckpointError::BindingMismatch);
    }
    if checkpoint.partition != partition {
        return Err(CheckpointError::PartitionMismatch {
            expected: checkpoint.partition.clone(),
            found: partition.to_owned(),
        });
    }
    if checkpoint.owner_epoch != owner_epoch {
        return Err(CheckpointError::OwnerEpochMismatch {
            expected: checkpoint.owner_epoch,
            found: owner_epoch,
        });
    }
    if journal_head_digest(prefix) != checkpoint.journal_head_digest {
        return Err(CheckpointError::JournalHeadMismatch {
            sequence: checkpoint.last_sequence,
        });
    }
    match prefix.last() {
        Some(event)
            if event.sequence == checkpoint.last_sequence
                && event.offset == checkpoint.last_offset => {}
        Some(_) => {
            return Err(CheckpointError::JournalHeadMismatch {
                sequence: checkpoint.last_sequence,
            });
        }
        None if checkpoint.last_sequence == 0 && checkpoint.last_offset == 0 => {}
        None => {
            return Err(CheckpointError::JournalHeadMismatch {
                sequence: checkpoint.last_sequence,
            });
        }
    }
    if checkpoint.state.digest() != checkpoint.state_digest {
        return Err(CheckpointError::StateDigestMismatch {
            sequence: checkpoint.last_sequence,
        });
    }
    let mut state = checkpoint.state.clone();
    apply_events(&mut state, tail, interrupt_at)?;
    Ok(state)
}

/// Restore from exactly one eligible checkpoint. Two candidates are ambiguous
/// and must never resolve to the largest offset.
pub fn restore_from_candidates(
    checkpoints: &[StreamCheckpoint],
    binding: &CheckpointBinding,
    partition: &str,
    owner_epoch: u64,
    prefix: &[JournalEvent],
    tail: &[JournalEvent],
) -> Result<ReplayedState, CheckpointError> {
    let mut eligible = checkpoints.iter();
    let first = eligible.next().ok_or(CheckpointError::Incomplete {
        field: "checkpoint",
    })?;
    if eligible.next().is_some() {
        return Err(CheckpointError::AmbiguousCheckpoints);
    }
    restore(first, binding, partition, owner_epoch, prefix, tail)
}

/// Explicit duplicate-id policy. A repeated record id is always rejected with
/// evidence (sequence, line, first line and exact bytes) rather than silently
/// skipped, so every physical line remains accountable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DuplicatePolicy {
    #[default]
    Reject,
}

/// Errors opening a streaming source. Read/parse failures that belong to a
/// particular physical line are reported through `SourceError` instead.
#[derive(Debug, Error)]
pub enum FileSourceError {
    #[error("opening source `{path}`: {message}")]
    Open { path: String, message: String },
    #[error("reading source bytes for fingerprint `{path}`: {message}")]
    Fingerprint { path: String, message: String },
    #[error("rewinding source after fingerprint `{path}`: {message}")]
    Rewind { path: String, message: String },
    #[error("resume offset {expected} is past end of source")]
    UnexpectedEof { expected: u64 },
    #[error("reading resume prefix at offset {offset}: {message}")]
    SeekRead { offset: u64, message: String },
    #[error("resume anchor rejected: {0}")]
    Resume(#[from] ResumeError),
}

/// A `BufRead`-backed line source with a fixed-size reusable buffer.
#[derive(Debug)]
pub struct FileSource<R: BufRead> {
    identity: SourceIdentity,
    reader: R,
    line_buffer: Vec<u8>,
    sequence: u64,
    line_number: usize,
    byte_offset: u64,
    last_offset: u64,
    seen: DuplicateIndex,
    duplicate_policy: DuplicatePolicy,
    exhausted: bool,
}

impl<R: BufRead> FileSource<R> {
    /// Wrap a reader with a registered identity. No bytes are read yet.
    #[must_use]
    pub fn new(reader: R, identity: SourceIdentity) -> Self {
        Self {
            identity,
            reader,
            line_buffer: Vec::with_capacity(MAX_LINE_BYTES.min(8192)),
            sequence: 0,
            line_number: 0,
            byte_offset: 0,
            last_offset: 0,
            seen: DuplicateIndex::default(),
            duplicate_policy: DuplicatePolicy::default(),
            exhausted: false,
        }
    }

    #[must_use]
    pub fn with_duplicate_policy(mut self, policy: DuplicatePolicy) -> Self {
        self.duplicate_policy = policy;
        self
    }

    /// Build a source positioned at a verified durable anchor. The reader is
    /// advanced to the anchor's physical byte offset before any observation
    /// is produced; no line before that offset is re-emitted.
    pub fn with_resume(
        mut reader: R,
        identity: SourceIdentity,
        anchor: &DurableCheckpoint,
        target_id: &str,
    ) -> Result<Self, FileSourceError> {
        anchor.verify_against(&identity, target_id)?;
        discard_bytes(&mut reader, anchor.last_committed_offset)?;
        let mut source = Self::new(reader, identity);
        source.sequence = anchor.last_committed_sequence;
        source.line_number = anchor.last_committed_line;
        source.byte_offset = anchor.last_committed_offset;
        source.last_offset = anchor.last_committed_offset;
        Ok(source)
    }

    #[must_use]
    pub const fn identity(&self) -> &SourceIdentity {
        &self.identity
    }

    #[must_use]
    pub const fn last_offset(&self) -> u64 {
        self.last_offset
    }

    #[must_use]
    pub const fn next_offset(&self) -> u64 {
        self.byte_offset
    }

    #[must_use]
    pub const fn line_number(&self) -> usize {
        self.line_number
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Current reusable buffer capacity. Exposed so a test can prove reads
    /// stay bounded regardless of input size.
    #[must_use]
    pub fn buffer_capacity(&self) -> usize {
        self.line_buffer.capacity()
    }

    fn io_error(
        &self,
        sequence: u64,
        line_number: usize,
        operation: &str,
        error: std::io::Error,
    ) -> SourceError {
        SourceError::Io {
            sequence,
            line_number,
            offset: self.byte_offset,
            message: format!("{operation}: {error}"),
        }
    }

    fn reject(
        &self,
        sequence: u64,
        line_number: usize,
        raw_bytes: Vec<u8>,
        reason: String,
    ) -> SourceError {
        SourceError::MalformedLine {
            sequence,
            line_number,
            raw_bytes,
            reason,
        }
    }

    fn validate_record(
        &mut self,
        raw_bytes: &[u8],
        sequence: u64,
        line_number: usize,
    ) -> Result<String, SourceError> {
        let value: serde_json::Value = serde_json::from_slice(raw_bytes).map_err(|error| {
            self.reject(sequence, line_number, raw_bytes.to_vec(), error.to_string())
        })?;
        let object = value.as_object().ok_or_else(|| {
            self.reject(
                sequence,
                line_number,
                raw_bytes.to_vec(),
                "record must be a JSON object".to_owned(),
            )
        })?;

        if let Some(version) = object.get("schema_version") {
            let found = version.as_u64().ok_or_else(|| {
                self.reject(
                    sequence,
                    line_number,
                    raw_bytes.to_vec(),
                    "schema_version must be an unsigned integer".to_owned(),
                )
            })?;
            if found != u64::from(JSONL_SCHEMA_VERSION) {
                return Err(self.reject(
                    sequence,
                    line_number,
                    raw_bytes.to_vec(),
                    format!(
                        "unsupported schema_version {found}; reader accepts {JSONL_SCHEMA_VERSION}"
                    ),
                ));
            }
        }

        let record_id = object
            .get("id")
            .and_then(serde_json::Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                self.reject(
                    sequence,
                    line_number,
                    raw_bytes.to_vec(),
                    "id must be a non-empty string".to_owned(),
                )
            })?
            .to_owned();
        if !object
            .get("payload")
            .is_some_and(serde_json::Value::is_object)
        {
            return Err(self.reject(
                sequence,
                line_number,
                raw_bytes.to_vec(),
                "payload must be an object".to_owned(),
            ));
        }

        let first_line = self.seen.lookup(&record_id).map_err(|error| {
            self.io_error(sequence, line_number, "duplicate index lookup", error)
        })?;
        if let Some(first_line) = first_line {
            let _ = self.duplicate_policy;
            return Err(SourceError::DuplicateId {
                sequence,
                line_number,
                first_line,
                record_id,
                raw_bytes: raw_bytes.to_vec(),
            });
        }
        self.seen.insert(&record_id, line_number).map_err(|error| {
            self.io_error(sequence, line_number, "duplicate index insert", error)
        })?;
        Ok(record_id)
    }
}

impl FileSource<std::io::BufReader<std::fs::File>> {
    /// Open a real file, fingerprint it with bounded reads on one file handle,
    /// rewind that handle, and return a source positioned at byte zero. The
    /// source file must remain unchanged while this source is being consumed.
    pub fn open(path: &Path, name: &str) -> Result<Self, FileSourceError> {
        let mut file = std::fs::File::open(path).map_err(|error| FileSourceError::Open {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        let fingerprint = SourceFingerprint::compute_reader(&mut file).map_err(|error| {
            FileSourceError::Fingerprint {
                path: path.display().to_string(),
                message: error.to_string(),
            }
        })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| FileSourceError::Rewind {
                path: path.display().to_string(),
                message: error.to_string(),
            })?;
        let identity = SourceIdentity::register_with_fingerprint(name, fingerprint);
        Ok(Self::new(std::io::BufReader::new(file), identity))
    }

    /// Open a real file, fingerprint it with bounded reads, then resume from a
    /// verified anchor using the same open file handle.
    pub fn open_with_resume(
        path: &Path,
        name: &str,
        anchor: &DurableCheckpoint,
        target_id: &str,
    ) -> Result<Self, FileSourceError> {
        let mut file = std::fs::File::open(path).map_err(|error| FileSourceError::Open {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        let fingerprint = SourceFingerprint::compute_reader(&mut file).map_err(|error| {
            FileSourceError::Fingerprint {
                path: path.display().to_string(),
                message: error.to_string(),
            }
        })?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| FileSourceError::Rewind {
                path: path.display().to_string(),
                message: error.to_string(),
            })?;
        let identity = SourceIdentity::register_with_fingerprint(name, fingerprint);
        let reader = std::io::BufReader::new(file);
        Self::with_resume(reader, identity, anchor, target_id)
    }
}

impl<R: BufRead> SourceAdapter for FileSource<R> {
    fn read_one(&mut self) -> Result<Option<RawObservation>, SourceError> {
        if self.exhausted {
            return Ok(None);
        }
        let start_offset = self.byte_offset;
        self.last_offset = start_offset;
        self.line_buffer.clear();

        // `Take` bounds this call to one line plus its delimiter. The reusable
        // buffer can therefore never hold more than MAX_LINE_BYTES + 1 bytes.
        let limit = (MAX_LINE_BYTES + 1) as u64;
        let read = {
            let mut limited = self.reader.by_ref().take(limit);
            limited
                .read_until(b'\n', &mut self.line_buffer)
                .map_err(|error| SourceError::Io {
                    sequence: self.sequence + 1,
                    line_number: self.line_number + 1,
                    offset: self.byte_offset,
                    message: error.to_string(),
                })?
        };
        self.byte_offset += read as u64;
        if read == 0 {
            self.exhausted = true;
            return Ok(None);
        }
        let ends_with_newline = self.line_buffer.last() == Some(&b'\n');
        if !ends_with_newline && self.line_buffer.len() > MAX_LINE_BYTES {
            self.exhausted = true;
            return Err(SourceError::LineTooLong {
                sequence: self.sequence + 1,
                line_number: self.line_number + 1,
                offset: start_offset,
                limit: MAX_LINE_BYTES,
                raw_bytes: self.line_buffer.clone(),
            });
        }

        let mut content_len = self.line_buffer.len();
        if ends_with_newline {
            content_len -= 1;
        }
        // A trailing `\r` from CRLF input is retained verbatim, like the
        // in-memory source. Only the `\n` delimiter is removed.
        let raw_bytes = self.line_buffer[..content_len].to_vec();
        let sequence = self.sequence + 1;
        let line_number = self.line_number + 1;
        self.sequence = sequence;
        self.line_number = line_number;
        self.last_offset = start_offset;

        let record_id = self.validate_record(&raw_bytes, sequence, line_number)?;
        let provenance = format!(
            "file:{}:{}@{}",
            self.identity.name, line_number, start_offset
        );
        Ok(Some(RawObservation {
            sequence,
            line_number,
            source_id: self.identity.source_id.clone(),
            record_id,
            raw_bytes,
            provenance,
        }))
    }
}

fn discard_bytes<R: Read>(reader: &mut R, offset: u64) -> Result<(), FileSourceError> {
    let mut remaining = offset;
    let mut scratch = [0u8; 8192];
    while remaining > 0 {
        let want = remaining.min(scratch.len() as u64) as usize;
        let read = reader
            .read(&mut scratch[..want])
            .map_err(|error| FileSourceError::SeekRead {
                offset: offset - remaining,
                message: error.to_string(),
            })
            .and_then(|read| {
                if read == 0 {
                    Err(FileSourceError::UnexpectedEof { expected: offset })
                } else {
                    Ok(read)
                }
            })?;
        remaining -= read as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    struct ReadRequestTracker<R> {
        inner: R,
        largest_request: usize,
    }

    impl<R: Read> Read for ReadRequestTracker<R> {
        fn read(&mut self, buffer: &mut [u8]) -> Result<usize, std::io::Error> {
            self.largest_request = self.largest_request.max(buffer.len());
            self.inner.read(buffer)
        }
    }

    fn record(id: &str, value: i64) -> String {
        format!(
            "{{\"id\":\"{id}\",\"payload\":{{\"entity_id\":\"e\",\"kind\":\"k\",\"value\":{value},\"observed_at\":1}}}}"
        )
    }

    fn source(text: &str) -> FileSource<Cursor<Vec<u8>>> {
        let bytes = text.as_bytes().to_vec();
        FileSource::new(
            Cursor::new(bytes.clone()),
            SourceIdentity::register("fixture", &bytes),
        )
    }

    #[test]
    fn reader_fingerprint_uses_a_fixed_bounded_buffer() {
        let bytes = vec![0x5a; FINGERPRINT_BUFFER_BYTES * 4 + 17];
        let mut reader = ReadRequestTracker {
            inner: Cursor::new(bytes.clone()),
            largest_request: 0,
        };
        let fingerprint =
            SourceFingerprint::compute_reader(&mut reader).expect("reader fingerprint");
        assert_eq!(fingerprint, SourceFingerprint::compute(&bytes));
        assert_eq!(reader.largest_request, FINGERPRINT_BUFFER_BYTES);
    }

    #[test]
    fn duplicate_index_memory_is_fixed_across_cardinality() {
        let mut small = DuplicateIndex::with_buckets(8);
        let mut large = DuplicateIndex::with_buckets(8);
        for index in 0..10 {
            small
                .insert(&format!("id-{index}"), index)
                .expect("small insert");
        }
        for index in 0..5_000 {
            large
                .insert(&format!("id-{index}"), index)
                .expect("large insert");
        }
        assert_eq!(small.memory_bytes(), large.memory_bytes());
        assert_eq!(large.lookup("id-4999").expect("lookup"), Some(4999));
        assert_eq!(large.lookup("missing").expect("lookup"), None);
        assert_eq!(large.lookup("id-7").expect("lookup"), Some(7));
    }

    #[test]
    fn duplicate_index_is_exact_when_all_ids_share_a_bucket() {
        let mut index = DuplicateIndex::with_buckets(1);
        index.insert("alpha", 3).expect("insert alpha");
        index.insert("beta", 9).expect("insert beta");
        assert_eq!(index.lookup("alpha").expect("lookup"), Some(3));
        assert_eq!(index.lookup("beta").expect("lookup"), Some(9));
        assert_eq!(index.lookup("gamma").expect("lookup"), None);
        let scratch = index.path.clone().expect("scratch path");
        assert!(scratch.exists());
        drop(index);
        assert!(!scratch.exists(), "scratch index must be removed on drop");
    }

    #[test]
    fn file_open_fingerprints_and_reads_from_the_same_rewound_handle() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("source.jsonl");
        let text = format!("{}\n", record("file-open", 7));
        let bytes = text.as_bytes();
        let mut file = std::fs::File::create(&path).expect("create source");
        file.write_all(bytes).expect("write source");
        drop(file);

        let mut source = FileSource::open(&path, "file-open").expect("open source");
        assert_eq!(
            source.identity().fingerprint(),
            &SourceFingerprint::compute(bytes)
        );
        let observation = source
            .read_one()
            .expect("read source")
            .expect("first observation");
        assert_eq!(observation.record_id, "file-open");
    }

    #[test]
    fn streaming_reads_exact_bytes_offsets_and_fingerprint() {
        let first = record("a", 1);
        let second = record("b", 2);
        let text = format!("{first}\r\n{second}\n");
        let bytes = text.as_bytes().to_vec();
        let mut reader = source(&text);
        assert_eq!(
            reader.identity().fingerprint(),
            &SourceFingerprint::compute(&bytes)
        );

        let a = reader.read_one().expect("first").expect("observation");
        assert_eq!(a.sequence, 1);
        assert_eq!(a.line_number, 1);
        assert_eq!(a.raw_bytes, format!("{first}\r").as_bytes());
        assert_eq!(reader.last_offset(), 0);
        assert!(a.provenance.contains("file:fixture:1@0"));

        let b = reader.read_one().expect("second").expect("observation");
        assert_eq!(b.sequence, 2);
        assert_eq!(b.raw_bytes, second.as_bytes());
        assert_eq!(reader.last_offset(), (first.len() + 2) as u64);
        assert_eq!(reader.next_offset(), text.len() as u64);
        assert!(reader.read_one().expect("end").is_none());
    }

    #[test]
    fn buffer_capacity_is_bounded_across_many_lines() {
        let text = (0..64)
            .map(|index| format!("{}\n", record(&format!("line-{index}"), 1)))
            .collect::<String>();
        let mut reader = source(&text);
        let initial = reader.buffer_capacity();
        for _ in 0..64 {
            let _ = reader.read_one().expect("read").expect("observation");
        }
        assert!(reader.buffer_capacity() <= MAX_LINE_BYTES + 1);
        assert!(reader.buffer_capacity() <= initial.max(MAX_LINE_BYTES + 1));
        let mut huge = String::from("{\"id\":\"huge\",\"payload\":{\"entity_id\":\"");
        huge.push_str(&"x".repeat(MAX_LINE_BYTES + 16));
        let mut reader = source(&huge);
        let error = reader.read_one().expect_err("line too long");
        assert!(matches!(error, SourceError::LineTooLong { limit, .. } if limit == MAX_LINE_BYTES));
        assert!(reader.buffer_capacity() <= MAX_LINE_BYTES + 1);
    }

    #[test]
    fn malformed_and_duplicate_lines_carry_physical_evidence() {
        let mut reader = source("{not json}\n");
        let error = reader.read_one().expect_err("malformed");
        assert_eq!(error.sequence(), 1);
        assert_eq!(error.raw_bytes(), b"{not json}");
        assert!(matches!(
            error,
            SourceError::MalformedLine { line_number: 1, .. }
        ));

        let line = record("dup", 1);
        let text = format!("{line}\n{line}\n");
        let mut reader = source(&text);
        let _ = reader.read_one().expect("first").expect("observation");
        let error = reader.read_one().expect_err("duplicate");
        assert!(matches!(
            error,
            SourceError::DuplicateId {
                sequence: 2,
                line_number: 2,
                first_line: 1,
                ..
            }
        ));
    }

    #[test]
    fn resume_is_bound_to_source_identity_fingerprint_and_target() {
        let text = format!("{}\n{}\n", record("a", 1), record("b", 2));
        let bytes = text.as_bytes().to_vec();
        let identity = SourceIdentity::register("fixture", &bytes);
        let binding = CheckpointBinding::new(&identity, "pg-a");
        let anchor =
            DurableCheckpoint::new(&binding).advanced(1, (record("a", 1).len() + 1) as u64);

        let mut resumed = FileSource::with_resume(
            Cursor::new(bytes.clone()),
            identity.clone(),
            &anchor,
            "pg-a",
        )
        .expect("resume");
        let observation = resumed.read_one().expect("read").expect("observation");
        assert_eq!(observation.record_id, "b");
        assert_eq!(observation.sequence, 2);

        let other_bytes = format!("{}\n", record("a", 99)).into_bytes();
        let other = SourceIdentity::register("fixture", &other_bytes);
        assert!(matches!(
            FileSource::with_resume(Cursor::new(other_bytes), other, &anchor, "pg-a"),
            Err(FileSourceError::Resume(
                ResumeError::FingerprintMismatch { .. }
            ))
        ));
        assert!(matches!(
            FileSource::with_resume(
                Cursor::new(bytes.clone()),
                identity.clone(),
                &anchor,
                "pg-b"
            ),
            Err(FileSourceError::Resume(ResumeError::TargetMismatch { .. }))
        ));
        let mut bad_version = anchor.clone();
        bad_version.schema_version += 1;
        assert!(matches!(
            FileSource::with_resume(
                Cursor::new(bytes.clone()),
                identity.clone(),
                &bad_version,
                "pg-a"
            ),
            Err(FileSourceError::Resume(
                ResumeError::UnsupportedSchemaVersion { .. }
            ))
        ));
        let mut bad_id = anchor.clone();
        bad_id.source_id = "other".to_owned();
        assert!(matches!(
            FileSource::with_resume(Cursor::new(bytes), identity, &bad_id, "pg-a"),
            Err(FileSourceError::Resume(
                ResumeError::SourceIdentityMismatch { .. }
            ))
        ));
    }

    #[test]
    fn registry_reuses_the_first_registration() {
        let mut registry = SourceRegistry::new();
        let first = registry.register("fixture", b"abc").clone();
        let second = registry.register("fixture", b"xyz").clone();
        assert_eq!(first, second);
        assert_eq!(registry.resolve("fixture"), Some(&first));
        assert!(registry.resolve("missing").is_none());
    }

    fn journal() -> Vec<JournalEvent> {
        (1..=6_u64)
            .map(|sequence| JournalEvent {
                sequence,
                offset: sequence * 32,
                mutation: if sequence == 4 {
                    Mutation::Delete {
                        key: "key-2".to_owned(),
                    }
                } else if sequence % 2 == 0 {
                    Mutation::NoOp
                } else {
                    Mutation::Put {
                        key: format!("key-{sequence}"),
                        value: i64::try_from(sequence).expect("small sequence"),
                    }
                },
            })
            .collect()
    }

    fn binding() -> CheckpointBinding {
        CheckpointBinding {
            source_id: "stream-a".to_owned(),
            source_fingerprint: "sha256:0123456789abcdef".to_owned(),
            target_id: "target-a".to_owned(),
        }
    }

    fn checkpoint_at(events: &[JournalEvent]) -> StreamCheckpoint {
        StreamCheckpoint::create(
            binding(),
            "partition-a",
            7,
            GENESIS_CHECKPOINT.to_owned(),
            events,
            None,
        )
        .expect("checkpoint")
    }

    #[test]
    fn replay_equals_restore_across_complete_state() {
        let events = journal();
        let boundary = 4;
        let prefix = &events[..boundary];
        let tail = &events[boundary..];
        let checkpoint = checkpoint_at(prefix);

        let replayed = replay(&events).expect("full replay");
        let restored =
            restore(&checkpoint, &binding(), "partition-a", 7, prefix, tail).expect("restore");

        assert_eq!(
            replayed, restored,
            "replay and restore must agree on every field"
        );
        assert_eq!(
            replayed.digest(),
            restored.digest(),
            "replay and restore must agree on the state digest"
        );
        assert_eq!(
            checkpoint.journal_head_digest,
            journal_head_digest(prefix),
            "checkpoint must bind the journal head it was created from"
        );
        assert_eq!(
            checkpoint.state_digest,
            replay(prefix).expect("prefix replay").digest(),
            "checkpoint must bind the reconstructed state digest"
        );
        assert_eq!(
            checkpoint.last_sequence, 4,
            "checkpoint must bind its terminal sequence"
        );
        assert_eq!(
            checkpoint.last_offset, 128,
            "checkpoint must bind its terminal physical offset"
        );
    }

    #[test]
    fn restore_refuses_a_wrong_stream_partition_or_owner_epoch() {
        let events = journal();
        let checkpoint = checkpoint_at(&events[..4]);
        let mut other_binding = binding();
        other_binding.target_id = "target-b".to_owned();
        assert!(
            matches!(
                restore(
                    &checkpoint,
                    &other_binding,
                    "partition-a",
                    7,
                    &events[..4],
                    &events[4..]
                ),
                Err(CheckpointError::BindingMismatch)
            ),
            "a different stream target must be refused"
        );
        assert!(
            matches!(
                restore(
                    &checkpoint,
                    &binding(),
                    "partition-b",
                    7,
                    &events[..4],
                    &events[4..]
                ),
                Err(CheckpointError::PartitionMismatch { .. })
            ),
            "a different partition must be refused"
        );
        assert!(
            matches!(
                restore(
                    &checkpoint,
                    &binding(),
                    "partition-a",
                    8,
                    &events[..4],
                    &events[4..]
                ),
                Err(CheckpointError::OwnerEpochMismatch { .. })
            ),
            "a different owner epoch must be refused"
        );
        assert!(
            matches!(
                restore(
                    &checkpoint,
                    &binding(),
                    "partition-a",
                    7,
                    &events[..5],
                    &events[5..]
                ),
                Err(CheckpointError::JournalHeadMismatch { .. })
            ),
            "a different journal prefix must be refused"
        );
    }

    #[test]
    fn restore_does_not_silently_choose_the_largest_offset() {
        let events = journal();
        let earlier = checkpoint_at(&events[..3]);
        let later = checkpoint_at(&events[..5]);
        let candidates = [earlier, later];
        assert_eq!(
            restore_from_candidates(
                &candidates,
                &binding(),
                "partition-a",
                7,
                &events[..5],
                &events[5..]
            ),
            Err(CheckpointError::AmbiguousCheckpoints),
            "two eligible checkpoints must never resolve to the largest offset"
        );
        assert!(
            matches!(
                restore(
                    &candidates[0],
                    &binding(),
                    "partition-a",
                    7,
                    &events[..5],
                    &events[5..]
                ),
                Err(CheckpointError::JournalHeadMismatch { .. })
            ),
            "a checkpoint must not advance to a longer journal prefix on its own"
        );
        assert!(
            matches!(
                restore(
                    &candidates[0],
                    &binding(),
                    "partition-a",
                    7,
                    &events[..3],
                    &events[5..]
                ),
                Err(CheckpointError::Replay(ReplayError::NonContiguous { .. }))
            ),
            "a gap in the tail must not be skipped"
        );
    }

    #[test]
    fn interrupted_checkpoint_creation_fails_closed() {
        let events = journal();
        for field in [
            "binding",
            "partition",
            "owner_epoch",
            "state",
            "journal_head",
        ] {
            let outcome = StreamCheckpoint::create(
                binding(),
                "partition-a",
                7,
                GENESIS_CHECKPOINT.to_owned(),
                &events[..4],
                Some(field),
            );
            assert_eq!(
                outcome,
                Err(CheckpointError::Interrupted { field }),
                "interruption at {field} must not emit a checkpoint"
            );
        }
        let mut incomplete = binding();
        incomplete.source_fingerprint.clear();
        assert_eq!(
            StreamCheckpoint::create(
                incomplete,
                "partition-a",
                7,
                GENESIS_CHECKPOINT.to_owned(),
                &events[..4],
                None
            ),
            Err(CheckpointError::Incomplete { field: "binding" }),
            "a checkpoint without a stream binding must be refused"
        );
    }

    #[test]
    fn interrupted_replay_and_restore_fail_closed() {
        let events = journal();
        assert_eq!(
            replay_with_interrupt(&events, Some(2)),
            Err(ReplayError::Interrupted { at: 2 }),
            "an interrupted replay must not return partial state"
        );
        assert!(
            replay(&events).is_ok(),
            "an uninterrupted replay of the same journal must succeed"
        );
        let checkpoint = checkpoint_at(&events[..4]);
        assert!(
            matches!(
                restore_with_interrupt(
                    &checkpoint,
                    &binding(),
                    "partition-a",
                    7,
                    &events[..4],
                    &events[4..],
                    Some(1)
                ),
                Err(CheckpointError::Replay(ReplayError::Interrupted { at: 1 }))
            ),
            "an interrupted restore must not return partial state"
        );
        assert!(
            restore(
                &checkpoint,
                &binding(),
                "partition-a",
                7,
                &events[..4],
                &events[4..]
            )
            .is_ok(),
            "an uninterrupted restore of the same input must succeed"
        );
    }
}
