//! Segmented, checkpointed local durability (Platform P6.2.1).
//!
//! The production-shaped runner reaches this store through the
//! [`crate::application::DurableStore`] abstraction. Segments hold multiple
//! framed commits, are bounded by record count and encoded bytes, rotate into
//! a verified archive, and are finalized with separate record, footer, rename
//! and directory sync boundaries. A commit is durable only after those
//! barriers complete in order; no rename is treated as a commit before them.

use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use serde::{
    Deserialize, //
    Serialize,   //
};
use sha2::{
    Digest, //
    Sha256, //
};
use thiserror::Error;

use crate::{
    application::{
        CommitIntent, CommitSink, DurableStore,
        durable::{COMMIT_SCHEMA_VERSION, CommitRecord, DurableState, checksum_of, load_state},
        file_source::{CheckpointBinding, DurableCheckpoint},
    },
    report::write_json_atomic,
};

pub const SEGMENT_SCHEMA_VERSION: u32 = 2;
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 2;
pub const ARCHIVE_SCHEMA_VERSION: u32 = 1;
const BLOOM_BITS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncPolicy {
    Full,
    None,
}

/// Bounds for segment rotation and snapshot cadence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreLimits {
    pub max_segment_records: usize,
    pub max_segment_bytes: usize,
    pub max_hot_segments: usize,
    pub snapshot_every_commits: u64,
}

impl Default for StoreLimits {
    fn default() -> Self {
        Self {
            max_segment_records: 32,
            max_segment_bytes: 1024 * 1024,
            max_hot_segments: 8,
            snapshot_every_commits: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SegmentFault {
    #[default]
    None,
    FailBeforeWrite,
    DiskFull,
    FailAfterHeader,
    FailAfterFrames,
    FailBeforeFooter,
    FailAfterFooterBeforeRename,
    FailAfterRenameBeforeDirSync,
    FailBeforeArchiveCopy,
    FailAfterArchiveCopyBeforeManifest,
    CorruptFrame,
    CorruptSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SegmentError {
    #[error("segmented store I/O failure: {0}")]
    Io(String),
    #[error("segmented store serialization failure: {0}")]
    Serialize(String),
    #[error("incomplete segment `{0}` may contain acknowledged data")]
    IncompleteSegment(String),
    #[error("segment `{path}` is corrupt: {reason}")]
    CorruptSegment { path: String, reason: String },
    #[error("segment `{path}` version {found} is unsupported (expected {expected})")]
    UnsupportedVersion {
        path: String,
        found: u32,
        expected: u32,
    },
    #[error("acknowledged segment `{0}` is missing or unverifiable")]
    MissingAcknowledgedSegment(String),
    #[error("segment sequence gap: expected `{expected}`, found `{found}`")]
    SequenceGap { expected: u64, found: u64 },
    #[error("snapshot `{path}` is invalid: {reason}")]
    InvalidSnapshot { path: String, reason: String },
    #[error("archive entry `{path}` is invalid: {reason}")]
    InvalidArchive { path: String, reason: String },
    #[error("store mixes legacy commit files and segments without a migration marker")]
    MixedFormat,
    #[error("store binding does not match its segment or snapshot")]
    BindingMismatch,
    #[error("fault injected: {0}")]
    FaultInjected(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentHeader {
    pub schema_version: u32,
    pub source_id: String,
    pub source_fingerprint: String,
    pub target_id: String,
    pub first_sequence: u64,
    pub expected_records: u64,
    pub sync_policy: SyncPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentFrame {
    pub sequence: u64,
    pub checksum: String,
    pub record: CommitRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentFooter {
    pub record_count: u64,
    pub last_sequence: u64,
    pub frames_checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentFrontier {
    pub segment: String,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub record_count: u64,
    pub frames_checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoverySnapshot {
    pub schema_version: u32,
    pub source_id: String,
    pub source_fingerprint: String,
    pub target_id: String,
    pub frontier: Option<SegmentFrontier>,
    pub materialized: CommitRecord,
    pub bloom_bits: Vec<u8>,
    pub commit_count: u64,
    pub event_count: u64,
    pub quarantine_count: u64,
    pub since_snapshot: u64,
    pub checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub path: String,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub record_count: u64,
    pub checksum: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub schema_version: u32,
    pub entries: Vec<ArchiveEntry>,
    pub checksum: String,
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = std::fmt::Write::write_fmt(&mut text, format_args!("{byte:02x}"));
    }
    text
}

fn json_line<T: Serialize>(value: &T) -> Result<String, SegmentError> {
    serde_json::to_string(value).map_err(|error| SegmentError::Serialize(error.to_string()))
}

fn sync_file(file: &File) -> Result<(), SegmentError> {
    file.sync_all()
        .map_err(|error| SegmentError::Io(error.to_string()))
}

fn sync_dir(path: &Path) -> Result<(), SegmentError> {
    let handle = File::open(path).map_err(|error| SegmentError::Io(error.to_string()))?;
    sync_file(&handle)
}

fn frames_checksum(frames: &[SegmentFrame]) -> String {
    let mut data = Vec::new();
    for frame in frames {
        data.extend_from_slice(frame.checksum.as_bytes());
        data.push(b'\n');
    }
    hex_digest(&data)
}

fn bloom_positions(value: &str) -> [usize; 3] {
    let mut positions = [0usize; 3];
    for (index, seed) in [
        0xcbf29ce484222325u64,
        0x9e3779b97f4a7c15,
        0x5851f42d4c957f2d,
    ]
    .into_iter()
    .enumerate()
    {
        let mut hash = seed;
        for byte in value.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
        positions[index] = (hash % BLOOM_BITS as u64) as usize;
    }
    positions
}

fn bloom_insert(bits: &mut [u8], value: &str) {
    for position in bloom_positions(value) {
        bits[position / 8] |= 1 << (position % 8);
    }
}

fn bloom_maybe_contains(bits: &[u8], value: &str) -> bool {
    bloom_positions(value)
        .iter()
        .all(|position| bits[position / 8] & (1 << (position % 8)) != 0)
}

fn segment_name(first: u64, last: u64) -> String {
    format!("seg-{first:012}-{last:012}.jsonl")
}

#[derive(Debug)]
struct OpenSegment {
    temp: PathBuf,
    frontier: SegmentFrontier,
    frames: Vec<SegmentFrame>,
    bytes: usize,
}

/// Bounded recovery state: the snapshot's materialized record plus the records
/// finalized after its frontier. Historical evidence stays on disk.
#[derive(Debug)]
pub struct SegmentedStore {
    directory: PathBuf,
    binding: CheckpointBinding,
    state: DurableState,
    next_sequence: u64,
    fault: SegmentFault,
    sync_policy: SyncPolicy,
    limits: StoreLimits,
    snapshot: RecoverySnapshot,
    bloom: Vec<u8>,
    hot: Vec<SegmentFrontier>,
    archives: Vec<ArchiveEntry>,
    open: Option<OpenSegment>,
}

impl SegmentedStore {
    pub fn open(
        directory: &Path,
        binding: CheckpointBinding,
        sync_policy: SyncPolicy,
        limits: StoreLimits,
    ) -> Result<Self, SegmentError> {
        Self::open_with(directory, binding, sync_policy, limits, false)
    }

    fn open_with(
        directory: &Path,
        binding: CheckpointBinding,
        sync_policy: SyncPolicy,
        limits: StoreLimits,
        allow_mixed: bool,
    ) -> Result<Self, SegmentError> {
        let segments_dir = directory.join("segments");
        let snapshots_dir = directory.join("snapshots");
        let archive_dir = directory.join("archive");
        let mut pending_temp: Option<PathBuf> = None;
        if let Ok(entries) = std::fs::read_dir(&segments_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(".tmp-") {
                    let path = entry.path();
                    let (header, _, footer, _) = parse_temp(&path, &binding)?;
                    if let Some(footer) = footer {
                        let final_name = segment_name(header.first_sequence, footer.last_sequence);
                        let final_path = segments_dir.join(final_name);
                        std::fs::rename(&path, &final_path)
                            .map_err(|e| SegmentError::Io(e.to_string()))?;
                        if sync_policy == SyncPolicy::Full {
                            sync_dir(&segments_dir)?;
                        }
                    } else if pending_temp.replace(path).is_some() {
                        return Err(SegmentError::IncompleteSegment(
                            "multiple open segments".to_owned(),
                        ));
                    }
                }
            }
        }
        let has_segments = std::fs::read_dir(&segments_dir)
            .map(|mut entries| entries.next().is_some())
            .unwrap_or(false);
        let has_legacy = std::fs::read_dir(directory)
            .map(|entries| {
                entries
                    .flatten()
                    .any(|entry| entry.file_name().to_string_lossy().starts_with("commit-"))
            })
            .unwrap_or(false);
        if has_legacy
            && has_segments
            && !allow_mixed
            && !directory.join("legacy-migrated.json").exists()
        {
            return Err(SegmentError::MixedFormat);
        }

        let archives = load_archive(&archive_dir)?;
        let snapshot = load_snapshot(&snapshots_dir, &binding)?;
        let snapshot = snapshot.unwrap_or_else(|| {
            empty_snapshot(
                &binding,
                CommitRecord {
                    target_id: binding.target_id.clone(),
                    committed_event_ids: Vec::new(),
                    dispositions: Vec::new(),
                    quarantines: Vec::new(),
                    checkpoint: DurableCheckpoint::new(&binding),
                },
                vec![0u8; BLOOM_BITS / 8],
            )
        });

        let covered = snapshot.frontier.as_ref().map_or(0, |f| f.last_sequence);
        let (hot, mut records) = load_segments(&segments_dir, &binding, covered)?;
        let chain = hot.last().map_or(covered, |f| f.last_sequence);
        let mut recovered_open = None;
        if let Some(path) = pending_temp {
            let (header, frames, _, bytes) = parse_temp(&path, &binding)?;
            if header.first_sequence != chain + 1 {
                return Err(SegmentError::SequenceGap {
                    expected: chain + 1,
                    found: header.first_sequence,
                });
            }
            let frontier = SegmentFrontier {
                segment: segment_name(header.first_sequence, header.first_sequence),
                first_sequence: header.first_sequence,
                last_sequence: frames.last().map_or(header.first_sequence, |f| f.sequence),
                record_count: frames.len() as u64,
                frames_checksum: frames_checksum(&frames),
            };
            if header.first_sequence > covered {
                records.extend(frames.iter().map(|frame| frame.record.clone()));
            }
            recovered_open = Some(OpenSegment {
                temp: path,
                frontier,
                frames,
                bytes,
            });
        }
        if let Some(claimed) = &snapshot.frontier {
            let in_hot = hot
                .iter()
                .any(|frontier| frontier.segment == claimed.segment);
            let in_archive = archives.iter().any(|entry| entry.path == claimed.segment);
            if !in_hot && !in_archive {
                return Err(SegmentError::MissingAcknowledgedSegment(
                    claimed.segment.clone(),
                ));
            }
        }
        let mut snapshot = snapshot;
        if snapshot.frontier.is_none() {
            if let Some(last) = hot.last() {
                snapshot.frontier = Some(last.clone());
            }
            if let Some(record) = records.last() {
                snapshot.materialized = record.clone();
            }
        }
        let mut all_records = vec![snapshot.materialized.clone()];
        all_records.extend(records);
        let mut bloom = vec![0u8; BLOOM_BITS / 8];
        rebuild_bloom(&segments_dir, &mut bloom)?;
        rebuild_bloom(&archive_dir, &mut bloom)?;
        Ok(Self {
            directory: directory.to_path_buf(),
            binding,
            state: DurableState {
                records: all_records,
            },
            next_sequence: recovered_open
                .as_ref()
                .map_or(chain + 1, |segment| segment.frontier.last_sequence + 1),
            fault: SegmentFault::None,
            sync_policy,
            limits,
            snapshot,
            bloom,
            hot,
            archives,
            open: recovered_open,
        })
    }

    #[must_use]
    pub const fn state(&self) -> &DurableState {
        &self.state
    }

    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    #[must_use]
    pub fn archive_entries(&self) -> &[ArchiveEntry] {
        &self.archives
    }

    pub fn set_fault(&mut self, fault: SegmentFault) {
        self.fault = fault;
    }

    /// Exact historical lookup. The Bloom filter proves only absence; a
    /// positive result triggers disk scan and any I/O error is propagated.
    pub fn is_committed(&self, event_id: &str) -> Result<bool, SegmentError> {
        if !bloom_maybe_contains(&self.bloom, event_id) {
            return Ok(false);
        }
        if self
            .state
            .records
            .iter()
            .any(|record| record.committed_event_ids.iter().any(|id| id == event_id))
        {
            return Ok(true);
        }
        if self.scan_dir(&self.directory.join("segments"), event_id)? {
            return Ok(true);
        }
        self.scan_dir(&self.directory.join("archive"), event_id)
    }

    fn scan_dir(&self, directory: &Path, event_id: &str) -> Result<bool, SegmentError> {
        if !directory.exists() {
            return Ok(false);
        }
        for entry in std::fs::read_dir(directory).map_err(|e| SegmentError::Io(e.to_string()))? {
            let path = entry.map_err(|e| SegmentError::Io(e.to_string()))?.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if !(name.starts_with("seg-") || name.starts_with(".tmp-")) {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|e| SegmentError::Io(e.to_string()))?;
            for line in BufReader::new(bytes.as_slice()).lines() {
                let line = line.map_err(|e| SegmentError::Io(e.to_string()))?;
                if let Ok(frame) = serde_json::from_str::<SegmentFrame>(&line)
                    && frame
                        .record
                        .committed_event_ids
                        .iter()
                        .any(|id| id == event_id)
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Commit one record. The record is fsynced before acknowledgement; the
    /// segment is finalized when its count or byte limit is reached.
    pub fn commit(&mut self, record: CommitRecord) -> Result<(), SegmentError> {
        if self.binding.target_id != record.target_id
            || self.binding.source_id != record.checkpoint.source_id
            || self.binding.source_fingerprint != record.checkpoint.source_fingerprint
        {
            return Err(SegmentError::BindingMismatch);
        }
        if self.fault == SegmentFault::FailBeforeWrite {
            return Err(SegmentError::FaultInjected(
                "failed before write".to_owned(),
            ));
        }
        if self.fault == SegmentFault::DiskFull {
            return Err(SegmentError::Io("no space left on device".to_owned()));
        }
        if self.fault == SegmentFault::CorruptSnapshot {
            let snapshots = self.directory.join("snapshots");
            std::fs::create_dir_all(&snapshots).map_err(|e| SegmentError::Io(e.to_string()))?;
            std::fs::write(snapshots.join("current.json"), b"{\"corrupt\":true}")
                .map_err(|e| SegmentError::Io(e.to_string()))?;
            return Err(SegmentError::FaultInjected("corrupt snapshot".to_owned()));
        }

        let sequence = self.next_sequence;
        if self.open.is_none() {
            let segments = self.directory.join("segments");
            std::fs::create_dir_all(&segments).map_err(|e| SegmentError::Io(e.to_string()))?;
            let temp = segments.join(format!(".tmp-{sequence:012}"));
            let header = SegmentHeader {
                schema_version: SEGMENT_SCHEMA_VERSION,
                source_id: self.binding.source_id.clone(),
                source_fingerprint: self.binding.source_fingerprint.clone(),
                target_id: self.binding.target_id.clone(),
                first_sequence: sequence,
                expected_records: self.limits.max_segment_records as u64,
                sync_policy: self.sync_policy,
            };
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)
                .map_err(|e| SegmentError::Io(e.to_string()))?;
            file.write_all(format!("{}\n", json_line(&header)?).as_bytes())
                .map_err(|e| SegmentError::Io(e.to_string()))?;
            if self.sync_policy == SyncPolicy::Full {
                sync_file(&file)?;
            }
            if self.fault == SegmentFault::FailAfterHeader {
                return Err(SegmentError::FaultInjected(
                    "failed after header".to_owned(),
                ));
            }
            self.open = Some(OpenSegment {
                temp,
                frontier: SegmentFrontier {
                    segment: segment_name(sequence, sequence),
                    first_sequence: sequence,
                    last_sequence: sequence,
                    record_count: 0,
                    frames_checksum: String::new(),
                },
                frames: Vec::new(),
                bytes: 0,
            });
        }

        let frame = SegmentFrame {
            sequence,
            checksum: checksum_of(&record).map_err(|e| SegmentError::Serialize(e.to_string()))?,
            record: record.clone(),
        };
        let line = format!("{}\n", json_line(&frame)?);
        if self.fault == SegmentFault::FailAfterFrames {
            return Err(SegmentError::FaultInjected(
                "failed after frames".to_owned(),
            ));
        }
        {
            let Some(segment) = self.open.as_mut() else {
                return Err(SegmentError::Io("open segment missing".to_owned()));
            };
            let mut file = OpenOptions::new()
                .append(true)
                .open(&segment.temp)
                .map_err(|e| SegmentError::Io(e.to_string()))?;
            if self.fault == SegmentFault::CorruptFrame {
                file.write_all(b"{invalid}\n")
                    .map_err(|e| SegmentError::Io(e.to_string()))?;
            } else {
                file.write_all(line.as_bytes())
                    .map_err(|e| SegmentError::Io(e.to_string()))?;
            }
            if self.sync_policy == SyncPolicy::Full {
                sync_file(&file)?;
            }
            segment.bytes += line.len();
            segment.frames.push(frame);
            segment.frontier.last_sequence = sequence;
        }

        for id in &record.committed_event_ids {
            bloom_insert(&mut self.bloom, id);
        }
        self.state.records.push(record.clone());
        self.next_sequence += 1;
        self.snapshot.commit_count += 1;
        self.snapshot.event_count += record.committed_event_ids.len() as u64;
        self.snapshot.quarantine_count += record.quarantines.len() as u64;
        self.snapshot.since_snapshot += 1;
        self.snapshot.materialized = record;
        self.snapshot.bloom_bits = self.bloom.clone();

        let full = {
            let Some(segment) = self.open.as_ref() else {
                return Err(SegmentError::Io("open segment missing".to_owned()));
            };
            segment.frames.len() >= self.limits.max_segment_records
                || segment.bytes >= self.limits.max_segment_bytes
        };
        if full {
            self.finalize_segment()?;
        }
        if self.snapshot.since_snapshot >= self.limits.snapshot_every_commits {
            self.write_snapshot()?;
        }
        Ok(())
    }

    fn finalize_segment(&mut self) -> Result<(), SegmentError> {
        let Some(segment) = self.open.as_mut() else {
            return Err(SegmentError::Io("open segment missing".to_owned()));
        };
        let frames_checksum = frames_checksum(&segment.frames);
        let footer = SegmentFooter {
            record_count: segment.frames.len() as u64,
            last_sequence: segment.frontier.last_sequence,
            frames_checksum: frames_checksum.clone(),
        };
        if self.fault == SegmentFault::FailBeforeFooter {
            return Err(SegmentError::FaultInjected(
                "failed before footer".to_owned(),
            ));
        }
        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(&segment.temp)
                .map_err(|e| SegmentError::Io(e.to_string()))?;
            file.write_all(format!("{}\n", json_line(&footer)?).as_bytes())
                .map_err(|e| SegmentError::Io(e.to_string()))?;
            if self.sync_policy == SyncPolicy::Full {
                sync_file(&file)?;
            }
        }
        if self.fault == SegmentFault::FailAfterFooterBeforeRename {
            return Err(SegmentError::FaultInjected(
                "failed before rename".to_owned(),
            ));
        }
        let segments = self.directory.join("segments");
        let final_path = segments.join(&segment.frontier.segment);
        std::fs::rename(&segment.temp, &final_path).map_err(|e| SegmentError::Io(e.to_string()))?;
        if self.fault == SegmentFault::FailAfterRenameBeforeDirSync {
            return Err(SegmentError::FaultInjected(
                "failed before dir sync".to_owned(),
            ));
        }
        if self.sync_policy == SyncPolicy::Full {
            sync_dir(&segments)?;
        }
        let mut finalized = segment.frontier.clone();
        finalized.record_count = segment.frames.len() as u64;
        finalized.frames_checksum = frames_checksum;
        self.hot.push(finalized.clone());
        self.snapshot.frontier = Some(finalized);
        self.open = None;
        if self.hot.len() > self.limits.max_hot_segments {
            self.rotate_archive()?;
        }
        Ok(())
    }

    fn rotate_archive(&mut self) -> Result<(), SegmentError> {
        let Some(frontier) = self.hot.first().cloned() else {
            return Ok(());
        };
        if self.fault == SegmentFault::FailBeforeArchiveCopy {
            return Err(SegmentError::FaultInjected(
                "failed before archive copy".to_owned(),
            ));
        }
        let archive_dir = self.directory.join("archive");
        std::fs::create_dir_all(&archive_dir).map_err(|e| SegmentError::Io(e.to_string()))?;
        let source = self.directory.join("segments").join(&frontier.segment);
        let bytes = std::fs::read(&source).map_err(|e| SegmentError::Io(e.to_string()))?;
        if !segment_bytes_match(&bytes, &frontier) {
            return Err(SegmentError::MissingAcknowledgedSegment(
                frontier.segment.clone(),
            ));
        }
        let temp = archive_dir.join(format!(".tmp-{}", frontier.segment));
        std::fs::write(&temp, &bytes).map_err(|e| SegmentError::Io(e.to_string()))?;
        if self.sync_policy == SyncPolicy::Full {
            sync_file(&File::open(&temp).map_err(|e| SegmentError::Io(e.to_string()))?)?;
        }
        let target = archive_dir.join(&frontier.segment);
        std::fs::rename(&temp, &target).map_err(|e| SegmentError::Io(e.to_string()))?;
        if self.sync_policy == SyncPolicy::Full {
            sync_dir(&archive_dir)?;
        }
        if self.fault == SegmentFault::FailAfterArchiveCopyBeforeManifest {
            return Err(SegmentError::FaultInjected(
                "failed before archive manifest".to_owned(),
            ));
        }
        let mut manifest = ArchiveManifest {
            schema_version: ARCHIVE_SCHEMA_VERSION,
            entries: self.archives.clone(),
            checksum: String::new(),
        };
        manifest.entries.push(ArchiveEntry {
            path: frontier.segment.clone(),
            first_sequence: frontier.first_sequence,
            last_sequence: frontier.last_sequence,
            record_count: frontier.record_count,
            checksum: hex_digest(&bytes),
        });
        manifest.entries.sort_by_key(|entry| entry.first_sequence);
        manifest.checksum = manifest_checksum(&manifest);
        write_json_atomic(&archive_dir.join("manifest.json"), &manifest)
            .map_err(|e| SegmentError::Io(e.to_string()))?;
        if self.sync_policy == SyncPolicy::Full {
            sync_dir(&archive_dir)?;
        }
        self.archives = manifest.entries;
        std::fs::remove_file(&source).map_err(|e| SegmentError::Io(e.to_string()))?;
        if self.sync_policy == SyncPolicy::Full {
            sync_dir(&self.directory.join("segments"))?;
        }
        self.hot.remove(0);
        Ok(())
    }

    fn write_snapshot(&mut self) -> Result<(), SegmentError> {
        let snapshots = self.directory.join("snapshots");
        std::fs::create_dir_all(&snapshots).map_err(|e| SegmentError::Io(e.to_string()))?;
        let mut ready = self.snapshot.clone();
        ready.since_snapshot = 0;
        ready.checksum = snapshot_checksum(&ready);
        write_json_atomic(&snapshots.join("current.json"), &ready)
            .map_err(|e| SegmentError::Io(e.to_string()))?;
        if self.sync_policy == SyncPolicy::Full {
            sync_dir(&snapshots)?;
        }
        self.snapshot = ready;
        self.state.records.truncate(1);
        Ok(())
    }

    pub fn verify(&self) -> Result<(), SegmentError> {
        Self::open(
            &self.directory,
            self.binding.clone(),
            self.sync_policy,
            self.limits,
        )
        .map(|_| ())
    }

    /// Verify the archive and copy every segment plus its manifest into
    /// `destination`, returning the restored file names.
    pub fn restore_archive(&self, destination: &Path) -> Result<Vec<String>, SegmentError> {
        std::fs::create_dir_all(destination).map_err(|e| SegmentError::Io(e.to_string()))?;
        let manifest = ArchiveManifest {
            schema_version: ARCHIVE_SCHEMA_VERSION,
            entries: self.archives.clone(),
            checksum: manifest_checksum(&ArchiveManifest {
                schema_version: ARCHIVE_SCHEMA_VERSION,
                entries: self.archives.clone(),
                checksum: String::new(),
            }),
        };
        let mut restored = vec!["manifest.json".to_owned()];
        write_json_atomic(&destination.join("manifest.json"), &manifest)
            .map_err(|e| SegmentError::Io(e.to_string()))?;
        for entry in &self.archives {
            let source = self.directory.join("archive").join(safe_name(&entry.path)?);
            let bytes = std::fs::read(&source).map_err(|e| SegmentError::Io(e.to_string()))?;
            if hex_digest(&bytes) != entry.checksum {
                return Err(SegmentError::MissingAcknowledgedSegment(entry.path.clone()));
            }
            let temp = destination.join(format!(".tmp-{}", entry.path));
            std::fs::write(&temp, &bytes).map_err(|e| SegmentError::Io(e.to_string()))?;
            std::fs::rename(&temp, destination.join(safe_name(&entry.path)?))
                .map_err(|e| SegmentError::Io(e.to_string()))?;
            restored.push(entry.path.clone());
        }
        Ok(restored)
    }
}

fn safe_name(name: &str) -> Result<&str, SegmentError> {
    if name.contains('/') || name.contains('\\') || name == ".." || name.contains("..") {
        return Err(SegmentError::InvalidArchive {
            path: name.to_owned(),
            reason: "unsafe path component".to_owned(),
        });
    }
    Ok(name)
}

impl CommitSink for SegmentedStore {
    fn commit(&mut self, intent: &CommitIntent) -> Result<(), String> {
        let checkpoint = DurableCheckpoint {
            schema_version: COMMIT_SCHEMA_VERSION,
            source_id: self.binding.source_id.clone(),
            source_fingerprint: self.binding.source_fingerprint.clone(),
            target_id: intent.target_id.clone(),
            last_committed_sequence: intent.next_sequence,
            last_committed_line: intent.next_sequence as usize,
            last_committed_offset: intent.next_offset,
        };
        let record = CommitRecord {
            target_id: intent.target_id.clone(),
            committed_event_ids: intent.committed_event_ids.clone(),
            dispositions: intent.dispositions.clone(),
            quarantines: intent.quarantines.clone(),
            checkpoint,
        };
        SegmentedStore::commit(self, record).map_err(|error| error.to_string())
    }
}

impl DurableStore for SegmentedStore {
    fn durable_state(&self) -> &DurableState {
        self.state()
    }

    fn durable_next_sequence(&self) -> u64 {
        self.next_sequence()
    }

    fn verify_store(&self) -> Result<(), String> {
        self.verify().map_err(|error| error.to_string())
    }
}

fn empty_snapshot(
    binding: &CheckpointBinding,
    materialized: CommitRecord,
    bloom: Vec<u8>,
) -> RecoverySnapshot {
    let mut snapshot = RecoverySnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source_id: binding.source_id.clone(),
        source_fingerprint: binding.source_fingerprint.clone(),
        target_id: binding.target_id.clone(),
        frontier: None,
        materialized,
        bloom_bits: bloom,
        commit_count: 0,
        event_count: 0,
        quarantine_count: 0,
        since_snapshot: 0,
        checksum: String::new(),
    };
    snapshot.checksum = snapshot_checksum(&snapshot);
    snapshot
}

fn snapshot_checksum(snapshot: &RecoverySnapshot) -> String {
    let mut copy = snapshot.clone();
    copy.checksum.clear();
    hex_digest(&serde_json::to_vec(&copy).unwrap_or_default())
}

fn manifest_checksum(manifest: &ArchiveManifest) -> String {
    let mut copy = manifest.clone();
    copy.checksum.clear();
    hex_digest(&serde_json::to_vec(&copy).unwrap_or_default())
}

fn load_snapshot(
    directory: &Path,
    binding: &CheckpointBinding,
) -> Result<Option<RecoverySnapshot>, SegmentError> {
    let path = directory.join("current.json");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&path).map_err(|error| SegmentError::Io(error.to_string()))?;
    let snapshot: RecoverySnapshot =
        serde_json::from_slice(&bytes).map_err(|error| SegmentError::InvalidSnapshot {
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;
    if snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(SegmentError::InvalidSnapshot {
            path: path.display().to_string(),
            reason: format!("unsupported version {}", snapshot.schema_version),
        });
    }
    if snapshot_checksum(&snapshot) != snapshot.checksum {
        return Err(SegmentError::InvalidSnapshot {
            path: path.display().to_string(),
            reason: "checksum mismatch".to_owned(),
        });
    }
    if snapshot.source_id != binding.source_id
        || snapshot.source_fingerprint != binding.source_fingerprint
        || snapshot.target_id != binding.target_id
    {
        return Err(SegmentError::BindingMismatch);
    }
    Ok(Some(snapshot))
}

fn rebuild_bloom(directory: &Path, bloom: &mut [u8]) -> Result<(), SegmentError> {
    if !directory.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(directory).map_err(|e| SegmentError::Io(e.to_string()))? {
        let path = entry.map_err(|e| SegmentError::Io(e.to_string()))?.path();
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !(name.starts_with("seg-") || name.starts_with(".tmp-")) {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| SegmentError::Io(e.to_string()))?;
        for line in BufReader::new(bytes.as_slice())
            .lines()
            .map_while(std::result::Result::ok)
        {
            if let Ok(frame) = serde_json::from_str::<SegmentFrame>(&line) {
                for id in &frame.record.committed_event_ids {
                    bloom_insert(bloom, id);
                }
            }
        }
    }
    Ok(())
}

fn segment_bytes_match(bytes: &[u8], frontier: &SegmentFrontier) -> bool {
    let mut frames = Vec::new();
    for line in BufReader::new(bytes)
        .lines()
        .map_while(std::result::Result::ok)
    {
        if let Ok(frame) = serde_json::from_str::<SegmentFrame>(&line) {
            frames.push(frame);
        }
    }
    frames.len() as u64 == frontier.record_count
        && frames_checksum(&frames) == frontier.frames_checksum
}

fn parse_temp(
    path: &Path,
    binding: &CheckpointBinding,
) -> Result<
    (
        SegmentHeader,
        Vec<SegmentFrame>,
        Option<SegmentFooter>,
        usize,
    ),
    SegmentError,
> {
    let bytes = std::fs::read(path).map_err(|e| SegmentError::Io(e.to_string()))?;
    let mut lines = BufReader::new(bytes.as_slice()).lines();
    let header: SegmentHeader = serde_json::from_str(
        &lines
            .next()
            .transpose()
            .map_err(|e| SegmentError::Io(e.to_string()))?
            .ok_or_else(|| SegmentError::CorruptSegment {
                path: path.display().to_string(),
                reason: "missing header".to_owned(),
            })?,
    )
    .map_err(|e| SegmentError::CorruptSegment {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    if header.schema_version != SEGMENT_SCHEMA_VERSION {
        return Err(SegmentError::UnsupportedVersion {
            path: path.display().to_string(),
            found: header.schema_version,
            expected: SEGMENT_SCHEMA_VERSION,
        });
    }
    if header.source_id != binding.source_id
        || header.source_fingerprint != binding.source_fingerprint
        || header.target_id != binding.target_id
    {
        return Err(SegmentError::BindingMismatch);
    }
    let mut frames = Vec::new();
    let mut footer = None;
    let mut consumed = 0usize;
    for line in lines {
        let line = line.map_err(|e| SegmentError::Io(e.to_string()))?;
        consumed += line.len() + 1;
        if let Ok(frame) = serde_json::from_str::<SegmentFrame>(&line) {
            let expected = header.first_sequence + frames.len() as u64;
            if frame.sequence != expected
                || checksum_of(&frame.record).map_err(|e| SegmentError::Serialize(e.to_string()))?
                    != frame.checksum
            {
                return Err(SegmentError::CorruptSegment {
                    path: path.display().to_string(),
                    reason: "frame sequence or checksum mismatch".to_owned(),
                });
            }
            frames.push(frame);
        } else if let Ok(parsed) = serde_json::from_str::<SegmentFooter>(&line) {
            footer = Some(parsed);
        } else {
            return Err(SegmentError::CorruptSegment {
                path: path.display().to_string(),
                reason: "unrecognized frame".to_owned(),
            });
        }
    }
    if let Some(ref footer) = footer
        && (footer.record_count != frames.len() as u64
            || footer.frames_checksum != frames_checksum(&frames))
    {
        return Err(SegmentError::CorruptSegment {
            path: path.display().to_string(),
            reason: "footer mismatch".to_owned(),
        });
    }
    Ok((header, frames, footer, consumed))
}

fn load_segments(
    directory: &Path,
    binding: &CheckpointBinding,
    covered: u64,
) -> Result<(Vec<SegmentFrontier>, Vec<CommitRecord>), SegmentError> {
    let mut names = Vec::new();
    if directory.exists() {
        for entry in std::fs::read_dir(directory).map_err(|e| SegmentError::Io(e.to_string()))? {
            let name = entry
                .map_err(|e| SegmentError::Io(e.to_string()))?
                .file_name()
                .to_string_lossy()
                .into_owned();
            if name.starts_with("seg-") && name.ends_with(".jsonl") {
                names.push(name);
            }
        }
    }
    names.sort();
    let mut frontiers = Vec::new();
    let mut replay = Vec::new();
    let mut expected = 1u64;
    for name in names {
        let path = directory.join(&name);
        let bytes = std::fs::read(&path).map_err(|e| SegmentError::Io(e.to_string()))?;
        let mut lines = BufReader::new(bytes.as_slice()).lines();
        let header: SegmentHeader = serde_json::from_str(
            &lines
                .next()
                .transpose()
                .map_err(|e| SegmentError::Io(e.to_string()))?
                .ok_or_else(|| SegmentError::CorruptSegment {
                    path: name.clone(),
                    reason: "missing header".to_owned(),
                })?,
        )
        .map_err(|e| SegmentError::CorruptSegment {
            path: name.clone(),
            reason: e.to_string(),
        })?;
        if header.schema_version != SEGMENT_SCHEMA_VERSION {
            return Err(SegmentError::UnsupportedVersion {
                path: name,
                found: header.schema_version,
                expected: SEGMENT_SCHEMA_VERSION,
            });
        }
        let (declared_first, declared_last) = parse_segment_name(&name)?;
        if header.first_sequence != declared_first || header.expected_records == 0 {
            return Err(SegmentError::CorruptSegment {
                path: name.clone(),
                reason: "header range does not match segment name".to_owned(),
            });
        }
        if header.source_id != binding.source_id
            || header.source_fingerprint != binding.source_fingerprint
            || header.target_id != binding.target_id
        {
            return Err(SegmentError::BindingMismatch);
        }
        let mut frames = Vec::new();
        let mut footer = None;
        for line in lines {
            let line = line.map_err(|e| SegmentError::Io(e.to_string()))?;
            if let Ok(frame) = serde_json::from_str::<SegmentFrame>(&line) {
                frames.push(frame);
            } else if let Ok(parsed) = serde_json::from_str::<SegmentFooter>(&line) {
                footer = Some(parsed);
            } else {
                return Err(SegmentError::CorruptSegment {
                    path: name.clone(),
                    reason: "unrecognized frame".to_owned(),
                });
            }
        }
        let footer = footer.ok_or_else(|| SegmentError::CorruptSegment {
            path: name.clone(),
            reason: "missing footer".to_owned(),
        })?;
        if frames.is_empty()
            || frames.len() > header.expected_records as usize
            || footer.record_count != frames.len() as u64
        {
            return Err(SegmentError::CorruptSegment {
                path: name.clone(),
                reason: "record count mismatch".to_owned(),
            });
        }
        for (index, frame) in frames.iter().enumerate() {
            if frame.sequence != header.first_sequence + index as u64 {
                return Err(SegmentError::CorruptSegment {
                    path: name.clone(),
                    reason: "frame sequence out of range".to_owned(),
                });
            }
            let computed =
                checksum_of(&frame.record).map_err(|e| SegmentError::Serialize(e.to_string()))?;
            if frame.checksum != computed {
                return Err(SegmentError::CorruptSegment {
                    path: name.clone(),
                    reason: "frame checksum mismatch".to_owned(),
                });
            }
        }
        let computed = frames_checksum(&frames);
        if footer.frames_checksum != computed || footer.last_sequence != declared_last {
            return Err(SegmentError::CorruptSegment {
                path: name.clone(),
                reason: "footer checksum or range mismatch".to_owned(),
            });
        }
        if header.first_sequence != expected {
            return Err(SegmentError::SequenceGap {
                expected,
                found: header.first_sequence,
            });
        }
        expected = declared_last + 1;
        let frontier = SegmentFrontier {
            segment: name,
            first_sequence: declared_first,
            last_sequence: declared_last,
            record_count: frames.len() as u64,
            frames_checksum: computed,
        };
        if declared_first > covered {
            replay.extend(frames.into_iter().map(|frame| frame.record));
        }
        frontiers.push(frontier);
    }
    Ok((frontiers, replay))
}

fn parse_segment_name(name: &str) -> Result<(u64, u64), SegmentError> {
    let stem = name
        .strip_prefix("seg-")
        .and_then(|value| value.strip_suffix(".jsonl"))
        .ok_or_else(|| SegmentError::CorruptSegment {
            path: name.to_owned(),
            reason: "invalid segment name".to_owned(),
        })?;
    let mut parts = stem.split('-');
    let first = parts.next().and_then(|value| value.parse().ok());
    let last = parts.next().and_then(|value| value.parse().ok());
    match (first, last, parts.next()) {
        (Some(first), Some(last), None) => Ok((first, last)),
        _ => Err(SegmentError::CorruptSegment {
            path: name.to_owned(),
            reason: "invalid segment range".to_owned(),
        }),
    }
}

fn load_archive(directory: &Path) -> Result<Vec<ArchiveEntry>, SegmentError> {
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let path = directory.join("manifest.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path).map_err(|e| SegmentError::Io(e.to_string()))?;
    let manifest: ArchiveManifest =
        serde_json::from_slice(&bytes).map_err(|e| SegmentError::InvalidArchive {
            path: path.display().to_string(),
            reason: e.to_string(),
        })?;
    if manifest.schema_version != ARCHIVE_SCHEMA_VERSION {
        return Err(SegmentError::InvalidArchive {
            path: path.display().to_string(),
            reason: "unsupported version".to_owned(),
        });
    }
    if manifest_checksum(&manifest) != manifest.checksum {
        return Err(SegmentError::InvalidArchive {
            path: path.display().to_string(),
            reason: "checksum mismatch".to_owned(),
        });
    }
    let mut expected = 1u64;
    for entry in &manifest.entries {
        let name = safe_name(&entry.path)?;
        if entry.first_sequence != expected || entry.last_sequence < entry.first_sequence {
            return Err(SegmentError::InvalidArchive {
                path: entry.path.clone(),
                reason: "sequence discontinuity".to_owned(),
            });
        }
        let segment = directory.join(name);
        if !segment.exists() {
            return Err(SegmentError::MissingAcknowledgedSegment(entry.path.clone()));
        }
        let bytes = std::fs::read(&segment).map_err(|e| SegmentError::Io(e.to_string()))?;
        if hex_digest(&bytes) != entry.checksum {
            return Err(SegmentError::MissingAcknowledgedSegment(entry.path.clone()));
        }
        expected = entry.last_sequence + 1;
    }
    Ok(manifest.entries)
}

/// Verify a legacy store and migrate it into the segmented format. Idempotent
/// after interruption: an existing verified segment set is completed by
/// writing the migration marker. Legacy files are never rewritten or deleted.
pub fn migrate_legacy(
    directory: &Path,
    binding: CheckpointBinding,
    sync_policy: SyncPolicy,
    limits: StoreLimits,
) -> Result<SegmentedStore, SegmentError> {
    let marker = directory.join("legacy-migrated.json");
    if marker.exists() {
        return SegmentedStore::open(directory, binding, sync_policy, limits);
    }
    let legacy =
        load_state(directory, Some(&binding)).map_err(|error| SegmentError::InvalidSnapshot {
            path: directory.display().to_string(),
            reason: format!("legacy store failed verification: {error}"),
        })?;
    if legacy.records.is_empty() {
        return Err(SegmentError::InvalidSnapshot {
            path: directory.display().to_string(),
            reason: "legacy store has no records".to_owned(),
        });
    }
    let segments_dir = directory.join("segments");
    let snapshots_dir = directory.join("snapshots");
    std::fs::create_dir_all(&segments_dir).map_err(|e| SegmentError::Io(e.to_string()))?;
    std::fs::create_dir_all(&snapshots_dir).map_err(|e| SegmentError::Io(e.to_string()))?;
    let first = 1u64;
    let last = legacy.records.len() as u64;
    let name = segment_name(first, last);
    let final_path = segments_dir.join(&name);
    if !final_path.exists() {
        let header = SegmentHeader {
            schema_version: SEGMENT_SCHEMA_VERSION,
            source_id: binding.source_id.clone(),
            source_fingerprint: binding.source_fingerprint.clone(),
            target_id: binding.target_id.clone(),
            first_sequence: first,
            expected_records: last,
            sync_policy,
        };
        let frames: Vec<SegmentFrame> = legacy
            .records
            .iter()
            .enumerate()
            .map(|(index, record)| SegmentFrame {
                sequence: index as u64 + 1,
                checksum: checksum_of(record)
                    .map_err(|e| SegmentError::Serialize(e.to_string()))
                    .unwrap_or_default(),
                record: record.clone(),
            })
            .collect();
        let checksum = frames_checksum(&frames);
        let mut text = format!("{}\n", json_line(&header)?);
        for frame in &frames {
            text.push_str(&json_line(frame)?);
            text.push('\n');
        }
        let footer = SegmentFooter {
            record_count: last,
            last_sequence: last,
            frames_checksum: checksum.clone(),
        };
        text.push_str(&json_line(&footer)?);
        text.push('\n');
        std::fs::write(&final_path, text.as_bytes())
            .map_err(|e| SegmentError::Io(e.to_string()))?;
        if sync_policy == SyncPolicy::Full {
            sync_file(&File::open(&final_path).map_err(|e| SegmentError::Io(e.to_string()))?)?;
            sync_dir(&segments_dir)?;
        }
        let Some(materialized) = legacy.records.last().cloned() else {
            return Err(SegmentError::InvalidSnapshot {
                path: directory.display().to_string(),
                reason: "legacy store has no records to migrate".to_owned(),
            });
        };
        let mut bloom = vec![0u8; BLOOM_BITS / 8];
        for record in &legacy.records {
            for id in &record.committed_event_ids {
                bloom_insert(&mut bloom, id);
            }
        }
        let mut snapshot = empty_snapshot(&binding, materialized, bloom);
        snapshot.frontier = Some(SegmentFrontier {
            segment: name.clone(),
            first_sequence: first,
            last_sequence: last,
            record_count: last,
            frames_checksum: checksum,
        });
        snapshot.commit_count = last;
        snapshot.event_count = legacy.committed_event_ids().len() as u64;
        snapshot.quarantine_count = legacy.quarantine_count() as u64;
        let mut ready = snapshot.clone();
        ready.checksum = snapshot_checksum(&ready);
        write_json_atomic(&snapshots_dir.join("current.json"), &ready)
            .map_err(|e| SegmentError::Io(e.to_string()))?;
        if sync_policy == SyncPolicy::Full {
            sync_dir(&snapshots_dir)?;
        }
    }
    std::fs::write(&marker, b"{}\n").map_err(|e| SegmentError::Io(e.to_string()))?;
    SegmentedStore::open_with(directory, binding, sync_policy, limits, true)
}
