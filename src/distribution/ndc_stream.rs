// SPDX-License-Identifier: Apache-2.0
//! Bounded streaming NDC v2 Profile 1 producer with a two-intent lifecycle.
//!
//! This module consumes one canonical record at a time from an
//! [`ArtifactRecordSource`]. The core owns the record buffer: each adapter
//! writes record bytes into a bounded [`RecordSink`] that the core supplies,
//! and canonical JSON is validated only from those core-held bytes. Byte-derived
//! order, expanded and stored digests are updated incrementally as bytes are
//! emitted, and artifacts are written to an owned staging tree. No
//! whole-artifact vector, whole-input record vector or whole-dataset sort
//! exists on this path.
//!
//! A durable [`PreparationIntent`] is written and synced before any source is
//! consumed. A [`SealedPublicationIntent`] is written and synced only after
//! every artifact reached end of stream, every staged file is synced and the
//! manifest and sidecar exist. No receipt, marker or final rename precedes the
//! seal. The existing publication core performs the final rename, receipt,
//! marker and recovery; this module adds no second publication state machine.
//!
//! Numeric maxima are DEFERRED by `WS-STREAM-001`. Production invocation
//! requires an approved profile selected by trusted local policy, and no
//! approved profile is registered. Only finite `TEST_ONLY` profiles admitted
//! by a test harness can drive this path today. `PERF-001` and
//! `OPERATIONALLY_QUALIFIED` remain blocked.

use std::collections::BTreeSet;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::BufReader;
use std::io::Read as IoRead;
use std::io::Write as IoWrite;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::mem::ManuallyDrop;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::FromRawFd;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering as AtomicOrdering;
use std::time::Duration;
use std::time::Instant;

use flate2::Compression as GzipCompression;
use flate2::write::GzEncoder;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest as _;
use sha2::Sha256;
use thiserror::Error;

use crate::distribution::ndc_release::ARTIFACT_DIRECTORY;
use crate::distribution::ndc_release::ArtifactDescriptor;
use crate::distribution::ndc_release::COMPRESSION_VERSION_GZIP;
use crate::distribution::ndc_release::COMPRESSION_VERSION_NONE;
use crate::distribution::ndc_release::CanonicalRecord;
use crate::distribution::ndc_release::ENCODING_NDJSON;
use crate::distribution::ndc_release::INTENT_SCHEMA_VERSION;
use crate::distribution::ndc_release::INTENT_WIRE_PROFILE;
use crate::distribution::ndc_release::JOURNAL_GENESIS_DIGEST;
use crate::distribution::ndc_release::JOURNAL_SCHEMA_VERSION;
use crate::distribution::ndc_release::ProducerError;
use crate::distribution::ndc_release::PublicationEvidence;
use crate::distribution::ndc_release::PublicationIntentV2;
use crate::distribution::ndc_release::PublicationOperation;
use crate::distribution::ndc_release::PublicationReceipt;
use crate::distribution::ndc_release::PublicationState;
use crate::distribution::ndc_release::RealPublicationFs;
use crate::distribution::ndc_release::RecordOrderKey;
use crate::distribution::ndc_release::RecoveryOutcome;
use crate::distribution::ndc_release::ReleaseManifest;
use crate::distribution::ndc_release::SealRequest;
use crate::distribution::ndc_release::SealedManifest;
use crate::distribution::ndc_release::SignatureConfig;
use crate::distribution::ndc_release::build_receipt_evidence;
use crate::distribution::ndc_release::finalize_publication_v2;
use crate::distribution::ndc_release::hex_encode;
use crate::distribution::ndc_release::intent_checksum;
use crate::distribution::ndc_release::io_error;
use crate::distribution::ndc_release::provision_directory;
use crate::distribution::ndc_release::recover_interrupted;
use crate::distribution::ndc_release::reference_key_tuple;
use crate::distribution::ndc_release::seal_manifest;
use crate::distribution::ndc_release::stage_for_state;
use crate::distribution::ndc_release::staging_name;
use crate::distribution::ndc_release::sync_directory;
use crate::distribution::ndc_release::sync_file;
use crate::distribution::ndc_release::validate_artifact_path;
use crate::distribution::ndc_release::validate_artifact_set;
use crate::distribution::ndc_release::validate_record;
use crate::distribution::ndc_release::write_intent;
use crate::distribution::ndc_release::write_new_file;
use crate::distribution::ndc_release::write_stage;
use crate::distribution::ndc_wire::EvidenceSpec;
use crate::distribution::ndc_wire::WireArtifactProfile;
use crate::distribution::ndc_wire::derive_order_key;
use crate::distribution::ndc_wire::map_artifact_profile;
use crate::distribution::ndc_wire::parse_canonical_record;
use crate::distribution::ndc_wire::wire_order_key_to_internal;
use crate::distribution::stream_profile::ProcessingRole;
use crate::distribution::stream_profile::ProfileError;
use crate::distribution::stream_profile::ProfileLimits;
use crate::distribution::stream_profile::ProfileSelection;
use crate::distribution::stream_profile::ResourceProfile;

/// Layout version of the two streaming ledger intents.
pub const STREAM_INTENT_SCHEMA_VERSION: u32 = 1;

/// Evidence literal for a sealed spool. This is ledger-local evidence, not a
/// third intent and not a new publication state.
pub const SPOOL_SEALED: &str = "SPOOL_SEALED";

/// Explicitly unregistered, test-only codec literal. No gzip codec identifier
/// is registered by the ratification, so production gzip invocation fails
/// closed until an owner decision registers one.
pub const TEST_ONLY_CODEC_PROFILE: &str = "TEST_ONLY-GZIP-DEFLATE-FLATE2-1";

/// Stable ordering profile literal reused from the v2 intent surface.
pub const STREAM_ORDERING_PROFILE: &str = INTENT_WIRE_PROFILE;

/// Fail-closed streaming outcomes. Every refusal names the stage that
/// detected it and carries a stable code.
#[derive(Debug, Error)]
pub enum StreamError {
    /// One canonical record failed byte validation.
    #[error("invalid record at index {0}: {1}")]
    InvalidRecord(usize, String),

    /// A byte-derived order key repeated, decreased or left its profile.
    #[error("invalid record order in `{0}`: {1}")]
    InvalidRecordOrder(String, String),

    /// An enforced profile bound was exceeded.
    #[error("stream resource bound exceeded: {0}")]
    PolicyExceeded(String),

    /// The opened source reported a different snapshot identity than the plan.
    #[error("source identity mismatch in `{0}`: planned {1}, observed {2}")]
    SourceIdentityMismatch(String, String, String),

    /// The opened source reported a different stream binding than the plan.
    #[error("source binding mismatch in `{0}`: planned {1}, observed {2}")]
    SourceBindingMismatch(String, String, String),

    /// A replay proof member differed from the preparation commitment.
    #[error("source replay mismatch in `{0}`: {1}")]
    SourceReplayMismatch(String, String),

    /// A non-replayable spool did not recompute its sealed evidence.
    #[error("spool evidence mismatch in `{0}`: {1}")]
    SpoolEvidenceMismatch(String, String),

    /// Cancellation arrived before the seal.
    #[error("publication cancelled before seal at {0}")]
    PublicationCancelled(&'static str),

    /// Cancellation arrived after the seal; no short cut to availability exists.
    #[error("cancellation after seal at {0}; the operation must be reconciled")]
    CancellationAfterSeal(&'static str),

    /// A pre-seal failure preserved with its quarantine disposition.
    #[error(transparent)]
    PreparationQuarantined(#[from] PreparationQuarantineReport),

    /// Quarantine evidence could not be verified as a durable record.
    #[error("quarantine evidence verification failed in `{0}`: {1}")]
    QuarantineVerification(String, String),

    /// Trusted local policy could not select an approved profile.
    #[error("stream profile selection refused: {0}")]
    Profile(#[from] ProfileError),

    /// The compression profile identifier is not registered for invocation.
    #[error("unregistered compression profile: {0}")]
    CodecProfileUnregistered(String),

    /// The canonical wire mapping refused the sealed manifest.
    #[error("canonical wire mapping failed: {0}")]
    WireMapping(String),

    /// The existing publication core refused a transition.
    #[error(transparent)]
    Publication(#[from] ProducerError),

    /// A filesystem operation failed.
    #[error("stream filesystem failure during {0}: {1}")]
    Io(String, #[source] io::Error),
}

impl StreamError {
    /// Stable code for typed fault injection and recovery evidence.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRecord(..) => "STREAM_INVALID_RECORD",
            Self::InvalidRecordOrder(..) => "STREAM_INVALID_ORDER",
            Self::PolicyExceeded(_) => "STREAM_POLICY_EXCEEDED",
            Self::SourceIdentityMismatch(..) => "STREAM_SOURCE_IDENTITY",
            Self::SourceBindingMismatch(..) => "STREAM_SOURCE_BINDING",
            Self::SourceReplayMismatch(..) => "STREAM_REPLAY_MISMATCH",
            Self::SpoolEvidenceMismatch(..) => "STREAM_SPOOL_EVIDENCE",
            Self::PublicationCancelled(_) => "STREAM_CANCELLED_BEFORE_SEAL",
            Self::CancellationAfterSeal(_) => "STREAM_CANCELLED_AFTER_SEAL",
            Self::PreparationQuarantined(_) => "STREAM_PREPARATION_QUARANTINED",
            Self::QuarantineVerification(..) => "STREAM_QUARANTINE_VERIFICATION",
            Self::Profile(error) => error.code(),
            Self::CodecProfileUnregistered(_) => "STREAM_CODEC_UNREGISTERED",
            Self::WireMapping(_) => "STREAM_WIRE_MAPPING",
            Self::Publication(error) => match error {
                ProducerError::PublicationCollision(_) => "PUB_COLLISION",
                ProducerError::UncertainPublication(_) => "PUB_UNCERTAIN",
                ProducerError::ArtifactSetMismatch(_) => "PUB_ARTIFACT_SET",
                _ => "PUB_CORE_FAILURE",
            },
            Self::Io(..) => "STREAM_IO",
        }
    }
}

/// Explicit lifecycle states for one streaming preparation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PreparationState {
    /// The preparation intent is synced and no source has been consumed.
    PreparationIntentDurable,
    /// Artifacts are being produced from bounded source reads.
    Preparing,
    /// The sealed intent is synced and no pre-seal failure was observed.
    Sealed,
    /// A first failure was observed after the preparation intent was durable.
    PreparationFailed,
    /// Quarantine evidence is being committed to durable storage.
    QuarantineCommit,
    /// A verifiable quarantine record is durable.
    QuarantinedDurable,
    /// The quarantine record could not be committed to durable storage.
    QuarantinePending,
}

impl PreparationState {
    /// Stable wire literal for ledger evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreparationIntentDurable => "PREPARATION_INTENT_DURABLE",
            Self::Preparing => "PREPARING",
            Self::Sealed => "SEALED",
            Self::PreparationFailed => "PREPARATION_FAILED",
            Self::QuarantineCommit => "QUARANTINE_COMMIT",
            Self::QuarantinedDurable => "QUARANTINED_DURABLE",
            Self::QuarantinePending => "QUARANTINE_PENDING",
        }
    }
}

impl fmt::Display for PreparationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Source consumption disposition at the first pre-seal failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceConsumptionState {
    /// No source was opened.
    NotStarted,
    /// A source is being read through bounded records.
    Consuming,
    /// Consumption was stopped at a failure.
    Stopped,
    /// Every planned source reached end of stream.
    Complete,
}

impl SourceConsumptionState {
    /// Stable wire literal for ledger evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "NOT_STARTED",
            Self::Consuming => "CONSUMING",
            Self::Stopped => "STOPPED",
            Self::Complete => "COMPLETE",
        }
    }
}

/// First pre-seal failure paired with its quarantine disposition.
#[derive(Debug, Error)]
#[error(
    "preparation failed at {failure_stage} with {failure_code}: {first_failure}; quarantine {quarantine_state}"
)]
pub struct PreparationQuarantineReport {
    /// Explicit preparation state observed at the failure boundary.
    pub observed_state: PreparationState,
    /// Stable code of the preserved first failure.
    pub failure_code: String,
    /// Pipeline stage that reported the preserved first failure.
    pub failure_stage: String,
    /// Display text of the preserved first failure.
    pub first_failure: String,
    /// Quarantine disposition reported apart from the first failure.
    pub quarantine_state: PreparationState,
    /// Digest of the verified quarantine record when durable.
    pub quarantine_record_digest: Option<String>,
}

/// Declaration of whether identical input can be reproduced after a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Replayability {
    /// The source is backed by an immutable snapshot and can be replayed.
    Replayable,
    /// The source cannot be reproduced; a durable spool is mandatory.
    NonReplayable,
}

impl Replayability {
    /// Stable wire literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Replayable => "REPLAYABLE",
            Self::NonReplayable => "NON_REPLAYABLE",
        }
    }
}

/// Durable state recorded in one spool evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SpoolState {
    /// Spool bytes were written and the spool file was synced.
    Written,
    /// The spool directory entry and its ledger evidence are durable.
    Sealed,
}

impl SpoolState {
    /// Stable wire literal.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Written => "WRITTEN",
            Self::Sealed => "SEALED",
        }
    }
}

/// Opaque, versioned source-snapshot identity. No right, truth or completeness
/// claim is carried by this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    /// Opaque snapshot identifier.
    pub snapshot_id: String,
    /// Immutable revision of that snapshot.
    pub revision: String,
}

/// Opaque token shared by snapshot identities and stream bindings.
fn is_opaque_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

impl SourceIdentity {
    /// Validate and construct one opaque source identity.
    pub fn new(
        snapshot_id: impl Into<String>,
        revision: impl Into<String>,
    ) -> Result<Self, StreamError> {
        let snapshot_id = snapshot_id.into();
        let revision = revision.into();
        if !is_opaque_token(&snapshot_id) || !is_opaque_token(&revision) {
            return Err(StreamError::InvalidRecord(
                0,
                "source identity is empty or outside the opaque alphabet".to_owned(),
            ));
        }
        Ok(Self {
            snapshot_id,
            revision,
        })
    }
}

/// Binding of one canonical artifact position to one caller-declared stream.
/// The binding separates streams that report one shared snapshot identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSourceBinding {
    /// Canonical partition of the bound artifact.
    pub logical_partition_id: String,
    /// Canonical shard ordinal of the bound artifact.
    pub shard_ordinal: u32,
    /// Release-relative path of the bound artifact.
    pub path: String,
    /// Snapshot identifier declared by the plan and reported by the source.
    pub source_snapshot_id: String,
    /// Revision declared by the plan and reported by the source.
    pub source_revision: String,
    /// Stream identifier unique within the snapshot.
    pub binding_id: String,
}

/// Compression method declared by one artifact plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionMode {
    /// Store the expanded canonical stream unchanged.
    None,
    /// Store the stream with the registered flate2 gzip framing.
    Gzip,
}

impl CompressionMode {
    /// Version literal emitted in the artifact descriptor.
    #[must_use]
    pub const fn version_str(self) -> &'static str {
        match self {
            Self::None => COMPRESSION_VERSION_NONE,
            Self::Gzip => COMPRESSION_VERSION_GZIP,
        }
    }
}

/// Immutable description of one planned artifact and its replay commitments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactPlan {
    /// Logical partition identity used for canonical artifact order.
    pub logical_partition_id: String,
    /// Shard ordinal within the logical partition.
    pub shard_ordinal: u32,
    /// Release-relative POSIX artifact path.
    pub path: String,
    /// Declared byte-derived ordering profile.
    pub record_order_profile: crate::distribution::ndc_release::RecordOrderProfile,
    /// Declared record encoding.
    pub encoding: String,
    /// Declared compression method.
    pub compression: CompressionMode,
    /// Declared compression profile identifier.
    pub compression_profile_id: String,
    /// Opaque source snapshot identifier.
    pub source_snapshot_id: String,
    /// Immutable source revision.
    pub source_revision: String,
    /// Stream identifier that separates this artifact from other streams on
    /// the same snapshot. The source must report the same identifier.
    pub source_binding_id: String,
    /// Replayability declaration checked against the opened source.
    pub replayability: Replayability,
    /// Digest committed over emitted canonical bytes.
    pub source_content_digest: String,
    /// Committed record count.
    pub expected_record_count: u64,
    /// First committed byte-derived key.
    pub first_order_key: String,
    /// Last committed byte-derived key.
    pub last_order_key: String,
}

impl ArtifactPlan {
    /// Identity reported by the source that must match this plan.
    pub fn source_identity(&self) -> Result<SourceIdentity, StreamError> {
        SourceIdentity::new(
            self.source_snapshot_id.clone(),
            self.source_revision.clone(),
        )
    }

    /// Binding evidence derived from this plan for the two ledger intents.
    #[must_use]
    pub fn source_binding(&self) -> ArtifactSourceBinding {
        ArtifactSourceBinding {
            logical_partition_id: self.logical_partition_id.clone(),
            shard_ordinal: self.shard_ordinal,
            path: self.path.clone(),
            source_snapshot_id: self.source_snapshot_id.clone(),
            source_revision: self.source_revision.clone(),
            binding_id: self.source_binding_id.clone(),
        }
    }
}

/// Bounded, one-record-at-a-time source for one planned artifact.
///
/// The core owns the record buffer. An adapter writes bytes into the
/// [`RecordSink`] supplied by the core instead of returning a pre-materialized
/// record. [`RecordSliceSource`] adapts already-materialized bytes, but it does
/// not bound allocation that a caller performed before the write.
pub trait ArtifactRecordSource {
    /// Opaque snapshot identity and revision; must equal the plan values.
    fn source_identity(&self) -> SourceIdentity;
    /// Stream binding reported by this source; must equal the plan value.
    fn source_binding_id(&self) -> String;
    /// Declaration checked against the plan; a weaker declaration fails closed.
    fn replayability(&self) -> Replayability;
    /// Write one canonical record, without a line terminator, into the
    /// core-provided sink. Return `true` when a record was written and `false`
    /// at end of stream. A call after end of stream is a typed state error.
    fn write_next_record(&mut self, sink: &mut RecordSink<'_>) -> Result<bool, StreamError>;
    /// Declared bound checked by the core before the source is consumed.
    fn max_record_bytes(&self) -> u64;
}

/// Core-owned bounded buffer for one canonical record.
///
/// The core allocates and reuses the backing vector. Each write is checked
/// before the buffer grows, so one oversized write and a sequence of smaller
/// writes that cross the bound take the same refusal path. An adapter cannot
/// supply record bytes by any route other than this sink.
pub struct RecordSink<'a> {
    buffer: &'a mut Vec<u8>,
    max_record_bytes: u64,
    index: usize,
    exceeded: bool,
}

impl<'a> RecordSink<'a> {
    /// Wrap one core-owned reusable buffer with the profile record bound.
    #[must_use]
    pub fn new(buffer: &'a mut Vec<u8>, max_record_bytes: u64, index: usize) -> Self {
        Self {
            buffer,
            max_record_bytes,
            index,
            exceeded: false,
        }
    }

    /// Number of record bytes accepted so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether no record bytes were accepted so far.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Whether a write tried to cross the profile record bound.
    #[must_use]
    pub fn exceeded(&self) -> bool {
        self.exceeded
    }

    /// Append one chunk after checked length accounting.
    ///
    /// A chunk that would cross the bound is refused whole; no part of it is
    /// appended. The `exceeded` marker stays observable to the core even when
    /// an adapter ignores the returned error.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        let current = u64::try_from(self.buffer.len())
            .map_err(|_| StreamError::PolicyExceeded("record length overflow".to_owned()))?;
        let added = u64::try_from(bytes.len())
            .map_err(|_| StreamError::PolicyExceeded("write length overflow".to_owned()))?;
        let total = checked_total(current, added, "record bytes")?;
        if total > self.max_record_bytes {
            self.exceeded = true;
            return Err(StreamError::PolicyExceeded(format!(
                "record {} exceeds max_record_bytes {}",
                self.index, self.max_record_bytes
            )));
        }
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }
}

impl IoWrite for RecordSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.push(bytes)
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Compatibility adapter over records a caller already materialized.
///
/// Each record is pushed into the core sink in one bounded write; no extra
/// copy is made here. The caller's own allocation is outside the core bound,
/// so this adapter does not claim memory independence for materialized input.
pub struct RecordSliceSource {
    identity: SourceIdentity,
    binding_id: String,
    replayability: Replayability,
    records: Box<[CanonicalRecord]>,
    max_record_bytes: u64,
    index: usize,
    ended: bool,
}

impl RecordSliceSource {
    /// Take ownership of already-materialized records and declare the stream
    /// identity. The records are moved, not copied again.
    pub fn new(
        records: impl Into<Box<[CanonicalRecord]>>,
        identity: SourceIdentity,
        binding_id: impl Into<String>,
        replayability: Replayability,
    ) -> Result<Self, StreamError> {
        let records = records.into();
        let binding_id = binding_id.into();
        if !is_opaque_token(&binding_id) {
            return Err(StreamError::PolicyExceeded(
                "source binding is empty or outside the opaque alphabet".to_owned(),
            ));
        }
        let max_record_bytes = records.iter().fold(0_u64, |largest, record| {
            let length = u64::try_from(record.bytes.len()).unwrap_or(u64::MAX);
            largest.max(length)
        });
        Ok(Self {
            identity,
            binding_id,
            replayability,
            records,
            max_record_bytes,
            index: 0,
            ended: false,
        })
    }
}

impl ArtifactRecordSource for RecordSliceSource {
    fn source_identity(&self) -> SourceIdentity {
        self.identity.clone()
    }

    fn source_binding_id(&self) -> String {
        self.binding_id.clone()
    }

    fn replayability(&self) -> Replayability {
        self.replayability
    }

    fn write_next_record(&mut self, sink: &mut RecordSink<'_>) -> Result<bool, StreamError> {
        if self.ended {
            return Err(StreamError::InvalidRecord(
                self.index,
                "record requested after end of stream".to_owned(),
            ));
        }
        let Some(record) = self.records.get(self.index) else {
            self.ended = true;
            return Ok(false);
        };
        sink.push(&record.bytes)?;
        self.index = self.index.saturating_add(1);
        Ok(true)
    }

    fn max_record_bytes(&self) -> u64 {
        self.max_record_bytes
    }
}

/// Bounded framer over a byte reader. Bytes are written into the core sink;
/// no unbounded line read or adapter-owned record buffer is used.
pub struct BoundedRecordFramer<R: IoRead> {
    reader: R,
    identity: SourceIdentity,
    binding_id: String,
    replayability: Replayability,
    max_record_bytes: u64,
    ended: bool,
    index: usize,
}

impl<R: IoRead> BoundedRecordFramer<R> {
    /// Construct a framer with a profile-supplied record bound and a declared
    /// stream binding.
    pub fn new(
        reader: R,
        identity: SourceIdentity,
        binding_id: impl Into<String>,
        replayability: Replayability,
        max_record_bytes: u64,
    ) -> Result<Self, StreamError> {
        if max_record_bytes == 0 {
            return Err(StreamError::PolicyExceeded(
                "max_record_bytes must be positive".to_owned(),
            ));
        }
        let binding_id = binding_id.into();
        if !is_opaque_token(&binding_id) {
            return Err(StreamError::PolicyExceeded(
                "source binding is empty or outside the opaque alphabet".to_owned(),
            ));
        }
        Ok(Self {
            reader,
            identity,
            binding_id,
            replayability,
            max_record_bytes,
            ended: false,
            index: 0,
        })
    }
}

impl<R: IoRead> ArtifactRecordSource for BoundedRecordFramer<R> {
    fn source_identity(&self) -> SourceIdentity {
        self.identity.clone()
    }

    fn source_binding_id(&self) -> String {
        self.binding_id.clone()
    }

    fn replayability(&self) -> Replayability {
        self.replayability
    }

    fn write_next_record(&mut self, sink: &mut RecordSink<'_>) -> Result<bool, StreamError> {
        if self.ended {
            return Err(StreamError::InvalidRecord(
                self.index,
                "record requested after end of stream".to_owned(),
            ));
        }
        let mut byte = [0_u8; 1];
        loop {
            match self.reader.read(&mut byte) {
                Ok(0) => {
                    if sink.is_empty() {
                        self.ended = true;
                        return Ok(false);
                    }
                    return Err(StreamError::InvalidRecord(
                        self.index,
                        "trailing record without LF terminator".to_owned(),
                    ));
                }
                Ok(1) => {
                    if byte[0] == b'\n' {
                        if sink.is_empty() {
                            return Err(StreamError::InvalidRecord(
                                self.index,
                                "empty record".to_owned(),
                            ));
                        }
                        self.index = self.index.saturating_add(1);
                        return Ok(true);
                    }
                    sink.push(&byte)?;
                }
                Ok(_) => {
                    return Err(StreamError::Io(
                        "framer read".to_owned(),
                        io::Error::other("a one-byte read returned multiple bytes"),
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(StreamError::Io("framer read".to_owned(), error)),
            }
        }
    }

    fn max_record_bytes(&self) -> u64 {
        self.max_record_bytes
    }
}

/// Commitments proven against the preparation intent before publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayProof {
    /// Binding of the source that emitted this proof.
    pub source_binding_id: String,
    /// Digest over emitted canonical bytes in order.
    pub source_content_digest: String,
    /// Observed record count.
    pub record_count: u64,
    /// First derived order key.
    pub first_order_key: String,
    /// Last derived order key.
    pub last_order_key: String,
}

/// Compare one replay proof with the immutable plan commitments.
pub fn verify_replay_proof(
    path: &str,
    plan: &ArtifactPlan,
    proof: &ReplayProof,
) -> Result<(), StreamError> {
    if proof.source_binding_id != plan.source_binding_id {
        return Err(StreamError::SourceBindingMismatch(
            path.to_owned(),
            plan.source_binding_id.clone(),
            proof.source_binding_id.clone(),
        ));
    }
    if proof.source_content_digest != plan.source_content_digest {
        return Err(StreamError::SourceReplayMismatch(
            path.to_owned(),
            "source_content_digest".to_owned(),
        ));
    }
    if proof.record_count != plan.expected_record_count {
        return Err(StreamError::SourceReplayMismatch(
            path.to_owned(),
            "record count".to_owned(),
        ));
    }
    if proof.first_order_key != plan.first_order_key {
        return Err(StreamError::SourceReplayMismatch(
            path.to_owned(),
            "first order key".to_owned(),
        ));
    }
    if proof.last_order_key != plan.last_order_key {
        return Err(StreamError::SourceReplayMismatch(
            path.to_owned(),
            "last order key".to_owned(),
        ));
    }
    Ok(())
}

/// Incremental byte-derived order check with one predecessor in fixed state.
struct OrderTracker {
    wire_profile: WireArtifactProfile,
    previous: Option<RecordOrderKey>,
    first: Option<String>,
    last: Option<String>,
}

impl OrderTracker {
    fn new(plan: &ArtifactPlan) -> Result<Self, StreamError> {
        let wire_profile = map_artifact_profile(&plan.record_order_profile).map_err(|error| {
            StreamError::InvalidRecordOrder(path_lossy(&plan.path), error.to_string())
        })?;
        Ok(Self {
            wire_profile,
            previous: None,
            first: None,
            last: None,
        })
    }

    fn observe(
        &mut self,
        path: &str,
        bytes: &[u8],
        index: usize,
        policy: &crate::distribution::ndc_release::ResourcePolicy,
    ) -> Result<String, StreamError> {
        validate_record(bytes, index, policy)
            .map_err(|error| StreamError::InvalidRecord(index, error.to_string()))?;
        let parsed = parse_canonical_record(bytes, policy)
            .map_err(|error| StreamError::InvalidRecord(index, error.to_string()))?;
        let derived = derive_order_key(&parsed, &self.wire_profile)
            .map_err(|error| StreamError::InvalidRecordOrder(path.to_owned(), error.to_string()))?;
        let key = wire_order_key_to_internal(&derived).map_err(|error| {
            StreamError::InvalidRecordOrder(
                path.to_owned(),
                format!("key cannot be represented: {error}"),
            )
        })?;
        match (&self.wire_profile, &key) {
            (
                WireArtifactProfile::Sequenced {
                    sequence_domain_id: expected_domain,
                    sequence_epoch: expected_epoch,
                },
                RecordOrderKey::Sequenced {
                    sequence_domain: domain,
                    sequence_epoch: epoch,
                    sequence_number,
                },
            ) => {
                if domain != expected_domain || epoch != expected_epoch {
                    return Err(StreamError::InvalidRecordOrder(
                        path.to_owned(),
                        "sequence domain or epoch mismatch".to_owned(),
                    ));
                }
                if self.previous.as_ref().is_some_and(|old| {
                    matches!(old, RecordOrderKey::Sequenced { sequence_number: old, .. } if *old == *sequence_number)
                }) {
                    return Err(StreamError::InvalidRecordOrder(
                        path.to_owned(),
                        "duplicate sequence position".to_owned(),
                    ));
                }
                if self.previous.as_ref().is_some_and(|old| {
                    matches!(old, RecordOrderKey::Sequenced { sequence_number: old, .. } if *sequence_number < *old)
                }) {
                    return Err(StreamError::InvalidRecordOrder(
                        path.to_owned(),
                        "sequence position moved backwards".to_owned(),
                    ));
                }
            }
            (WireArtifactProfile::Reference, RecordOrderKey::Reference { .. }) => {
                let current = reference_key_tuple(&key).ok_or_else(|| {
                    StreamError::InvalidRecordOrder(
                        path.to_owned(),
                        "invalid reference key".to_owned(),
                    )
                })?;
                let current = (
                    current.0.to_owned(),
                    current.1,
                    current.2,
                    current.3.to_owned(),
                );
                if let Some(RecordOrderKey::Reference { .. }) = &self.previous {
                    let old = reference_key_tuple(self.previous.as_ref().ok_or_else(|| {
                        StreamError::InvalidRecordOrder(
                            path.to_owned(),
                            "missing predecessor".to_owned(),
                        )
                    })?)
                    .ok_or_else(|| {
                        StreamError::InvalidRecordOrder(
                            path.to_owned(),
                            "invalid predecessor".to_owned(),
                        )
                    })?;
                    let old = (old.0.to_owned(), old.1, old.2, old.3.to_owned());
                    if current == old {
                        return Err(StreamError::InvalidRecordOrder(
                            path.to_owned(),
                            "duplicate reference position".to_owned(),
                        ));
                    }
                    if current < old {
                        return Err(StreamError::InvalidRecordOrder(
                            path.to_owned(),
                            "reference position moved backwards".to_owned(),
                        ));
                    }
                }
            }
            _ => {
                return Err(StreamError::InvalidRecordOrder(
                    path.to_owned(),
                    "derived order key does not match the declared profile".to_owned(),
                ));
            }
        }
        let material = serde_json::to_vec(&key).map_err(|error| {
            StreamError::InvalidRecordOrder(path.to_owned(), format!("key serialization: {error}"))
        })?;
        let rendered = hex_encode(&sha256_bytes(&material));
        if self.first.is_none() {
            self.first = Some(rendered.clone());
        }
        self.last = Some(rendered.clone());
        self.previous = Some(key);
        Ok(rendered)
    }
}

fn path_lossy(path: &str) -> String {
    path.to_owned()
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn checked_total(current: u64, next: u64, label: &str) -> Result<u64, StreamError> {
    current
        .checked_add(next)
        .ok_or_else(|| StreamError::PolicyExceeded(format!("{label} counter overflow")))
}

fn enforce(current: u64, maximum: u64, label: &str) -> Result<(), StreamError> {
    if current > maximum {
        return Err(StreamError::PolicyExceeded(format!(
            "{label} {current} exceeds {maximum}"
        )));
    }
    Ok(())
}

/// Check one artifact's codec expansion ratio against its stored size.
///
/// The admissible expanded size is `stored_bytes * max_expansion_ratio`,
/// widened to `u128` so a product of two `u64` profile values cannot wrap. A
/// stream with zero stored bytes admits zero expanded bytes: the empty
/// artifact has no bytes on either side of the codec. The check runs after the
/// codec is finished and before any replay proof, manifest or seal is built.
fn enforce_expansion_ratio(
    expanded_bytes: u64,
    stored_bytes: u64,
    max_expansion_ratio: u64,
) -> Result<(), StreamError> {
    if stored_bytes == 0 && expanded_bytes != 0 {
        return Err(StreamError::PolicyExceeded(
            "max_expansion_ratio zero stored bytes with expanded bytes".to_owned(),
        ));
    }
    let allowed = u128::from(stored_bytes) * u128::from(max_expansion_ratio);
    let observed = u128::from(expanded_bytes);
    if observed > allowed {
        return Err(StreamError::PolicyExceeded(format!(
            "max_expansion_ratio {observed} exceeds {allowed} for {stored_bytes} stored bytes at ratio {max_expansion_ratio}"
        )));
    }
    Ok(())
}

/// Stored-byte sink that digests and bounds bytes on their way to the staging
/// file. The compressor writes into this sink; no whole-artifact buffer exists.
struct StoredSink<'a> {
    writer: &'a mut File,
    expanded_hasher: Sha256,
    stored_hasher: Sha256,
    expanded_bytes: u64,
    stored_bytes: u64,
    release_stored: &'a mut u64,
    disk_bytes: &'a mut u64,
    limits: &'a ProfileLimits,
}

impl IoWrite for StoredSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let length = u64::try_from(buf.len())
            .map_err(|_| io::Error::other("stored chunk exceeds addressable length"))?;
        let stored =
            checked_total(self.stored_bytes, length, "stored bytes").map_err(io::Error::other)?;
        enforce(
            stored,
            self.limits.max_stored_bytes_per_artifact(),
            "max_stored_bytes_per_artifact",
        )
        .map_err(io::Error::other)?;
        let release = checked_total(*self.release_stored, length, "release stored bytes")
            .map_err(io::Error::other)?;
        enforce(
            release,
            self.limits.max_stored_bytes_per_release(),
            "max_stored_bytes_per_release",
        )
        .map_err(io::Error::other)?;
        let disk =
            checked_total(*self.disk_bytes, length, "temp disk bytes").map_err(io::Error::other)?;
        enforce(disk, self.limits.temp_disk_bytes(), "temp_disk_bytes")
            .map_err(io::Error::other)?;
        self.writer.write_all(buf)?;
        self.stored_hasher.update(buf);
        self.stored_bytes = stored;
        *self.release_stored = release;
        *self.disk_bytes = disk;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// Inputs to one artifact streaming pass.
struct ArtifactStreamInput<'a> {
    source: &'a mut dyn ArtifactRecordSource,
    plan: &'a ArtifactPlan,
    expected_replayability: Replayability,
    path: &'a Path,
    dataset_hasher: &'a mut Sha256,
    release_expanded: &'a mut u64,
    release_stored: &'a mut u64,
    release_records: &'a mut u64,
    disk_bytes: &'a mut u64,
    profile: &'a ResourceProfile,
    cancellation: &'a Cancellation,
    faults: &'a StreamFaults,
    evidence: &'a mut PreparationEvidence,
    started: Instant,
}

/// Fixed-size result of one artifact streaming pass.
struct ArtifactStreamResult {
    descriptor: crate::distribution::ndc_release::ArtifactDescriptor,
    proof: ReplayProof,
}

fn stream_artifact(input: ArtifactStreamInput<'_>) -> Result<ArtifactStreamResult, StreamError> {
    let limits = input.profile.limits();
    let policy = limits.to_resource_policy();
    let planned = input.plan.source_identity()?;
    let observed = input.source.source_identity();
    if planned != observed {
        return Err(StreamError::SourceIdentityMismatch(
            input.plan.path.clone(),
            format!("{}#{}", planned.snapshot_id, planned.revision),
            format!("{}#{}", observed.snapshot_id, observed.revision),
        ));
    }
    if input.source.replayability() != input.expected_replayability {
        return Err(StreamError::SourceIdentityMismatch(
            input.plan.path.clone(),
            input.expected_replayability.as_str().to_owned(),
            input.source.replayability().as_str().to_owned(),
        ));
    }
    let planned_binding = input.plan.source_binding_id.as_str();
    let observed_binding = input.source.source_binding_id();
    if planned_binding != observed_binding {
        return Err(StreamError::SourceBindingMismatch(
            input.plan.path.clone(),
            planned_binding.to_owned(),
            observed_binding,
        ));
    }
    enforce(
        input.source.max_record_bytes(),
        limits.max_record_bytes(),
        "source record bound",
    )?;
    input.cancellation.check("artifact-open")?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(input.path)
        .map_err(|error| io_error("open staging artifact", error))?;
    let sink = StoredSink {
        writer: &mut file,
        expanded_hasher: Sha256::new(),
        stored_hasher: Sha256::new(),
        expanded_bytes: 0,
        stored_bytes: 0,
        release_stored: input.release_stored,
        disk_bytes: input.disk_bytes,
        limits,
    };
    let mut tracker = OrderTracker::new(input.plan)?;
    let mut content_hasher = Sha256::new();
    let mut record_count = 0_u64;
    let mut record_buffer = Vec::new();
    let mut written = match input.plan.compression {
        CompressionMode::None => GzipWriter::Plain(sink),
        CompressionMode::Gzip => GzipWriter::Gzip(GzEncoder::new(sink, GzipCompression::default())),
    };
    loop {
        record_buffer.clear();
        let index = usize::try_from(record_count)
            .map_err(|_| StreamError::PolicyExceeded("record index overflow".to_owned()))?;
        let written_record = {
            let mut sink = RecordSink::new(&mut record_buffer, limits.max_record_bytes(), index);
            let result = input.source.write_next_record(&mut sink);
            if sink.exceeded() {
                return Err(StreamError::PolicyExceeded(format!(
                    "record {index} exceeds max_record_bytes {}",
                    limits.max_record_bytes()
                )));
            }
            result
        };
        if !written_record? {
            break;
        }
        input.evidence.stage = FaultStage::SourceRead.as_str();
        injected(input.faults, FaultStage::SourceRead)?;
        let bytes = &record_buffer[..];
        input.cancellation.check("record")?;
        check_duration(input.started, limits)?;
        tracker.observe(&input.plan.path, bytes, index, &policy)?;
        input.evidence.stage = FaultStage::RecordValidation.as_str();
        injected(input.faults, FaultStage::RecordValidation)?;
        let next = u64::try_from(bytes.len())
            .map_err(|_| StreamError::PolicyExceeded("record length overflow".to_owned()))?
            .checked_add(1)
            .ok_or_else(|| {
                StreamError::PolicyExceeded("framed record length overflow".to_owned())
            })?;
        enforce(
            next,
            limits.max_record_bytes().saturating_add(1),
            "framed record with LF",
        )?;
        let expanded = checked_total(written.expanded_bytes(), next, "expanded bytes")?;
        enforce(
            expanded,
            limits.max_expanded_bytes_per_artifact(),
            "max_expanded_bytes_per_artifact",
        )?;
        let release = checked_total(*input.release_expanded, next, "release expanded bytes")?;
        enforce(
            release,
            limits.max_expanded_bytes_per_release(),
            "max_expanded_bytes_per_release",
        )?;
        written.update_expanded(bytes);
        written.write_expanded(bytes)?;
        written.update_expanded(b"\n");
        written.write_expanded(b"\n")?;
        input.evidence.stage = FaultStage::ArtifactWrite.as_str();
        injected(input.faults, FaultStage::ArtifactWrite)?;
        written.set_expanded(expanded);
        *input.release_expanded = release;
        content_hasher.update(bytes);
        content_hasher.update(b"\n");
        input.dataset_hasher.update(bytes);
        input.dataset_hasher.update(b"\n");
        record_count = checked_total(record_count, 1, "record count")?;
        enforce(
            record_count,
            limits.max_records_per_artifact(),
            "max_records_per_artifact",
        )?;
    }
    let release_records = checked_total(*input.release_records, record_count, "release records")?;
    enforce(
        release_records,
        limits.max_records_per_release(),
        "max_records_per_release",
    )?;
    *input.release_records = release_records;
    let sink = written.finish()?;
    input.evidence.stage = FaultStage::Compression.as_str();
    injected(input.faults, FaultStage::Compression)?;
    enforce_expansion_ratio(
        sink.expanded_bytes,
        sink.stored_bytes,
        limits.max_expansion_ratio(),
    )?;
    let proof = ReplayProof {
        source_binding_id: input.plan.source_binding_id.clone(),
        source_content_digest: hex_encode(&content_hasher.finalize()),
        record_count,
        first_order_key: tracker.first.clone().unwrap_or_default(),
        last_order_key: tracker.last.clone().unwrap_or_default(),
    };
    verify_replay_proof(&path_lossy(&input.plan.path), input.plan, &proof)?;
    let StoredSink {
        writer,
        stored_hasher,
        expanded_hasher,
        stored_bytes,
        expanded_bytes,
        ..
    } = sink;
    let stored_sha256 = hex_encode(&stored_hasher.finalize());
    let expanded_sha256 = hex_encode(&expanded_hasher.finalize());
    let _ = writer;
    sync_file(input.path)?;
    input.evidence.stage = FaultStage::FileSync.as_str();
    injected(input.faults, FaultStage::FileSync)?;
    let descriptor = crate::distribution::ndc_release::ArtifactDescriptor {
        logical_partition_id: input.plan.logical_partition_id.clone(),
        shard_ordinal: input.plan.shard_ordinal,
        path: input.plan.path.clone(),
        record_order_profile: input.plan.record_order_profile.clone(),
        encoding: input.plan.encoding.clone(),
        compression: match input.plan.compression {
            CompressionMode::None => crate::distribution::ndc_release::COMPRESSION_NONE.to_owned(),
            CompressionMode::Gzip => crate::distribution::ndc_release::COMPRESSION_GZIP.to_owned(),
        },
        compression_version: input.plan.compression.version_str().to_owned(),
        stored_bytes,
        stored_sha256,
        uncompressed_bytes: expanded_bytes,
        uncompressed_sha256: expanded_sha256,
        record_count,
    };
    Ok(ArtifactStreamResult { descriptor, proof })
}

/// One compression writer with a fixed compressor instance.
enum GzipWriter<'a> {
    Plain(StoredSink<'a>),
    Gzip(GzEncoder<StoredSink<'a>>),
}

impl<'a> GzipWriter<'a> {
    fn expanded_bytes(&self) -> u64 {
        match self {
            Self::Plain(sink) => sink.expanded_bytes,
            Self::Gzip(encoder) => encoder.get_ref().expanded_bytes,
        }
    }

    fn set_expanded(&mut self, value: u64) {
        match self {
            Self::Plain(sink) => sink.expanded_bytes = value,
            Self::Gzip(encoder) => encoder.get_mut().expanded_bytes = value,
        }
    }

    fn update_expanded(&mut self, bytes: &[u8]) {
        match self {
            Self::Plain(sink) => sink.expanded_hasher.update(bytes),
            Self::Gzip(encoder) => encoder.get_mut().expanded_hasher.update(bytes),
        }
    }

    fn write_expanded(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        match self {
            Self::Plain(sink) => sink
                .write_all(bytes)
                .map_err(|error| StreamError::from(io_error("write expanded artifact", error))),
            Self::Gzip(encoder) => encoder
                .write_all(bytes)
                .map_err(|error| StreamError::from(io_error("write gzip artifact", error))),
        }
    }

    fn finish(self) -> Result<StoredSink<'a>, StreamError> {
        match self {
            Self::Plain(sink) => Ok(sink),
            Self::Gzip(encoder) => encoder
                .finish()
                .map_err(|error| StreamError::from(io_error("finalize gzip stream", error))),
        }
    }
}

/// Check the fixed-state ceiling against the role memory budget. The bound
/// covers one core-owned record buffer, the profile-declared handoff slots as
/// a conservative ceiling and one I/O chunk; it is computed from the profile
/// before any source is opened.
fn check_memory_budget(limits: &ProfileLimits) -> Result<(), StreamError> {
    let slots = limits
        .queue_capacity_records()
        .checked_add(1)
        .ok_or_else(|| StreamError::PolicyExceeded("memory budget slot overflow".to_owned()))?;
    let records = limits
        .max_record_bytes()
        .checked_mul(slots)
        .ok_or_else(|| StreamError::PolicyExceeded("memory budget record overflow".to_owned()))?;
    let total = records
        .checked_add(limits.io_chunk_bytes())
        .ok_or_else(|| {
            StreamError::PolicyExceeded("memory budget byte total overflow".to_owned())
        })?;
    enforce(total, limits.memory_budget_bytes(), "memory_budget_bytes")
}

fn check_duration(started: Instant, limits: &ProfileLimits) -> Result<(), StreamError> {
    let budget = Duration::from_secs(limits.max_processing_duration_secs());
    if started.elapsed() > budget {
        return Err(StreamError::PolicyExceeded(
            "max_processing_duration exceeded".to_owned(),
        ));
    }
    Ok(())
}

/// Immutable, self-digested preparation record written before consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparationIntent {
    /// Intent layout version.
    pub schema_version: u32,
    /// Unique operation identity.
    pub operation_id: String,
    /// Complete ordered artifact source plan.
    pub source_plan: Vec<ArtifactPlan>,
    /// Ordered artifact-to-stream bindings for this operation.
    pub source_bindings: Vec<ArtifactSourceBinding>,
    /// Selected role-profile identifier.
    pub resource_profile_id: String,
    /// Canonical digest of the selected role profile.
    pub resource_profile_digest: String,
    /// Processing role that produced the bytes.
    pub role: String,
    /// Registered wire profile literal.
    pub wire_profile_id: String,
    /// Ordering profile literal.
    pub ordering_profile_id: String,
    /// Compression profile literal declared by the operation.
    pub compression_profile_id: String,
    /// Exact planned release-relative file set.
    pub planned_paths: Vec<String>,
    /// Complete ordered inventory of spool plans, one per non-replayable
    /// artifact in canonical artifact order. Empty when no source needs a
    /// spool.
    pub spool_plan: Vec<SpoolPlan>,
    /// Invocation context that admitted the profile.
    pub invocation_context: String,
    /// Digest of canonical bytes with this member excluded.
    pub intent_sha256: String,
}

/// One operation-scoped spool declaration for one non-replayable artifact.
///
/// The plan is fixed in the preparation intent before any source is consumed.
/// The spool file identity depends on the operation, the canonical artifact
/// ordinal and the opaque binding; the artifact path is evidence only and is
/// excluded from spool file naming and resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoolPlan {
    /// Operation whose preparation intent carries this plan.
    pub operation_id: String,
    /// Opaque stream binding of the non-replayable artifact.
    pub artifact_binding_id: String,
    /// Release-relative artifact path carried as evidence, not as a name.
    pub artifact_path: String,
    /// Snapshot identifier declared by the artifact plan.
    pub source_snapshot_id: String,
    /// Immutable revision declared by the artifact plan.
    pub source_revision: String,
    /// Safe spool file name within the caller-configured spool directory.
    pub spool_file_id: String,
    /// Per-spool byte bound drawn from the shared temp-disk budget.
    pub max_spool_bytes: u64,
}

/// Derive one path-independent spool file identity.
///
/// The name combines the opaque operation identity, the canonical artifact
/// ordinal and a digest of the opaque binding. No part of the artifact path
/// reaches the file name, and both caller-supplied tokens are checked against
/// the opaque alphabet before use.
pub fn spool_file_id(
    operation_id: &str,
    artifact_ordinal: usize,
    binding_id: &str,
) -> Result<String, StreamError> {
    if !is_opaque_token(operation_id) {
        return Err(StreamError::PolicyExceeded(
            "operation id is empty or outside the opaque alphabet".to_owned(),
        ));
    }
    if !is_opaque_token(binding_id) {
        return Err(StreamError::PolicyExceeded(
            "spool binding id is empty or outside the opaque alphabet".to_owned(),
        ));
    }
    let ordinal = u64::try_from(artifact_ordinal)
        .map_err(|_| StreamError::PolicyExceeded("spool artifact ordinal overflow".to_owned()))?;
    let material = format!("{operation_id}\0{ordinal}\0{binding_id}");
    let digest = hex_encode(&sha256_bytes(material.as_bytes()));
    Ok(format!(
        "{operation_id}-{ordinal:08}-{}.spool",
        &digest[..16]
    ))
}

/// Build the preparation-time plan for one non-replayable artifact.
fn build_spool_plan(
    operation_id: &str,
    artifact_ordinal: usize,
    plan: &ArtifactPlan,
    max_spool_bytes: u64,
) -> Result<SpoolPlan, StreamError> {
    if plan.replayability != Replayability::NonReplayable {
        return Err(StreamError::PolicyExceeded(
            "a replayable artifact has no spool plan".to_owned(),
        ));
    }
    Ok(SpoolPlan {
        operation_id: operation_id.to_owned(),
        artifact_binding_id: plan.source_binding_id.clone(),
        artifact_path: plan.path.clone(),
        source_snapshot_id: plan.source_snapshot_id.clone(),
        source_revision: plan.source_revision.clone(),
        spool_file_id: spool_file_id(operation_id, artifact_ordinal, &plan.source_binding_id)?,
        max_spool_bytes,
    })
}

/// Immutable, self-digested seal written only after all artifacts are complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedPublicationIntent {
    /// Intent layout version.
    pub schema_version: u32,
    /// The same operation identity as the preparation intent.
    pub operation_id: String,
    /// Digest of the exact preparation record.
    pub preparation_intent_sha256: String,
    /// Digest of the canonical manifest bytes.
    pub manifest_sha256: String,
    /// Digest of the exact detached sidecar bytes.
    pub sidecar_sha256: String,
    /// Dataset digest over ordered uncompressed artifact streams.
    pub data_sha256: String,
    /// Full ordered descriptor inventory.
    pub artifact_inventory: Vec<crate::distribution::ndc_release::ArtifactDescriptor>,
    /// Ordered artifact-to-stream bindings carried from preparation.
    pub source_bindings: Vec<ArtifactSourceBinding>,
    /// Total stored bytes across artifacts.
    pub stored_bytes: u64,
    /// Total expanded bytes across artifacts.
    pub expanded_bytes: u64,
    /// Total records across artifacts.
    pub record_count: u64,
    /// Complete expected publication receipt.
    pub expected_receipt: PublicationReceipt,
    /// Digest of the exact expected receipt bytes.
    pub expected_receipt_sha256: String,
    /// Registered wire profile literal.
    pub wire_profile_id: String,
    /// Resource profile identifier bound at production.
    pub resource_profile_id: String,
    /// Resource profile digest bound at production.
    pub resource_profile_digest: String,
    /// Complete ordered inventory of independent spool evidence records.
    pub spool_evidence: Vec<SpoolEvidence>,
    /// Digest of canonical bytes with this member excluded.
    pub intent_sha256: String,
}

/// Layout version of the typed streaming quarantine record.
pub const QUARANTINE_SCHEMA_VERSION: u32 = 1;

/// Versioned, self-digested evidence for one failed streaming preparation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRecord {
    /// Quarantine layout version.
    pub schema_version: u32,
    /// Operation identity validated before any ledger path was formed.
    pub operation_id: String,
    /// Digest of the preparation intent that preceded the failure.
    pub preparation_intent_digest: String,
    /// Pipeline stage that observed the first failure.
    pub failure_stage: String,
    /// Stable code of the first failure.
    pub failure_code: String,
    /// Display text of the first failure.
    pub first_failure: String,
    /// Staging directory name retained for inspection.
    pub staging_directory: String,
    /// Spool object names retained for inspection.
    pub spool_inventory: Vec<String>,
    /// Partial artifact paths retained for inspection.
    pub partial_artifact_inventory: Vec<String>,
    /// Source consumption disposition at the first failure.
    pub source_consumption_state: SourceConsumptionState,
    /// Bytes observed in retained staging and spool objects.
    pub observed_bytes: u64,
    /// Plan-derived expected expanded byte total.
    pub expected_bytes: u64,
    /// Explicit quarantine state at commit time.
    pub quarantine_state: PreparationState,
    /// Digest of canonical bytes with this member excluded.
    pub record_digest: String,
}

fn canonical_ledger_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, StreamError> {
    serde_json::to_vec(value).map_err(|error| {
        StreamError::Publication(ProducerError::PublicationEvidence(format!(
            "ledger record serialization: {error}"
        )))
    })
}

fn ledger_digest<T: Serialize>(value: &T) -> Result<String, StreamError> {
    Ok(hex_encode(&sha256_bytes(&canonical_ledger_bytes(value)?)))
}

fn preparation_file(ledger: &Path, operation_id: &str) -> PathBuf {
    ledger.join(format!("{operation_id}.preparation.json"))
}

fn sealed_file(ledger: &Path, operation_id: &str) -> PathBuf {
    ledger.join(format!("{operation_id}.sealed.json"))
}

fn spool_evidence_file(ledger: &Path, spool_file_id: &str) -> PathBuf {
    ledger.join(format!("{spool_file_id}.{SPOOL_SEALED}.json"))
}

fn commit_ledger_record(path: &Path, bytes: &[u8], ledger: &Path) -> Result<(), StreamError> {
    write_new_file(path, bytes)?;
    sync_directory(ledger)?;
    Ok(())
}

/// Ledger records use their own caller-bounded budget and are outside the
/// operation temp-disk budget. Each record length is checked against its
/// profile maximum before the write allocates or commits anything.
fn commit_bounded_ledger_record(
    path: &Path,
    bytes: &[u8],
    ledger: &Path,
    maximum: u64,
    label: &str,
) -> Result<(), StreamError> {
    let length = u64::try_from(bytes.len()).map_err(|_| {
        StreamError::PolicyExceeded(format!("{label} length exceeds addressable length"))
    })?;
    enforce(length, maximum, label)?;
    commit_ledger_record(path, bytes, ledger)
}

fn write_preparation_intent(
    ledger: &Path,
    intent: &PreparationIntent,
    maximum: u64,
) -> Result<String, StreamError> {
    let digest = ledger_digest(intent)?;
    let complete = PreparationIntent {
        intent_sha256: digest.clone(),
        ..intent.clone()
    };
    let bytes = canonical_ledger_bytes(&complete)?;
    commit_bounded_ledger_record(
        &preparation_file(ledger, &complete.operation_id),
        &bytes,
        ledger,
        maximum,
        "max_preparation_intent_bytes",
    )?;
    Ok(digest)
}

fn load_preparation_intent(
    ledger: &Path,
    operation_id: &str,
) -> Result<Option<PreparationIntent>, StreamError> {
    let path = preparation_file(ledger, operation_id);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StreamError::Io("read preparation intent".to_owned(), error)),
    };
    let intent: PreparationIntent = serde_json::from_slice(&bytes).map_err(|error| {
        StreamError::Publication(ProducerError::PublicationEvidence(format!(
            "invalid preparation evidence: {error}"
        )))
    })?;
    let without_self_digest = PreparationIntent {
        intent_sha256: String::new(),
        ..intent.clone()
    };
    if ledger_digest(&without_self_digest)? != intent.intent_sha256 {
        return Err(StreamError::Publication(
            ProducerError::PublicationEvidence("preparation intent digest mismatch".to_owned()),
        ));
    }
    Ok(Some(intent))
}

fn write_sealed_intent(
    ledger: &Path,
    intent: &SealedPublicationIntent,
    maximum: u64,
) -> Result<String, StreamError> {
    let digest = ledger_digest(intent)?;
    let complete = SealedPublicationIntent {
        intent_sha256: digest.clone(),
        ..intent.clone()
    };
    let bytes = canonical_ledger_bytes(&complete)?;
    commit_bounded_ledger_record(
        &sealed_file(ledger, &complete.operation_id),
        &bytes,
        ledger,
        maximum,
        "max_sealed_intent_bytes",
    )?;
    Ok(digest)
}

fn load_sealed_intent(
    ledger: &Path,
    operation_id: &str,
) -> Result<Option<SealedPublicationIntent>, StreamError> {
    let path = sealed_file(ledger, operation_id);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StreamError::Io("read sealed intent".to_owned(), error)),
    };
    let intent: SealedPublicationIntent = serde_json::from_slice(&bytes).map_err(|error| {
        StreamError::Publication(ProducerError::PublicationEvidence(format!(
            "invalid sealed evidence: {error}"
        )))
    })?;
    let without_self_digest = SealedPublicationIntent {
        intent_sha256: String::new(),
        ..intent.clone()
    };
    if ledger_digest(&without_self_digest)? != intent.intent_sha256 {
        return Err(StreamError::Publication(
            ProducerError::PublicationEvidence("sealed intent digest mismatch".to_owned()),
        ));
    }
    Ok(Some(intent))
}

/// Independent, self-digested evidence for one durable spool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoolEvidence {
    /// Safe spool file name derived from operation, ordinal and binding.
    pub spool_file_id: String,
    /// Operation whose preparation chain binds this spool.
    pub operation_id: String,
    /// Opaque binding of the artifact whose source was spooled.
    pub artifact_binding_id: String,
    /// Snapshot identity reported by the spooled source.
    pub source_identity: SourceIdentity,
    /// Exact stored spool byte count.
    pub stored_bytes: u64,
    /// SHA-256 of the exact stored spool bytes.
    pub stored_sha256: String,
    /// Record count written to the spool.
    pub record_count: u64,
    /// First byte-derived key in the spool.
    pub first_order_key: String,
    /// Last byte-derived key in the spool.
    pub last_order_key: String,
    /// Durability state committed with this evidence.
    pub spool_state: SpoolState,
    /// Per-spool byte bound copied from the preparation plan.
    pub max_spool_bytes: u64,
    /// Preparation digest bound into this evidence.
    pub preparation_intent_sha256: String,
    /// Digest of canonical bytes with this member excluded.
    pub evidence_sha256: String,
}

/// Injected failure at one spool durability boundary. Production callers pass
/// `None`; the named points let a harness exercise crash boundaries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SpoolFault {
    /// No injected failure.
    #[default]
    None,
    /// Fail while syncing the spool file, before any directory barrier.
    FailFileSync,
    /// Fail while syncing the spool directory, after the file sync.
    FailDirectorySync,
    /// Fail after the spool directory sync, before evidence is committed.
    FailEvidenceCommit,
}

impl SpoolFault {
    /// Stable label for typed failure messages.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::FailFileSync => "spool file sync",
            Self::FailDirectorySync => "spool directory sync",
            Self::FailEvidenceCommit => "spool evidence commit",
        }
    }
}

fn seal_spool_evidence(evidence: &SpoolEvidence) -> Result<SpoolEvidence, StreamError> {
    let mut complete = evidence.clone();
    complete.evidence_sha256 = String::new();
    complete.evidence_sha256 = ledger_digest(&complete)?;
    Ok(complete)
}

/// Load and verify one on-disk spool evidence record.
pub fn load_spool_evidence(
    ledger: &Path,
    spool_file_id: &str,
) -> Result<Option<SpoolEvidence>, StreamError> {
    let path = spool_evidence_file(ledger, spool_file_id);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StreamError::Io("read spool evidence".to_owned(), error)),
    };
    let evidence: SpoolEvidence = serde_json::from_slice(&bytes).map_err(|error| {
        StreamError::Publication(ProducerError::PublicationEvidence(format!(
            "invalid spool evidence: {error}"
        )))
    })?;
    if seal_spool_evidence(&evidence)? != evidence {
        return Err(StreamError::Publication(
            ProducerError::PublicationEvidence("spool evidence digest mismatch".to_owned()),
        ));
    }
    Ok(Some(evidence))
}

/// Charge one temporary-file write against the single operation-scoped disk
/// budget. Every spool, staged artifact, manifest and sidecar uses this helper.
fn reserve_temp_bytes(
    used: &mut u64,
    amount: u64,
    label: &str,
    maximum: u64,
) -> Result<u64, StreamError> {
    let next = checked_total(*used, amount, label)?;
    enforce(next, maximum, "temp_disk_bytes")?;
    *used = next;
    Ok(next)
}

/// Write a non-replayable source once into its planned spool and commit
/// independent evidence. The order is write, sync file, sync spool directory,
/// commit evidence and sync the ledger directory; no seal precedes that chain.
#[expect(
    clippy::too_many_arguments,
    reason = "explicit spool durability inputs"
)]
pub fn spool_non_replayable(
    source: &mut dyn ArtifactRecordSource,
    plan: &ArtifactPlan,
    spool_plan: &SpoolPlan,
    spool_dir: &Path,
    ledger: &Path,
    preparation_digest: &str,
    profile: &ResourceProfile,
    temp_disk_used: &mut u64,
    fault: SpoolFault,
) -> Result<(SpoolEvidence, BoundedRecordFramer<BufReader<File>>), StreamError> {
    let limits = profile.limits();
    let policy = limits.to_resource_policy();
    if spool_plan.artifact_binding_id != plan.source_binding_id
        || !is_opaque_token(&spool_plan.operation_id)
    {
        return Err(StreamError::SourceBindingMismatch(
            plan.path.clone(),
            plan.source_binding_id.clone(),
            spool_plan.artifact_binding_id.clone(),
        ));
    }
    if spool_plan.artifact_path != plan.path
        || spool_plan.source_snapshot_id != plan.source_snapshot_id
        || spool_plan.source_revision != plan.source_revision
    {
        return Err(StreamError::SpoolEvidenceMismatch(
            spool_plan.spool_file_id.clone(),
            "spool plan does not describe this artifact".to_owned(),
        ));
    }
    let identity = source.source_identity();
    if identity != plan.source_identity()? {
        return Err(StreamError::SourceIdentityMismatch(
            plan.path.clone(),
            plan.source_snapshot_id.clone(),
            identity.snapshot_id,
        ));
    }
    let observed_binding = source.source_binding_id();
    if observed_binding != plan.source_binding_id {
        return Err(StreamError::SourceBindingMismatch(
            plan.path.clone(),
            plan.source_binding_id.clone(),
            observed_binding,
        ));
    }
    let path = spool_dir.join(&spool_plan.spool_file_id);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| io_error("create spool", error))?;
    let mut hasher = Sha256::new();
    let mut stored_bytes = 0_u64;
    let mut records = 0_u64;
    let mut first = String::new();
    let mut last = String::new();
    let mut tracker = OrderTracker::new(plan)?;
    let mut record_buffer = Vec::new();
    loop {
        record_buffer.clear();
        let index = usize::try_from(records)
            .map_err(|_| StreamError::PolicyExceeded("spool record index overflow".to_owned()))?;
        let written_record = {
            let mut sink = RecordSink::new(&mut record_buffer, limits.max_record_bytes(), index);
            let result = source.write_next_record(&mut sink);
            if sink.exceeded() {
                return Err(StreamError::PolicyExceeded(format!(
                    "record {index} exceeds max_record_bytes {}",
                    limits.max_record_bytes()
                )));
            }
            result
        };
        if !written_record? {
            break;
        }
        let bytes = &record_buffer[..];
        tracker.observe(&plan.path, bytes, index, &policy)?;
        let next = u64::try_from(bytes.len())
            .map_err(|_| StreamError::PolicyExceeded("spool record length overflow".to_owned()))?
            .checked_add(1)
            .ok_or_else(|| {
                StreamError::PolicyExceeded("spool framed length overflow".to_owned())
            })?;
        stored_bytes = checked_total(stored_bytes, next, "spool bytes")?;
        enforce(stored_bytes, spool_plan.max_spool_bytes, "max_spool_bytes")?;
        reserve_temp_bytes(
            temp_disk_used,
            next,
            "spool temp disk bytes",
            limits.temp_disk_bytes(),
        )?;
        file.write_all(bytes)
            .map_err(|error| io_error("write spool record", error))?;
        file.write_all(b"\n")
            .map_err(|error| io_error("write spool terminator", error))?;
        hasher.update(bytes);
        hasher.update(b"\n");
        records = checked_total(records, 1, "spool records")?;
        enforce(
            records,
            limits.max_records_per_artifact(),
            "max_records_per_artifact",
        )?;
        if first.is_empty() {
            first = tracker.first.clone().unwrap_or_default();
        }
        last = tracker.last.clone().unwrap_or_default();
    }
    if fault == SpoolFault::FailFileSync {
        return Err(StreamError::Io(
            "injected spool file sync failure".to_owned(),
            io::Error::other(SpoolFault::FailFileSync.label()),
        ));
    }
    file.sync_all()
        .map_err(|error| io_error("sync spool file", error))?;
    drop(file);
    if fault == SpoolFault::FailDirectorySync {
        return Err(StreamError::Io(
            "injected spool directory sync failure".to_owned(),
            io::Error::other(SpoolFault::FailDirectorySync.label()),
        ));
    }
    sync_directory(spool_dir)?;
    if fault == SpoolFault::FailEvidenceCommit {
        return Err(StreamError::Io(
            "injected spool evidence commit failure".to_owned(),
            io::Error::other(SpoolFault::FailEvidenceCommit.label()),
        ));
    }
    let evidence = seal_spool_evidence(&SpoolEvidence {
        spool_file_id: spool_plan.spool_file_id.clone(),
        operation_id: spool_plan.operation_id.clone(),
        artifact_binding_id: plan.source_binding_id.clone(),
        source_identity: identity,
        stored_bytes,
        stored_sha256: hex_encode(&hasher.finalize()),
        record_count: records,
        first_order_key: first,
        last_order_key: last,
        spool_state: SpoolState::Sealed,
        max_spool_bytes: spool_plan.max_spool_bytes,
        preparation_intent_sha256: preparation_digest.to_owned(),
        evidence_sha256: String::new(),
    })?;
    let bytes = canonical_ledger_bytes(&evidence)?;
    commit_bounded_ledger_record(
        &spool_evidence_file(ledger, &evidence.spool_file_id),
        &bytes,
        ledger,
        limits.max_journal_record_bytes(),
        "max_journal_record_bytes",
    )?;
    let framer = BoundedRecordFramer::new(
        BufReader::new(File::open(&path).map_err(|error| io_error("open spool", error))?),
        plan.source_identity()?,
        plan.source_binding_id.clone(),
        Replayability::Replayable,
        limits.max_record_bytes(),
    )?;
    Ok((evidence, framer))
}

/// A descriptor owned for the duration of one spool verification. The
/// directory and its named child are opened without following a final symlink.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct SpoolDescriptor {
    raw: libc::c_int,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl SpoolDescriptor {
    /// Open the spool directory itself without following a symlink.
    #[expect(
        unsafe_code,
        reason = "the spool directory boundary uses the libc open system call"
    )]
    fn open_directory(path: &Path, label: &str) -> Result<Self, StreamError> {
        let name = CString::new(path.as_os_str().as_bytes()).map_err(|error| {
            StreamError::SpoolEvidenceMismatch(
                label.to_owned(),
                format!("spool directory path is not NUL-free: {error}"),
            )
        })?;
        // SAFETY: `name` owns a NUL-terminated buffer that outlives this call.
        // `O_NOFOLLOW` rejects a symlink at the final component, `O_DIRECTORY`
        // requires a directory and `O_CLOEXEC` keeps the fd out of children.
        let raw = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(StreamError::Io(
                format!("open {label} directory"),
                io::Error::last_os_error(),
            ));
        }
        Ok(Self { raw })
    }

    /// Open a named child relative to the directory descriptor.
    #[expect(
        unsafe_code,
        reason = "children are opened relative to a descriptor with the libc openat system call"
    )]
    fn open_child(&self, name: &str, label: &str) -> Result<Self, StreamError> {
        let child = CString::new(name).map_err(|error| {
            StreamError::SpoolEvidenceMismatch(
                label.to_owned(),
                format!("spool file name is not NUL-free: {error}"),
            )
        })?;
        // SAFETY: `self.raw` is a live directory descriptor and `child` is a
        // NUL-terminated buffer that outlives the call. `O_NOFOLLOW` rejects a
        // symlink at the named child.
        let raw = unsafe {
            libc::openat(
                self.raw,
                child.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(StreamError::Io(
                format!("open {label} without following links"),
                io::Error::last_os_error(),
            ));
        }
        Ok(Self { raw })
    }

    /// Classify the object behind this descriptor without following links.
    #[expect(
        unsafe_code,
        reason = "fstat classifies the object behind an already opened descriptor"
    )]
    fn stat(&self, label: &str) -> Result<libc::stat, StreamError> {
        // SAFETY: `libc::stat` is a plain data struct whose zero bit pattern
        // is valid before the system call fills it.
        let mut info: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `info` has the platform stat layout and `raw` is live.
        let status = unsafe { libc::fstat(self.raw, &mut info) };
        if status != 0 {
            return Err(StreamError::Io(
                format!("fstat {label}"),
                io::Error::last_os_error(),
            ));
        }
        Ok(info)
    }

    /// Read one chunk directly through the verified descriptor.
    #[expect(
        unsafe_code,
        reason = "bytes are read from an already opened descriptor with libc read"
    )]
    fn read_chunk(&mut self, buffer: &mut [u8], label: &str) -> Result<usize, StreamError> {
        // SAFETY: `raw` is a live file descriptor and `buffer` is writable for
        // the length passed to the system call.
        let count = unsafe { libc::read(self.raw, buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            return Err(StreamError::Io(
                format!("read {label}"),
                io::Error::last_os_error(),
            ));
        }
        usize::try_from(count).map_err(|_| {
            StreamError::PolicyExceeded("spool read length exceeds addressable length".to_owned())
        })
    }

    /// Return the verified descriptor to its first byte.
    #[expect(
        unsafe_code,
        reason = "rewinding a regular-file descriptor uses the libc lseek system call"
    )]
    fn rewind(&self, label: &str) -> Result<(), StreamError> {
        // SAFETY: `raw` is a live regular-file descriptor held by this value.
        let position = unsafe { libc::lseek(self.raw, 0, libc::SEEK_SET) };
        if position < 0 {
            return Err(StreamError::Io(
                format!("rewind {label}"),
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    /// Transfer the verified descriptor into a standard file reader.
    #[expect(
        unsafe_code,
        reason = "an owned raw descriptor is transferred into a standard File"
    )]
    fn into_file(self) -> File {
        let raw = ManuallyDrop::new(self).raw;
        // SAFETY: `raw` is an owned descriptor with no remaining owner.
        unsafe { File::from_raw_fd(raw) }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for SpoolDescriptor {
    #[expect(
        unsafe_code,
        reason = "closing an owned raw descriptor uses the libc close system call"
    )]
    fn drop(&mut self) {
        // SAFETY: `raw` is an owned descriptor that is not used after close.
        unsafe {
            libc::close(self.raw);
        }
    }
}

/// Verify a sealed spool through its directory descriptor and return the
/// bounded reader over the same verified bytes. A symlink, a non-regular
/// object, an altered digest, a changed byte count or a changed record count
/// refuses the operation before any seal is written.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn verify_spool(
    spool_dir: &Path,
    evidence: &SpoolEvidence,
    profile: &ResourceProfile,
) -> Result<BoundedRecordFramer<BufReader<File>>, StreamError> {
    let limits = profile.limits();
    let label = &evidence.spool_file_id;
    let directory = SpoolDescriptor::open_directory(spool_dir, label)?;
    let mut file = directory.open_child(label, label)?;
    let info = file.stat(label)?;
    if info.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(StreamError::SpoolEvidenceMismatch(
            label.clone(),
            "spool is not a regular file".to_owned(),
        ));
    }
    if info.st_nlink != 1 {
        return Err(StreamError::SpoolEvidenceMismatch(
            label.clone(),
            "spool has an external hard link".to_owned(),
        ));
    }
    let observed = u64::try_from(info.st_size).map_err(|_| {
        StreamError::SpoolEvidenceMismatch(label.clone(), "spool size is negative".to_owned())
    })?;
    if observed != evidence.stored_bytes {
        return Err(StreamError::SpoolEvidenceMismatch(
            label.clone(),
            "spool byte count differs from the sealed evidence".to_owned(),
        ));
    }
    enforce(observed, evidence.max_spool_bytes, "max_spool_bytes")?;
    enforce(observed, limits.temp_disk_bytes(), "temp_disk_bytes")?;
    let chunk = usize::try_from(limits.io_chunk_bytes()).map_err(|_| {
        StreamError::PolicyExceeded("io chunk exceeds addressable length".to_owned())
    })?;
    let mut buffer = vec![0_u8; chunk];
    let mut hasher = Sha256::new();
    let mut read = 0_u64;
    let mut terminators = 0_u64;
    while read < evidence.stored_bytes {
        let remaining = evidence.stored_bytes.saturating_sub(read);
        let allowed = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let count = file.read_chunk(&mut buffer[..allowed], label)?;
        if count == 0 {
            break;
        }
        read = checked_total(
            read,
            u64::try_from(count).map_err(|_| {
                StreamError::PolicyExceeded("spool read length overflow".to_owned())
            })?,
            "spool read",
        )?;
        enforce(read, evidence.stored_bytes, "spool verify read")?;
        hasher.update(&buffer[..count]);
        let seen = u64::try_from(
            buffer[..count]
                .iter()
                .filter(|&&byte| byte == b'\n')
                .count(),
        )
        .map_err(|_| StreamError::PolicyExceeded("spool terminator count overflow".to_owned()))?;
        terminators = checked_total(terminators, seen, "spool verify records")?;
        enforce(terminators, evidence.record_count, "spool verify records")?;
        enforce(
            terminators,
            limits.max_records_per_artifact(),
            "max_records_per_artifact",
        )?;
    }
    if read != evidence.stored_bytes {
        return Err(StreamError::SpoolEvidenceMismatch(
            label.clone(),
            "spool byte count differs from the sealed evidence".to_owned(),
        ));
    }
    if terminators != evidence.record_count {
        return Err(StreamError::SpoolEvidenceMismatch(
            label.clone(),
            "spool record count differs from the sealed evidence".to_owned(),
        ));
    }
    let mut extra = [0_u8; 1];
    if file.read_chunk(&mut extra, label)? != 0 {
        return Err(StreamError::SpoolEvidenceMismatch(
            label.clone(),
            "spool grew past its sealed byte count".to_owned(),
        ));
    }
    if hex_encode(&hasher.finalize()) != evidence.stored_sha256 {
        return Err(StreamError::SpoolEvidenceMismatch(
            label.clone(),
            "spool digest differs from the sealed evidence".to_owned(),
        ));
    }
    file.rewind(label)?;
    BoundedRecordFramer::new(
        BufReader::new(file.into_file()),
        evidence.source_identity.clone(),
        evidence.artifact_binding_id.clone(),
        Replayability::Replayable,
        limits.max_record_bytes(),
    )
}

/// Descriptor-relative verification is unavailable on this target; the
/// streaming path fails closed rather than falling back to path-based reads.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn verify_spool(
    spool_dir: &Path,
    evidence: &SpoolEvidence,
    profile: &ResourceProfile,
) -> Result<BoundedRecordFramer<BufReader<File>>, StreamError> {
    let _ = (spool_dir, profile);
    Err(StreamError::SpoolEvidenceMismatch(
        evidence.spool_file_id.clone(),
        "descriptor-relative spool verification is unavailable on this target".to_owned(),
    ))
}

/// Explicit cancellation signal checked at each durable boundary.
#[derive(Debug, Clone, Default)]
pub struct Cancellation {
    flag: Arc<AtomicBool>,
}

impl Cancellation {
    /// Construct an unsignalled cancellation handle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation. A signal after the seal cannot advance the
    /// operation to availability.
    pub fn cancel(&self) {
        self.flag.store(true, AtomicOrdering::SeqCst);
    }

    /// Whether cancellation was requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(AtomicOrdering::SeqCst)
    }

    fn check(&self, stage: &'static str) -> Result<(), StreamError> {
        if self.is_cancelled() {
            return Err(StreamError::PublicationCancelled(stage));
        }
        Ok(())
    }
}

/// Invocation context. Production has no approved profile to select while the
/// numeric maxima are deferred; only a test harness can admit `TEST_ONLY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationContext {
    /// Owner-approved production invocation.
    Production,
    /// Finite profile admitted by a test harness.
    #[cfg(test)]
    TestHarness,
}

/// Every operation between preparation intent durability and the seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum FaultStage {
    #[default]
    None,
    PreparationIntent,
    StagingCreate,
    StagingSync,
    ArtifactRoot,
    SpoolWrite,
    SpoolVerify,
    ArtifactParent,
    SourceRead,
    RecordValidation,
    ArtifactWrite,
    Compression,
    FileSync,
    ManifestSeal,
    ReceiptBuild,
    ManifestWrite,
    SidecarWrite,
    ArtifactDirSync,
    StagingDirSync,
}

impl FaultStage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::PreparationIntent => "preparation-intent",
            Self::StagingCreate => "staging-create",
            Self::StagingSync => "staging-sync",
            Self::ArtifactRoot => "artifact-root",
            Self::SpoolWrite => "spool-write",
            Self::SpoolVerify => "spool-verify",
            Self::ArtifactParent => "artifact-parent",
            Self::SourceRead => "source-read",
            Self::RecordValidation => "record-validation",
            Self::ArtifactWrite => "artifact-write",
            Self::Compression => "compression",
            Self::FileSync => "file-sync",
            Self::ManifestSeal => "manifest-seal",
            Self::ReceiptBuild => "receipt-build",
            Self::ManifestWrite => "manifest-write",
            Self::SidecarWrite => "sidecar-write",
            Self::ArtifactDirSync => "artifact-dir-sync",
            Self::StagingDirSync => "staging-dir-sync",
        }
    }
}

/// Injected fault points used by cancellation and crash-boundary tests.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StreamFaults {
    /// Stop after the preparation intent is synced and before any consumption.
    pub(crate) crash_before_seal: bool,
    /// Request cancellation immediately before the sealed intent is written.
    pub(crate) cancel_before_seal: bool,
    /// Request cancellation immediately after the sealed intent is written.
    pub(crate) cancel_after_seal: bool,
    /// Fail after the named pre-seal operation with a typed fault.
    pub(crate) fail_after: Option<FaultStage>,
    /// Refuse the quarantine ledger write to exercise the pending state.
    pub(crate) quarantine_commit_fails: bool,
    /// Injected failure at one of the spool durability boundaries.
    pub(crate) spool_fault: SpoolFault,
}

fn injected(faults: &StreamFaults, stage: FaultStage) -> Result<(), StreamError> {
    if faults.fail_after == Some(stage) {
        let message = format!("injected failure after {}", stage.as_str());
        return Err(StreamError::Io(message.clone(), io::Error::other(message)));
    }
    Ok(())
}

/// One streaming publication request. Sources are caller-owned and are
/// consumed through the bounded trait; no record vector is accepted here.
pub struct StreamingBuildRequest<'a> {
    /// Parent directory of final release directories.
    pub release_root: &'a Path,
    /// Producer journal directory for both intents and receipt evidence.
    pub ledger_dir: &'a Path,
    /// Caller-configured trusted spool directory for non-replayable sources.
    pub spool_dir: &'a Path,
    /// Unique operation identity.
    pub operation_id: &'a str,
    /// Commit position bound into the receipt.
    pub commit_position: &'a str,
    /// Complete manifest whose artifact inventory and dataset digest are set
    /// by this pipeline.
    pub manifest: &'a ReleaseManifest,
    /// Typed wire evidence supplement.
    pub evidence: &'a EvidenceSpec,
    /// Event types observed in the validated canonical record streams.
    pub observed_event_types: &'a BTreeSet<String>,
    /// Injected signing material.
    pub signature: SignatureConfig<'a>,
    /// Source objects aligned by input position with `plans`; the pipeline
    /// moves each source with its plan during canonical sorting.
    pub sources: Vec<Box<dyn ArtifactRecordSource + 'a>>,
    /// Immutable artifact plans in any order; each plan declares the binding
    /// of the source at the same input position.
    pub plans: &'a [ArtifactPlan],
    /// Selected role profile.
    pub profile: &'a ResourceProfile,
    /// Trusted local profile policy.
    pub profile_selection: &'a ProfileSelection,
    /// Invocation context that gates test-only profiles.
    pub context: InvocationContext,
    /// Cancellation handle shared with the caller.
    pub cancellation: Cancellation,
    pub(crate) faults: StreamFaults,
}

/// Result of one completed streaming publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingOutcome {
    /// Canonical manifest bytes.
    pub manifest_bytes: Vec<u8>,
    /// Detached sidecar bytes with one trailing LF.
    pub sidecar_bytes: Vec<u8>,
    /// Sorted descriptors with computed digests.
    pub descriptors: Vec<crate::distribution::ndc_release::ArtifactDescriptor>,
    /// Per-artifact source bindings in canonical artifact order.
    pub source_bindings: Vec<ArtifactSourceBinding>,
    /// Durable receipt written by the publication core.
    pub receipt: PublicationReceipt,
    /// Evidence retained for recovery.
    pub recovery_evidence: PublicationEvidence,
    /// Digest of the durable preparation record.
    pub preparation_intent_sha256: String,
    /// Digest of the durable seal.
    pub sealed_intent_sha256: String,
    /// Replay proofs verified for each artifact in canonical order.
    pub replay_proofs: Vec<ReplayProof>,
    /// Independent sealed spool evidence in the same order as the plans.
    pub spool_evidence: Vec<SpoolEvidence>,
}

fn select_profile(request: &StreamingBuildRequest<'_>) -> Result<(), StreamError> {
    let id = request.profile.id();
    match request.context {
        InvocationContext::Production => {
            request
                .profile_selection
                .select_for_production(ProcessingRole::Producer, id)?;
            Err(StreamError::Profile(ProfileError::NoApprovedProfile(
                ProcessingRole::Producer.as_str(),
            )))
        }
        #[cfg(test)]
        InvocationContext::TestHarness => {
            if !id.name().contains("TEST_ONLY") {
                return Err(StreamError::Profile(ProfileError::TestOnlyRefused(
                    id.as_literal(),
                )));
            }
            let selected = request
                .profile_selection
                .select_for_test(ProcessingRole::Producer, id)?;
            if selected != request.profile {
                return Err(StreamError::Profile(ProfileError::DigestMismatch(
                    id.as_literal(),
                )));
            }
            Ok(())
        }
    }
}

/// One plan and the source at its input position. The pair is the unit of
/// canonical sorting, so a plan cannot be paired with another input's
/// source after a permutation.
struct PlannedSource<'a> {
    plan: ArtifactPlan,
    source: Box<dyn ArtifactRecordSource + 'a>,
}

fn validate_sources<'a>(
    request: &StreamingBuildRequest<'a>,
    sources: Vec<Box<dyn ArtifactRecordSource + 'a>>,
) -> Result<Vec<PlannedSource<'a>>, StreamError> {
    let limits = request.profile.limits();
    let count = u64::try_from(request.plans.len())
        .map_err(|_| StreamError::PolicyExceeded("plan count overflow".to_owned()))?;
    enforce(count, limits.max_artifacts_per_release(), "artifact count")?;
    enforce(
        u64::try_from(sources.len())
            .map_err(|_| StreamError::PolicyExceeded("source count overflow".to_owned()))?,
        limits.max_artifacts_per_release(),
        "source count",
    )?;
    if sources.len() != request.plans.len() {
        return Err(StreamError::PolicyExceeded(
            "source count differs from plan count".to_owned(),
        ));
    }
    let policy = limits.to_resource_policy();
    let mut pairs: Vec<PlannedSource<'a>> = request
        .plans
        .iter()
        .cloned()
        .zip(sources)
        .map(|(plan, source)| PlannedSource { plan, source })
        .collect();
    let mut positions = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut bindings = BTreeSet::new();
    for pair in &pairs {
        let plan = &pair.plan;
        validate_artifact_path(&plan.path, &policy).map_err(StreamError::Publication)?;
        if !positions.insert((plan.logical_partition_id.clone(), plan.shard_ordinal)) {
            return Err(StreamError::PolicyExceeded(format!(
                "duplicate artifact position {}#{}",
                plan.logical_partition_id, plan.shard_ordinal
            )));
        }
        if !paths.insert(plan.path.clone()) {
            return Err(StreamError::PolicyExceeded(format!(
                "duplicate artifact path {}",
                plan.path
            )));
        }
        if plan.encoding != ENCODING_NDJSON {
            return Err(StreamError::PolicyExceeded(
                "unsupported artifact encoding".to_owned(),
            ));
        }
        if plan.source_content_digest.len() != 64
            || !plan
                .source_content_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(StreamError::PolicyExceeded(
                "source content digest is not a 64-character hex digest".to_owned(),
            ));
        }
        match plan.compression {
            CompressionMode::None => {
                if plan.compression_profile_id != COMPRESSION_VERSION_NONE {
                    return Err(StreamError::CodecProfileUnregistered(
                        plan.compression_profile_id.clone(),
                    ));
                }
            }
            CompressionMode::Gzip => match request.context {
                InvocationContext::Production => {
                    return Err(StreamError::CodecProfileUnregistered(
                        plan.compression_profile_id.clone(),
                    ));
                }
                #[cfg(test)]
                InvocationContext::TestHarness => {
                    if plan.compression_profile_id != TEST_ONLY_CODEC_PROFILE {
                        return Err(StreamError::CodecProfileUnregistered(
                            plan.compression_profile_id.clone(),
                        ));
                    }
                }
            },
        }
        plan.source_identity()?;
        if !is_opaque_token(&plan.source_binding_id) {
            return Err(StreamError::PolicyExceeded(
                "source binding is empty or outside the opaque alphabet".to_owned(),
            ));
        }
        if !bindings.insert(plan.source_binding_id.clone()) {
            return Err(StreamError::PolicyExceeded(format!(
                "duplicate artifact binding {}",
                plan.source_binding_id
            )));
        }
    }
    pairs.sort_by(|left, right| {
        left.plan
            .logical_partition_id
            .cmp(&right.plan.logical_partition_id)
            .then(left.plan.shard_ordinal.cmp(&right.plan.shard_ordinal))
    });
    Ok(pairs)
}

fn write_compatibility_stages(
    ledger: &Path,
    sealed: &SealedPublicationIntent,
    recovery_intent_sha256: &str,
    receipt: &PublicationReceipt,
    evidence: &PublicationEvidence,
    policy: &crate::distribution::ndc_release::ResourcePolicy,
) -> Result<PublicationOperation, StreamError> {
    let mut operation = PublicationOperation {
        schema_version: JOURNAL_SCHEMA_VERSION,
        sequence_number: 0,
        previous_record_sha256: JOURNAL_GENESIS_DIGEST.to_owned(),
        operation_id: sealed.operation_id.clone(),
        release_id: evidence.release_id.clone(),
        manifest_sha256: sealed.manifest_sha256.clone(),
        data_sha256: sealed.data_sha256.clone(),
        commit_position: receipt.commit_position.clone(),
        staging_directory: staging_name(&sealed.operation_id),
        final_directory: evidence.release_id.clone(),
        supersedes_release_id: receipt.supersedes_release_id.clone(),
        expected_receipt_sha256: evidence.receipt_sha256.clone(),
        intent_sha256: Some(recovery_intent_sha256.to_owned()),
        stage: PublicationState::OperationIntentDurable,
        record_sha256: String::new(),
    };
    write_stage(ledger, &mut operation, 0, policy, &RealPublicationFs)?;
    let mut entry = stage_for_state(&operation, PublicationState::StagingEntryDurable)?;
    write_stage(ledger, &mut entry, 1, policy, &RealPublicationFs)?;
    let mut tree = stage_for_state(&entry, PublicationState::StagingTreeDurable)?;
    write_stage(ledger, &mut tree, 2, policy, &RealPublicationFs)?;
    Ok(tree)
}

/// Evidence gathered while the preparation state advances to the seal.
#[derive(Debug)]
struct PreparationEvidence {
    state: PreparationState,
    staging_directory: String,
    spool_inventory: Vec<String>,
    partial_artifact_inventory: Vec<String>,
    source_consumption_state: SourceConsumptionState,
    observed_bytes: u64,
    expected_bytes: u64,
    stage: &'static str,
}

impl PreparationEvidence {
    fn new(operation_id: &str, expected_bytes: u64) -> Self {
        Self {
            state: PreparationState::PreparationIntentDurable,
            staging_directory: staging_name(operation_id),
            spool_inventory: Vec::new(),
            partial_artifact_inventory: Vec::new(),
            source_consumption_state: SourceConsumptionState::NotStarted,
            observed_bytes: 0,
            expected_bytes,
            stage: FaultStage::PreparationIntent.as_str(),
        }
    }

    fn stop(&mut self) {
        self.source_consumption_state = SourceConsumptionState::Stopped;
    }
}

/// Durable state produced at the seal boundary.
struct PreparedPublication {
    staging: PathBuf,
    sealed_manifest: SealedManifest,
    descriptors: Vec<ArtifactDescriptor>,
    source_bindings: Vec<ArtifactSourceBinding>,
    receipt: PublicationReceipt,
    recovery_evidence: PublicationEvidence,
    sealed: SealedPublicationIntent,
    sealed_digest: String,
    replay_proofs: Vec<ReplayProof>,
    spool_evidence: Vec<SpoolEvidence>,
}

/// Outcome of a quarantine commit attempt reported apart from a failure.
struct QuarantineCommit {
    state: PreparationState,
    record_digest: Option<String>,
}

fn planned_expected_bytes(plans: &[ArtifactPlan], max_record_bytes: u64) -> u64 {
    plans.iter().fold(0_u64, |total, plan| {
        total.saturating_add(
            plan.expected_record_count
                .saturating_add(1)
                .saturating_mul(max_record_bytes),
        )
    })
}

/// Execute one bounded streaming publication with a durable quarantine on
/// every failure between the preparation intent and the seal.
pub fn publish_streaming(
    mut request: StreamingBuildRequest<'_>,
) -> Result<StreamingOutcome, StreamError> {
    let started = Instant::now();
    select_profile(&request)?;
    validate_operation_id(request.operation_id)?;
    if request.signature.key_id != request.manifest.publication_identity.signing_key_id {
        return Err(StreamError::Publication(
            ProducerError::InvalidSignatureConfig(
                "sidecar key id does not match the manifest publisher".to_owned(),
            ),
        ));
    }
    if request.signature.verifying_key != &request.signature.signing_key.verifying_key() {
        return Err(StreamError::Publication(
            ProducerError::InvalidSignatureConfig(
                "injected verifying key does not match the signing key".to_owned(),
            ),
        ));
    }
    let limits = request.profile.limits();
    enforce(
        1,
        limits.max_concurrent_artifacts(),
        "max_concurrent_artifacts",
    )?;
    enforce(1, limits.worker_count(), "worker_count")?;
    check_memory_budget(limits)?;
    request.cancellation.check("operation-start")?;
    check_duration(started, limits)?;
    let sources = std::mem::take(&mut request.sources);
    let pairs = validate_sources(&request, sources)?;
    let plans: Vec<ArtifactPlan> = pairs.iter().map(|pair| pair.plan.clone()).collect();
    let source_bindings: Vec<ArtifactSourceBinding> = pairs
        .iter()
        .map(|pair| pair.plan.source_binding())
        .collect();
    let planned_paths = planned_file_set(&plans);
    let spool_plans: Vec<SpoolPlan> = pairs
        .iter()
        .enumerate()
        .filter(|(_, pair)| pair.plan.replayability == Replayability::NonReplayable)
        .map(|(ordinal, pair)| {
            build_spool_plan(
                request.operation_id,
                ordinal,
                &pair.plan,
                limits.temp_disk_bytes(),
            )
        })
        .collect::<Result<_, _>>()?;

    provision_directory(request.ledger_dir, "stream ledger", &RealPublicationFs)?;
    provision_directory(request.spool_dir, "trusted spool", &RealPublicationFs)?;
    let preparation = PreparationIntent {
        schema_version: STREAM_INTENT_SCHEMA_VERSION,
        operation_id: request.operation_id.to_owned(),
        source_plan: plans.clone(),
        source_bindings: source_bindings.clone(),
        resource_profile_id: request.profile.id().as_literal(),
        resource_profile_digest: hex_encode(request.profile.digest()),
        role: ProcessingRole::Producer.as_str().to_owned(),
        wire_profile_id: INTENT_WIRE_PROFILE.to_owned(),
        ordering_profile_id: STREAM_ORDERING_PROFILE.to_owned(),
        compression_profile_id: plans
            .first()
            .map(|plan| plan.compression_profile_id.clone())
            .unwrap_or_default(),
        planned_paths,
        spool_plan: spool_plans.clone(),
        invocation_context: match request.context {
            InvocationContext::Production => "PRODUCTION".to_owned(),
            #[cfg(test)]
            InvocationContext::TestHarness => "TEST_HARNESS".to_owned(),
        },
        intent_sha256: String::new(),
    };
    let preparation_digest = write_preparation_intent(
        request.ledger_dir,
        &preparation,
        limits.max_preparation_intent_bytes(),
    )?;

    let expected_bytes = planned_expected_bytes(&plans, limits.max_record_bytes());
    let mut evidence = PreparationEvidence::new(request.operation_id, expected_bytes);
    let prepared = match run_preparation(
        &mut request,
        started,
        &preparation_digest,
        pairs,
        source_bindings,
        &mut evidence,
    ) {
        Ok(prepared) => prepared,
        Err(first_failure) => {
            evidence.state = PreparationState::PreparationFailed;
            evidence.stop();
            evidence.state = PreparationState::QuarantineCommit;
            let commit = ensure_quarantine_record(
                request.ledger_dir,
                request.operation_id,
                &preparation_digest,
                &evidence,
                first_failure.code(),
                &first_failure.to_string(),
                request.faults.quarantine_commit_fails,
            );
            evidence.state = commit.state;
            return Err(StreamError::PreparationQuarantined(
                PreparationQuarantineReport {
                    observed_state: evidence.state,
                    failure_code: first_failure.code().to_owned(),
                    failure_stage: evidence.stage.to_owned(),
                    first_failure: first_failure.to_string(),
                    quarantine_state: commit.state,
                    quarantine_record_digest: commit.record_digest,
                },
            ));
        }
    };
    finalize_prepared_publication(&request, prepared)
}

/// Advance from preparation intent durability to the sealed intent. Every
/// error in this window is surfaced to the caller for durable quarantine.
fn run_preparation<'a>(
    request: &mut StreamingBuildRequest<'a>,
    started: Instant,
    preparation_digest: &str,
    mut pairs: Vec<PlannedSource<'a>>,
    source_bindings: Vec<ArtifactSourceBinding>,
    evidence: &mut PreparationEvidence,
) -> Result<PreparedPublication, StreamError> {
    let limits = request.profile.limits();
    let policy = limits.to_resource_policy();
    let plans: Vec<ArtifactPlan> = pairs.iter().map(|pair| pair.plan.clone()).collect();
    let spool_plans: Vec<SpoolPlan> = pairs
        .iter()
        .enumerate()
        .filter(|(_, pair)| pair.plan.replayability == Replayability::NonReplayable)
        .map(|(ordinal, pair)| {
            build_spool_plan(
                request.operation_id,
                ordinal,
                &pair.plan,
                limits.temp_disk_bytes(),
            )
        })
        .collect::<Result<_, _>>()?;

    if request.faults.crash_before_seal {
        evidence.stage = FaultStage::PreparationIntent.as_str();
        return Err(StreamError::Publication(ProducerError::Io(
            "injected crash before seal".to_owned(),
            io::Error::other("injected crash before seal"),
        )));
    }
    evidence.state = PreparationState::Preparing;
    evidence.stage = PreparationState::Preparing.as_str();

    let staging = request
        .release_root
        .join(staging_name(request.operation_id));
    provision_directory(request.release_root, "release root", &RealPublicationFs)?;
    evidence.stage = FaultStage::StagingCreate.as_str();
    fs::create_dir(&staging).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            StreamError::Publication(ProducerError::PublicationEvidence(
                "staging directory already exists".to_owned(),
            ))
        } else {
            io_error("create streaming staging directory", error).into()
        }
    })?;
    injected(&request.faults, FaultStage::StagingCreate)?;
    evidence.stage = FaultStage::StagingSync.as_str();
    sync_directory(request.release_root)?;
    injected(&request.faults, FaultStage::StagingSync)?;
    let artifact_root = staging.join(ARTIFACT_DIRECTORY);
    evidence.stage = FaultStage::ArtifactRoot.as_str();
    fs::create_dir(&artifact_root)
        .map_err(|error| io_error("create staging artifact directory", error))?;
    injected(&request.faults, FaultStage::ArtifactRoot)?;

    let mut dataset_hasher = Sha256::new();
    let mut descriptors = Vec::with_capacity(plans.len());
    let mut replay_proofs = Vec::with_capacity(plans.len());
    let mut release_expanded = 0_u64;
    let mut release_stored = 0_u64;
    let mut release_records = 0_u64;
    let mut disk_bytes = 0_u64;
    evidence.source_consumption_state = SourceConsumptionState::Consuming;
    let mut spooled: Vec<SpoolEvidence> = Vec::new();
    for pair in pairs.iter_mut() {
        request.cancellation.check("artifact-start")?;
        let plan = &pair.plan;
        let source = pair.source.as_mut();
        let mut spool = None;
        if plan.replayability == Replayability::NonReplayable {
            let planned = spool_plans
                .iter()
                .find(|planned| planned.artifact_binding_id == plan.source_binding_id)
                .ok_or_else(|| {
                    StreamError::SpoolEvidenceMismatch(
                        plan.path.clone(),
                        "no preparation spool plan for this artifact".to_owned(),
                    )
                })?;
            if !evidence.spool_inventory.contains(&planned.spool_file_id) {
                evidence.spool_inventory.push(planned.spool_file_id.clone());
            }
            evidence.stage = FaultStage::SpoolWrite.as_str();
            let (spool_evidence, _) = spool_non_replayable(
                source,
                plan,
                planned,
                request.spool_dir,
                request.ledger_dir,
                preparation_digest,
                request.profile,
                &mut disk_bytes,
                request.faults.spool_fault,
            )?;
            evidence.observed_bytes = evidence
                .observed_bytes
                .saturating_add(spool_evidence.stored_bytes);
            injected(&request.faults, FaultStage::SpoolWrite)?;
            evidence.stage = FaultStage::SpoolVerify.as_str();
            let framer = verify_spool(request.spool_dir, &spool_evidence, request.profile)?;
            injected(&request.faults, FaultStage::SpoolVerify)?;
            spooled.push(spool_evidence);
            spool = Some(framer);
        }
        let target = staging.join(&plan.path);
        if let Some(parent) = target.parent() {
            evidence.stage = FaultStage::ArtifactParent.as_str();
            fs::create_dir_all(parent)
                .map_err(|error| io_error("create artifact parent", error))?;
            injected(&request.faults, FaultStage::ArtifactParent)?;
        }
        if !evidence.partial_artifact_inventory.contains(&plan.path) {
            evidence.partial_artifact_inventory.push(plan.path.clone());
        }
        evidence.stage = FaultStage::SourceRead.as_str();
        let expected_replayability = if spool.is_some() {
            Replayability::Replayable
        } else {
            plan.replayability
        };
        let stream: &mut dyn ArtifactRecordSource = match spool.as_mut() {
            Some(framer) => framer,
            None => source,
        };
        let result = stream_artifact(ArtifactStreamInput {
            source: stream,
            plan,
            expected_replayability,
            path: &target,
            dataset_hasher: &mut dataset_hasher,
            release_expanded: &mut release_expanded,
            release_stored: &mut release_stored,
            release_records: &mut release_records,
            disk_bytes: &mut disk_bytes,
            profile: request.profile,
            cancellation: &request.cancellation,
            faults: &request.faults,
            evidence,
            started,
        })?;
        evidence.observed_bytes = evidence
            .observed_bytes
            .saturating_add(result.descriptor.stored_bytes);
        descriptors.push(result.descriptor);
        replay_proofs.push(result.proof);
    }
    evidence.source_consumption_state = SourceConsumptionState::Complete;
    let data_sha256 = hex_encode(&dataset_hasher.finalize());
    let mut manifest = request.manifest.clone();
    manifest.artifacts = descriptors.clone();
    manifest.digests.data_sha256 = data_sha256.clone();
    evidence.stage = FaultStage::ManifestSeal.as_str();
    let sealed_manifest = seal_manifest(SealRequest {
        manifest: &manifest,
        evidence: request.evidence,
        observed_event_types: request.observed_event_types,
        signature: request.signature,
        policy: &policy,
    })?;
    injected(&request.faults, FaultStage::ManifestSeal)?;
    evidence.stage = FaultStage::ReceiptBuild.as_str();
    let (receipt, recovery_evidence) = build_receipt_evidence(
        &manifest,
        &descriptors,
        request.operation_id,
        request.commit_position,
        &sealed_manifest,
        &policy,
    )?;
    injected(&request.faults, FaultStage::ReceiptBuild)?;
    evidence.stage = FaultStage::ManifestWrite.as_str();
    let manifest_len = u64::try_from(sealed_manifest.manifest_bytes.len())
        .map_err(|_| StreamError::PolicyExceeded("manifest length overflow".to_owned()))?;
    reserve_temp_bytes(
        &mut disk_bytes,
        manifest_len,
        "manifest temp disk bytes",
        limits.temp_disk_bytes(),
    )?;
    let sidecar_len = u64::try_from(sealed_manifest.sidecar_bytes.len())
        .map_err(|_| StreamError::PolicyExceeded("sidecar length overflow".to_owned()))?;
    reserve_temp_bytes(
        &mut disk_bytes,
        sidecar_len,
        "sidecar temp disk bytes",
        limits.temp_disk_bytes(),
    )?;
    write_new_file(
        &staging.join(crate::distribution::ndc_release::MANIFEST_FILE_NAME),
        &sealed_manifest.manifest_bytes,
    )?;
    injected(&request.faults, FaultStage::ManifestWrite)?;
    evidence.stage = FaultStage::SidecarWrite.as_str();
    write_new_file(
        &staging.join(crate::distribution::ndc_release::SIDECAR_FILE_NAME),
        &sealed_manifest.sidecar_bytes,
    )?;
    injected(&request.faults, FaultStage::SidecarWrite)?;
    evidence.stage = FaultStage::ArtifactDirSync.as_str();
    sync_directory(&artifact_root)?;
    injected(&request.faults, FaultStage::ArtifactDirSync)?;
    evidence.stage = FaultStage::StagingDirSync.as_str();
    sync_directory(&staging)?;
    injected(&request.faults, FaultStage::StagingDirSync)?;

    if request.faults.cancel_before_seal {
        request.cancellation.cancel();
    }
    evidence.stage = "before-seal";
    request.cancellation.check("before-seal")?;

    let sealed = SealedPublicationIntent {
        schema_version: STREAM_INTENT_SCHEMA_VERSION,
        operation_id: request.operation_id.to_owned(),
        preparation_intent_sha256: preparation_digest.to_owned(),
        manifest_sha256: sealed_manifest.manifest_sha256.clone(),
        sidecar_sha256: sealed_manifest.sidecar_sha256.clone(),
        data_sha256: data_sha256.clone(),
        artifact_inventory: descriptors.clone(),
        source_bindings: source_bindings.clone(),
        stored_bytes: release_stored,
        expanded_bytes: release_expanded,
        record_count: release_records,
        expected_receipt: receipt.clone(),
        expected_receipt_sha256: recovery_evidence.receipt_sha256.clone(),
        wire_profile_id: INTENT_WIRE_PROFILE.to_owned(),
        resource_profile_id: request.profile.id().as_literal(),
        resource_profile_digest: hex_encode(request.profile.digest()),
        spool_evidence: spooled.clone(),
        intent_sha256: String::new(),
    };
    let sealed_digest = write_sealed_intent(
        request.ledger_dir,
        &sealed,
        limits.max_sealed_intent_bytes(),
    )?;
    evidence.state = PreparationState::Sealed;
    Ok(PreparedPublication {
        staging,
        sealed_manifest,
        descriptors,
        source_bindings,
        receipt,
        recovery_evidence,
        sealed,
        sealed_digest,
        replay_proofs,
        spool_evidence: spooled,
    })
}

/// Reconcile a sealed publication through the existing publication core.
fn finalize_prepared_publication(
    request: &StreamingBuildRequest<'_>,
    prepared: PreparedPublication,
) -> Result<StreamingOutcome, StreamError> {
    let policy = request.profile.limits().to_resource_policy();
    let recovery_intent_sha256 =
        write_compatibility_publication_intent(request.ledger_dir, &prepared.sealed, &policy)?;

    if request.faults.cancel_after_seal {
        request.cancellation.cancel();
    }
    if request.cancellation.is_cancelled() {
        return Err(StreamError::CancellationAfterSeal("after-seal"));
    }

    let tree = write_compatibility_stages(
        request.ledger_dir,
        &prepared.sealed,
        &recovery_intent_sha256,
        &prepared.receipt,
        &prepared.recovery_evidence,
        &policy,
    )?;
    validate_artifact_set(
        &prepared.staging,
        &prepared.recovery_evidence,
        Some(&prepared.sealed_manifest.sidecar_sha256),
        &policy,
    )?;
    let final_dir = request
        .release_root
        .join(&prepared.recovery_evidence.release_id);
    finalize_publication_v2(
        request.release_root,
        request.ledger_dir,
        &tree,
        &prepared.staging,
        &final_dir,
        &prepared.receipt,
        &policy,
        Default::default(),
        &RealPublicationFs,
    )?;

    Ok(StreamingOutcome {
        manifest_bytes: prepared.sealed_manifest.manifest_bytes,
        sidecar_bytes: prepared.sealed_manifest.sidecar_bytes,
        descriptors: prepared.descriptors,
        source_bindings: prepared.source_bindings,
        receipt: prepared.receipt,
        recovery_evidence: prepared.recovery_evidence,
        preparation_intent_sha256: prepared.sealed.preparation_intent_sha256,
        sealed_intent_sha256: prepared.sealed_digest,
        replay_proofs: prepared.replay_proofs,
        spool_evidence: prepared.spool_evidence,
    })
}

fn planned_file_set(plans: &[ArtifactPlan]) -> Vec<String> {
    let mut paths = vec![
        crate::distribution::ndc_release::MANIFEST_FILE_NAME.to_owned(),
        crate::distribution::ndc_release::SIDECAR_FILE_NAME.to_owned(),
    ];
    paths.extend(plans.iter().map(|plan| plan.path.clone()));
    paths.sort();
    paths
}

fn write_compatibility_publication_intent(
    ledger: &Path,
    sealed: &SealedPublicationIntent,
    policy: &crate::distribution::ndc_release::ResourcePolicy,
) -> Result<String, StreamError> {
    let intent = PublicationIntentV2 {
        schema_version: INTENT_SCHEMA_VERSION,
        operation_id: sealed.operation_id.clone(),
        release_id: sealed.expected_receipt.release_id.clone(),
        manifest_sha256: sealed.manifest_sha256.clone(),
        sidecar_sha256: sealed.sidecar_sha256.clone(),
        data_sha256: sealed.data_sha256.clone(),
        commit_position: sealed.expected_receipt.commit_position.clone(),
        staging_directory: staging_name(&sealed.operation_id),
        final_directory: sealed.expected_receipt.release_id.clone(),
        supersedes_release_id: sealed.expected_receipt.supersedes_release_id.clone(),
        expected_receipt: sealed.expected_receipt.clone(),
        expected_receipt_sha256: sealed.expected_receipt_sha256.clone(),
        artifacts: sealed
            .artifact_inventory
            .iter()
            .map(crate::distribution::ndc_release::IntentArtifact::from)
            .collect(),
        wire_profile: sealed.wire_profile_id.clone(),
        resource_profile: crate::distribution::ndc_release::resource_profile_id(policy),
        intent_sha256: String::new(),
    };
    let digest = intent_checksum(&intent, policy)?;
    let intent = PublicationIntentV2 {
        intent_sha256: digest.clone(),
        ..intent
    };
    write_intent(ledger, &intent, policy, &RealPublicationFs)?;
    Ok(digest)
}

fn quarantine_file(ledger: &Path, operation_id: &str) -> PathBuf {
    ledger.join(format!("{operation_id}.quarantine.json"))
}

fn validate_operation_id(operation_id: &str) -> Result<(), StreamError> {
    if is_opaque_token(operation_id) {
        Ok(())
    } else {
        Err(StreamError::PolicyExceeded(
            "operation id is empty, oversized or outside the opaque alphabet".to_owned(),
        ))
    }
}

fn quarantine_verification(message: String) -> StreamError {
    StreamError::QuarantineVerification("quarantine evidence".to_owned(), message)
}

fn verify_quarantine_record(record: &QuarantineRecord) -> Result<(), StreamError> {
    if record.schema_version != QUARANTINE_SCHEMA_VERSION {
        return Err(quarantine_verification(
            "schema version is not supported".to_owned(),
        ));
    }
    if validate_operation_id(&record.operation_id).is_err() {
        return Err(quarantine_verification(
            "operation id is not a valid path token".to_owned(),
        ));
    }
    if !matches!(
        record.quarantine_state,
        PreparationState::QuarantinedDurable | PreparationState::QuarantinePending
    ) {
        return Err(quarantine_verification(
            "quarantine state is not a terminal state".to_owned(),
        ));
    }
    let mut unsigned = record.clone();
    unsigned.record_digest = String::new();
    if ledger_digest(&unsigned)? != record.record_digest {
        return Err(quarantine_verification("record digest mismatch".to_owned()));
    }
    Ok(())
}

fn load_verified_quarantine_record(
    ledger: &Path,
    operation_id: &str,
    preparation_digest: &str,
) -> Result<QuarantineRecord, StreamError> {
    validate_operation_id(operation_id)?;
    let bytes = fs::read(quarantine_file(ledger, operation_id))
        .map_err(|error| StreamError::Io("read quarantine record".to_owned(), error))?;
    let record: QuarantineRecord = serde_json::from_slice(&bytes)
        .map_err(|error| quarantine_verification(format!("invalid quarantine record: {error}")))?;
    verify_quarantine_record(&record)?;
    if record.operation_id != operation_id || record.preparation_intent_digest != preparation_digest
    {
        return Err(quarantine_verification(
            "record does not match the operation chain".to_owned(),
        ));
    }
    Ok(record)
}

fn ensure_quarantine_record(
    ledger: &Path,
    operation_id: &str,
    preparation_digest: &str,
    evidence: &PreparationEvidence,
    failure_code: &str,
    first_failure_text: &str,
    refuse_commit: bool,
) -> QuarantineCommit {
    let pending = QuarantineCommit {
        state: PreparationState::QuarantinePending,
        record_digest: None,
    };
    if validate_operation_id(operation_id).is_err() || refuse_commit {
        return pending;
    }
    if let Ok(record) = load_verified_quarantine_record(ledger, operation_id, preparation_digest) {
        return QuarantineCommit {
            state: record.quarantine_state,
            record_digest: Some(record.record_digest),
        };
    }
    let record = QuarantineRecord {
        schema_version: QUARANTINE_SCHEMA_VERSION,
        operation_id: operation_id.to_owned(),
        preparation_intent_digest: preparation_digest.to_owned(),
        failure_stage: evidence.stage.to_owned(),
        failure_code: failure_code.to_owned(),
        first_failure: first_failure_text.to_owned(),
        staging_directory: evidence.staging_directory.clone(),
        spool_inventory: evidence.spool_inventory.clone(),
        partial_artifact_inventory: evidence.partial_artifact_inventory.clone(),
        source_consumption_state: evidence.source_consumption_state,
        observed_bytes: evidence.observed_bytes,
        expected_bytes: evidence.expected_bytes,
        quarantine_state: PreparationState::QuarantinedDurable,
        record_digest: String::new(),
    };
    let digest = match ledger_digest(&record) {
        Ok(digest) => digest,
        Err(_) => return pending,
    };
    let complete = QuarantineRecord {
        record_digest: digest,
        ..record
    };
    let bytes = match canonical_ledger_bytes(&complete) {
        Ok(bytes) => bytes,
        Err(_) => return pending,
    };
    if commit_ledger_record(&quarantine_file(ledger, operation_id), &bytes, ledger).is_err() {
        return pending;
    }
    match load_verified_quarantine_record(ledger, operation_id, preparation_digest) {
        Ok(verified) => QuarantineCommit {
            state: verified.quarantine_state,
            record_digest: Some(verified.record_digest),
        },
        Err(_) => pending,
    }
}

fn collect_directory_objects(
    directory: &Path,
    prefix: &str,
    inventory: &mut Vec<String>,
    depth: u8,
    maximum: usize,
) -> Result<(), StreamError> {
    if depth > 4 {
        return Err(StreamError::PolicyExceeded(
            "quarantine inventory depth bound exceeded".to_owned(),
        ));
    }
    let entries = fs::read_dir(directory)
        .map_err(|error| StreamError::Io("read quarantine directory".to_owned(), error))?;
    for entry in entries {
        let entry = entry.map_err(|error| {
            StreamError::Io("read quarantine directory entry".to_owned(), error)
        })?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.contains('/')
            || name.contains('\\')
        {
            continue;
        }
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let is_directory = entry
            .file_type()
            .map_err(|error| StreamError::Io("stat quarantine entry".to_owned(), error))?
            .is_dir();
        if is_directory {
            collect_directory_objects(&entry.path(), &relative, inventory, depth + 1, maximum)?;
        }
        inventory.push(relative);
        if inventory.len() > maximum {
            return Err(StreamError::PolicyExceeded(
                "quarantine inventory bound exceeded".to_owned(),
            ));
        }
    }
    Ok(())
}

fn enumerate_staging_objects(
    release_root: &Path,
    staging_directory: &str,
    policy: &crate::distribution::ndc_release::ResourcePolicy,
) -> Result<Vec<String>, StreamError> {
    let directory = release_root.join(staging_directory);
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let maximum = usize::try_from(policy.max_artifact_count).unwrap_or(usize::MAX);
    let mut inventory = Vec::new();
    collect_directory_objects(&directory, "", &mut inventory, 0, maximum)?;
    inventory.sort();
    Ok(inventory)
}

fn enumerate_spool_objects(
    spool_dir: &Path,
    operation_id: &str,
    policy: &crate::distribution::ndc_release::ResourcePolicy,
) -> Result<Vec<String>, StreamError> {
    if !spool_dir.exists() {
        return Ok(Vec::new());
    }
    let maximum = usize::try_from(policy.max_artifact_count).unwrap_or(usize::MAX);
    let prefix = format!("{operation_id}-");
    let entries = fs::read_dir(spool_dir)
        .map_err(|error| StreamError::Io("read spool directory".to_owned(), error))?;
    let mut inventory = Vec::new();
    for entry in entries {
        let entry = entry
            .map_err(|error| StreamError::Io("read spool directory entry".to_owned(), error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) && name.ends_with(".spool") {
            inventory.push(name);
            if inventory.len() > maximum {
                return Err(StreamError::PolicyExceeded(
                    "spool quarantine inventory bound exceeded".to_owned(),
                ));
            }
        }
    }
    inventory.sort();
    Ok(inventory)
}

fn retained_object_bytes(base: &Path, names: &[String]) -> u64 {
    names
        .iter()
        .map(|name| {
            fs::metadata(base.join(name))
                .map(|data| data.len())
                .unwrap_or(0)
        })
        .fold(0_u64, u64::saturating_add)
}

/// Recovery outcome for the two streaming intents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRecoveryOutcome {
    /// No preparation record exists for this operation.
    NoPreparationEvidence,
    /// A preparation record was not sealed; the carried state is the verified
    /// quarantine disposition, which may be pending.
    PreparationOnlyQuarantined(PreparationState),
    /// A verified seal exists and the publication core completed reconciliation.
    Recovered(RecoveryOutcome),
}

/// Check that the sealed spool inventory matches the preparation plan and the
/// independently durable evidence records before recovery may proceed.
fn verify_spool_inventory(
    ledger: &Path,
    preparation: &PreparationIntent,
    sealed: &SealedPublicationIntent,
) -> Result<(), StreamError> {
    let plans = &preparation.spool_plan;
    let evidence = &sealed.spool_evidence;
    if plans.len() != evidence.len() {
        return Err(StreamError::Publication(
            ProducerError::PublicationEvidence(
                "sealed spool inventory differs from the preparation inventory".to_owned(),
            ),
        ));
    }
    for (plan, item) in plans.iter().zip(evidence.iter()) {
        if item.spool_file_id != plan.spool_file_id
            || item.operation_id != plan.operation_id
            || item.artifact_binding_id != plan.artifact_binding_id
            || item.source_identity.snapshot_id != plan.source_snapshot_id
            || item.source_identity.revision != plan.source_revision
            || item.max_spool_bytes != plan.max_spool_bytes
            || item.preparation_intent_sha256 != preparation.intent_sha256
            || item.spool_state != SpoolState::Sealed
        {
            return Err(StreamError::Publication(
                ProducerError::PublicationEvidence(
                    "spool evidence does not match its preparation plan".to_owned(),
                ),
            ));
        }
        let durable = load_spool_evidence(ledger, &plan.spool_file_id)?.ok_or_else(|| {
            StreamError::Publication(ProducerError::PublicationEvidence(
                "sealed spool evidence record is missing".to_owned(),
            ))
        })?;
        if &durable != item {
            return Err(StreamError::Publication(
                ProducerError::PublicationEvidence(
                    "durable spool evidence differs from the sealed inventory".to_owned(),
                ),
            ));
        }
    }
    Ok(())
}

/// Recover one streaming operation from durable evidence alone. A preparation
/// record without a seal yields no receipt, marker or final rename, and yields
/// a preparation-only state only with verifiable quarantine evidence.
pub fn recover_streaming(
    release_root: &Path,
    ledger: &Path,
    spool_dir: &Path,
    operation_id: &str,
    policy: &crate::distribution::ndc_release::ResourcePolicy,
) -> Result<StreamRecoveryOutcome, StreamError> {
    validate_operation_id(operation_id)?;
    let preparation = load_preparation_intent(ledger, operation_id)?;
    let sealed = load_sealed_intent(ledger, operation_id)?;
    match (preparation, sealed) {
        (None, None) => Ok(StreamRecoveryOutcome::NoPreparationEvidence),
        (Some(preparation), None) => {
            let staging_directory = staging_name(operation_id);
            let partial_artifact_inventory =
                enumerate_staging_objects(release_root, &staging_directory, policy)?;
            let spool_inventory = enumerate_spool_objects(spool_dir, operation_id, policy)?;
            let observed_bytes = retained_object_bytes(
                &release_root.join(&staging_directory),
                &partial_artifact_inventory,
            )
            .saturating_add(retained_object_bytes(spool_dir, &spool_inventory));
            let evidence = PreparationEvidence {
                state: PreparationState::PreparationFailed,
                staging_directory,
                spool_inventory,
                partial_artifact_inventory,
                source_consumption_state: SourceConsumptionState::Stopped,
                observed_bytes,
                expected_bytes: planned_expected_bytes(
                    &preparation.source_plan,
                    policy.max_record_bytes,
                ),
                stage: "recovery",
            };
            let commit = match load_verified_quarantine_record(
                ledger,
                operation_id,
                &preparation.intent_sha256,
            ) {
                Ok(record) => QuarantineCommit {
                    state: record.quarantine_state,
                    record_digest: Some(record.record_digest),
                },
                Err(StreamError::Io(_, error)) if error.kind() == io::ErrorKind::NotFound => {
                    ensure_quarantine_record(
                        ledger,
                        operation_id,
                        &preparation.intent_sha256,
                        &evidence,
                        "STREAM_PREPARATION_ONLY",
                        "preparation intent without a durable seal",
                        false,
                    )
                }
                Err(error) => return Err(error),
            };
            Ok(StreamRecoveryOutcome::PreparationOnlyQuarantined(
                commit.state,
            ))
        }
        (None, Some(_)) => Err(StreamError::Publication(
            ProducerError::PublicationEvidence(
                "sealed intent lacks its preparation chain".to_owned(),
            ),
        )),
        (Some(preparation), Some(sealed)) => {
            if sealed.preparation_intent_sha256 != preparation.intent_sha256
                || sealed.operation_id != preparation.operation_id
                || sealed.resource_profile_id != preparation.resource_profile_id
                || sealed.resource_profile_digest != preparation.resource_profile_digest
                || sealed.source_bindings != preparation.source_bindings
            {
                return Err(StreamError::Publication(
                    ProducerError::PublicationEvidence(
                        "sealed intent does not match the preparation chain".to_owned(),
                    ),
                ));
            }
            verify_spool_inventory(ledger, &preparation, &sealed)?;
            let outcome = recover_interrupted(release_root, ledger, operation_id, policy)?;
            Ok(StreamRecoveryOutcome::Recovered(outcome))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::error::Error as StdError;
    use std::io::Cursor;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use tempfile::TempDir;

    use super::*;
    use crate::distribution::ndc_release;
    use crate::distribution::ndc_release::RecordOrderProfile;
    use crate::distribution::ndc_release::canonicalize_strict;
    use crate::distribution::ndc_release::parse_jcs_value;
    use crate::distribution::ndc_wire;
    use crate::distribution::stream_profile::LimitInputs;
    use crate::distribution::stream_profile::ResourceProfileId;

    type TestResult<T = ()> = Result<T, Box<dyn StdError>>;

    const SPEC: &str = include_str!(
        "../../docs/specifications/ndc-conformance-producer-spec-example-2026-11-24.json"
    );
    const RSS_CHILD_TEST: &str = "distribution::ndc_stream::tests::streaming_rss_child";
    const RSS_CHILD_ENV: &str = "FB_B15_RSS_CHILD";
    const RSS_SCALE_ENV: &str = "FB_B15_RSS_SCALE";
    const RSS_PROFILE_MEMORY_BUDGET: u64 = 96 * 1024 * 1024;

    fn test_limits() -> LimitInputs {
        LimitInputs {
            max_record_bytes: 4_096,
            max_records_per_artifact: 2_048,
            max_records_per_release: 8_192,
            max_artifacts_per_release: 8,
            max_stored_bytes_per_artifact: 8_388_608,
            max_stored_bytes_per_release: 33_554_432,
            max_expanded_bytes_per_artifact: 8_388_608,
            max_expanded_bytes_per_release: 33_554_432,
            max_decompression_budget_bytes: 33_554_432,
            max_expansion_ratio: 32,
            storage_codec_window_bytes: 32_768,
            io_chunk_bytes: 4_096,
            max_nesting_depth: 16,
            max_string_bytes: 1_024,
            max_token_bytes: 128,
            max_object_members: 64,
            max_array_elements: 256,
            max_concurrent_artifacts: 1,
            worker_count: 1,
            queue_capacity_records: 64,
            temp_disk_bytes: 33_554_432,
            max_processing_duration_secs: 120,
            max_journal_record_bytes: 65_536,
            max_preparation_intent_bytes: 262_144,
            max_sealed_intent_bytes: 262_144,
            max_open_file_descriptors: 8,
            memory_budget_bytes: RSS_PROFILE_MEMORY_BUDGET,
        }
    }

    fn test_profile() -> TestResult<ResourceProfile> {
        Ok(ResourceProfile::new_test_only(
            ResourceProfileId::new("STREAM_B15_TEST_ONLY_V1", 1)?,
            ProcessingRole::Producer,
            ProfileLimits::new(test_limits())?,
        )?)
    }

    fn test_manifest() -> TestResult<ndc_release::ReleaseManifest> {
        let spec = ndc_wire::parse_conformance_spec(SPEC)?;
        let mut manifest = spec.manifest;
        manifest.release_identity.release_id = "release-b15-test".to_owned();
        manifest.lineage.supersedes = None;
        Ok(manifest)
    }

    fn test_evidence() -> TestResult<EvidenceSpec> {
        Ok(ndc_wire::parse_conformance_spec(SPEC)?.evidence)
    }

    fn test_keys() -> (SigningKey, ed25519_dalek::VerifyingKey) {
        let signing = SigningKey::from_bytes(&[0x51; 32]);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn sequenced_record(text: &str, number: u64) -> TestResult<CanonicalRecord> {
        let policy = test_profile()?.limits().to_resource_policy();
        let value = json!({
            "envelope_schema_version": "envelope-abstract-1",
            "event_type": "event-type-abstract",
            "ordering": {
                "kind": "sequenced",
                "sequence_domain_id": "domain-a",
                "sequence_epoch": "epoch-1",
                "sequence_number": number.to_string()
            },
            "payload": {
                "fields": [
                    {
                        "field_name": "abstract-field",
                        "kind": "string",
                        "value": text
                    }
                ]
            }
        });
        let parsed = parse_jcs_value(&value.to_string())?;
        Ok(CanonicalRecord {
            bytes: canonicalize_strict(&parsed, &policy)?,
        })
    }

    fn proof_for_records(
        plan: &ArtifactPlan,
        records: &[CanonicalRecord],
    ) -> TestResult<ReplayProof> {
        let policy = test_profile()?.limits().to_resource_policy();
        let mut tracker = OrderTracker::new(plan)?;
        let mut hasher = Sha256::new();
        for (index, record) in records.iter().enumerate() {
            tracker.observe(&plan.path, &record.bytes, index, &policy)?;
            hasher.update(&record.bytes);
            hasher.update(b"\n");
        }
        Ok(ReplayProof {
            source_binding_id: plan.source_binding_id.clone(),
            source_content_digest: hex_encode(&hasher.finalize()),
            record_count: u64::try_from(records.len())?,
            first_order_key: tracker.first.unwrap_or_default(),
            last_order_key: tracker.last.unwrap_or_default(),
        })
    }

    fn make_plan_with_binding(
        partition: &str,
        shard: u32,
        path: &str,
        compression: CompressionMode,
        records: &[CanonicalRecord],
        binding_id: &str,
    ) -> TestResult<ArtifactPlan> {
        let digest = hex_encode(
            &records
                .iter()
                .fold(Sha256::new(), |mut hasher, record| {
                    hasher.update(&record.bytes);
                    hasher.update(b"\n");
                    hasher
                })
                .finalize(),
        );
        let mut plan = ArtifactPlan {
            logical_partition_id: partition.to_owned(),
            shard_ordinal: shard,
            path: path.to_owned(),
            record_order_profile: RecordOrderProfile::Sequenced {
                sequence_domain: "domain-a".to_owned(),
                sequence_epoch: "epoch-1".to_owned(),
            },
            encoding: ENCODING_NDJSON.to_owned(),
            compression,
            compression_profile_id: match compression {
                CompressionMode::None => COMPRESSION_VERSION_NONE.to_owned(),
                CompressionMode::Gzip => TEST_ONLY_CODEC_PROFILE.to_owned(),
            },
            source_snapshot_id: "SNAPSHOT_A".to_owned(),
            source_revision: "rev-1".to_owned(),
            source_binding_id: binding_id.to_owned(),
            replayability: Replayability::Replayable,
            source_content_digest: digest,
            expected_record_count: u64::try_from(records.len())?,
            first_order_key: String::new(),
            last_order_key: String::new(),
        };
        let proof = proof_for_records(&plan, records)?;
        plan.first_order_key = proof.first_order_key;
        plan.last_order_key = proof.last_order_key;
        Ok(plan)
    }

    fn make_plan(
        partition: &str,
        shard: u32,
        path: &str,
        compression: CompressionMode,
        records: &[CanonicalRecord],
    ) -> TestResult<ArtifactPlan> {
        make_plan_with_binding(
            partition,
            shard,
            path,
            compression,
            records,
            &format!("{partition}-{shard}"),
        )
    }

    fn source_for(
        plan: &ArtifactPlan,
        records: &[CanonicalRecord],
    ) -> TestResult<Box<dyn ArtifactRecordSource>> {
        let mut bytes = Vec::new();
        for record in records {
            bytes.extend_from_slice(&record.bytes);
            bytes.push(b'\n');
        }
        let framer = BoundedRecordFramer::new(
            Cursor::new(bytes),
            plan.source_identity()?,
            plan.source_binding_id.clone(),
            plan.replayability,
            test_profile()?.limits().max_record_bytes(),
        )?;
        Ok(Box::new(framer))
    }

    fn spool_plan_for(
        operation_id: &str,
        ordinal: usize,
        plan: &ArtifactPlan,
    ) -> TestResult<SpoolPlan> {
        Ok(build_spool_plan(
            operation_id,
            ordinal,
            plan,
            test_profile()?.limits().temp_disk_bytes(),
        )?)
    }

    fn spool_for_test(
        fixture: &Fixture,
        operation_id: &str,
        plan: &ArtifactPlan,
        records: &[CanonicalRecord],
    ) -> TestResult<(SpoolEvidence, u64)> {
        let planned = spool_plan_for(operation_id, 0, plan)?;
        let profile = test_profile()?;
        let mut disk = 0_u64;
        let mut source = source_for(plan, records)?;
        let (evidence, _) = spool_non_replayable(
            source.as_mut(),
            plan,
            &planned,
            &fixture.spool,
            &fixture.ledger,
            "test-preparation-digest",
            &profile,
            &mut disk,
            SpoolFault::None,
        )?;
        Ok((evidence, disk))
    }

    struct Fixture {
        _temp: TempDir,
        root: PathBuf,
        ledger: PathBuf,
        spool: PathBuf,
    }

    fn fixture() -> TestResult<Fixture> {
        let temp = TempDir::new()?;
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let spool = temp.path().join("spool");
        fs::create_dir_all(&root)?;
        fs::create_dir_all(&ledger)?;
        fs::create_dir_all(&spool)?;
        Ok(Fixture {
            _temp: temp,
            root,
            ledger,
            spool,
        })
    }

    fn publish(
        fixture: &Fixture,
        plans: Vec<ArtifactPlan>,
        sources: Vec<Box<dyn ArtifactRecordSource>>,
        faults: StreamFaults,
        cancellation: Cancellation,
    ) -> TestResult<Result<StreamingOutcome, StreamError>> {
        let manifest = test_manifest()?;
        let evidence = test_evidence()?;
        let observed = BTreeSet::new();
        let (signing, verifying) = test_keys();
        let profile = test_profile()?;
        let mut selection = ProfileSelection::new();
        selection.insert_test_only(profile.clone())?;
        Ok(publish_streaming(StreamingBuildRequest {
            release_root: &fixture.root,
            ledger_dir: &fixture.ledger,
            spool_dir: &fixture.spool,
            operation_id: "operation-b15",
            commit_position: "commit-b15",
            manifest: &manifest,
            evidence: &evidence,
            observed_event_types: &observed,
            signature: SignatureConfig {
                signing_key: &signing,
                verifying_key: &verifying,
                key_id: &manifest.publication_identity.signing_key_id,
            },
            sources,
            plans: &plans,
            profile: &profile,
            profile_selection: &selection,
            context: InvocationContext::TestHarness,
            cancellation,
            faults,
        }))
    }

    fn publish_with_limits(
        fixture: &Fixture,
        limits: LimitInputs,
        operation_id: &str,
        plans: Vec<ArtifactPlan>,
        sources: Vec<Box<dyn ArtifactRecordSource>>,
    ) -> TestResult<Result<StreamingOutcome, StreamError>> {
        let profile = ResourceProfile::new_test_only(
            ResourceProfileId::new("STREAM_B15_TEST_ONLY_RATIO_V1", 1)?,
            ProcessingRole::Producer,
            ProfileLimits::new(limits)?,
        )?;
        let manifest = test_manifest()?;
        let evidence = test_evidence()?;
        let observed = BTreeSet::new();
        let (signing, verifying) = test_keys();
        let mut selection = ProfileSelection::new();
        selection.insert_test_only(profile.clone())?;
        Ok(publish_streaming(StreamingBuildRequest {
            release_root: &fixture.root,
            ledger_dir: &fixture.ledger,
            spool_dir: &fixture.spool,
            operation_id,
            commit_position: "commit-b15",
            manifest: &manifest,
            evidence: &evidence,
            observed_event_types: &observed,
            signature: SignatureConfig {
                signing_key: &signing,
                verifying_key: &verifying,
                key_id: &manifest.publication_identity.signing_key_id,
            },
            sources,
            plans: &plans,
            profile: &profile,
            profile_selection: &selection,
            context: InvocationContext::TestHarness,
            cancellation: Cancellation::new(),
            faults: StreamFaults::default(),
        }))
    }

    fn varied_text(seed: u64, length: usize) -> String {
        let alphabet = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut state = seed;
        let mut text = String::with_capacity(length);
        for _ in 0..length {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let slot = usize::try_from(state >> 58).expect("six high bits fit in usize");
            text.push(char::from(alphabet[slot % alphabet.len()]));
        }
        text
    }

    fn assert_no_availability(fixture: &Fixture) -> TestResult {
        let receipt = fixture.ledger.join("release-b15-test.receipt.json");
        let marker = fixture.ledger.join("release-b15-test.available");
        let final_dir = fixture.root.join("release-b15-test");
        assert!(!receipt.exists(), "a refused operation has no receipt");
        assert!(!marker.exists(), "a refused operation has no marker");
        assert!(!final_dir.exists(), "a refused operation has no final name");
        Ok(())
    }

    fn assert_quarantine_record(fixture: &Fixture, operation_id: &str) -> TestResult {
        let preparation = load_preparation_intent(&fixture.ledger, operation_id)?
            .ok_or_else(|| io::Error::other("the preparation intent is missing"))?;
        let record = load_verified_quarantine_record(
            &fixture.ledger,
            operation_id,
            &preparation.intent_sha256,
        )?;
        assert_eq!(
            record.operation_id, operation_id,
            "the durable record belongs to this operation"
        );
        assert_eq!(
            record.quarantine_state,
            PreparationState::QuarantinedDurable,
            "the durable record carries the terminal quarantine state"
        );
        Ok(())
    }

    /// Test-only reader that reproduces the core handoff and returns a copy
    /// for assertions; production code keeps only the core-owned buffer.
    struct TestReader {
        buffer: Vec<u8>,
        max_record_bytes: u64,
        index: usize,
    }

    fn quarantined_report(
        result: Result<StreamingOutcome, StreamError>,
    ) -> PreparationQuarantineReport {
        match result {
            Err(StreamError::PreparationQuarantined(report)) => report,
            other => panic!("a pre-seal failure must be quarantined: {other:?}"),
        }
    }

    impl TestReader {
        fn new(max_record_bytes: u64) -> Self {
            Self {
                buffer: Vec::new(),
                max_record_bytes,
                index: 0,
            }
        }

        fn next(
            &mut self,
            source: &mut dyn ArtifactRecordSource,
        ) -> Result<Option<CanonicalRecord>, StreamError> {
            self.buffer.clear();
            let result = {
                let mut sink = RecordSink::new(&mut self.buffer, self.max_record_bytes, self.index);
                let result = source.write_next_record(&mut sink);
                if sink.exceeded() {
                    return Err(StreamError::PolicyExceeded(format!(
                        "record {} exceeds max_record_bytes {}",
                        self.index, self.max_record_bytes
                    )));
                }
                result
            };
            if !result? {
                return Ok(None);
            }
            self.index = self.index.saturating_add(1);
            Ok(Some(CanonicalRecord {
                bytes: self.buffer.clone(),
            }))
        }
    }

    fn one_record_plan(path: &str) -> TestResult<(ArtifactPlan, Vec<CanonicalRecord>)> {
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan("partition-a", 0, path, CompressionMode::None, &records)?;
        Ok((plan, records))
    }

    fn publish_with_fault(
        fixture: &Fixture,
        fault: FaultStage,
    ) -> TestResult<Result<StreamingOutcome, StreamError>> {
        let (plan, records) = one_record_plan("artifacts/a.jsonl")?;
        let sources = vec![source_for(&plan, &records)?];
        publish(
            fixture,
            vec![plan],
            sources,
            StreamFaults {
                fail_after: Some(fault),
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )
    }

    fn assert_fault_quarantines(fixture: &Fixture, fault: FaultStage) -> TestResult {
        let report = quarantined_report(publish_with_fault(fixture, fault)?);
        assert_eq!(
            report.quarantine_state,
            PreparationState::QuarantinedDurable,
            "the injected fault is recorded with durable quarantine"
        );
        assert!(
            !sealed_file(&fixture.ledger, "operation-b15").exists(),
            "a pre-seal fault writes no sealed intent"
        );
        assert_quarantine_record(fixture, "operation-b15")?;
        assert_no_availability(fixture)?;
        let policy = test_profile()?.limits().to_resource_policy();
        let recovered = recover_streaming(
            &fixture.root,
            &fixture.ledger,
            &fixture.spool,
            "operation-b15",
            &policy,
        )?;
        assert_eq!(
            recovered,
            StreamRecoveryOutcome::PreparationOnlyQuarantined(PreparationState::QuarantinedDurable),
            "a fresh recovery process reads the durable quarantine"
        );
        Ok(())
    }

    fn publish_plan_with_fault(
        fixture: &Fixture,
        plan: ArtifactPlan,
        records: Vec<CanonicalRecord>,
        fault: FaultStage,
    ) -> TestResult<Result<StreamingOutcome, StreamError>> {
        let sources = vec![source_for(&plan, &records)?];
        publish(
            fixture,
            vec![plan],
            sources,
            StreamFaults {
                fail_after: Some(fault),
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )
    }

    #[test]
    fn fault_after_staging_create_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::StagingCreate)
    }

    #[test]
    fn fault_after_staging_sync_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::StagingSync)
    }

    #[test]
    fn fault_after_artifact_root_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::ArtifactRoot)
    }

    #[test]
    fn fault_after_artifact_parent_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::ArtifactParent)
    }

    #[test]
    fn fault_after_source_read_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::SourceRead)
    }

    #[test]
    fn fault_after_record_validation_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::RecordValidation)
    }

    #[test]
    fn fault_after_artifact_write_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::ArtifactWrite)
    }

    #[test]
    fn fault_after_compression_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::Compression)
    }

    #[test]
    fn fault_after_file_sync_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::FileSync)
    }

    #[test]
    fn fault_after_manifest_seal_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::ManifestSeal)
    }

    #[test]
    fn fault_after_receipt_build_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::ReceiptBuild)
    }

    #[test]
    fn fault_after_manifest_write_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::ManifestWrite)
    }

    #[test]
    fn fault_after_sidecar_write_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::SidecarWrite)
    }

    #[test]
    fn fault_after_artifact_dir_sync_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::ArtifactDirSync)
    }

    #[test]
    fn fault_after_staging_dir_sync_quarantines() -> TestResult {
        let fixture = fixture()?;
        assert_fault_quarantines(&fixture, FaultStage::StagingDirSync)
    }

    fn non_replayable_plan(path: &str) -> TestResult<(ArtifactPlan, Vec<CanonicalRecord>)> {
        let (mut plan, records) = one_record_plan(path)?;
        plan.replayability = Replayability::NonReplayable;
        Ok((plan, records))
    }

    #[test]
    fn fault_after_spool_write_quarantines() -> TestResult {
        let fixture = fixture()?;
        let (plan, records) = non_replayable_plan("artifacts/spooled.jsonl")?;
        let report = quarantined_report(publish_plan_with_fault(
            &fixture,
            plan,
            records,
            FaultStage::SpoolWrite,
        )?);
        assert_eq!(
            report.quarantine_state,
            PreparationState::QuarantinedDurable,
            "a spool write fault is quarantined durably"
        );
        assert_quarantine_record(&fixture, "operation-b15")?;
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn fault_after_spool_verify_quarantines() -> TestResult {
        let fixture = fixture()?;
        let (plan, records) = non_replayable_plan("artifacts/spooled.jsonl")?;
        let report = quarantined_report(publish_plan_with_fault(
            &fixture,
            plan,
            records,
            FaultStage::SpoolVerify,
        )?);
        assert_eq!(
            report.quarantine_state,
            PreparationState::QuarantinedDurable,
            "a spool verify fault is quarantined durably"
        );
        assert_quarantine_record(&fixture, "operation-b15")?;
        assert_no_availability(&fixture)?;
        Ok(())
    }

    const ALL_PRE_SEAL_FAULTS: &[FaultStage] = &[
        FaultStage::PreparationIntent,
        FaultStage::StagingCreate,
        FaultStage::StagingSync,
        FaultStage::ArtifactRoot,
        FaultStage::SpoolWrite,
        FaultStage::SpoolVerify,
        FaultStage::ArtifactParent,
        FaultStage::SourceRead,
        FaultStage::RecordValidation,
        FaultStage::ArtifactWrite,
        FaultStage::Compression,
        FaultStage::FileSync,
        FaultStage::ManifestSeal,
        FaultStage::ReceiptBuild,
        FaultStage::ManifestWrite,
        FaultStage::SidecarWrite,
        FaultStage::ArtifactDirSync,
        FaultStage::StagingDirSync,
    ];

    #[test]
    fn every_pre_seal_fault_leaves_no_availability() -> TestResult {
        for fault in ALL_PRE_SEAL_FAULTS {
            let fixture = fixture()?;
            let (plan, records) =
                if matches!(fault, FaultStage::SpoolWrite | FaultStage::SpoolVerify) {
                    non_replayable_plan("artifacts/spooled.jsonl")?
                } else {
                    one_record_plan("artifacts/a.jsonl")?
                };
            let sources = vec![source_for(&plan, &records)?];
            let faults = if *fault == FaultStage::PreparationIntent {
                StreamFaults {
                    crash_before_seal: true,
                    ..StreamFaults::default()
                }
            } else {
                StreamFaults {
                    fail_after: Some(*fault),
                    ..StreamFaults::default()
                }
            };
            let result = publish(&fixture, vec![plan], sources, faults, Cancellation::new())?;
            let report = quarantined_report(result);
            assert!(
                matches!(
                    report.quarantine_state,
                    PreparationState::QuarantinedDurable | PreparationState::QuarantinePending
                ),
                "fault {fault:?} reports a typed quarantine state"
            );
            assert!(
                !sealed_file(&fixture.ledger, "operation-b15").exists(),
                "fault {fault:?} writes no sealed intent"
            );
            assert_no_availability(&fixture)?;
        }
        Ok(())
    }

    #[test]
    fn quarantine_record_is_canonical_and_digest_verified() -> TestResult {
        let fixture = fixture()?;
        quarantined_report(publish_with_fault(&fixture, FaultStage::ManifestWrite)?);
        let preparation = load_preparation_intent(&fixture.ledger, "operation-b15")?
            .ok_or_else(|| io::Error::other("the preparation intent is missing"))?;
        let path = quarantine_file(&fixture.ledger, "operation-b15");
        let bytes = fs::read(&path)?;
        let record: QuarantineRecord = serde_json::from_slice(&bytes)?;
        assert_eq!(
            record.schema_version, QUARANTINE_SCHEMA_VERSION,
            "the record carries the pinned schema version"
        );
        assert_eq!(
            canonical_ledger_bytes(&record)?,
            bytes,
            "the durable record is the canonical ledger serialization"
        );
        let mut unsigned = record.clone();
        unsigned.record_digest = String::new();
        assert_eq!(
            ledger_digest(&unsigned)?,
            record.record_digest,
            "the record digest covers every other member"
        );
        assert_eq!(
            record.preparation_intent_digest, preparation.intent_sha256,
            "the record binds the preparation intent"
        );
        assert_eq!(
            record.failure_code, "STREAM_IO",
            "the first failure code survives the commit"
        );
        assert_eq!(
            record.source_consumption_state,
            SourceConsumptionState::Stopped,
            "consumption was stopped at the first failure"
        );
        assert!(
            !record.partial_artifact_inventory.is_empty(),
            "partial artifacts are enumerated"
        );
        Ok(())
    }

    #[test]
    fn existing_quarantine_record_is_verified_not_replaced() -> TestResult {
        let fixture = fixture()?;
        quarantined_report(publish_with_fault(&fixture, FaultStage::ManifestWrite)?);
        let path = quarantine_file(&fixture.ledger, "operation-b15");
        let before = fs::read(&path)?;
        let preparation = load_preparation_intent(&fixture.ledger, "operation-b15")?
            .ok_or_else(|| io::Error::other("the preparation intent is missing"))?;
        let evidence = PreparationEvidence::new("operation-b15", 4_096);
        let commit = ensure_quarantine_record(
            &fixture.ledger,
            "operation-b15",
            &preparation.intent_sha256,
            &evidence,
            "STREAM_OTHER",
            "another failure",
            false,
        );
        assert_eq!(
            commit.state,
            PreparationState::QuarantinedDurable,
            "an existing verified record is accepted"
        );
        assert_eq!(
            fs::read(&path)?,
            before,
            "an existing record is verified rather than replaced"
        );
        Ok(())
    }

    #[test]
    fn corrupted_quarantine_record_is_refused_by_recovery() -> TestResult {
        let fixture = fixture()?;
        quarantined_report(publish_with_fault(&fixture, FaultStage::ManifestWrite)?);
        let path = quarantine_file(&fixture.ledger, "operation-b15");
        let mut bytes = fs::read(&path)?;
        let last = bytes.len().saturating_sub(2);
        bytes[last] = b'0';
        fs::write(&path, bytes)?;
        let policy = test_profile()?.limits().to_resource_policy();
        let result = recover_streaming(
            &fixture.root,
            &fixture.ledger,
            &fixture.spool,
            "operation-b15",
            &policy,
        );
        assert!(
            matches!(result, Err(StreamError::QuarantineVerification(..))),
            "a corrupted record is not reported as successful quarantine"
        );
        Ok(())
    }

    #[test]
    fn quarantine_record_with_wrong_operation_is_refused() -> TestResult {
        let fixture = fixture()?;
        quarantined_report(publish_with_fault(&fixture, FaultStage::ManifestWrite)?);
        let path = quarantine_file(&fixture.ledger, "operation-b15");
        let mut record: QuarantineRecord = serde_json::from_slice(&fs::read(&path)?)?;
        record.operation_id = "operation-other".to_owned();
        let mut unsigned = record.clone();
        unsigned.record_digest = String::new();
        record.record_digest = ledger_digest(&unsigned)?;
        fs::write(&path, canonical_ledger_bytes(&record)?)?;
        let preparation = load_preparation_intent(&fixture.ledger, "operation-b15")?
            .ok_or_else(|| io::Error::other("the preparation intent is missing"))?;
        let result = load_verified_quarantine_record(
            &fixture.ledger,
            "operation-b15",
            &preparation.intent_sha256,
        );
        assert!(
            matches!(result, Err(StreamError::QuarantineVerification(..))),
            "a record for another operation is refused"
        );
        Ok(())
    }

    #[test]
    fn operation_id_path_validation_refuses_traversal() -> TestResult {
        let fixture = fixture()?;
        assert!(
            matches!(
                validate_operation_id("../escape"),
                Err(StreamError::PolicyExceeded(_))
            ),
            "a traversal token is refused before path use"
        );
        assert!(
            matches!(
                recover_streaming(
                    &fixture.root,
                    &fixture.ledger,
                    &fixture.spool,
                    "../escape",
                    &test_profile()?.limits().to_resource_policy(),
                ),
                Err(StreamError::PolicyExceeded(_))
            ),
            "recovery refuses a traversal operation id"
        );
        Ok(())
    }

    #[test]
    fn operation_id_path_validation_refuses_empty_and_oversize() -> TestResult {
        assert!(
            matches!(
                validate_operation_id(""),
                Err(StreamError::PolicyExceeded(_))
            ),
            "an empty operation id is refused"
        );
        let oversized = "a".repeat(129);
        assert!(
            matches!(
                validate_operation_id(&oversized),
                Err(StreamError::PolicyExceeded(_))
            ),
            "an oversized operation id is refused"
        );
        Ok(())
    }

    #[test]
    fn quarantine_pending_when_durable_commit_is_refused() -> TestResult {
        let fixture = fixture()?;
        let (plan, records) = one_record_plan("artifacts/a.jsonl")?;
        let sources = vec![source_for(&plan, &records)?];
        let result = publish(
            &fixture,
            vec![plan],
            sources,
            StreamFaults {
                fail_after: Some(FaultStage::SourceRead),
                quarantine_commit_fails: true,
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )?;
        let report = quarantined_report(result);
        assert_eq!(
            report.quarantine_state,
            PreparationState::QuarantinePending,
            "a refused ledger write reports the pending state"
        );
        assert_eq!(
            report.observed_state,
            PreparationState::QuarantinePending,
            "the explicit state machine ends in quarantine pending"
        );
        assert!(
            report.quarantine_record_digest.is_none(),
            "a pending commit carries no verifiable record digest"
        );
        assert!(
            !quarantine_file(&fixture.ledger, "operation-b15").exists(),
            "a refused commit leaves no record claiming success"
        );
        assert!(
            !sealed_file(&fixture.ledger, "operation-b15").exists(),
            "a pending quarantine writes no sealed intent"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn first_failure_survives_a_pending_quarantine_commit() -> TestResult {
        let fixture = fixture()?;
        let (plan, records) = one_record_plan("artifacts/a.jsonl")?;
        let sources = vec![source_for(&plan, &records)?];
        let result = publish(
            &fixture,
            vec![plan],
            sources,
            StreamFaults {
                fail_after: Some(FaultStage::SourceRead),
                quarantine_commit_fails: true,
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )?;
        let report = quarantined_report(result);
        assert_eq!(
            report.failure_code, "STREAM_IO",
            "the first failure code is preserved when quarantine is pending"
        );
        assert_eq!(
            report.failure_stage,
            FaultStage::SourceRead.as_str(),
            "the first failure stage is preserved"
        );
        assert!(
            report
                .first_failure
                .contains("injected failure after source-read"),
            "the first failure text is preserved"
        );
        Ok(())
    }

    #[test]
    fn recovery_enumerates_residual_staging_and_spool_objects() -> TestResult {
        let fixture = fixture()?;
        let (plan, records) = non_replayable_plan("artifacts/spooled.jsonl")?;
        quarantined_report(publish_plan_with_fault(
            &fixture,
            plan,
            records,
            FaultStage::ArtifactWrite,
        )?);
        let preparation = load_preparation_intent(&fixture.ledger, "operation-b15")?
            .ok_or_else(|| io::Error::other("the preparation intent is missing"))?;
        let record = load_verified_quarantine_record(
            &fixture.ledger,
            "operation-b15",
            &preparation.intent_sha256,
        )?;
        assert!(
            record
                .partial_artifact_inventory
                .iter()
                .any(|name| name == "artifacts/spooled.jsonl"),
            "the partial artifact path is retained"
        );
        let planned_ids: Vec<String> = preparation
            .spool_plan
            .iter()
            .map(|plan| plan.spool_file_id.clone())
            .collect();
        assert!(
            planned_ids
                .iter()
                .all(|name| record.spool_inventory.contains(name)),
            "the operation's spool objects are retained"
        );
        assert!(
            record.observed_bytes > 0,
            "observed bytes are retained with the evidence"
        );
        Ok(())
    }

    #[test]
    fn source_consumption_stops_at_first_failure() -> TestResult {
        let fixture = fixture()?;
        let (plan, first_record) = one_record_plan("artifacts/a.jsonl")?;
        let records = vec![first_record[0].clone(), sequenced_record("abstract-2", 2)?];
        let reads = Arc::new(AtomicUsize::new(0));
        let source = CountingSource {
            inner: source_for(&plan, &records)?,
            completions: Arc::new(AtomicUsize::new(0)),
            reads: reads.clone(),
            completed: false,
        };
        let result = publish(
            &fixture,
            vec![plan],
            vec![Box::new(source) as Box<dyn ArtifactRecordSource>],
            StreamFaults {
                fail_after: Some(FaultStage::SourceRead),
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )?;
        let report = quarantined_report(result);
        assert_eq!(
            report.quarantine_state,
            PreparationState::QuarantinedDurable,
            "a stopped source is quarantined durably"
        );
        assert_eq!(
            reads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "consumption stopped after the first record read"
        );
        Ok(())
    }

    #[test]
    fn no_quarantine_before_preparation_intent_is_durable() -> TestResult {
        let fixture = fixture()?;
        let (plan, records) = one_record_plan("artifacts/a.jsonl")?;
        let result = publish(
            &fixture,
            vec![plan],
            vec![source_for(&plan_for_cancel(), &records)?],
            StreamFaults::default(),
            {
                let cancellation = Cancellation::new();
                cancellation.cancel();
                cancellation
            },
        )?;
        assert!(
            matches!(result, Err(StreamError::PublicationCancelled(_))),
            "a refusal before preparation intent stays a typed refusal"
        );
        assert!(
            !quarantine_file(&fixture.ledger, "operation-b15").exists(),
            "no preparation failure evidence exists before the intent is durable"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    /// Adversarial adapter that supplies record bytes only through the core
    /// sink. `ignore_write_error` models an adapter that discards sink refusals.
    struct SinkWriterSource {
        identity: SourceIdentity,
        binding_id: String,
        replayability: Replayability,
        max_record_bytes: u64,
        chunks: Vec<Vec<u8>>,
        ignore_write_error: bool,
        ended: bool,
    }

    impl SinkWriterSource {
        fn new(
            plan: &ArtifactPlan,
            chunks: Vec<Vec<u8>>,
            ignore_write_error: bool,
        ) -> TestResult<Self> {
            Ok(Self {
                identity: plan.source_identity()?,
                binding_id: plan.source_binding_id.clone(),
                replayability: plan.replayability,
                max_record_bytes: test_profile()?.limits().max_record_bytes(),
                chunks,
                ignore_write_error,
                ended: false,
            })
        }
    }

    impl ArtifactRecordSource for SinkWriterSource {
        fn source_identity(&self) -> SourceIdentity {
            self.identity.clone()
        }

        fn source_binding_id(&self) -> String {
            self.binding_id.clone()
        }

        fn replayability(&self) -> Replayability {
            self.replayability
        }

        fn write_next_record(&mut self, sink: &mut RecordSink<'_>) -> Result<bool, StreamError> {
            if self.ended {
                return Err(StreamError::InvalidRecord(
                    0,
                    "record requested after end of stream".to_owned(),
                ));
            }
            for chunk in &self.chunks {
                if self.ignore_write_error {
                    let _ = sink.push(chunk);
                } else {
                    sink.push(chunk)?;
                }
            }
            self.ended = true;
            Ok(true)
        }

        fn max_record_bytes(&self) -> u64 {
            self.max_record_bytes
        }
    }

    fn publish_chunks(
        fixture: &Fixture,
        chunks: Vec<Vec<u8>>,
        ignore_write_error: bool,
        operation_id: &str,
    ) -> TestResult<Result<StreamingOutcome, StreamError>> {
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let source = SinkWriterSource::new(&plan, chunks, ignore_write_error)?;
        publish_with_limits(
            fixture,
            test_limits(),
            operation_id,
            vec![plan],
            vec![Box::new(source)],
        )
    }

    fn record_of_length(target: usize) -> TestResult<CanonicalRecord> {
        let base_length = sequenced_record("x", 1)?.bytes.len();
        assert!(target >= base_length, "target length must fit the envelope");
        let text = "a".repeat(target.saturating_sub(base_length).saturating_add(1));
        let policy = test_profile()?.limits().to_resource_policy();
        let value = json!({
            "envelope_schema_version": "envelope-abstract-1",
            "event_type": "event-type-abstract",
            "ordering": {
                "kind": "sequenced",
                "sequence_domain_id": "domain-a",
                "sequence_epoch": "epoch-1",
                "sequence_number": "1"
            },
            "payload": {
                "fields": [
                    {
                        "field_name": "abstract-field",
                        "kind": "string",
                        "value": text
                    }
                ]
            }
        });
        let parsed = parse_jcs_value(&value.to_string())?;
        Ok(CanonicalRecord {
            bytes: canonicalize_strict(&parsed, &policy)?,
        })
    }

    /// Plan for one long record. Order keys come from a short record with the
    /// same byte-derived position; the content digest covers the long bytes.
    fn plan_for_long_record(
        record: &CanonicalRecord,
        path: &str,
        binding_id: &str,
    ) -> TestResult<ArtifactPlan> {
        let short = [sequenced_record("x", 1)?];
        let mut plan = make_plan("partition-long", 0, path, CompressionMode::None, &short)?;
        plan.source_binding_id = binding_id.to_owned();
        plan.path = path.to_owned();
        let mut hasher = Sha256::new();
        hasher.update(&record.bytes);
        hasher.update(b"\n");
        plan.source_content_digest = hex_encode(&hasher.finalize());
        plan.expected_record_count = 1;
        Ok(plan)
    }

    /// Build a plan whose declared ordering profile is the reference profile.
    fn make_reference_plan(
        partition: &str,
        shard: u32,
        path: &str,
        records: &[CanonicalRecord],
        binding_id: &str,
    ) -> TestResult<ArtifactPlan> {
        let mut hasher = Sha256::new();
        for record in records {
            hasher.update(&record.bytes);
            hasher.update(b"\n");
        }
        let mut plan = ArtifactPlan {
            logical_partition_id: partition.to_owned(),
            shard_ordinal: shard,
            path: path.to_owned(),
            record_order_profile: RecordOrderProfile::Reference,
            encoding: ENCODING_NDJSON.to_owned(),
            compression: CompressionMode::None,
            compression_profile_id: COMPRESSION_VERSION_NONE.to_owned(),
            source_snapshot_id: "SNAPSHOT_A".to_owned(),
            source_revision: "rev-1".to_owned(),
            source_binding_id: binding_id.to_owned(),
            replayability: Replayability::Replayable,
            source_content_digest: hex_encode(&hasher.finalize()),
            expected_record_count: u64::try_from(records.len())?,
            first_order_key: String::new(),
            last_order_key: String::new(),
        };
        let proof = proof_for_records(&plan, records)?;
        plan.first_order_key = proof.first_order_key;
        plan.last_order_key = proof.last_order_key;
        Ok(plan)
    }

    fn reference_record(object_id: &str, revision: u64, time: u64) -> TestResult<CanonicalRecord> {
        let policy = test_profile()?.limits().to_resource_policy();
        let value = json!({
            "envelope_schema_version": "envelope-abstract-1",
            "event_type": "event-type-abstract",
            "ordering": {
                "kind": "reference",
                "object_id": object_id,
                "revision": revision.to_string(),
                "knowledge_time_ns": time.to_string(),
                "assertion_id": "assertion-a"
            },
            "payload": {
                "fields": [
                    {
                        "field_name": "abstract-field",
                        "kind": "string",
                        "value": "abstract-reference"
                    }
                ]
            }
        });
        let parsed = parse_jcs_value(&value.to_string())?;
        Ok(CanonicalRecord {
            bytes: canonicalize_strict(&parsed, &policy)?,
        })
    }

    #[test]
    fn framer_yields_one_record_at_a_time_and_reports_end_of_stream() -> TestResult {
        let policy = test_profile()?.limits().to_resource_policy();
        let first = sequenced_record("abstract-1", 1)?;
        let second = sequenced_record("abstract-2", 2)?;
        let mut bytes = first.bytes.clone();
        bytes.push(b'\n');
        bytes.extend_from_slice(&second.bytes);
        bytes.push(b'\n');
        let source_identity = SourceIdentity::new("SNAPSHOT_A", "rev-1")?;
        let mut framer = BoundedRecordFramer::new(
            Cursor::new(bytes),
            source_identity,
            "binding-framer",
            Replayability::Replayable,
            policy.max_record_bytes,
        )?;
        let mut reader = TestReader::new(policy.max_record_bytes);
        let first_read = reader
            .next(&mut framer)?
            .expect("the first record is present");
        assert_eq!(
            first_read.bytes, first.bytes,
            "the first record is unchanged"
        );
        let second_read = reader
            .next(&mut framer)?
            .expect("the second record is present");
        assert_eq!(
            second_read.bytes, second.bytes,
            "the second record is unchanged"
        );
        assert!(
            reader.next(&mut framer)?.is_none(),
            "end of stream is explicit"
        );
        let state_error = matches!(
            reader.next(&mut framer),
            Err(StreamError::InvalidRecord(_, _))
        );
        assert!(
            state_error,
            "a core-sink read after end of stream is a typed state error"
        ); // the sink carries the typed state error after end of stream
        Ok(())
    }

    #[test]
    fn one_byte_reader_proves_there_is_no_unbounded_line_read() -> TestResult {
        struct OneByteReader {
            bytes: Vec<u8>,
            position: usize,
        }
        impl IoRead for OneByteReader {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                if self.position >= self.bytes.len() || output.is_empty() {
                    return Ok(0);
                }
                output[0] = self.bytes[self.position];
                self.position += 1;
                Ok(1)
            }
        }
        let record = sequenced_record("abstract-one-byte", 1)?;
        let mut bytes = record.bytes.clone();
        bytes.push(b'\n');
        let reader = OneByteReader { bytes, position: 0 };
        let mut framer = BoundedRecordFramer::new(
            reader,
            SourceIdentity::new("SNAPSHOT_A", "rev-1")?,
            "binding-one-byte",
            Replayability::Replayable,
            4_096,
        )?;
        let observed = TestReader::new(4_096)
            .next(&mut framer)?
            .expect("the framed record is present");
        assert_eq!(
            observed.bytes, record.bytes,
            "one-byte reads reconstruct the record"
        );
        Ok(())
    }

    #[test]
    fn framer_rejects_oversize_boundary_and_trailing_record() -> TestResult {
        let identity = SourceIdentity::new("SNAPSHOT_A", "rev-1")?;
        let long = vec![b'a'; 16];
        let mut too_long = long.clone();
        too_long.push(b'a');
        too_long.push(b'\n');
        let mut framer = BoundedRecordFramer::new(
            Cursor::new(too_long),
            identity.clone(),
            "binding-too-long",
            Replayability::Replayable,
            16,
        )?;
        assert!(
            matches!(
                TestReader::new(16).next(&mut framer),
                Err(StreamError::PolicyExceeded(_))
            ),
            "a record above the bound is refused before allocation grows"
        );
        let mut exact = BoundedRecordFramer::new(
            Cursor::new({
                let mut bytes = long;
                bytes.push(b'\n');
                bytes
            }),
            identity.clone(),
            "binding-exact",
            Replayability::Replayable,
            16,
        )?;
        let exact_read = TestReader::new(16).next(&mut exact)?.is_some();
        assert!(exact_read, "exact bound record is accepted");
        let mut trailing = BoundedRecordFramer::new(
            Cursor::new(b"incomplete".to_vec()),
            identity,
            "binding-trailing",
            Replayability::Replayable,
            16,
        )?;
        assert!(
            matches!(
                TestReader::new(16).next(&mut trailing),
                Err(StreamError::InvalidRecord(_, _))
            ),
            "a trailing record without LF is refused"
        );
        Ok(())
    }

    #[test]
    fn core_sink_accepts_a_write_at_the_record_limit() {
        let mut buffer = Vec::new();
        let mut sink = RecordSink::new(&mut buffer, 16, 0);
        sink.push(&[b'a'; 16])
            .expect("a write at the bound is accepted");
        assert_eq!(sink.len(), 16, "the core buffer holds exactly the bound");
        assert!(!sink.exceeded(), "no bound breach is recorded at the limit");
    }

    #[test]
    fn core_sink_rejects_one_write_past_the_record_limit() {
        let mut buffer = Vec::new();
        let mut sink = RecordSink::new(&mut buffer, 16, 0);
        let error = sink
            .push(&[b'a'; 17])
            .expect_err("one write past the bound is refused");
        assert!(
            matches!(&error, StreamError::PolicyExceeded(message) if message == "record 0 exceeds max_record_bytes 16"),
            "the typed refusal names the record and the bound"
        );
        assert!(sink.exceeded(), "the core observes the bound breach");
        assert!(
            buffer.is_empty(),
            "no part of the refused chunk is appended"
        );
    }

    #[test]
    fn core_sink_rejects_incremental_writes_with_the_same_refusal() {
        let mut single_buffer = Vec::new();
        let mut single = RecordSink::new(&mut single_buffer, 16, 0);
        let single_error = single
            .push(&[b'a'; 17])
            .expect_err("one oversized write is refused");
        let mut gradual_buffer = Vec::new();
        let mut gradual = RecordSink::new(&mut gradual_buffer, 16, 0);
        for _ in 0..16 {
            gradual
                .push(b"b")
                .expect("bytes up to the bound are accepted");
        }
        let gradual_error = gradual
            .push(b"b")
            .expect_err("the byte past the bound is refused");
        assert_eq!(
            single_error.to_string(),
            gradual_error.to_string(),
            "one large write and incremental writes produce one refusal message"
        );
        assert_eq!(
            single_error.code(),
            gradual_error.code(),
            "both write patterns share the typed policy code"
        );
        assert_eq!(
            gradual_buffer.len(),
            16,
            "the incremental buffer stops at the bound"
        );
    }

    #[test]
    fn malicious_adapter_one_oversized_write_is_refused_before_seal() -> TestResult {
        let fixture = fixture()?;
        let result = publish_chunks(
            &fixture,
            vec![vec![b'a'; 4_097]],
            false,
            "operation-oversized-single",
        )?;
        let report = quarantined_report(result);
        assert_eq!(
            report.failure_code, "STREAM_POLICY_EXCEEDED",
            "a single oversized write is preserved as a bound failure"
        );
        assert_eq!(
            report.first_failure,
            "stream resource bound exceeded: record 0 exceeds max_record_bytes 4096",
            "a single oversized write names the core bound"
        );
        assert!(
            preparation_file(&fixture.ledger, "operation-oversized-single").exists(),
            "preparation is durable before the source is consumed"
        );
        assert!(
            load_sealed_intent(&fixture.ledger, "operation-oversized-single")?.is_none(),
            "no seal follows an oversized write"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn malicious_adapter_incremental_oversized_writes_are_refused_before_seal() -> TestResult {
        let fixture = fixture()?;
        let chunks = (0..4_097).map(|_| vec![b'a']).collect();
        let result = publish_chunks(&fixture, chunks, false, "operation-oversized-incremental")?;
        let report = quarantined_report(result);
        assert_eq!(
            report.failure_code, "STREAM_POLICY_EXCEEDED",
            "incremental writes past the bound are preserved as a bound failure"
        );
        assert_eq!(
            report.first_failure,
            "stream resource bound exceeded: record 0 exceeds max_record_bytes 4096",
            "incremental writes past the bound meet the same refusal as one write"
        );
        assert!(
            load_sealed_intent(&fixture.ledger, "operation-oversized-incremental")?.is_none(),
            "no seal follows incremental oversized writes"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn malicious_adapter_ignoring_sink_errors_is_still_refused() -> TestResult {
        let fixture = fixture()?;
        let result = publish_chunks(
            &fixture,
            vec![vec![b'a'; 4_097]],
            true,
            "operation-ignored-sink-error",
        )?;
        let report = quarantined_report(result);
        assert_eq!(
            report.failure_code, "STREAM_POLICY_EXCEEDED",
            "a discarded sink error is preserved as a bound failure"
        );
        assert_eq!(
            report.first_failure,
            "stream resource bound exceeded: record 0 exceeds max_record_bytes 4096",
            "discarding the sink error does not bypass the core check"
        );
        assert!(
            load_sealed_intent(&fixture.ledger, "operation-ignored-sink-error")?.is_none(),
            "a discarding adapter cannot reach the seal"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn record_slice_adapter_writes_through_the_core_sink() -> TestResult {
        let fixture = fixture()?;
        let records = vec![
            sequenced_record("abstract-slice", 1)?,
            sequenced_record("abstract-slice-next", 2)?,
        ];
        let plan = make_plan(
            "partition-slice",
            0,
            "artifacts/slice.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let source = RecordSliceSource::new(
            records.clone(),
            plan.source_identity()?,
            plan.source_binding_id.clone(),
            plan.replayability,
        )?;
        let outcome = publish_with_limits(
            &fixture,
            test_limits(),
            "operation-slice",
            vec![plan],
            vec![Box::new(source)],
        )??;
        assert_eq!(
            outcome.descriptors[0].record_count, 2,
            "the compatibility adapter emits both records through the sink"
        );
        assert_eq!(
            outcome.replay_proofs[0].source_content_digest,
            stream_digest(&records),
            "the compatibility adapter preserves the emitted byte digest"
        );
        Ok(())
    }

    #[test]
    fn nested_json_is_rejected_from_core_held_bytes() -> TestResult {
        let fixture = fixture()?;
        let mut text = String::from("null");
        for _ in 0..20 {
            text = format!("{{\"a\":{text}}}");
        }
        let result = publish_chunks(
            &fixture,
            vec![text.into_bytes()],
            false,
            "operation-nested-json",
        )?;
        let report = quarantined_report(result);
        assert_eq!(
            report.failure_code, "STREAM_INVALID_RECORD",
            "deeply nested JSON is preserved as an invalid record"
        );
        assert!(
            report.first_failure.contains("nesting depth"),
            "deeply nested JSON is refused after core validation"
        );
        assert!(
            load_sealed_intent(&fixture.ledger, "operation-nested-json")?.is_none(),
            "a nested JSON refusal leaves no seal"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn malformed_json_is_rejected_from_core_held_bytes() -> TestResult {
        let fixture = fixture()?;
        let cases = [b"{\"a\": 1}".to_vec(), b"{broken".to_vec(), Vec::new()];
        for (index, bytes) in cases.into_iter().enumerate() {
            let operation_id = format!("operation-malformed-{index}");
            let result = publish_chunks(&fixture, vec![bytes], false, &operation_id)?;
            let report = quarantined_report(result);
            assert_eq!(
                report.failure_code, "STREAM_INVALID_RECORD",
                "malformed case {index} is preserved as an invalid record"
            );
            assert!(
                load_sealed_intent(&fixture.ledger, &operation_id)?.is_none(),
                "malformed case {index} leaves no seal"
            );
        }
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn record_at_exact_limit_passes_through_the_core_sink() -> TestResult {
        let fixture = fixture()?;
        let record = record_of_length(4_096)?;
        assert_eq!(
            record.bytes.len(),
            4_096,
            "the fixture record is at the core bound"
        );
        let plan = plan_for_long_record(&record, "artifacts/exact.jsonl", "binding-exact")?;
        let source = RecordSliceSource::new(
            vec![record],
            plan.source_identity()?,
            plan.source_binding_id.clone(),
            plan.replayability,
        )?;
        let mut limits = test_limits();
        limits.max_string_bytes = 4_096;
        let outcome = publish_with_limits(
            &fixture,
            limits,
            "operation-exact-limit",
            vec![plan],
            vec![Box::new(source)],
        )??;
        assert_eq!(
            outcome.descriptors[0].record_count, 1,
            "a record at the core bound is emitted"
        );
        assert!(
            sealed_file(&fixture.ledger, "operation-exact-limit").exists(),
            "a record at the bound reaches the seal"
        );
        Ok(())
    }

    #[test]
    fn record_one_byte_past_limit_is_rejected_by_the_core_sink() -> TestResult {
        let fixture = fixture()?;
        let record = record_of_length(4_097)?;
        assert_eq!(
            record.bytes.len(),
            4_097,
            "the fixture record is one byte past the core bound"
        );
        let plan = plan_for_long_record(&record, "artifacts/over.jsonl", "binding-over")?;
        let source = SinkWriterSource::new(&plan, vec![record.bytes.clone()], false)?;
        let mut limits = test_limits();
        limits.max_string_bytes = 4_096;
        let result = publish_with_limits(
            &fixture,
            limits,
            "operation-max-plus-one",
            vec![plan],
            vec![Box::new(source)],
        )?;
        let report = quarantined_report(result);
        assert_eq!(
            report.failure_code, "STREAM_POLICY_EXCEEDED",
            "the byte past the bound is preserved as a bound failure"
        );
        assert_eq!(
            report.first_failure,
            "stream resource bound exceeded: record 0 exceeds max_record_bytes 4096",
            "the byte past the bound is refused by the core sink"
        );
        assert!(
            load_sealed_intent(&fixture.ledger, "operation-max-plus-one")?.is_none(),
            "no seal follows a max-plus-one record"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn sequenced_and_reference_profiles_both_stream_through_the_core_sink() -> TestResult {
        let sequenced_fixture = fixture()?;
        let sequenced_records = vec![
            sequenced_record("abstract-seq-1", 1)?,
            sequenced_record("abstract-seq-2", 2)?,
        ];
        let sequenced_plan = make_plan(
            "partition-profile",
            0,
            "artifacts/seq.jsonl",
            CompressionMode::None,
            &sequenced_records,
        )?;
        let sequenced_source = RecordSliceSource::new(
            sequenced_records,
            sequenced_plan.source_identity()?,
            sequenced_plan.source_binding_id.clone(),
            sequenced_plan.replayability,
        )?;
        let sequenced_outcome = publish_with_limits(
            &sequenced_fixture,
            test_limits(),
            "operation-profile-seq",
            vec![sequenced_plan],
            vec![Box::new(sequenced_source)],
        )??;
        assert_eq!(
            sequenced_outcome.replay_proofs[0].record_count, 2,
            "the sequenced profile streams two records"
        );

        let reference_fixture = fixture()?;
        let reference_records = vec![
            reference_record("object-a", 1, 10)?,
            reference_record("object-b", 2, 20)?,
        ];
        let reference_plan = make_reference_plan(
            "partition-profile",
            1,
            "artifacts/ref.jsonl",
            &reference_records,
            "binding-profile-ref",
        )?;
        let reference_source = RecordSliceSource::new(
            reference_records,
            reference_plan.source_identity()?,
            reference_plan.source_binding_id.clone(),
            reference_plan.replayability,
        )?;
        let reference_outcome = publish_with_limits(
            &reference_fixture,
            test_limits(),
            "operation-profile-ref",
            vec![reference_plan],
            vec![Box::new(reference_source)],
        )??;
        assert_eq!(
            reference_outcome.replay_proofs[0].record_count, 2,
            "the reference profile streams two records"
        );
        assert_ne!(
            reference_outcome.replay_proofs[0].first_order_key,
            reference_outcome.replay_proofs[0].last_order_key,
            "the reference profile derives distinct byte-derived keys"
        );
        Ok(())
    }

    #[test]
    fn reference_profile_out_of_order_is_rejected_from_core_held_bytes() -> TestResult {
        let fixture = fixture()?;
        let ordered = vec![
            reference_record("object-a", 1, 10)?,
            reference_record("object-b", 2, 20)?,
        ];
        let plan = make_reference_plan(
            "partition-ref-order",
            0,
            "artifacts/ref-ordered.jsonl",
            &ordered,
            "binding-ref-order",
        )?;
        let records = vec![
            reference_record("object-b", 2, 20)?,
            reference_record("object-a", 1, 10)?,
        ];
        let source = RecordSliceSource::new(
            records,
            plan.source_identity()?,
            plan.source_binding_id.clone(),
            plan.replayability,
        )?;
        let result = publish_with_limits(
            &fixture,
            test_limits(),
            "operation-ref-reversed",
            vec![plan],
            vec![Box::new(source)],
        )?;
        let report = quarantined_report(result);
        assert_eq!(
            report.failure_code, "STREAM_INVALID_ORDER",
            "a decreasing reference position is preserved as an order failure"
        );
        assert!(
            load_sealed_intent(&fixture.ledger, "operation-ref-reversed")?.is_none(),
            "an out-of-order reference stream reaches no seal"
        );
        Ok(())
    }

    #[test]
    fn profile_digest_is_unchanged_by_the_bounded_record_port() -> TestResult {
        assert_eq!(
            hex_encode(test_profile()?.digest()),
            "fd9ed2d5e618b94cb829b824d2531f4857efbdede7901c475245a90ca80f28ce",
            "the role profile digest predates the bounded record port"
        );
        Ok(())
    }

    #[test]
    fn spool_refuses_an_oversized_write_from_an_adapter() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let mut plan = make_plan(
            "partition-spool",
            0,
            "artifacts/spooled.jsonl",
            CompressionMode::None,
            &records,
        )?;
        plan.replayability = Replayability::NonReplayable;
        let planned = spool_plan_for("operation-spool-oversized", 0, &plan)?;
        let mut source = SinkWriterSource::new(&plan, vec![vec![b'a'; 4_097]], false)?;
        let mut disk = 0_u64;
        let result = spool_non_replayable(
            &mut source,
            &plan,
            &planned,
            &fixture.spool,
            &fixture.ledger,
            "test-preparation-digest",
            &test_profile()?,
            &mut disk,
            SpoolFault::None,
        );
        assert!(
            matches!(result, Err(StreamError::PolicyExceeded(_))),
            "the spool path uses the same core bound as the artifact path"
        );
        assert!(
            !spool_evidence_file(&fixture.ledger, &planned.spool_file_id).exists(),
            "no spool seal exists after an oversized write"
        );
        Ok(())
    }

    #[test]
    fn core_owns_the_only_record_handoff() {
        let source = include_str!("ndc_stream.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(
            !production.contains("fn next_record("),
            "the pre-materialized record method is absent from the source port"
        );
        assert!(
            !production.contains("VecDeque"),
            "the adapter-owned record queue is removed from the streaming path"
        );
        assert!(
            production.contains("RecordSink"),
            "the core sink is the one record handoff"
        );
    }

    #[test]
    fn canonical_byte_validation_rejects_malformed_forms() -> TestResult {
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &[sequenced_record("abstract-1", 1)?],
        )?;
        let policy = test_profile()?.limits().to_resource_policy();
        let mut tracker = OrderTracker::new(&plan)?;
        let cases = [
            Vec::new(),
            vec![0xef, 0xbb, 0xbf, b'{', b'}'],
            b"{\"a\": 1}".to_vec(),
            b"{\"nul\":\x00}".to_vec(),
            b"{\"cr\":\"a\rb\"}".to_vec(),
        ];
        for bytes in cases {
            assert!(
                matches!(
                    tracker.observe(&plan.path, &bytes, 0, &policy),
                    Err(StreamError::InvalidRecord(_, _))
                ),
                "malformed or non-canonical bytes are refused"
            );
        }
        Ok(())
    }

    #[test]
    fn byte_derived_ordering_accepts_an_increasing_stream() -> TestResult {
        let records = vec![
            sequenced_record("abstract-1", 1)?,
            sequenced_record("abstract-2", 2)?,
        ];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let policy = test_profile()?.limits().to_resource_policy();
        let mut tracker = OrderTracker::new(&plan)?;
        for (index, record) in records.iter().enumerate() {
            tracker.observe(&plan.path, &record.bytes, index, &policy)?;
        }
        assert_ne!(
            plan.first_order_key, plan.last_order_key,
            "distinct ordered records produce distinct derived keys"
        );
        Ok(())
    }

    #[test]
    fn wrong_domain_or_epoch_is_rejected() -> TestResult {
        let mut record = sequenced_record("abstract-1", 1)?;
        let text = String::from_utf8(record.bytes)?;
        let wrong = text.replace("domain-a", "domain-b");
        record.bytes = wrong.into_bytes();
        let policy = test_profile()?.limits().to_resource_policy();
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &[sequenced_record("abstract-1", 1)?],
        )?;
        let mut tracker = OrderTracker::new(&plan)?;
        assert!(
            matches!(
                tracker.observe(&plan.path, &record.bytes, 0, &policy),
                Err(StreamError::InvalidRecordOrder(_, reason))
                    if reason.contains("domain or epoch")
            ),
            "a derived key outside the declared domain is refused"
        );
        Ok(())
    }

    #[test]
    fn duplicate_and_decreasing_positions_are_rejected() -> TestResult {
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &[sequenced_record("abstract-1", 1)?],
        )?;
        let policy = test_profile()?.limits().to_resource_policy();
        let mut duplicate = OrderTracker::new(&plan)?;
        duplicate.observe(
            &plan.path,
            &sequenced_record("abstract-1", 1)?.bytes,
            0,
            &policy,
        )?;
        assert!(
            matches!(
                duplicate.observe(&plan.path, &sequenced_record("abstract-x", 1)?.bytes, 1, &policy),
                Err(StreamError::InvalidRecordOrder(_, reason)) if reason.contains("duplicate")
            ),
            "equal derived positions are refused"
        );
        let mut decreasing = OrderTracker::new(&plan)?;
        decreasing.observe(
            &plan.path,
            &sequenced_record("abstract-1", 2)?.bytes,
            0,
            &policy,
        )?;
        assert!(
            matches!(
                decreasing.observe(&plan.path, &sequenced_record("abstract-2", 1)?.bytes, 1, &policy),
                Err(StreamError::InvalidRecordOrder(_, reason)) if reason.contains("backwards")
            ),
            "a decreasing derived position is refused"
        );
        Ok(())
    }

    #[test]
    fn dataset_digest_matches_the_batch_stream_definition() -> TestResult {
        let fixture = fixture()?;
        let records = vec![
            sequenced_record("abstract-1", 1)?,
            sequenced_record("abstract-2", 2)?,
        ];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let outcome = publish(
            &fixture,
            vec![plan],
            sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let mut expected = Vec::new();
        for record in &records {
            expected.extend_from_slice(&record.bytes);
            expected.push(b'\n');
        }
        assert_eq!(
            outcome.recovery_evidence.data_sha256,
            hex_encode(&sha256_bytes(&expected)),
            "the dataset digest covers ordered uncompressed artifact streams"
        );
        assert_eq!(
            outcome.receipt.data_sha256, outcome.recovery_evidence.data_sha256,
            "the receipt carries the same dataset digest"
        );
        Ok(())
    }

    #[test]
    fn manifest_and_sidecar_match_the_batch_producer_bytes() -> TestResult {
        let stream_fixture = fixture()?;
        let records = vec![
            sequenced_record("abstract-1", 1)?,
            sequenced_record("abstract-2", 2)?,
        ];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let streamed = publish(
            &stream_fixture,
            vec![plan.clone()],
            sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let batch_fixture = fixture()?;
        let manifest = test_manifest()?;
        let evidence = test_evidence()?;
        let observed = BTreeSet::new();
        let (signing, verifying) = test_keys();
        let profile = test_profile()?;
        let policy = profile.limits().to_resource_policy();
        let input = ndc_release::ArtifactInput {
            logical_partition_id: plan.logical_partition_id.clone(),
            shard_ordinal: plan.shard_ordinal,
            path: plan.path.clone(),
            record_order_profile: plan.record_order_profile.clone(),
            encoding: plan.encoding.clone(),
            compression: ndc_release::ArtifactCompression::None,
            records,
        };
        let lineage = ndc_release::LineageContext {
            predecessor: None,
            known_receipts: &[],
            now_ns: 0,
        };
        let batch = ndc_release::build_release(&ndc_release::BuildRequest {
            release_root: &batch_fixture.root,
            ledger_dir: &batch_fixture.ledger,
            operation_id: "operation-b15-batch",
            commit_position: "commit-b15",
            manifest: &manifest,
            evidence: &evidence,
            observed_event_types: &observed,
            artifacts: &[input],
            signature: SignatureConfig {
                signing_key: &signing,
                verifying_key: &verifying,
                key_id: &manifest.publication_identity.signing_key_id,
            },
            policy: &policy,
            lineage,
        })?;
        assert_eq!(
            streamed.manifest_bytes, batch.manifest_bytes,
            "the streaming manifest is byte-identical to the batch manifest"
        );
        assert_eq!(
            streamed.sidecar_bytes, batch.sidecar_bytes,
            "the streaming sidecar is byte-identical to the batch sidecar"
        );
        assert_eq!(
            streamed.recovery_evidence.data_sha256, batch.evidence.data_sha256,
            "both producers derive the same dataset digest"
        );
        Ok(())
    }

    #[test]
    fn gzip_output_is_byte_identical_to_the_batch_encoder() -> TestResult {
        let fixture = fixture()?;
        let records = vec![
            sequenced_record("abstract-1", 1)?,
            sequenced_record("abstract-2", 2)?,
        ];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/gzip.jsonl.gz",
            CompressionMode::Gzip,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let outcome = publish(
            &fixture,
            vec![plan],
            sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let stored = fs::read(
            fixture
                .root
                .join("release-b15-test/artifacts/gzip.jsonl.gz"),
        )?;
        let mut expected_input = Vec::new();
        for record in &records {
            expected_input.extend_from_slice(&record.bytes);
            expected_input.push(b'\n');
        }
        let expected = ndc_release::compress_test_vector(&expected_input)?;
        assert_eq!(
            stored, expected,
            "streaming gzip bytes equal the registered batch encoder"
        );
        assert_eq!(
            outcome.descriptors[0].stored_bytes,
            u64::try_from(stored.len())?,
            "the descriptor counts the exact stored bytes"
        );
        Ok(())
    }

    #[test]
    fn gzip_output_is_deterministic_across_repeated_runs() -> TestResult {
        let mut outputs = Vec::new();
        for operation in 0..2 {
            let fixture = fixture()?;
            let records = vec![sequenced_record("abstract-repeat", 1)?];
            let mut plan = make_plan(
                "partition-a",
                0,
                "artifacts/repeat.jsonl.gz",
                CompressionMode::Gzip,
                &records,
            )?;
            plan.source_snapshot_id = format!("SNAPSHOT_{operation}");
            let sources = vec![source_for(&plan, &records)?];
            let outcome = publish(
                &fixture,
                vec![plan],
                sources,
                StreamFaults::default(),
                Cancellation::new(),
            )??;
            outputs.push((
                fs::read(
                    fixture
                        .root
                        .join("release-b15-test/artifacts/repeat.jsonl.gz"),
                )?,
                outcome.sidecar_bytes,
            ));
        }
        assert_eq!(outputs[0].0, outputs[1].0, "gzip bytes repeat exactly");
        assert_eq!(outputs[0].1, outputs[1].1, "sidecar bytes repeat exactly");
        Ok(())
    }

    #[test]
    fn unregistered_gzip_codec_profile_fails_closed() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let mut plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl.gz",
            CompressionMode::Gzip,
            &records,
        )?;
        plan.compression_profile_id = "UNREGISTERED-GZIP".to_owned();
        let manifest = test_manifest()?;
        let evidence = test_evidence()?;
        let observed = BTreeSet::new();
        let (signing, verifying) = test_keys();
        let profile = test_profile()?;
        let mut selection = ProfileSelection::new();
        selection.insert_test_only(profile.clone())?;
        let result = publish_streaming(StreamingBuildRequest {
            release_root: &fixture.root,
            ledger_dir: &fixture.ledger,
            spool_dir: &fixture.spool,
            operation_id: "operation-unregistered-codec",
            commit_position: "commit-b15",
            manifest: &manifest,
            evidence: &evidence,
            observed_event_types: &observed,
            signature: SignatureConfig {
                signing_key: &signing,
                verifying_key: &verifying,
                key_id: &manifest.publication_identity.signing_key_id,
            },
            sources: vec![source_for(&plan, &records)?],
            plans: &[plan],
            profile: &profile,
            profile_selection: &selection,
            context: InvocationContext::TestHarness,
            cancellation: Cancellation::new(),
            faults: StreamFaults::default(),
        });
        assert!(
            matches!(result, Err(StreamError::CodecProfileUnregistered(_))),
            "no gzip codec identifier is registered by the ratification"
        );
        Ok(())
    }

    #[test]
    fn production_invocation_refuses_a_test_only_profile_before_opening_a_source() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let manifest = test_manifest()?;
        let evidence = test_evidence()?;
        let observed = BTreeSet::new();
        let (signing, verifying) = test_keys();
        let profile = test_profile()?;
        let selection = ProfileSelection::new();
        let result = publish_streaming(StreamingBuildRequest {
            release_root: &fixture.root,
            ledger_dir: &fixture.ledger,
            spool_dir: &fixture.spool,
            operation_id: "operation-production-refusal",
            commit_position: "commit-b15",
            manifest: &manifest,
            evidence: &evidence,
            observed_event_types: &observed,
            signature: SignatureConfig {
                signing_key: &signing,
                verifying_key: &verifying,
                key_id: &manifest.publication_identity.signing_key_id,
            },
            sources: vec![source_for(&plan, &records)?],
            plans: &[plan],
            profile: &profile,
            profile_selection: &selection,
            context: InvocationContext::Production,
            cancellation: Cancellation::new(),
            faults: StreamFaults::default(),
        });
        assert!(
            matches!(
                result,
                Err(StreamError::Profile(ProfileError::NoApprovedProfile(_)))
            ),
            "no production invocation without a registered approved profile"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn record_and_byte_limits_are_enforced_at_the_boundary() -> TestResult {
        let fixture = fixture()?;
        let records = vec![
            sequenced_record("abstract-1", 1)?,
            sequenced_record("abstract-2", 2)?,
        ];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let mut limits = test_limits();
        limits.max_records_per_artifact = 1;
        limits.queue_capacity_records = 1;
        let profile = ResourceProfile::new_test_only(
            ResourceProfileId::new("STREAM_B15_TEST_ONLY_TIGHT_V1", 1)?,
            ProcessingRole::Producer,
            ProfileLimits::new(limits)?,
        )?;
        let manifest = test_manifest()?;
        let evidence = test_evidence()?;
        let observed = BTreeSet::new();
        let (signing, verifying) = test_keys();
        let mut selection = ProfileSelection::new();
        selection.insert_test_only(profile.clone())?;
        let result = publish_streaming(StreamingBuildRequest {
            release_root: &fixture.root,
            ledger_dir: &fixture.ledger,
            spool_dir: &fixture.spool,
            operation_id: "operation-count-bound",
            commit_position: "commit-b15",
            manifest: &manifest,
            evidence: &evidence,
            observed_event_types: &observed,
            signature: SignatureConfig {
                signing_key: &signing,
                verifying_key: &verifying,
                key_id: &manifest.publication_identity.signing_key_id,
            },
            sources: vec![source_for(&plan, &records)?],
            plans: &[plan],
            profile: &profile,
            profile_selection: &selection,
            context: InvocationContext::TestHarness,
            cancellation: Cancellation::new(),
            faults: StreamFaults::default(),
        });
        let report = quarantined_report(result);
        assert_eq!(
            report.failure_code, "STREAM_POLICY_EXCEEDED",
            "the record bound failure is preserved"
        );
        assert!(
            report.first_failure.contains("max_records_per_artifact"),
            "the record count is checked on the second record"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn memory_budget_below_the_fixed_state_ceiling_is_refused() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let mut limits = test_limits();
        limits.memory_budget_bytes = 1_024;
        let profile = ResourceProfile::new_test_only(
            ResourceProfileId::new("STREAM_B15_TEST_ONLY_SMALL_RSS_V1", 1)?,
            ProcessingRole::Producer,
            ProfileLimits::new(limits)?,
        )?;
        let manifest = test_manifest()?;
        let evidence = test_evidence()?;
        let observed = BTreeSet::new();
        let (signing, verifying) = test_keys();
        let mut selection = ProfileSelection::new();
        selection.insert_test_only(profile.clone())?;
        let result = publish_streaming(StreamingBuildRequest {
            release_root: &fixture.root,
            ledger_dir: &fixture.ledger,
            spool_dir: &fixture.spool,
            operation_id: "operation-memory-bound",
            commit_position: "commit-b15",
            manifest: &manifest,
            evidence: &evidence,
            observed_event_types: &observed,
            signature: SignatureConfig {
                signing_key: &signing,
                verifying_key: &verifying,
                key_id: &manifest.publication_identity.signing_key_id,
            },
            sources: vec![source_for(&plan, &records)?],
            plans: &[plan],
            profile: &profile,
            profile_selection: &selection,
            context: InvocationContext::TestHarness,
            cancellation: Cancellation::new(),
            faults: StreamFaults::default(),
        });
        assert!(
            matches!(
                result,
                Err(StreamError::PolicyExceeded(bound))
                    if bound.contains("memory_budget_bytes")
            ),
            "a role memory budget below the fixed state ceiling is refused before source open"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn cancellation_before_seal_leaves_no_evidence_of_availability() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let result = publish(
            &fixture,
            vec![plan],
            sources,
            StreamFaults {
                cancel_before_seal: true,
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )?;
        let report = match result {
            Err(StreamError::PreparationQuarantined(report)) => report,
            other => panic!("cancellation before seal must quarantine: {other:?}"),
        };
        assert_eq!(
            report.failure_code, "STREAM_CANCELLED_BEFORE_SEAL",
            "the first failure code is preserved"
        ); // cancellation is the preserved first failure
        assert_eq!(
            report.quarantine_state,
            PreparationState::QuarantinedDurable,
            "quarantine"
        ); // cancellation before seal is quarantined
        assert!(
            !sealed_file(&fixture.ledger, "operation-b15").exists(),
            "cancellation before seal writes no sealed intent"
        );
        assert_quarantine_record(&fixture, "operation-b15")?;
        assert_no_availability(&fixture)?;
        Ok(())
    }

    fn plan_for_cancel() -> ArtifactPlan {
        ArtifactPlan {
            logical_partition_id: "partition-a".to_owned(),
            shard_ordinal: 0,
            path: "artifacts/a.jsonl".to_owned(),
            record_order_profile: RecordOrderProfile::Sequenced {
                sequence_domain: "domain-a".to_owned(),
                sequence_epoch: "epoch-1".to_owned(),
            },
            encoding: ENCODING_NDJSON.to_owned(),
            compression: CompressionMode::None,
            compression_profile_id: COMPRESSION_VERSION_NONE.to_owned(),
            source_snapshot_id: "SNAPSHOT_A".to_owned(),
            source_revision: "rev-1".to_owned(),
            source_binding_id: "binding-cancel".to_owned(),
            replayability: Replayability::Replayable,
            source_content_digest: String::new(),
            expected_record_count: 1,
            first_order_key: String::new(),
            last_order_key: String::new(),
        }
    }

    #[test]
    fn cancellation_after_seal_never_short_cuts_to_available() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let result = publish(
            &fixture,
            vec![plan],
            sources,
            StreamFaults {
                cancel_after_seal: true,
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )?;
        assert!(
            matches!(result, Err(StreamError::CancellationAfterSeal(_))),
            "a signal after the seal is a distinct typed outcome"
        );
        assert!(
            sealed_file(&fixture.ledger, "operation-b15").exists(),
            "the seal exists before the late cancellation"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn crash_before_seal_is_never_available_and_recovery_quarantines() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let result = publish(
            &fixture,
            vec![plan],
            sources,
            StreamFaults {
                crash_before_seal: true,
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )?;
        let report = match result {
            Err(StreamError::PreparationQuarantined(report)) => report,
            other => panic!("an injected crash before seal must quarantine: {other:?}"),
        };
        assert_eq!(
            report.quarantine_state,
            PreparationState::QuarantinedDurable,
            "quarantine"
        ); // crash before seal is quarantined
        assert!(
            preparation_file(&fixture.ledger, "operation-b15").exists(),
            "the preparation intent is durable before consumption"
        );
        assert!(
            !sealed_file(&fixture.ledger, "operation-b15").exists(),
            "no sealed intent exists after a crash before seal"
        );
        let policy = test_profile()?.limits().to_resource_policy();
        let recovered = recover_streaming(
            &fixture.root,
            &fixture.ledger,
            &fixture.spool,
            "operation-b15",
            &policy,
        )?;
        assert_eq!(
            recovered,
            StreamRecoveryOutcome::PreparationOnlyQuarantined(PreparationState::QuarantinedDurable),
            "recovery verifies the durable quarantine without a seal"
        );
        assert_quarantine_record(&fixture, "operation-b15")?;
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn replay_proof_members_each_fail_closed() -> TestResult {
        let base = vec![
            sequenced_record("abstract-1", 1)?,
            sequenced_record("abstract-2", 2)?,
        ];
        let committed = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &base,
        )?;
        let cases: Vec<(Vec<CanonicalRecord>, &'static str)> = vec![
            (
                vec![
                    sequenced_record("abstract-changed", 1)?,
                    sequenced_record("abstract-2", 2)?,
                ],
                "source_content_digest",
            ),
            (vec![sequenced_record("abstract-1", 1)?], "record count"),
            (
                vec![
                    sequenced_record("abstract-1", 3)?,
                    sequenced_record("abstract-2", 4)?,
                ],
                "first order key",
            ),
            (
                vec![
                    sequenced_record("abstract-1", 1)?,
                    sequenced_record("abstract-2", 5)?,
                ],
                "last order key",
            ),
        ];
        for (records, member) in cases {
            let mut source_plan = make_plan(
                "partition-a",
                0,
                "artifacts/a.jsonl",
                CompressionMode::None,
                &records,
            )?;
            source_plan.replayability = Replayability::Replayable;
            match member {
                "source_content_digest" => {
                    source_plan.source_content_digest = committed.source_content_digest.clone();
                }
                "record count" => {
                    source_plan.expected_record_count = committed.expected_record_count;
                }
                "first order key" => {
                    source_plan.first_order_key = committed.first_order_key.clone();
                }
                "last order key" => {
                    source_plan.last_order_key = committed.last_order_key.clone();
                }
                other => return Err(format!("unknown replay case {other}").into()),
            }
            let fixture = fixture()?;
            let sources = vec![source_for(&source_plan, &records)?];
            let result = publish(
                &fixture,
                vec![source_plan],
                sources,
                StreamFaults::default(),
                Cancellation::new(),
            )?;
            let report = quarantined_report(result);
            assert_eq!(
                report.failure_code, "STREAM_REPLAY_MISMATCH",
                "a differing {member} member is the preserved first failure"
            );
            assert!(
                report.first_failure.contains(member),
                "a differing {member} member quarantines before availability"
            );
            assert_no_availability(&fixture)?;
        }
        Ok(())
    }

    #[test]
    fn source_identity_mismatch_refuses_before_consumption() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let mut source = source_for(&plan, &records)?;
        let record = TestReader::new(4_096)
            .next(source.as_mut())?
            .expect("the source has one record");
        let mut wrong = plan.clone();
        wrong.source_revision = "rev-2".to_owned();
        let wrong_source = BoundedRecordFramer::new(
            Cursor::new({
                let mut bytes = record.bytes;
                bytes.push(b'\n');
                bytes
            }),
            wrong.source_identity()?,
            wrong.source_binding_id.clone(),
            Replayability::Replayable,
            4_096,
        )?;
        let manifest = test_manifest()?;
        let evidence = test_evidence()?;
        let observed = BTreeSet::new();
        let (signing, verifying) = test_keys();
        let profile = test_profile()?;
        let mut selection = ProfileSelection::new();
        selection.insert_test_only(profile.clone())?;
        let result = publish_streaming(StreamingBuildRequest {
            release_root: &fixture.root,
            ledger_dir: &fixture.ledger,
            spool_dir: &fixture.spool,
            operation_id: "operation-identity-mismatch",
            commit_position: "commit-b15",
            manifest: &manifest,
            evidence: &evidence,
            observed_event_types: &observed,
            signature: SignatureConfig {
                signing_key: &signing,
                verifying_key: &verifying,
                key_id: &manifest.publication_identity.signing_key_id,
            },
            sources: vec![Box::new(wrong_source)],
            plans: &[plan],
            profile: &profile,
            profile_selection: &selection,
            context: InvocationContext::TestHarness,
            cancellation: Cancellation::new(),
            faults: StreamFaults::default(),
        });
        let report = quarantined_report(result);
        assert_eq!(
            report.failure_code, "STREAM_SOURCE_IDENTITY",
            "identity refusal"
        ); // identity mismatch is the preserved first failure
        Ok(())
    }

    #[test]
    fn non_replayable_source_is_spooled_and_a_truncated_spool_is_quarantined() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let mut plan = make_plan(
            "partition-a",
            0,
            "artifacts/spooled.jsonl",
            CompressionMode::None,
            &records,
        )?;
        plan.replayability = Replayability::NonReplayable;
        let (evidence, _) = spool_for_test(&fixture, "operation-spool", &plan, &records)?;
        let _verified = verify_spool(&fixture.spool, &evidence, &test_profile()?)?;
        let path = fixture.spool.join(&evidence.spool_file_id);
        let mut bytes = fs::read(&path)?;
        bytes.truncate(bytes.len().saturating_sub(1));
        fs::write(&path, bytes)?;
        assert!(
            matches!(
                verify_spool(&fixture.spool, &evidence, &test_profile()?),
                Err(StreamError::SpoolEvidenceMismatch(..))
            ),
            "a truncated spool is retained as quarantine evidence, not adopted"
        );
        assert!(
            spool_evidence_file(&fixture.ledger, &evidence.spool_file_id).exists(),
            "the spool seal survives a mismatch"
        );
        Ok(())
    }

    #[test]
    fn streaming_path_has_no_whole_artifact_vector_or_sort() {
        let source = include_str!("ndc_stream.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for forbidden in [
            "read_until",
            "Vec<CanonicalRecord>",
            "sort_byte_derived",
            "PreparedRelease",
            "Vec<Vec<u8>>",
            "uncompressed.extend_from_slice",
            "stored.extend_from_slice",
        ] {
            assert!(
                !production.contains(forbidden),
                "the streaming path must not contain `{forbidden}`"
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[expect(
        unsafe_code,
        reason = "getrusage reports process peak memory through the libc interface"
    )]
    fn peak_rss_bytes() -> TestResult<u64> {
        // SAFETY: `usage` is a plain data struct whose zero bit pattern is
        // valid before the system call fills it.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: `usage` is writable for the platform rusage layout and the
        // process handle is valid for this call.
        let status = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        if status != 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }
        let reported = u64::try_from(usage.ru_maxrss)?;
        #[cfg(target_os = "linux")]
        {
            Ok(reported.saturating_mul(1024))
        }
        #[cfg(target_os = "macos")]
        {
            Ok(reported)
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn spawn_streaming_rss_child(scale: u64) -> TestResult<u64> {
        let output = Command::new(env::current_exe()?)
            .arg("--exact")
            .arg(RSS_CHILD_TEST)
            .arg("--nocapture")
            .env(RSS_CHILD_ENV, "1")
            .env(RSS_SCALE_ENV, scale.to_string())
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let status = output.status.to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            output.status.success(),
            "RSS child at scale {scale} exited with {status}: {stderr}"
        );
        let reported = stdout
            .lines()
            .find_map(|line| line.strip_prefix("FB_B15_RSS_BYTES="))
            .ok_or_else(|| io::Error::other("the RSS child reported no peak RSS"))?;
        Ok(reported.parse()?)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn streaming_rss_child() -> TestResult {
        let Ok(scale) = env::var(RSS_SCALE_ENV) else {
            return Ok(());
        };
        let scale = scale.parse::<u64>()?;
        let count = 8_u64.saturating_mul(scale);
        let fixture = fixture()?;
        let records = (1..=count)
            .map(|number| sequenced_record("abstract-rss", number))
            .collect::<TestResult<Vec<CanonicalRecord>>>()?;
        let plan = make_plan(
            "partition-rss",
            0,
            "artifacts/rss.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let outcome = publish(
            &fixture,
            vec![plan],
            sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let _ = outcome;
        println!("FB_B15_RSS_BYTES={}", peak_rss_bytes()?);
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn rss_plateau_holds_across_one_two_and_four_times_the_volume() -> TestResult {
        let samples = [
            spawn_streaming_rss_child(1)?,
            spawn_streaming_rss_child(2)?,
            spawn_streaming_rss_child(4)?,
        ];
        let highest = samples.iter().copied().max().unwrap_or(0);
        let lowest = samples.iter().copied().min().unwrap_or(0);
        assert!(
            highest <= lowest.saturating_add(32 * 1024 * 1024),
            "peak RSS plateaus across 1x, 2x and 4x: {samples:?}"
        );
        assert!(
            highest <= RSS_PROFILE_MEMORY_BUDGET,
            "peak RSS stays below the finite test-only profile budget: {samples:?}"
        );
        Ok(())
    }

    #[test]
    fn sealed_intent_chain_is_verified_on_recovery() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let outcome = publish(
            &fixture,
            vec![plan],
            sources,
            StreamFaults::default(),
            Cancellation::new(),
        )?;
        let outcome = outcome?;
        assert!(
            !outcome.preparation_intent_sha256.is_empty(),
            "the preparation digest is bound into the outcome"
        );
        assert!(
            !outcome.sealed_intent_sha256.is_empty(),
            "the seal digest is bound into the outcome"
        );
        assert_eq!(
            outcome.replay_proofs.len(),
            1,
            "one replay proof is retained per artifact"
        );
        let manifest_bytes = fs::read(fixture.root.join("release-b15-test/manifest.json"))?;
        assert_eq!(
            manifest_bytes, outcome.manifest_bytes,
            "the published manifest is the sealed manifest"
        );
        Ok(())
    }

    struct CountingSource {
        inner: Box<dyn ArtifactRecordSource>,
        completions: Arc<AtomicUsize>,
        reads: Arc<AtomicUsize>,
        completed: bool,
    }

    impl ArtifactRecordSource for CountingSource {
        fn source_identity(&self) -> SourceIdentity {
            self.inner.source_identity()
        }

        fn source_binding_id(&self) -> String {
            self.inner.source_binding_id()
        }

        fn replayability(&self) -> Replayability {
            self.inner.replayability()
        }

        fn write_next_record(&mut self, sink: &mut RecordSink<'_>) -> Result<bool, StreamError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let written = self.inner.write_next_record(sink)?;
            if !written && !self.completed {
                self.completed = true;
                self.completions
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            Ok(written)
        }

        fn max_record_bytes(&self) -> u64 {
            self.inner.max_record_bytes()
        }
    }

    struct ShuffledCase {
        plans: Vec<ArtifactPlan>,
        sources: Vec<Box<dyn ArtifactRecordSource>>,
        records: Vec<Vec<CanonicalRecord>>,
        completions: Vec<Arc<AtomicUsize>>,
    }

    fn shuffled_case() -> TestResult<ShuffledCase> {
        let specs = [
            (
                "partition-c",
                0_u32,
                "artifacts/c.jsonl",
                "value-c",
                7_u64,
                "binding-c",
                false,
            ),
            (
                "partition-a",
                1,
                "artifacts/a1.jsonl",
                "value-a1",
                3,
                "binding-a1",
                false,
            ),
            (
                "partition-b",
                0,
                "artifacts/b.jsonl",
                "value-b",
                5,
                "binding-b",
                true,
            ),
            (
                "partition-a",
                0,
                "artifacts/a0.jsonl",
                "value-a0",
                1,
                "binding-a0",
                true,
            ),
        ];
        let mut plans = Vec::new();
        let mut sources: Vec<Box<dyn ArtifactRecordSource>> = Vec::new();
        let mut all_records = Vec::new();
        let mut completions = Vec::new();
        let mut reads = Vec::new();
        for (partition, shard, path, text, number, binding, non_replayable) in specs {
            let records = vec![
                sequenced_record(text, number)?,
                sequenced_record(&format!("{text}-next"), number.saturating_add(1))?,
            ];
            let mut plan = make_plan_with_binding(
                partition,
                shard,
                path,
                CompressionMode::None,
                &records,
                binding,
            )?;
            plan.source_snapshot_id = "SHARED_SNAPSHOT".to_owned();
            plan.source_revision = "rev-shared".to_owned();
            if non_replayable {
                plan.replayability = Replayability::NonReplayable;
            }
            let inner = source_for(&plan, &records)?;
            let completion = Arc::new(AtomicUsize::new(0));
            let read = Arc::new(AtomicUsize::new(0));
            sources.push(Box::new(CountingSource {
                inner,
                completions: completion.clone(),
                reads: read.clone(),
                completed: false,
            }));
            completions.push(completion);
            reads.push(read);
            all_records.push(records);
            plans.push(plan);
        }
        Ok(ShuffledCase {
            plans,
            sources,
            records: all_records,
            completions,
        })
    }

    fn canonical_expectation(
        plans: &[ArtifactPlan],
        records: &[Vec<CanonicalRecord>],
    ) -> Vec<(ArtifactPlan, Vec<CanonicalRecord>)> {
        let mut expected: Vec<(ArtifactPlan, Vec<CanonicalRecord>)> =
            plans.iter().cloned().zip(records.iter().cloned()).collect();
        expected.sort_by(|left, right| {
            left.0
                .logical_partition_id
                .cmp(&right.0.logical_partition_id)
                .then(left.0.shard_ordinal.cmp(&right.0.shard_ordinal))
        });
        expected
    }

    fn stream_digest(records: &[CanonicalRecord]) -> String {
        hex_encode(
            &records
                .iter()
                .fold(Sha256::new(), |mut hasher, record| {
                    hasher.update(&record.bytes);
                    hasher.update(b"\n");
                    hasher
                })
                .finalize(),
        )
    }

    #[test]
    fn shuffled_source_binding_pairs_survive_canonical_sort() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let expected = canonical_expectation(&case.plans, &case.records);
        assert_eq!(
            outcome.descriptors.len(),
            expected.len(),
            "every shuffled artifact produced one descriptor"
        );
        for (index, (plan, _)) in expected.iter().enumerate() {
            let descriptor = &outcome.descriptors[index];
            assert_eq!(
                (
                    descriptor.logical_partition_id.as_str(),
                    descriptor.shard_ordinal,
                    descriptor.path.as_str()
                ),
                (
                    plan.logical_partition_id.as_str(),
                    plan.shard_ordinal,
                    plan.path.as_str()
                ),
                "descriptor {index} carries the canonical position of its paired plan"
            );
        }
        Ok(())
    }

    #[test]
    fn shuffled_descriptors_digest_and_count_match_assigned_source() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let expected = canonical_expectation(&case.plans, &case.records);
        for (index, (_, records)) in expected.iter().enumerate() {
            let descriptor = &outcome.descriptors[index];
            assert_eq!(
                descriptor.uncompressed_sha256,
                stream_digest(records),
                "descriptor {index} digests the bytes of its assigned source"
            );
            assert_eq!(
                descriptor.record_count,
                u64::try_from(records.len())?,
                "descriptor {index} counts the records of its assigned source"
            );
            assert_eq!(
                outcome.source_bindings[index].binding_id, expected[index].0.source_binding_id,
                "descriptor {index} carries the binding of its assigned source"
            );
        }
        Ok(())
    }

    #[test]
    fn shuffled_replay_proofs_match_assigned_plans() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let expected = canonical_expectation(&case.plans, &case.records);
        assert_eq!(
            outcome.replay_proofs.len(),
            expected.len(),
            "one proof is retained for each artifact"
        );
        for (index, (plan, records)) in expected.iter().enumerate() {
            let proof = &outcome.replay_proofs[index];
            verify_replay_proof(&plan.path, plan, proof)?;
            assert_eq!(
                proof.source_binding_id, plan.source_binding_id,
                "proof {index} binds the plan's source stream"
            );
            assert_eq!(
                proof.source_content_digest,
                stream_digest(records),
                "proof {index} digests the assigned source"
            );
        }
        Ok(())
    }

    #[test]
    fn shuffled_sources_are_consumed_to_end_once_each() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let _outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        for (index, counter) in case.completions.iter().enumerate() {
            assert_eq!(
                counter.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "source {index} reached end of stream in one pass"
            );
        }
        Ok(())
    }

    #[test]
    fn shuffled_non_replayable_sources_write_separate_binding_spools() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let _outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let files: Vec<String> = fs::read_dir(&fixture.spool)?
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect();
        let expected = canonical_expectation(&case.plans, &case.records);
        for (ordinal, (plan, _)) in expected
            .iter()
            .enumerate()
            .filter(|(_, (plan, _))| plan.replayability == Replayability::NonReplayable)
        {
            let spool_id = spool_file_id("operation-b15", ordinal, &plan.source_binding_id)?;
            let file_context = format!("binding {} has its own spool file", plan.source_binding_id);
            assert!(files.contains(&spool_id), "{file_context}");
            let evidence_context = format!(
                "binding {} has its own sealed spool evidence",
                plan.source_binding_id
            );
            assert!(
                spool_evidence_file(&fixture.ledger, &spool_id).exists(),
                "{evidence_context}"
            );
        }
        Ok(())
    }

    #[test]
    fn shuffled_preparation_intent_carries_canonical_source_bindings() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let preparation = load_preparation_intent(&fixture.ledger, "operation-b15")?
            .ok_or_else(|| io::Error::other("the preparation intent is missing"))?;
        let expected = canonical_expectation(&case.plans, &case.records);
        let canonical: Vec<ArtifactSourceBinding> = expected
            .iter()
            .map(|(plan, _)| plan.source_binding())
            .collect();
        assert_eq!(
            preparation.source_bindings, canonical,
            "preparation evidence binds each canonical position to one stream"
        );
        assert_eq!(
            outcome.source_bindings, canonical,
            "the outcome exposes the same canonical bindings"
        );
        Ok(())
    }

    #[test]
    fn shuffled_sealed_intent_carries_canonical_source_bindings() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let _outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let sealed = load_sealed_intent(&fixture.ledger, "operation-b15")?
            .ok_or_else(|| io::Error::other("the sealed intent is missing"))?;
        let expected = canonical_expectation(&case.plans, &case.records);
        let canonical: Vec<ArtifactSourceBinding> = expected
            .iter()
            .map(|(plan, _)| plan.source_binding())
            .collect();
        assert_eq!(
            sealed.source_bindings, canonical,
            "the seal repeats the preparation binding order"
        );
        Ok(())
    }

    #[test]
    fn shuffled_recovery_accepts_the_matching_binding_chain() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let _outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let policy = test_profile()?.limits().to_resource_policy();
        let recovered = recover_streaming(
            &fixture.root,
            &fixture.ledger,
            &fixture.spool,
            "operation-b15",
            &policy,
        )?;
        assert!(
            matches!(recovered, StreamRecoveryOutcome::Recovered(_)),
            "a matching binding chain recovers the publication"
        );
        Ok(())
    }

    #[test]
    fn wrong_binding_refuses_before_a_record_is_read() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let inner = BoundedRecordFramer::new(
            Cursor::new(Vec::new()),
            plan.source_identity()?,
            "binding-other",
            plan.replayability,
            test_profile()?.limits().max_record_bytes(),
        )?;
        let read = Arc::new(AtomicUsize::new(0));
        let source = CountingSource {
            inner: Box::new(inner),
            completions: Arc::new(AtomicUsize::new(0)),
            reads: read.clone(),
            completed: false,
        };
        let result = publish(
            &fixture,
            vec![plan],
            vec![Box::new(source) as Box<dyn ArtifactRecordSource>],
            StreamFaults::default(),
            Cancellation::new(),
        )?;
        let report = quarantined_report(result);
        assert_eq!(
            report.failure_code, "STREAM_SOURCE_BINDING",
            "binding refusal"
        ); // binding mismatch is the preserved first failure
        assert_eq!(
            read.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "no record was read from the misbound source"
        );
        assert!(
            !sealed_file(&fixture.ledger, "operation-b15").exists(),
            "a binding mismatch cannot reach the seal"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn wrong_binding_refuses_before_a_non_replayable_source_is_spooled() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let mut plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        plan.replayability = Replayability::NonReplayable;
        let inner = BoundedRecordFramer::new(
            Cursor::new(Vec::new()),
            plan.source_identity()?,
            "binding-other",
            plan.replayability,
            test_profile()?.limits().max_record_bytes(),
        )?;
        let read = Arc::new(AtomicUsize::new(0));
        let source = CountingSource {
            inner: Box::new(inner),
            completions: Arc::new(AtomicUsize::new(0)),
            reads: read.clone(),
            completed: false,
        };
        let result = publish(
            &fixture,
            vec![plan.clone()],
            vec![Box::new(source) as Box<dyn ArtifactRecordSource>],
            StreamFaults::default(),
            Cancellation::new(),
        )?;
        let report = quarantined_report(result);
        assert_eq!(
            report.failure_code, "STREAM_SOURCE_BINDING",
            "spool binding refusal"
        ); // spool binding mismatch is the preserved first failure
        assert_eq!(
            read.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the spool did not consume the misbound source"
        );
        let spool_id = spool_file_id("operation-b15", 0, &plan.source_binding_id)?;
        assert!(
            !fixture.spool.join(spool_id).exists(),
            "no spool bytes were written for the refused source"
        );
        Ok(())
    }

    #[test]
    fn duplicate_artifact_positions_reject_in_shuffled_input() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let mut plans = case.plans.clone();
        plans[0].logical_partition_id = plans[2].logical_partition_id.clone();
        plans[0].shard_ordinal = plans[2].shard_ordinal;
        let result = publish(
            &fixture,
            plans,
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )?;
        assert!(
            matches!(result, Err(StreamError::PolicyExceeded(message)) if message.contains("duplicate artifact position")),
            "two plans at one canonical position are refused"
        );
        assert!(
            !sealed_file(&fixture.ledger, "operation-b15").exists(),
            "a duplicate position cannot reach the seal"
        );
        Ok(())
    }

    #[test]
    fn duplicate_binding_ids_reject_before_preparation() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let mut plans = case.plans.clone();
        plans[0].source_binding_id = plans[1].source_binding_id.clone();
        let result = publish(
            &fixture,
            plans,
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )?;
        assert!(
            matches!(result, Err(StreamError::PolicyExceeded(message)) if message.contains("duplicate artifact binding")),
            "two plans may not claim one source stream"
        );
        assert!(
            !preparation_file(&fixture.ledger, "operation-b15").exists(),
            "a duplicate binding is refused before preparation"
        );
        Ok(())
    }

    #[test]
    fn source_bindings_use_the_opaque_alphabet() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let mut invalid = plan.clone();
        invalid.source_binding_id = String::new();
        let result = publish(
            &fixture,
            vec![invalid],
            sources,
            StreamFaults::default(),
            Cancellation::new(),
        )?;
        assert!(
            matches!(result, Err(StreamError::PolicyExceeded(message)) if message.contains("source binding")),
            "an empty binding is refused"
        );
        assert!(
            BoundedRecordFramer::new(
                Cursor::new(Vec::new()),
                SourceIdentity::new("SNAPSHOT_A", "rev-1")?,
                "binding.with.dot",
                Replayability::Replayable,
                4_096,
            )
            .is_err(),
            "a framer refuses a binding outside the opaque alphabet"
        );
        Ok(())
    }

    #[test]
    fn source_count_mismatch_rejects_before_preparation() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let mut sources = case.sources;
        sources.pop();
        let result = publish(
            &fixture,
            case.plans.clone(),
            sources,
            StreamFaults::default(),
            Cancellation::new(),
        )?;
        assert!(
            matches!(result, Err(StreamError::PolicyExceeded(message)) if message.contains("source count differs")),
            "a missing source is refused before any plan is consumed"
        );
        assert!(
            !preparation_file(&fixture.ledger, "operation-b15").exists(),
            "a count mismatch writes no preparation intent"
        );
        Ok(())
    }

    #[test]
    fn canonical_result_is_independent_of_input_order() -> TestResult {
        let first_fixture = fixture()?;
        let first = shuffled_case()?;
        let first_outcome = publish(
            &first_fixture,
            first.plans.clone(),
            first.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let second_fixture = fixture()?;
        let second = shuffled_case()?;
        let mut second_plans = second.plans.clone();
        let mut second_sources = second.sources;
        second_plans.reverse();
        second_sources.reverse();
        let second_outcome = publish(
            &second_fixture,
            second_plans,
            second_sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        assert_eq!(
            first_outcome.descriptors, second_outcome.descriptors,
            "descriptors do not depend on input permutation"
        );
        assert_eq!(
            first_outcome.replay_proofs, second_outcome.replay_proofs,
            "replay proofs do not depend on input permutation"
        );
        assert_eq!(
            first_outcome.manifest_bytes, second_outcome.manifest_bytes,
            "manifest bytes do not depend on input permutation"
        );
        Ok(())
    }

    #[test]
    fn shuffled_dataset_digest_follows_the_canonical_assignment() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let expected = canonical_expectation(&case.plans, &case.records);
        let mut bytes = Vec::new();
        for (_, records) in expected {
            for record in records {
                bytes.extend_from_slice(&record.bytes);
                bytes.push(b'\n');
            }
        }
        assert_eq!(
            outcome.recovery_evidence.data_sha256,
            hex_encode(&sha256_bytes(&bytes)),
            "the dataset digest follows the canonically assigned sources"
        );
        Ok(())
    }

    #[test]
    fn sealed_inventory_matches_canonical_descriptors() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let sealed = load_sealed_intent(&fixture.ledger, "operation-b15")?
            .ok_or_else(|| io::Error::other("the sealed intent is missing"))?;
        assert_eq!(
            sealed.artifact_inventory, outcome.descriptors,
            "the seal binds the same canonical descriptor inventory"
        );
        for pair in outcome.descriptors.windows(2) {
            assert!(
                (pair[0].logical_partition_id.as_str(), pair[0].shard_ordinal)
                    <= (pair[1].logical_partition_id.as_str(), pair[1].shard_ordinal),
                "descriptors stay in canonical partition and shard order"
            );
        }
        Ok(())
    }

    #[test]
    fn expansion_ratio_at_limit_is_accepted() {
        assert!(
            enforce_expansion_ratio(48, 16, 3).is_ok(),
            "expanded bytes at stored bytes times ratio satisfy the bound"
        );
    }

    #[test]
    fn expansion_ratio_one_byte_over_limit_is_rejected() {
        let error = enforce_expansion_ratio(49, 16, 3)
            .expect_err("one expanded byte above the bound is refused");
        assert!(
            matches!(&error, StreamError::PolicyExceeded(message) if message.contains("max_expansion_ratio")),
            "the typed refusal names the expansion ratio bound"
        );
    }

    #[test]
    fn expansion_ratio_zero_stored_and_zero_expanded_is_accepted() {
        assert!(
            enforce_expansion_ratio(0, 0, 7).is_ok(),
            "an empty artifact has no bytes on either side of the codec"
        );
    }

    #[test]
    fn expansion_ratio_zero_stored_with_expanded_bytes_is_rejected() {
        let error = enforce_expansion_ratio(1, 0, 7)
            .expect_err("expanded bytes without stored bytes are refused");
        assert!(
            matches!(&error, StreamError::PolicyExceeded(message) if message.contains("zero stored bytes")),
            "the refusal names the explicit zero-stored-byte rule"
        );
    }

    #[test]
    fn expansion_ratio_tautological_calculation_is_replaced() {
        let error = enforce_expansion_ratio(1_000, 10, 10)
            .expect_err("the stored-based relation refuses a case the old calculation admitted");
        assert!(
            matches!(&error, StreamError::PolicyExceeded(message) if message.contains("max_expansion_ratio")),
            "the regression case is reported as a ratio bound breach"
        );
    }

    #[test]
    fn expansion_ratio_u64_max_product_is_overflow_safe() {
        assert!(
            enforce_expansion_ratio(u64::MAX, u64::MAX, u64::MAX).is_ok(),
            "the u64 product fits in u128 and is accepted"
        );
    }

    #[test]
    fn expansion_ratio_large_product_rejects_without_overflow() {
        let error = enforce_expansion_ratio((1_u64 << 63) + 1, 1_u64 << 62, 2)
            .expect_err("a wide product above the bound is refused in u128");
        assert!(
            matches!(&error, StreamError::PolicyExceeded(message) if message.contains("max_expansion_ratio")),
            "the wide case reports the ratio bound instead of an arithmetic error"
        );
    }

    #[test]
    fn expansion_ratio_single_stored_byte_boundary_is_enforced() {
        assert!(
            enforce_expansion_ratio(32, 1, 32).is_ok(),
            "one stored byte admits ratio-many expanded bytes"
        );
        let error = enforce_expansion_ratio(33, 1, 32)
            .expect_err("one byte past the single-stored-byte bound is refused");
        assert!(
            matches!(&error, StreamError::PolicyExceeded(message) if message.contains("max_expansion_ratio")),
            "the single-stored-byte breach names the bound"
        );
    }

    #[test]
    fn expansion_ratio_pipeline_plain_at_ratio_one_passes() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let mut limits = test_limits();
        limits.max_expansion_ratio = 1;
        let outcome = publish_with_limits(
            &fixture,
            limits,
            "operation-ratio-plain",
            vec![plan],
            sources,
        )??;
        let descriptor = &outcome.descriptors[0];
        assert_eq!(
            descriptor.uncompressed_bytes, descriptor.stored_bytes,
            "an uncompressed artifact sits at the ratio-one boundary"
        );
        assert!(
            sealed_file(&fixture.ledger, "operation-ratio-plain").exists(),
            "an artifact at the ratio bound reaches the seal"
        );
        Ok(())
    }

    #[test]
    fn expansion_ratio_pipeline_incompressible_gzip_passes() -> TestResult {
        let fixture = fixture()?;
        let records = (0..24)
            .map(|index| sequenced_record(&varied_text(index + 1, 512), index + 1))
            .collect::<TestResult<Vec<_>>>()?;
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl.gz",
            CompressionMode::Gzip,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let mut limits = test_limits();
        limits.max_expansion_ratio = 2;
        let outcome = publish_with_limits(
            &fixture,
            limits,
            "operation-ratio-incompressible",
            vec![plan],
            sources,
        )??;
        let descriptor = &outcome.descriptors[0];
        assert!(
            descriptor.uncompressed_bytes > descriptor.stored_bytes,
            "the gzip framing and varied content remain distinguishable"
        );
        assert!(
            descriptor.uncompressed_bytes <= descriptor.stored_bytes * 2,
            "high-entropy content stays within a ratio of two"
        );
        assert!(
            sealed_file(&fixture.ledger, "operation-ratio-incompressible").exists(),
            "an artifact within the ratio reaches the seal"
        );
        Ok(())
    }

    #[test]
    fn expansion_ratio_pipeline_highly_compressible_rejects() -> TestResult {
        let fixture = fixture()?;
        let repeated = "a".repeat(2_048);
        let records = (0..40)
            .map(|index| sequenced_record(&repeated, index + 1))
            .collect::<TestResult<Vec<_>>>()?;
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl.gz",
            CompressionMode::Gzip,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let outcome = publish_with_limits(
            &fixture,
            test_limits(),
            "operation-ratio-compressible",
            vec![plan],
            sources,
        )?;
        let report = quarantined_report(outcome);
        assert!(
            report.first_failure.contains("max_expansion_ratio"),
            "a compressed stream above the ratio is quarantined before the seal"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn expansion_ratio_rejection_leaves_no_sealed_intent_or_receipt() -> TestResult {
        let fixture = fixture()?;
        let repeated = "a".repeat(1_024);
        let records = (0..32)
            .map(|index| sequenced_record(&repeated, index + 1))
            .collect::<TestResult<Vec<_>>>()?;
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl.gz",
            CompressionMode::Gzip,
            &records,
        )?;
        let sources = vec![source_for(&plan, &records)?];
        let mut limits = test_limits();
        limits.max_expansion_ratio = 4;
        let result = publish_with_limits(
            &fixture,
            limits,
            "operation-ratio-evidence",
            vec![plan],
            sources,
        )?;
        let report = quarantined_report(result);
        assert!(
            report.first_failure.contains("max_expansion_ratio"),
            "the ratio breach is preserved as a typed policy refusal in quarantine"
        );
        assert!(
            preparation_file(&fixture.ledger, "operation-ratio-evidence").exists(),
            "the preparation intent is durable before the artifact is consumed"
        );
        assert!(
            !sealed_file(&fixture.ledger, "operation-ratio-evidence").exists(),
            "no sealed intent follows a ratio refusal"
        );
        assert!(
            load_sealed_intent(&fixture.ledger, "operation-ratio-evidence")?.is_none(),
            "no recoverable seal exists after a ratio refusal"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn expansion_ratio_pipeline_empty_uncompressed_artifact_passes() -> TestResult {
        let fixture = fixture()?;
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &[],
        )?;
        let sources = vec![source_for(&plan, &[])?];
        let outcome = publish_with_limits(
            &fixture,
            test_limits(),
            "operation-ratio-empty-plain",
            vec![plan],
            sources,
        )??;
        let descriptor = &outcome.descriptors[0];
        assert_eq!(
            descriptor.stored_bytes, 0,
            "an empty uncompressed artifact stores zero bytes"
        );
        assert_eq!(
            descriptor.uncompressed_bytes, 0,
            "an empty uncompressed artifact expands to zero bytes"
        );
        assert!(
            sealed_file(&fixture.ledger, "operation-ratio-empty-plain").exists(),
            "the zero-stored-byte case reaches the seal"
        );
        Ok(())
    }

    #[test]
    fn expansion_ratio_pipeline_empty_gzip_artifact_passes() -> TestResult {
        let fixture = fixture()?;
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl.gz",
            CompressionMode::Gzip,
            &[],
        )?;
        let sources = vec![source_for(&plan, &[])?];
        let outcome = publish_with_limits(
            &fixture,
            test_limits(),
            "operation-ratio-empty-gzip",
            vec![plan],
            sources,
        )??;
        let descriptor = &outcome.descriptors[0];
        assert_eq!(
            descriptor.uncompressed_bytes, 0,
            "an empty gzip artifact expands to zero bytes"
        );
        assert!(
            descriptor.stored_bytes > 0,
            "the gzip framing stores bytes for an empty artifact"
        );
        assert!(
            sealed_file(&fixture.ledger, "operation-ratio-empty-gzip").exists(),
            "a gzip artifact with stored framing and zero expanded bytes reaches the seal"
        );
        Ok(())
    }

    #[test]
    fn expansion_ratio_rejection_in_second_artifact_precedes_seal() -> TestResult {
        let fixture = fixture()?;
        let plain_records = vec![sequenced_record("abstract-1", 1)?];
        let plain_plan = make_plan(
            "partition-a",
            0,
            "artifacts/a.jsonl",
            CompressionMode::None,
            &plain_records,
        )?;
        let repeated = "a".repeat(2_048);
        let packed_records = (0..40)
            .map(|index| sequenced_record(&repeated, index + 1))
            .collect::<TestResult<Vec<_>>>()?;
        let packed_plan = make_plan(
            "partition-b",
            1,
            "artifacts/b.jsonl.gz",
            CompressionMode::Gzip,
            &packed_records,
        )?;
        let plans = vec![packed_plan, plain_plan];
        let sources = vec![
            source_for(&plans[0], &packed_records)?,
            source_for(&plans[1], &plain_records)?,
        ];
        let result = publish_with_limits(
            &fixture,
            test_limits(),
            "operation-ratio-second-artifact",
            plans,
            sources,
        )?;
        let report = quarantined_report(result);
        assert!(
            report.first_failure.contains("max_expansion_ratio"),
            "the second canonical artifact's ratio breach is quarantined"
        );
        assert!(
            !sealed_file(&fixture.ledger, "operation-ratio-second-artifact").exists(),
            "a multi-artifact ratio breach also precedes the seal"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    fn assert_quarantined_failure(
        result: &Result<StreamingOutcome, StreamError>,
        code: &str,
        context: &str,
    ) {
        assert!(
            matches!(result, Err(StreamError::PreparationQuarantined(report))
                if report.failure_code == code),
            "{context}: {result:?}"
        );
    }

    fn assert_failed_spool_has_no_seal(fixture: &Fixture, operation_id: &str) -> TestResult {
        assert!(
            !sealed_file(&fixture.ledger, operation_id).exists(),
            "a failed spool precedes the seal"
        );
        assert_no_availability(fixture)?;
        let preparation = load_preparation_intent(&fixture.ledger, operation_id)?
            .ok_or_else(|| io::Error::other("preparation intent is missing"))?;
        for planned in &preparation.spool_plan {
            assert!(
                !spool_evidence_file(&fixture.ledger, &planned.spool_file_id).exists(),
                "a failed spool has no SPOOL_SEALED evidence"
            );
        }
        Ok(())
    }

    #[test]
    fn two_non_replayable_sources_have_distinct_prepared_spool_plans() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let _outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let preparation = load_preparation_intent(&fixture.ledger, "operation-b15")?
            .ok_or_else(|| io::Error::other("preparation intent is missing"))?;
        assert_eq!(
            preparation.spool_plan.len(),
            2,
            "two non-replayable sources produce two prepared spool plans"
        );
        assert_ne!(
            preparation.spool_plan[0].spool_file_id, preparation.spool_plan[1].spool_file_id,
            "prepared spool ids are distinct"
        );
        for planned in &preparation.spool_plan {
            assert!(
                planned.spool_file_id.ends_with(".spool"),
                "a planned spool id keeps the safe extension"
            );
            assert!(
                !planned.spool_file_id.contains('/'),
                "a planned spool id carries no path separator"
            );
        }
        Ok(())
    }

    #[test]
    fn spool_plan_fields_bind_artifact_ordinal_and_identity() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let _outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let preparation = load_preparation_intent(&fixture.ledger, "operation-b15")?
            .ok_or_else(|| io::Error::other("preparation intent is missing"))?;
        let expected = canonical_expectation(&case.plans, &case.records);
        for (ordinal, (plan, _)) in expected
            .iter()
            .enumerate()
            .filter(|(_, (plan, _))| plan.replayability == Replayability::NonReplayable)
        {
            let planned = preparation
                .spool_plan
                .iter()
                .find(|item| item.artifact_binding_id == plan.source_binding_id)
                .ok_or_else(|| io::Error::other("spool plan is missing for a source"))?;
            assert_eq!(
                planned.operation_id, "operation-b15",
                "the spool plan carries the operation identity"
            );
            assert_eq!(
                planned.artifact_path, plan.path,
                "the spool plan carries the artifact path as evidence"
            );
            assert_eq!(
                planned.source_snapshot_id, plan.source_snapshot_id,
                "the spool plan carries the source snapshot"
            );
            assert_eq!(
                planned.source_revision, plan.source_revision,
                "the spool plan carries the source revision"
            );
            assert_eq!(
                planned.spool_file_id,
                spool_file_id("operation-b15", ordinal, &plan.source_binding_id)?,
                "the spool id follows the canonical ordinal and binding"
            );
            assert_eq!(
                planned.max_spool_bytes,
                test_profile()?.limits().temp_disk_bytes(),
                "the spool plan carries the profile disk bound"
            );
        }
        Ok(())
    }

    #[test]
    fn spool_ids_ignore_artifact_path_and_reject_unsafe_tokens() -> TestResult {
        let first = spool_file_id("operation-path-a", 3, "binding-a")?;
        let second = spool_file_id("operation-path-a", 3, "binding-a")?;
        assert_eq!(first, second, "the same identity and ordinal derive one id");
        assert!(
            !first.contains("artifacts"),
            "no artifact path reaches the spool id"
        );
        assert!(
            matches!(
                spool_file_id("../escape", 0, "binding-a"),
                Err(StreamError::PolicyExceeded(..))
            ),
            "an operation id with a path separator is refused"
        );
        assert!(
            matches!(
                spool_file_id("operation-path-a", 0, "../binding"),
                Err(StreamError::PolicyExceeded(..))
            ),
            "a binding id with a path separator is refused"
        );
        Ok(())
    }

    #[test]
    fn two_non_replayable_sources_have_independent_spool_evidence() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        assert_eq!(
            outcome.spool_evidence.len(),
            2,
            "each non-replayable source has its own evidence"
        );
        assert_ne!(
            outcome.spool_evidence[0].spool_file_id, outcome.spool_evidence[1].spool_file_id,
            "spool evidence names are distinct"
        );
        assert_ne!(
            outcome.spool_evidence[0].stored_sha256, outcome.spool_evidence[1].stored_sha256,
            "spool evidence digests are independent"
        );
        for item in &outcome.spool_evidence {
            assert_eq!(
                item.operation_id, "operation-b15",
                "spool evidence carries the operation"
            );
            assert_eq!(
                item.spool_state,
                SpoolState::Sealed,
                "spool evidence records the sealed state"
            );
            assert_eq!(
                item.preparation_intent_sha256, outcome.preparation_intent_sha256,
                "spool evidence binds the preparation digest"
            );
            assert!(
                !item.first_order_key.is_empty(),
                "spool evidence records the first byte-derived key"
            );
            assert!(
                !item.last_order_key.is_empty(),
                "spool evidence records the last byte-derived key"
            );
        }
        Ok(())
    }

    #[test]
    fn each_spool_evidence_record_is_individually_durable() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        for item in &outcome.spool_evidence {
            let loaded = load_spool_evidence(&fixture.ledger, &item.spool_file_id)?
                .ok_or_else(|| io::Error::other("spool evidence record is missing"))?;
            assert_eq!(
                &loaded, item,
                "the durable record equals the outcome evidence"
            );
        }
        Ok(())
    }

    #[test]
    fn sealed_intent_binds_the_complete_spool_inventory() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let preparation = load_preparation_intent(&fixture.ledger, "operation-b15")?
            .ok_or_else(|| io::Error::other("preparation intent is missing"))?;
        let sealed = load_sealed_intent(&fixture.ledger, "operation-b15")?
            .ok_or_else(|| io::Error::other("sealed intent is missing"))?;
        assert_eq!(
            sealed.spool_evidence, outcome.spool_evidence,
            "the seal carries the complete spool inventory"
        );
        verify_spool_inventory(&fixture.ledger, &preparation, &sealed)?;
        Ok(())
    }

    #[test]
    fn tampered_spool_evidence_stops_recovery() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let outcome = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults::default(),
            Cancellation::new(),
        )??;
        let item = &outcome.spool_evidence[0];
        let path = spool_evidence_file(&fixture.ledger, &item.spool_file_id);
        let mut record: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
        record["stored_sha256"] = serde_json::Value::String("0".repeat(64));
        fs::write(&path, serde_json::to_vec(&record)?)?;
        let policy = test_profile()?.limits().to_resource_policy();
        assert!(
            matches!(
                recover_streaming(
                    &fixture.root,
                    &fixture.ledger,
                    &fixture.spool,
                    "operation-b15",
                    &policy,
                ),
                Err(StreamError::Publication(..))
            ),
            "a changed spool evidence digest stops recovery"
        );
        Ok(())
    }

    #[test]
    fn corrupted_spool_bytes_are_refused_before_adoption() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let mut plan = make_plan(
            "partition-a",
            0,
            "artifacts/corrupt.jsonl",
            CompressionMode::None,
            &records,
        )?;
        plan.replayability = Replayability::NonReplayable;
        let (evidence, _) = spool_for_test(&fixture, "operation-corrupt", &plan, &records)?;
        let path = fixture.spool.join(&evidence.spool_file_id);
        let mut bytes = fs::read(&path)?;
        let middle = bytes.len() / 2;
        bytes[middle] = bytes[middle].wrapping_add(1);
        fs::write(&path, bytes)?;
        assert!(
            matches!(
                verify_spool(&fixture.spool, &evidence, &test_profile()?),
                Err(StreamError::SpoolEvidenceMismatch(..))
            ),
            "altered spool bytes differ from the sealed digest"
        );
        Ok(())
    }

    #[test]
    fn spool_record_count_mismatch_is_refused_before_adoption() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let mut plan = make_plan(
            "partition-a",
            0,
            "artifacts/count.jsonl",
            CompressionMode::None,
            &records,
        )?;
        plan.replayability = Replayability::NonReplayable;
        let (evidence, _) = spool_for_test(&fixture, "operation-count", &plan, &records)?;
        let mut changed = evidence.clone();
        changed.record_count = evidence.record_count.saturating_add(1);
        assert!(
            matches!(
                verify_spool(&fixture.spool, &changed, &test_profile()?),
                Err(StreamError::SpoolEvidenceMismatch(..))
            ),
            "a changed record count is refused during the bounded read"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_replaced_spool_path_is_refused() -> TestResult {
        use std::os::unix::fs::symlink;

        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let mut plan = make_plan(
            "partition-a",
            0,
            "artifacts/linked.jsonl",
            CompressionMode::None,
            &records,
        )?;
        plan.replayability = Replayability::NonReplayable;
        let (evidence, _) = spool_for_test(&fixture, "operation-link", &plan, &records)?;
        let original = fixture.spool.join(&evidence.spool_file_id);
        let copy = fixture
            .spool
            .join(format!("{}-copy", evidence.spool_file_id));
        fs::rename(&original, &copy)?;
        symlink(&copy, &original)?;
        assert!(
            verify_spool(&fixture.spool, &evidence, &test_profile()?).is_err(),
            "a symlink at the spool file name is refused by the no-follow open"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_spool_directory_is_refused() -> TestResult {
        use std::os::unix::fs::symlink;

        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let mut plan = make_plan(
            "partition-a",
            0,
            "artifacts/linked-dir.jsonl",
            CompressionMode::None,
            &records,
        )?;
        plan.replayability = Replayability::NonReplayable;
        let (evidence, _) = spool_for_test(&fixture, "operation-link-dir", &plan, &records)?;
        let real = fixture.root.join("spool-real");
        fs::rename(&fixture.spool, &real)?;
        symlink(&real, &fixture.spool)?;
        assert!(
            verify_spool(&fixture.spool, &evidence, &test_profile()?).is_err(),
            "a symlink at the spool directory is refused by the no-follow open"
        );
        Ok(())
    }

    #[test]
    fn verified_reader_consumes_the_sealed_spool_bytes() -> TestResult {
        let fixture = fixture()?;
        let records = vec![
            sequenced_record("abstract-1", 1)?,
            sequenced_record("abstract-2", 2)?,
        ];
        let mut plan = make_plan(
            "partition-a",
            0,
            "artifacts/reader.jsonl",
            CompressionMode::None,
            &records,
        )?;
        plan.replayability = Replayability::NonReplayable;
        let (evidence, _) = spool_for_test(&fixture, "operation-reader", &plan, &records)?;
        let mut framer = verify_spool(&fixture.spool, &evidence, &test_profile()?)?;
        let mut reader = TestReader::new(test_profile()?.limits().max_record_bytes());
        let mut hasher = Sha256::new();
        let mut count = 0_u64;
        while let Some(record) = reader.next(&mut framer)? {
            hasher.update(&record.bytes);
            hasher.update(b"\n");
            count = checked_total(count, 1, "verified reader records")?;
        }
        assert_eq!(
            count, evidence.record_count,
            "the bounded reader sees the sealed record count"
        );
        assert_eq!(
            hex_encode(&hasher.finalize()),
            evidence.stored_sha256,
            "the bounded reader hashes the sealed spool bytes"
        );
        Ok(())
    }

    #[test]
    fn spool_file_sync_failure_leaves_no_seal_or_publication() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let result = publish(
            &fixture,
            case.plans,
            case.sources,
            StreamFaults {
                spool_fault: SpoolFault::FailFileSync,
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )?;
        assert_quarantined_failure(
            &result,
            "STREAM_IO",
            "a spool file sync failure is quarantined with a typed filesystem code",
        );
        assert_failed_spool_has_no_seal(&fixture, "operation-b15")?;
        Ok(())
    }

    #[test]
    fn spool_directory_sync_failure_leaves_file_without_evidence() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let result = publish(
            &fixture,
            case.plans.clone(),
            case.sources,
            StreamFaults {
                spool_fault: SpoolFault::FailDirectorySync,
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )?;
        assert_quarantined_failure(
            &result,
            "STREAM_IO",
            "a spool directory sync failure is quarantined",
        );
        let expected = canonical_expectation(&case.plans, &case.records);
        let (ordinal, plan) = expected
            .iter()
            .enumerate()
            .find(|(_, (plan, _))| plan.replayability == Replayability::NonReplayable)
            .ok_or_else(|| io::Error::other("a non-replayable source is required"))?;
        let spool_id = spool_file_id("operation-b15", ordinal, &plan.0.source_binding_id)?;
        assert!(
            fixture.spool.join(&spool_id).exists(),
            "the synced spool file remains as quarantine evidence"
        );
        assert_failed_spool_has_no_seal(&fixture, "operation-b15")?;
        Ok(())
    }

    #[test]
    fn spool_evidence_commit_failure_precedes_the_seal() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let result = publish(
            &fixture,
            case.plans,
            case.sources,
            StreamFaults {
                spool_fault: SpoolFault::FailEvidenceCommit,
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )?;
        assert_quarantined_failure(
            &result,
            "STREAM_IO",
            "a spool evidence commit failure is quarantined",
        );
        assert_failed_spool_has_no_seal(&fixture, "operation-b15")?;
        Ok(())
    }

    #[test]
    fn recovery_after_file_sync_before_spool_directory_sync_is_preparation_only() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let _result = publish(
            &fixture,
            case.plans,
            case.sources,
            StreamFaults {
                spool_fault: SpoolFault::FailDirectorySync,
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )?;
        let policy = test_profile()?.limits().to_resource_policy();
        assert!(
            matches!(
                recover_streaming(
                    &fixture.root,
                    &fixture.ledger,
                    &fixture.spool,
                    "operation-b15",
                    &policy,
                ),
                Ok(StreamRecoveryOutcome::PreparationOnlyQuarantined(
                    PreparationState::QuarantinedDurable
                ))
            ),
            "a synced file without a durable directory entry is not recovered"
        );
        Ok(())
    }

    #[test]
    fn recovery_after_spool_directory_sync_before_evidence_commit_is_preparation_only() -> TestResult
    {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let _result = publish(
            &fixture,
            case.plans,
            case.sources,
            StreamFaults {
                spool_fault: SpoolFault::FailEvidenceCommit,
                ..StreamFaults::default()
            },
            Cancellation::new(),
        )?;
        let policy = test_profile()?.limits().to_resource_policy();
        assert!(
            matches!(
                recover_streaming(
                    &fixture.root,
                    &fixture.ledger,
                    &fixture.spool,
                    "operation-b15",
                    &policy,
                ),
                Ok(StreamRecoveryOutcome::PreparationOnlyQuarantined(
                    PreparationState::QuarantinedDurable
                ))
            ),
            "a durable directory entry without evidence is not recovered"
        );
        Ok(())
    }

    #[test]
    fn aggregate_temp_disk_quota_is_shared_by_all_spools() -> TestResult {
        let fixture = fixture()?;
        let case = shuffled_case()?;
        let pairs: Vec<(ArtifactPlan, Box<dyn ArtifactRecordSource>)> = case
            .plans
            .into_iter()
            .zip(case.sources)
            .filter(|(plan, _)| plan.replayability == Replayability::NonReplayable)
            .collect();
        assert_eq!(pairs.len(), 2, "two non-replayable sources feed the test");
        let plans = pairs.iter().map(|(plan, _)| plan.clone()).collect();
        let sources = pairs.into_iter().map(|(_, source)| source).collect();
        let mut limits = test_limits();
        limits.temp_disk_bytes = 1;
        let result = publish_with_limits(&fixture, limits, "operation-quota", plans, sources)?;
        assert!(
            matches!(&result, Err(StreamError::PreparationQuarantined(report))
                if report.failure_code == "STREAM_POLICY_EXCEEDED"),
            "one operation-scoped budget covers both non-replayable sources: {result:?}"
        );
        assert!(
            !sealed_file(&fixture.ledger, "operation-quota").exists(),
            "aggregate quota exhaustion precedes the seal"
        );
        assert_no_availability(&fixture)?;
        Ok(())
    }

    #[test]
    fn spool_bytes_consume_the_same_quota_as_staging_bytes() -> TestResult {
        let records = vec![sequenced_record("abstract-1", 1)?];
        let mut plan = make_plan(
            "partition-a",
            0,
            "artifacts/shared.jsonl",
            CompressionMode::None,
            &records,
        )?;
        plan.replayability = Replayability::NonReplayable;
        let measured = fixture()?;
        let (evidence, _) = spool_for_test(&measured, "operation-shared", &plan, &records)?;
        let mut limits = test_limits();
        limits.temp_disk_bytes = evidence.stored_bytes.saturating_add(1);
        let fixture = fixture()?;
        let result = publish_with_limits(
            &fixture,
            limits,
            "operation-shared",
            vec![plan.clone()],
            vec![source_for(&plan, &records)?],
        )?;
        assert!(
            matches!(&result, Err(StreamError::PreparationQuarantined(report))
                if report.failure_code == "PUB_CORE_FAILURE"
                    && report.first_failure.contains("temp_disk_bytes")),
            "staging is charged after the spool has used the shared budget: {result:?}"
        );
        assert!(
            !sealed_file(&fixture.ledger, "operation-shared").exists(),
            "the shared quota breach precedes the seal"
        );
        Ok(())
    }

    #[test]
    fn ledger_intent_bytes_use_the_separately_bounded_ledger_budget() -> TestResult {
        let fixture = fixture()?;
        let records = vec![sequenced_record("abstract-1", 1)?];
        let plan = make_plan(
            "partition-a",
            0,
            "artifacts/ledger.jsonl",
            CompressionMode::None,
            &records,
        )?;
        let mut limits = test_limits();
        limits.temp_disk_bytes = 1;
        let result = publish_with_limits(
            &fixture,
            limits,
            "operation-ledger-budget",
            vec![plan.clone()],
            vec![source_for(&plan, &records)?],
        )?;
        assert!(
            matches!(&result, Err(StreamError::PreparationQuarantined(report))
                if report.failure_code == "PUB_CORE_FAILURE"
                    && report.first_failure.contains("temp_disk_bytes")),
            "the staging write exceeds the one-byte temp budget: {result:?}"
        );
        assert!(
            preparation_file(&fixture.ledger, "operation-ledger-budget").exists(),
            "the preparation intent is bounded by the ledger budget instead"
        );
        Ok(())
    }
}
