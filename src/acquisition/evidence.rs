// SPDX-License-Identifier: Apache-2.0
//! Durable acquisition evidence bound to the raw-frame journal.
//!
//! The journal remains the evidence authority. A packet is written to the
//! journal before its versioned evidence extension is persisted. Once the run
//! is closed, the extension is bound to the stable [`JournalPosition`] of its
//! journal record and both are verified as one evidence relationship. A
//! mismatch, an absent extension or an ambiguous position fails closed.

use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
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

/// Append-only NDJSON store of evidence extensions.
#[derive(Debug, Clone)]
pub struct EvidenceStore {
    path: PathBuf,
}

impl EvidenceStore {
    /// Open or create a store in `directory`.
    pub fn new(directory: &Path, name: &str) -> anyhow::Result<Self> {
        std::fs::create_dir_all(directory)?;
        let path = directory.join(name);
        if !path.exists() {
            File::create(&path)?;
        }
        Ok(Self { path })
    }

    /// Return the store file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one validated extension.
    pub fn append(&self, extension: &EvidenceExtension) -> anyhow::Result<()> {
        extension.validate()?;
        let mut file = OpenOptions::new().append(true).open(&self.path)?;
        let line =
            serde_json::to_string(extension).map_err(|error| anyhow::anyhow!(error.to_string()))?;
        writeln!(file, "{line}")?;
        file.sync_all()?;
        Ok(())
    }

    /// Load every extension, failing closed on an unsupported version.
    pub fn load(&self) -> anyhow::Result<Vec<EvidenceExtension>> {
        let file = File::open(&self.path)?;
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

    /// Rewrite the store with bound extensions.
    pub fn write_all(&self, extensions: &[EvidenceExtension]) -> anyhow::Result<()> {
        let temporary = self.path.with_extension("tmp");
        {
            let file = File::create(&temporary)?;
            let mut writer = BufWriter::new(file);
            for extension in extensions {
                extension.validate()?;
                let line = serde_json::to_string(extension)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                writeln!(writer, "{line}")?;
            }
            writer.flush()?;
            writer.get_ref().sync_all()?;
        }
        std::fs::rename(&temporary, &self.path)?;
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

/// Ingestion path that journals raw bytes before persisting their extension.
pub struct EvidencePipeline {
    journal: JournalHandle,
    store: EvidenceStore,
    profile: DurabilityProfile,
    injected_failure: Option<FailurePoint>,
    stages: Option<ProcessingStages>,
    next_receive_seq: AtomicU64,
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
            next_receive_seq: AtomicU64::new(1),
        })
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
        let receive_seq = self.next_receive_seq.fetch_add(1, Ordering::Relaxed);
        let record = DataRecord {
            source,
            connection_epoch: evidence.connection_epoch,
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
        let ack_level = match self.profile {
            DurabilityProfile::D1 => JournalAckLevel::Written,
            DurabilityProfile::D2 => JournalAckLevel::Flushed,
            DurabilityProfile::D3 => JournalAckLevel::Synced,
            DurabilityProfile::D4 | DurabilityProfile::D5 => JournalAckLevel::Synced,
        };
        let ack = match self
            .journal
            .record_ack(record, ack_level, Duration::from_secs(5))
        {
            Ok(ack) => ack,
            Err(error) => {
                return Self::rejected(
                    evidence_id,
                    FailurePoint::JournalPersist,
                    &format!("journal acknowledgement failed: {error}"),
                );
            }
        };
        extension.journal_ack = Some(ack.clone());
        if self.injected_failure == Some(FailurePoint::JournalPersist) {
            return EvidenceReceipt {
                evidence_id,
                disposition: EvidenceDisposition::Quarantined {
                    at: FailurePoint::JournalPersist,
                    reason: "journal persistence interrupted".to_owned(),
                },
                ack: DurabilityAck::Journalled,
            };
        }
        if self.injected_failure == Some(FailurePoint::EvidencePersist) {
            return EvidenceReceipt {
                evidence_id,
                disposition: EvidenceDisposition::Quarantined {
                    at: FailurePoint::EvidencePersist,
                    reason: "evidence extension write interrupted".to_owned(),
                },
                ack: DurabilityAck::Journalled,
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
                    ack: DurabilityAck::Journalled,
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
                ack: DurabilityAck::Journalled,
            };
        }
        let achieved = match ack.level {
            JournalAckLevel::Queued => DurabilityAck::Journalled,
            JournalAckLevel::Written => DurabilityAck::Written,
            JournalAckLevel::Flushed => DurabilityAck::Flushed,
            JournalAckLevel::Synced => DurabilityAck::Synced,
        };
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
    use super::*;
    use crate::{
        acquisition::arbiter::FeedChannel,
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
}
