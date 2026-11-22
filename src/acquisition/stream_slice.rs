// SPDX-License-Identifier: Apache-2.0
//! One integrated acquisition slice from reception to replay verification.
//!
//! The source declaration and fixture connector feed raw packets into the
//! journal through the evidence pipeline. The arbiter orders them, the codec
//! registry decodes them, typed normalization produces domain records, quality
//! transitions are recorded, and replay from the journal verifies the typed
//! result. Raw bytes stay in the evidence store; typed records only reference
//! them.

use std::{
    collections::BTreeMap, //
    sync::Mutex,           //
    time::Duration,        //
};

use serde::Deserialize;
use serde::Serialize;

use crate::{
    acquisition::{
        arbiter::{
            ArbiterLimits, ArbiterVerdict, BoundedMemorySink, FeedArbiter, FeedChannel,
            SequenceDomain, SequencedPacket,
        },
        codec::CodecRegistry,
        evidence::{
            CanonicalEvidenceRecord, CanonicalSink, DurabilityProfile, EvidencePipeline,
            EvidenceStore, bind_and_verify,
        },
        packet::PacketEvidence,
    },
    integrity::journal::{
        JournalConfig, JournalEntry, JournalHandle, JournalMeta, JournalVisitor, SyncMode,
        visit_observations,
    },
    model::SourceId,
    quality::{QualityReason, QualityRecord, QualityState, transition},
    util::sha256_hex,
};

/// Configuration of one integrated slice run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliceConfig {
    pub source_id: String,
    pub source: SourceId,
    pub schema_version: u32,
    pub profile: DurabilityProfile,
}

/// Canonical sink that retains records for replay reconciliation.
#[derive(Debug, Default)]
pub struct CollectingSink {
    records: Mutex<Vec<CanonicalEvidenceRecord>>,
}

impl CollectingSink {
    /// Return a clone of the records persisted during the run.
    pub fn records(&self) -> Vec<CanonicalEvidenceRecord> {
        self.records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

impl CanonicalSink for CollectingSink {
    fn persist(&self, record: &CanonicalEvidenceRecord) -> anyhow::Result<()> {
        self.records
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(record.clone());
        Ok(())
    }
}

/// Replay reconciliation against the authoritative journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliceVerification {
    pub journal_records: usize,
    pub matched: usize,
    pub missing: usize,
    pub unexpected: usize,
    pub corrupt: usize,
    pub order_mismatches: usize,
    pub valid: bool,
}

/// Processing disposition of one raw record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingDisposition {
    Accepted,
    Buffered,
    DuplicateIdentical,
    DuplicateConflict,
    Stale,
    GapRejected,
    BufferRejected,
    DecodeRejected,
    NormalizationRejected,
}

impl ProcessingDisposition {
    /// Return the stable contract string for this disposition.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Buffered => "buffered",
            Self::DuplicateIdentical => "duplicate_identical",
            Self::DuplicateConflict => "duplicate_conflict",
            Self::Stale => "stale",
            Self::GapRejected => "gap_rejected",
            Self::BufferRejected => "buffer_rejected",
            Self::DecodeRejected => "decode_rejected",
            Self::NormalizationRejected => "normalization_rejected",
        }
    }
}

/// Disposition bound to the raw record that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliceDispositionRecord {
    pub evidence_id: String,
    pub sequence: u64,
    pub disposition: ProcessingDisposition,
}

/// Outcome of one integrated slice run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SliceOutcome {
    pub submitted: usize,
    pub accepted: usize,
    pub duplicates: usize,
    pub stale: usize,
    pub typed_events: usize,
    pub dispositions: BTreeMap<String, u64>,
    pub disposition_records: Vec<SliceDispositionRecord>,
    pub quality: Vec<QualityRecord>,
    pub verification: SliceVerification,
    pub evidence_reconciled: bool,
}

struct ReplayCollector<'a> {
    codecs: &'a CodecRegistry,
    source_id: &'a str,
    schema_version: u32,
    arbiter: FeedArbiter,
    extension_index: BTreeMap<(u64, u64), (String, Option<u64>, FeedChannel)>,
    evidence_ids: BTreeMap<u64, String>,
    identities: Vec<(String, String)>,
}

impl<'a> JournalVisitor for ReplayCollector<'a> {
    fn visit(&mut self, entry: &JournalEntry<'_>) -> anyhow::Result<()> {
        let key = (
            entry.position.segment_index,
            entry.position.segment_record_ordinal,
        );
        let Some((evidence_id, sequence, channel)) = self.extension_index.get(&key).cloned() else {
            return Ok(());
        };
        let sequence = sequence.unwrap_or_else(|| entry.position.segment_record_ordinal + 1);
        self.evidence_ids.insert(sequence, evidence_id);
        let packet = SequencedPacket {
            channel,
            sequence,
            payload: entry.payload.to_vec(),
            received_at_us: entry.received_at_us,
        };
        let in_order = packet.clone();
        let verdict = self.arbiter.submit(packet);
        let ready = if verdict == ArbiterVerdict::Accepted {
            vec![in_order]
        } else {
            Vec::new()
        };
        for replayed in ready.into_iter().chain(self.arbiter.drain_available()) {
            let replay_id = self
                .evidence_ids
                .get(&replayed.sequence)
                .cloned()
                .unwrap_or_else(|| format!("replay-{}", replayed.sequence));
            let events = self.codecs.decode_normalized(
                &replay_id,
                self.source_id,
                self.schema_version,
                &replayed.payload,
            )?;
            for event in events {
                if let Some(typed) = event.payload {
                    let body = serde_json::to_string(&typed.payload)
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    self.identities
                        .push((event.packet_id, sha256_hex(body.as_bytes())));
                }
            }
        }
        Ok(())
    }
}

/// Replay journal records and reconcile typed digests with canonical records.
pub fn verify_replay(
    journal_directory: &std::path::Path,
    codecs: &CodecRegistry,
    config: &SliceConfig,
    canonical: &[CanonicalEvidenceRecord],
    store: &EvidenceStore,
    limits: ArbiterLimits,
) -> anyhow::Result<SliceVerification> {
    let mut extension_index = BTreeMap::new();
    for extension in store.load()? {
        if let Some(position) = extension.position {
            let channel = if extension.channel == "secondary" {
                FeedChannel::Secondary
            } else {
                FeedChannel::Primary
            };
            extension_index.insert(
                (position.segment_index, position.segment_record_ordinal),
                (extension.evidence_id, extension.sequence, channel),
            );
        }
    }
    let mut collector = ReplayCollector {
        codecs,
        source_id: &config.source_id,
        schema_version: config.schema_version,
        arbiter: FeedArbiter::new(
            SequenceDomain::new(&config.source_id, 1),
            1,
            limits,
            Box::new(BoundedMemorySink::new(limits.max_rejected_entries)),
        )?,
        extension_index,
        evidence_ids: BTreeMap::new(),
        identities: Vec::new(),
    };
    visit_observations(journal_directory, &mut collector)?;
    let mut matched: usize = 0;
    let mut order_mismatches: usize = 0;
    let common = collector.identities.len().min(canonical.len());
    for ((evidence_id, digest), expected) in collector.identities.iter().zip(canonical.iter()) {
        if evidence_id == &expected.evidence_id && digest == &expected.payload_digest {
            matched = matched.saturating_add(1);
        } else {
            order_mismatches = order_mismatches.saturating_add(1);
        }
    }
    let missing = canonical.len().saturating_sub(common);
    let unexpected = collector.identities.len().saturating_sub(common);
    let valid = order_mismatches == 0 && missing == 0 && unexpected == 0;
    Ok(SliceVerification {
        journal_records: collector.identities.len(),
        matched,
        missing,
        unexpected,
        corrupt: order_mismatches,
        order_mismatches,
        valid,
    })
}

fn journal_config(directory: &std::path::Path) -> JournalConfig {
    JournalConfig {
        directory: directory.to_path_buf(),
        queue_capacity: 64,
        enqueue_timeout: Duration::from_millis(250),
        flush_interval: Duration::from_millis(10),
        sync_interval: Duration::from_millis(20),
        segment_max_bytes: 0,
        segment_max_seconds: 0,
        sync_mode: SyncMode::Interval,
    }
}

/// Run one deterministic slice through every stage.
pub fn run_stream_slice(
    directory: &std::path::Path,
    run_id: &str,
    config: &SliceConfig,
    packets: Vec<SequencedPacket>,
    codecs: &CodecRegistry,
    sink: &CollectingSink,
    limits: ArbiterLimits,
) -> anyhow::Result<SliceOutcome> {
    let journal = JournalHandle::start(
        journal_config(directory),
        JournalMeta {
            run_id: run_id.to_owned(),
            venue: config.source_id.clone(),
            code_commit: "fixture".to_owned(),
            route: None,
            config_sha256: sha256_hex(format!("{config:?}").as_bytes()),
        },
    )?;
    let store = EvidenceStore::new(directory, "slice-evidence.jsonl")?;
    let pipeline = EvidencePipeline::new(journal, store.clone(), config.profile)?;
    let domain = SequenceDomain::new(&config.source_id, 1);
    let mut arbiter = FeedArbiter::new(
        domain,
        1,
        limits,
        Box::new(BoundedMemorySink::new(limits.max_rejected_entries)),
    )?;
    let submitted = packets.len();
    let mut accepted = 0;
    let mut duplicates = 0;
    let mut stale = 0;
    let mut typed_events = 0;
    let mut dispositions: BTreeMap<String, u64> = BTreeMap::new();
    let mut disposition_records = Vec::new();
    let mut evidence_ids: BTreeMap<u64, String> = BTreeMap::new();
    let mut quality = Vec::new();

    for (receive_sequence, packet) in packets.into_iter().enumerate() {
        let context = crate::acquisition::evidence::EvidenceContext {
            sequence_domain_id: config.source_id.clone(),
            source_schema_id: "fixture-schema".to_owned(),
            source_schema_version: config.schema_version,
            receive_sequence: receive_sequence as u64 + 1,
        };
        let evidence = PacketEvidence::new(
            &config.source_id,
            packet.channel,
            config.source.shard as u64,
            Some(packet.sequence),
            "fixture-slice",
            packet.payload.clone(),
            packet.received_at_us,
            "lab",
            "fixture-decoder",
        );
        let receipt = pipeline.ingest(&evidence, config.source, &context);
        evidence_ids
            .entry(packet.sequence)
            .or_insert_with(|| receipt.evidence_id.clone());
        *dispositions
            .entry(receipt.disposition.as_str().to_owned())
            .or_default() += 1;
        let sequence = packet.sequence;
        let in_order = packet.clone();
        let verdict = arbiter.submit(packet);
        let processing_disposition = match &verdict {
            ArbiterVerdict::Accepted => ProcessingDisposition::Accepted,
            ArbiterVerdict::OutOfOrder | ArbiterVerdict::Gap(_) => ProcessingDisposition::Buffered,
            ArbiterVerdict::DuplicateIdentical => ProcessingDisposition::DuplicateIdentical,
            ArbiterVerdict::DuplicateConflict { .. } => ProcessingDisposition::DuplicateConflict,
            ArbiterVerdict::Stale => ProcessingDisposition::Stale,
            ArbiterVerdict::GapExceeded { .. } => ProcessingDisposition::GapRejected,
            _ => ProcessingDisposition::BufferRejected,
        };
        disposition_records.push(SliceDispositionRecord {
            evidence_id: receipt.evidence_id.clone(),
            sequence,
            disposition: processing_disposition,
        });
        match &verdict {
            ArbiterVerdict::Accepted => accepted += 1,
            ArbiterVerdict::DuplicateIdentical | ArbiterVerdict::DuplicateConflict { .. } => {
                duplicates += 1;
            }
            ArbiterVerdict::Stale => stale += 1,
            _ => {}
        }
        let ready = if matches!(verdict, ArbiterVerdict::Accepted) {
            vec![in_order]
        } else {
            Vec::new()
        };
        for drained in ready.into_iter().chain(arbiter.drain_available()) {
            let drained_id = evidence_ids
                .get(&drained.sequence)
                .cloned()
                .unwrap_or_else(|| receipt.evidence_id.clone());
            let events = codecs.decode_normalized(
                &drained_id,
                &config.source_id,
                config.schema_version,
                &drained.payload,
            )?;
            for event in events {
                if let Some(typed) = event.payload {
                    let state = transition(QualityState::RawCaptured, QualityState::Decoded)?;
                    let state = transition(state, QualityState::Normalized)?;
                    let state = transition(state, QualityState::Validated)?;
                    quality.push(QualityRecord {
                        event_id: event.packet_id.clone(),
                        state,
                        reason: None,
                        observed_at_us: drained.received_at_us,
                        verifier: "stream-slice".to_owned(),
                    });
                    let body = serde_json::to_string(&typed.payload)
                        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    sink.persist(&CanonicalEvidenceRecord {
                        evidence_id: event.packet_id.clone(),
                        source: config.source_id.clone(),
                        schema_version: config.schema_version,
                        kind: event.kind,
                        payload_type: typed.payload_type,
                        payload_digest: sha256_hex(body.as_bytes()),
                    })?;
                    typed_events += 1;
                } else {
                    quality.push(QualityRecord {
                        event_id: event.packet_id.clone(),
                        state: QualityState::Rejected,
                        reason: Some(QualityReason::DecodeFailure),
                        observed_at_us: drained.received_at_us,
                        verifier: "stream-slice".to_owned(),
                    });
                }
            }
        }
    }
    pipeline.shutdown(Duration::from_secs(10))?;
    let run_directory = directory.join(run_id);
    let evidence = bind_and_verify(&run_directory, &store)?;
    let verification = verify_replay(
        &run_directory,
        codecs,
        config,
        &sink.records(),
        &store,
        limits,
    )?;
    Ok(SliceOutcome {
        submitted,
        accepted,
        duplicates,
        stale,
        typed_events,
        dispositions,
        disposition_records,
        quality,
        verification,
        evidence_reconciled: evidence.reconciled(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acquisition::{
        arbiter::FeedChannel,
        codec::{DecodeStatus, DecodedObservation, FeedCodec},
    };

    struct SliceCodec;

    impl FeedCodec for SliceCodec {
        fn decode(&self, payload: &[u8]) -> anyhow::Result<Vec<DecodedObservation>> {
            Ok(vec![DecodedObservation {
                packet_id: String::new(),
                source: String::new(),
                schema_version: 0,
                kind: "trade".to_owned(),
                payload_json: String::from_utf8(payload.to_vec())?,
                status: DecodeStatus::Decoded,
                reason: None,
            }])
        }

        fn schema_version(&self) -> u32 {
            1
        }
    }

    fn packet(sequence: u64, body: &str) -> SequencedPacket {
        packet_at(sequence, 1_700_000_000_000_000 + sequence as i64, body)
    }

    fn packet_at(sequence: u64, received_at_us: i64, body: &str) -> SequencedPacket {
        SequencedPacket {
            channel: FeedChannel::Primary,
            sequence,
            payload: body.as_bytes().to_vec(),
            received_at_us,
        }
    }

    #[test]
    fn integrated_slice_reconciles_journal_typed_events_and_replay() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = SliceConfig {
            source_id: "slice-source".to_owned(),
            source: SourceId::new(1, 0),
            schema_version: 1,
            profile: DurabilityProfile::D1,
        };
        let mut codecs = CodecRegistry::new();
        codecs
            .register("slice-source", Box::new(SliceCodec))
            .expect("codec registered");
        let sink = CollectingSink::default();
        let packets = vec![
            packet(
                1,
                "{\"trade_id\":\"t1\",\"price_mantissa\":1,\"quantity_mantissa\":2}",
            ),
            packet(
                2,
                "{\"trade_id\":\"t2\",\"price_mantissa\":3,\"quantity_mantissa\":4}",
            ),
        ];
        let outcome = run_stream_slice(
            directory.path(),
            "slice-run",
            &config,
            packets,
            &codecs,
            &sink,
            ArbiterLimits::default(),
        )
        .expect("slice completed");
        assert_eq!(outcome.submitted, 2, "both packets submitted");
        assert_eq!(outcome.accepted, 2, "both packets accepted");
        assert_eq!(outcome.typed_events, 2, "two typed events produced");
        assert!(outcome.evidence_reconciled, "evidence extensions reconcile");
        assert!(
            outcome.verification.valid,
            "replay matches canonical records"
        );
        assert_eq!(sink.records().len(), 2, "two canonical records persisted");
    }

    #[test]
    fn reordered_duplicate_and_stale_replay_reconciles_with_dispositions() {
        let directory = tempfile::tempdir().expect("tempdir");
        let config = SliceConfig {
            source_id: "slice-source".to_owned(),
            source: SourceId::new(1, 0),
            schema_version: 1,
            profile: DurabilityProfile::D1,
        };
        let mut codecs = CodecRegistry::new();
        codecs
            .register("slice-source", Box::new(SliceCodec))
            .expect("codec registered");
        let sink = CollectingSink::default();
        let packets = vec![
            packet(
                1,
                "{\"trade_id\":\"t1\",\"price_mantissa\":1,\"quantity_mantissa\":2}",
            ),
            packet(
                3,
                "{\"trade_id\":\"t3\",\"price_mantissa\":3,\"quantity_mantissa\":4}",
            ),
            packet_at(
                2,
                1_700_000_000_000_003,
                "{\"trade_id\":\"t2\",\"price_mantissa\":5,\"quantity_mantissa\":6}",
            ),
            packet_at(
                2,
                1_700_000_000_000_004,
                "{\"trade_id\":\"t2\",\"price_mantissa\":5,\"quantity_mantissa\":6}",
            ),
            packet_at(
                2,
                1_700_000_000_000_005,
                "{\"trade_id\":\"conflict\",\"price_mantissa\":9,\"quantity_mantissa\":9}",
            ),
            packet_at(
                0,
                1_700_000_000_000_006,
                "{\"trade_id\":\"stale\",\"price_mantissa\":9,\"quantity_mantissa\":9}",
            ),
        ];
        let outcome = run_stream_slice(
            directory.path(),
            "reordered-run",
            &config,
            packets,
            &codecs,
            &sink,
            ArbiterLimits::default(),
        )
        .expect("slice completed");
        let dispositions: Vec<ProcessingDisposition> = outcome
            .disposition_records
            .iter()
            .map(|record| record.disposition)
            .collect();
        assert!(
            dispositions.contains(&ProcessingDisposition::Buffered),
            "sequence 3 was buffered"
        );
        assert!(
            dispositions.contains(&ProcessingDisposition::DuplicateIdentical),
            "identical duplicate recorded"
        );
        assert!(
            dispositions.contains(&ProcessingDisposition::DuplicateConflict),
            "conflicting duplicate recorded"
        );
        assert!(
            dispositions.contains(&ProcessingDisposition::Stale),
            "stale packet recorded"
        );
        assert_eq!(
            outcome.typed_events, 3,
            "sequences 1, 2 and 3 produced typed events"
        );
        let detail = format!("ordered replay mismatch: {:?}", outcome.verification);
        assert!(outcome.verification.valid, "{detail}");
        assert_eq!(
            outcome.verification.matched, 3,
            "every typed event matched in order"
        );
        let canonical = sink.records();
        let ids: std::collections::BTreeSet<&str> = canonical
            .iter()
            .map(|record| record.evidence_id.as_str())
            .collect();
        assert_eq!(
            ids.len(),
            3,
            "each drained packet keeps its own raw evidence identity"
        );
    }
}
