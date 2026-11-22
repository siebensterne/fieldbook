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
            ArbiterLimits, ArbiterVerdict, BoundedMemorySink, FeedArbiter, SequenceDomain,
            SequencedPacket,
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
    pub valid: bool,
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
    pub quality: Vec<QualityRecord>,
    pub verification: SliceVerification,
    pub evidence_reconciled: bool,
}

struct ReplayCollector<'a> {
    codecs: &'a CodecRegistry,
    source_id: &'a str,
    schema_version: u32,
    digests: Vec<String>,
}

impl<'a> JournalVisitor for ReplayCollector<'a> {
    fn visit(&mut self, entry: &JournalEntry<'_>) -> anyhow::Result<()> {
        let events = self.codecs.decode_normalized(
            &format!("replay-{}", entry.position.segment_record_ordinal),
            self.source_id,
            self.schema_version,
            entry.payload,
        )?;
        for event in events {
            if let Some(typed) = event.payload {
                let body = serde_json::to_string(&typed.payload)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                self.digests.push(sha256_hex(body.as_bytes()));
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
) -> anyhow::Result<SliceVerification> {
    let mut collector = ReplayCollector {
        codecs,
        source_id: &config.source_id,
        schema_version: config.schema_version,
        digests: Vec::new(),
    };
    visit_observations(journal_directory, &mut collector)?;
    let mut expected: BTreeMap<String, usize> = BTreeMap::new();
    for record in canonical {
        *expected.entry(record.payload_digest.clone()).or_default() += 1;
    }
    let mut matched: usize = 0;
    let mut corrupt: usize = 0;
    for digest in &collector.digests {
        match expected.get_mut(digest) {
            Some(count) if *count > 0 => {
                *count = count.saturating_sub(1);
                matched = matched.saturating_add(1);
            }
            _ => corrupt = corrupt.saturating_add(1),
        }
    }
    let missing: usize = expected.values().sum();
    let valid = missing == 0 && corrupt == 0 && matched == canonical.len();
    Ok(SliceVerification {
        journal_records: collector.digests.len(),
        matched,
        missing,
        unexpected: 0,
        corrupt,
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
        *dispositions
            .entry(receipt.disposition.as_str().to_owned())
            .or_default() += 1;
        let in_order = packet.clone();
        let verdict = arbiter.submit(packet);
        match &verdict {
            ArbiterVerdict::Accepted => accepted += 1,
            ArbiterVerdict::DuplicateIdentical | ArbiterVerdict::DuplicateConflict { .. } => {
                duplicates += 1;
            }
            ArbiterVerdict::Stale => stale += 1,
            _ => {}
        }
        let record_id = receipt.evidence_id;
        let ready = if matches!(verdict, ArbiterVerdict::Accepted) {
            vec![in_order]
        } else {
            Vec::new()
        };
        for drained in ready.into_iter().chain(arbiter.drain_available()) {
            let events = codecs.decode_normalized(
                &record_id,
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
    let verification = verify_replay(&run_directory, codecs, config, &sink.records())?;
    Ok(SliceOutcome {
        submitted,
        accepted,
        duplicates,
        stale,
        typed_events,
        dispositions,
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
        SequencedPacket {
            channel: FeedChannel::Primary,
            sequence,
            payload: body.as_bytes().to_vec(),
            received_at_us: 1_700_000_000_000_000 + sequence as i64,
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
}
