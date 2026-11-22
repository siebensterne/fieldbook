// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "integration tests drive failure paths with unwrap/expect/panic and print diagnostics"
)]
#![allow(
    clippy::allow_attributes,
    reason = "test crates relax the production lint set wholesale; `expect` cannot express lints that may not fire"
)]

//! End-to-end raw evidence tests on a real journal and deterministic codec.

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use fieldbook::{
    acquisition::{
        arbiter::FeedChannel,
        codec::{CodecRegistry, DecodeStatus, DecodedObservation, FeedCodec},
        evidence::{
            CanonicalEvidenceRecord, CanonicalSink, DurabilityProfile, EvidenceDisposition,
            EvidenceExtension, EvidenceLedger, EvidencePipeline, EvidenceReceipt, EvidenceStore,
            FailurePoint, ProcessingStages, bind_and_verify,
        },
        packet::PacketEvidence,
    },
    integrity::journal::{JournalConfig, JournalHandle, JournalMeta, SyncMode},
    model::SourceId,
};

struct FixtureCodec;

impl FeedCodec for FixtureCodec {
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

#[derive(Default, Clone)]
struct RecordingSink {
    records: Arc<Mutex<Vec<CanonicalEvidenceRecord>>>,
}

impl CanonicalSink for RecordingSink {
    fn persist(&self, record: &CanonicalEvidenceRecord) -> anyhow::Result<()> {
        self.records.lock().expect("lock").push(record.clone());
        Ok(())
    }
}

fn config(directory: &std::path::Path) -> JournalConfig {
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

fn packet(sequence: u64) -> PacketEvidence {
    PacketEvidence::new(
        "fixture-source",
        FeedChannel::Primary,
        1,
        Some(sequence),
        "fixture-codec",
        b"{\"trade_id\":\"t-1\",\"price_mantissa\":10,\"quantity_mantissa\":2}".to_vec(),
        1_700_000_000_000_000 + sequence as i64,
        "lab",
        "decoder-1",
    )
}

fn stages(sink: RecordingSink) -> ProcessingStages {
    let mut codecs = CodecRegistry::new();
    codecs
        .register("fixture-source", Box::new(FixtureCodec))
        .expect("codec registered");
    ProcessingStages::new(codecs, Box::new(sink))
}

fn ingest_one(
    directory: &std::path::Path,
    run_id: &str,
    failure: Option<FailurePoint>,
    with_stages: bool,
) -> (EvidenceReceipt, EvidenceStore, std::path::PathBuf, usize) {
    let journal = JournalHandle::start(config(directory), meta(run_id)).expect("journal started");
    let store = EvidenceStore::new(directory, "evidence.jsonl").expect("store created");
    let mut pipeline = EvidencePipeline::new(journal, store.clone(), DurabilityProfile::D1)
        .expect("pipeline created");
    if with_stages {
        pipeline = pipeline.with_stages(stages(RecordingSink::default()));
    }
    if let Some(point) = failure {
        pipeline = pipeline.with_injected_failure(point);
    }
    let receipt = pipeline.ingest(&packet(1), SourceId::new(1, 0), 1);
    let stored = store.load().expect("extensions load").len();
    let run_directory = directory.join(run_id);
    pipeline
        .shutdown(Duration::from_secs(10))
        .expect("journal closed");
    (receipt, store, run_directory, stored)
}

#[test]
fn every_failure_point_has_an_explicit_disposition() {
    let cases = [
        (FailurePoint::Receive, "rejected", 0),
        (FailurePoint::JournalSubmit, "rejected", 0),
        (FailurePoint::JournalPersist, "quarantined", 0),
        (FailurePoint::EvidencePersist, "quarantined", 0),
        (FailurePoint::Decode, "quarantined", 1),
        (FailurePoint::Normalize, "quarantined", 1),
        (FailurePoint::CanonicalPersist, "quarantined", 1),
    ];
    for (index, (point, expected, stored)) in cases.into_iter().enumerate() {
        let directory = tempfile::tempdir().expect("tempdir");
        let (receipt, store, run_directory, actual_stored) = ingest_one(
            directory.path(),
            &format!("failure-{index}"),
            Some(point),
            false,
        );
        assert_eq!(
            receipt.disposition.as_str(),
            expected,
            "{point} must produce an explicit disposition"
        );
        assert_eq!(actual_stored, stored, "{point} evidence persistence count");
        let mut ledger = EvidenceLedger {
            received: 0,
            persisted: 0,
            rejected: 0,
            quarantined: 0,
        };
        ledger.apply(&receipt);
        assert!(
            ledger.reconciled(),
            "{point} must be accounted exactly once"
        );
        let report = bind_and_verify(&run_directory, &store).expect("binding report");
        if matches!(
            point,
            FailurePoint::JournalPersist | FailurePoint::EvidencePersist
        ) {
            assert!(
                !report.reconciled(),
                "{point} must be visible as an evidence gap"
            );
        }
    }
}

#[test]
fn real_decode_normalization_and_canonical_persist_succeed() {
    let directory = tempfile::tempdir().expect("tempdir");
    let journal =
        JournalHandle::start(config(directory.path()), meta("complete")).expect("journal started");
    let store = EvidenceStore::new(directory.path(), "evidence.jsonl").expect("store created");
    let sink = RecordingSink::default();
    let recorded = sink.clone();
    let pipeline = EvidencePipeline::new(journal, store.clone(), DurabilityProfile::D1)
        .expect("pipeline created")
        .with_stages(stages(sink));
    let receipt = pipeline.ingest(&packet(1), SourceId::new(1, 0), 1);
    assert_eq!(
        receipt.disposition,
        EvidenceDisposition::EvidencePersisted,
        "complete path must reach evidence persistence"
    );
    let run_directory = directory.path().join("complete");
    pipeline
        .shutdown(Duration::from_secs(10))
        .expect("journal closed");
    let report = bind_and_verify(&run_directory, &store).expect("binding verified");
    assert!(report.reconciled(), "journal and extension reconcile");
    assert_eq!(
        recorded.records.lock().expect("lock").len(),
        1,
        "one typed canonical record persisted"
    );
}

#[test]
fn duplicate_extension_binding_is_reported_as_conflict() {
    let directory = tempfile::tempdir().expect("tempdir");
    let journal =
        JournalHandle::start(config(directory.path()), meta("duplicate")).expect("journal started");
    let store = EvidenceStore::new(directory.path(), "evidence.jsonl").expect("store created");
    let pipeline = EvidencePipeline::new(journal, store.clone(), DurabilityProfile::D1)
        .expect("pipeline created");
    pipeline.ingest(&packet(1), SourceId::new(1, 0), 1);
    let stored = store.load().expect("extensions load");
    store.append(&stored[0]).expect("duplicate appended");
    let run_directory = directory.path().join("duplicate");
    pipeline
        .shutdown(Duration::from_secs(10))
        .expect("journal closed");
    let report = bind_and_verify(&run_directory, &store).expect("binding report");
    assert!(
        !report.conflicts.is_empty(),
        "two extensions for one journal record must conflict"
    );
    assert!(!report.reconciled(), "conflict blocks reconciliation");
}

#[test]
fn extension_rejects_unknown_schema_version() {
    let directory = tempfile::tempdir().expect("tempdir");
    let store = EvidenceStore::new(directory.path(), "evidence.jsonl").expect("store created");
    let mut extension = EvidenceExtension::from_packet(&packet(1), SourceId::new(1, 0));
    extension.schema_version = 99;
    assert!(
        store.append(&extension).is_err(),
        "unknown evidence version must fail closed"
    );
}
