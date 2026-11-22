// SPDX-License-Identifier: Apache-2.0
//! Deterministic fixture-backed implementations of the acquisition ports.
//!
//! These connectors read fixed in-memory fixtures. They exercise modality
//! contracts and the internal data path without a network connection, a live
//! venue or a rights claim. Each connector declares only the capability it
//! implements and its manifest validates against the typed port it serves.

use std::collections::BTreeSet;

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde::Serialize;

use crate::{
    adapter::{
        AccessStatus, HistoricalCapability, Protocol, RecoveryCapability, RecoveryReport,
        SourceCapabilityManifest, SourceHealth, SourceHealthState, TimestampCapability, Transport,
    },
    modality::{
        AcquiredRecord, BatchCapability, BatchConnector, BatchPage, DocumentCapability,
        DocumentConnector, DocumentRecord, OnChainCapability, OnChainConnector, SnapshotCapability,
        SnapshotConnector, SourceLifecycle, StreamingCapability, StreamingConnector,
    },
    reference_data::VenueCategory,
    taxonomy::{AssetClass, CountryCode, DataCategory, DepthModel, Frequency},
};

fn manifest(
    source_id: &str,
    protocol: Protocol,
    transport: Transport,
    country: CountryCode,
) -> SourceCapabilityManifest {
    SourceCapabilityManifest {
        source_id: source_id.to_owned(),
        provider: "fixture-provider".to_owned(),
        venue_mic: None,
        country,
        venue_category: VenueCategory::ContributedQuotationSystem,
        asset_classes: vec![AssetClass::Equity],
        data_categories: vec![DataCategory::Trades],
        protocols: vec![protocol],
        transports: vec![transport],
        book_model: DepthModel::Level2,
        timestamps: TimestampCapability {
            exchange_event_time: false,
            exchange_publication_time: false,
            packet_capture_time: true,
            sequence_numbers: true,
            clock_source: "fixture_clock".to_owned(),
        },
        recovery: RecoveryCapability {
            snapshot: false,
            incremental_recovery: false,
            packet_sequence: true,
            exchange_sequence: false,
            gap_request: false,
        },
        historical: HistoricalCapability {
            available: false,
            earliest_us: None,
            frequency: Frequency::RealTime,
        },
        access: AccessStatus::Public,
        schema_version: 1,
        modalities: Vec::new(),
        streaming: None,
        snapshot: None,
        batch: None,
        document: None,
        on_chain: None,
    }
}

fn health() -> SourceHealth {
    SourceHealth {
        state: SourceHealthState::Connected,
        last_success_us: Some(1_700_000_000_000_000),
        reason: None,
    }
}

/// One received streaming observation with an explicit sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FixtureStreamFrame {
    pub object_id: String,
    pub payload: Vec<u8>,
    pub sequence: u64,
    pub source_timestamp_us: i64,
}

/// Fixture-backed continuous stream with an explicit recovery snapshot.
pub struct FixtureStreamingConnector {
    manifest: SourceCapabilityManifest,
    frames: Vec<FixtureStreamFrame>,
    subscribed: BTreeSet<String>,
    cursor: usize,
    recovered: usize,
}

impl FixtureStreamingConnector {
    /// Construct a streaming fixture with ordered frames.
    #[must_use]
    pub fn new(country: CountryCode, source_id: &str, frames: Vec<FixtureStreamFrame>) -> Self {
        let mut manifest = manifest(
            source_id,
            Protocol::WebSocket,
            Transport::WebSocket,
            country,
        );
        manifest.modalities = vec![crate::modality::AcquisitionModality::Streaming];
        manifest.streaming = Some(StreamingCapability {
            continuous: true,
            sequence_numbers: true,
            recovery: RecoveryCapability {
                snapshot: true,
                incremental_recovery: false,
                packet_sequence: true,
                exchange_sequence: false,
                gap_request: false,
            },
        });
        Self {
            manifest,
            frames,
            subscribed: BTreeSet::new(),
            cursor: 0,
            recovered: 0,
        }
    }
}

#[async_trait]
impl SourceLifecycle for FixtureStreamingConnector {
    fn manifest(&self) -> &SourceCapabilityManifest {
        &self.manifest
    }

    async fn health(&mut self) -> Result<SourceHealth> {
        Ok(health())
    }

    async fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl StreamingConnector for FixtureStreamingConnector {
    async fn connect(&mut self) -> Result<()> {
        self.cursor = 0;
        Ok(())
    }

    async fn subscribe(&mut self, object_ids: &[String]) -> Result<()> {
        anyhow::ensure!(!object_ids.is_empty(), "no objects subscribed");
        self.subscribed.extend(object_ids.iter().cloned());
        Ok(())
    }

    async fn next_record(&mut self) -> Result<Option<AcquiredRecord>> {
        let subscribed = self.subscribed.clone();
        let found = self.frames[self.cursor..]
            .iter()
            .enumerate()
            .find(|(_, frame)| subscribed.contains(&frame.object_id))
            .map(|(offset, frame)| (self.cursor + offset, frame.clone()));
        let Some((index, frame)) = found else {
            self.cursor = self.frames.len();
            return Ok(None);
        };
        self.cursor = index.saturating_add(1);
        Ok(Some(AcquiredRecord {
            object_id: frame.object_id.clone(),
            raw: frame.payload.clone(),
            source_timestamp_us: Some(frame.source_timestamp_us),
            sequence: Some(frame.sequence),
        }))
    }

    async fn recover(&mut self) -> Result<RecoveryReport> {
        self.recovered = self.recovered.saturating_add(1);
        self.cursor = 0;
        Ok(RecoveryReport {
            attempts: self.recovered as u32,
            recovered: true,
            gaps: 0,
            reason: Some("fixture snapshot replay".to_owned()),
        })
    }
}

/// Fixture-backed keyed snapshot source with pagination.
pub struct FixtureSnapshotConnector {
    manifest: SourceCapabilityManifest,
    pages: Vec<Vec<AcquiredRecord>>,
    cursor: usize,
}

impl FixtureSnapshotConnector {
    /// Construct a snapshot fixture with explicit pages.
    #[must_use]
    pub fn new(country: CountryCode, source_id: &str, pages: Vec<Vec<AcquiredRecord>>) -> Self {
        let mut manifest = manifest(source_id, Protocol::Rest, Transport::Http, country);
        manifest.modalities = vec![crate::modality::AcquisitionModality::Snapshot];
        manifest.snapshot = Some(SnapshotCapability {
            keyed_lookup: true,
            pagination: true,
            as_of: false,
        });
        Self {
            manifest,
            pages,
            cursor: 0,
        }
    }
}

#[async_trait]
impl SourceLifecycle for FixtureSnapshotConnector {
    fn manifest(&self) -> &SourceCapabilityManifest {
        &self.manifest
    }

    async fn health(&mut self) -> Result<SourceHealth> {
        Ok(health())
    }

    async fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl SnapshotConnector for FixtureSnapshotConnector {
    async fn fetch(&mut self, object_id: &str) -> Result<Option<AcquiredRecord>> {
        Ok(self
            .pages
            .iter()
            .flat_map(|page| page.iter())
            .find(|record| record.object_id == object_id)
            .cloned())
    }

    async fn fetch_page(&mut self, cursor: Option<&str>) -> Result<Vec<AcquiredRecord>> {
        let index = match cursor {
            None => self.cursor,
            Some(value) => value.parse::<usize>()?,
        };
        let page = self
            .pages
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("cursor outside snapshot fixture"))?
            .clone();
        self.cursor = index.saturating_add(1);
        Ok(page)
    }
}

/// Fixture-backed batch source with a checksummed manifest.
pub struct FixtureBatchConnector {
    manifest: SourceCapabilityManifest,
    pages: Vec<BatchPage>,
    cursor: usize,
}

impl FixtureBatchConnector {
    /// Construct a batch fixture with resumable pages.
    #[must_use]
    pub fn new(country: CountryCode, source_id: &str, pages: Vec<BatchPage>) -> Self {
        let mut manifest = manifest(source_id, Protocol::File, Transport::Sftp, country);
        manifest.modalities = vec![crate::modality::AcquisitionModality::Batch];
        manifest.batch = Some(BatchCapability {
            cursor: true,
            manifest: true,
            incremental: false,
        });
        Self {
            manifest,
            pages,
            cursor: 0,
        }
    }
}

#[async_trait]
impl SourceLifecycle for FixtureBatchConnector {
    fn manifest(&self) -> &SourceCapabilityManifest {
        &self.manifest
    }

    async fn health(&mut self) -> Result<SourceHealth> {
        Ok(health())
    }

    async fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl BatchConnector for FixtureBatchConnector {
    async fn list_objects(&mut self) -> Result<Vec<String>> {
        Ok(self
            .pages
            .iter()
            .flat_map(|page| page.records.iter().map(|record| record.object_id.clone()))
            .collect())
    }

    async fn fetch_page(&mut self, cursor: Option<&str>) -> Result<BatchPage> {
        let index = match cursor {
            None => 0,
            Some(value) => value.parse::<usize>()?,
        };
        let page = self
            .pages
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("cursor outside fixture"))?;
        self.cursor = index.saturating_add(1);
        Ok(page.clone())
    }
}

/// Fixture-backed document source with publication metadata and versions.
pub struct FixtureDocumentConnector {
    manifest: SourceCapabilityManifest,
    documents: Vec<DocumentRecord>,
}

impl FixtureDocumentConnector {
    /// Construct a document fixture.
    #[must_use]
    pub fn new(country: CountryCode, source_id: &str, documents: Vec<DocumentRecord>) -> Self {
        let mut manifest = manifest(source_id, Protocol::Document, Transport::Http, country);
        manifest.modalities = vec![crate::modality::AcquisitionModality::Document];
        manifest.document = Some(DocumentCapability {
            original_bytes: true,
            versioned: true,
            extraction: false,
        });
        Self {
            manifest,
            documents,
        }
    }
}

#[async_trait]
impl SourceLifecycle for FixtureDocumentConnector {
    fn manifest(&self) -> &SourceCapabilityManifest {
        &self.manifest
    }

    async fn health(&mut self) -> Result<SourceHealth> {
        Ok(health())
    }

    async fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl DocumentConnector for FixtureDocumentConnector {
    async fn list_documents(&mut self) -> Result<Vec<String>> {
        Ok(self
            .documents
            .iter()
            .map(|document| document.object_id.clone())
            .collect())
    }

    async fn fetch_document(&mut self, object_id: &str) -> Result<Option<DocumentRecord>> {
        let document = self
            .documents
            .iter()
            .find(|document| document.object_id == object_id)
            .cloned();
        if let Some(document) = &document {
            let digest = crate::util::sha256_hex(&document.bytes);
            anyhow::ensure!(
                digest == document.sha256,
                "document hash does not match original bytes"
            );
        }
        Ok(document)
    }
}

/// Evidence that a previously observed block was replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReorgEvidence {
    pub chain_id: String,
    pub replaced_block: String,
    pub replacement_block: String,
    pub observed_at_us: i64,
}

/// Fixture-backed on-chain source with block continuity and reorg evidence.
pub struct FixtureOnChainConnector {
    manifest: SourceCapabilityManifest,
    blocks: Vec<AcquiredRecord>,
    reorgs: Vec<ReorgEvidence>,
    cursor: usize,
}

impl FixtureOnChainConnector {
    /// Construct an on-chain fixture with explicit chain identity.
    #[must_use]
    pub fn new(
        country: CountryCode,
        source_id: &str,
        blocks: Vec<AcquiredRecord>,
        reorgs: Vec<ReorgEvidence>,
    ) -> Self {
        let mut manifest = manifest(source_id, Protocol::BlockchainRpc, Transport::Http, country);
        manifest.modalities = vec![crate::modality::AcquisitionModality::OnChain];
        manifest.on_chain = Some(OnChainCapability {
            rpc_query: true,
            block_stream: true,
            protocol_events: false,
        });
        Self {
            manifest,
            blocks,
            reorgs,
            cursor: 0,
        }
    }

    /// Return recorded reorganization evidence.
    #[must_use]
    pub fn reorgs(&self) -> &[ReorgEvidence] {
        &self.reorgs
    }

    /// Whether a block identity was superseded by a reorganization.
    #[must_use]
    pub fn is_superseded(&self, block: &str) -> bool {
        self.reorgs
            .iter()
            .any(|reorg| reorg.replaced_block == block)
    }
}

#[async_trait]
impl SourceLifecycle for FixtureOnChainConnector {
    fn manifest(&self) -> &SourceCapabilityManifest {
        &self.manifest
    }

    async fn health(&mut self) -> Result<SourceHealth> {
        Ok(health())
    }

    async fn disconnect(&mut self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl OnChainConnector for FixtureOnChainConnector {
    async fn query(&mut self, request: &str) -> Result<Vec<AcquiredRecord>> {
        Ok(self
            .blocks
            .iter()
            .filter(|record| record.object_id.contains(request))
            .cloned()
            .collect())
    }

    async fn next_block(&mut self) -> Result<Option<AcquiredRecord>> {
        let Some(block) = self.blocks.get(self.cursor) else {
            return Ok(None);
        };
        self.cursor = self.cursor.saturating_add(1);
        Ok(Some(block.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modality::validate_modalities;

    fn country() -> CountryCode {
        CountryCode::new("US").expect("country code")
    }

    fn acquired(id: &str, body: &str, sequence: u64) -> AcquiredRecord {
        AcquiredRecord {
            object_id: id.to_owned(),
            raw: body.as_bytes().to_vec(),
            source_timestamp_us: Some(1_700_000_000_000_000 + sequence as i64),
            sequence: Some(sequence),
        }
    }

    #[test]
    fn every_fixture_manifest_declares_one_realizable_modality() {
        let source = FixtureStreamingConnector::new(country(), "stream", Vec::new());
        let snapshot = FixtureSnapshotConnector::new(country(), "snapshot", Vec::new());
        let batch = FixtureBatchConnector::new(country(), "batch", Vec::new());
        let document = FixtureDocumentConnector::new(country(), "document", Vec::new());
        let chain = FixtureOnChainConnector::new(country(), "chain", Vec::new(), Vec::new());
        for manifest in [
            source.manifest(),
            snapshot.manifest(),
            batch.manifest(),
            document.manifest(),
            chain.manifest(),
        ] {
            let valid = validate_modalities(manifest).is_ok();
            let detail = format!("fixture manifest for {} must validate", manifest.source_id);
            assert!(valid, "{detail}");
        }
    }

    #[tokio::test]
    async fn streaming_fixture_delivers_ordered_frames_and_recovers() {
        let frames = vec![
            FixtureStreamFrame {
                object_id: "a".to_owned(),
                payload: b"one".to_vec(),
                sequence: 1,
                source_timestamp_us: 1_000,
            },
            FixtureStreamFrame {
                object_id: "b".to_owned(),
                payload: b"two".to_vec(),
                sequence: 2,
                source_timestamp_us: 2_000,
            },
        ];
        let mut connector = FixtureStreamingConnector::new(country(), "stream", frames);
        connector.connect().await.expect("connect");
        connector
            .subscribe(&["a".to_owned(), "b".to_owned()])
            .await
            .expect("subscribe");
        let first = connector.next_record().await.expect("next").expect("frame");
        assert_eq!(first.sequence, Some(1), "frames are ordered");
        let second = connector.next_record().await.expect("next").expect("frame");
        assert_eq!(second.sequence, Some(2), "second frame delivered");
        assert!(
            connector.next_record().await.expect("end").is_none(),
            "stream ends at the fixture boundary"
        );
        let report = connector.recover().await.expect("recover");
        assert!(report.recovered, "fixture recovery succeeds");
        let replayed = connector.next_record().await.expect("next").expect("frame");
        assert_eq!(replayed.sequence, Some(1), "recovery replays from snapshot");
    }

    #[tokio::test]
    async fn streaming_fixture_filters_unsubscribed_objects() {
        let frames = vec![
            FixtureStreamFrame {
                object_id: "a".to_owned(),
                payload: b"a".to_vec(),
                sequence: 1,
                source_timestamp_us: 1_000,
            },
            FixtureStreamFrame {
                object_id: "b".to_owned(),
                payload: b"b".to_vec(),
                sequence: 2,
                source_timestamp_us: 2_000,
            },
        ];
        let mut connector = FixtureStreamingConnector::new(country(), "stream", frames);
        connector
            .subscribe(&["b".to_owned()])
            .await
            .expect("subscribe");
        let first = connector.next_record().await.expect("next").expect("frame");
        assert_eq!(
            first.object_id, "b",
            "only subscribed objects are delivered"
        );
        assert!(
            connector.next_record().await.expect("end").is_none(),
            "unsubscribed frames are skipped"
        );
    }

    #[tokio::test]
    async fn snapshot_fixture_supports_keyed_lookup_and_pagination() {
        let first = vec![acquired("a", "value-a", 1)];
        let second = vec![acquired("b", "value-b", 2)];
        let mut connector = FixtureSnapshotConnector::new(
            country(),
            "snapshot",
            vec![first.clone(), second.clone()],
        );
        let fetched = connector.fetch("a").await.expect("fetch").expect("record");
        assert_eq!(fetched.object_id, "a", "keyed lookup works");
        let page1 = connector.fetch_page(None).await.expect("first page");
        assert_eq!(page1, first, "first page returned by the port");
        let page2 = connector.fetch_page(Some("1")).await.expect("second page");
        assert_eq!(page2, second, "second page returned by the port");
        assert!(
            connector.fetch_page(Some("2")).await.is_err(),
            "pagination terminates at the fixture boundary"
        );
    }

    #[tokio::test]
    async fn batch_fixture_resumes_from_cursor() {
        let page = BatchPage {
            records: vec![acquired("file-a", "payload", 1)],
            next_cursor: Some("1".to_owned()),
        };
        let mut connector = FixtureBatchConnector::new(country(), "batch", vec![page.clone()]);
        let objects = connector.list_objects().await.expect("list");
        assert_eq!(objects, vec!["file-a".to_owned()], "manifest lists objects");
        let fetched = connector.fetch_page(Some("0")).await.expect("page");
        assert_eq!(fetched, page, "page is deterministic and resumable");
    }

    #[tokio::test]
    async fn document_fixture_keeps_original_bytes_and_versions() {
        let original = DocumentRecord {
            object_id: "filing:v1".to_owned(),
            sha256: crate::util::sha256_hex(b"original"),
            published_us: Some(1_000),
            bytes: b"original".to_vec(),
        };
        let revised = DocumentRecord {
            object_id: "filing:v2".to_owned(),
            sha256: crate::util::sha256_hex(b"revised"),
            published_us: Some(2_000),
            bytes: b"revised".to_vec(),
        };
        let mut connector = FixtureDocumentConnector::new(
            country(),
            "document",
            vec![original.clone(), revised.clone()],
        );
        let documents = connector.list_documents().await.expect("list");
        assert_eq!(documents.len(), 2, "both versions remain visible");
        let fetched = connector
            .fetch_document("filing:v1")
            .await
            .expect("fetch")
            .expect("record");
        assert_eq!(fetched.bytes, original.bytes, "original bytes retained");
    }

    #[tokio::test]
    async fn onchain_fixture_keeps_block_continuity_and_reorg_evidence() {
        let blocks = vec![
            acquired("chain-1:100", "block-100", 100),
            acquired("chain-1:101", "block-101", 101),
        ];
        let reorgs = vec![ReorgEvidence {
            chain_id: "chain-1".to_owned(),
            replaced_block: "chain-1:101".to_owned(),
            replacement_block: "chain-1:101b".to_owned(),
            observed_at_us: 2_000,
        }];
        let mut connector =
            FixtureOnChainConnector::new(country(), "chain", blocks.clone(), reorgs);
        let first = connector.next_block().await.expect("next").expect("block");
        assert!(
            first.object_id.contains("chain-1"),
            "chain identity retained"
        );
        let queried = connector.query("101").await.expect("query");
        assert_eq!(queried.len(), 1, "query filters by block identity");
        assert_eq!(queried[0].sequence, Some(101), "block continuity retained");
        assert_eq!(
            connector.reorgs().len(),
            1,
            "reorganization evidence retained"
        );
        assert!(
            connector.is_superseded("chain-1:101"),
            "superseded blocks are explicit"
        );
    }

    #[tokio::test]
    async fn document_fixture_refuses_a_hash_mismatch() {
        let mut document = DocumentRecord {
            object_id: "filing:bad".to_owned(),
            sha256: "a".repeat(64),
            published_us: Some(1_000),
            bytes: b"original".to_vec(),
        };
        let mut connector =
            FixtureDocumentConnector::new(country(), "document", vec![document.clone()]);
        assert!(
            connector.fetch_document("filing:bad").await.is_err(),
            "a false document hash must fail closed"
        );
        document.sha256 = crate::util::sha256_hex(&document.bytes);
        let mut valid = FixtureDocumentConnector::new(country(), "document", vec![document]);
        assert!(
            valid.fetch_document("filing:bad").await.is_ok(),
            "a verified hash is accepted"
        );
    }
}
