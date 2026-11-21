// SPDX-License-Identifier: Apache-2.0
//! Typed acquisition ports separated by source modality.
//!
//! A historical file provider and a multicast exchange do not share one
//! lifecycle. The shared contract here is kept minimal: identity via a
//! manifest, health, and disconnect. Everything else is a typed port that a
//! connector implements only for the modality it genuinely declares.
//!
//! There is no dynamic plugin framework and no modality inference. A manifest
//! must declare a capability before the matching port applies, and a connector
//! must not receive credit for a capability it did not declare.

use std::fmt;

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde::Serialize;

use crate::governance::adapter::{
    ManifestError, RecoveryCapability, RecoveryReport, SourceCapabilityManifest, SourceHealth,
};

/// Shape of the interaction with a source, independent of its protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionModality {
    /// Continuous packets or messages.
    Streaming,
    /// Keyed request and response retrieval.
    Snapshot,
    /// Manifest- or cursor-driven batch delivery.
    Batch,
    /// Document retrieval with publication metadata.
    Document,
    /// Blockchain query and event subscription.
    OnChain,
}

impl AcquisitionModality {
    /// Return the stable contract string for this modality.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Streaming => "streaming",
            Self::Snapshot => "snapshot",
            Self::Batch => "batch",
            Self::Document => "document",
            Self::OnChain => "on_chain",
        }
    }

    /// Name of the typed port that implements this modality.
    pub const fn required_port(self) -> &'static str {
        match self {
            Self::Streaming => "StreamingConnector",
            Self::Snapshot => "SnapshotConnector",
            Self::Batch => "BatchConnector",
            Self::Document => "DocumentConnector",
            Self::OnChain => "OnChainConnector",
        }
    }
}

impl fmt::Display for AcquisitionModality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Continuous-delivery capability declared by a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingCapability {
    /// Whether the source pushes a continuous stream.
    pub continuous: bool,
    /// Whether the source publishes sequence numbers.
    pub sequence_numbers: bool,
    /// Recovery facilities the source genuinely supports.
    pub recovery: RecoveryCapability,
}

/// Keyed retrieval capability declared by a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCapability {
    /// Whether a single object can be fetched by identifier.
    pub keyed_lookup: bool,
    /// Whether results can be paginated.
    pub pagination: bool,
    /// Whether an as-of historical query is supported.
    pub as_of: bool,
}

/// Batch delivery capability declared by a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchCapability {
    /// Whether a batch is addressed by cursor.
    pub cursor: bool,
    /// Whether the source publishes a manifest of delivered objects.
    pub manifest: bool,
    /// Whether incremental delivery is supported.
    pub incremental: bool,
}

/// Document delivery capability declared by a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentCapability {
    /// Whether the original bytes are preserved.
    pub original_bytes: bool,
    /// Whether documents are versioned by the source.
    pub versioned: bool,
    /// Whether the source supplies extracted facts.
    pub extraction: bool,
}

/// On-chain capability declared by a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnChainCapability {
    /// Whether arbitrary queries are supported.
    pub rpc_query: bool,
    /// Whether block streams are supported.
    pub block_stream: bool,
    /// Whether protocol events are supported.
    pub protocol_events: bool,
}

/// One acquisition output record from any modality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquiredRecord {
    /// Source-local object identifier.
    pub object_id: String,
    /// Exact bytes received from the source.
    pub raw: Vec<u8>,
    /// Source-supplied timestamp, when the source supplies one.
    pub source_timestamp_us: Option<i64>,
    /// Source sequence number, when the source supplies one.
    pub sequence: Option<u64>,
}

/// One page of a cursor-driven batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchPage {
    /// Records in this page.
    pub records: Vec<AcquiredRecord>,
    /// Opaque cursor for the next page, absent at the end.
    pub next_cursor: Option<String>,
}

/// One source document with independent integrity metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentRecord {
    /// Source-local document identifier.
    pub object_id: String,
    /// Digest of the original bytes.
    pub sha256: String,
    /// Source publication time, when supplied.
    pub published_us: Option<i64>,
    /// Original document bytes.
    pub bytes: Vec<u8>,
}

/// Small lifecycle shared by every source, regardless of modality.
#[async_trait]
pub trait SourceLifecycle: Send + Sync {
    /// Return the connector's declared capability manifest.
    fn manifest(&self) -> &SourceCapabilityManifest;

    /// Report source health with a reason.
    async fn health(&mut self) -> Result<SourceHealth>;

    /// Close the source connection.
    async fn disconnect(&mut self) -> Result<()>;
}

/// Continuous streaming port.
#[async_trait]
pub trait StreamingConnector: SourceLifecycle {
    /// Establish the source connection.
    async fn connect(&mut self) -> Result<()>;

    /// Subscribe to an explicit object set.
    async fn subscribe(&mut self, object_ids: &[String]) -> Result<()>;

    /// Return the next acquired record, if one is available.
    async fn next_record(&mut self) -> Result<Option<AcquiredRecord>>;

    /// Recover from a declared discontinuity.
    async fn recover(&mut self) -> Result<RecoveryReport>;
}

/// Keyed request and response port.
#[async_trait]
pub trait SnapshotConnector: SourceLifecycle {
    /// Fetch one object by source-local identifier.
    async fn fetch(&mut self, object_id: &str) -> Result<Option<AcquiredRecord>>;
}

/// Manifest- or cursor-driven batch port.
#[async_trait]
pub trait BatchConnector: SourceLifecycle {
    /// List the objects advertised by the source.
    async fn list_objects(&mut self) -> Result<Vec<String>>;

    /// Fetch one page, optionally continuing from a cursor.
    async fn fetch_page(&mut self, cursor: Option<&str>) -> Result<BatchPage>;
}

/// Document retrieval port.
#[async_trait]
pub trait DocumentConnector: SourceLifecycle {
    /// List document identifiers advertised by the source.
    async fn list_documents(&mut self) -> Result<Vec<String>>;

    /// Fetch one original document with its publication metadata.
    async fn fetch_document(&mut self, object_id: &str) -> Result<Option<DocumentRecord>>;
}

/// Blockchain query and subscription port.
#[async_trait]
pub trait OnChainConnector: SourceLifecycle {
    /// Execute a declared query.
    async fn query(&mut self, request: &str) -> Result<Vec<AcquiredRecord>>;

    /// Return the next block or protocol-event record.
    async fn next_block(&mut self) -> Result<Option<AcquiredRecord>>;
}

/// Check that every declared modality has its capability declaration and a
/// protocol/transport combination that can realize it.
pub fn validate_modalities(manifest: &SourceCapabilityManifest) -> Result<(), ManifestError> {
    use crate::governance::adapter::{
        Protocol,  //
        Transport, //
    };

    if manifest.modalities.is_empty() {
        return Err(ManifestError::MissingModalities);
    }
    for modality in &manifest.modalities {
        let capability_present = match modality {
            AcquisitionModality::Streaming => manifest.streaming.is_some(),
            AcquisitionModality::Snapshot => manifest.snapshot.is_some(),
            AcquisitionModality::Batch => manifest.batch.is_some(),
            AcquisitionModality::Document => manifest.document.is_some(),
            AcquisitionModality::OnChain => manifest.on_chain.is_some(),
        };
        if !capability_present {
            return Err(ManifestError::MissingModalityCapability(*modality));
        }
        let protocol_ok = match modality {
            AcquisitionModality::Streaming => manifest.protocols.iter().any(|protocol| {
                matches!(
                    protocol,
                    Protocol::NativeBinary
                        | Protocol::Fix
                        | Protocol::FixSbe
                        | Protocol::Itch
                        | Protocol::Fast
                        | Protocol::WebSocket
                )
            }),
            AcquisitionModality::Snapshot => manifest.protocols.contains(&Protocol::Rest),
            AcquisitionModality::Batch => manifest.protocols.contains(&Protocol::File),
            AcquisitionModality::Document => manifest.protocols.contains(&Protocol::Document),
            AcquisitionModality::OnChain => manifest.protocols.contains(&Protocol::BlockchainRpc),
        };
        if !protocol_ok {
            return Err(ManifestError::InconsistentModality {
                modality: *modality,
                reason: "declared protocols cannot realize the modality",
            });
        }
        let transport_ok = match modality {
            AcquisitionModality::Streaming => manifest.transports.iter().any(|transport| {
                matches!(
                    transport,
                    Transport::Tcp
                        | Transport::UdpMulticast
                        | Transport::WebSocket
                        | Transport::Ipc
                )
            }),
            AcquisitionModality::Snapshot => manifest.transports.contains(&Transport::Http),
            AcquisitionModality::Batch => manifest.transports.iter().any(|transport| {
                matches!(
                    transport,
                    Transport::File | Transport::Sftp | Transport::Http
                )
            }),
            AcquisitionModality::Document => manifest.transports.iter().any(|transport| {
                matches!(
                    transport,
                    Transport::File | Transport::Sftp | Transport::Http
                )
            }),
            AcquisitionModality::OnChain => manifest.transports.iter().any(|transport| {
                matches!(
                    transport,
                    Transport::Http | Transport::Ipc | Transport::WebSocket
                )
            }),
        };
        if !transport_ok {
            return Err(ManifestError::InconsistentModality {
                modality: *modality,
                reason: "declared transports cannot realize the modality",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::adapter::{
        AccessStatus,             //
        Protocol,                 //
        SourceCapabilityManifest, //
        Transport,                //
    };
    use crate::reference_data::VenueCategory;
    use crate::taxonomy::{
        AssetClass,   //
        CountryCode,  //
        DataCategory, //
        DepthModel,   //
        Frequency,    //
    };

    fn manifest() -> SourceCapabilityManifest {
        SourceCapabilityManifest {
            source_id: "source".to_owned(),
            provider: "provider".to_owned(),
            venue_mic: None,
            country: CountryCode::new("US").expect("country code"),
            venue_category: VenueCategory::Exchange,
            asset_classes: vec![AssetClass::Equity],
            data_categories: vec![DataCategory::Trades],
            protocols: vec![Protocol::WebSocket],
            transports: vec![Transport::WebSocket],
            book_model: DepthModel::Level2,
            timestamps: crate::governance::adapter::TimestampCapability {
                exchange_event_time: false,
                exchange_publication_time: false,
                packet_capture_time: true,
                sequence_numbers: true,
                clock_source: "host".to_owned(),
            },
            recovery: RecoveryCapability {
                snapshot: false,
                incremental_recovery: false,
                packet_sequence: true,
                exchange_sequence: false,
                gap_request: false,
            },
            historical: crate::governance::adapter::HistoricalCapability {
                available: false,
                earliest_us: None,
                frequency: Frequency::RealTime,
            },
            access: AccessStatus::Public,
            schema_version: 1,
            modalities: vec![AcquisitionModality::Streaming],
            streaming: Some(StreamingCapability {
                continuous: true,
                sequence_numbers: true,
                recovery: RecoveryCapability {
                    snapshot: false,
                    incremental_recovery: false,
                    packet_sequence: true,
                    exchange_sequence: false,
                    gap_request: false,
                },
            }),
            snapshot: None,
            batch: None,
            document: None,
            on_chain: None,
        }
    }

    #[test]
    fn modality_labels_and_ports_are_stable() {
        assert_eq!(
            AcquisitionModality::Streaming.as_str(),
            "streaming",
            "streaming label is stable"
        );
        assert_eq!(
            AcquisitionModality::OnChain.as_str(),
            "on_chain",
            "on-chain label is stable"
        );
        assert_eq!(
            AcquisitionModality::Streaming.required_port(),
            "StreamingConnector",
            "streaming port name is stable"
        );
        assert_eq!(
            AcquisitionModality::Document.required_port(),
            "DocumentConnector",
            "document port name is stable"
        );
    }

    #[test]
    fn undeclared_modality_is_rejected() {
        let mut source = manifest();
        source.modalities.clear();
        assert_eq!(
            validate_modalities(&source),
            Err(ManifestError::MissingModalities),
            "empty modality declaration must fail"
        );
    }

    #[test]
    fn modality_without_capability_is_rejected() {
        let mut source = manifest();
        source.streaming = None;
        assert!(
            matches!(
                validate_modalities(&source),
                Err(ManifestError::MissingModalityCapability(
                    AcquisitionModality::Streaming
                ))
            ),
            "a declared modality without capability must fail"
        );
    }

    #[test]
    fn inconsistent_protocol_is_rejected() {
        let mut source = manifest();
        source.protocols = vec![Protocol::File];
        assert!(
            matches!(
                validate_modalities(&source),
                Err(ManifestError::InconsistentModality { .. })
            ),
            "an unrealizable modality must fail"
        );
    }
}
