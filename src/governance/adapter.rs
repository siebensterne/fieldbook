//! Universal acquisition framework and source capability declarations.
//!
//! A connector declares what a source genuinely provides. A data structure
//! named an order book does not make a source an L3 venue, and an available
//! endpoint does not grant redistribution rights.

use std::collections::BTreeMap;

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde::Serialize;

use crate::{
    governance::modality::{
        AcquisitionModality, BatchCapability, DocumentCapability, OnChainCapability,
        SnapshotCapability, StreamingCapability, validate_modalities,
    },
    reference_data::VenueCategory,
    taxonomy::{AssetClass, CountryCode, DataCategory, DepthModel, Frequency},
};

/// Wire protocol or application encoding exposed by a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    NativeBinary,
    Fix,
    FixSbe,
    Itch,
    Fast,
    WebSocket,
    Rest,
    File,
    BlockchainRpc,
    Document,
}

impl Protocol {
    /// Return the stable contract string for this protocol.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeBinary => "native_binary",
            Self::Fix => "fix",
            Self::FixSbe => "fix_sbe",
            Self::Itch => "itch",
            Self::Fast => "fast",
            Self::WebSocket => "web_socket",
            Self::Rest => "rest",
            Self::File => "file",
            Self::BlockchainRpc => "blockchain_rpc",
            Self::Document => "document",
        }
    }
}

/// Delivery transport used by a connector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    UdpMulticast,
    WebSocket,
    Http,
    Sftp,
    File,
    Ipc,
}

impl Transport {
    /// Return the stable contract string for this transport.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::UdpMulticast => "udp_multicast",
            Self::WebSocket => "web_socket",
            Self::Http => "http",
            Self::Sftp => "sftp",
            Self::File => "file",
            Self::Ipc => "ipc",
        }
    }
}

/// Recovery facilities genuinely supported by a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryCapability {
    pub snapshot: bool,
    pub incremental_recovery: bool,
    pub packet_sequence: bool,
    pub exchange_sequence: bool,
    pub gap_request: bool,
}

/// Timestamp facilities declared by a source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampCapability {
    pub exchange_event_time: bool,
    pub exchange_publication_time: bool,
    pub packet_capture_time: bool,
    pub sequence_numbers: bool,
    pub clock_source: String,
}

/// Historical availability declared by a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalCapability {
    pub available: bool,
    pub earliest_us: Option<i64>,
    pub frequency: Frequency,
}

/// Commercial status of a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessStatus {
    Public,
    Licensed,
    Delayed,
    ParticipantEntitled,
}

impl AccessStatus {
    /// Return the stable contract string for this access status.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Licensed => "licensed",
            Self::Delayed => "delayed",
            Self::ParticipantEntitled => "participant_entitled",
        }
    }
}

/// Machine-readable declaration of a source's real capabilities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCapabilityManifest {
    pub source_id: String,
    pub provider: String,
    pub venue_mic: Option<String>,
    pub country: CountryCode,
    pub venue_category: VenueCategory,
    pub asset_classes: Vec<AssetClass>,
    pub data_categories: Vec<DataCategory>,
    pub protocols: Vec<Protocol>,
    pub transports: Vec<Transport>,
    pub book_model: DepthModel,
    pub timestamps: TimestampCapability,
    pub recovery: RecoveryCapability,
    pub historical: HistoricalCapability,
    pub access: AccessStatus,
    pub schema_version: u32,
    /// Acquisition modalities the connector genuinely implements.
    #[serde(default)]
    pub modalities: Vec<AcquisitionModality>,
    /// Capability declaration for the streaming port, when declared.
    #[serde(default)]
    pub streaming: Option<StreamingCapability>,
    /// Capability declaration for the snapshot port, when declared.
    #[serde(default)]
    pub snapshot: Option<SnapshotCapability>,
    /// Capability declaration for the batch port, when declared.
    #[serde(default)]
    pub batch: Option<BatchCapability>,
    /// Capability declaration for the document port, when declared.
    #[serde(default)]
    pub document: Option<DocumentCapability>,
    /// Capability declaration for the on-chain port, when declared.
    #[serde(default)]
    pub on_chain: Option<OnChainCapability>,
}

impl SourceCapabilityManifest {
    /// Validate declaration shape and fail closed on empty coverage.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.source_id.is_empty() || self.provider.is_empty() {
            return Err(ManifestError::MissingIdentity);
        }
        if self.asset_classes.is_empty() || self.data_categories.is_empty() {
            return Err(ManifestError::MissingCoverage);
        }
        if self.protocols.is_empty() || self.transports.is_empty() {
            return Err(ManifestError::MissingTransport);
        }
        if self.schema_version == 0 {
            return Err(ManifestError::InvalidSchemaVersion);
        }
        validate_modalities(self)?;
        Ok(())
    }
}

/// Manifest validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    /// Source or provider identity is empty.
    #[error("source and provider identity are required")]
    MissingIdentity,
    /// Asset classes or data categories are empty.
    #[error("coverage declaration is required")]
    MissingCoverage,
    /// Protocol or transport declaration is empty.
    #[error("protocol and transport declaration are required")]
    MissingTransport,
    /// Schema version must be positive.
    #[error("schema version must be positive")]
    InvalidSchemaVersion,
    /// Two different manifests claimed the same source identity.
    #[error("conflicting manifest for source {0}")]
    Conflict(String),
    /// The manifest did not declare any acquisition modality.
    #[error("at least one acquisition modality must be declared")]
    MissingModalities,
    /// A declared modality has no corresponding capability declaration.
    #[error("modality {0} has no capability declaration")]
    MissingModalityCapability(AcquisitionModality),
    /// Declared protocols or transports cannot realize a declared modality.
    #[error("modality {modality} is inconsistent with declared protocols or transports: {reason}")]
    InconsistentModality {
        /// Modality that could not be realized.
        modality: AcquisitionModality,
        /// Description of the inconsistency.
        reason: &'static str,
    },
}

/// Health of one connected source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SourceHealthState {
    Connecting,
    Connected,
    Degraded,
    Reconnecting,
    Stopped,
}

/// Health report with explicit reason, not a boolean.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceHealth {
    pub state: SourceHealthState,
    pub last_success_us: Option<i64>,
    pub reason: Option<String>,
}

/// Outcome of a source recovery attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub attempts: u32,
    pub recovered: bool,
    pub gaps: u64,
    pub reason: Option<String>,
}

/// Acquisition contract implemented by every source connector.
#[async_trait]
pub trait SourceConnector: Send + Sync {
    /// Return the connector's capability declaration.
    fn manifest(&self) -> &SourceCapabilityManifest;

    /// Establish the source connection.
    async fn connect(&mut self) -> Result<()>;

    /// Discover available instruments or information objects.
    async fn discover(&mut self) -> Result<Vec<String>>;

    /// Subscribe to an explicit object set.
    async fn subscribe(&mut self, identifiers: &[String]) -> Result<()>;

    /// Recover from a declared discontinuity.
    async fn recover(&mut self) -> Result<RecoveryReport>;

    /// Report source health with a reason.
    async fn health(&mut self) -> Result<SourceHealth>;

    /// Close the source connection.
    async fn disconnect(&mut self) -> Result<()>;
}

/// Registry of declared source capabilities.
#[derive(Debug, Default)]
pub struct SourceRegistry {
    manifests: BTreeMap<String, SourceCapabilityManifest>,
}

impl SourceRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a validated manifest.
    pub fn register(&mut self, manifest: SourceCapabilityManifest) -> Result<(), ManifestError> {
        manifest.validate()?;
        match self.manifests.get(&manifest.source_id) {
            Some(existing) if existing != &manifest => {
                Err(ManifestError::Conflict(manifest.source_id.clone()))
            }
            Some(_) => Ok(()),
            None => {
                self.manifests.insert(manifest.source_id.clone(), manifest);
                Ok(())
            }
        }
    }

    /// Return a declared manifest by source identity.
    pub fn resolve(&self, source_id: &str) -> Option<&SourceCapabilityManifest> {
        self.manifests.get(source_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> SourceCapabilityManifest {
        SourceCapabilityManifest {
            source_id: "source".to_owned(),
            provider: "provider".to_owned(),
            venue_mic: Some("XABC".to_owned()),
            country: CountryCode::new("US").expect("country code"),
            venue_category: VenueCategory::Exchange,
            asset_classes: vec![AssetClass::Equity],
            data_categories: vec![DataCategory::Level2Book],
            protocols: vec![Protocol::Itch],
            transports: vec![Transport::UdpMulticast],
            book_model: DepthModel::Level3,
            timestamps: TimestampCapability {
                exchange_event_time: true,
                exchange_publication_time: false,
                packet_capture_time: true,
                sequence_numbers: true,
                clock_source: "ptp".to_owned(),
            },
            recovery: RecoveryCapability {
                snapshot: true,
                incremental_recovery: true,
                packet_sequence: true,
                exchange_sequence: true,
                gap_request: true,
            },
            historical: HistoricalCapability {
                available: true,
                earliest_us: Some(0),
                frequency: Frequency::RealTime,
            },
            access: AccessStatus::Licensed,
            schema_version: 1,
            modalities: vec![AcquisitionModality::Streaming],
            streaming: Some(StreamingCapability {
                continuous: true,
                sequence_numbers: true,
                recovery: RecoveryCapability {
                    snapshot: true,
                    incremental_recovery: true,
                    packet_sequence: true,
                    exchange_sequence: true,
                    gap_request: true,
                },
            }),
            snapshot: None,
            batch: None,
            document: None,
            on_chain: None,
        }
    }

    #[test]
    fn declaration_must_be_complete() {
        let mut incomplete = manifest();
        incomplete.data_categories.clear();
        assert_eq!(
            incomplete.validate(),
            Err(ManifestError::MissingCoverage),
            "empty coverage must fail"
        );
        assert!(manifest().validate().is_ok(), "complete manifest must pass");
    }

    #[test]
    fn registry_rejects_conflicting_identity() {
        let mut registry = SourceRegistry::new();
        registry.register(manifest()).expect("first manifest");
        let mut altered = manifest();
        altered.book_model = DepthModel::Level1;
        assert!(
            registry.register(altered).is_err(),
            "conflicting manifest must be rejected"
        );
        assert_eq!(
            registry.resolve("source"),
            Some(&manifest()),
            "original manifest must remain"
        );
    }
}
