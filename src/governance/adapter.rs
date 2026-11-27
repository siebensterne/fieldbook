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

/// Registry of declared source capabilities and their enforceable grants.
#[derive(Debug, Default)]
pub struct SourceRegistry {
    manifests: BTreeMap<String, SourceCapabilityManifest>,
    grants: BTreeMap<(String, SourceCapability), CapabilityGrant>,
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

    /// Record one validated capability grant. A second grant for the same
    /// subject and capability is refused so selection stays unambiguous.
    pub fn grant(&mut self, grant: CapabilityGrant) -> Result<(), CapabilityDenial> {
        grant.validate()?;
        let key = (grant.subject.clone(), grant.capability);
        if self.grants.contains_key(&key) {
            return Err(CapabilityDenial::Incompatible {
                reason: "duplicate capability grant",
            });
        }
        self.grants.insert(key, grant);
        Ok(())
    }

    /// Record a revocation with its retained reason reference.
    pub fn revoke(
        &mut self,
        subject: &str,
        capability: SourceCapability,
        reason_ref: &str,
    ) -> Result<(), CapabilityDenial> {
        if reason_ref.is_empty() {
            return Err(CapabilityDenial::Incompatible {
                reason: "empty revocation reference",
            });
        }
        let grant = self
            .grants
            .get_mut(&(subject.to_owned(), capability))
            .ok_or(CapabilityDenial::Missing {
                subject: subject.to_owned(),
                capability,
            })?;
        grant.state = GrantState::Revoked {
            reason_ref: reason_ref.to_owned(),
        };
        Ok(())
    }

    /// Enforced selection point for a source or target. Every requested
    /// binding, the manifest declaration, the grant state and the validity
    /// interval are checked before a manifest is returned. Unknown is denied.
    pub fn select(
        &self,
        request: &SelectionRequest<'_>,
    ) -> Result<&SourceCapabilityManifest, CapabilityDenial> {
        let manifest = self
            .resolve(request.subject)
            .ok_or(CapabilityDenial::Incompatible {
                reason: "unknown source identity",
            })?;
        if !request.capability.declared_by(manifest) {
            return Err(CapabilityDenial::Incompatible {
                reason: "capability not declared",
            });
        }
        let grant = self
            .grants
            .get(&(request.subject.to_owned(), request.capability))
            .ok_or_else(|| CapabilityDenial::Missing {
                subject: request.subject.to_owned(),
                capability: request.capability,
            })?;
        if grant.actor != request.actor
            || grant.subject != request.subject
            || grant.action != request.action
            || grant.resource != request.resource
            || grant.scope != request.scope
            || grant.policy_version != request.policy_version
        {
            return Err(CapabilityDenial::Incompatible {
                reason: "grant binding mismatch",
            });
        }
        if let GrantState::Revoked { reason_ref } = &grant.state {
            return Err(CapabilityDenial::Revoked {
                reason_ref: reason_ref.clone(),
            });
        }
        if request.at_us < grant.valid_from_us
            || grant.valid_until_us.is_some_and(|end| request.at_us > end)
        {
            return Err(CapabilityDenial::Expired {
                at_us: request.at_us,
                valid_from_us: grant.valid_from_us,
                valid_until_us: grant.valid_until_us,
            });
        }
        Ok(manifest)
    }
}

/// Named capability that a manifest may declare and a request may exercise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceCapability {
    Streaming,
    Snapshot,
    Batch,
    Document,
    OnChain,
    Historical,
}

impl SourceCapability {
    /// Return the stable contract string for this capability.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Streaming => "streaming",
            Self::Snapshot => "snapshot",
            Self::Batch => "batch",
            Self::Document => "document",
            Self::OnChain => "on_chain",
            Self::Historical => "historical",
        }
    }

    /// Answer whether a manifest genuinely declares this capability.
    pub fn declared_by(self, manifest: &SourceCapabilityManifest) -> bool {
        match self {
            Self::Streaming => {
                manifest
                    .modalities
                    .contains(&AcquisitionModality::Streaming)
                    && manifest.streaming.is_some()
            }
            Self::Snapshot => {
                manifest.modalities.contains(&AcquisitionModality::Snapshot)
                    && manifest.snapshot.is_some()
            }
            Self::Batch => {
                manifest.modalities.contains(&AcquisitionModality::Batch)
                    && manifest.batch.is_some()
            }
            Self::Document => {
                manifest.modalities.contains(&AcquisitionModality::Document)
                    && manifest.document.is_some()
            }
            Self::OnChain => {
                manifest.modalities.contains(&AcquisitionModality::OnChain)
                    && manifest.on_chain.is_some()
            }
            Self::Historical => manifest.historical.available,
        }
    }
}

/// Action a selection request performs on its resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityAction {
    SelectSource,
    SelectTarget,
}

/// Scope in which a capability grant is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityScope {
    Acquisition,
    Distribution,
}

/// Reference to retained proof, never the proof bytes themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityEvidence {
    pub digest: String,
    pub origin: String,
}

impl CapabilityEvidence {
    fn validate(&self) -> Result<(), CapabilityDenial> {
        if self.digest.len() < 16 || !self.digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CapabilityDenial::Incompatible {
                reason: "invalid evidence digest",
            });
        }
        if self.origin.is_empty() {
            return Err(CapabilityDenial::Incompatible {
                reason: "missing evidence origin",
            });
        }
        Ok(())
    }
}

/// Lifecycle of a recorded grant. Revocation always carries a reason reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GrantState {
    Active,
    Revoked { reason_ref: String },
}

/// Enforceable capability grant binding every party and condition of a choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub actor: String,
    pub subject: String,
    pub capability: SourceCapability,
    pub action: CapabilityAction,
    pub resource: String,
    pub scope: CapabilityScope,
    pub policy_version: u32,
    pub valid_from_us: i64,
    pub valid_until_us: Option<i64>,
    pub evidence: CapabilityEvidence,
    pub state: GrantState,
}

impl CapabilityGrant {
    /// Validate every binding, the policy version and the retained evidence.
    pub fn validate(&self) -> Result<(), CapabilityDenial> {
        if self.actor.is_empty() || self.subject.is_empty() || self.resource.is_empty() {
            return Err(CapabilityDenial::Incompatible {
                reason: "empty grant binding",
            });
        }
        if self.policy_version == 0 {
            return Err(CapabilityDenial::Incompatible {
                reason: "zero policy version",
            });
        }
        if self
            .valid_until_us
            .is_some_and(|end| self.valid_from_us > end)
        {
            return Err(CapabilityDenial::Expired {
                at_us: self.valid_from_us,
                valid_from_us: self.valid_from_us,
                valid_until_us: self.valid_until_us,
            });
        }
        self.evidence.validate()?;
        if let GrantState::Revoked { reason_ref } = &self.state
            && reason_ref.is_empty()
        {
            return Err(CapabilityDenial::Incompatible {
                reason: "empty revocation reference",
            });
        }
        Ok(())
    }
}

/// Explicit request made at the point a source or target is selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionRequest<'a> {
    pub actor: &'a str,
    pub subject: &'a str,
    pub capability: SourceCapability,
    pub action: CapabilityAction,
    pub resource: &'a str,
    pub scope: CapabilityScope,
    pub policy_version: u32,
    pub at_us: i64,
}

/// Fail-closed reason a selection was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityDenial {
    #[error("no capability grant for subject {subject} and capability {capability:?}")]
    Missing {
        subject: String,
        capability: SourceCapability,
    },
    #[error("capability expired at {at_us}; valid from {valid_from_us} until {valid_until_us:?}")]
    Expired {
        at_us: i64,
        valid_from_us: i64,
        valid_until_us: Option<i64>,
    },
    #[error("capability grant was revoked: {reason_ref}")]
    Revoked { reason_ref: String },
    #[error("capability is incompatible with the selection request: {reason}")]
    Incompatible { reason: &'static str },
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

    fn evidence() -> CapabilityEvidence {
        CapabilityEvidence {
            digest: "0123456789abcdef".to_owned(),
            origin: "retained-proof-store".to_owned(),
        }
    }

    fn grant() -> CapabilityGrant {
        CapabilityGrant {
            actor: "actor-a".to_owned(),
            subject: "source".to_owned(),
            capability: SourceCapability::Streaming,
            action: CapabilityAction::SelectSource,
            resource: "target-a".to_owned(),
            scope: CapabilityScope::Acquisition,
            policy_version: 1,
            valid_from_us: 10,
            valid_until_us: Some(20),
            evidence: evidence(),
            state: GrantState::Active,
        }
    }

    fn request() -> SelectionRequest<'static> {
        SelectionRequest {
            actor: "actor-a",
            subject: "source",
            capability: SourceCapability::Streaming,
            action: CapabilityAction::SelectSource,
            resource: "target-a",
            scope: CapabilityScope::Acquisition,
            policy_version: 1,
            at_us: 15,
        }
    }

    #[test]
    fn compatible_grant_permits_selection() {
        let mut registry = SourceRegistry::new();
        registry.register(manifest()).expect("manifest");
        registry.grant(grant()).expect("grant");
        assert_eq!(
            registry.select(&request()),
            Ok(&manifest()),
            "a manifest-declared capability with a matching grant permits selection"
        );
    }

    #[test]
    fn missing_capability_grant_is_rejected_at_selection() {
        let mut registry = SourceRegistry::new();
        registry.register(manifest()).expect("manifest");
        assert_eq!(
            registry.select(&request()),
            Err(CapabilityDenial::Missing {
                subject: "source".to_owned(),
                capability: SourceCapability::Streaming,
            }),
            "selection without a recorded grant must fail closed"
        );
    }

    #[test]
    fn expired_capability_grant_is_rejected_at_selection() {
        let mut registry = SourceRegistry::new();
        registry.register(manifest()).expect("manifest");
        registry.grant(grant()).expect("grant");
        let mut late = request();
        late.at_us = 21;
        assert!(
            matches!(
                registry.select(&late),
                Err(CapabilityDenial::Expired { at_us: 21, .. })
            ),
            "a request after the validity interval must be refused"
        );
        let mut early = request();
        early.at_us = 9;
        assert!(
            matches!(
                registry.select(&early),
                Err(CapabilityDenial::Expired { at_us: 9, .. })
            ),
            "a request before the validity interval must be refused"
        );
    }

    #[test]
    fn revoked_capability_grant_is_rejected_at_selection() {
        let mut registry = SourceRegistry::new();
        registry.register(manifest()).expect("manifest");
        registry.grant(grant()).expect("grant");
        registry
            .revoke("source", SourceCapability::Streaming, "proof-of-revocation")
            .expect("revocation");
        assert_eq!(
            registry.select(&request()),
            Err(CapabilityDenial::Revoked {
                reason_ref: "proof-of-revocation".to_owned(),
            }),
            "a revoked grant must fail closed with its reason reference"
        );
    }

    #[test]
    fn incompatible_grant_bindings_are_rejected_at_selection() {
        for label in ["actor", "action", "resource", "scope", "policy_version"] {
            let mut registry = SourceRegistry::new();
            registry.register(manifest()).expect("manifest");
            registry.grant(grant()).expect("grant");
            let mut selection = request();
            match label {
                "actor" => selection.actor = "actor-b",
                "action" => selection.action = CapabilityAction::SelectTarget,
                "resource" => selection.resource = "target-b",
                "scope" => selection.scope = CapabilityScope::Distribution,
                "policy_version" => selection.policy_version = 2,
                _ => {}
            }
            assert_eq!(
                registry.select(&selection),
                Err(CapabilityDenial::Incompatible {
                    reason: "grant binding mismatch",
                }),
                "binding {label} must be enforced at selection"
            );
        }
    }

    #[test]
    fn unknown_capability_is_never_supported() {
        let mut registry = SourceRegistry::new();
        registry.register(manifest()).expect("manifest");
        let mut undeclared = grant();
        undeclared.capability = SourceCapability::OnChain;
        registry.grant(undeclared).expect("grant");
        let mut undeclared_request = request();
        undeclared_request.capability = SourceCapability::OnChain;
        assert_eq!(
            registry.select(&undeclared_request),
            Err(CapabilityDenial::Incompatible {
                reason: "capability not declared",
            }),
            "an undeclared capability must never be treated as supported"
        );
        let mut unknown = request();
        unknown.subject = "missing-source";
        assert_eq!(
            registry.select(&unknown),
            Err(CapabilityDenial::Incompatible {
                reason: "unknown source identity",
            }),
            "an unknown source must never be treated as supported"
        );
    }

    #[test]
    fn malformed_grant_is_refused_at_registration() {
        let mut registry = SourceRegistry::new();
        let mut without_evidence = grant();
        without_evidence.evidence.digest.clear();
        assert_eq!(
            registry.grant(without_evidence),
            Err(CapabilityDenial::Incompatible {
                reason: "invalid evidence digest",
            }),
            "a grant without a retained evidence reference must be refused"
        );
        let mut zero_policy = grant();
        zero_policy.policy_version = 0;
        assert_eq!(
            registry.grant(zero_policy),
            Err(CapabilityDenial::Incompatible {
                reason: "zero policy version",
            }),
            "a grant without a policy version must be refused"
        );
    }
}
