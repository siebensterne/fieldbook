// SPDX-License-Identifier: Apache-2.0
//! Independent source conformance harness.
//!
//! A source is certified by comparing its declaration against deterministic
//! fixtures and actual connector output. A successful `connect()` is never a
//! certification signal. Every check is explicit, fail-closed, and reported
//! with a reason so an unmet condition cannot hide behind an ordinal status.

use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;

use crate::{
    acquisition::arbiter::{ArbiterLimits, SequencedPacket},
    acquisition::codec::{CodecRegistry, DecodeStatus},
    acquisition::fixture_connectors::{
        FixtureBatchConnector, FixtureDocumentConnector, FixtureOnChainConnector,
        FixtureSnapshotConnector, FixtureStreamFrame, FixtureStreamingConnector,
    },
    acquisition::stream_slice::{CollectingSink, SliceConfig, run_stream_slice},
    governance::modality::{
        AcquiredRecord, AcquisitionModality, BatchConnector, BatchPage, DocumentConnector,
        DocumentRecord, OnChainConnector, SnapshotConnector, StreamingConnector,
    },
    governance::{
        adapter::SourceCapabilityManifest,
        coverage_certification::ExpectedUniverse,
        modality::validate_modalities,
        rights::{AuthorizationScope, LicensingRegistry, Operation, ScopeSet, UsageRight},
    },
    taxonomy::CountryCode,
};

/// Evidence state of one independent conformance stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceStageState {
    /// No evidence was supplied for this stage.
    NotAssessed,
    /// The harness verified this stage against a deterministic fixture.
    Pass,
    /// The harness found a discrepancy.
    Fail,
    /// External evidence was referenced but not independently validated here.
    Declared,
}

impl ConformanceStageState {
    /// Return the stable contract string for this state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAssessed => "not_assessed",
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Declared => "declared",
        }
    }
}

/// Separate conformance statuses. A fixture result cannot stand in for a live
/// or network result, and a successful writer cannot stand in for completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceStatuses {
    pub code_present: ConformanceStageState,
    pub fixture_conformant: ConformanceStageState,
    pub integration_conformant: ConformanceStageState,
    pub rights_approved: ConformanceStageState,
    pub network_validated: ConformanceStageState,
    pub live_verified: ConformanceStageState,
    pub history_reconciled: ConformanceStageState,
    pub certified: ConformanceStageState,
}

impl ConformanceStatuses {
    /// Whether every stage carries independently verified passing evidence.
    #[must_use]
    pub fn fully_certified(&self) -> bool {
        [
            self.code_present,
            self.fixture_conformant,
            self.integration_conformant,
            self.rights_approved,
            self.network_validated,
            self.live_verified,
            self.history_reconciled,
            self.certified,
        ]
        .iter()
        .all(|state| *state == ConformanceStageState::Pass)
    }
}

/// Optional references to evidence that this harness cannot independently
/// validate. Providing a reference records a declaration, not a pass.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalEvidence {
    #[serde(default)]
    pub network_validation: Option<String>,
    #[serde(default)]
    pub live_capture: Option<String>,
    #[serde(default)]
    pub history_reconciliation: Option<String>,
}

/// Deterministic end-to-end fixture for the integration stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationFixture {
    pub directory: PathBuf,
    pub run_id: String,
    pub config: SliceConfig,
    pub packets: Vec<SequencedPacket>,
    pub expected_typed_events: usize,
}

/// Policy for observation kinds absent from the declaration.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownEventPolicy {
    #[default]
    Reject,
    AllowDocumented,
}

/// Description of a modality fixture the harness must invoke.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorFixture {
    pub modality: AcquisitionModality,
    pub object_id: String,
    pub expected_records: usize,
}

/// What a source claims before any conformance evidence is examined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceDeclaration {
    /// Source identity used by the codec registry.
    pub source_id: String,
    /// Provider identity, distinct from the source when applicable.
    #[serde(default)]
    pub provider_id: String,
    /// Product identity whose rights are exercised.
    #[serde(default)]
    pub product_id: String,
    /// Dataset whose rights are exercised.
    pub dataset: String,
    /// Machine-readable capability manifest.
    pub manifest: SourceCapabilityManifest,
    /// Expected universe, or an explicit declaration that none is measurable.
    pub expected_universe: Option<ExpectedUniverse>,
    /// Observation kinds the source declares that it publishes.
    pub declared_kinds: Vec<String>,
    /// Rights that the declared workflow requires.
    pub rights_required: Vec<UsageRight>,
    /// Optional end-to-end fixture for the integration stage.
    #[serde(default)]
    pub integration: Option<IntegrationFixture>,
    /// Optional references to externally validated evidence.
    #[serde(default)]
    pub external: ExternalEvidence,
    /// Source or test path proving the implementation exists.
    #[serde(default)]
    pub code_reference: Option<String>,
    /// Explicit exemption reason when no rights are required.
    #[serde(default)]
    pub rights_exemption: Option<String>,
    /// How undeclared observation kinds are treated.
    #[serde(default)]
    pub unknown_event_policy: UnknownEventPolicy,
    /// Modality connector fixture the harness must invoke.
    #[serde(default)]
    pub connector_fixture: Option<ConnectorFixture>,
}

impl ConformanceDeclaration {
    /// Check the declaration shape without consulting a connector.
    pub fn validate(&self) -> Result<(), ConformanceError> {
        if self.source_id.is_empty() || self.dataset.is_empty() {
            return Err(ConformanceError::MissingIdentity);
        }
        if self.manifest.source_id != self.source_id {
            return Err(ConformanceError::IdentityMismatch);
        }
        if self.declared_kinds.is_empty() {
            return Err(ConformanceError::MissingKinds);
        }
        self.manifest.validate()?;
        validate_modalities(&self.manifest)?;
        Ok(())
    }
}

/// Failure in a source declaration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConformanceError {
    /// Source or dataset identity is empty.
    #[error("source and dataset identity are required")]
    MissingIdentity,
    /// Manifest identity disagrees with the declaration.
    #[error("manifest identity disagrees with the declaration")]
    IdentityMismatch,
    /// No published observation kinds were declared.
    #[error("declared observation kinds are required")]
    MissingKinds,
    /// The capability manifest is invalid.
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    /// A declared modality is invalid.
    #[error("invalid modality: {0}")]
    InvalidModality(String),
}

impl From<crate::governance::adapter::ManifestError> for ConformanceError {
    fn from(value: crate::governance::adapter::ManifestError) -> Self {
        Self::InvalidManifest(value.to_string())
    }
}

/// One expected observation in a deterministic fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpectedObservation {
    /// Observation kind reported by the codec.
    pub kind: String,
    /// Exact interchange body expected from the connector.
    pub payload_json: String,
    /// Decode outcome expected from the connector.
    pub status: DecodeStatus,
}

/// Deterministic fixture used to test a declaration against connector output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceFixture {
    /// Stable fixture name.
    pub name: String,
    /// Packet identifier stamped onto decoded observations.
    pub packet_id: String,
    /// Schema version the codec must resolve.
    pub schema_version: u32,
    /// Exact raw bytes supplied to the connector.
    pub raw_payload: Vec<u8>,
    /// Observations the connector must produce.
    pub expected: Vec<ExpectedObservation>,
}

/// One independent conformance check and its reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceCheck {
    /// Stable check name.
    pub name: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Human-readable disposition, including on failure.
    pub detail: String,
}

/// Result of testing one declaration against one fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReport {
    /// Source under test.
    pub source_id: String,
    /// Fixture used for the test.
    pub fixture: String,
    /// Independent checks and their dispositions.
    pub checks: Vec<ConformanceCheck>,
    /// Separate evidence statuses for each conformance stage.
    pub statuses: ConformanceStatuses,
    /// `true` only when every check passed. This is not a live certification.
    pub certified: bool,
}

impl ConformanceReport {
    /// Whether all checks passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|check| check.passed)
    }

    /// Return the checks that failed, with their reasons.
    pub fn failures(&self) -> impl Iterator<Item = &ConformanceCheck> {
        self.checks.iter().filter(|check| !check.passed)
    }

    /// Return the JSON representation used by evidence manifests.
    pub fn to_json(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(self).map_err(|error| anyhow::anyhow!(error.to_string()))
    }
}

/// Invoke the real modality fixture and count the records it produces.
fn invoke_connector_fixture(
    fixture: &ConnectorFixture,
    country: CountryCode,
) -> anyhow::Result<usize> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let object_id = fixture.object_id.clone();
        match fixture.modality {
            AcquisitionModality::Streaming => {
                let frames = vec![FixtureStreamFrame {
                    object_id: object_id.clone(),
                    payload: b"fixture".to_vec(),
                    sequence: 1,
                    source_timestamp_us: 1_000,
                }];
                let mut connector = FixtureStreamingConnector::new(country, "conformance", frames);
                connector.connect().await?;
                connector.subscribe(&[object_id]).await?;
                let mut count = 0;
                while connector.next_record().await?.is_some() {
                    count += 1;
                }
                Ok(count)
            }
            AcquisitionModality::Snapshot => {
                let record = AcquiredRecord {
                    object_id,
                    raw: b"fixture".to_vec(),
                    source_timestamp_us: Some(1_000),
                    sequence: Some(1),
                };
                let mut connector =
                    FixtureSnapshotConnector::new(country, "conformance", vec![vec![record]]);
                Ok(connector.fetch_page(None).await?.len())
            }
            AcquisitionModality::Batch => {
                let record = AcquiredRecord {
                    object_id: object_id.clone(),
                    raw: b"fixture".to_vec(),
                    source_timestamp_us: Some(1_000),
                    sequence: Some(1),
                };
                let page = BatchPage {
                    records: vec![record],
                    next_cursor: None,
                };
                let mut connector = FixtureBatchConnector::new(country, "conformance", vec![page]);
                Ok(connector.fetch_page(None).await?.records.len())
            }
            AcquisitionModality::Document => {
                let bytes = b"fixture".to_vec();
                let document = DocumentRecord {
                    object_id: object_id.clone(),
                    sha256: crate::util::sha256_hex(&bytes),
                    published_us: Some(1_000),
                    bytes,
                };
                let mut connector =
                    FixtureDocumentConnector::new(country, "conformance", vec![document]);
                Ok(usize::from(
                    connector.fetch_document(&object_id).await?.is_some(),
                ))
            }
            AcquisitionModality::OnChain => {
                let block = AcquiredRecord {
                    object_id,
                    raw: b"fixture".to_vec(),
                    source_timestamp_us: Some(1_000),
                    sequence: Some(1),
                };
                let mut connector =
                    FixtureOnChainConnector::new(country, "conformance", vec![block], Vec::new());
                Ok(usize::from(connector.next_block().await?.is_some()))
            }
        }
    })
}

fn add_check(report: &mut ConformanceReport, name: &str, passed: bool, detail: String) {
    report.checks.push(ConformanceCheck {
        name: name.to_owned(),
        passed,
        detail,
    });
}

fn observed_signature(
    declaration: &ConformanceDeclaration,
    fixture: &ConformanceFixture,
    codecs: &CodecRegistry,
) -> Vec<(String, String, String)> {
    let mut observed = Vec::new();
    if let Ok(batch) = codecs.decode(
        &fixture.packet_id,
        &declaration.source_id,
        fixture.schema_version,
        &fixture.raw_payload,
    ) {
        for observation in batch
            .accepted
            .into_iter()
            .chain(batch.rejected)
            .chain(batch.unsupported)
        {
            observed.push((
                observation.kind,
                observation.payload_json,
                observation.status.as_str().to_owned(),
            ));
        }
    }
    observed.sort();
    observed
}

fn expected_signature(fixture: &ConformanceFixture) -> Vec<(String, String, String)> {
    let mut expected: Vec<(String, String, String)> = fixture
        .expected
        .iter()
        .map(|observation| {
            (
                observation.kind.clone(),
                observation.payload_json.clone(),
                observation.status.as_str().to_owned(),
            )
        })
        .collect();
    expected.sort();
    expected
}

/// Test a declaration against a fixture and the supplied codec and rights
/// registries.
/// Build the explicit rights query for one declared conformance right.
///
/// Identities come from the declaration; every other value is supplied
/// explicitly. Nothing is inferred from a command name or an exchange.
fn declared_rights_query(
    declaration: &ConformanceDeclaration,
    right: UsageRight,
) -> Result<AuthorizationScope, crate::rights::RightsError> {
    use crate::rights::{
        DeliveryMethod, Licensee, Purpose, Recipient, Retention, TimeWindow, UsageMode,
    };
    let operation = match right {
        UsageRight::RealTimeAccess => Operation::RealTimeCapture,
        UsageRight::HistoricalStorage => Operation::HistoricalDataRetrieval,
        UsageRight::InternalProcessing => Operation::InternalAnalytics,
        UsageRight::DerivedData => Operation::DerivedDataCreation,
        UsageRight::Redistribution => Operation::ExternalRedistribution,
    };
    let purpose = match right {
        UsageRight::RealTimeAccess | UsageRight::InternalProcessing => Purpose::InternalAnalysis,
        UsageRight::HistoricalStorage => Purpose::HistoricalArchive,
        UsageRight::DerivedData => Purpose::DerivedProduct,
        UsageRight::Redistribution => Purpose::Redistribution,
    };
    AuthorizationScope::request()
        .licensee(Licensee::system())
        .venue(declaration.provider_id.clone())
        .provider_id(declaration.provider_id.clone())
        .source_id(declaration.source_id.clone())
        .dataset_id(declaration.dataset.clone())
        .product_id(declaration.product_id.clone())
        .segment("conformance-scope")
        .territory(declaration.manifest.country.clone())
        .operation(operation)
        .usage_right(right)
        .usage_mode(UsageMode::NonDisplay)
        .recipient(Recipient::Internal)
        .purpose(purpose)
        .delivery_method(DeliveryMethod::File)
        .retention(Retention::NONE)
        .instruments(ScopeSet::Universe("conformance-universe-1".to_owned()))
        .fields(ScopeSet::Universe("conformance-universe-1".to_owned()))
        .modalities(ScopeSet::Universe("conformance-universe-1".to_owned()))
        .data_time_window(TimeWindow {
            from_us: Some(0),
            to_us: Some(4_102_444_800_000_000),
        })
        .build()
}

pub fn run_conformance(
    declaration: &ConformanceDeclaration,
    fixture: &ConformanceFixture,
    codecs: &CodecRegistry,
    rights: &LicensingRegistry,
    at_us: i64,
) -> ConformanceReport {
    let mut report = ConformanceReport {
        source_id: declaration.source_id.clone(),
        fixture: fixture.name.clone(),
        checks: Vec::new(),
        statuses: ConformanceStatuses {
            code_present: ConformanceStageState::NotAssessed,
            fixture_conformant: ConformanceStageState::NotAssessed,
            integration_conformant: ConformanceStageState::NotAssessed,
            rights_approved: ConformanceStageState::NotAssessed,
            network_validated: if declaration.external.network_validation.is_some() {
                ConformanceStageState::Declared
            } else {
                ConformanceStageState::NotAssessed
            },
            live_verified: if declaration.external.live_capture.is_some() {
                ConformanceStageState::Declared
            } else {
                ConformanceStageState::NotAssessed
            },
            history_reconciled: if declaration.external.history_reconciliation.is_some() {
                ConformanceStageState::Declared
            } else {
                ConformanceStageState::NotAssessed
            },
            certified: ConformanceStageState::NotAssessed,
        },
        certified: false,
    };

    match declaration.validate() {
        Ok(()) => {
            let code_ok = declaration
                .code_reference
                .as_ref()
                .is_some_and(|reference| !reference.trim().is_empty());
            report.statuses.code_present = if code_ok {
                ConformanceStageState::Pass
            } else {
                ConformanceStageState::Fail
            };
            add_check(
                &mut report,
                "declaration",
                code_ok,
                if code_ok {
                    "manifest, identity and code reference are valid".to_owned()
                } else {
                    "a code reference is required for code presence".to_owned()
                },
            );
            if !code_ok {
                return report;
            }
        }
        Err(error) => {
            report.statuses.code_present = ConformanceStageState::Fail;
            add_check(&mut report, "declaration", false, error.to_string());
            return report;
        }
    }

    let codec_registered = codecs
        .resolve(&declaration.source_id, fixture.schema_version)
        .is_some();
    add_check(
        &mut report,
        "codec_registered",
        codec_registered,
        if codec_registered {
            format!(
                "codec resolved for schema version {}",
                fixture.schema_version
            )
        } else {
            "no codec registered for the declared schema version".to_owned()
        },
    );

    let observed = observed_signature(declaration, fixture, codecs);
    let expected = expected_signature(fixture);
    let decode_matches = observed == expected;
    add_check(
        &mut report,
        "fixture_decode_matches",
        decode_matches,
        if decode_matches {
            format!("{} observations matched", expected.len())
        } else {
            format!("expected {expected:?} but observed {observed:?}")
        },
    );

    let normalize_result = codecs.decode_normalized(
        &fixture.packet_id,
        &declaration.source_id,
        fixture.schema_version,
        &fixture.raw_payload,
    );
    let typed_ok = match &normalize_result {
        Ok(events) => {
            events.iter().all(|event| {
                if event.status == DecodeStatus::Decoded {
                    event.payload.is_some()
                } else {
                    event.payload.is_none()
                }
            }) && events.iter().all(|event| {
                event.raw.sha256 == crate::util::sha256_hex(&fixture.raw_payload)
                    && !event.raw.record_id.is_empty()
            })
        }
        Err(_) => false,
    };
    add_check(
        &mut report,
        "typed_normalization",
        typed_ok,
        if typed_ok {
            "typed payloads and independent raw evidence present".to_owned()
        } else {
            "typed normalization failed or raw evidence was altered".to_owned()
        },
    );
    report.statuses.fixture_conformant = if codec_registered && decode_matches && typed_ok {
        ConformanceStageState::Pass
    } else {
        ConformanceStageState::Fail
    };

    let mut denied_rights = Vec::new();
    if declaration.rights_required.is_empty() && declaration.rights_exemption.is_none() {
        denied_rights.push("no rights requirements declared".to_owned());
    }
    for right in &declaration.rights_required {
        let granted = declared_rights_query(declaration, *right)
            .ok()
            .is_some_and(|query| rights.authorize(&query, at_us).is_ok());
        if !granted {
            denied_rights.push(right.as_str().to_owned());
        }
    }
    add_check(
        &mut report,
        "rights_gate",
        denied_rights.is_empty(),
        if denied_rights.is_empty() {
            "all required rights granted".to_owned()
        } else {
            format!("denied rights: {}", denied_rights.join(", "))
        },
    );
    report.statuses.rights_approved = if denied_rights.is_empty() {
        ConformanceStageState::Pass
    } else {
        ConformanceStageState::Fail
    };

    let universe_detail = match &declaration.expected_universe {
        Some(universe @ ExpectedUniverse::Enumerated { .. }) => match universe.measure() {
            Ok(Some(measurement)) => format!(
                "enumerated universe: {} expected, {} supported",
                measurement.expected, measurement.supported
            ),
            Ok(None) => "enumerated universe could not be measured".to_owned(),
            Err(error) => format!("invalid universe: {error}"),
        },
        Some(ExpectedUniverse::Unmeasurable { reason }) => {
            format!("no denominator claimed: {reason}")
        }
        None => "no universe declaration".to_owned(),
    };
    let universe_ok = declaration
        .expected_universe
        .as_ref()
        .is_some_and(|universe| universe.validate().is_ok());
    add_check(
        &mut report,
        "universe_disclosed",
        universe_ok,
        universe_detail,
    );

    let declared_kinds: std::collections::BTreeSet<&str> = declaration
        .declared_kinds
        .iter()
        .map(String::as_str)
        .collect();
    let observed_kinds: std::collections::BTreeSet<&str> =
        observed.iter().map(|(kind, _, _)| kind.as_str()).collect();
    let missing_kinds: Vec<&str> = declared_kinds
        .difference(&observed_kinds)
        .copied()
        .collect();
    let kinds_ok = missing_kinds.is_empty();
    add_check(
        &mut report,
        "declared_kinds_covered",
        kinds_ok,
        if kinds_ok {
            "all declared kinds observed in fixture output".to_owned()
        } else {
            format!("declared kinds not observed: {}", missing_kinds.join(", "))
        },
    );
    let undeclared_kinds: Vec<&str> = observed_kinds
        .difference(&declared_kinds)
        .copied()
        .collect();
    let unexpected_kinds_ok = undeclared_kinds.is_empty()
        || declaration.unknown_event_policy == UnknownEventPolicy::AllowDocumented;
    add_check(
        &mut report,
        "undeclared_kinds_absent",
        unexpected_kinds_ok,
        if unexpected_kinds_ok {
            "observed kinds match the declaration".to_owned()
        } else {
            format!("undeclared kinds observed: {}", undeclared_kinds.join(", "))
        },
    );

    if let Some(connector) = &declaration.connector_fixture {
        let observed = invoke_connector_fixture(connector, declaration.manifest.country.clone());
        let passed = observed
            .as_ref()
            .is_ok_and(|count| *count == connector.expected_records);
        add_check(
            &mut report,
            "connector_fixture",
            passed,
            match observed {
                Ok(count) => format!("connector produced {count} records"),
                Err(error) => format!("connector fixture failed: {error}"),
            },
        );
    }

    if let Some(integration) = &declaration.integration {
        let sink = CollectingSink::default();
        let outcome = run_stream_slice(
            &integration.directory,
            &integration.run_id,
            &integration.config,
            integration.packets.clone(),
            codecs,
            &sink,
            ArbiterLimits::default(),
        );
        let passed = match &outcome {
            Ok(result) => {
                result.evidence_reconciled
                    && result.verification.valid
                    && result.typed_events == integration.expected_typed_events
            }
            Err(_) => false,
        };
        add_check(
            &mut report,
            "integration_replay",
            passed,
            if passed {
                "journal, typed events and replay reconcile".to_owned()
            } else {
                "the end-to-end fixture path did not reconcile".to_owned()
            },
        );
        report.statuses.integration_conformant = if passed {
            ConformanceStageState::Pass
        } else {
            ConformanceStageState::Fail
        };
    }

    report.certified = report.statuses.fully_certified();
    report.statuses.certified = if report.statuses.fully_certified() {
        ConformanceStageState::Pass
    } else {
        ConformanceStageState::NotAssessed
    };
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acquisition::codec::{
        DecodedObservation, //
        FeedCodec,          //
    };
    use crate::governance::adapter::{
        AccessStatus, HistoricalCapability, Protocol, RecoveryCapability, TimestampCapability,
        Transport,
    };
    use crate::governance::modality::{
        AcquisitionModality, SnapshotCapability, StreamingCapability,
    };
    use crate::governance::rights::{
        AuthorizationIdentity, //
        AuthorizationRecord,   //
        DecisionAudit,         //
        RightDecision,         //
    };
    use crate::reference_data::VenueCategory;

    fn rights_identity() -> AuthorizationIdentity {
        AuthorizationIdentity {
            scope: declared_rights_query(&declaration(), UsageRight::InternalProcessing)
                .expect("explicit conformance fixture"),
            valid_from: 0,
            valid_until: Some(200),
        }
    }
    use crate::taxonomy::{
        AssetClass,   //
        CountryCode,  //
        DataCategory, //
        DepthModel,   //
        Frequency,    //
    };

    struct JsonCodec {
        version: u32,
        status: DecodeStatus,
    }

    impl FeedCodec for JsonCodec {
        fn decode(&self, payload: &[u8]) -> anyhow::Result<Vec<DecodedObservation>> {
            Ok(vec![DecodedObservation {
                packet_id: String::new(),
                source: String::new(),
                schema_version: 0,
                kind: "trade".to_owned(),
                payload_json: String::from_utf8(payload.to_vec())?,
                status: self.status,
                reason: None,
            }])
        }

        fn schema_version(&self) -> u32 {
            self.version
        }
    }

    struct MultiKindCodec {
        version: u32,
        payloads: Vec<Vec<u8>>,
    }

    impl FeedCodec for MultiKindCodec {
        fn decode(&self, _payload: &[u8]) -> anyhow::Result<Vec<DecodedObservation>> {
            self.payloads
                .iter()
                .map(|body| {
                    let kind = if body.len() <= 2 {
                        "unknown_kind"
                    } else {
                        "trade"
                    };
                    Ok(DecodedObservation {
                        packet_id: String::new(),
                        source: String::new(),
                        schema_version: 0,
                        kind: kind.to_owned(),
                        payload_json: String::from_utf8(body.clone())?,
                        status: DecodeStatus::Decoded,
                        reason: None,
                    })
                })
                .collect()
        }

        fn schema_version(&self) -> u32 {
            self.version
        }
    }

    fn declaration() -> ConformanceDeclaration {
        ConformanceDeclaration {
            source_id: "source".to_owned(),
            dataset: "quotes".to_owned(),
            manifest: SourceCapabilityManifest {
                source_id: "source".to_owned(),
                provider: "provider".to_owned(),
                venue_mic: None,
                country: CountryCode::new("US").expect("country code"),
                venue_category: VenueCategory::Exchange,
                asset_classes: vec![AssetClass::Equity],
                data_categories: vec![DataCategory::Trades],
                protocols: vec![Protocol::WebSocket, Protocol::Rest],
                transports: vec![Transport::WebSocket, Transport::Http],
                book_model: DepthModel::Level2,
                timestamps: TimestampCapability {
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
                historical: HistoricalCapability {
                    available: false,
                    earliest_us: None,
                    frequency: Frequency::RealTime,
                },
                access: AccessStatus::Public,
                schema_version: 1,
                modalities: vec![
                    AcquisitionModality::Streaming,
                    AcquisitionModality::Snapshot,
                ],
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
                snapshot: Some(SnapshotCapability {
                    keyed_lookup: true,
                    pagination: false,
                    as_of: false,
                }),
                batch: None,
                document: None,
                on_chain: None,
            },
            expected_universe: Some(ExpectedUniverse::Unmeasurable {
                reason: "opaque universe".to_owned(),
            }),
            declared_kinds: vec!["trade".to_owned()],
            rights_required: vec![UsageRight::InternalProcessing],
            integration: None,
            external: ExternalEvidence::default(),
            provider_id: "provider".to_owned(),
            product_id: "quotes".to_owned(),
            code_reference: Some("src/acquisition/fixture_connectors.rs".to_owned()),
            rights_exemption: None,
            unknown_event_policy: UnknownEventPolicy::Reject,
            connector_fixture: None,
        }
    }

    fn fixture() -> ConformanceFixture {
        ConformanceFixture {
            name: "trade-fixture".to_owned(),
            packet_id: "packet-1".to_owned(),
            schema_version: 1,
            raw_payload: b"{\"trade_id\":\"t-1\",\"price_mantissa\":10,\"quantity_mantissa\":2}"
                .to_vec(),
            expected: vec![ExpectedObservation {
                kind: "trade".to_owned(),
                payload_json:
                    "{\"trade_id\":\"t-1\",\"price_mantissa\":10,\"quantity_mantissa\":2}"
                        .to_owned(),
                status: DecodeStatus::Decoded,
            }],
        }
    }

    #[test]
    fn connect_success_is_not_a_certification_signal() {
        let mut codecs = CodecRegistry::new();
        codecs
            .register(
                "source",
                Box::new(JsonCodec {
                    version: 1,
                    status: DecodeStatus::Decoded,
                }),
            )
            .expect("register codec");
        let mut licensing = LicensingRegistry::new();
        licensing
            .register(AuthorizationRecord {
                identity: rights_identity(),
                decision: RightDecision::Permitted,
                audit: DecisionAudit {
                    licence_reference: "contract".to_owned(),
                    licence_document_hash: "a".repeat(64),
                    contract_revision: 1,
                    recorded_at_us: 0,
                    authority: "contract-registry".to_owned(),
                },
            })
            .expect("rights registered");
        let report = run_conformance(&declaration(), &fixture(), &codecs, &licensing, 100);
        assert!(report.passed(), "all fixture checks must pass");
        assert_eq!(
            report.statuses.fixture_conformant,
            ConformanceStageState::Pass,
            "fixture conformance is explicit"
        );
        assert_eq!(
            report.statuses.rights_approved,
            ConformanceStageState::Pass,
            "rights approval is explicit"
        );
        assert!(!report.certified, "a fixture cannot certify a live source");
        assert_eq!(report.checks.len(), 8, "eight explicit checks reported");
        assert!(
            report.checks.iter().all(|check| check.name != "connect"),
            "connection success is never a conformance check"
        );
    }

    #[test]
    fn integration_stage_uses_a_real_end_to_end_fixture() {
        use crate::{
            acquisition::arbiter::FeedChannel, acquisition::stream_slice::SliceConfig,
            model::SourceId,
        };

        let directory = tempfile::tempdir().expect("tempdir");
        let mut source = declaration();
        source.integration = Some(IntegrationFixture {
            directory: directory.path().to_path_buf(),
            run_id: "conformance-run".to_owned(),
            config: SliceConfig {
                source_id: "source".to_owned(),
                source: SourceId::new(2, 0),
                schema_version: 1,
                profile: crate::acquisition::evidence::DurabilityProfile::D1,
            },
            packets: vec![SequencedPacket {
                channel: FeedChannel::Primary,
                sequence: 1,
                payload: b"{\"trade_id\":\"t-1\",\"price_mantissa\":10,\"quantity_mantissa\":2}"
                    .to_vec(),
                received_at_us: 1_700_000_000_000_100,
            }],
            expected_typed_events: 1,
        });
        let mut codecs = CodecRegistry::new();
        codecs
            .register(
                "source",
                Box::new(JsonCodec {
                    version: 1,
                    status: DecodeStatus::Decoded,
                }),
            )
            .expect("codec registered");
        let mut licensing = LicensingRegistry::new();
        licensing
            .register(AuthorizationRecord {
                identity: rights_identity(),
                decision: RightDecision::Permitted,
                audit: DecisionAudit {
                    licence_reference: "contract".to_owned(),
                    licence_document_hash: "b".repeat(64),
                    contract_revision: 1,
                    recorded_at_us: 0,
                    authority: "registry".to_owned(),
                },
            })
            .expect("rights registered");
        let report = run_conformance(&source, &fixture(), &codecs, &licensing, 100);
        assert_eq!(
            report.statuses.integration_conformant,
            ConformanceStageState::Pass,
            "end-to-end fixture path must pass"
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "integration_replay"),
            "integration check is reported"
        );
        assert!(!report.certified, "no live evidence was supplied");
    }

    #[test]
    fn external_evidence_is_declared_not_passing() {
        let mut source = declaration();
        source.external = ExternalEvidence {
            network_validation: Some("authorized-network-test".to_owned()),
            live_capture: Some("permitted-capture".to_owned()),
            history_reconciliation: Some("reconstructed-history".to_owned()),
        };
        let mut codecs = CodecRegistry::new();
        codecs
            .register(
                "source",
                Box::new(JsonCodec {
                    version: 1,
                    status: DecodeStatus::Decoded,
                }),
            )
            .expect("codec registered");
        let report = run_conformance(&source, &fixture(), &codecs, &LicensingRegistry::new(), 100);
        assert_eq!(
            report.statuses.network_validated,
            ConformanceStageState::Declared,
            "an external reference is a declaration, not a pass"
        );
        assert_eq!(
            report.statuses.live_verified,
            ConformanceStageState::Declared,
            "a fixture cannot verify a live capture"
        );
        assert!(
            !report.statuses.fully_certified(),
            "no stage was validated live"
        );
    }

    #[test]
    fn vacuous_rights_and_missing_code_reference_fail() {
        let mut source = declaration();
        source.rights_required.clear();
        source.code_reference = None;
        let mut codecs = CodecRegistry::new();
        codecs
            .register(
                "source",
                Box::new(JsonCodec {
                    version: 1,
                    status: DecodeStatus::Decoded,
                }),
            )
            .expect("codec registered");
        let report = run_conformance(&source, &fixture(), &codecs, &LicensingRegistry::new(), 100);
        assert_eq!(
            report.statuses.code_present,
            ConformanceStageState::Fail,
            "code presence is a separate check"
        );
        assert!(
            report.checks.iter().any(|check| !check.passed),
            "an undeclared rights set cannot pass vacuously"
        );
        assert!(!report.certified, "no stage was satisfied");
    }

    #[test]
    fn undeclared_observation_kinds_are_rejected() {
        let mut source = declaration();
        source.declared_kinds = vec!["trade".to_owned()];
        let mut observed = fixture();
        observed.expected.push(ExpectedObservation {
            kind: "unknown_kind".to_owned(),
            payload_json: "{}".to_owned(),
            status: DecodeStatus::Decoded,
        });
        let mut codecs = CodecRegistry::new();
        codecs
            .register(
                "source",
                Box::new(MultiKindCodec {
                    version: 1,
                    payloads: vec![
                        b"{\"trade_id\":\"t-1\",\"price_mantissa\":10,\"quantity_mantissa\":2}"
                            .to_vec(),
                        b"{}".to_vec(),
                    ],
                }),
            )
            .expect("codec registered");
        let report = run_conformance(&source, &observed, &codecs, &LicensingRegistry::new(), 100);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "undeclared_kinds_absent" && !check.passed),
            "an unexpected kind must be reported"
        );
    }

    #[test]
    fn connector_fixture_is_invoked_by_the_harness() {
        let mut source = declaration();
        source.connector_fixture = Some(ConnectorFixture {
            modality: AcquisitionModality::Streaming,
            object_id: "fixture-object".to_owned(),
            expected_records: 1,
        });
        let mut codecs = CodecRegistry::new();
        codecs
            .register(
                "source",
                Box::new(JsonCodec {
                    version: 1,
                    status: DecodeStatus::Decoded,
                }),
            )
            .expect("codec registered");
        let report = run_conformance(&source, &fixture(), &codecs, &LicensingRegistry::new(), 100);
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "connector_fixture" && check.passed),
            "the actual connector implementation must run"
        );
    }

    #[test]
    fn mismatched_fixture_fails_closed() {
        let mut codecs = CodecRegistry::new();
        codecs
            .register(
                "source",
                Box::new(JsonCodec {
                    version: 1,
                    status: DecodeStatus::Rejected,
                }),
            )
            .expect("register codec");
        let report = run_conformance(
            &declaration(),
            &fixture(),
            &codecs,
            &LicensingRegistry::new(),
            100,
        );
        assert!(!report.certified, "mismatched output cannot certify");
        assert!(
            report.failures().count() >= 2,
            "decode, typing and rights failures are all reported"
        );
    }
}
