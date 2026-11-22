// SPDX-License-Identifier: Apache-2.0
//! Independent source conformance harness.
//!
//! A source is certified by comparing its declaration against deterministic
//! fixtures and actual connector output. A successful `connect()` is never a
//! certification signal. Every check is explicit, fail-closed, and reported
//! with a reason so an unmet condition cannot hide behind an ordinal status.

use serde::Deserialize;
use serde::Serialize;

use crate::{
    acquisition::codec::{CodecRegistry, DecodeStatus},
    governance::{
        adapter::SourceCapabilityManifest,
        coverage_certification::ExpectedUniverse,
        modality::validate_modalities,
        rights::{LicensingRegistry, UsageRight},
    },
};

/// What a source claims before any conformance evidence is examined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceDeclaration {
    /// Source identity used by the codec registry.
    pub source_id: String,
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
    /// `true` only when every check passed.
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
        certified: false,
    };

    match declaration.validate() {
        Ok(()) => add_check(
            &mut report,
            "declaration",
            true,
            "manifest, modalities and identity are valid".to_owned(),
        ),
        Err(error) => {
            add_check(&mut report, "declaration", false, error.to_string());
            report.certified = false;
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
            }) && events
                .iter()
                .all(|event| event.raw.bytes == fixture.raw_payload && !event.raw.sha256.is_empty())
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

    let mut denied_rights = Vec::new();
    let territory = declaration.manifest.country.clone();
    for right in &declaration.rights_required {
        if rights
            .authorize(&declaration.dataset, &territory, *right, at_us)
            .is_err()
        {
            denied_rights.push(right.as_str());
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

    let universe_detail = match &declaration.expected_universe {
        Some(ExpectedUniverse::Enumerated { .. }) => match declaration
            .expected_universe
            .as_ref()
            .and_then(ExpectedUniverse::measure)
        {
            Some(measurement) => format!(
                "enumerated universe: {} expected, {} supported",
                measurement.expected, measurement.supported
            ),
            None => "enumerated universe could not be measured".to_owned(),
        },
        Some(ExpectedUniverse::Unmeasurable { reason }) => {
            format!("no denominator claimed: {reason}")
        }
        None => "no universe declaration".to_owned(),
    };
    let universe_ok = declaration.expected_universe.is_some();
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

    report.certified = report.passed();
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
    use crate::reference_data::VenueCategory;
    use crate::taxonomy::{
        AssetClass,   //
        CountryCode,  //
        DataCategory, //
        DepthModel,   //
        Frequency,    //
    };
    use std::collections::BTreeMap;

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
        licensing.register(crate::governance::rights::LicensingRecord {
            provider: "provider".to_owned(),
            dataset: "quotes".to_owned(),
            territory: CountryCode::new("US").expect("country code"),
            rights: BTreeMap::from([(
                UsageRight::InternalProcessing,
                crate::governance::rights::RightDecision::Permitted,
            )]),
            valid_until_us: Some(200),
            audit_required: false,
            reference: "contract".to_owned(),
        });
        let report = run_conformance(&declaration(), &fixture(), &codecs, &licensing, 100);
        assert!(report.certified, "all evidence checks must pass");
        assert_eq!(report.checks.len(), 7, "seven explicit checks reported");
        assert!(
            report.checks.iter().all(|check| check.name != "connect"),
            "connection success is never a conformance check"
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
