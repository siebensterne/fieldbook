//! Coverage certification for global sources, markets and instruments.
//!
//! A coverage record discloses what a source provides. Missing data
//! is never represented as a zero value or as full coverage.
//!
//! Certification is not one ordinal ladder. Discovery, implementation,
//! technical validation, rights, operations, history, quality and
//! certification are separate dimensions, so a live feed without history, or
//! a licensed dataset awaiting validation, cannot hide an unmet condition.

use std::collections::{
    BTreeMap, //
    BTreeSet, //
};

use serde::Deserialize;
use serde::Serialize;

use crate::{
    quality::QualityReport,
    rights::{LicensingRegistry, UsageRight},
    taxonomy::{AssetClass, CountryCode, DataCategory, DepthModel, Frequency},
};

/// Legacy ordinal view of source maturity.
///
/// Retained for compatibility with existing reports. It must not be used as a
/// certification decision: use [`CoverageDimensions`] and the computed
/// [`CoverageRecord::certification`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Discovered,
    ConnectorImplemented,
    TechnicallyValidated,
    Licensed,
    Live,
    HistoricallyPopulated,
    Reconciled,
    Certified,
}

impl CoverageStatus {
    /// Return the stable contract string for this coverage status.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::ConnectorImplemented => "connector_implemented",
            Self::TechnicallyValidated => "technically_validated",
            Self::Licensed => "licensed",
            Self::Live => "live",
            Self::HistoricallyPopulated => "historically_populated",
            Self::Reconciled => "reconciled",
            Self::Certified => "certified",
        }
    }

    /// Return the ordinal rank of this status.
    pub const fn rank(self) -> u8 {
        match self {
            Self::Discovered => 0,
            Self::ConnectorImplemented => 1,
            Self::TechnicallyValidated => 2,
            Self::Licensed => 3,
            Self::Live => 4,
            Self::HistoricallyPopulated => 5,
            Self::Reconciled => 6,
            Self::Certified => 7,
        }
    }
}

/// Whether a source or dataset has been discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryState {
    Unknown,
    Discovered,
}

impl DiscoveryState {
    /// Return the stable contract string for this state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Discovered => "discovered",
        }
    }
}

/// Whether a connector exists for the declared source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationState {
    Absent,
    Implemented,
}

impl ImplementationState {
    /// Return the stable contract string for this state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Implemented => "implemented",
        }
    }
}

/// Result of technical conformance testing against fixtures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalState {
    Untested,
    Validated,
    Failed,
}

impl TechnicalState {
    /// Return the stable contract string for this state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Untested => "untested",
            Self::Validated => "validated",
            Self::Failed => "failed",
        }
    }
}

/// Contractual permission state for the dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RightsState {
    Unknown,
    Conditional,
    Permitted,
    Prohibited,
    Expired,
}

impl RightsState {
    /// Return the stable contract string for this state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Conditional => "conditional",
            Self::Permitted => "permitted",
            Self::Prohibited => "prohibited",
            Self::Expired => "expired",
        }
    }
}

/// Current operational state of the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationsState {
    Offline,
    Live,
    Degraded,
    Stopped,
}

impl OperationsState {
    /// Return the stable contract string for this state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Live => "live",
            Self::Degraded => "degraded",
            Self::Stopped => "stopped",
        }
    }
}

/// Completeness of retained history for the dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryState {
    None,
    Partial,
    Verified,
}

impl HistoryState {
    /// Return the stable contract string for this state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Partial => "partial",
            Self::Verified => "verified",
        }
    }
}

/// Quality verification state for the dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageQualityState {
    Untested,
    Passing,
    Failing,
}

impl CoverageQualityState {
    /// Return the stable contract string for this state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Untested => "untested",
            Self::Passing => "passing",
            Self::Failing => "failing",
        }
    }
}

/// Certification state computed from the applicable requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificationState {
    NotCertified,
    Certified,
    Revoked,
}

impl CertificationState {
    /// Return the stable contract string for this state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotCertified => "not_certified",
            Self::Certified => "certified",
            Self::Revoked => "revoked",
        }
    }
}

/// Independent coverage dimensions for one dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageDimensions {
    pub discovery: DiscoveryState,
    pub implementation: ImplementationState,
    pub technical: TechnicalState,
    pub rights: RightsState,
    pub operations: OperationsState,
    pub history: HistoryState,
    pub quality: CoverageQualityState,
    /// Explicit revocation overrides the computed state.
    pub certification: CertificationState,
}

impl Default for CoverageDimensions {
    fn default() -> Self {
        Self {
            discovery: DiscoveryState::Unknown,
            implementation: ImplementationState::Absent,
            technical: TechnicalState::Untested,
            rights: RightsState::Unknown,
            operations: OperationsState::Offline,
            history: HistoryState::None,
            quality: CoverageQualityState::Untested,
            certification: CertificationState::NotCertified,
        }
    }
}

impl CoverageDimensions {
    /// Whether every non-operational requirement is satisfied.
    #[must_use]
    pub fn requirements_met(&self) -> bool {
        self.discovery == DiscoveryState::Discovered
            && self.implementation == ImplementationState::Implemented
            && self.technical == TechnicalState::Validated
            && self.rights == RightsState::Permitted
            && self.history == HistoryState::Verified
            && self.quality == CoverageQualityState::Passing
    }

    /// Certification excluding the real-time operations requirement.
    #[must_use]
    pub fn derived_certification(&self) -> CertificationState {
        if self.certification == CertificationState::Revoked {
            return CertificationState::Revoked;
        }
        if self.requirements_met() {
            CertificationState::Certified
        } else {
            CertificationState::NotCertified
        }
    }
}

/// Full coverage identity. Every dimension is explicit; an unknown value is
/// not silently treated as full coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageScope {
    pub country: CountryCode,
    pub asset_class: AssetClass,
    pub category: DataCategory,
    pub depth: DepthModel,
    /// Venue or market identifier, when applicable.
    #[serde(default)]
    pub venue: Option<String>,
    /// Provider or source identifier.
    #[serde(default)]
    pub source: Option<String>,
    /// Data product identifier.
    #[serde(default)]
    pub product: Option<String>,
    /// Asset identifier.
    #[serde(default)]
    pub asset: Option<String>,
    /// Instrument identifier, when the record is instrument-level.
    #[serde(default)]
    pub instrument: Option<String>,
    /// Delivery frequency.
    pub frequency: Frequency,
    /// History range descriptor.
    #[serde(default)]
    pub history: Option<String>,
    /// Rights descriptor.
    #[serde(default)]
    pub rights: Option<String>,
}

/// A measured universe, or an explicit declaration that no denominator exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpectedUniverse {
    /// Enumerated expected and supported object sets.
    Enumerated {
        /// Objects the source is expected to publish.
        expected: BTreeSet<String>,
        /// Objects Fieldbook supports.
        supported: BTreeSet<String>,
    },
    /// No complete published universe exists; no denominator is invented.
    Unmeasurable {
        /// Why a denominator cannot be measured.
        reason: String,
    },
}

/// Coverage measurement for an enumerated universe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniverseMeasurement {
    /// Number of expected objects.
    pub expected: usize,
    /// Number of supported objects.
    pub supported: usize,
    /// Supported objects per thousand expected objects, capped at `1_000`.
    pub supported_per_mille: u32,
}

impl ExpectedUniverse {
    /// Measure an enumerated universe, or return `None` when it is unmeasurable.
    #[must_use]
    pub fn measure(&self) -> Option<UniverseMeasurement> {
        match self {
            Self::Enumerated {
                expected,
                supported,
            } => {
                let supported_per_mille = if expected.is_empty() {
                    0
                } else {
                    (supported.len() * 1_000 / expected.len()).min(1_000) as u32
                };
                Some(UniverseMeasurement {
                    expected: expected.len(),
                    supported: supported.len(),
                    supported_per_mille,
                })
            }
            Self::Unmeasurable { .. } => None,
        }
    }
}

/// Public, independently measurable coverage record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRecord {
    pub source_id: String,
    pub dataset: String,
    pub scope: CoverageScope,
    /// Legacy ordinal view. Certification is computed from `dimensions`.
    pub status: CoverageStatus,
    /// Independent coverage dimensions.
    #[serde(default)]
    pub dimensions: CoverageDimensions,
    /// Expected universe, when a denominator can be defined.
    #[serde(default)]
    pub expected_universe: Option<ExpectedUniverse>,
    pub history_start_us: Option<i64>,
    pub history_end_us: Option<i64>,
    pub real_time: bool,
    pub known_gaps: Vec<String>,
    pub evidence: Vec<String>,
}

impl CoverageRecord {
    /// Compute certification from applicable requirements.
    #[must_use]
    pub fn certification(&self) -> CertificationState {
        if self.dimensions.certification == CertificationState::Revoked {
            return CertificationState::Revoked;
        }
        let operations_satisfied = !self.real_time
            || matches!(
                self.dimensions.operations,
                OperationsState::Live | OperationsState::Degraded
            );
        if self.dimensions.requirements_met() && operations_satisfied {
            CertificationState::Certified
        } else {
            CertificationState::NotCertified
        }
    }

    /// Whether this record meets the structural requirements for certification.
    #[must_use]
    pub fn certifiable(&self) -> bool {
        self.certification() == CertificationState::Certified
            && self.known_gaps.is_empty()
            && !self.evidence.is_empty()
            && self.history_start_us.is_some()
    }

    /// Measured expected universe, absent for opaque markets.
    #[must_use]
    pub fn universe_measurement(&self) -> Option<UniverseMeasurement> {
        self.expected_universe
            .as_ref()
            .and_then(ExpectedUniverse::measure)
    }
}

/// A country-level market coverage dossier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountryDossier {
    pub country: CountryCode,
    pub official_exchange_registry: Option<String>,
    pub venues: Vec<String>,
    pub regulators: Vec<String>,
    pub economic_sources: Vec<String>,
    pub market_calendar: Option<String>,
    pub data_residency_restrictions: Vec<String>,
    #[serde(default)]
    pub central_banks: Vec<String>,
    #[serde(default)]
    pub debt_agencies: Vec<String>,
    #[serde(default)]
    pub statistical_agencies: Vec<String>,
    #[serde(default)]
    pub filing_authorities: Vec<String>,
    #[serde(default)]
    pub currencies: Vec<String>,
    #[serde(default)]
    pub local_identifiers: Vec<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub authorized_providers: Vec<String>,
}

/// Certification failure for one coverage record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertificationError {
    /// The source lacks a required maturity status.
    #[error("coverage status {status:?} is below certified for {source_id}")]
    InsufficientStatus {
        source_id: String,
        status: CoverageStatus,
    },
    /// An independent coverage dimension is unmet.
    #[error("coverage dimensions are insufficient for {0}")]
    InsufficientDimensions(String),
    /// Rights or quality evidence is missing.
    #[error("certification prerequisite missing for {source_id}: {requirement}")]
    MissingPrerequisite {
        source_id: String,
        requirement: &'static str,
    },
}

/// Promote a record only when every applicable prerequisite is present.
pub fn certify(
    record: &CoverageRecord,
    rights: &LicensingRegistry,
    quality: &QualityReport,
    at_us: i64,
) -> Result<CoverageRecord, CertificationError> {
    if record.status < CoverageStatus::TechnicallyValidated {
        return Err(CertificationError::InsufficientStatus {
            source_id: record.source_id.clone(),
            status: record.status,
        });
    }
    if !record.dimensions.requirements_met() {
        return Err(CertificationError::InsufficientDimensions(
            record.source_id.clone(),
        ));
    }
    if !record.known_gaps.is_empty() {
        return Err(CertificationError::MissingPrerequisite {
            source_id: record.source_id.clone(),
            requirement: "known_gaps",
        });
    }
    rights
        .authorize(
            &record.dataset,
            &record.scope.country,
            UsageRight::InternalProcessing,
            at_us,
        )
        .map_err(|_| CertificationError::MissingPrerequisite {
            source_id: record.source_id.clone(),
            requirement: "licensing",
        })?;
    if !quality.valid() {
        return Err(CertificationError::MissingPrerequisite {
            source_id: record.source_id.clone(),
            requirement: "reconciliation",
        });
    }
    let mut promoted = record.clone();
    promoted.status = CoverageStatus::Certified;
    promoted.dimensions.certification = CertificationState::Certified;
    Ok(promoted)
}

/// Aggregate matrix of coverage records by source.
#[derive(Debug, Default)]
pub struct CoverageMatrix {
    records: BTreeMap<String, CoverageRecord>,
}

impl CoverageMatrix {
    /// Create an empty matrix.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a coverage record under its source and dataset key.
    pub fn insert(&mut self, record: CoverageRecord) {
        let key = format!("{}:{}", record.source_id, record.dataset);
        self.records.insert(key, record);
    }

    /// Return the number of records at or above a status threshold.
    pub fn count_at_least(&self, minimum: CoverageStatus) -> usize {
        self.records
            .values()
            .filter(|record| record.status >= minimum)
            .count()
    }

    /// Return all records in a given certification state.
    pub fn by_certification(&self, state: CertificationState) -> Vec<&CoverageRecord> {
        self.records
            .values()
            .filter(|record| record.certification() == state)
            .collect()
    }

    /// Return all certified records.
    pub fn certified(&self) -> Vec<&CoverageRecord> {
        self.records
            .values()
            .filter(|record| record.certifiable())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        quality::Reconciliation,
        rights::{LicensingRecord, RightDecision},
    };
    use std::collections::BTreeMap;

    fn scope() -> CoverageScope {
        CoverageScope {
            country: CountryCode::new("US").expect("country code"),
            asset_class: AssetClass::Equity,
            category: DataCategory::Level2Book,
            depth: DepthModel::Level2,
            venue: Some("XABC".to_owned()),
            source: Some("source".to_owned()),
            product: Some("quotes".to_owned()),
            asset: Some("equity".to_owned()),
            instrument: None,
            frequency: Frequency::RealTime,
            history: Some("2020-01-01..".to_owned()),
            rights: Some("internal".to_owned()),
        }
    }

    fn dimensions() -> CoverageDimensions {
        CoverageDimensions {
            discovery: DiscoveryState::Discovered,
            implementation: ImplementationState::Implemented,
            technical: TechnicalState::Validated,
            rights: RightsState::Permitted,
            operations: OperationsState::Live,
            history: HistoryState::Verified,
            quality: CoverageQualityState::Passing,
            certification: CertificationState::NotCertified,
        }
    }

    fn record() -> CoverageRecord {
        CoverageRecord {
            source_id: "source".to_owned(),
            dataset: "quotes".to_owned(),
            scope: scope(),
            status: CoverageStatus::TechnicallyValidated,
            dimensions: dimensions(),
            expected_universe: None,
            history_start_us: Some(0),
            history_end_us: Some(100),
            real_time: true,
            known_gaps: Vec::new(),
            evidence: vec!["fixture".to_owned()],
        }
    }

    fn rights() -> LicensingRegistry {
        let mut decision = BTreeMap::new();
        decision.insert(UsageRight::InternalProcessing, RightDecision::Permitted);
        let mut registry = LicensingRegistry::new();
        registry.register(LicensingRecord {
            provider: "example".to_owned(),
            dataset: "quotes".to_owned(),
            territory: CountryCode::new("US").expect("country code"),
            rights: decision,
            valid_until_us: Some(200),
            audit_required: false,
            reference: "contract".to_owned(),
        });
        registry
    }

    fn quality() -> QualityReport {
        QualityReport {
            source_id: "source".to_owned(),
            dataset: "quotes".to_owned(),
            window_start_us: 0,
            window_end_us: 100,
            states: BTreeMap::new(),
            reasons: BTreeMap::new(),
            reconciliation: Reconciliation {
                expected: 1,
                observed: 1,
                missing: 0,
                extra: 0,
                duplicated: 0,
                rejected: 0,
                quarantined: 0,
            },
        }
    }

    #[test]
    fn certification_requires_all_prerequisites() {
        let certified = certify(&record(), &rights(), &quality(), 50).expect("certification");
        assert_eq!(
            certified.status,
            CoverageStatus::Certified,
            "prerequisites must promote status"
        );
        assert!(certified.certifiable(), "promoted record must certify");

        let mut with_gap = record();
        with_gap.known_gaps.push("missing auction data".to_owned());
        assert!(
            certify(&with_gap, &rights(), &quality(), 50).is_err(),
            "known gaps must block certification"
        );
    }

    #[test]
    fn matrix_counts_only_declared_status() {
        let mut matrix = CoverageMatrix::new();
        matrix.insert(record());
        assert_eq!(
            matrix.count_at_least(CoverageStatus::Certified),
            0,
            "uncertified records must not count"
        );
        assert_eq!(
            matrix.count_at_least(CoverageStatus::TechnicallyValidated),
            1,
            "validated records must count"
        );
    }

    #[test]
    fn ordinal_status_cannot_conceal_unmet_dimension() {
        let mut source = record();
        source.status = CoverageStatus::Certified;
        source.dimensions.rights = RightsState::Conditional;
        assert_eq!(
            source.certification(),
            CertificationState::NotCertified,
            "a declared status cannot override an unmet right"
        );
        assert!(
            !source.certifiable(),
            "conditional rights block certification"
        );
        assert!(
            certify(&source, &rights(), &quality(), 50).is_err(),
            "certification must reject unmet dimensions"
        );
    }

    #[test]
    fn historical_dataset_does_not_require_live_operations() {
        let mut source = record();
        source.real_time = false;
        source.dimensions.operations = OperationsState::Offline;
        assert_eq!(
            source.certification(),
            CertificationState::Certified,
            "historical data can certify without a live feed"
        );
    }

    #[test]
    fn revocation_overrides_computed_certification() {
        let mut source = record();
        source.dimensions.certification = CertificationState::Revoked;
        assert_eq!(
            source.certification(),
            CertificationState::Revoked,
            "revocation must be visible"
        );
        assert!(!source.certifiable(), "revoked record cannot certify");
    }

    #[test]
    fn unmeasurable_universe_invents_no_denominator() {
        let mut source = record();
        source.expected_universe = Some(ExpectedUniverse::Unmeasurable {
            reason: "opaque OTC market".to_owned(),
        });
        assert_eq!(
            source.universe_measurement(),
            None,
            "no denominator may be invented"
        );
    }

    #[test]
    fn enumerated_universe_is_measured() {
        let expected = BTreeSet::from([
            "A".to_owned(),
            "B".to_owned(),
            "C".to_owned(),
            "D".to_owned(),
        ]);
        let supported = BTreeSet::from(["A".to_owned(), "B".to_owned()]);
        let mut source = record();
        source.expected_universe = Some(ExpectedUniverse::Enumerated {
            expected,
            supported,
        });
        let measurement = source
            .universe_measurement()
            .expect("enumerated measurement");
        assert_eq!(measurement.expected, 4, "expected universe size retained");
        assert_eq!(measurement.supported, 2, "supported universe size retained");
        assert_eq!(measurement.supported_per_mille, 500, "coverage measured");
    }
}
