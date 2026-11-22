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

/// Failure to define a measurable coverage universe.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UniverseError {
    /// An enumerated universe had no expected objects.
    #[error("expected universe is empty")]
    EmptyExpected,
    /// A supported identifier was absent from the expected set.
    #[error("supported identifiers outside the expected universe: {0:?}")]
    UnsupportedOutsideExpected(Vec<String>),
    /// An unmeasurable declaration had no reason.
    #[error("unmeasurable universe requires a reason")]
    MissingReason,
}

impl ExpectedUniverse {
    /// Validate the universe contract before it is used for certification.
    pub fn validate(&self) -> Result<(), UniverseError> {
        match self {
            Self::Enumerated {
                expected,
                supported,
            } => {
                if expected.is_empty() {
                    return Err(UniverseError::EmptyExpected);
                }
                let outside: Vec<String> = supported.difference(expected).cloned().collect();
                if !outside.is_empty() {
                    return Err(UniverseError::UnsupportedOutsideExpected(outside));
                }
                Ok(())
            }
            Self::Unmeasurable { reason } => {
                if reason.trim().is_empty() {
                    Err(UniverseError::MissingReason)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Measure an enumerated universe, or return `None` when it is unmeasurable.
    ///
    /// # Errors
    /// Returns an error when the declaration is empty, unsupported identifiers
    /// lie outside the expected set, or an unmeasurable declaration has no
    /// reason. No denominator is invented for an opaque market.
    pub fn measure(&self) -> Result<Option<UniverseMeasurement>, UniverseError> {
        self.validate()?;
        match self {
            Self::Enumerated {
                expected,
                supported,
            } => {
                let supported_per_mille =
                    (supported.len() * 1_000 / expected.len()).min(1_000) as u32;
                Ok(Some(UniverseMeasurement {
                    expected: expected.len(),
                    supported: supported.len(),
                    supported_per_mille,
                }))
            }
            Self::Unmeasurable { .. } => Ok(None),
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
    /// Granularity of the claim made by this record.
    #[serde(default)]
    pub granularity: CoverageGranularity,
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
            && self
                .expected_universe
                .as_ref()
                .is_some_and(|universe| universe.validate().is_ok())
    }

    /// Measured expected universe, absent for opaque markets.
    ///
    /// # Errors
    /// Returns an error when the universe is missing or invalid.
    pub fn universe_measurement(&self) -> Result<Option<UniverseMeasurement>, UniverseError> {
        match &self.expected_universe {
            Some(universe) => universe.measure(),
            None => Err(UniverseError::EmptyExpected),
        }
    }

    /// Build the fully identified rights query for this coverage record.
    #[must_use]
    pub fn rights_query(&self, right: UsageRight) -> crate::rights::AuthorizationQuery {
        crate::rights::AuthorizationQuery {
            provider_id: self.source_id.clone(),
            source_id: self.source_id.clone(),
            dataset_id: self.dataset.clone(),
            product_id: self
                .scope
                .product
                .clone()
                .unwrap_or_else(|| self.dataset.clone()),
            territory: self.scope.country.clone(),
            usage_right: right,
            recipient_class: crate::rights::RecipientClass::Internal,
            purpose: crate::rights::Purpose::InternalAnalysis,
        }
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

/// Granularity at which a coverage record makes a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGranularity {
    #[default]
    Source,
    Product,
    Instrument,
}

/// Structured coverage identity used as the matrix key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CoverageIdentity {
    pub source: String,
    pub dataset: String,
    pub country: String,
    pub venue: String,
    pub asset_class: String,
    pub data_category: String,
    pub depth: String,
    pub product: String,
    pub asset: String,
    pub instrument: String,
    pub frequency: String,
    pub history_scope: String,
    pub rights_scope: String,
}

impl CoverageIdentity {
    /// Check that every field required at this granularity is present.
    pub fn validate(&self, granularity: CoverageGranularity) -> Result<(), &'static str> {
        if self.source.is_empty() || self.dataset.is_empty() || self.country.is_empty() {
            return Err("source, dataset and country are required at every granularity");
        }
        if granularity >= CoverageGranularity::Product
            && (self.product.is_empty()
                || self.venue.is_empty()
                || self.asset_class.is_empty()
                || self.data_category.is_empty())
        {
            return Err("product, venue, asset class and data category are required");
        }
        if granularity >= CoverageGranularity::Instrument
            && (self.asset.is_empty() || self.instrument.is_empty())
        {
            return Err("asset and instrument are required at instrument granularity");
        }
        Ok(())
    }
}

impl From<&CoverageRecord> for CoverageIdentity {
    fn from(record: &CoverageRecord) -> Self {
        Self {
            source: record.source_id.clone(),
            dataset: record.dataset.clone(),
            country: record.scope.country.as_str().to_owned(),
            venue: record.scope.venue.clone().unwrap_or_default(),
            asset_class: record.scope.asset_class.as_str().to_owned(),
            data_category: record.scope.category.as_str().to_owned(),
            depth: record.scope.depth.as_str().to_owned(),
            product: record.scope.product.clone().unwrap_or_default(),
            asset: record.scope.asset.clone().unwrap_or_default(),
            instrument: record.scope.instrument.clone().unwrap_or_default(),
            frequency: record.scope.frequency.as_str().to_owned(),
            history_scope: record.scope.history.clone().unwrap_or_default(),
            rights_scope: record.scope.rights.clone().unwrap_or_default(),
        }
    }
}

/// Two records claimed the same structured coverage identity with different
/// content. The second record is rejected instead of overwriting the first.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("conflicting coverage record for identity {0:?}")]
pub struct CoverageConflict(pub Box<CoverageIdentity>);

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
    /// The declared universe is invalid.
    #[error("coverage universe is invalid for {source_id}: {reason}")]
    InvalidUniverse { source_id: String, reason: String },
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
    let universe = record.expected_universe.as_ref().ok_or_else(|| {
        CertificationError::MissingPrerequisite {
            source_id: record.source_id.clone(),
            requirement: "expected_universe",
        }
    })?;
    universe
        .measure()
        .map_err(|error| CertificationError::InvalidUniverse {
            source_id: record.source_id.clone(),
            reason: error.to_string(),
        })?;
    let identity = CoverageIdentity::from(record);
    identity.validate(record.granularity).map_err(|reason| {
        CertificationError::InvalidUniverse {
            source_id: record.source_id.clone(),
            reason: reason.to_owned(),
        }
    })?;
    rights
        .authorize(&record.rights_query(UsageRight::InternalProcessing), at_us)
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

/// Aggregate matrix of coverage records keyed by complete structured identity.
#[derive(Debug, Default)]
pub struct CoverageMatrix {
    records: BTreeMap<CoverageIdentity, CoverageRecord>,
}

impl CoverageMatrix {
    /// Create an empty matrix.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a coverage record, rejecting a conflicting identity.
    ///
    /// # Errors
    /// Returns a conflict when the same structured identity already holds a
    /// different record. Identical re-insertion is idempotent.
    pub fn insert(&mut self, record: CoverageRecord) -> Result<(), CoverageConflict> {
        let key = CoverageIdentity::from(&record);
        if let Some(existing) = self.records.get(&key) {
            if existing != &record {
                return Err(CoverageConflict(Box::new(key)));
            }
            return Ok(());
        }
        self.records.insert(key, record);
        Ok(())
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
        rights::{
            AuthorizationIdentity, AuthorizationRecord, DecisionAudit, Purpose, RecipientClass,
            RightDecision,
        },
    };
    use std::collections::BTreeMap;

    fn universe() -> ExpectedUniverse {
        ExpectedUniverse::Enumerated {
            expected: BTreeSet::from(["A".to_owned(), "B".to_owned()]),
            supported: BTreeSet::from(["A".to_owned(), "B".to_owned()]),
        }
    }

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
            expected_universe: Some(universe()),
            granularity: CoverageGranularity::Source,
            history_start_us: Some(0),
            history_end_us: Some(100),
            real_time: true,
            known_gaps: Vec::new(),
            evidence: vec!["fixture".to_owned()],
        }
    }

    fn rights() -> LicensingRegistry {
        let mut registry = LicensingRegistry::new();
        registry
            .register(AuthorizationRecord {
                identity: AuthorizationIdentity {
                    provider_id: "source".to_owned(),
                    source_id: "source".to_owned(),
                    dataset_id: "quotes".to_owned(),
                    product_id: "quotes".to_owned(),
                    territory: CountryCode::new("US").expect("country code"),
                    usage_right: UsageRight::InternalProcessing,
                    recipient_class: RecipientClass::Internal,
                    purpose: Purpose::InternalAnalysis,
                    valid_from: 0,
                    valid_until: Some(200),
                },
                decision: RightDecision::Permitted,
                audit: DecisionAudit {
                    licence_reference: "contract".to_owned(),
                    licence_document_hash: "contract-hash".to_owned(),
                    contract_revision: 1,
                    recorded_at_us: 0,
                    authority: "contract-registry".to_owned(),
                },
            })
            .expect("rights registered");
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
        matrix.insert(record()).expect("record inserted");
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
            source
                .universe_measurement()
                .expect("valid unmeasurable declaration"),
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
            .expect("valid enumerated universe")
            .expect("enumerated measurement");
        assert_eq!(measurement.expected, 4, "expected universe size retained");
        assert_eq!(measurement.supported, 2, "supported universe size retained");
        assert_eq!(measurement.supported_per_mille, 500, "coverage measured");
    }

    #[test]
    fn supported_outside_expected_cannot_measure_coverage() {
        let universe = ExpectedUniverse::Enumerated {
            expected: BTreeSet::from(["A".to_owned(), "B".to_owned()]),
            supported: BTreeSet::from(["C".to_owned(), "D".to_owned()]),
        };
        assert!(
            matches!(
                universe.validate(),
                Err(UniverseError::UnsupportedOutsideExpected(_))
            ),
            "supported objects outside expected must be rejected"
        );
        let mut source = record();
        source.expected_universe = Some(universe);
        assert!(
            !source.certifiable(),
            "invalid universe blocks certification"
        );
        assert!(
            certify(&source, &rights(), &quality(), 50).is_err(),
            "unsupported identifiers must block certification"
        );
    }

    #[test]
    fn empty_expected_universe_is_invalid() {
        let universe = ExpectedUniverse::Enumerated {
            expected: BTreeSet::new(),
            supported: BTreeSet::new(),
        };
        assert_eq!(
            universe.validate(),
            Err(UniverseError::EmptyExpected),
            "an empty expected set has no denominator"
        );
        let mut source = record();
        source.expected_universe = Some(universe);
        assert!(
            certify(&source, &rights(), &quality(), 50).is_err(),
            "no denominator may be certified"
        );
    }

    #[test]
    fn missing_universe_declaration_blocks_certification() {
        let mut source = record();
        source.expected_universe = None;
        assert!(!source.certifiable(), "undisclosed universe cannot certify");
        assert!(
            matches!(
                certify(&source, &rights(), &quality(), 50),
                Err(CertificationError::MissingPrerequisite {
                    requirement: "expected_universe",
                    ..
                })
            ),
            "certification must name the missing universe"
        );
    }

    #[test]
    fn unmeasurable_universe_requires_a_reason() {
        let universe = ExpectedUniverse::Unmeasurable {
            reason: String::new(),
        };
        assert_eq!(
            universe.validate(),
            Err(UniverseError::MissingReason),
            "unmeasurable declarations must state why"
        );
    }

    #[test]
    fn duplicate_coverage_scope_conflicts() {
        let mut matrix = CoverageMatrix::new();
        matrix.insert(record()).expect("first record inserted");
        let mut different = record();
        different.real_time = false;
        assert!(
            matches!(matrix.insert(different), Err(CoverageConflict(_))),
            "a conflicting scope must not overwrite the first record"
        );
        assert_eq!(
            matrix.certified().len(),
            1,
            "the first record remains authoritative"
        );
    }

    #[test]
    fn identical_coverage_scope_is_idempotent() {
        let mut matrix = CoverageMatrix::new();
        matrix.insert(record()).expect("first record inserted");
        matrix
            .insert(record())
            .expect("identical re-insertion is safe");
        assert_eq!(
            matrix.by_certification(CertificationState::Certified).len(),
            1,
            "one record per identity"
        );
    }

    #[test]
    fn product_granularity_requires_a_complete_identity() {
        let mut source = record();
        source.granularity = CoverageGranularity::Product;
        source.scope.product = None;
        assert!(
            CoverageIdentity::from(&source)
                .validate(source.granularity)
                .is_err(),
            "product granularity needs a product identity"
        );
    }
}
