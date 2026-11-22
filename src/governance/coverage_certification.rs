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
    config::ExchangeKind,
    quality::QualityReport,
    rights::{AuthorizationScope, LicensingRegistry, UsageRight},
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
    /// Provider identity, distinct from the source identity when applicable.
    #[serde(default)]
    pub provider_id: String,
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
    /// Result of the single certification evaluation, set only by `certify`.
    #[serde(default)]
    pub last_evaluation: Option<CertificationEvaluation>,
}

impl CoverageRecord {
    /// Return the certification state from the single evaluation oracle.
    #[must_use]
    pub fn certification(&self) -> CertificationState {
        self.last_evaluation
            .as_ref()
            .map_or(CertificationState::NotCertified, |evaluation| {
                evaluation.certification_state
            })
    }

    /// Whether the stored evaluation satisfies every applicable requirement.
    #[must_use]
    pub fn certifiable(&self) -> bool {
        self.last_evaluation
            .as_ref()
            .is_some_and(CertificationEvaluation::certified)
    }

    /// Requirements that blocked the last evaluation.
    #[must_use]
    pub fn failed_requirements(&self) -> &[String] {
        self.last_evaluation
            .as_ref()
            .map_or(&[], |evaluation| evaluation.failed_requirements.as_slice())
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
        use crate::rights::Licensee;
        use crate::rights::Operation;
        use crate::rights::ScopeSet;
        let operation = match right {
            UsageRight::RealTimeAccess => Operation::RealTimeCapture,
            UsageRight::HistoricalStorage => Operation::HistoricalDataRetrieval,
            UsageRight::InternalProcessing => Operation::InternalAnalytics,
            UsageRight::DerivedData => Operation::DerivedDataCreation,
            UsageRight::Redistribution => Operation::ExternalRedistribution,
        };
        // The declared command scope supplies the contract vocabulary; the
        // coverage record overrides only the identities it genuinely owns.
        AuthorizationScope::for_exchange(ExchangeKind::Kalshi, operation).with(|scope| {
            scope.licensee = Licensee::system();
            scope.venue = self.provider_id.clone();
            scope.provider_id = self.provider_id.clone();
            scope.source_id = self.source_id.clone();
            scope.dataset_id = self.dataset.clone();
            scope.product_id = self
                .scope
                .product
                .clone()
                .unwrap_or_else(|| self.dataset.clone());
            scope.territory = self.scope.country.clone();
            scope.usage_right = right;
            scope.instruments = ScopeSet::All;
            scope.fields = ScopeSet::All;
            scope.modalities = ScopeSet::All;
        })
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
    /// One or more requirements failed the single evaluation oracle.
    #[error("coverage certification failed for {source_id}: {requirements:?}")]
    FailedRequirements {
        source_id: String,
        requirements: Vec<String>,
    },
}

/// Version of the single coverage certification policy.
pub const CERTIFICATION_POLICY_VERSION: u32 = 2;

/// Complete result of one coverage certification evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificationEvaluation {
    pub certification_state: CertificationState,
    pub failed_requirements: Vec<String>,
    pub evidence_references: Vec<String>,
    pub rights_proof: Option<crate::rights::AuthorizationProof>,
    pub universe_measurement: Option<UniverseMeasurement>,
    pub policy_version: u32,
    pub evaluated_at_us: i64,
}

impl CertificationEvaluation {
    /// Whether this evaluation satisfies every requirement.
    #[must_use]
    pub fn certified(&self) -> bool {
        self.certification_state == CertificationState::Certified
            && self.failed_requirements.is_empty()
            && !self.evidence_references.is_empty()
            && self.rights_proof.is_some()
    }
}

/// Single certification oracle used by `certify` and every matrix query.
pub fn evaluate(
    record: &CoverageRecord,
    rights: &LicensingRegistry,
    quality: &QualityReport,
    at_us: i64,
) -> CertificationEvaluation {
    use crate::rights::UsageRight;

    let mut failed: Vec<String> = Vec::new();
    let mut reject = |requirement: &str| failed.push(requirement.to_owned());

    if record.status < CoverageStatus::TechnicallyValidated {
        reject("status");
    }
    if record.dimensions.certification == CertificationState::Revoked {
        reject("revocation");
    }
    if !record.dimensions.requirements_met() {
        reject("dimensions");
    }
    let operations_satisfied = !record.real_time
        || matches!(
            record.dimensions.operations,
            OperationsState::Live | OperationsState::Degraded
        );
    if !operations_satisfied {
        reject("operations");
    }
    if !record.known_gaps.is_empty() {
        reject("known_gaps");
    }
    if record.evidence.is_empty() {
        reject("evidence");
    }
    let history_ok = match (record.history_start_us, record.history_end_us) {
        (Some(start), Some(end)) => start <= end,
        (Some(_), None) => true,
        (None, _) => false,
    };
    if !history_ok {
        reject("history");
    }
    let universe_measurement = match &record.expected_universe {
        Some(universe) => match universe.measure() {
            Ok(measurement) => measurement,
            Err(_) => {
                reject("universe");
                None
            }
        },
        None => {
            reject("universe");
            None
        }
    };
    let identity = CoverageIdentity::from(record);
    if identity.validate(record.granularity).is_err() {
        reject("identity");
    }
    if record.provider_id.trim().is_empty() {
        reject("provider_identity");
    }
    let rights_proof = rights
        .authorize(&record.rights_query(UsageRight::InternalProcessing), at_us)
        .ok();
    if rights_proof.is_none() {
        reject("licensing");
    }
    if !quality.valid() {
        reject("reconciliation");
    }

    let certification_state = if failed.is_empty() {
        CertificationState::Certified
    } else if record.dimensions.certification == CertificationState::Revoked {
        CertificationState::Revoked
    } else {
        CertificationState::NotCertified
    };
    CertificationEvaluation {
        certification_state,
        failed_requirements: failed,
        evidence_references: record.evidence.clone(),
        rights_proof,
        universe_measurement,
        policy_version: CERTIFICATION_POLICY_VERSION,
        evaluated_at_us: at_us,
    }
}

/// Promote a record only when every applicable prerequisite is present.
pub fn certify(
    record: &CoverageRecord,
    rights: &LicensingRegistry,
    quality: &QualityReport,
    at_us: i64,
) -> Result<CoverageRecord, CertificationError> {
    let evaluation = evaluate(record, rights, quality, at_us);
    if !evaluation.certified() {
        return Err(CertificationError::FailedRequirements {
            source_id: record.source_id.clone(),
            requirements: evaluation.failed_requirements.clone(),
        });
    }
    let mut promoted = record.clone();
    promoted.status = CoverageStatus::Certified;
    promoted.dimensions.certification = CertificationState::Certified;
    promoted.last_evaluation = Some(evaluation);
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
            AuthorizationIdentity, AuthorizationRecord, DecisionAudit, Operation, RightDecision,
        },
    };
    use std::collections::BTreeMap;

    fn rights_scope() -> AuthorizationScope {
        AuthorizationScope::for_exchange(ExchangeKind::Kalshi, Operation::InternalAnalytics).with(
            |scope| {
                scope.venue = "source".to_owned();
                scope.provider_id = "source".to_owned();
                scope.source_id = "source".to_owned();
                scope.dataset_id = "quotes".to_owned();
                scope.product_id = "quotes".to_owned();
                scope.usage_right = UsageRight::InternalProcessing;
            },
        )
    }

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
            provider_id: "source".to_owned(),
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
            last_evaluation: None,
        }
    }

    fn rights() -> LicensingRegistry {
        let mut registry = LicensingRegistry::new();
        registry
            .register(AuthorizationRecord {
                identity: AuthorizationIdentity {
                    scope: rights_scope(),
                    valid_from: 0,
                    valid_until: Some(200),
                },
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
        let certified = certify(&source, &rights(), &quality(), 50).expect("certification");
        assert_eq!(
            certified.certification(),
            CertificationState::Certified,
            "historical data can certify without a live feed"
        );
    }

    #[test]
    fn revocation_overrides_computed_certification() {
        let mut source = record();
        source.dimensions.certification = CertificationState::Revoked;
        let evaluation = evaluate(&source, &rights(), &quality(), 50);
        assert_eq!(
            evaluation.certification_state,
            CertificationState::Revoked,
            "revocation must be visible"
        );
        source.last_evaluation = Some(evaluation);
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
        let error = certify(&source, &rights(), &quality(), 50)
            .expect_err("missing universe must block certification");
        assert!(
            format!("{error:?}").contains("universe"),
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
        let certified = certify(&record(), &rights(), &quality(), 50).expect("certification");
        matrix.insert(certified).expect("first record inserted");
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
        let certified = certify(&record(), &rights(), &quality(), 50).expect("certification");
        matrix
            .insert(certified.clone())
            .expect("first record inserted");
        matrix
            .insert(certified)
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

    #[test]
    fn single_evaluation_oracle_agrees_across_all_queries() {
        let certified = certify(&record(), &rights(), &quality(), 50).expect("certification");
        assert_eq!(
            certified.certification(),
            CertificationState::Certified,
            "oracle state is certified"
        );
        assert!(
            certified.certifiable(),
            "certifiable agrees with certification"
        );
        assert!(
            certified.failed_requirements().is_empty(),
            "no requirements failed"
        );
        assert_eq!(
            certified
                .last_evaluation
                .as_ref()
                .expect("evaluation stored")
                .policy_version,
            CERTIFICATION_POLICY_VERSION,
            "policy version is recorded"
        );
        let mut matrix = CoverageMatrix::new();
        matrix.insert(certified).expect("record inserted");
        assert_eq!(
            matrix.by_certification(CertificationState::Certified).len(),
            1,
            "by_certification uses the stored evaluation"
        );
        assert_eq!(
            matrix.certified().len(),
            1,
            "certified uses the stored evaluation"
        );
    }

    #[test]
    fn evidence_history_and_operations_prerequisites_cannot_be_bypassed() {
        let mut missing_evidence = record();
        missing_evidence.evidence.clear();
        let error = certify(&missing_evidence, &rights(), &quality(), 50)
            .expect_err("evidence is required");
        assert!(
            format!("{error:?}").contains("evidence"),
            "the evidence requirement is named"
        );

        let mut missing_history = record();
        missing_history.history_start_us = None;
        assert!(
            certify(&missing_history, &rights(), &quality(), 50).is_err(),
            "history start is required"
        );

        let mut offline_live = record();
        offline_live.dimensions.operations = OperationsState::Offline;
        assert!(
            certify(&offline_live, &rights(), &quality(), 50).is_err(),
            "a real-time claim needs live operations"
        );
    }

    #[test]
    fn provider_identity_is_distinct_from_source_identity() {
        let mut source = record();
        source.provider_id = "other-provider".to_owned();
        assert!(
            certify(&source, &rights(), &quality(), 50).is_err(),
            "another provider's rights cannot authorize this record"
        );
        let mut matching_rights = rights();
        matching_rights
            .register(AuthorizationRecord {
                identity: AuthorizationIdentity {
                    scope: rights_scope().with(|scope| {
                        scope.venue = "other-provider".to_owned();
                        scope.provider_id = "other-provider".to_owned();
                    }),
                    valid_from: 0,
                    valid_until: Some(200),
                },
                decision: RightDecision::Permitted,
                audit: DecisionAudit {
                    licence_reference: "other-contract".to_owned(),
                    licence_document_hash: "c".repeat(64),
                    contract_revision: 2,
                    recorded_at_us: 0,
                    authority: "contract-registry".to_owned(),
                },
            })
            .expect("other provider rights registered");
        assert!(
            certify(&source, &matching_rights, &quality(), 50).is_ok(),
            "the matching provider grant authorizes the record"
        );
    }
}
