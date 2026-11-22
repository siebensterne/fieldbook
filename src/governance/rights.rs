// SPDX-License-Identifier: Apache-2.0
//! Machine-readable data rights and entitlement decisions.
//!
//! Authorization is scoped to a provider, a source product, a territory, a
//! recipient class, a purpose, a usage right and an effective interval. A
//! dataset name alone never carries permission. Access to a feed does not
//! grant storage, derived-data use or redistribution rights.
//!
//! Every decision is recorded with its licence reference, document digest,
//! contract revision and recording time. Ambiguous, conflicting or revoked
//! authorizations fail closed.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::OnceLock,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::Context;
use serde::Deserialize;
use serde::Serialize;

use crate::{
    config::{ExchangeKind, Settings},
    report::write_json_atomic,
    taxonomy::CountryCode,
    time::now_us,
};

/// Right being exercised over a dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageRight {
    RealTimeAccess,
    HistoricalStorage,
    InternalProcessing,
    DerivedData,
    Redistribution,
    Display,
    NonDisplay,
}

impl UsageRight {
    /// Return the stable contract string for this right.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RealTimeAccess => "real_time_access",
            Self::HistoricalStorage => "historical_storage",
            Self::InternalProcessing => "internal_processing",
            Self::DerivedData => "derived_data",
            Self::Redistribution => "redistribution",
            Self::Display => "display",
            Self::NonDisplay => "non_display",
        }
    }

    /// Whether this right is a retention or onward-use right that public
    /// access cannot imply.
    #[must_use]
    pub const fn requires_explicit_grant(self) -> bool {
        matches!(
            self,
            Self::HistoricalStorage | Self::DerivedData | Self::Redistribution
        )
    }
}

/// Class of recipient exercising a right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientClass {
    Public,
    Internal,
    Participant,
    Customer,
    Affiliate,
}

impl RecipientClass {
    /// Return the stable contract string for this recipient class.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Participant => "participant",
            Self::Customer => "customer",
            Self::Affiliate => "affiliate",
        }
    }
}

/// Purpose for which a right is exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    InternalAnalysis,
    Display,
    Redistribution,
    DerivedProduct,
    HistoricalArchive,
    Compliance,
}

impl Purpose {
    /// Return the stable contract string for this purpose.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InternalAnalysis => "internal_analysis",
            Self::Display => "display",
            Self::Redistribution => "redistribution",
            Self::DerivedProduct => "derived_product",
            Self::HistoricalArchive => "historical_archive",
            Self::Compliance => "compliance",
        }
    }
}

/// Operation that would contact or publish provider data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Collect,
    Discover,
    Latency,
    NetworkProbe,
    AnalyticsExport,
}

impl Operation {
    /// Return the stable contract string for this operation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Collect => "collect",
            Self::Discover => "discover",
            Self::Latency => "latency",
            Self::NetworkProbe => "network_probe",
            Self::AnalyticsExport => "analytics_export",
        }
    }
}

/// Decision recorded for one right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RightDecision {
    Permitted,
    Prohibited,
    ContractRequired,
    Unknown,
    Revoked,
}

impl RightDecision {
    /// Return the stable contract string for this decision.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permitted => "permitted",
            Self::Prohibited => "prohibited",
            Self::ContractRequired => "contract_required",
            Self::Unknown => "unknown",
            Self::Revoked => "revoked",
        }
    }
}

/// Dimensions that identify one authorization request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationQuery {
    /// Venue or provider venue the operation targets. Never optional.
    pub venue: String,
    pub provider_id: String,
    pub source_id: String,
    pub dataset_id: String,
    pub product_id: String,
    pub territory: CountryCode,
    pub operation: Operation,
    pub usage_right: UsageRight,
    pub recipient_class: RecipientClass,
    pub purpose: Purpose,
}

impl AuthorizationQuery {
    /// Reject a query with an incomplete identity. A missing venue is never
    /// treated as an unrestricted wildcard.
    pub fn validate(&self) -> Result<(), RightsError> {
        if self.venue.trim().is_empty() {
            return Err(RightsError::VenueAbsent);
        }
        if self.provider_id.trim().is_empty()
            || self.source_id.trim().is_empty()
            || self.dataset_id.trim().is_empty()
            || self.product_id.trim().is_empty()
        {
            return Err(RightsError::InvalidQuery);
        }
        Ok(())
    }
}

/// Effective interval and scope of one recorded decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationIdentity {
    /// Venue this record is scoped to. An absent venue denies.
    pub venue: String,
    pub provider_id: String,
    pub source_id: String,
    pub dataset_id: String,
    pub product_id: String,
    pub territory: CountryCode,
    pub operation: Operation,
    pub usage_right: UsageRight,
    pub recipient_class: RecipientClass,
    pub purpose: Purpose,
    /// First instant at which the decision is effective.
    pub valid_from: i64,
    /// Last effective instant; open when absent.
    pub valid_until: Option<i64>,
}

impl AuthorizationIdentity {
    /// Whether this record applies to a query at `at_us`.
    #[must_use]
    pub fn matches(&self, query: &AuthorizationQuery, at_us: i64) -> bool {
        self.venue == query.venue
            && self.provider_id == query.provider_id
            && self.source_id == query.source_id
            && self.dataset_id == query.dataset_id
            && self.product_id == query.product_id
            && self.territory == query.territory
            && self.operation == query.operation
            && self.usage_right == query.usage_right
            && self.recipient_class == query.recipient_class
            && self.purpose == query.purpose
            && self.valid_from <= at_us
            && self.valid_until.is_none_or(|end| at_us <= end)
    }

    /// Stable key for conflict detection. The interval is excluded so two
    /// revisions of the same authorization cannot coexist unnoticed.
    #[must_use]
    pub fn decision_key(
        &self,
    ) -> (
        String,
        String,
        String,
        String,
        String,
        String,
        u8,
        u8,
        u8,
        u8,
    ) {
        (
            self.venue.clone(),
            self.provider_id.clone(),
            self.source_id.clone(),
            self.dataset_id.clone(),
            self.product_id.clone(),
            self.territory.as_str().to_owned(),
            self.operation as u8,
            self.usage_right as u8,
            self.recipient_class as u8,
            self.purpose as u8,
        )
    }

    /// Reject an identity with no venue; an absent venue is never a wildcard.
    pub fn validate_identity(&self) -> Result<(), RightsError> {
        if self.venue.trim().is_empty() {
            return Err(RightsError::VenueAbsent);
        }
        Ok(())
    }

    /// Reject an interval whose end precedes its start.
    pub fn validate_interval(&self) -> Result<(), RightsError> {
        match self.valid_until {
            Some(end) if end < self.valid_from => Err(RightsError::InvalidInterval),
            _ => Ok(()),
        }
    }

    /// Whether two effective intervals overlap at any instant.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.valid_from <= other.valid_until.unwrap_or(i64::MAX)
            && other.valid_from <= self.valid_until.unwrap_or(i64::MAX)
    }
}

/// Audit record attached to one decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionAudit {
    pub licence_reference: String,
    pub licence_document_hash: String,
    pub contract_revision: u32,
    pub recorded_at_us: i64,
    pub authority: String,
}

impl DecisionAudit {
    /// Validate the audit evidence shape before a decision is trusted.
    pub fn validate(&self) -> Result<(), RightsError> {
        if self.licence_reference.trim().is_empty()
            || self.authority.trim().is_empty()
            || self.contract_revision == 0
            || self.licence_document_hash.len() != 64
            || !self
                .licence_document_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(RightsError::InvalidAudit);
        }
        Ok(())
    }
}

/// One contract-derived authorization record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRecord {
    pub identity: AuthorizationIdentity,
    pub audit: DecisionAudit,
    /// Decision for the identity above, recorded in `audit`.
    pub decision: RightDecision,
}

impl AuthorizationRecord {
    /// Whether this record grants the right it names at `at_us`.
    #[must_use]
    pub fn grants(&self, at_us: i64) -> bool {
        if self.identity.valid_from > at_us
            || self.identity.valid_until.is_some_and(|end| at_us > end)
        {
            return false;
        }
        if self.identity.recipient_class == RecipientClass::Public
            && self.identity.usage_right.requires_explicit_grant()
        {
            return false;
        }
        self.decision == RightDecision::Permitted
    }
}

/// Proof returned for one successful authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationProof {
    pub venue: String,
    pub provider_id: String,
    pub source_id: String,
    pub dataset_id: String,
    pub product_id: String,
    pub territory: String,
    pub operation: Operation,
    pub usage_right: UsageRight,
    pub recipient_class: RecipientClass,
    pub purpose: Purpose,
    pub at_us: i64,
    /// Rechecked at every egress attempt; an expired proof cannot be reused.
    pub valid_until: Option<i64>,
    pub licence_reference: String,
    pub licence_document_hash: String,
    pub contract_revision: u32,
}

/// Failure to authorize a dataset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RightsError {
    /// The query itself is incomplete.
    #[error("authorization query is incomplete")]
    InvalidQuery,
    /// A record or query has no venue, so no egress can be authorized.
    #[error("authorization identity has no venue")]
    VenueAbsent,
    /// No authorization was installed for this process.
    #[error("no active authorization for provider egress")]
    NoActiveAuthorization,
    /// The active authorization is no longer effective.
    #[error("active authorization has expired")]
    AuthorizationExpired,
    /// The active authorization is scoped to another venue or operation.
    #[error("active authorization does not cover {operation} for {venue}")]
    ScopeMismatch { operation: String, venue: String },
    /// The effective interval is malformed.
    #[error("authorization interval is invalid")]
    InvalidInterval,
    /// The decision audit evidence is malformed.
    #[error("decision audit evidence is invalid")]
    InvalidAudit,
    /// No record covers the identity and territory.
    #[error("no licensing record for {dataset_id} in {territory}")]
    MissingRecord {
        dataset_id: String,
        territory: String,
    },
    /// The right is absent, denied, conditional, expired or revoked.
    #[error("right {right} not granted for {dataset_id}")]
    RightNotGranted {
        dataset_id: String,
        right: &'static str,
    },
    /// A revoked decision blocks the operation.
    #[error("right {right} for {dataset_id} was revoked")]
    Revoked {
        dataset_id: String,
        right: &'static str,
    },
    /// Two records disagree for the same authorization identity.
    #[error("conflicting authorization for {dataset_id}: {reason}")]
    Conflict {
        dataset_id: String,
        reason: &'static str,
    },
}

/// Fail-closed registry of effective-dated authorization records.
#[derive(Debug, Default)]
pub struct LicensingRegistry {
    records: Vec<AuthorizationRecord>,
    decisions: BTreeMap<String, DecisionAudit>,
}

impl LicensingRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an authorization record.
    ///
    /// # Errors
    /// Returns a conflict when the same authorization identity and contract
    /// revision already carry a different decision, or when an earlier
    /// revision of the same identity already carries a contradictory decision.
    pub fn register(&mut self, record: AuthorizationRecord) -> Result<(), RightsError> {
        record.identity.validate_identity()?;
        record.identity.validate_interval()?;
        record.audit.validate()?;
        let revision_key = format!(
            "{:?}|{}",
            record.identity.decision_key(),
            record.audit.contract_revision
        );
        if let Some(existing) = self.decisions.get(&revision_key)
            && existing != &record.audit
        {
            return Err(RightsError::Conflict {
                dataset_id: record.identity.dataset_id.clone(),
                reason: "contract revision already recorded with a different decision",
            });
        }
        for existing in &self.records {
            let same_identity = existing.identity.decision_key() == record.identity.decision_key();
            let overlapping = existing.identity.overlaps(&record.identity);
            let contradictory = existing.decision != record.decision;
            let neither_revocation = existing.decision != RightDecision::Revoked
                && record.decision != RightDecision::Revoked;
            if same_identity && overlapping && contradictory && neither_revocation {
                return Err(RightsError::Conflict {
                    dataset_id: record.identity.dataset_id.clone(),
                    reason: "overlapping decisions contradict for the same identity",
                });
            }
        }
        self.decisions.insert(revision_key, record.audit.clone());
        self.records.push(record);
        Ok(())
    }

    /// Authorize one fully identified right at an instant.
    pub fn authorize(
        &self,
        query: &AuthorizationQuery,
        at_us: i64,
    ) -> Result<AuthorizationProof, RightsError> {
        query.validate()?;
        let mut candidates: Vec<&AuthorizationRecord> = self
            .records
            .iter()
            .filter(|record| record.identity.matches(query, at_us))
            .collect();
        if candidates.is_empty() {
            return Err(RightsError::MissingRecord {
                dataset_id: query.dataset_id.clone(),
                territory: query.territory.as_str().to_owned(),
            });
        }
        for record in &candidates {
            record.audit.validate()?;
        }
        candidates.sort_by_key(|record| {
            (
                record.identity.valid_from,
                record.audit.contract_revision,
                record.audit.recorded_at_us,
            )
        });
        let winning = candidates
            .last()
            .ok_or_else(|| RightsError::MissingRecord {
                dataset_id: query.dataset_id.clone(),
                territory: query.territory.as_str().to_owned(),
            })?;
        if winning.decision == RightDecision::Revoked {
            return Err(RightsError::Revoked {
                dataset_id: query.dataset_id.clone(),
                right: query.usage_right.as_str(),
            });
        }
        if !winning.grants(at_us) {
            return Err(RightsError::RightNotGranted {
                dataset_id: query.dataset_id.clone(),
                right: query.usage_right.as_str(),
            });
        }
        Ok(AuthorizationProof {
            venue: query.venue.clone(),
            provider_id: query.provider_id.clone(),
            source_id: query.source_id.clone(),
            dataset_id: query.dataset_id.clone(),
            product_id: query.product_id.clone(),
            territory: query.territory.as_str().to_owned(),
            operation: query.operation,
            usage_right: query.usage_right,
            recipient_class: query.recipient_class,
            purpose: query.purpose,
            at_us,
            valid_until: winning.identity.valid_until,
            licence_reference: winning.audit.licence_reference.clone(),
            licence_document_hash: winning.audit.licence_document_hash.clone(),
            contract_revision: winning.audit.contract_revision,
        })
    }
}

/// Runtime authorization source. Records come from a config file, never from
/// code, an environment variable, or a self-attested operator flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RightsFile {
    pub schema_version: u32,
    /// ISO 3166-1 alpha-2 territory for every decision in this file.
    pub territory: String,
    /// Recipient class for every decision in this file.
    pub recipient_class: RecipientClass,
    #[serde(default)]
    pub rights: Vec<AuthorizationRecord>,
}

/// Fully identified request for one operation. All identifiers are scalar and
/// abstract; no market observation is part of an authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub venue: String,
    pub provider_id: String,
    pub source_id: String,
    pub dataset_id: String,
    pub product_id: String,
    pub operation: Operation,
    pub purpose: Purpose,
}

impl AuthorizationRequest {
    /// Build the stable identity used for one configured venue and operation.
    #[must_use]
    pub fn for_exchange(exchange: ExchangeKind, operation: Operation) -> Self {
        let venue = exchange.to_string();
        let purpose = match operation {
            Operation::AnalyticsExport => Purpose::Redistribution,
            Operation::Collect | Operation::Latency => Purpose::InternalAnalysis,
            Operation::Discover | Operation::NetworkProbe => Purpose::Compliance,
        };
        let usage_source = match operation {
            Operation::AnalyticsExport => "derived-data",
            _ => "reference-data",
        };
        Self {
            venue: venue.clone(),
            provider_id: venue,
            source_id: format!("{usage_source}-source"),
            dataset_id: "market-reference".to_owned(),
            product_id: operation.as_str().to_owned(),
            operation,
            purpose,
        }
    }
}

/// Machine-readable audit event for one authorization or egress decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionAuditEvent {
    pub schema_version: u32,
    pub operation: String,
    pub venue: String,
    pub provider_id: String,
    pub source_id: String,
    pub dataset_id: String,
    pub product_id: String,
    pub territory: String,
    pub usage_right: String,
    pub recipient_class: String,
    pub purpose: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub recorded_at_us: i64,
}

static AUDIT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Append one decision as its own atomically installed JSON file. One file per
/// decision keeps the trail ordered and makes a partial write impossible.
fn record_decision(audit_dir: Option<&Path>, event: &DecisionAuditEvent) -> anyhow::Result<()> {
    let Some(directory) = audit_dir else {
        return Ok(());
    };
    let sequence = AUDIT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let safe = |value: &str| -> String {
        value
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                    character
                } else {
                    '_'
                }
            })
            .collect()
    };
    let name = format!(
        "{:020}-{}-{}-{sequence}.json",
        event.recorded_at_us,
        safe(&event.operation),
        safe(&event.venue)
    );
    let path = directory.join(name);
    write_json_atomic(&path, event).context("writing authorization audit event")
}

/// Fail-closed authorization registry loaded from a runtime configuration file.
#[derive(Debug)]
pub struct RightsContext {
    registry: LicensingRegistry,
    territory: CountryCode,
    recipient_class: RecipientClass,
    audit_dir: Option<PathBuf>,
    source: PathBuf,
}

impl RightsContext {
    /// Load authorization records from `path`.
    ///
    /// A missing, unreadable, malformed, or record-less file is an error: the
    /// caller must not proceed to any provider egress. Expired records are
    /// excluded rather than treated as grants, so they cannot authorize a
    /// later operation.
    pub fn load(path: &Path, audit_dir: Option<&Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading rights file `{}`", path.display()))?;
        let file = toml::from_str::<RightsFile>(&text)
            .with_context(|| format!("parsing rights file `{}`", path.display()))?;
        anyhow::ensure!(
            file.schema_version == 1,
            "unsupported rights schema version {}",
            file.schema_version
        );
        let territory = CountryCode::new(&file.territory)
            .with_context(|| format!("invalid territory in rights file `{}`", path.display()))?;
        let now = now_us().context("reading the clock for rights validation")?;
        let mut registry = LicensingRegistry::new();
        for record in file.rights {
            // An expired interval is never a grant. It is dropped here so it
            // cannot win a later decision even if the clock moves backwards.
            if record.identity.valid_until.is_some_and(|end| end < now) {
                continue;
            }
            registry
                .register(record)
                .with_context(|| format!("invalid record in rights file `{}`", path.display()))?;
        }
        let context = Self {
            registry,
            territory,
            recipient_class: file.recipient_class,
            audit_dir: audit_dir.map(Path::to_path_buf),
            source: path.to_path_buf(),
        };
        context.record_load_decision(now)?;
        Ok(context)
    }

    #[must_use]
    pub fn audit_dir(&self) -> Option<&Path> {
        self.audit_dir.as_deref()
    }

    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    fn query(&self, request: &AuthorizationRequest) -> AuthorizationQuery {
        AuthorizationQuery {
            venue: request.venue.clone(),
            provider_id: request.provider_id.clone(),
            source_id: request.source_id.clone(),
            dataset_id: request.dataset_id.clone(),
            product_id: request.product_id.clone(),
            territory: self.territory.clone(),
            operation: request.operation,
            usage_right: match request.operation {
                Operation::AnalyticsExport => UsageRight::DerivedData,
                _ => UsageRight::RealTimeAccess,
            },
            recipient_class: self.recipient_class,
            purpose: request.purpose,
        }
    }

    /// Authorize one operation, recording the decision before returning it.
    ///
    /// # Errors
    /// Returns an error for a denied decision, and also fails closed when the
    /// audit event itself cannot be written.
    pub fn authorize(
        &self,
        request: &AuthorizationRequest,
        at_us: i64,
    ) -> anyhow::Result<AuthorizationProof> {
        let query = self.query(request);
        // Validate the scope first so a venue-less query is denied even when
        // the registry is empty.
        let validation = query.validate();
        let outcome = match &validation {
            Err(error) => Err(error.clone()),
            Ok(()) => self.registry.authorize(&query, at_us),
        };
        let event = DecisionAuditEvent {
            schema_version: 1,
            operation: request.operation.as_str().to_owned(),
            venue: request.venue.clone(),
            provider_id: request.provider_id.clone(),
            source_id: request.source_id.clone(),
            dataset_id: query.dataset_id.clone(),
            product_id: query.product_id.clone(),
            territory: query.territory.as_str().to_owned(),
            usage_right: query.usage_right.as_str().to_owned(),
            recipient_class: query.recipient_class.as_str().to_owned(),
            purpose: query.purpose.as_str().to_owned(),
            decision: match &outcome {
                Ok(_) => RightDecision::Permitted.as_str().to_owned(),
                Err(error) => error.to_string(),
            },
            reason: outcome.as_ref().err().map(ToString::to_string),
            reference: outcome
                .as_ref()
                .ok()
                .map(|proof| format!("{}:{}", proof.licence_reference, proof.contract_revision)),
            recorded_at_us: at_us,
        };
        record_decision(self.audit_dir.as_deref(), &event)?;
        validation?;
        Ok(outcome?)
    }

    fn record_load_decision(&self, at_us: i64) -> anyhow::Result<()> {
        let event = DecisionAuditEvent {
            schema_version: 1,
            operation: "rights_load".to_owned(),
            venue: "*".to_owned(),
            provider_id: "*".to_owned(),
            source_id: self.source.to_string_lossy().into_owned(),
            dataset_id: "*".to_owned(),
            product_id: "*".to_owned(),
            territory: "*".to_owned(),
            usage_right: "*".to_owned(),
            recipient_class: "*".to_owned(),
            purpose: "*".to_owned(),
            decision: "permitted".to_owned(),
            reason: None,
            reference: Some(self.source.to_string_lossy().into_owned()),
            recorded_at_us: at_us,
        };
        record_decision(self.audit_dir.as_deref(), &event)
    }
}

/// The scoped authorization installed for this process. It is set once, by the
/// CLI dispatch, before any provider egress command runs.
#[derive(Debug)]
struct ActiveAuthorization {
    proof: AuthorizationProof,
    audit_dir: Option<PathBuf>,
}

static ACTIVE_AUTHORIZATION: OnceLock<ActiveAuthorization> = OnceLock::new();

/// Install the proof produced by the CLI authorization decision. Installing a
/// second proof fails closed instead of widening an existing grant.
pub fn install_active_authorization(
    proof: AuthorizationProof,
    audit_dir: Option<&Path>,
) -> anyhow::Result<()> {
    ACTIVE_AUTHORIZATION
        .set(ActiveAuthorization {
            proof,
            audit_dir: audit_dir.map(Path::to_path_buf),
        })
        .map_err(|_| anyhow::anyhow!("an active authorization is already installed"))
}

fn check_active(venue: &str, operation: &str, at_us: i64) -> anyhow::Result<()> {
    if venue.trim().is_empty() {
        return Err(RightsError::VenueAbsent.into());
    }
    let active = ACTIVE_AUTHORIZATION
        .get()
        .ok_or(RightsError::NoActiveAuthorization)?;
    let proof = &active.proof;
    if proof.venue.trim().is_empty() || proof.venue != venue {
        return Err(RightsError::ScopeMismatch {
            operation: operation.to_owned(),
            venue: venue.to_owned(),
        }
        .into());
    }
    if proof.valid_until.is_some_and(|end| at_us > end) {
        return Err(RightsError::AuthorizationExpired.into());
    }
    let event = DecisionAuditEvent {
        schema_version: 1,
        operation: proof.operation.as_str().to_owned(),
        venue: proof.venue.clone(),
        provider_id: proof.provider_id.clone(),
        source_id: proof.source_id.clone(),
        dataset_id: proof.dataset_id.clone(),
        product_id: proof.product_id.clone(),
        territory: proof.territory.clone(),
        usage_right: proof.usage_right.as_str().to_owned(),
        recipient_class: proof.recipient_class.as_str().to_owned(),
        purpose: proof.purpose.as_str().to_owned(),
        decision: "egress_permitted".to_owned(),
        reason: None,
        reference: Some(proof.licence_reference.clone()),
        recorded_at_us: at_us,
    };
    record_decision(active.audit_dir.as_deref(), &event)?;
    Ok(())
}

/// Enforce authorization at the common provider egress boundary. No HTTP
/// client or websocket is opened unless a live, venue-scoped proof is active.
pub fn require_provider_egress(venue: &str, operation: &str) -> anyhow::Result<()> {
    // Loopback test transports are not provider egress. This identity can never
    // be derived from a configured exchange, and websocket callers further
    // require the target host itself to be loopback.
    if venue.eq_ignore_ascii_case("loopback") {
        return Ok(());
    }
    let now = now_us().context("reading the clock for egress authorization")?;
    if let Err(error) = check_active(venue, operation, now) {
        if let Some(active) = ACTIVE_AUTHORIZATION.get() {
            let event = DecisionAuditEvent {
                schema_version: 1,
                operation: operation.to_owned(),
                venue: venue.to_owned(),
                provider_id: active.proof.provider_id.clone(),
                source_id: active.proof.source_id.clone(),
                dataset_id: active.proof.dataset_id.clone(),
                product_id: active.proof.product_id.clone(),
                territory: active.proof.territory.clone(),
                usage_right: active.proof.usage_right.as_str().to_owned(),
                recipient_class: active.proof.recipient_class.as_str().to_owned(),
                purpose: active.proof.purpose.as_str().to_owned(),
                decision: "egress_denied".to_owned(),
                reason: Some(error.to_string()),
                reference: Some(active.proof.licence_reference.clone()),
                recorded_at_us: now,
            };
            let _ = record_decision(active.audit_dir.as_deref(), &event);
        }
        return Err(error);
    }
    Ok(())
}

/// Authorize one provider-facing command from the runtime rights file.
///
/// Called by CLI dispatch before any library implementation runs, so a denial
/// happens before a client, a socket, or a published file exists. A missing
/// rights file is a denial, never a default grant.
pub fn authorize_command(settings: &Settings, operation: Operation) -> anyhow::Result<()> {
    let path = settings.governance.rights_file.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "{} requires a runtime authorization file: set [governance].rights_file or --rights-file",
            operation.as_str()
        )
    })?;
    let context = RightsContext::load(path, settings.governance.audit_dir.as_deref())?;
    let request = AuthorizationRequest::for_exchange(settings.exchange, operation);
    let proof = context.authorize(&request, now_us()?)?;
    install_active_authorization(proof, context.audit_dir())
}

/// Whether an authorization decision has been installed for this process.
#[must_use]
pub fn has_active_authorization() -> bool {
    ACTIVE_AUTHORIZATION.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> AuthorizationQuery {
        AuthorizationQuery {
            venue: "venue-a".to_owned(),
            provider_id: "provider-a".to_owned(),
            source_id: "source-a".to_owned(),
            dataset_id: "quotes".to_owned(),
            product_id: "product-a".to_owned(),
            territory: CountryCode::new("US").expect("country code"),
            operation: Operation::Collect,
            usage_right: UsageRight::HistoricalStorage,
            recipient_class: RecipientClass::Internal,
            purpose: Purpose::HistoricalArchive,
        }
    }

    fn record(
        decision: RightDecision,
        provider: &str,
        territory: &str,
        valid_from: i64,
        valid_until: Option<i64>,
        revision: u32,
    ) -> AuthorizationRecord {
        AuthorizationRecord {
            identity: AuthorizationIdentity {
                venue: "venue-a".to_owned(),
                provider_id: provider.to_owned(),
                source_id: "source-a".to_owned(),
                dataset_id: "quotes".to_owned(),
                product_id: "product-a".to_owned(),
                territory: CountryCode::new(territory).expect("country code"),
                operation: Operation::Collect,
                usage_right: UsageRight::HistoricalStorage,
                recipient_class: RecipientClass::Internal,
                purpose: Purpose::HistoricalArchive,
                valid_from,
                valid_until,
            },
            decision,
            audit: DecisionAudit {
                licence_reference: format!("licence-{provider}-{revision}"),
                licence_document_hash: format!("{:064x}", revision),
                contract_revision: revision,
                recorded_at_us: valid_from,
                authority: "contract-registry".to_owned(),
            },
        }
    }

    #[test]
    fn effective_dated_grant_authorizes_only_inside_its_window() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(record(
                RightDecision::Permitted,
                "provider-a",
                "US",
                100,
                Some(200),
                1,
            ))
            .expect("grant registered");
        assert!(
            registry.authorize(&query(), 99).is_err(),
            "future-effective grant must not authorize"
        );
        assert!(
            registry.authorize(&query(), 150).is_ok(),
            "effective grant must authorize"
        );
        assert!(
            registry.authorize(&query(), 201).is_err(),
            "expired grant must not authorize"
        );
    }

    #[test]
    fn provider_specific_decision_is_not_shared() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(record(
                RightDecision::Permitted,
                "provider-b",
                "US",
                0,
                None,
                1,
            ))
            .expect("other provider grant registered");
        assert!(
            registry.authorize(&query(), 1).is_err(),
            "a different provider's grant cannot authorize provider-a"
        );
    }

    #[test]
    fn conflicting_decisions_fail_closed() {
        let mut registry = LicensingRegistry::new();
        let mut conflicting = query();
        conflicting.usage_right = UsageRight::Redistribution;
        let mut grant = record(RightDecision::Permitted, "provider-a", "US", 0, None, 1);
        grant.identity.usage_right = UsageRight::Redistribution;
        let mut ban = record(RightDecision::Prohibited, "provider-a", "US", 0, None, 2);
        ban.identity.usage_right = UsageRight::Redistribution;
        registry.register(grant).expect("grant registered");
        assert!(
            matches!(registry.register(ban), Err(RightsError::Conflict { .. })),
            "a contradictory decision for the same identity must be rejected"
        );
        assert!(
            registry.authorize(&conflicting, 1).is_ok(),
            "the original grant remains; the conflicting ban was refused"
        );
    }

    #[test]
    fn revocation_blocks_authorization() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(record(
                RightDecision::Permitted,
                "provider-a",
                "US",
                0,
                None,
                1,
            ))
            .expect("grant registered");
        let revocation = record(RightDecision::Revoked, "provider-a", "US", 50, None, 2);
        registry
            .register(revocation)
            .expect("revocation registered");
        assert!(
            registry.authorize(&query(), 49).is_ok(),
            "grant held before revocation"
        );
        assert!(
            matches!(
                registry.authorize(&query(), 50),
                Err(RightsError::Revoked { .. })
            ),
            "revocation must take effect at its timestamp"
        );
    }

    #[test]
    fn territory_is_scoped() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(record(
                RightDecision::Permitted,
                "provider-a",
                "GB",
                0,
                None,
                1,
            ))
            .expect("grant registered");
        assert!(
            registry.authorize(&query(), 1).is_err(),
            "a GB grant cannot authorize US territory"
        );
    }

    #[test]
    fn public_access_never_grants_retention() {
        let mut registry = LicensingRegistry::new();
        let mut public = record(RightDecision::Permitted, "provider-a", "US", 0, None, 1);
        public.identity.recipient_class = RecipientClass::Public;
        registry
            .register(public)
            .expect("public decision registered");
        let mut public_query = query();
        public_query.recipient_class = RecipientClass::Public;
        assert!(
            registry.authorize(&public_query, 1).is_err(),
            "public access cannot imply historical storage"
        );
    }

    #[test]
    fn conflicting_registration_is_rejected() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(record(
                RightDecision::Permitted,
                "provider-a",
                "US",
                0,
                None,
                1,
            ))
            .expect("grant registered");
        assert!(
            registry
                .register(record(
                    RightDecision::Prohibited,
                    "provider-a",
                    "US",
                    0,
                    None,
                    1
                ))
                .is_err(),
            "same identity and revision cannot change decision"
        );
    }

    #[test]
    fn authorization_proof_carries_audit_identity() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(record(
                RightDecision::Permitted,
                "provider-a",
                "US",
                0,
                None,
                7,
            ))
            .expect("grant registered");
        let proof = registry.authorize(&query(), 1).expect("authorization");
        assert_eq!(
            proof.licence_reference, "licence-provider-a-7",
            "licence reference retained in proof"
        );
        assert_eq!(proof.contract_revision, 7, "revision retained");
        assert_eq!(proof.purpose, Purpose::HistoricalArchive, "purpose kept");
    }

    #[test]
    fn non_overlapping_decisions_coexist() {
        let mut registry = LicensingRegistry::new();
        let mut grant = record(
            RightDecision::Permitted,
            "provider-a",
            "US",
            0,
            Some(100),
            1,
        );
        let mut ban = record(
            RightDecision::Prohibited,
            "provider-a",
            "US",
            101,
            Some(200),
            2,
        );
        grant.audit.licence_document_hash = "a".repeat(64);
        ban.audit.licence_document_hash = "b".repeat(64);
        registry.register(grant).expect("grant registered");
        registry
            .register(ban)
            .expect("later prohibition registered");
        assert!(
            registry.authorize(&query(), 50).is_ok(),
            "earlier window is granted"
        );
        assert!(
            registry.authorize(&query(), 150).is_err(),
            "later window is prohibited"
        );
    }

    #[test]
    fn revision_keys_include_full_identity() {
        let mut registry = LicensingRegistry::new();
        let mut first = record(RightDecision::Permitted, "provider-a", "US", 0, None, 1);
        first.audit.licence_document_hash = "a".repeat(64);
        let mut second = first.clone();
        second.identity.product_id = "product-b".to_owned();
        second.audit.licence_document_hash = "b".repeat(64);
        let mut third = first.clone();
        third.identity.source_id = "source-b".to_owned();
        third.audit.licence_document_hash = "c".repeat(64);
        registry.register(first).expect("first product registered");
        registry
            .register(second)
            .expect("second product registered");
        registry.register(third).expect("second source registered");
        assert_eq!(
            registry.records.len(),
            3,
            "unrelated identities never collide on one contract revision"
        );
    }

    #[test]
    fn reinstatement_supersedes_revocation() {
        let mut registry = LicensingRegistry::new();
        let mut grant = record(RightDecision::Permitted, "provider-a", "US", 0, None, 1);
        grant.audit.licence_document_hash = "a".repeat(64);
        let mut revoked = record(RightDecision::Revoked, "provider-a", "US", 50, None, 2);
        revoked.audit.licence_document_hash = "b".repeat(64);
        let mut reinstated = record(RightDecision::Permitted, "provider-a", "US", 100, None, 3);
        reinstated.audit.licence_document_hash = "c".repeat(64);
        registry.register(grant).expect("grant registered");
        registry.register(revoked).expect("revocation registered");
        registry
            .register(reinstated)
            .expect("reinstatement registered");
        assert!(
            matches!(
                registry.authorize(&query(), 75),
                Err(RightsError::Revoked { .. })
            ),
            "revocation applies before reinstatement"
        );
        assert!(
            registry.authorize(&query(), 150).is_ok(),
            "later approved contract reauthorizes the source"
        );
    }

    #[test]
    fn malformed_interval_and_audit_are_refused() {
        let mut registry = LicensingRegistry::new();
        let mut invalid_interval =
            record(RightDecision::Permitted, "provider-a", "US", 10, Some(9), 1);
        invalid_interval.audit.licence_document_hash = "a".repeat(64);
        let interval_result = registry.register(invalid_interval);
        let interval_invalid = matches!(interval_result, Err(RightsError::InvalidInterval));
        assert!(interval_invalid, "invalid intervals are refused");
        let mut invalid_audit = record(RightDecision::Permitted, "provider-a", "US", 0, None, 1);
        invalid_audit.audit.licence_document_hash = "not-a-digest".to_owned();
        let audit_result = registry.register(invalid_audit);
        let audit_invalid = matches!(audit_result, Err(RightsError::InvalidAudit));
        assert!(audit_invalid, "invalid audit evidence is refused");
    }

    fn collect_request() -> AuthorizationRequest {
        AuthorizationRequest {
            venue: "venue-a".to_owned(),
            provider_id: "provider-a".to_owned(),
            source_id: "reference-data-source".to_owned(),
            dataset_id: "market-reference".to_owned(),
            product_id: "collect".to_owned(),
            operation: Operation::Collect,
            purpose: Purpose::InternalAnalysis,
        }
    }

    fn configured_record(
        operation: Operation,
        decision: RightDecision,
        valid_until: Option<i64>,
    ) -> AuthorizationRecord {
        AuthorizationRecord {
            identity: AuthorizationIdentity {
                venue: "venue-a".to_owned(),
                provider_id: "provider-a".to_owned(),
                source_id: "reference-data-source".to_owned(),
                dataset_id: "market-reference".to_owned(),
                product_id: operation.as_str().to_owned(),
                territory: CountryCode::new("US").expect("country code"),
                operation,
                usage_right: UsageRight::RealTimeAccess,
                recipient_class: RecipientClass::Internal,
                purpose: Purpose::InternalAnalysis,
                valid_from: 0,
                valid_until,
            },
            decision,
            audit: DecisionAudit {
                licence_reference: "contract-1".to_owned(),
                licence_document_hash: "a".repeat(64),
                contract_revision: 1,
                recorded_at_us: 0,
                authority: "contract-registry".to_owned(),
            },
        }
    }

    fn write_rights(
        directory: &std::path::Path,
        records: Vec<AuthorizationRecord>,
    ) -> std::path::PathBuf {
        let file = RightsFile {
            schema_version: 1,
            territory: "US".to_owned(),
            recipient_class: RecipientClass::Internal,
            rights: records,
        };
        let path = directory.join("rights.toml");
        std::fs::write(&path, toml::to_string(&file).expect("serde rights file"))
            .expect("write rights file");
        path
    }

    #[test]
    fn venue_is_required_in_both_query_and_record() {
        let mut registry = LicensingRegistry::new();
        let mut no_venue = configured_record(Operation::Collect, RightDecision::Permitted, None);
        no_venue.identity.venue.clear();
        assert!(
            matches!(registry.register(no_venue), Err(RightsError::VenueAbsent)),
            "a record without a venue is refused"
        );
        let mut different_venue =
            configured_record(Operation::Collect, RightDecision::Permitted, None);
        different_venue.identity.venue = "venue-b".to_owned();
        registry
            .register(different_venue)
            .expect("different venue registered");
        let request = collect_request();
        let context = RightsContext {
            registry,
            territory: CountryCode::new("US").expect("country code"),
            recipient_class: RecipientClass::Internal,
            audit_dir: None,
            source: std::path::PathBuf::from("in-memory"),
        };
        assert!(
            context.authorize(&request, 1).is_err(),
            "a grant for venue-b cannot authorize venue-a"
        );
        let mut no_venue_request = request;
        no_venue_request.venue.clear();
        assert!(
            context.authorize(&no_venue_request, 1).is_err(),
            "an absent venue always denies"
        );
    }

    #[test]
    fn operation_is_part_of_the_authorization_identity() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(configured_record(
                Operation::Discover,
                RightDecision::Permitted,
                None,
            ))
            .expect("discovery grant registered");
        let request = collect_request();
        let context = RightsContext {
            registry,
            territory: CountryCode::new("US").expect("country code"),
            recipient_class: RecipientClass::Internal,
            audit_dir: None,
            source: std::path::PathBuf::from("in-memory"),
        };
        assert!(
            context.authorize(&request, 1).is_err(),
            "a discovery grant cannot authorize collection"
        );
    }

    #[test]
    fn rights_loader_fails_closed_on_missing_and_malformed_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let missing = directory.path().join("absent.toml");
        assert!(
            RightsContext::load(&missing, None).is_err(),
            "a missing rights file denies"
        );
        let malformed = directory.path().join("malformed.toml");
        std::fs::write(&malformed, "schema_version = 1\nterritory = \"US\"\n")
            .expect("write malformed rights file");
        assert!(
            RightsContext::load(&malformed, None).is_err(),
            "a malformed rights file denies"
        );
        let empty = write_rights(directory.path(), Vec::new());
        let context = RightsContext::load(&empty, None).expect("empty registry loads");
        let request = collect_request();
        assert!(
            context.authorize(&request, 1).is_err(),
            "no records means no authorization"
        );
    }

    #[test]
    fn expired_and_unknown_rights_never_authorize() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let expired = write_rights(
            directory.path(),
            vec![configured_record(
                Operation::Collect,
                RightDecision::Permitted,
                Some(1),
            )],
        );
        let expired_context = RightsContext::load(&expired, None).expect("expired file loads");
        let request = collect_request();
        assert!(
            expired_context.authorize(&request, 2).is_err(),
            "an expired record must not grant egress"
        );
        let unknown_file = write_rights(
            directory.path(),
            vec![configured_record(
                Operation::Collect,
                RightDecision::ContractRequired,
                None,
            )],
        );
        let unknown_context = RightsContext::load(&unknown_file, None).expect("unknown file loads");
        assert!(
            unknown_context.authorize(&request, 2).is_err(),
            "an UNKNOWN/contract-required decision denies"
        );
    }

    #[test]
    fn every_decision_writes_a_machine_readable_audit_event() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let audit = directory.path().join("audit");
        let path = write_rights(
            directory.path(),
            vec![configured_record(
                Operation::Collect,
                RightDecision::Permitted,
                None,
            )],
        );
        let context = RightsContext::load(&path, Some(&audit)).expect("rights file loads");
        let request = collect_request();
        let proof = context.authorize(&request, 2).expect("decision granted");
        assert_eq!(proof.venue, "venue-a");
        assert_eq!(proof.operation, Operation::Collect);
        assert_eq!(proof.licence_reference, "contract-1");
        let entries: Vec<_> = std::fs::read_dir(&audit)
            .expect("audit directory")
            .map(|entry| entry.expect("audit entry").path())
            .collect();
        assert!(entries.len() >= 2, "load and decision are both recorded");
        let text = std::fs::read_to_string(&entries[1]).expect("audit event");
        let event: DecisionAuditEvent = serde_json::from_str(&text).expect("valid audit event");
        assert_eq!(event.operation, "collect");
        assert_eq!(event.venue, "venue-a");
        assert_eq!(event.decision, "permitted");
        assert_eq!(event.dataset_id, "market-reference");
        assert_eq!(event.product_id, "collect");
        assert_eq!(event.usage_right, "real_time_access");
        assert_eq!(event.purpose, "internal_analysis");
        assert_eq!(event.recorded_at_us, 2);
        assert!(
            event
                .reference
                .as_deref()
                .is_some_and(|r| r.contains("contract-1")),
            "the licence reference is recorded with the decision"
        );
    }
}
