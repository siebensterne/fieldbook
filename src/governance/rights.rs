// SPDX-License-Identifier: Apache-2.0
//! Machine-readable data rights and entitlement decisions.
//!
//! Authorization is scoped to a declared actor, a typed lifecycle operation,
//! a typed data object (kind, identity and version), a named recipient
//! identity and recipient class, a licensee, a provider, a source product, a
//! venue, a segment, an instrument/field/modality/time window, a territory, a
//! delivery method, a purpose, a retention rule and an effective interval.
//! A dataset name or an object kind alone never carries permission. Access to
//! a feed does not grant storage, derived-data use or redistribution rights.
//!
//! Every decision is recorded with its licence reference, document digest,
//! contract revision and recording time. Ambiguous, conflicting or revoked
//! authorizations fail closed.
//!
//! # Audit commit boundary
//!
//! An audit acknowledgement means one JSON file containing the decision has
//! been written to a sibling temporary file, its bytes `fsync`ed, the file
//! renamed into the audit directory and the parent directory `fsync`ed (see
//! [`crate::report::write_bytes_atomic`]). It is a durability acknowledgement
//! for the decision record only. It does not mean a provider was contacted,
//! that the operation succeeded, or that the underlying licence is valid. A
//! permitted decision is written **before** the network side effect; a write
//! failure prevents that side effect. A denied decision is written when
//! possible, but an audit failure never converts a denial into a permission.
//! Audit records carry only scalar identifiers and counts: no credentials,
//! proxy URLs, headers or raw payloads are ever included.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, LazyLock, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use anyhow::Context;
use serde::Deserialize;
use serde::Serialize;

use crate::config::Settings;
use crate::egress_intent::{
    AuthorityRefresh, AuthorizationSession, EgressIntent, EndpointIdentity, GrantSnapshot,
    InMemoryAuthority, MAX_LEASE_DURATION,
};
use crate::report::write_json_atomic;
use crate::taxonomy::CountryCode;
use crate::time::now_us;
use crate::util::sha256_hex;

/// Right being exercised over a dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageRight {
    RealTimeAccess,
    HistoricalStorage,
    InternalProcessing,
    DerivedData,
    Redistribution,
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

/// Display mode of a use. This is a separate concept from [`UsageRight`]:
/// display is how a permitted use is presented, not the right that permits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageMode {
    Display,
    NonDisplay,
}

impl UsageMode {
    /// Return the stable contract string for this mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Display => "display",
            Self::NonDisplay => "non_display",
        }
    }
}

/// Class of recipient exercising a right. `Internal` is a class, not a named
/// recipient: a request still has to supply the named recipient identity.
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

/// Backwards-compatible name for [`RecipientClass`].
pub type Recipient = RecipientClass;

/// Named recipient identity, independent of its recipient class.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecipientIdentity(String);

impl RecipientIdentity {
    /// Build a recipient identity after validating that it is non-blank.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidRecipientIdentity`] for a blank identity.
    pub fn new(value: &str) -> Result<Self, RightsError> {
        if value.trim().is_empty() {
            return Err(RightsError::InvalidRecipientIdentity);
        }
        Ok(Self(value.to_owned()))
    }

    /// Build a recipient identity from a declaration-owned string that was
    /// already validated by its source. Gate validation still rejects a blank.
    #[must_use]
    pub fn from_declared(value: String) -> Self {
        Self(value)
    }

    /// Return the validated recipient identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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
    /// The exact reviewed wording `proprietary_own_account_trading_research`.
    /// This is a distinct contract value. It is never an alias for
    /// `internal_analysis`, academic research, non-commercial research or
    /// `historical_archive`, and no value in an agreement may be substituted
    /// for it by inference.
    ProprietaryOwnAccountTradingResearch,
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
            Self::ProprietaryOwnAccountTradingResearch => {
                "proprietary_own_account_trading_research"
            }
        }
    }
}

/// Lifecycle operation being authorized. These are contract vocabulary, not
/// CLI command names. A command declares the operations it may require; a
/// proof names exactly one of them and is never inferred from a command name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    SourceContact,
    ReferenceDataRetrieval,
    HistoricalDataRetrieval,
    RealTimeCapture,
    RawStorage,
    Normalization,
    Replay,
    Backup,
    InternalAnalytics,
    DerivedDataCreation,
    Display,
    ExternalRedistribution,
    Retention,
    Deletion,
}

impl Operation {
    /// Return the stable contract string for this operation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceContact => "source_contact",
            Self::ReferenceDataRetrieval => "reference_data_retrieval",
            Self::HistoricalDataRetrieval => "historical_data_retrieval",
            Self::RealTimeCapture => "real_time_capture",
            Self::RawStorage => "raw_storage",
            Self::Normalization => "normalization",
            Self::Replay => "replay",
            Self::Backup => "backup",
            Self::InternalAnalytics => "internal_analytics",
            Self::DerivedDataCreation => "derived_data_creation",
            Self::Display => "display",
            Self::ExternalRedistribution => "external_redistribution",
            Self::Retention => "retention",
            Self::Deletion => "deletion",
        }
    }
}

/// Agent whose request or grant is evaluated. An actor is a declared fact:
/// it is never inferred from a command name, a transport action or a proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    /// Fieldbook acts as the producer of a source observation or release.
    FieldbookProducer,
    /// Nirnay acts as the consumer of an admitted release.
    NirnayConsumer,
    /// The written-permission review authority acts on a grant.
    RightsAuthority,
    /// The publication key holder acts on canonical signed bytes.
    SigningAuthority,
}

impl Actor {
    /// Return the stable contract string for this actor.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FieldbookProducer => "fieldbook_producer",
            Self::NirnayConsumer => "nirnay_consumer",
            Self::RightsAuthority => "rights_authority",
            Self::SigningAuthority => "signing_authority",
        }
    }
}

/// Class of object an action acts upon. A kind is one component of an object
/// identity and never substitutes for the object's identity or version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    /// Reference record declared by a source.
    SourceReferenceRecord,
    /// Exact source bytes before normalization.
    RawSourceRecord,
    /// Normalized observation produced by Fieldbook.
    CanonicalObservation,
    /// Immutable archive of exact source bytes.
    RawArchive,
    /// Published, immutable NDC release.
    NdcRelease,
    /// Consumer-local copy admitted for research use.
    ResearchCopy,
    /// Derived research dataset referenced by an experiment.
    ResearchDataset,
    /// Artifact derived from an admitted research object.
    DerivedArtifact,
}

impl ObjectKind {
    /// Return the stable contract string for this object kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceReferenceRecord => "source_reference_record",
            Self::RawSourceRecord => "raw_source_record",
            Self::CanonicalObservation => "canonical_observation",
            Self::RawArchive => "raw_archive",
            Self::NdcRelease => "ndc_release",
            Self::ResearchCopy => "research_copy",
            Self::ResearchDataset => "research_dataset",
            Self::DerivedArtifact => "derived_artifact",
        }
    }
}

/// Named identity of one object, independent of its kind and version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectIdentity(String);

impl ObjectIdentity {
    /// Build an object identity after validating that it is non-blank.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidObjectIdentity`] for a blank identity.
    pub fn new(value: &str) -> Result<Self, RightsError> {
        if value.trim().is_empty() {
            return Err(RightsError::InvalidObjectIdentity);
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the validated object identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Explicit version of one object, independent of its kind and identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectVersion(String);

impl ObjectVersion {
    /// Build an object version after validating that it is non-blank.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidObjectVersion`] for a blank version.
    pub fn new(value: &str) -> Result<Self, RightsError> {
        if value.trim().is_empty() {
            return Err(RightsError::InvalidObjectVersion);
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the validated object version.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Full identity of the object an action acts upon: kind, identity and version.
///
/// A kind alone is not an object. Two archives with different identities, or
/// two versions of one identity, are different objects and need separate grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataObject {
    pub kind: ObjectKind,
    pub id: ObjectIdentity,
    pub version: ObjectVersion,
}

impl DataObject {
    /// Build a typed object from its three explicit components.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidObjectIdentity`] or
    /// [`RightsError::InvalidObjectVersion`] for a blank component.
    pub fn new(kind: ObjectKind, id: &str, version: &str) -> Result<Self, RightsError> {
        Ok(Self {
            kind,
            id: ObjectIdentity::new(id)?,
            version: ObjectVersion::new(version)?,
        })
    }

    /// Build a typed object from declaration-owned strings that were already
    /// validated by their source. The authorization gate still validates
    /// blank components before any comparison; no value is inferred here.
    #[must_use]
    pub fn from_declared(kind: ObjectKind, id: String, version: String) -> Self {
        Self {
            kind,
            id: ObjectIdentity(id),
            version: ObjectVersion(version),
        }
    }

    /// Explicit diagnostic object used only by a denial event. It is never a
    /// grant and never matches a request.
    #[must_use]
    fn diagnostic() -> Self {
        Self {
            kind: ObjectKind::SourceReferenceRecord,
            id: ObjectIdentity("diagnostic-no-object".to_owned()),
            version: ObjectVersion("diagnostic-no-version".to_owned()),
        }
    }
}

/// Named legal entity that holds the licence. A licence never belongs to a
/// command, a process or an operator flag.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Licensee(String);

impl Licensee {
    /// The declared internal licensee used by abstract requests. It is a
    /// constant identity, never derived from a command name or operator flag.
    pub fn system() -> Self {
        Self("fieldbook-operator".to_owned())
    }

    /// Build a licensee identity after validating that it is non-blank.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidQuery`] for a blank identity.
    pub fn new(value: &str) -> Result<Self, RightsError> {
        if value.trim().is_empty() {
            return Err(RightsError::InvalidQuery);
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the validated identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Market-depth modality covered by a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    L1,
    L2,
    L3,
    OrderByOrder,
}

impl Modality {
    /// Return the stable contract string for this modality.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::L1 => "l1",
            Self::L2 => "l2",
            Self::L3 => "l3",
            Self::OrderByOrder => "order_by_order",
        }
    }
}

/// How covered data is delivered to the licensee.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMethod {
    Stream,
    Snapshot,
    Batch,
    File,
    Query,
}

impl DeliveryMethod {
    /// Return the stable contract string for this delivery method.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stream => "stream",
            Self::Snapshot => "snapshot",
            Self::Batch => "batch",
            Self::File => "file",
            Self::Query => "query",
        }
    }
}

/// Explicit retention limit. `None` is a state, not an ambiguous absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RetentionLimit {
    /// No retention is granted. This is not the same as indefinite retention.
    None,
    /// Retention up to and including the stated maximum number of seconds.
    Bounded(u64),
    /// Indefinite retention, granted explicitly by the written permission.
    Indefinite,
}

/// Typed retention policy: an explicit limit plus an explicit purge rule.
///
/// A grant covers a request when the requested limit is no wider and the
/// requested purge rule is no weaker. Consequently a narrower request is
/// permitted, an indefinite request can never be covered by a bounded grant,
/// and an absent duration is unambiguously [`RetentionLimit::None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    pub limit: RetentionLimit,
    /// Whether covered data must be purged at the end of the interval.
    pub purge_required: bool,
}

impl Retention {
    /// The fail-closed rule: no retention is permitted.
    pub const NONE: Self = Self {
        limit: RetentionLimit::None,
        purge_required: true,
    };

    /// A bounded retention rule with a mandatory purge.
    #[must_use]
    pub const fn bounded(max_age_secs: u64) -> Self {
        Self {
            limit: RetentionLimit::Bounded(max_age_secs),
            purge_required: true,
        }
    }

    /// Whether this grant's policy covers the requested policy.
    #[must_use]
    pub fn contains(&self, requested: &Self) -> bool {
        let limit_ok = match (self.limit, requested.limit) {
            (RetentionLimit::Indefinite, _) => true,
            (RetentionLimit::Bounded(permitted), RetentionLimit::Bounded(asked)) => {
                asked <= permitted
            }
            (RetentionLimit::Bounded(_), RetentionLimit::None) => true,
            (RetentionLimit::None, RetentionLimit::None) => true,
            (RetentionLimit::None, _) => false,
            (RetentionLimit::Bounded(_), RetentionLimit::Indefinite) => false,
        };
        // A purge requirement in the grant cannot be weakened by the request.
        let purge_ok = !self.purge_required || requested.purge_required;
        limit_ok && purge_ok
    }
}

/// A scope dimension with four explicit states.
///
/// `NotApplicable` records that the dimension has no meaning for the
/// operation (for example, instruments for a source contact). `Named` is an
/// explicit enumerated set; an empty `Named` set contains no members and is
/// never converted into `All`. `Universe` names an explicitly versioned
/// universe and is the only unbounded-but-defined set a capture may use.
/// `All` is unrestricted and may only be written explicitly in an operator
/// rights record; it is never a runtime default or an inferred wildcard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ScopeSet<T> {
    /// The dimension does not apply to this operation.
    NotApplicable,
    /// An explicit set of named members. Empty means "no members".
    Named(Vec<T>),
    /// Every member of a named, versioned universe.
    Universe(String),
    /// Unrestricted; operator-written only, never inferred.
    All,
}

impl<T: PartialEq + Eq> ScopeSet<T> {
    /// Whether every requested member is covered by this permitted set.
    #[must_use]
    pub fn contains_all(&self, requested: &Self) -> bool {
        match (self, requested) {
            (Self::All, _) => true,
            (Self::NotApplicable, Self::NotApplicable) => true,
            (Self::Named(permitted), Self::Named(asked)) => {
                asked.iter().all(|item| permitted.contains(item))
            }
            // A named request is a subset of the declared versioned universe.
            (Self::Universe(_), Self::Named(_)) => true,
            (Self::Universe(permitted), Self::Universe(asked)) => permitted == asked,
            // A bounded grant never covers an unbounded or inapplicable request.
            (Self::Named(_) | Self::Universe(_) | Self::NotApplicable, _) => false,
        }
    }

    /// Whether this set is bounded by an explicit enumeration or universe.
    #[must_use]
    pub const fn is_bounded(&self) -> bool {
        !matches!(self, Self::All)
    }

    /// Whether the dimension applies to the operation.
    #[must_use]
    pub const fn is_applicable(&self) -> bool {
        !matches!(self, Self::NotApplicable)
    }
}

impl<T> Default for ScopeSet<T> {
    fn default() -> Self {
        Self::Named(Vec::new())
    }
}

/// Inclusive time window over the data itself, distinct from the effective
/// interval over which the decision is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Earliest covered data instant; absent means unbounded.
    pub from_us: Option<i64>,
    /// Latest covered data instant; absent means unbounded.
    pub to_us: Option<i64>,
}

impl TimeWindow {
    /// Whether this permitted window covers every instant of `requested`.
    ///
    /// `None` is mathematical infinity: `from_us = None` is `-inf` and
    /// `to_us = None` is `+inf`. A bounded endpoint therefore cannot cover an
    /// unbounded request endpoint, while an unbounded grant endpoint covers
    /// any bounded request endpoint.
    #[must_use]
    pub fn contains(&self, requested: &Self) -> bool {
        start_covered(self.from_us, requested.from_us) && end_covered(self.to_us, requested.to_us)
    }

    /// Reject a window whose start is after its end.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidTimeWindow`] for a reversed window.
    pub fn validate(&self) -> Result<(), RightsError> {
        match (self.from_us, self.to_us) {
            (Some(from), Some(to)) if from > to => Err(RightsError::InvalidTimeWindow),
            _ => Ok(()),
        }
    }
}

fn start_covered(permitted: Option<i64>, requested: Option<i64>) -> bool {
    match permitted {
        // -inf covers every requested start, including another -inf.
        None => true,
        Some(permitted) => match requested {
            // A finite bound cannot cover -inf.
            None => false,
            Some(requested) => permitted <= requested,
        },
    }
}

fn end_covered(permitted: Option<i64>, requested: Option<i64>) -> bool {
    match permitted {
        // +inf covers every requested end, including another +inf.
        None => true,
        Some(permitted) => match requested {
            // A finite bound cannot cover +inf.
            None => false,
            Some(requested) => permitted >= requested,
        },
    }
}

/// Full identity and scope of one authorization request or one grant.
///
/// The same shape is used on both sides so a comparison can never silently
/// ignore a field: every exact dimension must be equal and every scoped
/// dimension of the request must lie inside the grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationScope {
    pub actor: Actor,
    pub licensee: Licensee,
    pub venue: String,
    pub provider_id: String,
    pub source_id: String,
    pub dataset_id: String,
    pub product_id: String,
    pub segment: String,
    pub territory: CountryCode,
    pub operation: Operation,
    pub data_object: DataObject,
    pub usage_right: UsageRight,
    pub usage_mode: UsageMode,
    pub recipient_class: RecipientClass,
    pub recipient_identity: RecipientIdentity,
    pub purpose: Purpose,
    pub delivery_method: DeliveryMethod,
    pub retention: Retention,
    pub instruments: ScopeSet<String>,
    pub fields: ScopeSet<String>,
    pub modalities: ScopeSet<Modality>,
    pub data_time_window: TimeWindow,
    /// Rights-file-approved endpoint authorities. This is a grant-only field:
    /// an empty set denies every real egress. It is compared with an intent's
    /// endpoint separately from the exact and scoped dimensions.
    #[serde(default)]
    pub approved_endpoints: Vec<EndpointIdentity>,
}

impl AuthorizationScope {
    /// Reject a scope with an incomplete identity, a placeholder segment, a
    /// reversed interval or a scope set that is invalid for its operation.
    ///
    /// # Errors
    /// Returns a [`RightsError`] describing the first invalid field.
    pub fn validate(&self) -> Result<(), RightsError> {
        if self.data_object.id.as_str().trim().is_empty() {
            return Err(RightsError::InvalidObjectIdentity);
        }
        if self.data_object.version.as_str().trim().is_empty() {
            return Err(RightsError::InvalidObjectVersion);
        }
        if self.recipient_identity.as_str().trim().is_empty() {
            return Err(RightsError::InvalidRecipientIdentity);
        }
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
        validate_segment(&self.segment)?;
        self.data_time_window.validate()?;
        validate_scope_sets(self)?;
        Ok(())
    }

    /// Whether every exact dimension of `requested` equals this grant.
    /// Retention is scoped, not exact: a narrower retention request is allowed.
    #[must_use]
    pub fn exact_match(&self, requested: &Self) -> bool {
        self.actor == requested.actor
            && self.licensee == requested.licensee
            && self.venue == requested.venue
            && self.provider_id == requested.provider_id
            && self.source_id == requested.source_id
            && self.dataset_id == requested.dataset_id
            && self.product_id == requested.product_id
            && self.segment == requested.segment
            && self.territory == requested.territory
            && self.operation == requested.operation
            && self.data_object == requested.data_object
            && self.usage_right == requested.usage_right
            && self.usage_mode == requested.usage_mode
            && self.recipient_class == requested.recipient_class
            && self.recipient_identity == requested.recipient_identity
            && self.purpose == requested.purpose
            && self.delivery_method == requested.delivery_method
    }

    /// Whether every scoped dimension of `requested` lies inside this grant.
    #[must_use]
    pub fn scope_contains(&self, requested: &Self) -> bool {
        self.instruments.contains_all(&requested.instruments)
            && self.fields.contains_all(&requested.fields)
            && self.modalities.contains_all(&requested.modalities)
            && self.data_time_window.contains(&requested.data_time_window)
            && self.retention.contains(&requested.retention)
    }

    /// Full comparison used by authorization and by every egress recheck.
    #[must_use]
    pub fn matches_request(&self, requested: &Self) -> bool {
        self.exact_match(requested) && self.scope_contains(requested)
    }

    /// Whether the requested endpoint is inside the rights-file-approved set.
    /// An empty set authorizes no endpoint; there is no implicit host wildcard.
    #[must_use]
    pub fn contains_endpoint(&self, endpoint: &EndpointIdentity) -> bool {
        self.approved_endpoints.contains(endpoint)
    }

    /// A minimal diagnostic scope used only to record a denial that had no
    /// proof. It is not a grant and is never installed as a permission.
    #[must_use]
    pub fn denial_scope(venue: &str, operation: Operation) -> Self {
        Self {
            actor: Actor::RightsAuthority,
            licensee: Licensee::system(),
            venue: venue.to_owned(),
            provider_id: "diagnostic-no-provider".to_owned(),
            source_id: "diagnostic-no-source".to_owned(),
            dataset_id: "diagnostic-no-dataset".to_owned(),
            product_id: "diagnostic-no-product".to_owned(),
            segment: "diagnostic-no-segment".to_owned(),
            territory: CountryCode::new("US").unwrap_or_default(),
            operation,
            data_object: DataObject::diagnostic(),
            usage_right: UsageRight::RealTimeAccess,
            usage_mode: UsageMode::NonDisplay,
            recipient_class: RecipientClass::Internal,
            recipient_identity: RecipientIdentity("diagnostic-no-recipient".to_owned()),
            purpose: Purpose::InternalAnalysis,
            delivery_method: DeliveryMethod::Query,
            retention: Retention::NONE,
            instruments: ScopeSet::NotApplicable,
            fields: ScopeSet::NotApplicable,
            modalities: ScopeSet::NotApplicable,
            data_time_window: TimeWindow::default(),
            approved_endpoints: Vec::new(),
        }
    }
}

/// Legacy operational labels are not market segments and must never become a
/// wildcard by inference from a command name.
const LEGACY_SEGMENTS: [&str; 7] = [
    "source-contact",
    "reference",
    "history",
    "live-capture",
    "analytics",
    "display",
    "distribution",
];

/// Validate that a segment names a real venue market segment from the written
/// permission, not a placeholder or wildcard.
fn validate_segment(segment: &str) -> Result<(), RightsError> {
    let value = segment.trim();
    if value.is_empty()
        || value == "*"
        || LEGACY_SEGMENTS.contains(&value.to_ascii_lowercase().as_str())
    {
        return Err(RightsError::InvalidSegment);
    }
    Ok(())
}

/// Operation-aware validation of scope sets. A source contact has no data
/// scope; capture requires named members or an explicitly versioned universe
/// and can never rely on an unrestricted `All`.
fn validate_scope_sets(scope: &AuthorizationScope) -> Result<(), RightsError> {
    if scope.operation == Operation::SourceContact {
        if scope.instruments.is_applicable()
            || scope.fields.is_applicable()
            || scope.modalities.is_applicable()
        {
            return Err(RightsError::InvalidScopeSet);
        }
        return Ok(());
    }
    if scope.operation == Operation::RealTimeCapture
        && (scope.instruments == ScopeSet::All
            || scope.fields == ScopeSet::All
            || scope.modalities == ScopeSet::All)
    {
        return Err(RightsError::InvalidScopeSet);
    }
    Ok(())
}

/// The scope requested by an operation. This is the type formerly called
/// `AuthorizationQuery`; both names are retained for call-site clarity.
pub type AuthorizationQuery = AuthorizationScope;
/// The scope requested by a provider-facing command.
pub type AuthorizationRequest = AuthorizationScope;

/// Explicit builder for an authorization request.
///
/// No value is inferred from a command name, an exchange, an environment
/// variable or a previous proof. Every required field must be supplied and
/// [`AuthorizationRequestBuilder::build`] fails closed on the first omission.
#[derive(Debug, Default)]
pub struct AuthorizationRequestBuilder {
    actor: Option<Actor>,
    licensee: Option<Licensee>,
    venue: Option<String>,
    provider_id: Option<String>,
    source_id: Option<String>,
    dataset_id: Option<String>,
    product_id: Option<String>,
    segment: Option<String>,
    territory: Option<CountryCode>,
    operation: Option<Operation>,
    data_object: Option<DataObject>,
    usage_right: Option<UsageRight>,
    usage_mode: Option<UsageMode>,
    recipient_class: Option<RecipientClass>,
    recipient_identity: Option<RecipientIdentity>,
    purpose: Option<Purpose>,
    delivery_method: Option<DeliveryMethod>,
    retention: Option<Retention>,
    instruments: Option<ScopeSet<String>>,
    fields: Option<ScopeSet<String>>,
    modalities: Option<ScopeSet<Modality>>,
    data_time_window: Option<TimeWindow>,
    approved_endpoints: Option<Vec<EndpointIdentity>>,
}

impl AuthorizationRequestBuilder {
    /// Create an empty builder. No field has a default.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the exact declared actor.
    #[must_use]
    pub fn actor(mut self, value: Actor) -> Self {
        self.actor = Some(value);
        self
    }

    /// Set the exact named licensee.
    #[must_use]
    pub fn licensee(mut self, value: Licensee) -> Self {
        self.licensee = Some(value);
        self
    }

    /// Set the exact venue identity.
    #[must_use]
    pub fn venue(mut self, value: impl Into<String>) -> Self {
        self.venue = Some(value.into());
        self
    }

    /// Set the exact provider identity.
    #[must_use]
    pub fn provider_id(mut self, value: impl Into<String>) -> Self {
        self.provider_id = Some(value.into());
        self
    }

    /// Set the exact source identity.
    #[must_use]
    pub fn source_id(mut self, value: impl Into<String>) -> Self {
        self.source_id = Some(value.into());
        self
    }

    /// Set the exact dataset identity.
    #[must_use]
    pub fn dataset_id(mut self, value: impl Into<String>) -> Self {
        self.dataset_id = Some(value.into());
        self
    }

    /// Set the exact source-product identity.
    #[must_use]
    pub fn product_id(mut self, value: impl Into<String>) -> Self {
        self.product_id = Some(value.into());
        self
    }

    /// Set the exact venue market segment.
    #[must_use]
    pub fn segment(mut self, value: impl Into<String>) -> Self {
        self.segment = Some(value.into());
        self
    }

    /// Set the exact contractual territory.
    #[must_use]
    pub fn territory(mut self, value: CountryCode) -> Self {
        self.territory = Some(value);
        self
    }

    /// Set the exact lifecycle operation. No second producer enum exists.
    #[must_use]
    pub fn operation(mut self, value: Operation) -> Self {
        self.operation = Some(value);
        self
    }

    /// Set the exact typed data object: kind, identity and version.
    #[must_use]
    pub fn data_object(mut self, value: DataObject) -> Self {
        self.data_object = Some(value);
        self
    }

    /// Set the exact usage right.
    #[must_use]
    pub fn usage_right(mut self, value: UsageRight) -> Self {
        self.usage_right = Some(value);
        self
    }

    /// Set the exact display mode.
    #[must_use]
    pub fn usage_mode(mut self, value: UsageMode) -> Self {
        self.usage_mode = Some(value);
        self
    }

    /// Set the exact recipient class. `Internal` is a class, not an identity.
    #[must_use]
    pub fn recipient_class(mut self, value: RecipientClass) -> Self {
        self.recipient_class = Some(value);
        self
    }

    /// Set the exact named recipient identity.
    #[must_use]
    pub fn recipient_identity(mut self, value: RecipientIdentity) -> Self {
        self.recipient_identity = Some(value);
        self
    }

    /// Set the exact reviewed purpose.
    #[must_use]
    pub fn purpose(mut self, value: Purpose) -> Self {
        self.purpose = Some(value);
        self
    }

    /// Set the exact delivery method.
    #[must_use]
    pub fn delivery_method(mut self, value: DeliveryMethod) -> Self {
        self.delivery_method = Some(value);
        self
    }

    /// Set the exact typed retention policy.
    #[must_use]
    pub fn retention(mut self, value: Retention) -> Self {
        self.retention = Some(value);
        self
    }

    /// Set the exact instrument scope set.
    #[must_use]
    pub fn instruments(mut self, value: ScopeSet<String>) -> Self {
        self.instruments = Some(value);
        self
    }

    /// Set the exact field scope set.
    #[must_use]
    pub fn fields(mut self, value: ScopeSet<String>) -> Self {
        self.fields = Some(value);
        self
    }

    /// Set the exact modality scope set.
    #[must_use]
    pub fn modalities(mut self, value: ScopeSet<Modality>) -> Self {
        self.modalities = Some(value);
        self
    }

    /// Set the exact data-time window.
    #[must_use]
    pub fn data_time_window(mut self, value: TimeWindow) -> Self {
        self.data_time_window = Some(value);
        self
    }

    /// Add one rights-file-approved endpoint authority to the grant.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidEndpoint`] for an unparseable URL.
    pub fn endpoint(mut self, url: &str) -> Result<Self, RightsError> {
        let endpoint = EndpointIdentity::from_url(url)?;
        self.approved_endpoints
            .get_or_insert_with(Vec::new)
            .push(endpoint);
        Ok(self)
    }

    /// Set the whole approved endpoint set explicitly.
    #[must_use]
    pub fn approved_endpoints(mut self, endpoints: Vec<EndpointIdentity>) -> Self {
        self.approved_endpoints = Some(endpoints);
        self
    }

    /// Finish the request, failing closed on the first missing value or
    /// invalid scope. Nothing is defaulted and no wildcard is inferred.
    ///
    /// # Errors
    /// Returns [`RightsError::MissingField`] for an absent required value, or
    /// the validation error for an invalid value.
    pub fn build(self) -> Result<AuthorizationScope, RightsError> {
        macro_rules! required {
            ($field:literal, $value:expr) => {
                $value.ok_or(RightsError::MissingField { field: $field })?
            };
        }
        let scope = AuthorizationScope {
            actor: required!("actor", self.actor),
            licensee: required!("licensee", self.licensee),
            venue: required!("venue", self.venue),
            provider_id: required!("provider_id", self.provider_id),
            source_id: required!("source_id", self.source_id),
            dataset_id: required!("dataset_id", self.dataset_id),
            product_id: required!("product_id", self.product_id),
            segment: required!("segment", self.segment),
            territory: required!("territory", self.territory),
            operation: required!("operation", self.operation),
            data_object: required!("data_object", self.data_object),
            usage_right: required!("usage_right", self.usage_right),
            usage_mode: required!("usage_mode", self.usage_mode),
            recipient_class: required!("recipient_class", self.recipient_class),
            recipient_identity: required!("recipient_identity", self.recipient_identity),
            purpose: required!("purpose", self.purpose),
            delivery_method: required!("delivery_method", self.delivery_method),
            retention: required!("retention", self.retention),
            instruments: required!("instruments", self.instruments),
            fields: required!("fields", self.fields),
            modalities: required!("modalities", self.modalities),
            data_time_window: required!("data_time_window", self.data_time_window),
            // An unwritten approved set denies every real endpoint; there is
            // no implicit wildcard host.
            approved_endpoints: self.approved_endpoints.unwrap_or_default(),
        };
        scope.validate()?;
        Ok(scope)
    }
}

impl AuthorizationScope {
    /// Start an explicit request. Every value must be supplied by the caller.
    #[must_use]
    pub fn request() -> AuthorizationRequestBuilder {
        AuthorizationRequestBuilder::new()
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

/// Effective interval and scope of one recorded decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationIdentity {
    #[serde(flatten)]
    pub scope: AuthorizationScope,
    /// First instant at which the decision is effective.
    pub valid_from: i64,
    /// Last effective instant; open when absent.
    pub valid_until: Option<i64>,
}

impl AuthorizationIdentity {
    /// Whether this record applies to a request at `at_us`.
    #[must_use]
    pub fn matches(&self, request: &AuthorizationRequest, at_us: i64) -> bool {
        self.scope.matches_request(request)
            && self.valid_from <= at_us
            && self.valid_until.is_none_or(|end| at_us <= end)
    }

    /// Stable key for conflict detection. The interval is excluded so two
    /// revisions of the same authorization cannot coexist unnoticed.
    #[must_use]
    pub fn decision_key(&self) -> String {
        let scope = &self.scope;
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}",
            scope.actor.as_str(),
            scope.licensee.as_str(),
            scope.venue,
            scope.provider_id,
            scope.source_id,
            scope.dataset_id,
            scope.product_id,
            scope.segment,
            scope.territory.as_str(),
            scope.operation.as_str(),
            scope.data_object.kind.as_str(),
            scope.data_object.id.as_str(),
            scope.data_object.version.as_str(),
            scope.usage_right.as_str(),
            scope.usage_mode.as_str(),
            scope.recipient_class.as_str(),
            scope.recipient_identity.as_str(),
            scope.purpose.as_str(),
            scope.delivery_method.as_str(),
            match scope.retention.limit {
                RetentionLimit::None => "retention-none".to_owned(),
                RetentionLimit::Bounded(age) => format!("retention-{age}"),
                RetentionLimit::Indefinite => "retention-indefinite".to_owned(),
            },
            if scope.retention.purge_required {
                "purge"
            } else {
                "no-purge"
            },
            scope.instruments,
            scope.fields,
            scope.modalities,
            scope.data_time_window,
            scope.approved_endpoints,
        )
    }

    /// Reject an identity with no venue; an absent venue is never a wildcard.
    ///
    /// # Errors
    /// Returns a [`RightsError`] when the identity is incomplete.
    pub fn validate_identity(&self) -> Result<(), RightsError> {
        self.scope.validate()
    }

    /// Reject an interval whose end precedes its start.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidInterval`] for a reversed interval.
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

/// Audit evidence attached to one decision.
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
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidAudit`] for malformed evidence.
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
        if self.identity.scope.recipient_class == RecipientClass::Public
            && self.identity.scope.usage_right.requires_explicit_grant()
        {
            return false;
        }
        self.decision == RightDecision::Permitted
    }
}

/// Proof returned for one successful authorization. It is bound to exactly
/// one operation and to the complete scope that was checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationProof {
    #[serde(flatten)]
    pub scope: AuthorizationScope,
    pub at_us: i64,
    pub valid_from: i64,
    /// Rechecked at every egress attempt; an expired proof cannot be reused.
    pub valid_until: Option<i64>,
    pub licence_reference: String,
    pub licence_document_hash: String,
    pub contract_revision: u32,
    /// Rights-registry revision at issuance. A later revision invalidates the
    /// grant snapshot at the next checkpoint.
    pub registry_revision: u64,
    /// Immutable identity of the grant snapshot that produced this proof.
    pub grant_snapshot_id: String,
    /// Declared maximum lease duration in microseconds.
    pub lease_duration_us: u64,
    /// Recording authority from the rights file, never a literal placeholder.
    pub recording_authority: String,
}

/// Failure to authorize a dataset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RightsError {
    /// The query itself is incomplete.
    #[error("authorization query is incomplete")]
    InvalidQuery,
    /// An object identity is blank; no kind or command supplies one.
    #[error("authorization data object identity is missing")]
    InvalidObjectIdentity,
    /// An object version is blank; an unversioned object is not implied.
    #[error("authorization data object version is missing")]
    InvalidObjectVersion,
    /// The named recipient identity is blank; a class is not an identity.
    #[error("authorization recipient identity is missing")]
    InvalidRecipientIdentity,
    /// An explicit request is missing a required value; nothing was inferred.
    #[error("authorization request is missing required field `{field}`")]
    MissingField { field: &'static str },
    /// A segment is a placeholder or wildcard, not a real market segment.
    #[error("authorization segment is not a real market segment")]
    InvalidSegment,
    /// A time window has a start after its end.
    #[error("authorization time window has from > to")]
    InvalidTimeWindow,
    /// A scope set is not valid for the requested operation.
    #[error("authorization scope set is not valid for the operation")]
    InvalidScopeSet,
    /// A record or query has no venue, so no egress can be authorized.
    #[error("authorization identity has no venue")]
    VenueAbsent,
    /// No authorization was installed for this process.
    #[error("no active authorization for provider egress")]
    NoActiveAuthorization,
    /// The active authorization is no longer effective.
    #[error("active authorization has expired")]
    AuthorizationExpired,
    /// The active authorization does not cover the full requested identity.
    #[error("active authorization does not cover {operation} for {venue} ({reason})")]
    ScopeMismatch {
        operation: String,
        venue: String,
        reason: &'static str,
    },
    /// The effective interval is malformed.
    #[error("authorization interval is invalid")]
    InvalidInterval,
    /// The decision audit evidence is malformed.
    #[error("decision audit evidence is invalid")]
    InvalidAudit,
    /// A writable audit sink is mandatory and was not configured.
    #[error("provider authorization requires a configured audit directory")]
    AuditSinkAbsent,
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
    /// An endpoint has no parseable host or port.
    #[error("endpoint identity is incomplete")]
    InvalidEndpoint,
    /// A requested lease exceeds the declared maximum or is zero.
    #[error("authorization lease exceeds the declared maximum duration")]
    LeaseTooLong,
    /// The lease of the active session has expired.
    #[error("authorization lease expired; egress denied until reauthorization")]
    LeaseExpired,
    /// The registry revision advanced or the grant snapshot was invalidated.
    #[error("authorization grant snapshot is no longer valid")]
    GrantInvalidated,
    /// The authority could not be consulted at a reauthorization checkpoint.
    #[error("authority could not be refreshed; failing closed")]
    AuthorityRefreshFailed,
    /// The endpoint is not in the approved endpoint set of the grant.
    #[error("endpoint {endpoint} is not approved for this grant")]
    EndpointNotApproved { endpoint: String },
    /// The active session was cancelled.
    #[error("authorization session was cancelled: {reason}")]
    SessionCancelled { reason: String },
}

/// Fail-closed registry of effective-dated authorization records.
#[derive(Debug, Default)]
pub struct LicensingRegistry {
    records: Vec<AuthorizationRecord>,
    decisions: BTreeMap<String, DecisionAudit>,
    /// Monotonically increasing rights-registry revision. Every registration
    /// advances it, so an installed proof can be invalidated by policy change.
    revision: u64,
}

impl LicensingRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current rights-registry revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Register an authorization record.
    ///
    /// # Errors
    /// Returns a conflict when the same authorization identity and contract
    /// revision already carry a different decision, or when an overlapping
    /// revision of the same identity carries a contradictory decision.
    pub fn register(&mut self, record: AuthorizationRecord) -> Result<(), RightsError> {
        record.identity.validate_identity()?;
        record.identity.validate_interval()?;
        record.audit.validate()?;
        let revision_key = format!(
            "{}|{}",
            record.identity.decision_key(),
            record.audit.contract_revision
        );
        if let Some(existing) = self.decisions.get(&revision_key)
            && existing != &record.audit
        {
            return Err(RightsError::Conflict {
                dataset_id: record.identity.scope.dataset_id.clone(),
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
                    dataset_id: record.identity.scope.dataset_id.clone(),
                    reason: "overlapping decisions contradict for the same identity",
                });
            }
        }
        self.decisions.insert(revision_key, record.audit.clone());
        self.records.push(record);
        self.revision = self.revision.saturating_add(1);
        Ok(())
    }

    /// Authorize one fully identified request at an instant.
    ///
    /// # Errors
    /// Returns the first fail-closed denial described by [`RightsError`].
    pub fn authorize(
        &self,
        request: &AuthorizationRequest,
        at_us: i64,
    ) -> Result<AuthorizationProof, RightsError> {
        request.validate()?;
        let mut candidates: Vec<&AuthorizationRecord> = self
            .records
            .iter()
            .filter(|record| record.identity.matches(request, at_us))
            .collect();
        if candidates.is_empty() {
            return Err(RightsError::MissingRecord {
                dataset_id: request.dataset_id.clone(),
                territory: request.territory.as_str().to_owned(),
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
                dataset_id: request.dataset_id.clone(),
                territory: request.territory.as_str().to_owned(),
            })?;
        if winning.decision == RightDecision::Revoked {
            return Err(RightsError::Revoked {
                dataset_id: request.dataset_id.clone(),
                right: request.usage_right.as_str(),
            });
        }
        if !winning.grants(at_us) {
            return Err(RightsError::RightNotGranted {
                dataset_id: request.dataset_id.clone(),
                right: request.usage_right.as_str(),
            });
        }
        let snapshot_input = format!(
            "grant-snapshot/v1|{}|{}|{}|{}",
            self.revision,
            winning.identity.decision_key(),
            winning.audit.licence_document_hash,
            winning.audit.authority
        );
        Ok(AuthorizationProof {
            scope: request.clone(),
            at_us,
            valid_from: winning.identity.valid_from,
            valid_until: winning.identity.valid_until,
            licence_reference: winning.audit.licence_reference.clone(),
            licence_document_hash: winning.audit.licence_document_hash.clone(),
            contract_revision: winning.audit.contract_revision,
            registry_revision: self.revision,
            grant_snapshot_id: sha256_hex(snapshot_input.as_bytes()),
            lease_duration_us: MAX_LEASE_DURATION.as_micros() as u64,
            recording_authority: winning.audit.authority.clone(),
        })
    }
}

/// Runtime authorization source. Records come from a config file, never from
/// code, an environment variable, or a self-attested operator flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RightsFile {
    pub schema_version: u32,
    /// Licensee holding every decision in this file.
    pub licensee: Licensee,
    /// ISO 3166-1 alpha-2 territory for every decision in this file.
    pub territory: String,
    /// Recipient class for every decision in this file.
    pub recipient_class: RecipientClass,
    /// Named recipient identity for every decision in this file.
    pub recipient_identity: RecipientIdentity,
    #[serde(default)]
    pub rights: Vec<AuthorizationRecord>,
}

/// Machine-readable audit event for one authorization or egress decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionAuditEvent {
    pub schema_version: u32,
    /// Unique identifier for this event within the process.
    pub event_id: String,
    /// Process/run correlation identifier.
    pub run_id: String,
    pub process_id: u32,
    /// Monotonically increasing per-process event order.
    pub sequence: u64,
    /// UTC wall-clock instant in microseconds since the Unix epoch.
    pub recorded_at_us: i64,
    /// Monotonic nanoseconds since process start, where meaningful.
    pub monotonic_ns_since_start: Option<u64>,
    /// Actual typed operation requested, not a transport action name.
    pub operation: String,
    /// Exact actor whose request was evaluated.
    pub actor: String,
    pub venue: String,
    pub provider_id: String,
    pub source_id: String,
    pub dataset_id: String,
    pub product_id: String,
    pub segment: String,
    /// Exact object kind, identity and version evaluated by the gate.
    pub data_object: DataObject,
    pub licensee: String,
    pub territory: String,
    pub usage_right: String,
    pub usage_mode: String,
    /// Exact recipient class evaluated by the gate.
    pub recipient_class: String,
    /// Exact named recipient identity evaluated by the gate.
    pub recipient_identity: String,
    pub purpose: String,
    pub delivery_method: String,
    pub retention: Retention,
    pub instruments: ScopeSet<String>,
    pub fields: ScopeSet<String>,
    pub modalities: ScopeSet<Modality>,
    pub data_time_window: TimeWindow,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Written-permission reference and contract revision of the evaluated
    /// grant. It is distinct from the immutable grant snapshot identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_evidence_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
    /// Recording authority from the rights file, when the event is tied to a grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recording_authority: Option<String>,
    /// Active session id for lifecycle events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Rights registry revision observed at the event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_revision: Option<u64>,
    /// Immutable grant snapshot identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_snapshot_id: Option<String>,
    /// Lease expiry instant in microseconds since the Unix epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_expires_at_us: Option<i64>,
    /// Endpoint authority checked by this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub policy_version: u32,
    pub software_version: String,
}

/// Optional lifecycle metadata attached to an audit event.
#[derive(Debug, Clone, Default)]
pub struct AuditContext {
    pub recording_authority: Option<String>,
    pub session_id: Option<String>,
    pub registry_revision: Option<u64>,
    pub grant_snapshot_id: Option<String>,
    pub lease_expires_at_us: Option<i64>,
    pub endpoint: Option<String>,
}

static AUDIT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn monotonic_ns_since_start() -> Option<u64> {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    let start = &*START;
    Some(
        start
            .elapsed()
            .as_nanos()
            .min(u64::MAX as u128)
            .try_into()
            .unwrap_or(u64::MAX),
    )
}

/// A validated, writable audit destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditSink {
    directory: PathBuf,
    run_id: String,
    policy_version: u32,
}

impl AuditSink {
    /// Validate that `directory` is configured and writable.
    ///
    /// The check writes and removes one probe file through the same atomic,
    /// `fsync`ing path used for real events, so an unwritable sink rejects
    /// authorization before any proof can exist.
    ///
    /// # Errors
    /// Returns an error when the path is blank or cannot be written.
    pub fn new(directory: &Path, policy_version: u32) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !directory.as_os_str().is_empty(),
            "audit directory must not be empty"
        );
        std::fs::create_dir_all(directory)
            .with_context(|| format!("creating audit directory `{}`", directory.display()))?;
        let probe = directory.join(format!(
            ".audit-probe-{}-{}.json",
            std::process::id(),
            AUDIT_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let marker = serde_json::json!({ "audit_probe": true });
        write_json_atomic(&probe, &marker)
            .with_context(|| format!("probing audit directory `{}`", directory.display()))?;
        std::fs::remove_file(&probe)
            .with_context(|| format!("removing audit probe in `{}`", directory.display()))?;
        Ok(Self {
            directory: directory.to_path_buf(),
            run_id: format!("fieldbook-{}-{}", std::process::id(), policy_version),
            policy_version,
        })
    }

    /// Construct a sink without probing the directory.
    ///
    /// Production code uses [`Self::new`]. This constructor exists so offline
    /// tests can verify that an unwritable destination fails closed; it does
    /// not itself grant or record anything.
    #[must_use]
    pub fn without_probe(directory: &Path, policy_version: u32) -> Self {
        Self {
            directory: directory.to_path_buf(),
            run_id: format!("fieldbook-{}-{}", std::process::id(), policy_version),
            policy_version,
        }
    }

    /// Construct the full event for one decision.
    #[must_use]
    fn build_event(
        &self,
        scope: &AuthorizationScope,
        decision: &str,
        reason: Option<String>,
        evidence: Option<&DecisionAudit>,
        at_us: i64,
        context: AuditContext,
    ) -> DecisionAuditEvent {
        let sequence = AUDIT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        DecisionAuditEvent {
            schema_version: 1,
            event_id: format!("{}-{}-{sequence}", std::process::id(), at_us),
            run_id: self.run_id.clone(),
            process_id: std::process::id(),
            sequence,
            recorded_at_us: at_us,
            monotonic_ns_since_start: monotonic_ns_since_start(),
            operation: scope.operation.as_str().to_owned(),
            actor: scope.actor.as_str().to_owned(),
            venue: scope.venue.clone(),
            provider_id: scope.provider_id.clone(),
            source_id: scope.source_id.clone(),
            dataset_id: scope.dataset_id.clone(),
            product_id: scope.product_id.clone(),
            segment: scope.segment.clone(),
            data_object: scope.data_object.clone(),
            licensee: scope.licensee.as_str().to_owned(),
            territory: scope.territory.as_str().to_owned(),
            usage_right: scope.usage_right.as_str().to_owned(),
            usage_mode: scope.usage_mode.as_str().to_owned(),
            recipient_class: scope.recipient_class.as_str().to_owned(),
            recipient_identity: scope.recipient_identity.as_str().to_owned(),
            purpose: scope.purpose.as_str().to_owned(),
            delivery_method: scope.delivery_method.as_str().to_owned(),
            retention: scope.retention,
            instruments: scope.instruments.clone(),
            fields: scope.fields.clone(),
            modalities: scope.modalities.clone(),
            data_time_window: scope.data_time_window,
            decision: decision.to_owned(),
            reason,
            reference: evidence.map(|audit| audit.licence_reference.clone()),
            grant_evidence_reference: evidence
                .map(|audit| format!("{}#{}", audit.licence_reference, audit.contract_revision)),
            evidence_digest: evidence.map(|audit| audit.licence_document_hash.clone()),
            recording_authority: context.recording_authority,
            session_id: context.session_id,
            registry_revision: context.registry_revision,
            grant_snapshot_id: context.grant_snapshot_id,
            lease_expires_at_us: context.lease_expires_at_us,
            endpoint: context.endpoint,
            policy_version: self.policy_version,
            software_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Commit one decision as its own atomically installed JSON file.
    ///
    /// # Errors
    /// Returns an error when the event cannot be durably written.
    pub fn record(
        &self,
        scope: &AuthorizationScope,
        decision: &str,
        reason: Option<String>,
        evidence: Option<&DecisionAudit>,
        at_us: i64,
    ) -> anyhow::Result<DecisionAuditEvent> {
        self.record_with_context(
            scope,
            decision,
            reason,
            evidence,
            at_us,
            AuditContext::default(),
        )
    }

    /// Commit one lifecycle event with its session, revision and lease metadata.
    ///
    /// # Errors
    /// Returns an error when the event cannot be durably written.
    pub fn record_with_context(
        &self,
        scope: &AuthorizationScope,
        decision: &str,
        reason: Option<String>,
        evidence: Option<&DecisionAudit>,
        at_us: i64,
        context: AuditContext,
    ) -> anyhow::Result<DecisionAuditEvent> {
        let event = self.build_event(scope, decision, reason, evidence, at_us, context);
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
            "{:020}-{}-{}-{}.json",
            event.recorded_at_us,
            safe(&event.operation),
            safe(&event.venue),
            event.sequence
        );
        let path = self.directory.join(name);
        write_json_atomic(&path, &event).context("writing authorization audit event")?;
        Ok(event)
    }

    /// Return the configured directory.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

/// Fail-closed authorization registry loaded from a runtime configuration file.
#[derive(Debug)]
pub struct RightsContext {
    registry: LicensingRegistry,
    sink: AuditSink,
    source: PathBuf,
}

impl RightsContext {
    /// Load authorization records from `path` into a validated audit sink.
    ///
    /// A missing, unreadable, malformed, or record-less file is an error: the
    /// caller must not proceed to any provider egress. A blank or unwritable
    /// `audit_dir` is likewise an error: no proof can be produced without a
    /// committed audit trail. Expired records are excluded rather than treated
    /// as grants.
    ///
    /// # Errors
    /// Returns an error for every fail-closed load condition.
    pub fn load(path: &Path, audit_dir: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading rights file `{}`", path.display()))?;
        let file = toml::from_str::<RightsFile>(&text)
            .with_context(|| format!("parsing rights file `{}`", path.display()))?;
        anyhow::ensure!(
            file.schema_version == 1,
            "unsupported rights schema version {}",
            file.schema_version
        );
        let file_licensee = Licensee::new(file.licensee.as_str())
            .map_err(|_| anyhow::anyhow!("invalid licensee in rights file"))?;
        let territory = CountryCode::new(&file.territory)
            .with_context(|| format!("invalid territory in rights file `{}`", path.display()))?;
        let sink = AuditSink::new(audit_dir, file.schema_version)
            .context("configuring the mandatory authorization audit sink")?;
        let now = now_us().context("reading the clock for rights validation")?;
        let mut registry = LicensingRegistry::new();
        for record in file.rights {
            // Root consistency: the file-level licensee and territory are not
            // decorative. A record that contradicts them is refused rather
            // than silently widening the root declaration.
            anyhow::ensure!(
                record.identity.scope.licensee == file_licensee,
                "record licensee `{}` contradicts the rights-file licensee `{}`",
                record.identity.scope.licensee.as_str(),
                file_licensee.as_str()
            );
            anyhow::ensure!(
                record.identity.scope.territory == territory,
                "record territory `{}` contradicts the rights-file territory `{}`",
                record.identity.scope.territory.as_str(),
                territory.as_str()
            );
            anyhow::ensure!(
                record.identity.scope.recipient_class == file.recipient_class,
                "record recipient class `{}` contradicts the rights-file recipient class `{}`",
                record.identity.scope.recipient_class.as_str(),
                file.recipient_class.as_str()
            );
            anyhow::ensure!(
                record.identity.scope.recipient_identity == file.recipient_identity,
                "record recipient identity `{}` contradicts the rights-file recipient identity `{}`",
                record.identity.scope.recipient_identity.as_str(),
                file.recipient_identity.as_str()
            );
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
            sink,
            source: path.to_path_buf(),
        };
        let load_scope = AuthorizationScope::denial_scope("*", Operation::SourceContact)
            .with(|scope| scope.territory = territory);
        context
            .sink
            .record(&load_scope, "rights_load", None, None, now)?;
        Ok(context)
    }

    /// Return the audit directory backing this context.
    #[must_use]
    pub fn audit_dir(&self) -> &Path {
        self.sink.directory()
    }

    /// Return the rights file that produced this context.
    #[must_use]
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Return the validated audit sink so multiple authorizations can share it.
    #[must_use]
    pub fn sink(&self) -> &AuditSink {
        &self.sink
    }

    /// Authorize one request, committing the decision before returning it.
    ///
    /// # Errors
    /// Returns an error for a denial and also fails closed when the audit
    /// event for a *permitted* decision cannot be committed. An audit failure
    /// on a denial never changes the denial into a permission.
    pub fn authorize(
        &self,
        request: &AuthorizationRequest,
        at_us: i64,
    ) -> anyhow::Result<AuthorizationProof> {
        let validation = request.validate();
        let outcome = match &validation {
            Err(error) => Err(error.clone()),
            Ok(()) => self.registry.authorize(request, at_us),
        };
        let evidence = outcome.as_ref().ok().map(|proof| DecisionAudit {
            licence_reference: proof.licence_reference.clone(),
            licence_document_hash: proof.licence_document_hash.clone(),
            contract_revision: proof.contract_revision,
            recorded_at_us: proof.at_us,
            // Preserve the recording authority written in the rights file.
            authority: proof.recording_authority.clone(),
        });
        let (decision, reason) = match &outcome {
            Ok(_) => ("grant".to_owned(), None),
            Err(error) => (error.to_string(), Some(error.to_string())),
        };
        let lifecycle =
            outcome
                .as_ref()
                .ok()
                .map_or_else(AuditContext::default, |proof| AuditContext {
                    recording_authority: Some(proof.recording_authority.clone()),
                    registry_revision: Some(proof.registry_revision),
                    grant_snapshot_id: Some(proof.grant_snapshot_id.clone()),
                    lease_expires_at_us: Some(proof.at_us.saturating_add(
                        i64::try_from(proof.lease_duration_us).unwrap_or(i64::MAX),
                    )),
                    ..AuditContext::default()
                });
        let audit_result = self.sink.record_with_context(
            request,
            &decision,
            reason,
            evidence.as_ref(),
            at_us,
            lifecycle,
        );
        match (outcome, audit_result) {
            (Ok(proof), Ok(_)) => Ok(proof),
            // A permitted decision without a committed event is not usable.
            (Ok(_), Err(error)) => Err(error),
            // A denial remains a denial even when its event could not be written.
            (Err(denial), _) => {
                validation?;
                Err(denial.into())
            }
        }
    }
}

/// One installed proof, its active session and the authority it refreshes from.
#[derive(Debug, Clone)]
struct ActiveAuthorization {
    proof: AuthorizationProof,
    sink: AuditSink,
    session: AuthorizationSession,
    authority: Option<Arc<dyn AuthorityRefresh>>,
}

#[derive(Debug, Default)]
struct GateState {
    active: Vec<ActiveAuthorization>,
    fallback_sink: Option<AuditSink>,
    next_session: u64,
}

/// Instance-scoped authorization state.
///
/// One gate holds many independent authorizations for different providers,
/// source products, segments and operations. Nothing is installed by default:
/// an empty gate denies every egress. The gate is cheaply cloneable so the same
/// instance can be shared with transport layers while remaining independent of
/// any other gate in the process.
#[derive(Debug, Clone, Default)]
pub struct AuthorizationGate {
    state: Arc<Mutex<GateState>>,
}

impl AuthorizationGate {
    /// Create an empty, fail-closed gate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, GateState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether the installed authorization covers the whole caller-supplied
    /// intent, including its endpoint. Time and lifecycle are checked separately.
    fn matches(item: &ActiveAuthorization, intent: &EgressIntent) -> bool {
        item.proof.scope.matches_request(&intent.to_scope())
            && item
                .proof
                .scope
                .contains_endpoint(&intent.endpoint_identity)
    }

    fn audit_parts(
        item: &ActiveAuthorization,
        intent: &EgressIntent,
    ) -> (AuditSink, AuditContext, DecisionAudit) {
        let context = AuditContext {
            recording_authority: Some(item.proof.recording_authority.clone()),
            session_id: Some(item.session.session_id.clone()),
            registry_revision: Some(item.proof.registry_revision),
            grant_snapshot_id: Some(item.proof.grant_snapshot_id.clone()),
            lease_expires_at_us: Some(item.session.expires_at_us),
            endpoint: Some(intent.endpoint_identity.authority()),
        };
        let evidence = DecisionAudit {
            licence_reference: item.proof.licence_reference.clone(),
            licence_document_hash: item.proof.licence_document_hash.clone(),
            contract_revision: item.proof.contract_revision,
            recorded_at_us: item.proof.at_us,
            authority: item.proof.recording_authority.clone(),
        };
        (item.sink.clone(), context, evidence)
    }

    /// Install one proof and start its active session.
    ///
    /// A second proof for the same full identity fails closed instead of
    /// widening an existing grant. Proofs for other providers, products,
    /// segments or operations coexist independently.
    ///
    /// # Errors
    /// Returns an error for an incomplete scope, an invalid lease or a duplicate.
    pub fn install(&self, proof: AuthorizationProof, sink: AuditSink) -> anyhow::Result<()> {
        self.install_with_authority(proof, sink, None).map(|_| ())
    }

    /// Install one proof with a refreshable authority for checkpoint checks.
    ///
    /// Returns the new active session id.
    ///
    /// # Errors
    /// Returns an error for an incomplete scope, an invalid lease or a duplicate.
    pub fn install_with_authority(
        &self,
        proof: AuthorizationProof,
        sink: AuditSink,
        authority: Option<Arc<dyn AuthorityRefresh>>,
    ) -> anyhow::Result<String> {
        proof.scope.validate()?;
        let at_us = proof.at_us;
        let snapshot = GrantSnapshot::new(
            proof.registry_revision,
            proof.grant_snapshot_id.clone(),
            proof.lease_duration_us,
            at_us,
        )?;
        let mut state = self.lock();
        if state
            .active
            .iter()
            .any(|item| item.proof.scope == proof.scope)
        {
            anyhow::bail!("an identical authorization is already installed in this gate");
        }
        let session_id = format!("session-{}", state.next_session);
        state.next_session = state.next_session.saturating_add(1);
        let session = AuthorizationSession {
            session_id: session_id.clone(),
            expires_at_us: snapshot.expires_at_us(),
            snapshot: snapshot.clone(),
            renewals: 0,
        };
        if state.fallback_sink.is_none() {
            state.fallback_sink = Some(sink.clone());
        }
        let context = AuditContext {
            recording_authority: Some(proof.recording_authority.clone()),
            session_id: Some(session_id.clone()),
            registry_revision: Some(snapshot.registry_revision),
            grant_snapshot_id: Some(snapshot.snapshot_id.clone()),
            lease_expires_at_us: Some(session.expires_at_us),
            ..AuditContext::default()
        };
        let evidence = DecisionAudit {
            licence_reference: proof.licence_reference.clone(),
            licence_document_hash: proof.licence_document_hash.clone(),
            contract_revision: proof.contract_revision,
            recorded_at_us: proof.at_us,
            authority: proof.recording_authority.clone(),
        };
        sink.record_with_context(&proof.scope, "grant", None, Some(&evidence), at_us, context)
            .context("committing grant audit event")?;
        state.active.push(ActiveAuthorization {
            proof,
            sink,
            session,
            authority,
        });
        Ok(session_id)
    }

    /// Evaluate the caller's intent against the gate.
    ///
    /// This is the single decision point used by every egress and checkpoint.
    /// The request is the caller's [`EgressIntent`]; it is never reconstructed
    /// from an installed proof.
    fn evaluate(
        &self,
        intent: &EgressIntent,
        at_us: i64,
        audit_egress: bool,
    ) -> anyhow::Result<AuthorizationProof> {
        intent.validate()?;
        let scope = intent.to_scope();
        let mut state = self.lock();
        let Some(index) = state
            .active
            .iter()
            .position(|item| Self::matches(item, intent))
        else {
            let error = if state.active.iter().any(|item| {
                item.proof.scope.matches_request(&scope)
                    && !item
                        .proof
                        .scope
                        .contains_endpoint(&intent.endpoint_identity)
            }) {
                RightsError::EndpointNotApproved {
                    endpoint: intent.endpoint_identity.authority(),
                }
            } else {
                RightsError::ScopeMismatch {
                    operation: intent.operation.as_str().to_owned(),
                    venue: intent.venue_id.clone(),
                    reason: "no live proof covers the full caller-supplied intent",
                }
            };
            let error: anyhow::Error = error.into();
            if let Some(sink) = state.fallback_sink.clone() {
                let _ = sink.record(
                    &scope,
                    "egress_denied",
                    Some(error.to_string()),
                    None,
                    at_us,
                );
            }
            return Err(error);
        };

        let (sink, context, evidence, session_id, expires_at, authority, proof) = {
            let item = &state.active[index];
            let (sink, context, evidence) = Self::audit_parts(item, intent);
            (
                sink,
                context,
                evidence,
                item.session.session_id.clone(),
                item.session.expires_at_us,
                item.authority.clone(),
                item.proof.clone(),
            )
        };

        let grant_expired =
            proof.valid_from > at_us || proof.valid_until.is_some_and(|end| at_us > end);
        if grant_expired {
            state.active.remove(index);
            let _ = sink.record_with_context(
                &scope,
                "grant_expired",
                Some(RightsError::AuthorizationExpired.to_string()),
                Some(&evidence),
                at_us,
                context,
            );
            return Err(RightsError::AuthorizationExpired.into());
        }
        if at_us > expires_at {
            state.active.remove(index);
            let _ = sink.record_with_context(
                &scope,
                "lease_expired",
                Some(RightsError::LeaseExpired.to_string()),
                Some(&evidence),
                at_us,
                context,
            );
            return Err(RightsError::LeaseExpired.into());
        }
        if let Some(authority) = authority {
            match authority.refresh() {
                Ok(current)
                    if current.revision == proof.registry_revision
                        && current.valid_snapshots.contains(&proof.grant_snapshot_id) => {}
                Ok(_) => {
                    state.active.remove(index);
                    let _ = sink.record_with_context(
                        &scope,
                        "grant_revoked",
                        Some(RightsError::GrantInvalidated.to_string()),
                        Some(&evidence),
                        at_us,
                        context,
                    );
                    return Err(RightsError::GrantInvalidated.into());
                }
                Err(error) => {
                    let _ = sink.record_with_context(
                        &scope,
                        "egress_denied",
                        Some(format!("{}: {error}", RightsError::AuthorityRefreshFailed)),
                        Some(&evidence),
                        at_us,
                        context,
                    );
                    return Err(RightsError::AuthorityRefreshFailed.into());
                }
            }
        }

        if audit_egress {
            // The permitted event is committed before the caller may egress.
            sink.record_with_context(
                &scope,
                "egress_permitted",
                None,
                Some(&evidence),
                at_us,
                context,
            )
            .context("committing egress authorization event")?;
        }
        let _ = session_id;
        Ok(proof)
    }

    /// Check the full request against a live authorization without auditing
    /// an egress. Used by callers that need a preflight decision only.
    ///
    /// # Errors
    /// Returns a fail-closed denial when no live authorization covers the intent.
    pub fn check_active(
        &self,
        intent: &EgressIntent,
        at_us: i64,
    ) -> anyhow::Result<AuthorizationProof> {
        self.evaluate(intent, at_us, false)
    }

    /// Reauthorize one egress attempt and commit its event before returning.
    /// No network side effect may begin until this returns `Ok`.
    ///
    /// # Errors
    /// Returns an error on denial and when a permitted egress event cannot be
    /// committed. Denial events are written when a sink is available.
    pub fn require_egress(&self, intent: &EgressIntent, at_us: i64) -> anyhow::Result<()> {
        self.evaluate(intent, at_us, true).map(|_| ())
    }

    /// Renew the lease of an active session after a successful authority refresh.
    ///
    /// # Errors
    /// Returns an error when the intent is not covered or the authority cannot
    /// be refreshed.
    pub fn renew_lease(&self, intent: &EgressIntent, at_us: i64) -> anyhow::Result<()> {
        intent.validate()?;
        let scope = intent.to_scope();
        let mut state = self.lock();
        let Some(index) = state
            .active
            .iter()
            .position(|item| Self::matches(item, intent))
        else {
            return Err(RightsError::ScopeMismatch {
                operation: intent.operation.as_str().to_owned(),
                venue: intent.venue_id.clone(),
                reason: "no session to renew for this intent",
            }
            .into());
        };
        let (sink, mut context, evidence, authority, expiry, duration) = {
            let item = &state.active[index];
            let (sink, context, evidence) = Self::audit_parts(item, intent);
            (
                sink,
                context,
                evidence,
                item.authority.clone(),
                item.session.expires_at_us,
                item.proof.lease_duration_us,
            )
        };
        if let Some(authority) = authority {
            let current = authority
                .refresh()
                .map_err(|_| RightsError::AuthorityRefreshFailed)?;
            if current.revision != state.active[index].proof.registry_revision
                || !current
                    .valid_snapshots
                    .contains(&state.active[index].proof.grant_snapshot_id)
            {
                let _ = sink.record_with_context(
                    &scope,
                    "grant_revoked",
                    Some(RightsError::GrantInvalidated.to_string()),
                    Some(&evidence),
                    at_us,
                    context,
                );
                state.active.remove(index);
                return Err(RightsError::GrantInvalidated.into());
            }
        }
        let new_expiry = at_us.saturating_add(i64::try_from(duration).unwrap_or(i64::MAX));
        state.active[index].session.expires_at_us = new_expiry;
        state.active[index].session.renewals =
            state.active[index].session.renewals.saturating_add(1);
        context.lease_expires_at_us = Some(new_expiry);
        let _ = expiry;
        sink.record_with_context(
            &scope,
            "lease_renewed",
            None,
            Some(&evidence),
            at_us,
            context,
        )
        .context("committing lease renewal event")?;
        Ok(())
    }

    /// Cancel the session covering `intent`, emitting a cancellation event.
    ///
    /// # Errors
    /// Returns an error when no active session covers the intent.
    pub fn cancel(&self, intent: &EgressIntent, reason: &str, at_us: i64) -> anyhow::Result<()> {
        let scope = intent.to_scope();
        let mut state = self.lock();
        let Some(index) = state
            .active
            .iter()
            .position(|item| Self::matches(item, intent))
        else {
            return Err(RightsError::SessionCancelled {
                reason: "no matching session".to_owned(),
            }
            .into());
        };
        let (sink, context, evidence) = Self::audit_parts(&state.active[index], intent);
        state.active.remove(index);
        sink.record_with_context(
            &scope,
            "session_cancelled",
            Some(reason.to_owned()),
            Some(&evidence),
            at_us,
            context,
        )
        .context("committing session cancellation event")?;
        Ok(())
    }

    /// Whether this gate holds at least one live proof.
    #[must_use]
    pub fn is_active(&self) -> bool {
        !self.lock().active.is_empty()
    }
}

// The binary's one-command-per-process entry point uses a lazily created
// gate instance. Unlike the removed single-proof `OnceLock`, this instance
// holds many independent proofs keyed by their full scope and is not a
// one-shot installation slot. Library consumers construct their own gates.
static DEFAULT_GATE: LazyLock<AuthorizationGate> = LazyLock::new(AuthorizationGate::new);

/// The binary's shared gate. Library callers should construct their own.
#[must_use]
pub fn default_gate() -> &'static AuthorizationGate {
    &DEFAULT_GATE
}

/// Install a proof into the binary's process-wide gate.
///
/// # Errors
/// Returns an error when the proof is incomplete or the gate already holds a
/// proof for the same full identity.
pub fn install_active_authorization(
    proof: AuthorizationProof,
    sink: AuditSink,
) -> anyhow::Result<()> {
    default_gate().install(proof, sink)
}

/// Enforce authorization at the common provider egress boundary. No HTTP
/// client or websocket is opened unless the caller-supplied [`EgressIntent`]
/// is covered by a live authorization in the shared gate.
///
/// # Errors
/// Returns the fail-closed denial; the network side effect must not proceed.
pub fn require_provider_egress(intent: &EgressIntent) -> anyhow::Result<()> {
    // Loopback test transports are not provider egress. This identity can never
    // be derived from a configured exchange, and the endpoint must itself be
    // loopback; a provider host is never covered by this exception.
    if intent.venue_id.eq_ignore_ascii_case("loopback") && intent.endpoint_identity.is_loopback() {
        return Ok(());
    }
    let now = now_us().context("reading the clock for egress authorization")?;
    if !default_gate().is_active() {
        return Err(RightsError::NoActiveAuthorization.into());
    }
    default_gate().require_egress(intent, now)
}

/// Authorize one caller-supplied egress intent from the runtime rights file
/// and install it into the shared gate with a refreshable authority.
///
/// Returns the authority handle so the owner can invalidate the grant during
/// a session; the gate observes the change at its next checkpoint.
///
/// # Errors
/// Returns an error for every fail-closed authorization condition.
pub fn authorize_egress_intent(
    settings: &Settings,
    intent: &EgressIntent,
) -> anyhow::Result<Arc<dyn AuthorityRefresh>> {
    intent.validate()?;
    let path = settings.governance.rights_file.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "provider egress requires a runtime authorization file: set [governance].rights_file or --rights-file"
        )
    })?;
    let audit_dir = settings.governance.audit_dir.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "provider egress requires a configured audit directory: set [governance].audit_dir or --rights-audit-dir"
        )
    })?;
    let context = RightsContext::load(path, audit_dir)?;
    let proof = context.authorize(&intent.to_scope(), now_us()?)?;
    let authority = Arc::new(InMemoryAuthority::new(
        proof.registry_revision,
        proof.grant_snapshot_id.clone(),
    ));
    default_gate().install_with_authority(
        proof,
        context.sink().clone(),
        Some(authority.clone()),
    )?;
    Ok(authority)
}

/// Authorize fully specified requests from the runtime rights file.
///
/// The caller supplies every exact value through
/// [`AuthorizationScope::request`]; nothing is reconstructed from a command
/// name, an exchange, an environment variable or an existing proof.
///
/// # Errors
/// Returns an error for every fail-closed authorization condition.
pub fn authorize_requests(
    settings: &Settings,
    requests: &[AuthorizationRequest],
) -> anyhow::Result<()> {
    let path = settings.governance.rights_file.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "provider egress requires a runtime authorization file: set [governance].rights_file or --rights-file"
        )
    })?;
    let audit_dir = settings.governance.audit_dir.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "provider egress requires a configured audit directory: set [governance].audit_dir or --rights-audit-dir"
        )
    })?;
    let context = RightsContext::load(path, audit_dir)?;
    let mut proofs = Vec::with_capacity(requests.len());
    for request in requests {
        proofs.push(context.authorize(request, now_us()?)?);
    }
    for proof in proofs {
        let authority: Arc<dyn AuthorityRefresh> = Arc::new(InMemoryAuthority::new(
            proof.registry_revision,
            proof.grant_snapshot_id.clone(),
        ));
        default_gate().install_with_authority(
            proof,
            context.sink().clone(),
            Some(authority.clone()),
        )?;
    }
    Ok(())
}

/// Authorize one provider-facing command from the runtime rights file.
///
/// Kept for callers that already hold an explicit [`AuthorizationRequest`].
/// No generic command-derived request exists.
///
/// # Errors
/// Returns an error for every fail-closed authorization condition.
pub fn authorize_command(settings: &Settings, request: AuthorizationRequest) -> anyhow::Result<()> {
    authorize_requests(settings, &[request])
}

/// Command-derived authorization is not permitted.
///
/// A command names an operation, not a provider, source product, venue,
/// segment, licensee, territory, purpose, recipient, endpoint or scope. A gated
/// command must supply an explicit `EgressIntent`; callers use
/// [`authorize_egress_intent`]. This function remains a fail-closed denial for
/// callers that still pass only operations.
///
/// # Errors
/// Always returns a fail-closed denial; the rights-file and audit-directory
/// preconditions are checked first so a missing configuration is reported.
pub fn authorize_operations(settings: &Settings, operations: &[Operation]) -> anyhow::Result<()> {
    let first = operations
        .first()
        .map_or("operation", |operation| operation.as_str());
    if settings.governance.rights_file.is_none() {
        anyhow::bail!(
            "{first} requires a runtime authorization file: set [governance].rights_file or --rights-file"
        );
    }
    if settings.governance.audit_dir.is_none() {
        anyhow::bail!(
            "{first} requires a configured audit directory: set [governance].audit_dir or --rights-audit-dir"
        );
    }
    anyhow::bail!(
        "{first} requires an explicit EgressIntent from the caller; generic command-derived scopes are not permitted"
    )
}

/// Whether an authorization decision has been installed for this process.
#[must_use]
pub fn has_active_authorization() -> bool {
    default_gate().is_active()
}

impl AuthorizationScope {
    /// Apply a mutation and return the result. Used by callers that derive a
    /// narrower request from a declared scope.
    #[must_use]
    pub fn with(mut self, mutate: impl FnOnce(&mut Self)) -> Self {
        mutate(&mut self);
        self
    }
}

impl AuthorizationGate {
    /// Install a proof described by its scope, interval and evidence.
    ///
    /// # Errors
    /// Returns an error when the evidence or scope is invalid.
    pub fn install_scope(
        &self,
        scope: AuthorizationScope,
        valid_from: i64,
        valid_until: Option<i64>,
        evidence: &DecisionAudit,
        sink: AuditSink,
    ) -> anyhow::Result<()> {
        evidence.validate().map_err(anyhow::Error::from)?;
        let proof = AuthorizationProof {
            scope,
            at_us: valid_from,
            valid_from,
            valid_until,
            licence_reference: evidence.licence_reference.clone(),
            licence_document_hash: evidence.licence_document_hash.clone(),
            contract_revision: evidence.contract_revision,
            registry_revision: 0,
            grant_snapshot_id: sha256_hex(
                format!("installed-scope|{}", evidence.licence_document_hash).as_bytes(),
            ),
            lease_duration_us: MAX_LEASE_DURATION.as_micros() as u64,
            recording_authority: evidence.authority.clone(),
        };
        self.install(proof, sink)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Abstract exact request used as the base for mismatch probes. Every
    /// value is supplied explicitly; no command-derived default exists.
    fn scope() -> AuthorizationScope {
        AuthorizationScope::request()
            .actor(Actor::FieldbookProducer)
            .data_object(
                DataObject::new(ObjectKind::RawSourceRecord, "object-a", "v1")
                    .expect("abstract object identity"),
            )
            .licensee(Licensee::new("licensee-a").expect("licensee"))
            .venue("venue-a")
            .provider_id("provider-a")
            .source_id("source-a")
            .dataset_id("quotes")
            .product_id("product-a")
            .segment("venue-a-equity-cash")
            .territory(CountryCode::new("US").expect("country code"))
            .operation(Operation::RealTimeCapture)
            .usage_right(UsageRight::HistoricalStorage)
            .usage_mode(UsageMode::NonDisplay)
            .recipient_class(RecipientClass::Internal)
            .recipient_identity(RecipientIdentity::new("recipient-a").expect("recipient identity"))
            .purpose(Purpose::HistoricalArchive)
            .delivery_method(DeliveryMethod::Stream)
            .retention(Retention::bounded(86_400))
            .instruments(ScopeSet::Named(vec![
                "inst-a".to_owned(),
                "inst-b".to_owned(),
            ]))
            .fields(ScopeSet::Named(vec!["bid".to_owned(), "ask".to_owned()]))
            .modalities(ScopeSet::Named(vec![Modality::L2]))
            .data_time_window(TimeWindow {
                from_us: Some(1_000),
                to_us: Some(9_000),
            })
            .build()
            .expect("explicit abstract request")
            .with(|scope| {
                scope.approved_endpoints = vec![
                    EndpointIdentity::from_url("wss://venue-a.example:443")
                        .expect("abstract approved endpoint"),
                ];
            })
    }

    /// Build the caller's explicit test request from a declared abstract scope.
    /// This is a test fixture convenience, not gate logic: the gate never
    /// derives a request from a proof.
    fn intent_for(scope: &AuthorizationScope) -> EgressIntent {
        let endpoint = scope
            .approved_endpoints
            .first()
            .cloned()
            .unwrap_or_else(|| EndpointIdentity {
                scheme: "wss".to_owned(),
                host: "venue-a.example".to_owned(),
                port: 443,
            });
        EgressIntent::builder()
            .provider_id(scope.provider_id.clone())
            .source_id(scope.source_id.clone())
            .source_product_id(scope.product_id.clone())
            .venue_id(scope.venue.clone())
            .segment_id(scope.segment.clone())
            .dataset_id(scope.dataset_id.clone())
            .actor(scope.actor)
            .operation(scope.operation)
            .data_object(scope.data_object.clone())
            .purpose(scope.purpose)
            .usage_mode(scope.usage_mode)
            .usage_right(scope.usage_right)
            .licensee(scope.licensee.clone())
            .recipient_class(scope.recipient_class)
            .recipient_identity(scope.recipient_identity.clone())
            .territory(scope.territory.clone())
            .instruments(scope.instruments.clone())
            .fields(scope.fields.clone())
            .modalities(scope.modalities.clone())
            .data_time_window(scope.data_time_window)
            .retention_request(scope.retention)
            .delivery_method(scope.delivery_method)
            .endpoint_identity(endpoint)
            .build()
            .expect("explicit abstract egress intent")
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
                scope: scope_with(|item| {
                    item.provider_id = provider.to_owned();
                    item.territory = CountryCode::new(territory).expect("country code");
                }),
                valid_from,
                valid_until,
            },
            decision,
            audit: DecisionAudit {
                licence_reference: format!("licence-{provider}-{revision}"),
                licence_document_hash: format!("{revision:064x}"),
                contract_revision: revision,
                recorded_at_us: valid_from,
                authority: "contract-registry".to_owned(),
            },
        }
    }

    fn scope_with(mutate: impl FnOnce(&mut AuthorizationScope)) -> AuthorizationScope {
        let mut value = scope();
        mutate(&mut value);
        value
    }

    fn sink(directory: &Path) -> AuditSink {
        AuditSink::new(directory, 1).expect("audit sink")
    }

    fn rights_file(records: Vec<AuthorizationRecord>) -> RightsFile {
        RightsFile {
            schema_version: 1,
            licensee: Licensee::new("licensee-a").expect("licensee"),
            territory: "US".to_owned(),
            recipient_class: RecipientClass::Internal,
            recipient_identity: RecipientIdentity::new("recipient-a").expect("recipient identity"),
            rights: records,
        }
    }

    fn write_rights(directory: &Path, records: Vec<AuthorizationRecord>) -> PathBuf {
        let path = directory.join("rights.toml");
        std::fs::write(
            &path,
            toml::to_string(&rights_file(records)).expect("serde rights file"),
        )
        .expect("write rights file");
        path
    }

    fn permitted_record(request: &AuthorizationScope) -> AuthorizationRecord {
        AuthorizationRecord {
            identity: AuthorizationIdentity {
                scope: request.clone(),
                valid_from: 0,
                valid_until: None,
            },
            decision: RightDecision::Permitted,
            audit: DecisionAudit {
                licence_reference: "contract-1".to_owned(),
                licence_document_hash: "a".repeat(64),
                contract_revision: 1,
                recorded_at_us: 0,
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
            registry.authorize(&scope(), 99).is_err(),
            "future grant denied"
        );
        assert!(
            registry.authorize(&scope(), 150).is_ok(),
            "effective grant permits"
        );
        assert!(
            registry.authorize(&scope(), 201).is_err(),
            "expired grant denied"
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
            registry.authorize(&scope(), 1).is_err(),
            "another provider's grant cannot authorize provider-a"
        );
    }

    #[test]
    fn conflicting_decisions_fail_closed() {
        let mut registry = LicensingRegistry::new();
        let mut request = scope();
        request.usage_right = UsageRight::Redistribution;
        let mut grant = record(RightDecision::Permitted, "provider-a", "US", 0, None, 1);
        grant.identity.scope.usage_right = UsageRight::Redistribution;
        let mut ban = record(RightDecision::Prohibited, "provider-a", "US", 0, None, 2);
        ban.identity.scope.usage_right = UsageRight::Redistribution;
        registry.register(grant).expect("grant registered");
        assert!(
            matches!(registry.register(ban), Err(RightsError::Conflict { .. })),
            "a contradictory decision for the same identity is refused"
        );
        assert!(
            registry.authorize(&request, 1).is_ok(),
            "original grant remains"
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
        registry
            .register(record(
                RightDecision::Revoked,
                "provider-a",
                "US",
                50,
                None,
                2,
            ))
            .expect("revocation registered");
        assert!(
            registry.authorize(&scope(), 49).is_ok(),
            "grant held before revocation"
        );
        assert!(
            matches!(
                registry.authorize(&scope(), 50),
                Err(RightsError::Revoked { .. })
            ),
            "revocation takes effect at its timestamp"
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
            registry.authorize(&scope(), 1).is_err(),
            "GB grant cannot authorize US"
        );
    }

    #[test]
    fn public_access_never_grants_retention() {
        let mut registry = LicensingRegistry::new();
        let mut public = record(RightDecision::Permitted, "provider-a", "US", 0, None, 1);
        public.identity.scope.recipient_class = RecipientClass::Public;
        registry
            .register(public)
            .expect("public decision registered");
        let mut request = scope();
        request.recipient_class = RecipientClass::Public;
        assert!(
            registry.authorize(&request, 1).is_err(),
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
        let proof = registry.authorize(&scope(), 1).expect("authorization");
        assert_eq!(
            proof.licence_reference, "licence-provider-a-7",
            "assertion context at line 1912"
        );
        assert_eq!(proof.contract_revision, 7, "assertion context at line 1913");
        assert_eq!(
            proof.scope.purpose,
            Purpose::HistoricalArchive,
            "assertion context at line 1914"
        );
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
            registry.authorize(&scope(), 50).is_ok(),
            "earlier window granted"
        );
        assert!(
            registry.authorize(&scope(), 150).is_err(),
            "later window prohibited"
        );
    }

    #[test]
    fn revision_keys_include_full_identity() {
        let mut registry = LicensingRegistry::new();
        let mut first = record(RightDecision::Permitted, "provider-a", "US", 0, None, 1);
        first.audit.licence_document_hash = "a".repeat(64);
        let mut second = first.clone();
        second.identity.scope.product_id = "product-b".to_owned();
        second.audit.licence_document_hash = "b".repeat(64);
        let mut third = first.clone();
        third.identity.scope.source_id = "source-b".to_owned();
        third.audit.licence_document_hash = "c".repeat(64);
        registry.register(first).expect("first product registered");
        registry
            .register(second)
            .expect("second product registered");
        registry.register(third).expect("second source registered");
        assert_eq!(
            registry.records.len(),
            3,
            "unrelated identities cannot collide"
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
                registry.authorize(&scope(), 75),
                Err(RightsError::Revoked { .. })
            ),
            "revocation applies before reinstatement"
        );
        assert!(
            registry.authorize(&scope(), 150).is_ok(),
            "reinstated grant permits"
        );
    }

    #[test]
    fn malformed_interval_and_audit_are_refused() {
        let mut registry = LicensingRegistry::new();
        let mut invalid_interval =
            record(RightDecision::Permitted, "provider-a", "US", 10, Some(9), 1);
        invalid_interval.audit.licence_document_hash = "a".repeat(64);
        assert!(
            matches!(
                registry.register(invalid_interval),
                Err(RightsError::InvalidInterval)
            ),
            "invalid intervals are refused"
        );
        let mut invalid_audit = record(RightDecision::Permitted, "provider-a", "US", 0, None, 1);
        invalid_audit.audit.licence_document_hash = "not-a-digest".to_owned();
        assert!(
            matches!(
                registry.register(invalid_audit),
                Err(RightsError::InvalidAudit)
            ),
            "invalid audit evidence is refused"
        );
    }

    #[test]
    fn venue_is_required_in_both_request_and_record() {
        let mut registry = LicensingRegistry::new();
        let mut no_venue = permitted_record(&scope());
        no_venue.identity.scope.venue.clear();
        assert!(
            matches!(registry.register(no_venue), Err(RightsError::VenueAbsent)),
            "a record without a venue is refused"
        );
        let different = permitted_record(&scope_with(|item| item.venue = "venue-b".to_owned()));
        registry
            .register(different)
            .expect("different venue registered");
        assert!(
            registry.authorize(&scope(), 1).is_err(),
            "a venue-b grant cannot authorize venue-a"
        );
        let mut no_venue_request = scope();
        no_venue_request.venue.clear();
        assert!(
            registry.authorize(&no_venue_request, 1).is_err(),
            "absent venue denies"
        );
    }

    #[test]
    fn operation_mismatch_never_authorizes_another_operation() {
        let grant = permitted_record(&scope_with(|item| {
            item.operation = Operation::RealTimeCapture
        }));
        let mut registry = LicensingRegistry::new();
        registry.register(grant).expect("grant registered");
        let mut probe = scope();
        probe.operation = Operation::SourceContact;
        probe.instruments = ScopeSet::NotApplicable;
        probe.fields = ScopeSet::NotApplicable;
        probe.modalities = ScopeSet::NotApplicable;
        assert!(
            matches!(
                registry.authorize(&probe, 1),
                Err(RightsError::MissingRecord { .. })
            ),
            "a capture grant cannot authorize a source contact"
        );
    }

    #[test]
    fn operation_mismatch_is_enforced_at_the_egress_boundary() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let request = scope();
        let gate = AuthorizationGate::new();
        gate.install_scope(
            request.clone(),
            0,
            None,
            &permitted_record(&request).audit,
            sink(directory.path()),
        )
        .expect("proof installed");
        let contact = intent_for(&scope_with(|item| {
            item.operation = Operation::SourceContact;
            item.instruments = ScopeSet::NotApplicable;
            item.fields = ScopeSet::NotApplicable;
            item.modalities = ScopeSet::NotApplicable;
        }));
        assert!(
            gate.require_egress(&contact, 1).is_err(),
            "a capture proof must never authorize a source-contact egress"
        );
        assert!(
            gate.require_egress(&intent_for(&request), 1).is_ok(),
            "the matching operation is permitted"
        );
    }

    #[test]
    fn source_product_and_segment_mismatch_deny() {
        let grant = permitted_record(&scope());
        let mut registry = LicensingRegistry::new();
        registry.register(grant).expect("grant registered");
        let mut wrong_product = scope();
        wrong_product.product_id = "other-product".to_owned();
        assert!(
            registry.authorize(&wrong_product, 1).is_err(),
            "source product is exact"
        );
        let mut wrong_segment = scope();
        wrong_segment.segment = "diagnostics".to_owned();
        assert!(
            registry.authorize(&wrong_segment, 1).is_err(),
            "segment is exact"
        );
    }

    #[test]
    fn instrument_field_modality_and_time_window_scope_deny() {
        let grant = permitted_record(&scope());
        let mut registry = LicensingRegistry::new();
        registry.register(grant).expect("grant registered");
        let mut extra_instrument = scope();
        extra_instrument.instruments =
            ScopeSet::Named(vec!["inst-a".to_owned(), "inst-c".to_owned()]);
        assert!(
            registry.authorize(&extra_instrument, 1).is_err(),
            "extra instrument denied"
        );
        let mut extra_field = scope();
        extra_field.fields = ScopeSet::Named(vec!["bid".to_owned(), "mid".to_owned()]);
        assert!(
            registry.authorize(&extra_field, 1).is_err(),
            "extra field denied"
        );
        let mut extra_modality = scope();
        extra_modality.modalities = ScopeSet::Named(vec![Modality::L2, Modality::L3]);
        assert!(
            registry.authorize(&extra_modality, 1).is_err(),
            "extra modality denied"
        );
        let mut wide_window = scope();
        wide_window.data_time_window.to_us = Some(10_000);
        let denied = registry.authorize(&wide_window, 1).is_err();
        assert!(denied, "wide window denied");
    }

    #[test]
    fn rights_loader_fails_closed_on_missing_and_malformed_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let audit = directory.path().join("audit");
        let missing = directory.path().join("absent.toml");
        assert!(
            RightsContext::load(&missing, &audit).is_err(),
            "missing file denies"
        );
        let malformed = directory.path().join("malformed.toml");
        std::fs::write(&malformed, "schema_version = 1\n").expect("write malformed rights file");
        assert!(
            RightsContext::load(&malformed, &audit).is_err(),
            "malformed file denies"
        );
        let empty = write_rights(directory.path(), Vec::new());
        let context = RightsContext::load(&empty, &audit).expect("empty registry loads");
        assert!(
            context.authorize(&scope(), 1).is_err(),
            "no records means no authorization"
        );
    }

    #[test]
    fn expired_and_unknown_rights_never_authorize() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let audit = directory.path().join("audit");
        let mut expired = permitted_record(&scope());
        expired.identity.valid_until = Some(1);
        let expired_path = write_rights(directory.path(), vec![expired]);
        let expired_context =
            RightsContext::load(&expired_path, &audit).expect("expired file loads");
        let denied = expired_context.authorize(&scope(), 2).is_err();
        assert!(denied, "expired context denied");
        let mut unknown = permitted_record(&scope());
        unknown.decision = RightDecision::ContractRequired;
        let unknown_path = write_rights(directory.path(), vec![unknown]);
        let unknown_context =
            RightsContext::load(&unknown_path, &audit).expect("unknown file loads");
        assert!(
            unknown_context.authorize(&scope(), 2).is_err(),
            "conditional decision denies"
        );
    }

    #[test]
    fn missing_audit_dir_is_never_silently_accepted() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = write_rights(directory.path(), vec![permitted_record(&scope())]);
        let absent = Path::new("");
        assert!(
            RightsContext::load(&path, absent).is_err(),
            "assertion context at line 2199"
        );
        let unwritable = directory.path().join("rights.toml");
        assert!(
            AuditSink::new(&unwritable, 1).is_err(),
            "a regular file is not a writable audit directory"
        );
    }

    #[test]
    fn audit_write_failure_prevents_egress() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let request = scope();
        let gate = AuthorizationGate::new();
        let good = sink(&directory.path().join("good"));
        gate.install_scope(
            request.clone(),
            0,
            None,
            &permitted_record(&request).audit,
            good,
        )
        .expect("proof installed");
        // Replace the sink with one whose directory is a file so every commit
        // fails. A permitted egress must not proceed on that failure.
        let blocker = directory.path().join("blocker.json");
        std::fs::write(&blocker, "not a directory").expect("blocker");
        let broken = AuditSink {
            directory: blocker.clone(),
            run_id: "broken".to_owned(),
            policy_version: 1,
        };
        let broken_gate = AuthorizationGate::new();
        assert!(
            broken_gate
                .install_scope(
                    request.clone(),
                    0,
                    None,
                    &permitted_record(&request).audit,
                    broken,
                )
                .is_err(),
            "an unwritable sink refuses the grant"
        );
        // An unwritable audit sink prevents installation of the grant itself,
        // so no egress can be permitted under it.
        assert!(!broken_gate.is_active(), "failed install leaves gate empty");
        let denied = broken_gate
            .require_egress(&intent_for(&request), 1)
            .is_err();
        assert!(denied, "audit write failure denies egress");
        let permitted = gate.require_egress(&intent_for(&request), 1).is_ok();
        assert!(permitted, "writable audit sink permits matching egress");
    }

    #[test]
    fn successful_egress_commits_its_audit_event_before_returning() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let audit = directory.path().join("audit");
        let request = scope();
        let gate = AuthorizationGate::new();
        gate.install_scope(
            request.clone(),
            0,
            None,
            &permitted_record(&request).audit,
            sink(&audit),
        )
        .expect("proof installed");
        let before = std::fs::read_dir(&audit).expect("audit directory").count();
        gate.require_egress(&intent_for(&request), 1)
            .expect("egress permitted");
        let after: Vec<_> = std::fs::read_dir(&audit)
            .expect("audit directory")
            .collect();
        assert_eq!(after.len(), before + 1, "one egress event is committed");
        let path = after
            .into_iter()
            .map(|entry| entry.expect("entry").path())
            .find(|path| {
                std::fs::read_to_string(path)
                    .unwrap_or_default()
                    .contains("egress_permitted")
            })
            .expect("egress event");
        let event: DecisionAuditEvent =
            serde_json::from_str(&std::fs::read_to_string(path).expect("event text"))
                .expect("valid event");
        assert_eq!(
            event.decision, "egress_permitted",
            "assertion context at line 2289"
        );
        assert_eq!(
            event.operation, "real_time_capture",
            "assertion context at line 2290"
        );
        assert!(event.evidence_digest.is_some(), "rights digest is retained");
    }

    #[test]
    fn every_decision_writes_a_machine_readable_audit_event() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let audit = directory.path().join("audit");
        let path = write_rights(directory.path(), vec![permitted_record(&scope())]);
        let context = RightsContext::load(&path, &audit).expect("rights file loads");
        let proof = context.authorize(&scope(), 2).expect("decision granted");
        assert_eq!(
            proof.scope.venue, "venue-a",
            "assertion context at line 2301"
        );
        assert_eq!(
            proof.scope.operation,
            Operation::RealTimeCapture,
            "assertion context at line 2302"
        );
        let entries: Vec<_> = std::fs::read_dir(&audit)
            .expect("audit directory")
            .map(|entry| entry.expect("audit entry").path())
            .collect();
        assert!(entries.len() >= 2, "load and decision are both recorded");
        let decision_path = entries
            .iter()
            .find(|path| {
                std::fs::read_to_string(path)
                    .unwrap_or_default()
                    .contains("real_time_capture")
            })
            .expect("decision event");
        let text = std::fs::read_to_string(decision_path).expect("audit event");
        let event: DecisionAuditEvent = serde_json::from_str(&text).expect("valid audit event");
        assert_eq!(
            event.operation, "real_time_capture",
            "assertion context at line 2318"
        );
        assert_eq!(event.venue, "venue-a", "assertion context at line 2319");
        assert_eq!(event.decision, "grant", "the grant event is audited");
        assert_eq!(
            event.product_id, "product-a",
            "assertion context at line 2321"
        );
        assert_eq!(
            event.segment, "venue-a-equity-cash",
            "assertion context at line 2322"
        );
        assert_eq!(
            event.usage_right, "historical_storage",
            "assertion context at line 2323"
        );
        assert_eq!(event.recorded_at_us, 2, "assertion context at line 2324");
        assert!(
            event.event_id.contains(&event.process_id.to_string()),
            "assertion context at line 2325"
        );
        assert!(
            event.monotonic_ns_since_start.is_some(),
            "assertion context at line 2326"
        );
        assert!(
            event
                .evidence_digest
                .as_deref()
                .is_some_and(|digest| digest.len() == 64),
            "assertion context at line 2327"
        );
        assert_eq!(event.policy_version, 1, "assertion context at line 2333");
        assert_eq!(
            event.software_version,
            env!("CARGO_PKG_VERSION"),
            "assertion context at line 2334"
        );
    }

    #[test]
    fn revocation_and_expiry_during_a_long_running_session_deny_egress() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let request = scope();
        let gate = AuthorizationGate::new();
        gate.install_scope(
            request.clone(),
            0,
            Some(200),
            &permitted_record(&request).audit,
            sink(directory.path()),
        )
        .expect("proof installed");
        assert!(
            gate.check_active(&intent_for(&request), 100).is_ok(),
            "the grant is live at instant 100"
        );
        assert!(
            gate.require_egress(&intent_for(&request), 100).is_ok(),
            "the matching operation is permitted"
        );
        assert!(
            matches!(gate.check_active(&intent_for(&request), 201), Err(error) if error.to_string().contains("expired")),
            "expiry during a session denies further checks"
        );
        assert!(
            gate.require_egress(&intent_for(&request), 201).is_err(),
            "expiry during a session denies further egress"
        );
        let revoked_gate = AuthorizationGate::new();
        revoked_gate
            .install_scope(
                request.clone(),
                0,
                None,
                &permitted_record(&request).audit,
                sink(directory.path()),
            )
            .expect("proof installed");
        assert!(
            revoked_gate
                .require_egress(&intent_for(&request), 1)
                .is_ok(),
            "the grant is live before revocation"
        );
        let mut revoked = permitted_record(&request);
        revoked.decision = RightDecision::Revoked;
        let mut registry = LicensingRegistry::new();
        registry
            .register(permitted_record(&request))
            .expect("original grant");
        registry.register(revoked).expect("revocation registered");
        assert!(
            matches!(
                registry.authorize(&request, 2),
                Err(RightsError::Revoked { .. })
            ),
            "a later revocation denies a renewed decision"
        );
    }

    #[test]
    fn two_independent_source_authorizations_coexist_in_one_gate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let gate = AuthorizationGate::new();
        let first = scope_with(|item| {
            item.provider_id = "provider-a".to_owned();
            item.product_id = "product-a".to_owned();
            item.operation = Operation::RealTimeCapture;
        });
        let second = scope_with(|item| {
            item.provider_id = "provider-b".to_owned();
            item.product_id = "product-b".to_owned();
            item.segment = "venue-a-equity-derivatives".to_owned();
            item.operation = Operation::ReferenceDataRetrieval;
        });
        gate.install_scope(
            first.clone(),
            0,
            None,
            &permitted_record(&first).audit,
            sink(directory.path()),
        )
        .expect("first installed");
        gate.install_scope(
            second.clone(),
            0,
            None,
            &permitted_record(&second).audit,
            sink(directory.path()),
        )
        .expect("second installed");
        assert!(gate.is_active(), "assertion context at line 2429");
        assert!(
            gate.check_active(&intent_for(&first), 1).is_ok(),
            "first proof is usable"
        );
        assert!(
            gate.check_active(&intent_for(&second), 1).is_ok(),
            "second proof is usable"
        );
        assert!(
            gate.require_egress(&intent_for(&first), 1).is_ok(),
            "first provider egress permitted"
        );
        assert!(
            gate.require_egress(&intent_for(&second), 1).is_ok(),
            "second provider egress permitted"
        );
        let mut swapped = second.clone();
        swapped.provider_id = "provider-a".to_owned();
        assert!(
            gate.check_active(&intent_for(&swapped), 1).is_err(),
            "one provider's proof cannot authorize another provider's source"
        );
    }

    #[test]
    fn explicit_request_builder_never_infers_values() {
        let request = AuthorizationScope::request()
            .actor(Actor::FieldbookProducer)
            .data_object(
                DataObject::new(ObjectKind::RawSourceRecord, "object-a", "v1")
                    .expect("object identity"),
            )
            .licensee(Licensee::new("licensee-a").expect("licensee"))
            .venue("venue-a")
            .provider_id("provider-a")
            .source_id("source-a")
            .dataset_id("quotes")
            .product_id("exact-source-product")
            .segment("venue-a-equity-cash")
            .territory(CountryCode::new("US").expect("country code"))
            .operation(Operation::RealTimeCapture)
            .usage_right(UsageRight::HistoricalStorage)
            .usage_mode(UsageMode::NonDisplay)
            .recipient_class(RecipientClass::Internal)
            .recipient_identity(RecipientIdentity::new("recipient-a").expect("recipient identity"))
            .purpose(Purpose::ProprietaryOwnAccountTradingResearch)
            .delivery_method(DeliveryMethod::Stream)
            .retention(Retention::bounded(86_400))
            .instruments(ScopeSet::Named(vec!["inst-a".to_owned()]))
            .fields(ScopeSet::Named(vec!["bid".to_owned()]))
            .modalities(ScopeSet::Named(vec![Modality::L2]))
            .data_time_window(TimeWindow {
                from_us: Some(10),
                to_us: Some(20),
            })
            .build()
            .expect("explicit request");
        assert_eq!(
            request.product_id, "exact-source-product",
            "product identity is explicit"
        );
        assert_ne!(
            request.product_id,
            request.operation.as_str(),
            "product is not operation"
        );
        let purpose = request.purpose.as_str();
        let expected_purpose = "proprietary_own_account_trading_research";
        assert_eq!(purpose, expected_purpose, "purpose is verbatim");
        assert_ne!(
            request.territory,
            CountryCode::default(),
            "territory is explicit"
        );

        // Every required value is mandatory; nothing is inferred.
        let missing = AuthorizationScope::request().build();
        assert!(
            matches!(missing, Err(RightsError::MissingField { .. })),
            "missing field denied"
        );

        // Legacy operational labels are not market segments.
        let legacy_segment = scope_with(|item| item.segment = "live-capture".to_owned());
        assert_eq!(
            legacy_segment.validate(),
            Err(RightsError::InvalidSegment),
            "legacy segment denied"
        );
    }

    #[test]
    fn display_mode_is_separate_from_usage_right() {
        let mut display = scope();
        display.usage_mode = UsageMode::Display;
        assert_ne!(
            display.usage_mode,
            scope().usage_mode,
            "assertion context at line 2476"
        );
        let expected_right = scope().usage_right;
        assert_eq!(display.usage_right, expected_right, "usage right unchanged");
    }

    fn registry_for(request: &AuthorizationScope) -> LicensingRegistry {
        let mut registry = LicensingRegistry::new();
        registry
            .register(permitted_record(request))
            .expect("grant registered");
        registry
    }

    #[test]
    fn time_window_containment_truth_table() {
        let bounded = TimeWindow {
            from_us: Some(10),
            to_us: Some(20),
        };
        let unbounded = TimeWindow::default();
        let half_open_start = TimeWindow {
            from_us: None,
            to_us: Some(20),
        };
        let half_open_end = TimeWindow {
            from_us: Some(10),
            to_us: None,
        };
        assert!(
            !bounded.contains(&unbounded),
            "bounded cannot cover unbounded"
        );
        assert!(
            !half_open_start.contains(&unbounded),
            "half-bounded end cannot cover unbounded"
        );
        assert!(
            !half_open_end.contains(&unbounded),
            "half-bounded start cannot cover unbounded"
        );
        assert!(unbounded.contains(&bounded), "unbounded covers bounded");
        assert!(unbounded.contains(&unbounded), "unbounded covers unbounded");
        assert!(
            half_open_start.contains(&bounded),
            "-inf start covers a finite start"
        );
        assert!(
            half_open_end.contains(&bounded),
            "+inf end covers a finite end"
        );
        assert!(
            !bounded.contains(&half_open_start),
            "finite start cannot cover -inf"
        );
        assert!(
            !bounded.contains(&half_open_end),
            "finite end cannot cover +inf"
        );
    }

    #[test]
    fn data_time_window_from_must_not_exceed_to() {
        let reversed = TimeWindow {
            from_us: Some(20),
            to_us: Some(10),
        };
        assert_eq!(
            reversed.validate(),
            Err(RightsError::InvalidTimeWindow),
            "reversed window denied"
        );
        let mut request = scope();
        request.data_time_window = reversed;
        assert!(
            matches!(request.validate(), Err(RightsError::InvalidTimeWindow)),
            "a reversed data window is rejected"
        );
        let mut record = permitted_record(&scope());
        record.identity.valid_from = 20;
        record.identity.valid_until = Some(10);
        assert!(
            matches!(
                record.identity.validate_interval(),
                Err(RightsError::InvalidInterval)
            ),
            "a reversed operational interval is rejected"
        );
    }

    #[test]
    fn unbounded_request_requires_unbounded_grant() {
        let unbounded = TimeWindow::default();
        let bounded_grant = registry_for(&scope_with(|item| {
            item.data_time_window = TimeWindow {
                from_us: Some(10),
                to_us: Some(20),
            };
        }));
        let mut unbounded_request = scope();
        unbounded_request.data_time_window = unbounded;
        assert!(
            bounded_grant.authorize(&unbounded_request, 1).is_err(),
            "bounded grant cannot authorize an unbounded data window"
        );

        let half_bounded_grant = registry_for(&scope_with(|item| {
            item.data_time_window = TimeWindow {
                from_us: None,
                to_us: Some(20),
            };
        }));
        assert!(
            half_bounded_grant.authorize(&unbounded_request, 1).is_err(),
            "half-bounded grant cannot authorize an unbounded data window"
        );

        let unbounded_grant = registry_for(&scope_with(|item| {
            item.data_time_window = unbounded;
        }));
        assert!(
            unbounded_grant.authorize(&unbounded_request, 1).is_ok(),
            "unbounded grant covers an unbounded request"
        );
        assert!(
            unbounded_grant.authorize(&scope(), 1).is_ok(),
            "unbounded grant also covers a bounded request"
        );
    }

    #[test]
    fn scope_set_states_are_distinct() {
        let empty_named = ScopeSet::Named(Vec::<String>::new());
        let named_a = ScopeSet::Named(vec!["inst-a".to_owned()]);
        assert!(
            !empty_named.contains_all(&named_a),
            "an empty Named set is not All"
        );
        assert!(ScopeSet::All.contains_all(&named_a), "All covers Named");
        assert!(
            !named_a.contains_all(&ScopeSet::All),
            "Named cannot cover All"
        );
        let universe_v1 = ScopeSet::<String>::Universe("v1".to_owned());
        let universe_v2 = ScopeSet::<String>::Universe("v2".to_owned());
        assert!(
            !universe_v1.contains_all(&universe_v2),
            "a versioned universe does not cover another version"
        );
        assert!(
            universe_v1.contains_all(&named_a),
            "a named subset is inside the declared universe"
        );
        let na = ScopeSet::<String>::NotApplicable;
        assert!(
            na.contains_all(&na) && !named_a.contains_all(&na),
            "NotApplicable is a distinct state"
        );
        let default = ScopeSet::<String>::default();
        assert_eq!(default, empty_named, "default is empty Named, never All");
    }

    #[test]
    fn capture_requires_named_or_versioned_universe() {
        let all = scope_with(|item| {
            item.instruments = ScopeSet::All;
            item.fields = ScopeSet::All;
            item.modalities = ScopeSet::All;
        });
        assert_eq!(
            all.validate(),
            Err(RightsError::InvalidScopeSet),
            "capture cannot rely on an unrestricted All"
        );
        let universe = scope_with(|item| {
            item.instruments = ScopeSet::Universe("v1".to_owned());
            item.fields = ScopeSet::Universe("v1".to_owned());
            item.modalities = ScopeSet::Universe("v1".to_owned());
        });
        assert!(universe.validate().is_ok(), "a versioned universe is valid");
    }

    #[test]
    fn source_contact_uses_not_applicable_scope_sets() {
        let contact = scope_with(|item| {
            item.operation = Operation::SourceContact;
            item.instruments = ScopeSet::NotApplicable;
            item.fields = ScopeSet::NotApplicable;
            item.modalities = ScopeSet::NotApplicable;
        });
        assert!(
            contact.validate().is_ok(),
            "source contact has no data scope"
        );
        let named = scope_with(|item| {
            item.operation = Operation::SourceContact;
        });
        assert_eq!(
            named.validate(),
            Err(RightsError::InvalidScopeSet),
            "source contact cannot name a data scope"
        );
    }

    #[test]
    fn retention_policy_containment_and_narrower_requests() {
        let grant = Retention::bounded(100);
        let mut registry = LicensingRegistry::new();
        registry
            .register(permitted_record(&scope_with(|item| {
                item.retention = grant;
            })))
            .expect("bounded grant registered");
        let narrower = scope_with(|item| item.retention = Retention::bounded(50));
        assert!(
            registry.authorize(&narrower, 1).is_ok(),
            "a narrower retention request is permitted"
        );
        let none = scope_with(|item| item.retention = Retention::NONE);
        assert!(
            registry.authorize(&none, 1).is_ok(),
            "no retention is narrower than bounded retention"
        );
        let indefinite = scope_with(|item| {
            item.retention = Retention {
                limit: RetentionLimit::Indefinite,
                purge_required: false,
            };
        });
        assert!(
            registry.authorize(&indefinite, 1).is_err(),
            "an indefinite request cannot exceed a bounded grant"
        );
        assert!(
            !grant.contains(&Retention::bounded(200)),
            "bounded grant does not cover a wider bounded request"
        );
        assert!(
            !Retention::NONE.contains(&Retention::bounded(1)),
            "None is unambiguously no retention, not unbounded"
        );
        assert!(
            Retention {
                limit: RetentionLimit::Indefinite,
                purge_required: false,
            }
            .contains(&Retention::bounded(1_000)),
            "an explicit indefinite grant covers a bounded request"
        );
    }

    #[test]
    fn missing_licensee_is_denied() {
        let missing = AuthorizationScope::request()
            .actor(Actor::FieldbookProducer)
            .venue("venue-a")
            .build();
        assert!(
            matches!(
                missing,
                Err(RightsError::MissingField { field: "licensee" })
            ),
            "a request without a licensee is rejected"
        );
        let registry = registry_for(&scope());
        let other = scope_with(|item| {
            item.licensee = Licensee::new("licensee-b").expect("other licensee");
        });
        assert!(
            registry.authorize(&other, 1).is_err(),
            "a different licensee is not covered by the grant"
        );
    }

    #[test]
    fn wrong_purpose_is_denied_and_exact_wording_is_preserved() {
        let registry = registry_for(&scope());
        let other = scope_with(|item| {
            item.purpose = Purpose::ProprietaryOwnAccountTradingResearch;
        });
        assert!(
            registry.authorize(&other, 1).is_err(),
            "a different purpose is not covered by the grant"
        );
        assert_eq!(
            Purpose::ProprietaryOwnAccountTradingResearch.as_str(),
            "proprietary_own_account_trading_research",
            "the declared wording is preserved verbatim"
        );
        assert_ne!(
            Purpose::ProprietaryOwnAccountTradingResearch,
            Purpose::InternalAnalysis,
            "the declared purpose is never aliased to internal analysis"
        );
        assert_ne!(
            "proprietary_own_account_trading_research", "academic_research",
            "the declared purpose is never aliased to academic research"
        );
        assert_ne!(
            "proprietary_own_account_trading_research", "non_commercial_research",
            "the declared purpose is never aliased to non-commercial research"
        );
    }

    #[test]
    fn wrong_recipient_is_denied() {
        let registry = registry_for(&scope());
        let other = scope_with(|item| item.recipient_class = RecipientClass::Customer);
        assert!(
            registry.authorize(&other, 1).is_err(),
            "a different recipient class is not covered by the grant"
        );
    }

    #[test]
    fn ambiguous_grants_fail_closed() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(permitted_record(&scope()))
            .expect("permitted grant registered");
        let mut conflicting = permitted_record(&scope());
        conflicting.decision = RightDecision::Prohibited;
        conflicting.audit.contract_revision = 2;
        conflicting.audit.licence_document_hash = "b".repeat(64);
        assert!(
            matches!(
                registry.register(conflicting),
                Err(RightsError::Conflict { .. })
            ),
            "an overlapping contradictory grant is refused"
        );
        assert!(
            registry.authorize(&scope(), 1).is_ok(),
            "the original unambiguous grant remains"
        );
    }

    #[test]
    fn every_exact_identity_dimension_mismatch_denies() {
        let registry = registry_for(&scope());
        type Mutation = (&'static str, fn(&mut AuthorizationScope));
        let mutations: [Mutation; 8] = [
            ("provider", |item| {
                item.provider_id = "provider-b".to_owned()
            }),
            ("source", |item| item.source_id = "source-b".to_owned()),
            ("dataset", |item| {
                item.dataset_id = "other-dataset".to_owned()
            }),
            ("product", |item| {
                item.product_id = "other-product".to_owned()
            }),
            ("segment", |item| {
                item.segment = "venue-a-other-segment".to_owned()
            }),
            ("venue", |item| item.venue = "venue-b".to_owned()),
            ("territory", |item| {
                item.territory = CountryCode::new("GB").expect("GB")
            }),
            ("delivery", |item| {
                item.delivery_method = DeliveryMethod::File
            }),
        ];
        for (name, mutate) in mutations {
            let request = scope_with(mutate);
            assert!(
                registry.authorize(&request, 1).is_err(),
                "{name} mismatch must deny"
            );
        }
    }

    // The following cases use only abstract identifiers, versions and
    // instants. No market observation, venue report or provider input exists.

    fn object(kind: ObjectKind, id: &str, version: &str) -> DataObject {
        DataObject::new(kind, id, version).expect("abstract object")
    }

    /// A complete builder; individual tests remove exactly one required value.
    fn abstract_request() -> AuthorizationRequestBuilder {
        AuthorizationScope::request()
            .actor(Actor::FieldbookProducer)
            .data_object(object(ObjectKind::RawSourceRecord, "object-a", "v1"))
            .licensee(Licensee::new("licensee-a").expect("licensee"))
            .venue("venue-a")
            .provider_id("provider-a")
            .source_id("source-a")
            .dataset_id("dataset-a")
            .product_id("product-a")
            .segment("venue-a-segment-a")
            .territory(CountryCode::new("US").expect("country code"))
            .operation(Operation::RealTimeCapture)
            .usage_right(UsageRight::HistoricalStorage)
            .usage_mode(UsageMode::NonDisplay)
            .recipient_class(RecipientClass::Internal)
            .recipient_identity(RecipientIdentity::new("recipient-a").expect("recipient"))
            .purpose(Purpose::ProprietaryOwnAccountTradingResearch)
            .delivery_method(DeliveryMethod::Stream)
            .retention(Retention::bounded(100))
            .instruments(ScopeSet::Named(vec!["instrument-a".to_owned()]))
            .fields(ScopeSet::Named(vec!["field-a".to_owned()]))
            .modalities(ScopeSet::Named(vec![Modality::L2]))
            .data_time_window(TimeWindow {
                from_us: Some(1),
                to_us: Some(9),
            })
    }

    #[test]
    fn same_action_different_actor_is_denied() {
        let registry = registry_for(&scope());
        let request = scope_with(|item| item.actor = Actor::NirnayConsumer);
        assert_eq!(
            request.operation,
            scope().operation,
            "the action is unchanged"
        );
        assert!(
            registry.authorize(&request, 1).is_err(),
            "a consumer cannot use a producer's grant for the same action"
        );
        assert!(
            !scope().exact_match(&request),
            "exact matching binds the actor"
        );
    }

    #[test]
    fn object_kind_alone_is_not_an_object_identity() {
        let first = object(ObjectKind::RawArchive, "archive-a", "v1");
        let second = object(ObjectKind::RawArchive, "archive-b", "v1");
        assert_eq!(first.kind, second.kind, "both are raw archives");
        assert_ne!(first, second, "a shared kind is not a shared object");
        assert_eq!(
            ObjectKind::RawArchive.as_str(),
            "raw_archive",
            "archive kind label"
        );
    }

    #[test]
    fn different_object_kind_is_denied() {
        let registry = registry_for(&scope());
        let request = scope_with(|item| {
            item.data_object = object(ObjectKind::RawArchive, "object-a", "v1");
        });
        assert!(
            registry.authorize(&request, 1).is_err(),
            "the same id and version under another kind need another grant"
        );
    }

    #[test]
    fn same_object_kind_different_identity_is_denied() {
        let registry = registry_for(&scope());
        let request = scope_with(|item| {
            item.data_object = object(ObjectKind::RawSourceRecord, "object-b", "v1");
        });
        assert!(
            registry.authorize(&request, 1).is_err(),
            "a different object identity needs another grant"
        );
    }

    #[test]
    fn different_object_version_is_denied() {
        let registry = registry_for(&scope());
        let request = scope_with(|item| {
            item.data_object = object(ObjectKind::RawSourceRecord, "object-a", "v2");
        });
        assert!(
            registry.authorize(&request, 1).is_err(),
            "a new object version needs another grant"
        );
    }

    #[test]
    fn same_recipient_class_different_identity_is_denied() {
        let registry = registry_for(&scope());
        let request = scope_with(|item| {
            item.recipient_identity =
                RecipientIdentity::new("recipient-b").expect("other recipient identity");
        });
        assert_eq!(
            request.recipient_class,
            scope().recipient_class,
            "both requests are internal"
        );
        assert!(
            registry.authorize(&request, 1).is_err(),
            "Internal is a class, not a named recipient"
        );
    }

    #[test]
    fn named_licensee_mismatch_denies() {
        let registry = registry_for(&scope());
        let request = scope_with(|item| {
            item.licensee = Licensee::new("licensee-b").expect("other named licensee");
        });
        assert!(
            registry.authorize(&request, 1).is_err(),
            "another named licensee is not covered"
        );
    }

    #[test]
    fn wrong_purpose_denies_even_with_an_otherwise_exact_grant() {
        let grant = scope_with(|item| {
            item.purpose = Purpose::ProprietaryOwnAccountTradingResearch;
        });
        let registry = registry_for(&grant);
        let request = scope();
        assert_eq!(
            request.purpose,
            Purpose::HistoricalArchive,
            "the request carries a different purpose"
        );
        assert!(
            registry.authorize(&request, 1).is_err(),
            "purpose is bound to the grant"
        );
    }

    #[test]
    fn missing_actor_object_or_recipient_identity_is_rejected() {
        type Removal = (&'static str, fn(&mut AuthorizationRequestBuilder));
        let removals: [Removal; 4] = [
            ("actor", |builder| builder.actor = None),
            ("data_object", |builder| builder.data_object = None),
            ("recipient_class", |builder| builder.recipient_class = None),
            ("recipient_identity", |builder| {
                builder.recipient_identity = None
            }),
        ];
        for (field, remove) in removals {
            let mut builder = abstract_request();
            remove(&mut builder);
            assert!(
                matches!(builder.build(), Err(RightsError::MissingField { field: missing }) if missing == field),
                "a missing {field} cannot be defaulted"
            );
        }
        assert!(
            matches!(
                DataObject::new(ObjectKind::RawArchive, " ", "v1"),
                Err(RightsError::InvalidObjectIdentity)
            ),
            "a blank object identity is not an object"
        );
        assert!(
            matches!(
                DataObject::new(ObjectKind::RawArchive, "archive-a", ""),
                Err(RightsError::InvalidObjectVersion)
            ),
            "a blank version is not an object version"
        );
        assert!(
            matches!(
                RecipientIdentity::new(" "),
                Err(RightsError::InvalidRecipientIdentity)
            ),
            "a blank recipient identity is not an identity"
        );
    }

    #[test]
    fn unrelated_extra_grants_do_not_extend_a_request() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let mut registry = LicensingRegistry::new();
        let granted = scope_with(|item| {
            item.data_object = object(ObjectKind::RawArchive, "archive-a", "v1");
        });
        let extra = scope_with(|item| {
            item.data_object = object(ObjectKind::RawArchive, "archive-b", "v1");
        });
        registry
            .register(permitted_record(&granted))
            .expect("first grant");
        registry
            .register(permitted_record(&extra))
            .expect("unrelated grant");
        let ungranted = scope_with(|item| {
            item.data_object = object(ObjectKind::RawArchive, "archive-c", "v1");
        });
        assert!(
            registry.authorize(&ungranted, 1).is_err(),
            "a third object is not covered by either grant"
        );

        let gate = AuthorizationGate::new();
        gate.install_scope(
            granted.clone(),
            0,
            None,
            &permitted_record(&granted).audit,
            sink(directory.path()),
        )
        .expect("first proof installed");
        assert!(
            gate.check_active(&intent_for(&extra), 1).is_err(),
            "an extra grant at the registry is not an installed proof"
        );
        assert!(
            gate.check_active(&intent_for(&granted), 1).is_ok(),
            "the exact grant still works"
        );
    }

    #[test]
    fn audit_event_carries_evaluated_identities_and_grant_evidence() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let audit = directory.path().join("audit");
        let evaluated = scope_with(|item| {
            item.actor = Actor::NirnayConsumer;
            item.data_object = object(ObjectKind::ResearchDataset, "research-ds-a", "v3");
            item.recipient_class = RecipientClass::Participant;
            item.recipient_identity =
                RecipientIdentity::new("participant-a").expect("recipient identity");
        });
        let gate = AuthorizationGate::new();
        gate.install_scope(
            evaluated.clone(),
            0,
            None,
            &permitted_record(&evaluated).audit,
            sink(&audit),
        )
        .expect("proof installed");
        gate.require_egress(&intent_for(&evaluated), 1)
            .expect("egress permitted");

        let path = std::fs::read_dir(&audit)
            .expect("audit directory")
            .map(|entry| entry.expect("entry").path())
            .find(|path| {
                std::fs::read_to_string(path)
                    .unwrap_or_default()
                    .contains("egress_permitted")
            })
            .expect("permitted event");
        let event: DecisionAuditEvent =
            serde_json::from_str(&std::fs::read_to_string(path).expect("event text"))
                .expect("valid event");
        assert_eq!(event.actor, "nirnay_consumer", "actor recorded in audit");
        assert_eq!(
            event.data_object.kind,
            ObjectKind::ResearchDataset,
            "object kind recorded"
        );
        assert_eq!(
            event.data_object.id.as_str(),
            "research-ds-a",
            "object id recorded"
        );
        assert_eq!(
            event.data_object.version.as_str(),
            "v3",
            "object version recorded"
        );
        assert_eq!(
            event.recipient_class, "participant",
            "recipient class recorded"
        );
        assert_eq!(
            event.recipient_identity, "participant-a",
            "recipient identity recorded"
        );
        let evidence_ref = event.grant_evidence_reference.as_deref();
        assert_eq!(
            evidence_ref,
            Some("contract-1#1"),
            "evidence clause recorded"
        );
        assert_eq!(
            event.reference.as_deref(),
            Some("contract-1"),
            "reference recorded"
        );
        assert!(event.grant_snapshot_id.is_some(), "snapshot id recorded");
        assert_ne!(
            event.grant_evidence_reference, event.grant_snapshot_id,
            "written evidence and immutable snapshot are separate references"
        );
    }

    #[test]
    fn producer_operation_enum_has_fourteen_distinct_values() {
        let operations = [
            Operation::SourceContact,
            Operation::ReferenceDataRetrieval,
            Operation::HistoricalDataRetrieval,
            Operation::RealTimeCapture,
            Operation::RawStorage,
            Operation::Normalization,
            Operation::Replay,
            Operation::Backup,
            Operation::InternalAnalytics,
            Operation::DerivedDataCreation,
            Operation::Display,
            Operation::ExternalRedistribution,
            Operation::Retention,
            Operation::Deletion,
        ];
        let mut names: Vec<_> = operations.iter().map(|item| item.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 14, "no second producer operation enum exists");
    }
}
