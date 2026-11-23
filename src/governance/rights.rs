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
    collections::{BTreeMap, BTreeSet},
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

/// Exact, versioned identity of a membership universe.
///
/// A universe is named by an explicit version, a content digest and the
/// membership source that produced it. Data-as-of and knowledge-time windows
/// bound the interval for which that exact version may be consulted. Member
/// names are never resolved against present-day symbols: every containment
/// decision needs a recorded membership fact for the exact reference and time.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UniverseRef {
    /// Stable identity of the universe, independent of any single version.
    pub universe_id: String,
    /// Exact version of that universe. A new version is a new set.
    pub version: String,
    /// Lowercase hex SHA-256 digest of the exact version's membership bytes.
    pub digest: String,
    /// Named source that produced the membership facts.
    pub membership_source: String,
    /// Data-time interval for which this version may be consulted.
    pub valid_time: TimeWindow,
    /// Knowledge-time interval in which this version was known.
    pub knowledge_time: TimeWindow,
    /// Monotonic revision of the universe declaration; never zero.
    pub revision: u64,
}

impl UniverseRef {
    /// Build a universe reference, validating every component.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidUniverse`] for a blank component, a
    /// malformed digest, a zero revision or a reversed window.
    pub fn new(
        universe_id: &str,
        version: &str,
        digest: &str,
        membership_source: &str,
        valid_time: TimeWindow,
        knowledge_time: TimeWindow,
        revision: u64,
    ) -> Result<Self, RightsError> {
        let reference = Self {
            universe_id: universe_id.to_owned(),
            version: version.to_owned(),
            digest: digest.to_owned(),
            membership_source: membership_source.to_owned(),
            valid_time,
            knowledge_time,
            revision,
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Validate the shape of a declared universe reference.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidUniverse`] when any component is invalid.
    pub fn validate(&self) -> Result<(), RightsError> {
        if self.universe_id.trim().is_empty()
            || self.version.trim().is_empty()
            || self.membership_source.trim().is_empty()
            || !is_lowercase_sha256(&self.digest)
            || self.revision == 0
        {
            return Err(RightsError::InvalidUniverse);
        }
        self.valid_time.validate()?;
        self.knowledge_time.validate()?;
        Ok(())
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Explicit instants at which a member's universe membership is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipTime {
    /// Data-as-of instant of the requested observation.
    pub data_as_of: i64,
    /// Knowledge-time instant at which the membership was known.
    pub knowledge_as_of: i64,
}

/// One recorded membership fact. It is evidence, not a live symbol lookup.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UniverseMembership {
    /// Exact universe version whose membership is recorded.
    pub universe: UniverseRef,
    /// Named member whose membership is recorded.
    pub member: String,
    /// Data-as-of instant of the recorded fact.
    pub data_as_of: i64,
    /// Knowledge-time instant of the recorded fact.
    pub knowledge_as_of: i64,
}

/// Recorded, versioned membership evidence for universe containment.
///
/// The registry contains only facts inserted by a caller that holds the
/// membership evidence. It never consults a current instrument master, a
/// command name or a symbol string that happens to exist today.
#[derive(Debug, Clone, Default)]
pub struct UniverseMembershipRegistry {
    facts: std::collections::BTreeSet<UniverseMembership>,
}

impl UniverseMembershipRegistry {
    /// Create an empty, fail-closed membership registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one membership fact after checking it against the exact universe.
    ///
    /// # Errors
    /// Returns [`RightsError::InvalidUniverse`] or
    /// [`RightsError::InvalidUniverseMembership`] for invalid evidence.
    pub fn record(&mut self, membership: UniverseMembership) -> Result<(), RightsError> {
        membership.universe.validate()?;
        if membership.member.trim().is_empty() {
            return Err(RightsError::InvalidUniverseMembership);
        }
        let data_point = TimeWindow {
            from_us: Some(membership.data_as_of),
            to_us: Some(membership.data_as_of),
        };
        let knowledge_point = TimeWindow {
            from_us: Some(membership.knowledge_as_of),
            to_us: Some(membership.knowledge_as_of),
        };
        if !membership.universe.valid_time.contains(&data_point)
            || !membership
                .universe
                .knowledge_time
                .contains(&knowledge_point)
        {
            return Err(RightsError::InvalidUniverseMembership);
        }
        self.facts.insert(membership);
        Ok(())
    }

    /// Whether the exact universe contains the named member at both instants.
    #[must_use]
    pub fn contains(&self, universe: &UniverseRef, member: &str, at: MembershipTime) -> bool {
        self.facts.contains(&UniverseMembership {
            universe: universe.clone(),
            member: member.to_owned(),
            data_as_of: at.data_as_of,
            knowledge_as_of: at.knowledge_as_of,
        })
    }

    /// Number of recorded membership facts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.facts.len()
    }

    /// Whether no membership facts have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }
}

/// Requirement level of one dimension in the applicability matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionRequirement {
    /// An explicit value must be supplied.
    Required,
    /// A value is permitted without a declared requirement; a missing value
    /// is still never encoded as `NotApplicable`.
    Optional,
    /// The value must be supplied and is inherited from the upstream scope.
    Inherited,
    /// The dimension has no meaning for this operation and must be absent.
    NotApplicable,
    /// Supplying the dimension is forbidden for this operation.
    Prohibited,
}

impl DimensionRequirement {
    /// Return the stable contract string for this requirement.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::Optional => "optional",
            Self::Inherited => "inherited",
            Self::NotApplicable => "not_applicable",
            Self::Prohibited => "prohibited",
        }
    }

    const fn needs_value(self) -> bool {
        matches!(self, Self::Required | Self::Optional | Self::Inherited)
    }

    const fn needs_absent(self) -> bool {
        matches!(self, Self::NotApplicable | Self::Prohibited)
    }
}

/// Scope representations an operation may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeRepresentations {
    /// Whether an explicit named set is allowed.
    pub named: bool,
    /// Whether an exact versioned universe is allowed.
    pub universe: bool,
    /// Whether an explicitly written unrestricted set is allowed.
    pub all: bool,
}

const NO_SETS: ScopeRepresentations = ScopeRepresentations {
    named: false,
    universe: false,
    all: false,
};
const BOUNDED_SETS: ScopeRepresentations = ScopeRepresentations {
    named: true,
    universe: true,
    all: false,
};
const OPEN_SETS: ScopeRepresentations = ScopeRepresentations {
    named: true,
    universe: true,
    all: true,
};

/// Applicability of every validated dimension to one action-object pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applicability {
    /// Operation whose dimensions are described.
    pub operation: Operation,
    /// Object kind permitted for this operation.
    pub data_object_kind: ObjectKind,
    /// Provider requirement.
    pub provider: DimensionRequirement,
    /// Venue requirement.
    pub venue: DimensionRequirement,
    /// Segment requirement.
    pub segment: DimensionRequirement,
    /// Instrument requirement.
    pub instruments: DimensionRequirement,
    /// Field requirement.
    pub fields: DimensionRequirement,
    /// Modality requirement.
    pub modality: DimensionRequirement,
    /// Data-time requirement.
    pub data_time: DimensionRequirement,
    /// Retention requirement.
    pub retention: DimensionRequirement,
    /// Permitted scope representations for named dimensions.
    pub representations: ScopeRepresentations,
}

/// Outcome of applying the matrix to one scope before containment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicabilityDecision {
    /// Every required dimension is present and every representation is allowed.
    Applicable,
    /// The operation has no data dimensions; its absent shape is correct.
    NotApplicable,
    /// The object kind is not permitted for the operation.
    Prohibited,
    /// A dimension is missing, present where absent is required, or malformed.
    Invalid,
}

impl ApplicabilityDecision {
    /// Return the stable contract string for this decision.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applicable => "applicable",
            Self::NotApplicable => "not_applicable",
            Self::Prohibited => "prohibited",
            Self::Invalid => "invalid",
        }
    }
}

const fn matrix_entry(
    operation: Operation,
    kind: ObjectKind,
    provider: DimensionRequirement,
    sets: DimensionRequirement,
    data_time: DimensionRequirement,
    retention: DimensionRequirement,
    representations: ScopeRepresentations,
) -> Applicability {
    Applicability {
        operation,
        data_object_kind: kind,
        provider,
        venue: DimensionRequirement::Required,
        segment: DimensionRequirement::Required,
        instruments: sets,
        fields: sets,
        modality: sets,
        data_time,
        retention,
        representations,
    }
}

/// Applicability of one action-object pair, or `None` when the pair is
/// prohibited. An unlisted object kind never inherits another kind's matrix.
#[must_use]
pub const fn applicability_for(operation: Operation, kind: ObjectKind) -> Option<Applicability> {
    use DimensionRequirement as D;
    match operation {
        Operation::SourceContact => match kind {
            ObjectKind::SourceReferenceRecord | ObjectKind::RawSourceRecord => Some(matrix_entry(
                operation,
                kind,
                D::Required,
                D::NotApplicable,
                D::NotApplicable,
                D::NotApplicable,
                NO_SETS,
            )),
            _ => None,
        },
        Operation::ReferenceDataRetrieval => match kind {
            ObjectKind::SourceReferenceRecord => Some(matrix_entry(
                operation,
                kind,
                D::Required,
                D::Required,
                D::Required,
                D::Inherited,
                BOUNDED_SETS,
            )),
            _ => None,
        },
        Operation::HistoricalDataRetrieval => match kind {
            ObjectKind::CanonicalObservation | ObjectKind::RawArchive => Some(matrix_entry(
                operation,
                kind,
                D::Required,
                D::Required,
                D::Required,
                D::Required,
                BOUNDED_SETS,
            )),
            _ => None,
        },
        Operation::RealTimeCapture => match kind {
            ObjectKind::RawSourceRecord => Some(matrix_entry(
                operation,
                kind,
                D::Required,
                D::Required,
                D::Inherited,
                D::Inherited,
                BOUNDED_SETS,
            )),
            _ => None,
        },
        Operation::RawStorage => match kind {
            ObjectKind::RawSourceRecord | ObjectKind::RawArchive => Some(matrix_entry(
                operation,
                kind,
                D::Required,
                D::Inherited,
                D::Inherited,
                D::Required,
                BOUNDED_SETS,
            )),
            _ => None,
        },
        Operation::Normalization => match kind {
            ObjectKind::RawSourceRecord | ObjectKind::CanonicalObservation => Some(matrix_entry(
                operation,
                kind,
                D::Required,
                D::Inherited,
                D::Inherited,
                D::Inherited,
                BOUNDED_SETS,
            )),
            _ => None,
        },
        Operation::Replay => match kind {
            ObjectKind::RawArchive | ObjectKind::ResearchCopy => Some(matrix_entry(
                operation,
                kind,
                D::Inherited,
                D::Inherited,
                D::Required,
                D::Inherited,
                BOUNDED_SETS,
            )),
            _ => None,
        },
        Operation::Backup => match kind {
            ObjectKind::RawArchive => Some(matrix_entry(
                operation,
                kind,
                D::Required,
                D::Inherited,
                D::Inherited,
                D::Required,
                BOUNDED_SETS,
            )),
            _ => None,
        },
        Operation::InternalAnalytics => match kind {
            ObjectKind::ResearchDataset => Some(matrix_entry(
                operation,
                kind,
                D::Inherited,
                D::Inherited,
                D::Inherited,
                D::Inherited,
                BOUNDED_SETS,
            )),
            _ => None,
        },
        Operation::DerivedDataCreation => match kind {
            ObjectKind::DerivedArtifact => Some(matrix_entry(
                operation,
                kind,
                D::Inherited,
                D::Inherited,
                D::Inherited,
                D::Inherited,
                BOUNDED_SETS,
            )),
            _ => None,
        },
        Operation::Display => match kind {
            ObjectKind::NdcRelease => Some(matrix_entry(
                operation,
                kind,
                D::Inherited,
                D::Inherited,
                D::Optional,
                D::Inherited,
                OPEN_SETS,
            )),
            _ => None,
        },
        Operation::ExternalRedistribution => match kind {
            ObjectKind::NdcRelease | ObjectKind::DerivedArtifact => Some(matrix_entry(
                operation,
                kind,
                D::Inherited,
                D::Inherited,
                D::Inherited,
                D::Required,
                OPEN_SETS,
            )),
            _ => None,
        },
        Operation::Retention => match kind {
            ObjectKind::RawArchive | ObjectKind::NdcRelease | ObjectKind::DerivedArtifact => {
                Some(matrix_entry(
                    operation,
                    kind,
                    D::Inherited,
                    D::Inherited,
                    D::Inherited,
                    D::Required,
                    BOUNDED_SETS,
                ))
            }
            _ => None,
        },
        Operation::Deletion => match kind {
            ObjectKind::RawArchive
            | ObjectKind::NdcRelease
            | ObjectKind::ResearchCopy
            | ObjectKind::ResearchDataset
            | ObjectKind::DerivedArtifact => Some(matrix_entry(
                operation,
                kind,
                D::Optional,
                D::NotApplicable,
                D::NotApplicable,
                D::Prohibited,
                NO_SETS,
            )),
            _ => None,
        },
    }
}

fn check_dimension(
    requirement: DimensionRequirement,
    field: &'static str,
    value: &str,
) -> Result<(), RightsError> {
    if requirement.needs_value() && value.trim().is_empty() {
        return Err(RightsError::MissingField { field });
    }
    if requirement.needs_absent() && !value.trim().is_empty() {
        return Err(RightsError::InvalidScopeSet);
    }
    Ok(())
}

fn check_scope_set<T>(
    set: &ScopeSet<T>,
    requirement: DimensionRequirement,
    representations: ScopeRepresentations,
) -> Result<(), RightsError> {
    if requirement.needs_absent() {
        if !matches!(set, ScopeSet::NotApplicable) {
            return Err(RightsError::InvalidScopeSet);
        }
        return Ok(());
    }
    match set {
        ScopeSet::NotApplicable => Err(RightsError::InvalidScopeSet),
        ScopeSet::Named(members) if members.is_empty() || !representations.named => {
            Err(RightsError::InvalidScopeSet)
        }
        ScopeSet::Named(_) => Ok(()),
        ScopeSet::Universe(reference) if representations.universe => reference.validate(),
        ScopeSet::Universe(_) => Err(RightsError::InvalidScopeSet),
        ScopeSet::All if representations.all => Ok(()),
        ScopeSet::All => Err(RightsError::InvalidScopeSet),
    }
}

fn check_data_time(
    window: &TimeWindow,
    requirement: DimensionRequirement,
) -> Result<(), RightsError> {
    window.validate()?;
    let unbounded = window.from_us.is_none() && window.to_us.is_none();
    if requirement.needs_absent() && !unbounded {
        return Err(RightsError::InvalidScopeSet);
    }
    if requirement == DimensionRequirement::Required && unbounded {
        return Err(RightsError::InvalidScopeSet);
    }
    Ok(())
}

fn check_retention(
    retention: &Retention,
    requirement: DimensionRequirement,
) -> Result<(), RightsError> {
    let none = retention.limit == RetentionLimit::None;
    if requirement.needs_absent() && !none {
        return Err(RightsError::InvalidScopeSet);
    }
    if requirement == DimensionRequirement::Required && none {
        return Err(RightsError::InvalidScopeSet);
    }
    Ok(())
}

/// Apply the applicability matrix to one grant or request before containment.
///
/// Both sides call this from [`AuthorizationScope::validate`], so a scope that
/// cannot be evaluated is never compared with a grant.
///
/// # Errors
/// Returns [`RightsError::ObjectKindNotApplicable`] for a prohibited pair,
/// [`RightsError::MissingField`] for an absent required identity dimension and
/// [`RightsError::InvalidScopeSet`] for a shape or representation violation.
pub fn validate_applicability(
    scope: &AuthorizationScope,
) -> Result<ApplicabilityDecision, RightsError> {
    let Some(applicability) = applicability_for(scope.operation, scope.data_object.kind) else {
        return Err(RightsError::ObjectKindNotApplicable {
            operation: scope.operation.as_str(),
            kind: scope.data_object.kind.as_str(),
        });
    };
    check_dimension(applicability.provider, "provider_id", &scope.provider_id)?;
    check_dimension(applicability.venue, "venue", &scope.venue)?;
    check_dimension(applicability.segment, "segment", &scope.segment)?;
    check_scope_set(
        &scope.instruments,
        applicability.instruments,
        applicability.representations,
    )?;
    check_scope_set(
        &scope.fields,
        applicability.fields,
        applicability.representations,
    )?;
    check_scope_set(
        &scope.modalities,
        applicability.modality,
        applicability.representations,
    )?;
    check_data_time(&scope.data_time_window, applicability.data_time)?;
    check_retention(&scope.retention, applicability.retention)?;
    if applicability.instruments == DimensionRequirement::NotApplicable {
        Ok(ApplicabilityDecision::NotApplicable)
    } else {
        Ok(ApplicabilityDecision::Applicable)
    }
}

/// A scope dimension with four explicit states.
///
/// `NotApplicable` records that the dimension has no meaning for the
/// operation (for example, instruments for a source contact). `Named` is an
/// explicit enumerated set; an empty `Named` set contains no members and is
/// never converted into `All`. `Universe` names an exact versioned universe:
/// it covers only the same reference, and named members only when recorded
/// membership evidence for that reference and both instants is supplied.
/// `All` is unrestricted and may only be written explicitly in an operator
/// rights record where the matrix allows it; it is never a runtime default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ScopeSet<T> {
    /// The dimension does not apply to this operation.
    NotApplicable,
    /// An explicit set of named members. Empty means "no members".
    Named(Vec<T>),
    /// Every member of an exact, versioned universe.
    Universe(UniverseRef),
    /// Unrestricted; operator-written only, never inferred.
    All,
}

impl<T: PartialEq + Eq> ScopeSet<T> {
    /// Whether every requested member is covered by this permitted set.
    ///
    /// A universe covers only an equal universe reference. A named
    /// request is never silently admitted by a universe here; that requires
    /// the explicit membership-evidence path.
    #[must_use]
    pub fn contains_all(&self, requested: &Self) -> bool {
        match (self, requested) {
            (Self::All, _) => true,
            (Self::NotApplicable, Self::NotApplicable) => true,
            (Self::Named(permitted), Self::Named(asked)) => {
                asked.iter().all(|item| permitted.contains(item))
            }
            (Self::Universe(permitted), Self::Universe(asked)) => permitted == asked,
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

    /// Return the exact universe reference when this set names one.
    #[must_use]
    pub fn universe_ref(&self) -> Option<&UniverseRef> {
        match self {
            Self::Universe(reference) => Some(reference),
            _ => None,
        }
    }
}

impl ScopeSet<String> {
    /// Verify named-member containment against recorded universe membership.
    ///
    /// Every requested name must be present for the exact universe reference at
    /// the required data-as-of and knowledge-time instants. An unknown name, a
    /// different reference or a different instant denies. No current symbol
    /// resolution or present-day clock is consulted.
    #[must_use]
    pub fn contains_universe_member(
        &self,
        requested: &Self,
        membership: &UniverseMembershipRegistry,
        at: MembershipTime,
    ) -> bool {
        match (self, requested) {
            (Self::Universe(reference), Self::Named(members)) => {
                !members.is_empty()
                    && members
                        .iter()
                        .all(|member| membership.contains(reference, member, at))
            }
            _ => self.contains_all(requested),
        }
    }
}

impl<T> Default for ScopeSet<T> {
    fn default() -> Self {
        Self::Named(Vec::new())
    }
}

/// Inclusive time window over the data itself, distinct from the effective
/// interval over which the decision is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
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
        validate_applicability(self)?;
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
        self.scope_contains_with(requested, None)
    }

    /// Scope containment with optional, explicit membership evidence.
    ///
    /// Universe-to-named containment is denied unless the caller supplies both
    /// the membership registry and the required data-as-of/knowledge-time.
    #[must_use]
    pub fn scope_contains_with(
        &self,
        requested: &Self,
        membership: Option<(&UniverseMembershipRegistry, MembershipTime)>,
    ) -> bool {
        let instruments_ok = match membership {
            Some((registry, at)) => {
                self.instruments
                    .contains_universe_member(&requested.instruments, registry, at)
            }
            None => self.instruments.contains_all(&requested.instruments),
        };
        let fields_ok = match membership {
            Some((registry, at)) => {
                self.fields
                    .contains_universe_member(&requested.fields, registry, at)
            }
            None => self.fields.contains_all(&requested.fields),
        };
        instruments_ok
            && fields_ok
            && self.modalities.contains_all(&requested.modalities)
            && self.data_time_window.contains(&requested.data_time_window)
            && self.retention.contains(&requested.retention)
    }

    /// Full comparison used by authorization and by every egress recheck.
    #[must_use]
    pub fn matches_request(&self, requested: &Self) -> bool {
        self.matches_request_with(requested, None)
    }

    /// Full comparison with optional, explicit membership evidence.
    #[must_use]
    pub fn matches_request_with(
        &self,
        requested: &Self,
        membership: Option<(&UniverseMembershipRegistry, MembershipTime)>,
    ) -> bool {
        self.exact_match(requested) && self.scope_contains_with(requested, membership)
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
        self.matches_with(request, at_us, None)
    }

    /// Whether this record applies, with optional universe membership evidence.
    #[must_use]
    pub fn matches_with(
        &self,
        request: &AuthorizationRequest,
        at_us: i64,
        membership: Option<(&UniverseMembershipRegistry, MembershipTime)>,
    ) -> bool {
        self.scope.matches_request_with(request, membership)
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
    /// A universe reference is incomplete or malformed.
    #[error("authorization universe reference is incomplete or malformed")]
    InvalidUniverse,
    /// A membership fact is blank or lies outside the exact universe windows.
    #[error("authorization universe membership is invalid for the exact universe")]
    InvalidUniverseMembership,
    /// The object kind has no applicability entry for the operation.
    #[error("authorization object kind `{kind}` is not permitted for operation `{operation}`")]
    ObjectKindNotApplicable {
        operation: &'static str,
        kind: &'static str,
    },
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
    /// Recorded membership evidence used only for explicit universe-to-named
    /// containment. It is empty until evidence is supplied by a caller.
    membership: UniverseMembershipRegistry,
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

    /// Attach recorded universe membership evidence to this registry.
    #[must_use]
    pub fn with_membership(mut self, membership: UniverseMembershipRegistry) -> Self {
        self.membership = membership;
        self
    }

    /// Record one universe membership fact for later containment checks.
    ///
    /// # Errors
    /// Returns an error for invalid universe or membership evidence.
    pub fn record_membership(&mut self, membership: UniverseMembership) -> Result<(), RightsError> {
        self.membership.record(membership)
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
    /// Without explicit membership evidence, a named request is never admitted
    /// by a universe grant. Call [`Self::authorize_with_membership`] for that.
    ///
    /// # Errors
    /// Returns the first fail-closed denial described by [`RightsError`].
    pub fn authorize(
        &self,
        request: &AuthorizationRequest,
        at_us: i64,
    ) -> Result<AuthorizationProof, RightsError> {
        self.authorize_with(request, at_us, None)
    }

    /// Authorize with explicit universe membership evidence and instants.
    ///
    /// # Errors
    /// Returns the first fail-closed denial described by [`RightsError`].
    pub fn authorize_with_membership(
        &self,
        request: &AuthorizationRequest,
        at_us: i64,
        at: MembershipTime,
    ) -> Result<AuthorizationProof, RightsError> {
        self.authorize_with(request, at_us, Some(at))
    }

    fn authorize_with(
        &self,
        request: &AuthorizationRequest,
        at_us: i64,
        at: Option<MembershipTime>,
    ) -> Result<AuthorizationProof, RightsError> {
        request.validate()?;
        let membership = at.map(|instant| (&self.membership, instant));
        let mut candidates: Vec<&AuthorizationRecord> = self
            .records
            .iter()
            .filter(|record| record.identity.matches_with(request, at_us, membership))
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
        // The proof is bound to the request's full identity and to the
        // winning grant's approved endpoint set. A request's own set is empty
        // by construction; without this binding an authorized intent could
        // not reach the endpoint named in the winning rights record.
        let proof_scope = AuthorizationScope {
            approved_endpoints: winning.identity.scope.approved_endpoints.clone(),
            ..request.clone()
        };
        Ok(AuthorizationProof {
            scope: proof_scope,
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
    /// Result of the applicability matrix applied before containment.
    pub applicability_decision: ApplicabilityDecision,
    /// Digest of the exact universe referenced by this scope, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub universe_digest: Option<String>,
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
    /// Declared operation plan whose step produced this event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<String>,
    /// Declared step within that plan. A step is never inferred from a command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_id: Option<String>,
    /// Side-effect boundary this decision permits, not a command name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub side_effect_boundary: Option<String>,
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
    pub plan_id: Option<String>,
    pub step_id: Option<String>,
    pub side_effect_boundary: Option<String>,
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
        let applicability_decision = match validate_applicability(scope) {
            Ok(decision) => decision,
            Err(RightsError::ObjectKindNotApplicable { .. }) => ApplicabilityDecision::Prohibited,
            Err(_) => ApplicabilityDecision::Invalid,
        };
        let universe_digest = scope
            .instruments
            .universe_ref()
            .or_else(|| scope.fields.universe_ref())
            .or_else(|| scope.modalities.universe_ref())
            .map(|reference| reference.digest.clone());
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
            applicability_decision,
            universe_digest,
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
            plan_id: context.plan_id,
            step_id: context.step_id,
            side_effect_boundary: context.side_effect_boundary,
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
        self.authorize_with_context(request, at_us, AuditContext::default())
            .map(|(proof, _event)| proof)
    }

    /// Authorize one request and return both the proof and its committed
    /// audit event. Plan callers use the event id as the step's audit reference.
    ///
    /// # Errors
    /// Same fail-closed contract as [`Self::authorize`].
    pub fn authorize_with_context(
        &self,
        request: &AuthorizationRequest,
        at_us: i64,
        plan_context: AuditContext,
    ) -> anyhow::Result<(AuthorizationProof, DecisionAuditEvent)> {
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
        let mut lifecycle =
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
        lifecycle.plan_id = plan_context.plan_id;
        lifecycle.step_id = plan_context.step_id;
        lifecycle.side_effect_boundary = plan_context.side_effect_boundary;
        let audit_result = self.sink.record_with_context(
            request,
            &decision,
            reason,
            evidence.as_ref(),
            at_us,
            lifecycle,
        );
        match (outcome, audit_result) {
            (Ok(proof), Ok(event)) => Ok((proof, event)),
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
    membership: UniverseMembershipRegistry,
}

/// One proof queued for installation, with the plan metadata audited for
/// its step. A proof is never inferred from a command or from another step.
#[derive(Debug, Clone)]
pub struct ProofInstallation {
    pub proof: AuthorizationProof,
    pub sink: AuditSink,
    pub authority: Option<Arc<dyn AuthorityRefresh>>,
    pub plan_id: Option<String>,
    pub step_id: Option<String>,
    pub side_effect_boundary: Option<String>,
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

    /// Attach recorded universe membership evidence to this gate.
    #[must_use]
    pub fn with_membership(self, membership: UniverseMembershipRegistry) -> Self {
        self.lock().membership = membership;
        self
    }

    /// Record one universe membership fact for later containment checks.
    ///
    /// # Errors
    /// Returns an error for invalid universe or membership evidence.
    pub fn record_membership(&self, membership: UniverseMembership) -> Result<(), RightsError> {
        self.lock().membership.record(membership)
    }

    /// Whether the installed authorization covers the whole caller-supplied
    /// intent, including its endpoint. Time and lifecycle are checked separately.
    fn matches(
        item: &ActiveAuthorization,
        intent: &EgressIntent,
        membership: Option<(&UniverseMembershipRegistry, MembershipTime)>,
    ) -> bool {
        item.proof
            .scope
            .matches_request_with(&intent.to_scope(), membership)
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
            ..AuditContext::default()
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

    /// Audit parts for a local-data scope. No endpoint is fabricated: a local
    /// check never contacts or names a provider authority.
    fn audit_parts_for_scope(
        item: &ActiveAuthorization,
    ) -> (AuditSink, AuditContext, DecisionAudit) {
        let context = AuditContext {
            recording_authority: Some(item.proof.recording_authority.clone()),
            session_id: Some(item.session.session_id.clone()),
            registry_revision: Some(item.proof.registry_revision),
            grant_snapshot_id: Some(item.proof.grant_snapshot_id.clone()),
            lease_expires_at_us: Some(item.session.expires_at_us),
            ..AuditContext::default()
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

    fn scope_key(scope: &AuthorizationScope) -> anyhow::Result<String> {
        serde_json::to_string(scope).context("serializing authorization scope for batch identity")
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
        let installation = ProofInstallation {
            proof,
            sink,
            authority,
            plan_id: None,
            step_id: None,
            side_effect_boundary: None,
        };
        self.install_batch(vec![installation])?
            .into_iter()
            .next()
            .context("batch installation returned no session id")
    }

    /// Install a whole plan atomically: either every proof becomes active or
    /// none does. All fallible work (validation, duplicate detection and audit
    /// commits) completes before any state is mutated, so a failure on a later
    /// step cannot leave an earlier step authorized. A rollback audit record
    /// is committed when a failure is detected after earlier grant records.
    ///
    /// Returns the session ids in installation order.
    ///
    /// # Errors
    /// Returns the first fail-closed denial without installing any proof.
    pub fn install_batch(
        &self,
        installations: Vec<ProofInstallation>,
    ) -> anyhow::Result<Vec<String>> {
        let mut snapshots = Vec::with_capacity(installations.len());
        for installation in &installations {
            installation.proof.scope.validate()?;
            snapshots.push(GrantSnapshot::new(
                installation.proof.registry_revision,
                installation.proof.grant_snapshot_id.clone(),
                installation.proof.lease_duration_us,
                installation.proof.at_us,
            )?);
        }
        let mut state = self.lock();
        let mut keys: BTreeSet<String> = state
            .active
            .iter()
            .map(|item| Self::scope_key(&item.proof.scope))
            .collect::<anyhow::Result<_>>()?;
        for (index, installation) in installations.iter().enumerate() {
            let key = Self::scope_key(&installation.proof.scope)?;
            anyhow::ensure!(
                keys.insert(key),
                "an identical authorization is already installed in this gate (step {index})"
            );
        }
        let first_session = state.next_session;
        let session_ids: Vec<String> = (0..installations.len())
            .map(|offset| format!("session-{}", first_session.saturating_add(offset as u64)))
            .collect();
        let audit_outcome = (|| -> anyhow::Result<Vec<DecisionAuditEvent>> {
            let mut events = Vec::with_capacity(installations.len());
            for ((installation, snapshot), session_id) in
                installations.iter().zip(&snapshots).zip(&session_ids)
            {
                let context = AuditContext {
                    recording_authority: Some(installation.proof.recording_authority.clone()),
                    session_id: Some(session_id.clone()),
                    registry_revision: Some(snapshot.registry_revision),
                    grant_snapshot_id: Some(snapshot.snapshot_id.clone()),
                    lease_expires_at_us: Some(snapshot.expires_at_us()),
                    endpoint: None,
                    plan_id: installation.plan_id.clone(),
                    step_id: installation.step_id.clone(),
                    side_effect_boundary: installation.side_effect_boundary.clone(),
                };
                let evidence = DecisionAudit {
                    licence_reference: installation.proof.licence_reference.clone(),
                    licence_document_hash: installation.proof.licence_document_hash.clone(),
                    contract_revision: installation.proof.contract_revision,
                    recorded_at_us: installation.proof.at_us,
                    authority: installation.proof.recording_authority.clone(),
                };
                events.push(
                    installation
                        .sink
                        .record_with_context(
                            &installation.proof.scope,
                            "grant",
                            None,
                            Some(&evidence),
                            installation.proof.at_us,
                            context,
                        )
                        .context("committing grant audit event for plan step")?,
                );
            }
            Ok(events)
        })();
        if let Err(error) = audit_outcome {
            if let Some(first) = installations.first() {
                let rollback = AuthorizationScope::denial_scope(
                    &first.proof.scope.venue,
                    first.proof.scope.operation,
                );
                let context = AuditContext {
                    plan_id: first.plan_id.clone(),
                    step_id: first.step_id.clone(),
                    side_effect_boundary: first.side_effect_boundary.clone(),
                    ..AuditContext::default()
                };
                let _ = first.sink.record_with_context(
                    &rollback,
                    "plan_rollback",
                    Some(format!("{error}; no plan step was installed")),
                    None,
                    first.proof.at_us,
                    context,
                );
            }
            return Err(error);
        }
        // No state was mutated above. Commit the whole batch in one locked step.
        for ((installation, snapshot), session_id) in
            installations.iter().zip(&snapshots).zip(&session_ids)
        {
            state.active.push(ActiveAuthorization {
                proof: installation.proof.clone(),
                sink: installation.sink.clone(),
                session: AuthorizationSession {
                    session_id: session_id.clone(),
                    expires_at_us: snapshot.expires_at_us(),
                    snapshot: snapshot.clone(),
                    renewals: 0,
                },
                authority: installation.authority.clone(),
            });
        }
        state.next_session = first_session.saturating_add(installations.len() as u64);
        if !installations.is_empty() && state.fallback_sink.is_none() {
            state.fallback_sink = Some(installations[0].sink.clone());
        }
        Ok(session_ids)
    }

    /// Number of live proofs in this gate. Used by batch atomicity tests and
    /// by operators auditing a process; it is not a permission.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.lock().active.len()
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
        at: Option<MembershipTime>,
        metadata: AuditContext,
    ) -> anyhow::Result<AuthorizationProof> {
        intent.validate()?;
        let scope = intent.to_scope();
        let mut state = self.lock();
        let membership = state.membership.clone();
        let evidence = at.map(|instant| (&membership, instant));
        let Some(index) = state
            .active
            .iter()
            .position(|item| Self::matches(item, intent, evidence))
        else {
            let error = if state.active.iter().any(|item| {
                item.proof.scope.matches_request_with(&scope, evidence)
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
            let (sink, mut context, evidence) = Self::audit_parts(item, intent);
            context.plan_id = metadata.plan_id;
            context.step_id = metadata.step_id;
            context.side_effect_boundary = metadata.side_effect_boundary;
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
        self.evaluate(intent, at_us, false, None, AuditContext::default())
    }

    /// Preflight check with explicit universe membership evidence.
    ///
    /// # Errors
    /// Returns a fail-closed denial when no live authorization covers the intent.
    pub fn check_active_with_membership(
        &self,
        intent: &EgressIntent,
        at_us: i64,
        at: MembershipTime,
    ) -> anyhow::Result<AuthorizationProof> {
        self.evaluate(intent, at_us, false, Some(at), AuditContext::default())
    }

    /// Check a local-data-use scope against the live gate without any endpoint
    /// or provider contact. This is the separate gate used by replay, inspect,
    /// verify, journal and export steps. A grant for a different operation or
    /// object never covers the request, and a denied check never reads data.
    ///
    /// # Errors
    /// Returns a fail-closed denial when no live proof covers the full scope,
    /// and fails closed when a permitted event cannot be committed.
    pub fn check_scope_active(&self, scope: &AuthorizationScope, at_us: i64) -> anyhow::Result<()> {
        self.check_scope_active_with_context(scope, at_us, AuditContext::default())
    }

    /// Local-data check that audits the declaring plan, step and boundary.
    ///
    /// # Errors
    /// Returns the same fail-closed denial as [`Self::check_scope_active`].
    pub fn check_scope_active_with_context(
        &self,
        scope: &AuthorizationScope,
        at_us: i64,
        metadata: AuditContext,
    ) -> anyhow::Result<()> {
        scope.validate()?;
        let mut state = self.lock();
        let Some(index) = state
            .active
            .iter()
            .position(|item| item.proof.scope.matches_request(scope))
        else {
            let error: anyhow::Error = RightsError::ScopeMismatch {
                operation: scope.operation.as_str().to_owned(),
                venue: scope.venue.clone(),
                reason: "no live proof covers this local-data operation",
            }
            .into();
            if let Some(sink) = state.fallback_sink.clone() {
                let denial_context = AuditContext {
                    plan_id: metadata.plan_id.clone(),
                    step_id: metadata.step_id.clone(),
                    side_effect_boundary: metadata.side_effect_boundary.clone(),
                    ..AuditContext::default()
                };
                let _ = sink.record_with_context(
                    scope,
                    "local_denied",
                    Some(error.to_string()),
                    None,
                    at_us,
                    denial_context,
                );
            }
            return Err(error);
        };
        let item = &state.active[index];
        let (sink, context, evidence, authority, expires, proof) = {
            let (sink, mut context, evidence) = Self::audit_parts_for_scope(item);
            context.plan_id = metadata.plan_id;
            context.step_id = metadata.step_id;
            context.side_effect_boundary = metadata.side_effect_boundary;
            (
                sink,
                context,
                evidence,
                item.authority.clone(),
                item.session.expires_at_us,
                item.proof.clone(),
            )
        };
        if proof.valid_from > at_us || proof.valid_until.is_some_and(|end| at_us > end) {
            state.active.remove(index);
            let _ = sink.record_with_context(
                scope,
                "grant_expired",
                Some(RightsError::AuthorizationExpired.to_string()),
                Some(&evidence),
                at_us,
                context,
            );
            return Err(RightsError::AuthorizationExpired.into());
        }
        if at_us > expires {
            state.active.remove(index);
            let _ = sink.record_with_context(
                scope,
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
                        scope,
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
                        scope,
                        "local_denied",
                        Some(format!("{}: {error}", RightsError::AuthorityRefreshFailed)),
                        Some(&evidence),
                        at_us,
                        context,
                    );
                    return Err(RightsError::AuthorityRefreshFailed.into());
                }
            }
        }
        sink.record_with_context(
            scope,
            "local_permitted",
            None,
            Some(&evidence),
            at_us,
            context,
        )
        .context("committing local-data authorization event")?;
        Ok(())
    }

    /// Reauthorize one egress attempt and commit its event before returning.
    /// No network side effect may begin until this returns `Ok`.
    ///
    /// # Errors
    /// Returns an error on denial and when a permitted egress event cannot be
    /// committed. Denial events are written when a sink is available.
    pub fn require_egress(&self, intent: &EgressIntent, at_us: i64) -> anyhow::Result<()> {
        self.evaluate(intent, at_us, true, None, AuditContext::default())
            .map(|_| ())
    }

    /// Reauthorize one egress for a declared plan step, auditing its plan id,
    /// step id and side-effect boundary.
    ///
    /// # Errors
    /// Returns the fail-closed denial before the caller may egress.
    pub fn require_egress_with_plan_context(
        &self,
        intent: &EgressIntent,
        at_us: i64,
        metadata: AuditContext,
    ) -> anyhow::Result<()> {
        self.evaluate(intent, at_us, true, None, metadata)
            .map(|_| ())
    }

    /// Reauthorize an egress with explicit universe membership evidence.
    ///
    /// # Errors
    /// Returns an error on denial and when a permitted egress event cannot be
    /// committed.
    pub fn require_egress_with_membership(
        &self,
        intent: &EgressIntent,
        at_us: i64,
        at: MembershipTime,
    ) -> anyhow::Result<()> {
        self.evaluate(intent, at_us, true, Some(at), AuditContext::default())
            .map(|_| ())
    }

    /// Renew the lease of an active session after a successful authority refresh.
    ///
    /// # Errors
    /// Returns an error when the intent is not covered or the authority cannot
    /// be refreshed.
    pub fn renew_lease(&self, intent: &EgressIntent, at_us: i64) -> anyhow::Result<()> {
        self.renew_lease_with(intent, at_us, None)
    }

    fn renew_lease_with(
        &self,
        intent: &EgressIntent,
        at_us: i64,
        at: Option<MembershipTime>,
    ) -> anyhow::Result<()> {
        intent.validate()?;
        let scope = intent.to_scope();
        let mut state = self.lock();
        let membership = state.membership.clone();
        let evidence = at.map(|instant| (&membership, instant));
        let Some(index) = state
            .active
            .iter()
            .position(|item| Self::matches(item, intent, evidence))
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
        self.cancel_with(intent, reason, at_us, None)
    }

    /// Cancel a session matched with explicit universe membership evidence.
    ///
    /// # Errors
    /// Returns an error when no active session covers the intent.
    pub fn cancel_with_membership(
        &self,
        intent: &EgressIntent,
        reason: &str,
        at_us: i64,
        at: MembershipTime,
    ) -> anyhow::Result<()> {
        self.cancel_with(intent, reason, at_us, Some(at))
    }

    fn cancel_with(
        &self,
        intent: &EgressIntent,
        reason: &str,
        at_us: i64,
        at: Option<MembershipTime>,
    ) -> anyhow::Result<()> {
        let scope = intent.to_scope();
        let mut state = self.lock();
        let membership = state.membership.clone();
        let evidence = at.map(|instant| (&membership, instant));
        let Some(index) = state
            .active
            .iter()
            .position(|item| Self::matches(item, intent, evidence))
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
    let mut installations = Vec::with_capacity(requests.len());
    for request in requests {
        let proof = context.authorize(request, now_us()?)?;
        let authority: Arc<dyn AuthorityRefresh> = Arc::new(InMemoryAuthority::new(
            proof.registry_revision,
            proof.grant_snapshot_id.clone(),
        ));
        installations.push(ProofInstallation {
            proof,
            sink: context.sink().clone(),
            authority: Some(authority),
            plan_id: None,
            step_id: None,
            side_effect_boundary: None,
        });
    }
    // One atomic commit: a later duplicate or invalid proof denies the whole
    // batch and leaves no earlier proof active.
    default_gate().install_batch(installations)?;
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

    /// Abstract exact universe reference. No market universe is named.
    fn universe_ref(version: &str, digest: &str) -> UniverseRef {
        UniverseRef::new(
            "universe-a",
            version,
            digest,
            "abstract-membership",
            TimeWindow::default(),
            TimeWindow::default(),
            1,
        )
        .expect("abstract universe")
    }

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
        probe.data_time_window = TimeWindow::default();
        probe.retention = Retention::NONE;
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
            item.data_time_window = TimeWindow::default();
            item.retention = Retention::NONE;
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
            item.data_object = object(ObjectKind::SourceReferenceRecord, "reference-a", "v1");
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
        let universe_v1 = ScopeSet::<String>::Universe(universe_ref("v1", &"a".repeat(64)));
        let universe_v2 = ScopeSet::<String>::Universe(universe_ref("v2", &"a".repeat(64)));
        assert!(
            !universe_v1.contains_all(&universe_v2),
            "a versioned universe does not cover another version"
        );
        assert!(
            !universe_v1.contains_all(&named_a),
            "a named request needs explicit membership evidence"
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
            item.instruments = ScopeSet::Universe(universe_ref("v1", &"a".repeat(64)));
            item.fields = ScopeSet::Universe(universe_ref("v1", &"a".repeat(64)));
            item.modalities = ScopeSet::Universe(universe_ref("v1", &"a".repeat(64)));
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
            item.data_time_window = TimeWindow::default();
            item.retention = Retention::NONE;
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
            item.operation = Operation::RawStorage;
            item.data_object = object(ObjectKind::RawArchive, "archive-a", "v1");
        });
        let extra = scope_with(|item| {
            item.operation = Operation::RawStorage;
            item.data_object = object(ObjectKind::RawArchive, "archive-b", "v1");
        });
        registry
            .register(permitted_record(&granted))
            .expect("first grant");
        registry
            .register(permitted_record(&extra))
            .expect("unrelated grant");
        let ungranted = scope_with(|item| {
            item.operation = Operation::RawStorage;
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
            item.operation = Operation::InternalAnalytics;
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

    const ALL_OPERATIONS: [Operation; 14] = [
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

    const ALL_KINDS: [ObjectKind; 8] = [
        ObjectKind::SourceReferenceRecord,
        ObjectKind::RawSourceRecord,
        ObjectKind::CanonicalObservation,
        ObjectKind::RawArchive,
        ObjectKind::NdcRelease,
        ObjectKind::ResearchCopy,
        ObjectKind::ResearchDataset,
        ObjectKind::DerivedArtifact,
    ];

    const MEMBERSHIP_TIME: MembershipTime = MembershipTime {
        data_as_of: 1_000,
        knowledge_as_of: 2_000,
    };

    fn abstract_set(requirement: DimensionRequirement) -> ScopeSet<String> {
        match requirement {
            DimensionRequirement::NotApplicable | DimensionRequirement::Prohibited => {
                ScopeSet::NotApplicable
            }
            _ => ScopeSet::Named(vec!["member-a".to_owned()]),
        }
    }

    fn abstract_modality_set(requirement: DimensionRequirement) -> ScopeSet<Modality> {
        match requirement {
            DimensionRequirement::NotApplicable | DimensionRequirement::Prohibited => {
                ScopeSet::NotApplicable
            }
            _ => ScopeSet::Named(vec![Modality::L2]),
        }
    }

    /// Build the valid shape declared by the matrix for one permitted pair.
    fn applicable_scope(operation: Operation, kind: ObjectKind) -> AuthorizationScope {
        let applicability =
            applicability_for(operation, kind).expect("permitted action-object pair");
        scope_with(|item| {
            item.operation = operation;
            item.data_object = object(kind, "object-a", "v1");
            item.instruments = abstract_set(applicability.instruments);
            item.fields = abstract_set(applicability.fields);
            item.modalities = abstract_modality_set(applicability.modality);
            item.data_time_window = match applicability.data_time {
                DimensionRequirement::NotApplicable | DimensionRequirement::Prohibited => {
                    TimeWindow::default()
                }
                _ => TimeWindow {
                    from_us: Some(1),
                    to_us: Some(9),
                },
            };
            item.retention = match applicability.retention {
                DimensionRequirement::NotApplicable | DimensionRequirement::Prohibited => {
                    Retention::NONE
                }
                _ => Retention::bounded(100),
            };
        })
    }

    fn membership_at(universe: &UniverseRef, member: &str) -> UniverseMembership {
        UniverseMembership {
            universe: universe.clone(),
            member: member.to_owned(),
            data_as_of: MEMBERSHIP_TIME.data_as_of,
            knowledge_as_of: MEMBERSHIP_TIME.knowledge_as_of,
        }
    }

    fn memberships(facts: Vec<UniverseMembership>) -> UniverseMembershipRegistry {
        let mut registry = UniverseMembershipRegistry::new();
        for fact in facts {
            registry.record(fact).expect("recorded abstract membership");
        }
        registry
    }

    #[test]
    fn applicability_matrix_covers_every_action_object_pair() {
        let mut permitted = 0;
        for operation in ALL_OPERATIONS {
            for kind in ALL_KINDS {
                match applicability_for(operation, kind) {
                    Some(applicability) => {
                        permitted += 1;
                        assert_eq!(
                            applicability.operation, operation,
                            "matrix entry keeps its operation"
                        );
                        assert_eq!(
                            applicability.data_object_kind, kind,
                            "matrix entry keeps its object kind"
                        );
                        let valid = applicable_scope(operation, kind);
                        assert_eq!(
                            valid.validate(),
                            Ok(()),
                            "valid shape for {operation:?}/{kind:?}"
                        );
                    }
                    None => {
                        let invalid = scope_with(|item| {
                            item.operation = operation;
                            item.data_object = object(kind, "object-a", "v1");
                        });
                        assert!(
                            matches!(
                                invalid.validate(),
                                Err(RightsError::ObjectKindNotApplicable { .. })
                            ),
                            "unlisted pair {operation:?}/{kind:?} is prohibited"
                        );
                    }
                }
            }
        }
        assert_eq!(permitted, 26, "all permitted pairs have a valid shape");
    }

    #[test]
    fn missing_required_dimension_is_denied() {
        for field in ["provider_id", "venue", "segment"] {
            let mut probe =
                applicable_scope(Operation::RealTimeCapture, ObjectKind::RawSourceRecord);
            match field {
                "provider_id" => probe.provider_id.clear(),
                "venue" => probe.venue.clear(),
                "segment" => probe.segment.clear(),
                _ => unreachable!("enumerated abstract field"),
            }
            assert!(
                matches!(
                    validate_applicability(&probe),
                    Err(RightsError::MissingField { field: missing }) if missing == field
                ),
                "missing {field} is never NotApplicable"
            );
        }
    }

    #[test]
    fn incorrect_not_applicable_shape_is_denied() {
        let mut capture = applicable_scope(Operation::RealTimeCapture, ObjectKind::RawSourceRecord);
        capture.instruments = ScopeSet::NotApplicable;
        assert_eq!(
            capture.validate(),
            Err(RightsError::InvalidScopeSet),
            "capture instruments cannot be NotApplicable"
        );
        let mut contact = applicable_scope(Operation::SourceContact, ObjectKind::RawSourceRecord);
        assert_eq!(
            contact.validate(),
            Ok(()),
            "source contact has no data scope"
        );
        contact.instruments = ScopeSet::Named(vec!["member-a".to_owned()]);
        assert_eq!(
            contact.validate(),
            Err(RightsError::InvalidScopeSet),
            "source contact cannot name a data scope"
        );
    }

    #[test]
    fn empty_named_set_is_denied() {
        let mut empty = applicable_scope(Operation::RealTimeCapture, ObjectKind::RawSourceRecord);
        empty.instruments = ScopeSet::Named(Vec::new());
        assert_eq!(
            empty.validate(),
            Err(RightsError::InvalidScopeSet),
            "an empty Named set is not All"
        );
        assert_eq!(
            ScopeSet::<String>::default(),
            ScopeSet::Named(Vec::new()),
            "the default is empty Named, never All"
        );
    }

    #[test]
    fn explicit_all_is_limited_to_permitted_operations() {
        let mut capture = applicable_scope(Operation::RealTimeCapture, ObjectKind::RawSourceRecord);
        capture.instruments = ScopeSet::All;
        assert_eq!(
            capture.validate(),
            Err(RightsError::InvalidScopeSet),
            "capture cannot rely on an unrestricted All"
        );
        let mut display = applicable_scope(Operation::Display, ObjectKind::NdcRelease);
        display.instruments = ScopeSet::All;
        assert_eq!(
            display.validate(),
            Ok(()),
            "an explicitly written All is valid only where the matrix allows it"
        );
    }

    #[test]
    fn exact_universe_containment_is_version_and_digest_strict() {
        let v1 = universe_ref("v1", &"a".repeat(64));
        let v2 = universe_ref("v2", &"a".repeat(64));
        let other_digest = universe_ref("v1", &"b".repeat(64));
        let permitted = ScopeSet::Universe(v1.clone());
        assert!(
            permitted.contains_all(&ScopeSet::Universe(v1)),
            "the same universe reference covers itself"
        );
        assert!(
            !permitted.contains_all(&ScopeSet::Universe(v2)),
            "another universe version is not covered"
        );
        assert!(
            !permitted.contains_all(&ScopeSet::Universe(other_digest)),
            "another universe digest is not covered"
        );
        assert!(
            !permitted.contains_all(&ScopeSet::Named(vec!["member-a".to_owned()])),
            "named membership is never inferred by contains_all"
        );
    }

    #[test]
    fn named_member_inside_and_outside_universe() {
        let universe = universe_ref("v1", &"a".repeat(64));
        let mut registry = LicensingRegistry::new()
            .with_membership(memberships(vec![membership_at(&universe, "member-a")]));
        let grant = scope_with(|item| item.instruments = ScopeSet::Universe(universe));
        registry
            .register(permitted_record(&grant))
            .expect("universe grant registered");
        let inside = scope_with(|item| {
            item.instruments = ScopeSet::Named(vec!["member-a".to_owned()]);
        });
        let outside = scope_with(|item| {
            item.instruments = ScopeSet::Named(vec!["member-b".to_owned()]);
        });
        assert!(
            registry
                .authorize_with_membership(&inside, 1, MEMBERSHIP_TIME)
                .is_ok(),
            "a recorded member is covered at the required instants"
        );
        assert!(
            registry
                .authorize_with_membership(&outside, 1, MEMBERSHIP_TIME)
                .is_err(),
            "a member outside the universe is denied"
        );
        assert!(
            registry.authorize(&inside, 1).is_err(),
            "without evidence a named request is never admitted"
        );
    }

    #[test]
    fn unknown_membership_denies() {
        let universe = universe_ref("v1", &"a".repeat(64));
        let mut registry = LicensingRegistry::new();
        let grant = scope_with(|item| item.instruments = ScopeSet::Universe(universe));
        registry
            .register(permitted_record(&grant))
            .expect("universe grant registered");
        let asked = scope_with(|item| {
            item.instruments = ScopeSet::Named(vec!["member-a".to_owned()]);
        });
        assert!(
            registry
                .authorize_with_membership(&asked, 1, MEMBERSHIP_TIME)
                .is_err(),
            "an unrecorded member cannot be resolved to a universe"
        );
    }

    #[test]
    fn wrong_universe_version_or_digest_denies() {
        let universe = universe_ref("v1", &"a".repeat(64));
        let membership = memberships(vec![membership_at(&universe, "member-a")]);
        let asked = scope_with(|item| {
            item.instruments = ScopeSet::Named(vec!["member-a".to_owned()]);
        });
        for wrong in [
            universe_ref("v2", &"a".repeat(64)),
            universe_ref("v1", &"b".repeat(64)),
        ] {
            let mut registry = LicensingRegistry::new().with_membership(membership.clone());
            let grant = scope_with(|item| item.instruments = ScopeSet::Universe(wrong));
            registry
                .register(permitted_record(&grant))
                .expect("universe grant registered");
            assert!(
                registry
                    .authorize_with_membership(&asked, 1, MEMBERSHIP_TIME)
                    .is_err(),
                "a different version or digest cannot use the recorded membership"
            );
        }
    }

    #[test]
    fn historical_membership_mismatch_denies() {
        let universe = universe_ref("v1", &"a".repeat(64));
        let mut registry = LicensingRegistry::new()
            .with_membership(memberships(vec![membership_at(&universe, "member-a")]));
        let grant = scope_with(|item| item.instruments = ScopeSet::Universe(universe));
        registry
            .register(permitted_record(&grant))
            .expect("universe grant registered");
        let asked = scope_with(|item| {
            item.instruments = ScopeSet::Named(vec!["member-a".to_owned()]);
        });
        let later_knowledge = MembershipTime {
            data_as_of: MEMBERSHIP_TIME.data_as_of,
            knowledge_as_of: MEMBERSHIP_TIME.knowledge_as_of + 1,
        };
        let later_data = MembershipTime {
            data_as_of: MEMBERSHIP_TIME.data_as_of + 1,
            knowledge_as_of: MEMBERSHIP_TIME.knowledge_as_of,
        };
        let present_day = MembershipTime {
            data_as_of: i64::MAX / 4,
            knowledge_as_of: i64::MAX / 4,
        };
        assert!(
            registry
                .authorize_with_membership(&asked, 1, MEMBERSHIP_TIME)
                .is_ok(),
            "the recorded historical instants permit"
        );
        assert!(
            registry
                .authorize_with_membership(&asked, 1, later_knowledge)
                .is_err(),
            "a later knowledge instant is not substituted"
        );
        assert!(
            registry
                .authorize_with_membership(&asked, 1, later_data)
                .is_err(),
            "a later data instant is not substituted"
        );
        assert!(
            registry
                .authorize_with_membership(&asked, 1, present_day)
                .is_err(),
            "no present-day symbol resolution is performed"
        );
    }

    #[test]
    fn gate_universe_member_containment_uses_recorded_evidence() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let universe = universe_ref("v1", &"a".repeat(64));
        let grant_scope =
            scope_with(|item| item.instruments = ScopeSet::Universe(universe.clone()));
        let gate = AuthorizationGate::new()
            .with_membership(memberships(vec![membership_at(&universe, "member-a")]));
        gate.install_scope(
            grant_scope.clone(),
            0,
            None,
            &permitted_record(&grant_scope).audit,
            sink(directory.path()),
        )
        .expect("universe proof installed");
        let inside = intent_for(&scope_with(|item| {
            item.instruments = ScopeSet::Named(vec!["member-a".to_owned()]);
        }));
        assert!(
            gate.require_egress_with_membership(&inside, 1, MEMBERSHIP_TIME)
                .is_ok(),
            "recorded membership permits egress at the required instants"
        );
        assert!(
            gate.require_egress(&inside, 1).is_err(),
            "egress without membership evidence denies"
        );
    }

    #[test]
    fn audit_event_records_applicability_and_universe_digest() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let audit = directory.path().join("audit");
        let sink = sink(&audit);
        let universe = universe_ref("v1", &"a".repeat(64));
        let scope = scope_with(|item| item.instruments = ScopeSet::Universe(universe));
        let event = sink
            .record(&scope, "probe", None, None, 1)
            .expect("applicability event recorded");
        assert_eq!(
            event.applicability_decision,
            ApplicabilityDecision::Applicable,
            "the matrix decision is audited"
        );
        assert_eq!(
            event.universe_digest.as_deref(),
            Some("a".repeat(64).as_str()),
            "the exact universe digest is audited"
        );
        let contact = applicable_scope(Operation::SourceContact, ObjectKind::RawSourceRecord);
        let contact_event = sink
            .record(&contact, "probe", None, None, 1)
            .expect("not-applicable event recorded");
        assert_eq!(
            contact_event.applicability_decision,
            ApplicabilityDecision::NotApplicable,
            "an absent data scope is distinguished from an invalid one"
        );
        assert!(
            contact_event.universe_digest.is_none(),
            "a scope without a universe has no universe digest"
        );
    }

    #[test]
    fn batch_installation_is_atomic_on_later_failure() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let sink = sink(directory.path());
        let first = scope();
        let second = scope_with(|scope| {
            scope.operation = Operation::RawStorage;
            scope.data_object = DataObject::from_declared(
                ObjectKind::RawSourceRecord,
                "object-b".to_owned(),
                "v1".to_owned(),
            );
        });
        let make_proof = |scope: &AuthorizationScope| AuthorizationProof {
            scope: scope.clone(),
            at_us: 0,
            valid_from: 0,
            valid_until: None,
            licence_reference: "contract-1".to_owned(),
            licence_document_hash: "a".repeat(64),
            contract_revision: 1,
            registry_revision: 7,
            grant_snapshot_id: format!("snapshot-{}", scope.operation.as_str()),
            lease_duration_us: MAX_LEASE_DURATION.as_micros() as u64,
            recording_authority: "contract-registry".to_owned(),
        };
        let gate = AuthorizationGate::new();
        gate.install(make_proof(&second), sink.clone())
            .expect("existing grant for the second step");
        let before = gate.active_count();
        let installations = vec![
            ProofInstallation {
                proof: make_proof(&first),
                sink: sink.clone(),
                authority: None,
                plan_id: Some("plan-abstract".to_owned()),
                step_id: Some("capture".to_owned()),
                side_effect_boundary: Some("provider_contact".to_owned()),
            },
            ProofInstallation {
                proof: make_proof(&second),
                sink: sink.clone(),
                authority: None,
                plan_id: Some("plan-abstract".to_owned()),
                step_id: Some("storage".to_owned()),
                side_effect_boundary: Some("durable_storage".to_owned()),
            },
        ];
        assert!(
            gate.install_batch(installations).is_err(),
            "a duplicate later step denies the whole batch"
        );
        assert_eq!(
            gate.active_count(),
            before,
            "no earlier step was left installed"
        );
        assert!(
            gate.check_active(&intent_for(&first), 1).is_err(),
            "the first step was not partially authorized"
        );
    }
}
