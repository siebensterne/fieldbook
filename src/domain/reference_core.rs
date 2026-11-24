// SPDX-License-Identifier: Apache-2.0
//! Canonical financial object identity, assertions and coverage.
//!
//! This module declares abstract reference-object types. It names no venue,
//! dataset, provider or rights decision and reads no present-day clock.
//! Identities derive from explicit immutable assertions. Every lookup reports
//! uncertainty instead of selecting a first candidate.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;

use crate::domain::identity::OpaqueId;
use crate::domain::information::Bitemporal;

/// One of the twenty-one distinct canonical financial object classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectClass {
    Jurisdiction,
    Authority,
    MarketOperator,
    Venue,
    Segment,
    MarketProduct,
    LegalEntity,
    Security,
    FinancialInstrument,
    ContractFamily,
    ContractInstance,
    Listing,
    IdentifierAssertion,
    InstrumentTermsRevision,
    CorporateAction,
    Index,
    MarketCalendar,
    Source,
    DataProduct,
    Feed,
    Capability,
}

impl ObjectClass {
    /// Return the stable contract string for this object class.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Jurisdiction => "jurisdiction",
            Self::Authority => "authority",
            Self::MarketOperator => "market_operator",
            Self::Venue => "venue",
            Self::Segment => "segment",
            Self::MarketProduct => "market_product",
            Self::LegalEntity => "legal_entity",
            Self::Security => "security",
            Self::FinancialInstrument => "financial_instrument",
            Self::ContractFamily => "contract_family",
            Self::ContractInstance => "contract_instance",
            Self::Listing => "listing",
            Self::IdentifierAssertion => "identifier_assertion",
            Self::InstrumentTermsRevision => "instrument_terms_revision",
            Self::CorporateAction => "corporate_action",
            Self::Index => "index",
            Self::MarketCalendar => "market_calendar",
            Self::Source => "source",
            Self::DataProduct => "data_product",
            Self::Feed => "feed",
            Self::Capability => "capability",
        }
    }

    /// Return every declared class in a stable order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::Jurisdiction,
            Self::Authority,
            Self::MarketOperator,
            Self::Venue,
            Self::Segment,
            Self::MarketProduct,
            Self::LegalEntity,
            Self::Security,
            Self::FinancialInstrument,
            Self::ContractFamily,
            Self::ContractInstance,
            Self::Listing,
            Self::IdentifierAssertion,
            Self::InstrumentTermsRevision,
            Self::CorporateAction,
            Self::Index,
            Self::MarketCalendar,
            Self::Source,
            Self::DataProduct,
            Self::Feed,
            Self::Capability,
        ]
    }
}

impl fmt::Display for ObjectClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Typed failure from reference-core validation or storage.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReferenceCoreError {
    /// The identity namespace was empty.
    #[error("empty identity namespace")]
    EmptyNamespace,
    /// The assigning authority was empty.
    #[error("empty identity authority")]
    EmptyAuthority,
    /// The immutable stable key was empty.
    #[error("empty identity stable key")]
    EmptyStableKey,
    /// An assertion value was empty.
    #[error("empty assertion value")]
    EmptyAssertionValue,
    /// An assertion authority was empty.
    #[error("empty assertion authority")]
    EmptyAssertionAuthority,
    /// An assertion source was empty.
    #[error("empty assertion source")]
    EmptyAssertionSource,
    /// A revision was zero.
    #[error("revision must be nonzero")]
    ZeroRevision,
    /// A valid-time interval ended before it started.
    #[error("valid interval ends before it starts")]
    InvalidValidityInterval,
    /// A transaction-time interval ended before it started.
    #[error("knowledge interval ends before it starts")]
    InvalidKnowledgeInterval,
    /// An assertion described another assertion.
    #[error("assertion subject cannot be an assertion")]
    AssertionSubjectIsAssertion,
    /// A subject and revision pair was already stored.
    #[error("duplicate revision for subject {0}")]
    DuplicateRevision(String),
    /// A named predecessor was not stored.
    #[error("unknown predecessor {0}")]
    UnknownPredecessor(String),
    /// A predecessor chain closed on itself.
    #[error("predecessor cycle at {0}")]
    PredecessorCycle(String),
    /// A coverage jurisdiction was empty.
    #[error("empty coverage jurisdiction")]
    EmptyJurisdiction,
    /// A coverage capability was empty.
    #[error("empty coverage capability")]
    EmptyCapability,
    /// A coverage cell with identical dimensions was already stored.
    #[error("duplicate coverage cell")]
    DuplicateCoverageCell,
}

/// Opaque identity of one canonical financial object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectId(OpaqueId);

impl ObjectId {
    /// Derive an identity from a class and an immutable assertion.
    pub fn derive(
        class: ObjectClass,
        namespace: &str,
        authority: &str,
        stable_key: &str,
    ) -> Result<Self, ReferenceCoreError> {
        if namespace.is_empty() {
            return Err(ReferenceCoreError::EmptyNamespace);
        }
        if authority.is_empty() {
            return Err(ReferenceCoreError::EmptyAuthority);
        }
        if stable_key.is_empty() {
            return Err(ReferenceCoreError::EmptyStableKey);
        }
        Ok(Self::from_validated(
            class, namespace, authority, stable_key,
        ))
    }

    fn from_validated(
        class: ObjectClass,
        namespace: &str,
        authority: &str,
        stable_key: &str,
    ) -> Self {
        Self(OpaqueId::derive(
            class.as_str(),
            namespace,
            authority,
            stable_key,
        ))
    }

    /// Return the opaque identity text.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Class and opaque identity of one reference object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ObjectRef {
    /// Canonical class of the referenced object.
    pub class: ObjectClass,
    /// Opaque identity of the referenced object.
    pub id: ObjectId,
}

impl ObjectRef {
    /// Build a reference from an explicit immutable assertion.
    pub fn new(
        class: ObjectClass,
        namespace: &str,
        authority: &str,
        stable_key: &str,
    ) -> Result<Self, ReferenceCoreError> {
        Ok(Self {
            class,
            id: ObjectId::derive(class, namespace, authority, stable_key)?,
        })
    }

    /// Return the declared class.
    pub const fn class(&self) -> ObjectClass {
        self.class
    }

    /// Return the opaque identity.
    pub fn id(&self) -> &ObjectId {
        &self.id
    }
}

/// Scheme of an external identifier assertion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierScheme {
    Isin,
    Lei,
    Mic,
    ExchangeSymbol,
    ProviderSymbol,
    InternalStableKey,
    Other(String),
}

impl IdentifierScheme {
    /// Return the contract string for this scheme.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Isin => "isin",
            Self::Lei => "lei",
            Self::Mic => "mic",
            Self::ExchangeSymbol => "exchange_symbol",
            Self::ProviderSymbol => "provider_symbol",
            Self::InternalStableKey => "internal_stable_key",
            Self::Other(text) => text,
        }
    }
}

/// Evidentiary standing recorded with an assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Asserted,
    Corroborated,
    Verified,
    Rejected,
}

impl VerificationStatus {
    /// Return the contract string for this status.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Asserted => "asserted",
            Self::Corroborated => "corroborated",
            Self::Verified => "verified",
            Self::Rejected => "rejected",
        }
    }
}

/// One effective-dated, source-attributed identifier assertion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentifierAssertion {
    /// Declared identifier scheme.
    pub scheme: IdentifierScheme,
    /// Identifier text carried by the assertion.
    pub value: String,
    /// Authority that assigned the identifier text.
    pub authority: String,
    /// Object described by this assertion.
    pub subject: ObjectRef,
    /// Named source of the assertion record.
    pub source: String,
    /// First microsecond of the valid-time interval.
    pub valid_from_us: i64,
    /// Last microsecond of the valid-time interval, open when absent.
    pub valid_to_us: Option<i64>,
    /// Microsecond at which the source recorded this assertion.
    pub recorded_at_us: i64,
    /// Nonzero declaration revision.
    pub revision: u64,
    /// Evidentiary standing of the assertion.
    pub verification_status: VerificationStatus,
}

impl IdentifierAssertion {
    /// Validate every declared field.
    pub fn validate(&self) -> Result<(), ReferenceCoreError> {
        if self.value.is_empty() {
            return Err(ReferenceCoreError::EmptyAssertionValue);
        }
        if self.authority.is_empty() {
            return Err(ReferenceCoreError::EmptyAssertionAuthority);
        }
        if self.source.is_empty() {
            return Err(ReferenceCoreError::EmptyAssertionSource);
        }
        if self.revision == 0 {
            return Err(ReferenceCoreError::ZeroRevision);
        }
        if self.valid_to_us.is_some_and(|end| self.valid_from_us > end) {
            return Err(ReferenceCoreError::InvalidValidityInterval);
        }
        if self.subject.class() == ObjectClass::IdentifierAssertion {
            return Err(ReferenceCoreError::AssertionSubjectIsAssertion);
        }
        Ok(())
    }

    /// Answer whether this assertion applies at both supplied instants.
    pub fn applies(&self, valid_us: i64, knowledge_us: i64) -> bool {
        self.valid_from_us <= valid_us
            && self.valid_to_us.is_none_or(|end| valid_us <= end)
            && self.recorded_at_us <= knowledge_us
    }
}

/// Outcome of identifier-assertion resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssertionResolution {
    /// No applicable assertion was found.
    Unresolved,
    /// One assertion matched; the payload is its sorted candidate index.
    Resolved(usize),
    /// Applicable assertions describe different objects or claims.
    Ambiguous(Vec<usize>),
    /// Applicable assertions disagree about one subject and value.
    Conflict(Vec<usize>),
}

/// Resolve valid assertions for an explicit valid time and knowledge time.
pub fn resolve_assertions(
    assertions: &[IdentifierAssertion],
    valid_us: i64,
    knowledge_us: i64,
) -> AssertionResolution {
    let mut candidates: Vec<usize> = assertions
        .iter()
        .enumerate()
        .filter(|(_, assertion)| {
            assertion.validate().is_ok() && assertion.applies(valid_us, knowledge_us)
        })
        .map(|(index, _)| index)
        .collect();
    candidates.sort_unstable();
    match candidates.len() {
        0 => return AssertionResolution::Unresolved,
        1 => return AssertionResolution::Resolved(candidates[0]),
        _ => {}
    }

    let selected: Vec<&IdentifierAssertion> =
        candidates.iter().map(|index| &assertions[*index]).collect();
    let subjects: BTreeSet<&ObjectRef> = selected.iter().map(|item| &item.subject).collect();
    let values: BTreeSet<&str> = selected.iter().map(|item| item.value.as_str()).collect();
    let authorities: BTreeSet<&str> = selected
        .iter()
        .map(|item| item.authority.as_str())
        .collect();
    let revisions: BTreeSet<u64> = selected.iter().map(|item| item.revision).collect();
    let validity: BTreeSet<(i64, Option<i64>)> = selected
        .iter()
        .map(|item| (item.valid_from_us, item.valid_to_us))
        .collect();
    let distinct_claims = authorities.len() > 1 || revisions.len() > 1;

    if subjects.len() > 1 || values.len() > 1 {
        if distinct_claims && validity.len() > 1 {
            return AssertionResolution::Conflict(candidates);
        }
        return AssertionResolution::Ambiguous(candidates);
    }
    if distinct_claims {
        if validity.len() > 1 {
            return AssertionResolution::Conflict(candidates);
        }
        return AssertionResolution::Ambiguous(candidates);
    }
    AssertionResolution::Resolved(candidates[0])
}

/// One append-only, bitemporally scoped assertion about a subject.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitemporalAssertion<T> {
    /// Object described by this record.
    pub subject: ObjectRef,
    /// Abstract payload carried by this record.
    pub payload: T,
    /// Valid-time and knowledge-time interval.
    pub bitemporal: Bitemporal,
    /// Named source of the record.
    pub source: String,
    /// Nonzero declaration revision.
    pub revision: u64,
    /// Identity of the record superseded by this one.
    pub predecessor: Option<ObjectId>,
}

impl<T> BitemporalAssertion<T> {
    /// Answer whether this record applies at both supplied instants.
    pub fn applies_at(&self, valid_us: i64, knowledge_us: i64) -> bool {
        self.bitemporal.as_of(valid_us, knowledge_us)
    }

    /// Derive the identity of this assertion record.
    pub fn assertion_id(&self) -> ObjectId {
        ObjectId::from_validated(
            ObjectClass::IdentifierAssertion,
            self.subject.id().as_str(),
            &self.source,
            &self.revision.to_string(),
        )
    }

    /// Report whether this record explicitly supersedes another one.
    pub fn supersedes(&self, other: &Self) -> bool {
        self.subject == other.subject
            && self.revision > other.revision
            && self.predecessor.as_ref() == Some(&other.assertion_id())
    }

    /// Validate the record without consulting any clock.
    pub fn validate(&self) -> Result<(), ReferenceCoreError> {
        if self.source.is_empty() {
            return Err(ReferenceCoreError::EmptyAssertionSource);
        }
        if self.revision == 0 {
            return Err(ReferenceCoreError::ZeroRevision);
        }
        if self
            .bitemporal
            .valid_to_us
            .is_some_and(|end| self.bitemporal.valid_from_us > end)
        {
            return Err(ReferenceCoreError::InvalidValidityInterval);
        }
        if self
            .bitemporal
            .transaction_to_us
            .is_some_and(|end| self.bitemporal.transaction_from_us > end)
        {
            return Err(ReferenceCoreError::InvalidKnowledgeInterval);
        }
        Ok(())
    }
}

/// Outcome of a bitemporal ledger lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerResolution {
    /// No applicable record was found.
    Unresolved,
    /// One record matched; the payload is its sorted ledger index.
    Resolved(usize),
    /// Two or more independent heads matched.
    Ambiguous(Vec<usize>),
    /// Two or more heads diverged from one predecessor.
    Conflict(Vec<usize>),
}

/// Append-only store of bitemporal assertions with fail-closed insertion.
#[derive(Debug, Clone)]
pub struct BitemporalLedger<T> {
    entries: Vec<BitemporalAssertion<T>>,
    by_id: BTreeMap<ObjectId, usize>,
    by_subject_revision: BTreeMap<(ObjectRef, u64), usize>,
}

impl<T> BitemporalLedger<T> {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            by_id: BTreeMap::new(),
            by_subject_revision: BTreeMap::new(),
        }
    }

    /// Append a record, rejecting duplicates, unknown predecessors and cycles.
    pub fn insert(
        &mut self,
        assertion: BitemporalAssertion<T>,
    ) -> Result<usize, ReferenceCoreError> {
        assertion.validate()?;
        let key = (assertion.subject.clone(), assertion.revision);
        if self.by_subject_revision.contains_key(&key) {
            return Err(ReferenceCoreError::DuplicateRevision(
                assertion.subject.id().to_string(),
            ));
        }
        let own_id = assertion.assertion_id();
        if assertion.predecessor.as_ref() == Some(&own_id) {
            return Err(ReferenceCoreError::PredecessorCycle(own_id.to_string()));
        }
        if let Some(predecessor) = &assertion.predecessor {
            let Some(pred_index) = self.by_id.get(predecessor).copied() else {
                return Err(ReferenceCoreError::UnknownPredecessor(
                    predecessor.to_string(),
                ));
            };
            if self.reaches(pred_index, &own_id) {
                return Err(ReferenceCoreError::PredecessorCycle(own_id.to_string()));
            }
        }
        let index = self.entries.len();
        self.by_id.insert(own_id, index);
        self.by_subject_revision.insert(key, index);
        self.entries.push(assertion);
        Ok(index)
    }

    /// Query one subject at an explicit valid time and knowledge time.
    pub fn query(&self, subject: &ObjectRef, valid_us: i64, knowledge_us: i64) -> LedgerResolution {
        let mut candidates: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.subject == *subject && entry.applies_at(valid_us, knowledge_us)
            })
            .map(|(index, _)| index)
            .collect();
        candidates.sort_unstable();
        match candidates.len() {
            0 => return LedgerResolution::Unresolved,
            1 => return LedgerResolution::Resolved(candidates[0]),
            _ => {}
        }

        let heads: Vec<usize> = candidates
            .iter()
            .copied()
            .filter(|index| {
                let id = self.entries[*index].assertion_id();
                !candidates.iter().any(|other| {
                    *other != *index && self.entries[*other].predecessor.as_ref() == Some(&id)
                })
            })
            .collect();
        match heads.len() {
            1 => LedgerResolution::Resolved(heads[0]),
            0 => LedgerResolution::Unresolved,
            _ => {
                let parents: Vec<Option<&ObjectId>> = heads
                    .iter()
                    .map(|index| self.entries[*index].predecessor.as_ref())
                    .collect();
                let shared_parent = parents.first().is_some_and(|first| {
                    parents
                        .iter()
                        .all(|parent| parent.is_some() && parent == first)
                });
                if shared_parent {
                    LedgerResolution::Conflict(heads)
                } else {
                    LedgerResolution::Ambiguous(heads)
                }
            }
        }
    }

    /// Read one stored record by its ledger index.
    pub fn get(&self, index: usize) -> Option<&BitemporalAssertion<T>> {
        self.entries.get(index)
    }

    /// Return the number of stored records.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Report whether the ledger holds no records.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn reaches(&self, start: usize, target: &ObjectId) -> bool {
        let mut visited = BTreeSet::new();
        let mut cursor = Some(start);
        while let Some(index) = cursor {
            if !visited.insert(index) || self.entries[index].assertion_id() == *target {
                return true;
            }
            cursor = self.entries[index]
                .predecessor
                .as_ref()
                .and_then(|id| self.by_id.get(id).copied());
        }
        false
    }
}

impl<T> Default for BitemporalLedger<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Lifecycle state recorded for one coverage cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    NotScoped,
    Proposed,
    SourceIdentified,
    RightsUnknown,
    RightsVerified,
    AdapterImplemented,
    ConformanceVerified,
    DataReconciled,
    Qualified,
    Degraded,
    Suspended,
    Retired,
}

impl CoverageState {
    /// Return the contract string for this coverage state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotScoped => "not_scoped",
            Self::Proposed => "proposed",
            Self::SourceIdentified => "source_identified",
            Self::RightsUnknown => "rights_unknown",
            Self::RightsVerified => "rights_verified",
            Self::AdapterImplemented => "adapter_implemented",
            Self::ConformanceVerified => "conformance_verified",
            Self::DataReconciled => "data_reconciled",
            Self::Qualified => "qualified",
            Self::Degraded => "degraded",
            Self::Suspended => "suspended",
            Self::Retired => "retired",
        }
    }
}

/// One coverage fact with explicit dimensions and explicit counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageCell {
    /// Class of object in scope.
    pub class: ObjectClass,
    /// Required jurisdiction dimension.
    pub jurisdiction: String,
    /// Optional venue dimension, unspecified when absent.
    pub venue: Option<String>,
    /// Optional segment dimension, unspecified when absent.
    pub segment: Option<String>,
    /// Optional product dimension, unspecified when absent.
    pub product: Option<String>,
    /// Required capability dimension.
    pub capability: String,
    /// Declared denominator count, unknown when absent.
    pub denominator: Option<u64>,
    /// Declared numerator count, unknown when absent.
    pub numerator: Option<u64>,
    /// Declared coverage state.
    pub state: CoverageState,
}

impl CoverageCell {
    /// Compute a ratio only when both counts are declared and the denominator
    /// is positive. An unknown denominator yields no percentage.
    pub fn ratio(&self) -> Option<f64> {
        match (self.numerator, self.denominator) {
            (Some(numerator), Some(denominator)) if denominator > 0 => {
                Some(numerator as f64 / denominator as f64)
            }
            _ => None,
        }
    }

    /// Validate the required dimensions.
    pub fn validate(&self) -> Result<(), ReferenceCoreError> {
        if self.jurisdiction.is_empty() {
            return Err(ReferenceCoreError::EmptyJurisdiction);
        }
        if self.capability.is_empty() {
            return Err(ReferenceCoreError::EmptyCapability);
        }
        Ok(())
    }

    /// Report whether this cell matches a scope on every dimension.
    pub fn matches_scope(&self, scope: &CoverageScope) -> bool {
        self.class == scope.class
            && self.jurisdiction == scope.jurisdiction
            && self.venue == scope.venue
            && self.segment == scope.segment
            && self.product == scope.product
            && self.capability == scope.capability
    }
}

/// Exact dimensions used for a coverage lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageScope {
    /// Required object class.
    pub class: ObjectClass,
    /// Required jurisdiction.
    pub jurisdiction: String,
    /// Required venue dimension, unspecified when absent.
    pub venue: Option<String>,
    /// Required segment dimension, unspecified when absent.
    pub segment: Option<String>,
    /// Required product dimension, unspecified when absent.
    pub product: Option<String>,
    /// Required capability.
    pub capability: String,
}

/// Outcome of an exact-dimension coverage lookup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageQueryResolution {
    /// No cell had these exact dimensions.
    Unresolved,
    /// One cell matched; the payload is its registry index.
    Resolved(usize),
}

type CoverageKey = (
    ObjectClass,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
);

/// Registry of coverage cells with exact-dimension matching.
#[derive(Debug, Clone)]
pub struct CoverageRegistry {
    entries: Vec<CoverageCell>,
    keys: BTreeSet<CoverageKey>,
}

impl CoverageRegistry {
    /// Create an empty registry. An empty scope collection covers nothing.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            keys: BTreeSet::new(),
        }
    }

    /// Insert one cell, rejecting invalid or duplicate dimension tuples.
    pub fn insert(&mut self, cell: CoverageCell) -> Result<usize, ReferenceCoreError> {
        cell.validate()?;
        let key = Self::key(
            cell.class,
            &cell.jurisdiction,
            &cell.venue,
            &cell.segment,
            &cell.product,
            &cell.capability,
        );
        if self.keys.contains(&key) {
            return Err(ReferenceCoreError::DuplicateCoverageCell);
        }
        let index = self.entries.len();
        self.keys.insert(key);
        self.entries.push(cell);
        Ok(index)
    }

    /// Query one exact dimension tuple, with no wildcard behaviour.
    pub fn query(&self, scope: &CoverageScope) -> CoverageQueryResolution {
        let key = Self::key(
            scope.class,
            &scope.jurisdiction,
            &scope.venue,
            &scope.segment,
            &scope.product,
            &scope.capability,
        );
        self.entries
            .iter()
            .enumerate()
            .find(|(_, cell)| {
                cell.matches_scope(scope)
                    && Self::key(
                        cell.class,
                        &cell.jurisdiction,
                        &cell.venue,
                        &cell.segment,
                        &cell.product,
                        &cell.capability,
                    ) == key
            })
            .map(|(index, _)| CoverageQueryResolution::Resolved(index))
            .unwrap_or(CoverageQueryResolution::Unresolved)
    }

    /// Read one stored cell by its registry index.
    pub fn get(&self, index: usize) -> Option<&CoverageCell> {
        self.entries.get(index)
    }

    fn key(
        class: ObjectClass,
        jurisdiction: &str,
        venue: &Option<String>,
        segment: &Option<String>,
        product: &Option<String>,
        capability: &str,
    ) -> CoverageKey {
        (
            class,
            jurisdiction.to_owned(),
            venue.clone(),
            segment.clone(),
            product.clone(),
            capability.to_owned(),
        )
    }
}

impl Default for CoverageRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object_ref(class: ObjectClass, key: &str) -> ObjectRef {
        ObjectRef::new(class, "namespace-a", "authority-a", key).expect("valid object ref")
    }

    fn assertion(
        value: &str,
        subject: &ObjectRef,
        authority: &str,
        valid_from_us: i64,
        valid_to_us: Option<i64>,
        recorded_at_us: i64,
        revision: u64,
    ) -> IdentifierAssertion {
        IdentifierAssertion {
            scheme: IdentifierScheme::InternalStableKey,
            value: value.to_owned(),
            authority: authority.to_owned(),
            subject: subject.clone(),
            source: "source-a".to_owned(),
            valid_from_us,
            valid_to_us,
            recorded_at_us,
            revision,
            verification_status: VerificationStatus::Asserted,
        }
    }

    fn cell(
        venue: Option<&str>,
        segment: Option<&str>,
        product: Option<&str>,
        denominator: Option<u64>,
        numerator: Option<u64>,
    ) -> CoverageCell {
        CoverageCell {
            class: ObjectClass::Venue,
            jurisdiction: "jurisdiction-a".to_owned(),
            venue: venue.map(str::to_owned),
            segment: segment.map(str::to_owned),
            product: product.map(str::to_owned),
            capability: "capability-a".to_owned(),
            denominator,
            numerator,
            state: CoverageState::NotScoped,
        }
    }

    fn scope(venue: Option<&str>, segment: Option<&str>, product: Option<&str>) -> CoverageScope {
        CoverageScope {
            class: ObjectClass::Venue,
            jurisdiction: "jurisdiction-a".to_owned(),
            venue: venue.map(str::to_owned),
            segment: segment.map(str::to_owned),
            product: product.map(str::to_owned),
            capability: "capability-a".to_owned(),
        }
    }

    #[test]
    fn same_assertion_inputs_derive_same_object_id() {
        let first = ObjectId::derive(ObjectClass::Security, "ns-a", "authority-a", "key-7")
            .expect("first identity");
        let second = ObjectId::derive(ObjectClass::Security, "ns-a", "authority-a", "key-7")
            .expect("second identity");
        assert_eq!(
            first, second,
            "equal assertion inputs derive equal identities"
        );
    }

    #[test]
    fn changed_authority_derives_different_object_id() {
        let first = ObjectId::derive(ObjectClass::Security, "ns-a", "authority-a", "key-7")
            .expect("first identity");
        let second = ObjectId::derive(ObjectClass::Security, "ns-a", "authority-b", "key-7")
            .expect("second identity");
        assert_ne!(
            first, second,
            "authority participates in identity derivation"
        );
    }

    #[test]
    fn twenty_one_object_classes_have_unique_strings() {
        let all = ObjectClass::all();
        assert_eq!(all.len(), 21, "every declared class is enumerated");
        let mut strings = BTreeSet::new();
        for class in all {
            assert!(
                strings.insert(class.as_str()),
                "each class must have a unique contract string"
            );
        }
    }

    #[test]
    fn empty_derivation_inputs_are_rejected() {
        assert!(
            matches!(
                ObjectId::derive(ObjectClass::Venue, "", "authority-a", "key-a"),
                Err(ReferenceCoreError::EmptyNamespace)
            ),
            "empty namespace must be rejected"
        );
        assert!(
            matches!(
                ObjectId::derive(ObjectClass::Venue, "ns-a", "", "key-a"),
                Err(ReferenceCoreError::EmptyAuthority)
            ),
            "empty authority must be rejected"
        );
        assert!(
            matches!(
                ObjectId::derive(ObjectClass::Venue, "ns-a", "authority-a", ""),
                Err(ReferenceCoreError::EmptyStableKey)
            ),
            "empty stable key must be rejected"
        );
    }

    #[test]
    fn assertion_applies_only_inside_valid_and_knowledge_intervals() {
        let subject = object_ref(ObjectClass::Security, "key-1");
        let item = assertion("value-a", &subject, "authority-a", 100, Some(200), 50, 1);
        assert!(item.applies(150, 75), "interior instants apply");
        assert!(!item.applies(99, 75), "earlier valid instant is outside");
        assert!(!item.applies(201, 75), "later valid instant is outside");
        assert!(
            !item.applies(150, 49),
            "earlier knowledge instant is outside"
        );
    }

    #[test]
    fn invalid_assertion_fields_are_rejected() {
        let subject = object_ref(ObjectClass::Security, "key-1");
        let mut item = assertion("value-a", &subject, "authority-a", 100, Some(200), 50, 1);
        item.value.clear();
        assert!(
            matches!(
                item.validate(),
                Err(ReferenceCoreError::EmptyAssertionValue)
            ),
            "empty value must be rejected"
        );
        item.value = "value-a".to_owned();
        item.authority.clear();
        assert!(
            matches!(
                item.validate(),
                Err(ReferenceCoreError::EmptyAssertionAuthority)
            ),
            "empty authority must be rejected"
        );
        item.authority = "authority-a".to_owned();
        item.source.clear();
        assert!(
            matches!(
                item.validate(),
                Err(ReferenceCoreError::EmptyAssertionSource)
            ),
            "empty source must be rejected"
        );
        item.source = "source-a".to_owned();
        item.revision = 0;
        assert!(
            matches!(item.validate(), Err(ReferenceCoreError::ZeroRevision)),
            "zero revision must be rejected"
        );
        item.revision = 1;
        item.valid_to_us = Some(99);
        assert!(
            matches!(
                item.validate(),
                Err(ReferenceCoreError::InvalidValidityInterval)
            ),
            "inverted validity must be rejected"
        );
        item.valid_to_us = Some(200);
        item.subject = object_ref(ObjectClass::IdentifierAssertion, "key-assertion");
        assert!(
            matches!(
                item.validate(),
                Err(ReferenceCoreError::AssertionSubjectIsAssertion)
            ),
            "assertion subject class must be rejected"
        );
    }

    #[test]
    fn single_assertion_resolves_and_outside_time_is_unresolved() {
        let subject = object_ref(ObjectClass::Security, "key-1");
        let item = assertion("value-a", &subject, "authority-a", 100, Some(200), 50, 1);
        assert_eq!(
            resolve_assertions(std::slice::from_ref(&item), 150, 75),
            AssertionResolution::Resolved(0),
            "one applicable assertion resolves"
        );
        assert_eq!(
            resolve_assertions(std::slice::from_ref(&item), 300, 75),
            AssertionResolution::Unresolved,
            "an outside valid instant must not resolve"
        );
    }

    #[test]
    fn resolution_does_not_select_first_match() {
        let subject_a = object_ref(ObjectClass::Security, "key-a");
        let subject_b = object_ref(ObjectClass::Security, "key-b");
        let first = assertion("value-a", &subject_b, "authority-a", 100, None, 50, 1);
        let second = assertion("value-a", &subject_a, "authority-a", 100, None, 50, 1);
        let result = resolve_assertions(&[first, second], 150, 75);
        assert!(
            matches!(result, AssertionResolution::Ambiguous(_)),
            "ambiguous candidates must not resolve to the first index"
        );
    }

    #[test]
    fn distinct_subjects_resolve_ambiguous_with_sorted_indices() {
        let subject_a = object_ref(ObjectClass::Security, "key-a");
        let subject_b = object_ref(ObjectClass::Security, "key-b");
        let first = assertion("value-a", &subject_a, "authority-a", 100, None, 50, 1);
        let second = assertion("value-a", &subject_b, "authority-a", 100, None, 50, 1);
        match resolve_assertions(&[second, first], 150, 75) {
            AssertionResolution::Ambiguous(indices) => {
                assert_eq!(indices, vec![0, 1], "candidate indices must be sorted");
            }
            _ => panic!("distinct subjects must produce an ambiguous outcome"),
        }
    }

    #[test]
    fn same_subject_different_values_with_disagreeing_authority_resolves_conflict() {
        let subject = object_ref(ObjectClass::FinancialInstrument, "key-9");
        let first = assertion("value-a", &subject, "authority-a", 100, Some(400), 50, 1);
        let second = assertion("value-b", &subject, "authority-b", 50, Some(300), 60, 2);
        assert!(
            matches!(
                resolve_assertions(&[first, second], 200, 100),
                AssertionResolution::Conflict(_)
            ),
            "disagreeing claims about one subject must conflict"
        );
    }

    #[test]
    fn bitemporal_query_at_historical_knowledge_time() {
        let subject = object_ref(ObjectClass::Security, "key-2");
        let first = BitemporalAssertion {
            subject: subject.clone(),
            payload: 1_u64,
            bitemporal: Bitemporal::new(10, 20),
            source: "source-a".to_owned(),
            revision: 1,
            predecessor: None,
        };
        let second = BitemporalAssertion {
            subject: subject.clone(),
            payload: 2_u64,
            bitemporal: Bitemporal::new(10, 40),
            source: "source-a".to_owned(),
            revision: 2,
            predecessor: Some(first.assertion_id()),
        };
        assert!(
            second.supersedes(&first),
            "explicit predecessor with higher revision supersedes"
        );
        let mut ledger = BitemporalLedger::new();
        ledger.insert(first).expect("first record");
        ledger.insert(second).expect("second record");
        assert_eq!(
            ledger.query(&subject, 15, 30),
            LedgerResolution::Resolved(0),
            "historical knowledge time resolves the earlier record"
        );
        assert_eq!(
            ledger.query(&subject, 15, 50),
            LedgerResolution::Resolved(1),
            "later knowledge time resolves the superseding record"
        );
    }

    #[test]
    fn unknown_predecessor_is_rejected() {
        let subject = object_ref(ObjectClass::Security, "key-3");
        let missing = ObjectId::derive(
            ObjectClass::IdentifierAssertion,
            "namespace-a",
            "authority-a",
            "missing-key",
        )
        .expect("missing identity");
        let orphan = BitemporalAssertion {
            subject,
            payload: 1_u64,
            bitemporal: Bitemporal::new(10, 20),
            source: "source-a".to_owned(),
            revision: 2,
            predecessor: Some(missing),
        };
        let mut ledger = BitemporalLedger::new();
        assert!(
            matches!(
                ledger.insert(orphan),
                Err(ReferenceCoreError::UnknownPredecessor(_))
            ),
            "unknown predecessor must fail closed"
        );
    }

    #[test]
    fn duplicate_revision_is_rejected() {
        let subject = object_ref(ObjectClass::Security, "key-4");
        let first = BitemporalAssertion {
            subject: subject.clone(),
            payload: 1_u64,
            bitemporal: Bitemporal::new(10, 20),
            source: "source-a".to_owned(),
            revision: 3,
            predecessor: None,
        };
        let duplicate = BitemporalAssertion {
            subject,
            payload: 2_u64,
            bitemporal: Bitemporal::new(10, 30),
            source: "source-a".to_owned(),
            revision: 3,
            predecessor: None,
        };
        let mut ledger = BitemporalLedger::new();
        ledger.insert(first).expect("first record");
        assert!(
            matches!(
                ledger.insert(duplicate),
                Err(ReferenceCoreError::DuplicateRevision(_))
            ),
            "duplicate subject and revision must be rejected"
        );
    }

    #[test]
    fn predecessor_cycle_is_rejected() {
        let subject = object_ref(ObjectClass::Security, "key-5");
        let mut cycle = BitemporalAssertion {
            subject,
            payload: 1_u64,
            bitemporal: Bitemporal::new(10, 20),
            source: "source-a".to_owned(),
            revision: 4,
            predecessor: None,
        };
        let own_id = cycle.assertion_id();
        cycle.predecessor = Some(own_id);
        let mut ledger = BitemporalLedger::new();
        assert!(
            matches!(
                ledger.insert(cycle),
                Err(ReferenceCoreError::PredecessorCycle(_))
            ),
            "self-referential predecessor must be rejected"
        );
    }

    #[test]
    fn supersession_chain_resolves_to_single_head() {
        let subject = object_ref(ObjectClass::Security, "key-6");
        let first = BitemporalAssertion {
            subject: subject.clone(),
            payload: 1_u64,
            bitemporal: Bitemporal::new(10, 20),
            source: "source-a".to_owned(),
            revision: 1,
            predecessor: None,
        };
        let second = BitemporalAssertion {
            subject: subject.clone(),
            payload: 2_u64,
            bitemporal: Bitemporal::new(10, 30),
            source: "source-a".to_owned(),
            revision: 2,
            predecessor: Some(first.assertion_id()),
        };
        let third = BitemporalAssertion {
            subject: subject.clone(),
            payload: 3_u64,
            bitemporal: Bitemporal::new(10, 40),
            source: "source-a".to_owned(),
            revision: 3,
            predecessor: Some(second.assertion_id()),
        };
        let mut ledger = BitemporalLedger::new();
        ledger.insert(first).expect("first record");
        ledger.insert(second).expect("second record");
        let head = ledger.insert(third).expect("third record");
        assert_eq!(
            ledger.query(&subject, 15, 60),
            LedgerResolution::Resolved(head),
            "a single chain head resolves without fallback"
        );
    }

    #[test]
    fn unknown_denominator_yields_no_ratio() {
        let item = cell(None, None, None, None, Some(2));
        assert_eq!(
            item.ratio(),
            None,
            "unknown denominator yields no percentage"
        );
    }

    #[test]
    fn zero_denominator_yields_no_ratio() {
        let item = cell(None, None, None, Some(0), Some(2));
        assert_eq!(item.ratio(), None, "zero denominator yields no percentage");
    }

    #[test]
    fn explicit_counts_yield_exact_ratio() {
        let item = cell(None, None, None, Some(4), Some(2));
        assert_eq!(item.ratio(), Some(0.5), "declared counts yield a ratio");
    }

    #[test]
    fn empty_coverage_registry_covers_nothing() {
        let registry = CoverageRegistry::new();
        assert_eq!(
            registry.query(&scope(None, None, None)),
            CoverageQueryResolution::Unresolved,
            "an empty scope collection covers nothing"
        );
    }

    #[test]
    fn exact_dimension_query_matches_only_equal_scope() {
        let mut registry = CoverageRegistry::new();
        registry
            .insert(cell(None, None, None, Some(4), Some(2)))
            .expect("coverage cell");
        assert_eq!(
            registry.query(&scope(None, None, None)),
            CoverageQueryResolution::Resolved(0),
            "identical dimensions match"
        );
        assert_eq!(
            registry.query(&scope(Some("venue-a"), None, None)),
            CoverageQueryResolution::Unresolved,
            "an absent dimension is unspecified, not a wildcard"
        );
    }
}
