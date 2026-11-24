// SPDX-License-Identifier: Apache-2.0
//! Evidence-bound source, product and capability registry with coverage promotion.
//!
//! Capability claims carry references to retained proof and not the proof bytes.
//! A developer declaration alone cannot raise a capability to `Verified`, and
//! capability standing is recorded apart from rights standing: a capability may
//! be `Verified` while rights remain `Unknown`. Coverage promotion reuses the
//! twelve [`CoverageState`] values and admits only explicitly listed steps.
//!
//! The module declares abstract structures. It names no venue, provider,
//! dataset, rights decision or feed, and it reads no clock.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::domain::information::Bitemporal;
use crate::domain::reference_core::CoverageCell;
use crate::domain::reference_core::CoverageQueryResolution;
use crate::domain::reference_core::CoverageRegistry;
use crate::domain::reference_core::CoverageScope;
use crate::domain::reference_core::CoverageState;
use crate::domain::reference_core::ObjectClass;
use crate::domain::reference_core::ObjectId;
use crate::domain::reference_core::ObjectRef;
use crate::domain::reference_core::ReferenceCoreError;

/// Category of retained proof named by an [`EvidenceRef`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A declaration made by the source itself.
    SourceDeclaration,
    /// An independent check of the declared capability.
    IndependentVerification,
    /// A recorded conformance report.
    ConformanceReport,
    /// A recorded reconciliation report.
    ReconciliationReport,
    /// A recorded grant of rights.
    RightsGrant,
    /// A recorded recovery drill result.
    RecoveryDrill,
}

impl EvidenceKind {
    /// Return the stable contract string for this evidence category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceDeclaration => "source_declaration",
            Self::IndependentVerification => "independent_verification",
            Self::ConformanceReport => "conformance_report",
            Self::ReconciliationReport => "reconciliation_report",
            Self::RightsGrant => "rights_grant",
            Self::RecoveryDrill => "recovery_drill",
        }
    }

    /// Return every declared category in a stable order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::SourceDeclaration,
            Self::IndependentVerification,
            Self::ConformanceReport,
            Self::ReconciliationReport,
            Self::RightsGrant,
            Self::RecoveryDrill,
        ]
    }
}

/// Reference to retained proof and not the proof itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// Category of the retained proof.
    pub kind: EvidenceKind,
    /// Digest of the retained proof bytes.
    pub digest: String,
    /// Microsecond at which the proof was recorded.
    pub recorded_at_us: i64,
    /// Named origin of the proof reference.
    pub source: String,
}

impl EvidenceRef {
    /// Validate the digest format and the named origin.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.digest.is_empty() {
            return Err(CapabilityError::EmptyEvidenceDigest);
        }
        if self.digest.len() < MIN_DIGEST_HEX_CHARS
            || !self.digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CapabilityError::InvalidEvidenceDigest);
        }
        if self.source.is_empty() {
            return Err(CapabilityError::EmptyEvidenceSource);
        }
        Ok(())
    }
}

/// Minimum number of hexadecimal characters in a proof digest reference.
const MIN_DIGEST_HEX_CHARS: usize = 16;

/// Evidentiary standing recorded for one capability claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    /// A claim made without retained proof.
    Asserted,
    /// A claim with retained proof.
    Evidenced,
    /// A claim with independent verification and a conformance report.
    Verified,
    /// A claim whose proof was withdrawn or contradicted.
    Revoked,
}

impl CapabilityState {
    /// Return the stable contract string for this capability state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Asserted => "asserted",
            Self::Evidenced => "evidenced",
            Self::Verified => "verified",
            Self::Revoked => "revoked",
        }
    }
}

/// Rights standing recorded apart from capability standing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RightsState {
    /// No rights decision was recorded.
    Unknown,
    /// Rights were recorded as verified.
    Verified,
    /// Rights were recorded as revoked.
    Revoked,
}

impl RightsState {
    /// Return the stable contract string for this rights state.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Verified => "verified",
            Self::Revoked => "revoked",
        }
    }
}

/// One bitemporal capability claim about a source, data product or feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityAssertion {
    /// Identity of this claim, derived with `ObjectClass::Capability`.
    pub id: ObjectId,
    /// Subject of the claim, restricted to a source, data product or feed.
    pub subject: ObjectRef,
    /// Named capability delivered by the subject.
    pub capability: String,
    /// Evidentiary standing of the claim.
    pub state: CapabilityState,
    /// Rights standing of the claim, recorded separately.
    pub rights: RightsState,
    /// References to retained proof supporting the claim.
    pub evidence: BTreeSet<EvidenceRef>,
    /// Valid-time and knowledge-time interval of the claim.
    pub bitemporal: Bitemporal,
    /// Nonzero declaration revision.
    pub revision: u64,
    /// Named source of the claim.
    pub source: String,
}

impl CapabilityAssertion {
    /// Validate fields, temporal bounds and the evidence required by the state.
    pub fn validate(&self) -> Result<(), CapabilityError> {
        if self.capability.is_empty() {
            return Err(CapabilityError::EmptyCapability);
        }
        if self.source.is_empty() {
            return Err(CapabilityError::EmptySource);
        }
        if !matches!(
            self.subject.class(),
            ObjectClass::Source | ObjectClass::DataProduct | ObjectClass::Feed
        ) {
            return Err(CapabilityError::InvalidSubjectClass);
        }
        if self.revision == 0 {
            return Err(CapabilityError::ZeroRevision);
        }
        if self
            .bitemporal
            .valid_to_us
            .is_some_and(|end| self.bitemporal.valid_from_us > end)
        {
            return Err(CapabilityError::InvalidValidityInterval);
        }
        if self
            .bitemporal
            .transaction_to_us
            .is_some_and(|end| self.bitemporal.transaction_from_us > end)
        {
            return Err(CapabilityError::InvalidKnowledgeInterval);
        }
        for item in &self.evidence {
            item.validate()?;
        }
        self.validate_state_evidence()?;
        Ok(())
    }

    /// Answer whether the claim applies at both supplied instants.
    pub fn applies(&self, valid_us: i64, knowledge_us: i64) -> bool {
        self.bitemporal.as_of(valid_us, knowledge_us)
    }

    fn validate_state_evidence(&self) -> Result<(), CapabilityError> {
        let kinds: BTreeSet<EvidenceKind> = self.evidence.iter().map(|item| item.kind).collect();
        match self.state {
            CapabilityState::Asserted if !kinds.is_empty() => {
                Err(CapabilityError::UnexpectedEvidence)
            }
            CapabilityState::Evidenced | CapabilityState::Revoked if kinds.is_empty() => {
                Err(CapabilityError::MissingEvidence)
            }
            CapabilityState::Verified => {
                if !kinds.contains(&EvidenceKind::IndependentVerification) {
                    return Err(CapabilityError::MissingIndependentVerification);
                }
                if !kinds.contains(&EvidenceKind::ConformanceReport) {
                    return Err(CapabilityError::MissingConformanceReport);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// Typed failure from capability validation, storage or coverage promotion setup.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CapabilityError {
    /// A capability name was empty.
    #[error("empty capability name")]
    EmptyCapability,
    /// A claim source was empty.
    #[error("empty capability source")]
    EmptySource,
    /// A proof reference had an empty digest.
    #[error("empty evidence digest")]
    EmptyEvidenceDigest,
    /// A proof reference had a short or non-hexadecimal digest.
    #[error("invalid evidence digest")]
    InvalidEvidenceDigest,
    /// A proof reference had an empty origin.
    #[error("empty evidence source")]
    EmptyEvidenceSource,
    /// The subject class was not a source, data product or feed.
    #[error("invalid capability subject class")]
    InvalidSubjectClass,
    /// A declaration revision was zero.
    #[error("revision must be nonzero")]
    ZeroRevision,
    /// The valid-time interval ended before it started.
    #[error("valid interval ends before it starts")]
    InvalidValidityInterval,
    /// The knowledge-time interval ended before it started.
    #[error("knowledge interval ends before it starts")]
    InvalidKnowledgeInterval,
    /// An evidenced or revoked claim carried no proof reference.
    #[error("evidenced or revoked capability has no evidence")]
    MissingEvidence,
    /// A verified claim lacked independent verification.
    #[error("verified capability lacks independent verification")]
    MissingIndependentVerification,
    /// A verified claim lacked a conformance report.
    #[error("verified capability lacks a conformance report")]
    MissingConformanceReport,
    /// An asserted claim carried a proof reference.
    #[error("asserted capability must carry no evidence")]
    UnexpectedEvidence,
    /// A claim identity was already stored.
    #[error("duplicate capability identity: {0}")]
    DuplicateId(String),
    /// A subject, capability and revision tuple was already stored.
    #[error("duplicate capability revision: {0}")]
    DuplicateRevision(String),
    /// A named claim was not stored.
    #[error("unknown capability identity: {0}")]
    UnknownId(String),
    /// A qualified cell had missing or non-positive declared counts.
    #[error("qualified cell requires a numerator and a positive denominator")]
    MissingCounts,
    /// A combined-registry cell index was not stored.
    #[error("unknown coverage cell index: {0}")]
    UnknownCell(usize),
}

/// Outcome of a capability lookup at explicit valid and knowledge times.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapabilityResolution {
    /// No applicable claim was found.
    Unresolved,
    /// One claim matched; the payload is its sorted registry index.
    Resolved(usize),
    /// Applicable claims agree on state and rights.
    Ambiguous(Vec<usize>),
    /// Applicable claims disagree about state or rights.
    Conflict(Vec<usize>),
}

/// Append-only-style store of capability claims with fail-closed insertion.
#[derive(Debug, Clone)]
pub struct CapabilityRegistry {
    entries: BTreeMap<ObjectId, CapabilityAssertion>,
    revisions: BTreeMap<(ObjectRef, String, u64), ObjectId>,
    order: Vec<ObjectId>,
}

impl CapabilityRegistry {
    /// Create an empty capability registry. An empty registry resolves nothing.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            revisions: BTreeMap::new(),
            order: Vec::new(),
        }
    }

    /// Store one validated claim, rejecting duplicate identities and revisions.
    pub fn insert(&mut self, assertion: CapabilityAssertion) -> Result<(), CapabilityError> {
        assertion.validate()?;
        if self.entries.contains_key(&assertion.id) {
            return Err(CapabilityError::DuplicateId(assertion.id.to_string()));
        }
        let revision_key = (
            assertion.subject.clone(),
            assertion.capability.clone(),
            assertion.revision,
        );
        if self.revisions.contains_key(&revision_key) {
            return Err(CapabilityError::DuplicateRevision(format!(
                "{} revision {}",
                assertion.subject.id(),
                assertion.revision
            )));
        }
        let id = assertion.id.clone();
        self.entries.insert(id.clone(), assertion);
        self.revisions.insert(revision_key, id.clone());
        self.order.push(id);
        Ok(())
    }

    /// Record a revocation with proof on a stored claim.
    pub fn revoke(
        &mut self,
        id: &ObjectId,
        evidence: BTreeSet<EvidenceRef>,
    ) -> Result<(), CapabilityError> {
        if evidence.is_empty() {
            return Err(CapabilityError::MissingEvidence);
        }
        for item in &evidence {
            item.validate()?;
        }
        let Some(assertion) = self.entries.get_mut(id) else {
            return Err(CapabilityError::UnknownId(id.to_string()));
        };
        assertion.state = CapabilityState::Revoked;
        assertion.evidence.extend(evidence);
        assertion.validate()
    }

    /// Resolve claims for one subject and capability at explicit instants.
    pub fn resolve(
        &self,
        subject: &ObjectRef,
        capability: &str,
        valid_us: i64,
        knowledge_us: i64,
    ) -> CapabilityResolution {
        let mut candidates: Vec<usize> = self
            .order
            .iter()
            .enumerate()
            .filter(|(_, id)| {
                self.entries.get(*id).is_some_and(|claim| {
                    claim.subject == *subject
                        && claim.capability == capability
                        && claim.applies(valid_us, knowledge_us)
                })
            })
            .map(|(index, _)| index)
            .collect();
        candidates.sort_unstable();
        match candidates.as_slice() {
            [] => CapabilityResolution::Unresolved,
            [only] => CapabilityResolution::Resolved(*only),
            [first, remainder @ ..] => {
                let Some(first_claim) = self.claim_at(*first) else {
                    return CapabilityResolution::Unresolved;
                };
                let agrees = remainder.iter().all(|index| {
                    self.claim_at(*index).is_some_and(|claim| {
                        claim.state == first_claim.state && claim.rights == first_claim.rights
                    })
                });
                if agrees {
                    CapabilityResolution::Ambiguous(candidates)
                } else {
                    CapabilityResolution::Conflict(candidates)
                }
            }
        }
    }

    /// Read one stored claim by identity.
    pub fn get(&self, id: &ObjectId) -> Option<&CapabilityAssertion> {
        self.entries.get(id)
    }

    /// Return the number of stored claims.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Report whether no claims are stored.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn claim_at(&self, index: usize) -> Option<&CapabilityAssertion> {
        self.order.get(index).and_then(|id| self.entries.get(id))
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Reason a coverage transition was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionDenial {
    /// The pair is absent from the admitted-transition list.
    NotAdmitted,
    /// The transition would skip a declared stage.
    SkippedStage,
    /// A backward transition carried no recorded reason reference.
    MissingReason,
    /// Qualification requires rights in the verified state.
    MissingRightsVerification,
}

/// Typed refusal of a coverage-state transition.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PromotionError {
    /// The pair or its recorded reason failed admission.
    #[error("coverage transition {from:?} -> {to:?} denied: {denial:?}")]
    Denied {
        /// State at which the transition started.
        from: CoverageState,
        /// State the transition targeted.
        to: CoverageState,
        /// Refusal category.
        denial: PromotionDenial,
    },
    /// Evidence required by the admitted transition was absent.
    #[error("coverage transition {from:?} -> {to:?} missing evidence: {missing:?}")]
    MissingEvidence {
        /// State at which the transition started.
        from: CoverageState,
        /// State the transition targeted.
        to: CoverageState,
        /// Evidence categories that were absent.
        missing: BTreeSet<EvidenceKind>,
    },
}

impl PromotionError {
    /// Return the state at which the refused transition started.
    pub const fn from(&self) -> CoverageState {
        match self {
            Self::Denied { from, .. } | Self::MissingEvidence { from, .. } => *from,
        }
    }

    /// Return the state the refused transition targeted.
    pub const fn to(&self) -> CoverageState {
        match self {
            Self::Denied { to, .. } | Self::MissingEvidence { to, .. } => *to,
        }
    }

    /// Return the absent evidence categories, when the refusal was evidence-based.
    pub fn missing(&self) -> Option<&BTreeSet<EvidenceKind>> {
        match self {
            Self::MissingEvidence { missing, .. } => Some(missing),
            Self::Denied { .. } => None,
        }
    }

    /// Return the refusal category, when the refusal was not evidence-based.
    pub const fn denial(&self) -> Option<PromotionDenial> {
        match self {
            Self::Denied { denial, .. } => Some(*denial),
            Self::MissingEvidence { .. } => None,
        }
    }
}

const ALL_COVERAGE_STATES: [CoverageState; 12] = [
    CoverageState::NotScoped,
    CoverageState::Proposed,
    CoverageState::SourceIdentified,
    CoverageState::RightsUnknown,
    CoverageState::RightsVerified,
    CoverageState::AdapterImplemented,
    CoverageState::ConformanceVerified,
    CoverageState::DataReconciled,
    CoverageState::Qualified,
    CoverageState::Degraded,
    CoverageState::Suspended,
    CoverageState::Retired,
];

#[derive(Debug, Clone)]
struct Admission {
    required: BTreeSet<EvidenceKind>,
    needs_recovery_drill: bool,
    needs_rights_verified: bool,
    needs_reason: bool,
}

impl Admission {
    fn plain() -> Self {
        Self {
            required: BTreeSet::new(),
            needs_recovery_drill: false,
            needs_rights_verified: false,
            needs_reason: false,
        }
    }

    fn with(required: BTreeSet<EvidenceKind>) -> Self {
        Self {
            required,
            ..Self::plain()
        }
    }

    fn qualified() -> Self {
        Self {
            required: BTreeSet::from([
                EvidenceKind::ConformanceReport,
                EvidenceKind::ReconciliationReport,
            ]),
            needs_recovery_drill: true,
            needs_rights_verified: true,
            needs_reason: false,
        }
    }

    fn backward() -> Self {
        Self {
            needs_reason: true,
            ..Self::plain()
        }
    }
}

fn admitted(from: CoverageState, to: CoverageState) -> Option<Admission> {
    match (from, to) {
        (CoverageState::NotScoped, CoverageState::Proposed)
        | (CoverageState::Proposed, CoverageState::SourceIdentified)
        | (CoverageState::SourceIdentified, CoverageState::RightsUnknown)
        | (CoverageState::RightsVerified, CoverageState::AdapterImplemented) => {
            Some(Admission::plain())
        }
        (CoverageState::RightsUnknown, CoverageState::RightsVerified) => {
            Some(Admission::with(BTreeSet::from([EvidenceKind::RightsGrant])))
        }
        (CoverageState::AdapterImplemented, CoverageState::ConformanceVerified) => {
            Some(Admission::with(BTreeSet::from([
                EvidenceKind::ConformanceReport,
            ])))
        }
        (CoverageState::ConformanceVerified, CoverageState::DataReconciled) => {
            Some(Admission::with(BTreeSet::from([
                EvidenceKind::ReconciliationReport,
            ])))
        }
        (CoverageState::DataReconciled, CoverageState::Qualified) => Some(Admission::qualified()),
        (_, CoverageState::Suspended | CoverageState::Retired | CoverageState::Degraded) => {
            Some(Admission::backward())
        }
        _ => None,
    }
}

fn denied(from: CoverageState, to: CoverageState, denial: PromotionDenial) -> PromotionError {
    PromotionError::Denied { from, to, denial }
}

/// Report why a transition between two existing coverage states is refused.
pub fn promotion_error(
    from: CoverageState,
    to: CoverageState,
    evidence: &BTreeSet<EvidenceKind>,
    rights: RightsState,
) -> Option<PromotionError> {
    if from == to {
        return Some(denied(from, to, PromotionDenial::NotAdmitted));
    }
    let Some(admission) = admitted(from, to) else {
        let denial = if from == CoverageState::AdapterImplemented && to == CoverageState::Qualified
        {
            PromotionDenial::SkippedStage
        } else {
            PromotionDenial::NotAdmitted
        };
        return Some(denied(from, to, denial));
    };
    if admission.needs_reason && evidence.is_empty() {
        return Some(denied(from, to, PromotionDenial::MissingReason));
    }
    if admission.needs_rights_verified && rights != RightsState::Verified {
        return Some(denied(from, to, PromotionDenial::MissingRightsVerification));
    }
    let mut missing: BTreeSet<EvidenceKind> =
        admission.required.difference(evidence).copied().collect();
    if admission.needs_recovery_drill && !evidence.contains(&EvidenceKind::RecoveryDrill) {
        missing.insert(EvidenceKind::RecoveryDrill);
    }
    if missing.is_empty() {
        None
    } else {
        Some(PromotionError::MissingEvidence { from, to, missing })
    }
}

/// Return a promoted copy of a cell, leaving the supplied cell unchanged.
pub fn promote(
    cell: &CoverageCell,
    to: CoverageState,
    evidence: &BTreeSet<EvidenceKind>,
    rights: RightsState,
) -> Result<CoverageCell, PromotionError> {
    if let Some(error) = promotion_error(cell.state, to, evidence, rights) {
        return Err(error);
    }
    let mut promoted = cell.clone();
    promoted.state = to;
    Ok(promoted)
}

fn require_declared_counts(cell: &CoverageCell) -> Result<(), CapabilityError> {
    match (cell.denominator, cell.numerator) {
        (Some(denominator), Some(_)) if denominator > 0 => Ok(()),
        _ => Err(CapabilityError::MissingCounts),
    }
}

/// Typed failure from the combined capability and coverage registries.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoverageRegistryError {
    /// The coverage cell failed its own validation.
    #[error(transparent)]
    Coverage(#[from] ReferenceCoreError),
    /// A capability or declared-count rule failed.
    #[error(transparent)]
    Capability(#[from] CapabilityError),
    /// A coverage-state transition was refused.
    #[error(transparent)]
    Promotion(#[from] PromotionError),
}

/// Combined capability registry and exact-dimension coverage registry.
#[derive(Debug, Clone)]
pub struct CapabilityCoverageRegistry {
    capabilities: CapabilityRegistry,
    coverage: CoverageRegistry,
    cells: Vec<CoverageCell>,
}

impl CapabilityCoverageRegistry {
    /// Create an empty combined registry. An empty registry covers nothing.
    pub fn new() -> Self {
        Self {
            capabilities: CapabilityRegistry::new(),
            coverage: CoverageRegistry::new(),
            cells: Vec::new(),
        }
    }

    /// Store one capability claim in the capability half of the registry.
    pub fn insert_capability(
        &mut self,
        assertion: CapabilityAssertion,
    ) -> Result<(), CoverageRegistryError> {
        self.capabilities.insert(assertion)?;
        Ok(())
    }

    /// Store a validated cell, requiring declared counts when already qualified.
    pub fn insert_cell(&mut self, cell: CoverageCell) -> Result<usize, CoverageRegistryError> {
        cell.validate()?;
        if cell.state == CoverageState::Qualified {
            require_declared_counts(&cell)?;
        }
        let index = self.coverage.insert(cell.clone())?;
        self.cells.push(cell);
        Ok(index)
    }

    /// Promote one stored cell to qualified status when evidence and rights admit it.
    pub fn qualify(
        &mut self,
        index: usize,
        evidence: &BTreeSet<EvidenceKind>,
        rights: RightsState,
    ) -> Result<(), CoverageRegistryError> {
        let Some(cell) = self.cells.get(index) else {
            return Err(CapabilityError::UnknownCell(index).into());
        };
        let promoted = promote(cell, CoverageState::Qualified, evidence, rights)?;
        require_declared_counts(&promoted)?;
        self.cells[index] = promoted;
        let mut rebuilt = CoverageRegistry::new();
        for stored in &self.cells {
            rebuilt.insert(stored.clone())?;
        }
        self.coverage = rebuilt;
        Ok(())
    }

    /// Query the coverage half by exact dimensions, with no wildcard behaviour.
    pub fn query_cell(&self, scope: &CoverageScope) -> CoverageQueryResolution {
        self.coverage.query(scope)
    }

    /// Read one stored cell by its registry index.
    pub fn get_cell(&self, index: usize) -> Option<&CoverageCell> {
        self.cells.get(index)
    }

    /// Return the stored capability registry.
    pub fn capabilities(&self) -> &CapabilityRegistry {
        &self.capabilities
    }

    /// Return the stored coverage registry.
    pub fn coverage(&self) -> &CoverageRegistry {
        &self.coverage
    }

    /// Count stored cells for every declared coverage state.
    pub fn coverage_summary(&self) -> BTreeMap<CoverageState, usize> {
        let mut summary: BTreeMap<CoverageState, usize> = ALL_COVERAGE_STATES
            .iter()
            .map(|state| (*state, 0_usize))
            .collect();
        for cell in &self.cells {
            if let Some(count) = summary.get_mut(&cell.state) {
                *count += 1;
            }
        }
        summary
    }
}

impl Default for CapabilityCoverageRegistry {
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

    fn proof(kind: EvidenceKind, tag: &str) -> EvidenceRef {
        EvidenceRef {
            kind,
            digest: format!("{tag}0123456789abcdef"),
            recorded_at_us: 10,
            source: "proof-a".to_owned(),
        }
    }

    fn claim(
        key: &str,
        state: CapabilityState,
        rights: RightsState,
        evidence: BTreeSet<EvidenceRef>,
    ) -> CapabilityAssertion {
        CapabilityAssertion {
            id: ObjectId::derive(ObjectClass::Capability, "namespace-a", "authority-a", key)
                .expect("valid claim identity"),
            subject: object_ref(ObjectClass::Source, "subject-a"),
            capability: "capability-a".to_owned(),
            state,
            rights,
            evidence,
            bitemporal: Bitemporal::new(10, 5),
            revision: key
                .bytes()
                .fold(1_u64, |total, byte| total.saturating_add(u64::from(byte))),
            source: "source-a".to_owned(),
        }
    }

    fn covering(
        state: CoverageState,
        denominator: Option<u64>,
        numerator: Option<u64>,
    ) -> CoverageCell {
        CoverageCell {
            class: ObjectClass::Source,
            jurisdiction: "jurisdiction-a".to_owned(),
            venue: None,
            segment: None,
            product: None,
            capability: "capability-a".to_owned(),
            denominator,
            numerator,
            state,
        }
    }

    #[test]
    fn evidence_kinds_have_stable_contract_strings() {
        let expected = [
            "source_declaration",
            "independent_verification",
            "conformance_report",
            "reconciliation_report",
            "rights_grant",
            "recovery_drill",
        ];
        for (kind, text) in EvidenceKind::all().iter().zip(expected) {
            assert_eq!(kind.as_str(), text, "evidence contract string is stable");
        }
    }

    #[test]
    fn valid_evidence_reference_passes_validation() {
        let item = proof(EvidenceKind::SourceDeclaration, "a");
        assert!(
            item.validate().is_ok(),
            "hex digest and origin are accepted"
        );
    }

    #[test]
    fn empty_evidence_digest_is_rejected() {
        let mut item = proof(EvidenceKind::SourceDeclaration, "a");
        item.digest.clear();
        assert_eq!(
            item.validate(),
            Err(CapabilityError::EmptyEvidenceDigest),
            "empty digest must be rejected"
        );
    }

    #[test]
    fn short_evidence_digest_is_rejected() {
        let mut item = proof(EvidenceKind::SourceDeclaration, "a");
        item.digest = "abc123".to_owned();
        assert_eq!(
            item.validate(),
            Err(CapabilityError::InvalidEvidenceDigest),
            "digest shorter than sixteen characters must be rejected"
        );
    }

    #[test]
    fn non_hex_evidence_digest_is_rejected() {
        let mut item = proof(EvidenceKind::SourceDeclaration, "a");
        item.digest = "zzzzzzzzzzzzzzzz".to_owned();
        assert_eq!(
            item.validate(),
            Err(CapabilityError::InvalidEvidenceDigest),
            "non-hexadecimal digest must be rejected"
        );
    }

    #[test]
    fn empty_evidence_source_is_rejected() {
        let mut item = proof(EvidenceKind::SourceDeclaration, "a");
        item.source.clear();
        assert_eq!(
            item.validate(),
            Err(CapabilityError::EmptyEvidenceSource),
            "empty evidence origin must be rejected"
        );
    }

    #[test]
    fn asserted_claim_with_evidence_is_rejected() {
        let item = claim(
            "claim-a",
            CapabilityState::Asserted,
            RightsState::Unknown,
            BTreeSet::from([proof(EvidenceKind::SourceDeclaration, "a")]),
        );
        assert_eq!(
            item.validate(),
            Err(CapabilityError::UnexpectedEvidence),
            "asserted claims must carry no proof reference"
        );
    }

    #[test]
    fn evidenced_claim_without_evidence_is_rejected() {
        let item = claim(
            "claim-a",
            CapabilityState::Evidenced,
            RightsState::Unknown,
            BTreeSet::new(),
        );
        assert_eq!(
            item.validate(),
            Err(CapabilityError::MissingEvidence),
            "evidenced claims require proof"
        );
    }

    #[test]
    fn revoked_claim_without_evidence_is_rejected() {
        let item = claim(
            "claim-a",
            CapabilityState::Revoked,
            RightsState::Unknown,
            BTreeSet::new(),
        );
        assert_eq!(
            item.validate(),
            Err(CapabilityError::MissingEvidence),
            "revoked claims require proof"
        );
    }

    #[test]
    fn verified_claim_without_required_evidence_is_rejected() {
        let item = claim(
            "claim-a",
            CapabilityState::Verified,
            RightsState::Unknown,
            BTreeSet::from([proof(EvidenceKind::SourceDeclaration, "a")]),
        );
        assert_eq!(
            item.validate(),
            Err(CapabilityError::MissingIndependentVerification),
            "a developer declaration cannot verify a capability"
        );
    }

    #[test]
    fn verified_claim_with_only_independent_evidence_is_rejected() {
        let item = claim(
            "claim-a",
            CapabilityState::Verified,
            RightsState::Unknown,
            BTreeSet::from([proof(EvidenceKind::IndependentVerification, "a")]),
        );
        assert_eq!(
            item.validate(),
            Err(CapabilityError::MissingConformanceReport),
            "independent verification alone cannot verify a capability"
        );
    }

    #[test]
    fn verified_claim_with_both_required_kinds_is_accepted() {
        let evidence = BTreeSet::from([
            proof(EvidenceKind::IndependentVerification, "a"),
            proof(EvidenceKind::ConformanceReport, "b"),
        ]);
        let item = claim(
            "claim-a",
            CapabilityState::Verified,
            RightsState::Unknown,
            evidence,
        );
        assert!(
            item.validate().is_ok(),
            "required proof pair verifies the claim"
        );
    }

    #[test]
    fn verified_capability_keeps_rights_unknown() {
        let evidence = BTreeSet::from([
            proof(EvidenceKind::IndependentVerification, "a"),
            proof(EvidenceKind::ConformanceReport, "b"),
        ]);
        let item = claim(
            "claim-a",
            CapabilityState::Verified,
            RightsState::Unknown,
            evidence,
        );
        assert_eq!(item.rights, RightsState::Unknown, "rights stand apart");
        assert!(
            item.validate().is_ok(),
            "unknown rights do not block capability"
        );
    }

    #[test]
    fn invalid_claim_fields_are_rejected() {
        let mut item = claim(
            "claim-a",
            CapabilityState::Asserted,
            RightsState::Unknown,
            BTreeSet::new(),
        );
        item.subject = object_ref(ObjectClass::Venue, "subject-a");
        assert_eq!(
            item.validate(),
            Err(CapabilityError::InvalidSubjectClass),
            "venue subjects are outside the allowed classes"
        );
        item.subject = object_ref(ObjectClass::Feed, "subject-a");
        item.revision = 0;
        assert_eq!(
            item.validate(),
            Err(CapabilityError::ZeroRevision),
            "zero revision must be rejected"
        );
        item.revision = 1;
        item.source.clear();
        assert_eq!(
            item.validate(),
            Err(CapabilityError::EmptySource),
            "empty source must be rejected"
        );
    }

    #[test]
    fn inverted_claim_intervals_are_rejected() {
        let mut item = claim(
            "claim-a",
            CapabilityState::Asserted,
            RightsState::Unknown,
            BTreeSet::new(),
        );
        item.bitemporal.valid_to_us = Some(9);
        assert_eq!(
            item.validate(),
            Err(CapabilityError::InvalidValidityInterval),
            "inverted valid interval must be rejected"
        );
        item.bitemporal.valid_to_us = None;
        item.bitemporal.transaction_to_us = Some(4);
        assert_eq!(
            item.validate(),
            Err(CapabilityError::InvalidKnowledgeInterval),
            "inverted knowledge interval must be rejected"
        );
    }

    #[test]
    fn duplicate_claim_identity_is_rejected() {
        let mut registry = CapabilityRegistry::new();
        let first = claim(
            "claim-a",
            CapabilityState::Asserted,
            RightsState::Unknown,
            BTreeSet::new(),
        );
        let duplicate = first.clone();
        registry.insert(first).expect("first claim");
        assert!(
            matches!(
                registry.insert(duplicate),
                Err(CapabilityError::DuplicateId(_))
            ),
            "duplicate identity must be rejected"
        );
    }

    #[test]
    fn duplicate_claim_revision_is_rejected() {
        let mut registry = CapabilityRegistry::new();
        let first = claim(
            "claim-a",
            CapabilityState::Asserted,
            RightsState::Unknown,
            BTreeSet::new(),
        );
        let mut second = claim(
            "claim-b",
            CapabilityState::Asserted,
            RightsState::Unknown,
            BTreeSet::new(),
        );
        second.subject = first.subject.clone();
        second.revision = first.revision;
        registry.insert(first).expect("first claim");
        assert!(
            matches!(
                registry.insert(second),
                Err(CapabilityError::DuplicateRevision(_))
            ),
            "repeated subject, capability and revision must be rejected"
        );
    }

    #[test]
    fn revoke_records_proof_and_state() {
        let mut registry = CapabilityRegistry::new();
        let id = object_id("claim-a");
        let assertion = claim(
            "claim-a",
            CapabilityState::Evidenced,
            RightsState::Unknown,
            BTreeSet::from([proof(EvidenceKind::SourceDeclaration, "a")]),
        );
        registry.insert(assertion).expect("stored claim");
        let proof_of_revocation =
            BTreeSet::from([proof(EvidenceKind::IndependentVerification, "b")]);
        registry
            .revoke(&id, proof_of_revocation)
            .expect("revocation");
        let stored = registry.get(&id).expect("revoked claim");
        assert_eq!(
            stored.state,
            CapabilityState::Revoked,
            "state becomes revoked"
        );
        assert_eq!(stored.evidence.len(), 2, "revocation proof is retained");
    }

    #[test]
    fn revoke_without_proof_is_rejected() {
        let mut registry = CapabilityRegistry::new();
        let id = object_id("claim-a");
        let assertion = claim(
            "claim-a",
            CapabilityState::Asserted,
            RightsState::Unknown,
            BTreeSet::new(),
        );
        registry.insert(assertion).expect("stored claim");
        assert_eq!(
            registry.revoke(&id, BTreeSet::new()),
            Err(CapabilityError::MissingEvidence),
            "revocation needs a recorded reason reference"
        );
    }

    #[test]
    fn resolution_is_unresolved_outside_applicable_instants() {
        let registry = CapabilityRegistry::new();
        let subject = object_ref(ObjectClass::Source, "subject-a");
        assert_eq!(
            registry.resolve(&subject, "capability-a", 15, 10),
            CapabilityResolution::Unresolved,
            "an empty registry resolves nothing"
        );
        let mut filled = registry;
        filled
            .insert(claim(
                "claim-a",
                CapabilityState::Asserted,
                RightsState::Unknown,
                BTreeSet::new(),
            ))
            .expect("stored claim");
        assert_eq!(
            filled.resolve(&subject, "capability-a", 5, 10),
            CapabilityResolution::Unresolved,
            "a valid instant before the interval does not resolve"
        );
    }

    #[test]
    fn resolution_returns_one_sorted_candidate() {
        let mut registry = CapabilityRegistry::new();
        let subject = object_ref(ObjectClass::Source, "subject-a");
        registry
            .insert(claim(
                "claim-a",
                CapabilityState::Asserted,
                RightsState::Unknown,
                BTreeSet::new(),
            ))
            .expect("stored claim");
        assert_eq!(
            registry.resolve(&subject, "capability-a", 15, 10),
            CapabilityResolution::Resolved(0),
            "one applicable claim resolves to its index"
        );
    }

    #[test]
    fn resolution_does_not_select_first_matching_candidate() {
        let mut registry = CapabilityRegistry::new();
        let subject = object_ref(ObjectClass::Source, "subject-a");
        for key in ["claim-a", "claim-b"] {
            registry
                .insert(claim(
                    key,
                    CapabilityState::Evidenced,
                    RightsState::Unknown,
                    BTreeSet::from([proof(EvidenceKind::SourceDeclaration, "a")]),
                ))
                .expect("stored claim");
        }
        assert_eq!(
            registry.resolve(&subject, "capability-a", 15, 10),
            CapabilityResolution::Ambiguous(vec![0, 1]),
            "agreeing claims must not collapse to the first index"
        );
    }

    #[test]
    fn resolution_reports_conflict_for_disagreeing_claims() {
        let mut registry = CapabilityRegistry::new();
        let subject = object_ref(ObjectClass::Source, "subject-a");
        registry
            .insert(claim(
                "claim-a",
                CapabilityState::Evidenced,
                RightsState::Unknown,
                BTreeSet::from([proof(EvidenceKind::SourceDeclaration, "a")]),
            ))
            .expect("first claim");
        registry
            .insert(claim(
                "claim-b",
                CapabilityState::Revoked,
                RightsState::Unknown,
                BTreeSet::from([proof(EvidenceKind::SourceDeclaration, "b")]),
            ))
            .expect("second claim");
        assert_eq!(
            registry.resolve(&subject, "capability-a", 15, 10),
            CapabilityResolution::Conflict(vec![0, 1]),
            "disagreeing claims must surface as a conflict"
        );
    }

    #[test]
    fn resolution_honours_historical_knowledge_time() {
        let mut registry = CapabilityRegistry::new();
        let subject = object_ref(ObjectClass::Source, "subject-a");
        let mut earlier = claim(
            "claim-a",
            CapabilityState::Asserted,
            RightsState::Unknown,
            BTreeSet::new(),
        );
        earlier.bitemporal.transaction_to_us = Some(20);
        let mut later = claim(
            "claim-b",
            CapabilityState::Asserted,
            RightsState::Unknown,
            BTreeSet::new(),
        );
        later.bitemporal.transaction_from_us = 20;
        registry.insert(earlier).expect("earlier claim");
        registry.insert(later).expect("later claim");
        assert_eq!(
            registry.resolve(&subject, "capability-a", 15, 10),
            CapabilityResolution::Resolved(0),
            "historical knowledge time selects the earlier claim"
        );
        assert_eq!(
            registry.resolve(&subject, "capability-a", 15, 30),
            CapabilityResolution::Resolved(1),
            "later knowledge time selects the later claim"
        );
    }

    #[test]
    fn adapter_implemented_cannot_skip_to_qualified() {
        let error = promotion_error(
            CoverageState::AdapterImplemented,
            CoverageState::Qualified,
            &BTreeSet::from([
                EvidenceKind::ConformanceReport,
                EvidenceKind::ReconciliationReport,
                EvidenceKind::RecoveryDrill,
            ]),
            RightsState::Verified,
        );
        assert_eq!(
            error.map(|item| item.denial()),
            Some(Some(PromotionDenial::SkippedStage)),
            "skipping directly to qualification must be refused"
        );
    }

    #[test]
    fn qualification_requires_all_evidence_and_verified_rights() {
        let insufficient = BTreeSet::from([
            EvidenceKind::ConformanceReport,
            EvidenceKind::ReconciliationReport,
        ]);
        let error = promotion_error(
            CoverageState::DataReconciled,
            CoverageState::Qualified,
            &insufficient,
            RightsState::Verified,
        );
        assert_eq!(
            error.and_then(|item| item.missing().cloned()),
            Some(BTreeSet::from([EvidenceKind::RecoveryDrill])),
            "a recovery drill must be recorded for qualification"
        );
        let mut complete = insufficient;
        complete.insert(EvidenceKind::RecoveryDrill);
        assert_eq!(
            promotion_error(
                CoverageState::DataReconciled,
                CoverageState::Qualified,
                &complete,
                RightsState::Unknown,
            )
            .map(|item| item.denial()),
            Some(Some(PromotionDenial::MissingRightsVerification)),
            "unknown rights block qualification"
        );
        assert_eq!(
            promotion_error(
                CoverageState::DataReconciled,
                CoverageState::Qualified,
                &complete,
                RightsState::Verified,
            ),
            None,
            "complete evidence and verified rights admit qualification"
        );
    }

    #[test]
    fn stage_specific_evidence_is_required() {
        assert_eq!(
            promotion_error(
                CoverageState::ConformanceVerified,
                CoverageState::DataReconciled,
                &BTreeSet::new(),
                RightsState::Unknown,
            )
            .and_then(|item| item.missing().cloned()),
            Some(BTreeSet::from([EvidenceKind::ReconciliationReport])),
            "data reconciliation requires a reconciliation report"
        );
        assert_eq!(
            promotion_error(
                CoverageState::AdapterImplemented,
                CoverageState::ConformanceVerified,
                &BTreeSet::new(),
                RightsState::Unknown,
            )
            .and_then(|item| item.missing().cloned()),
            Some(BTreeSet::from([EvidenceKind::ConformanceReport])),
            "conformance verification requires a conformance report"
        );
    }

    #[test]
    fn rights_unknown_requires_grant_to_promote() {
        assert_eq!(
            promotion_error(
                CoverageState::RightsUnknown,
                CoverageState::RightsVerified,
                &BTreeSet::new(),
                RightsState::Unknown,
            )
            .and_then(|item| item.missing().cloned()),
            Some(BTreeSet::from([EvidenceKind::RightsGrant])),
            "rights promotion without a grant is refused"
        );
        assert_eq!(
            promotion_error(
                CoverageState::RightsUnknown,
                CoverageState::RightsVerified,
                &BTreeSet::from([EvidenceKind::RightsGrant]),
                RightsState::Unknown,
            ),
            None,
            "a recorded grant admits rights promotion"
        );
    }

    #[test]
    fn backward_transitions_need_a_recorded_reason() {
        for target in [
            CoverageState::Suspended,
            CoverageState::Retired,
            CoverageState::Degraded,
        ] {
            assert_eq!(
                promotion_error(
                    CoverageState::Qualified,
                    target,
                    &BTreeSet::new(),
                    RightsState::Verified,
                )
                .map(|item| item.denial()),
                Some(Some(PromotionDenial::MissingReason)),
                "backward transitions require a recorded reason reference"
            );
            let reason = BTreeSet::from([EvidenceKind::SourceDeclaration]);
            assert_eq!(
                promotion_error(
                    CoverageState::Qualified,
                    target,
                    &reason,
                    RightsState::Verified,
                ),
                None,
                "a recorded reason admits a backward transition"
            );
        }
    }

    #[test]
    fn promotion_error_carries_source_and_target_states() {
        let error = promotion_error(
            CoverageState::NotScoped,
            CoverageState::Qualified,
            &BTreeSet::new(),
            RightsState::Unknown,
        )
        .expect("refused transition");
        assert_eq!(
            error.from(),
            CoverageState::NotScoped,
            "source state is reported"
        );
        assert_eq!(
            error.to(),
            CoverageState::Qualified,
            "target state is reported"
        );
        assert!(
            error.missing().is_none(),
            "a denied pair has no missing evidence"
        );
    }

    #[test]
    fn promote_returns_a_copy_and_leaves_input_unchanged() {
        let original = covering(CoverageState::DataReconciled, Some(4), Some(2));
        let evidence = BTreeSet::from([
            EvidenceKind::ConformanceReport,
            EvidenceKind::ReconciliationReport,
            EvidenceKind::RecoveryDrill,
        ]);
        let promoted = promote(
            &original,
            CoverageState::Qualified,
            &evidence,
            RightsState::Verified,
        )
        .expect("admitted promotion");
        assert_eq!(
            original.state,
            CoverageState::DataReconciled,
            "input cell keeps its state"
        );
        assert_eq!(
            promoted.state,
            CoverageState::Qualified,
            "returned cell carries the target state"
        );
        assert_ne!(
            promoted, original,
            "promotion produces a distinct stored value"
        );
    }

    #[test]
    fn qualified_cell_without_counts_is_rejected_on_insert() {
        let mut registry = CapabilityCoverageRegistry::new();
        assert_eq!(
            registry.insert_cell(covering(CoverageState::Qualified, None, Some(2))),
            Err(CoverageRegistryError::Capability(
                CapabilityError::MissingCounts
            )),
            "a qualified cell needs a declared denominator"
        );
        assert_eq!(
            registry.insert_cell(covering(CoverageState::Qualified, Some(4), None)),
            Err(CoverageRegistryError::Capability(
                CapabilityError::MissingCounts
            )),
            "a qualified cell needs a declared numerator"
        );
    }

    #[test]
    fn qualified_cell_with_zero_denominator_is_rejected_on_insert() {
        let mut registry = CapabilityCoverageRegistry::new();
        assert_eq!(
            registry.insert_cell(covering(CoverageState::Qualified, Some(0), Some(2))),
            Err(CoverageRegistryError::Capability(
                CapabilityError::MissingCounts
            )),
            "zero denominator cannot support qualification"
        );
    }

    #[test]
    fn qualify_rejects_missing_evidence_and_unknown_index() {
        let mut registry = CapabilityCoverageRegistry::new();
        let index = registry
            .insert_cell(covering(CoverageState::DataReconciled, Some(4), Some(2)))
            .expect("stored cell");
        assert!(
            matches!(
                registry.qualify(index, &BTreeSet::new(), RightsState::Verified),
                Err(CoverageRegistryError::Promotion(_)),
            ),
            "missing evidence blocks qualification"
        );
        assert_eq!(
            registry.qualify(99, &BTreeSet::new(), RightsState::Verified),
            Err(CoverageRegistryError::Capability(
                CapabilityError::UnknownCell(99)
            )),
            "unknown cell indices fail closed"
        );
    }

    #[test]
    fn qualify_updates_the_stored_cell() {
        let mut registry = CapabilityCoverageRegistry::new();
        let index = registry
            .insert_cell(covering(CoverageState::DataReconciled, Some(4), Some(2)))
            .expect("stored cell");
        let evidence = BTreeSet::from([
            EvidenceKind::ConformanceReport,
            EvidenceKind::ReconciliationReport,
            EvidenceKind::RecoveryDrill,
        ]);
        registry
            .qualify(index, &evidence, RightsState::Verified)
            .expect("admitted qualification");
        assert_eq!(
            registry.get_cell(index).expect("stored cell").state,
            CoverageState::Qualified,
            "the stored cell advances after qualification"
        );
    }

    #[test]
    fn empty_combined_registry_covers_nothing() {
        let registry = CapabilityCoverageRegistry::new();
        let scope = CoverageScope {
            class: ObjectClass::Source,
            jurisdiction: "jurisdiction-a".to_owned(),
            venue: None,
            segment: None,
            product: None,
            capability: "capability-a".to_owned(),
        };
        assert_eq!(
            registry.query_cell(&scope),
            CoverageQueryResolution::Unresolved,
            "an empty registry has no coverage"
        );
        assert!(
            registry.capabilities().is_empty(),
            "an empty registry has no capabilities"
        );
        assert_eq!(
            registry.coverage_summary().values().sum::<usize>(),
            0,
            "an empty registry counts no cells"
        );
    }

    #[test]
    fn coverage_summary_counts_each_state() {
        let mut registry = CapabilityCoverageRegistry::new();
        registry
            .insert_cell(covering(CoverageState::NotScoped, None, None))
            .expect("first cell");
        let mut second_cell = covering(CoverageState::NotScoped, None, None);
        second_cell.product = Some("product-a".to_owned());
        registry.insert_cell(second_cell).expect("second cell");
        let summary = registry.coverage_summary();
        assert_eq!(summary.len(), 12, "all declared states are enumerated");
        assert_eq!(
            summary.get(&CoverageState::NotScoped),
            Some(&2),
            "two cells share one state"
        );
        assert_eq!(
            summary.get(&CoverageState::Qualified),
            Some(&0),
            "unused states report a zero count"
        );
    }

    fn object_id(key: &str) -> ObjectId {
        ObjectId::derive(ObjectClass::Capability, "namespace-a", "authority-a", key)
            .expect("valid claim identity")
    }
}
