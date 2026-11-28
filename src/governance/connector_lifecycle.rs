// SPDX-License-Identifier: Apache-2.0
//! Transport-independent connector lifecycle state machine.
//!
//! The machine records decisions about a sequence of phases:
//! `Preflight` → `Connect` → `Discover` → `Subscribe` → `Capture` → `Decode` →
//! `Validate` → `Archive` → `Publish`, with `Quarantine` and `Closed` as
//! cleanup branches reachable from every nonterminal phase. There is no
//! concrete provider, socket, storage or market payload in this module.
//!
//! Rights are bound to *operations*, never to one global boolean. The six
//! operation scopes are provider connection/collection, local capture/storage,
//! decoding/transformation, retention, publication/downstream use and research
//! use. Every externally relevant transition consumes a single-use operation
//! lease: a typed authority backed by the exact source/provider identity,
//! product/instrument scope, operation, retention and permitted-use terms,
//! validity interval and evidence decision digest. A lease is issued only at
//! the integration boundary from a trusted clock observation. The pure state
//! machine never reads a clock: caller-supplied timestamps and
//! `RightsEvidenceState::Admitted` are declarations, not a rights grant.
//!
//! A denial revokes the affected scope permanently; an expired or reused lease
//! denies the individual operation without restoring any revoked scope.
//! Cleanup (`Quarantine`/`Closed`) needs no capability, grants none, publishes
//! nothing, extends no retention and admits no data. Publication remains a
//! separate authorised transition from `Archive` only.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;

use crate::util::sha256_hex;

/// Exact denial code for rights evidence that is unknown, missing, expired,
/// out of scope, already denied or backed by a non-current lease.
pub const RIGHTS_NOT_ADMITTED: &str = "RIGHTS_NOT_ADMITTED";

/// Stable reason codes for lifecycle denials and replay rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleReason {
    RightsNotAdmitted,
    InvalidTransition,
    CaptureBeforePreflight,
    LogMismatch,
}

impl LifecycleReason {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RightsNotAdmitted => RIGHTS_NOT_ADMITTED,
            Self::InvalidTransition => "INVALID_TRANSITION",
            Self::CaptureBeforePreflight => "CAPTURE_BEFORE_PREFLIGHT",
            Self::LogMismatch => "LOG_MISMATCH",
        }
    }
}

impl fmt::Display for LifecycleReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Typed lifecycle denial. A denial never advances the machine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("connector lifecycle denied: reason={reason} detail={detail}")]
pub struct LifecycleError {
    pub reason: LifecycleReason,
    pub detail: String,
}

impl LifecycleError {
    fn new(reason: LifecycleReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// Stable reason code of this denial.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        self.reason.as_str()
    }
}

fn rights_denial(detail: impl Into<String>) -> LifecycleError {
    LifecycleError::new(LifecycleReason::RightsNotAdmitted, detail)
}

/// Connector phases. All transitions are pure value changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorState {
    Preflight,
    Connect,
    Discover,
    Subscribe,
    Capture,
    Decode,
    Validate,
    Archive,
    Publish,
    Quarantine,
    Closed,
}

impl ConnectorState {
    /// Stable audit spelling of this phase.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Connect => "connect",
            Self::Discover => "discover",
            Self::Subscribe => "subscribe",
            Self::Capture => "capture",
            Self::Decode => "decode",
            Self::Validate => "validate",
            Self::Archive => "archive",
            Self::Publish => "publish",
            Self::Quarantine => "quarantine",
            Self::Closed => "closed",
        }
    }

    /// Legal successor phases from this phase.
    ///
    /// Every nonterminal phase can abort into `Quarantine` and then `Closed`.
    /// `Publish` has exactly one predecessor: an authorised `Archive` step.
    #[must_use]
    pub const fn allows(self, target: Self) -> bool {
        match self {
            Self::Preflight => matches!(target, Self::Connect | Self::Quarantine | Self::Closed),
            Self::Connect => matches!(target, Self::Discover | Self::Quarantine | Self::Closed),
            Self::Discover => matches!(target, Self::Subscribe | Self::Quarantine | Self::Closed),
            Self::Subscribe => matches!(target, Self::Capture | Self::Quarantine | Self::Closed),
            Self::Capture => matches!(target, Self::Decode | Self::Quarantine | Self::Closed),
            Self::Decode => matches!(target, Self::Validate | Self::Quarantine | Self::Closed),
            Self::Validate => matches!(target, Self::Archive | Self::Quarantine | Self::Closed),
            Self::Archive => matches!(target, Self::Publish | Self::Quarantine | Self::Closed),
            Self::Publish => matches!(target, Self::Closed),
            Self::Quarantine => matches!(target, Self::Closed),
            Self::Closed => false,
        }
    }
}

/// Operation-scoped rights capability. A phase may only advance when the
/// scope for its operation has a current, unconsumed lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationScope {
    /// Provider connection and collection.
    ProviderConnection,
    /// Local capture and storage.
    LocalCapture,
    /// Decoding and transformation.
    DecodeTransform,
    /// Retention of records.
    Retention,
    /// Publication and downstream use.
    Publication,
    /// Research use, gated explicitly because it has no lifecycle phase.
    ResearchUse,
}

impl OperationScope {
    /// All defined operation scopes in their declaration order.
    pub const ALL: [Self; 6] = [
        Self::ProviderConnection,
        Self::LocalCapture,
        Self::DecodeTransform,
        Self::Retention,
        Self::Publication,
        Self::ResearchUse,
    ];

    /// Stable audit spelling of this scope.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderConnection => "provider_connection",
            Self::LocalCapture => "local_capture",
            Self::DecodeTransform => "decode_transform",
            Self::Retention => "retention",
            Self::Publication => "publication",
            Self::ResearchUse => "research_use",
        }
    }
}

/// State of caller-supplied rights evidence. `Admitted` is a declaration by
/// the caller; it is never itself a rights grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RightsEvidenceState {
    Admitted,
    Unknown,
    Expired,
    OutOfScope,
}

/// Exact source, provider, product and instrument identity a lease is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseSubject {
    pub source_id: String,
    pub provider_id: String,
    pub product_ref: String,
    pub instrument_ref: String,
}

impl LeaseSubject {
    fn complete(&self) -> bool {
        [
            self.source_id.as_str(),
            self.provider_id.as_str(),
            self.product_ref.as_str(),
            self.instrument_ref.as_str(),
        ]
        .iter()
        .all(|value| !value.trim().is_empty())
    }
}

/// Retention and permitted-use terms a lease is bound to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseTerms {
    pub retention_until_utc_ns: u64,
    pub permitted_uses: BTreeSet<String>,
}

impl LeaseTerms {
    fn complete(&self) -> bool {
        self.retention_until_utc_ns > 0
            && !self.permitted_uses.is_empty()
            && self
                .permitted_uses
                .iter()
                .all(|value| !value.trim().is_empty())
    }
}

/// The operation a caller asks to perform and the exact scope it needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRequest {
    /// Unique issuance reference supplied by the trusted boundary. It makes
    /// each lease single-use even when evidence and observation are unchanged.
    pub lease_ref: String,
    pub operation_ref: String,
    pub required_scope: OperationScope,
    pub subject: LeaseSubject,
    pub terms: LeaseTerms,
    /// Caller-declared observation time. This value is explicitly *not* a
    /// trusted clock reading and is never used to grant or renew a lease.
    pub declared_observed_at_utc_ns: u64,
}

impl OperationRequest {
    fn complete(&self) -> bool {
        !self.lease_ref.trim().is_empty()
            && !self.operation_ref.trim().is_empty()
            && self.subject.complete()
            && self.terms.complete()
    }
}

/// Caller-supplied rights evidence bound to one operation, identity and term
/// set. Presence of this value is not a grant: authority is derived from the
/// evidence digest, declared state, exact bindings, validity interval and a
/// trusted clock observation at the integration boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRightsEvidence {
    pub evidence_ref: String,
    pub operation_ref: String,
    pub state: RightsEvidenceState,
    pub granted_scopes: BTreeSet<OperationScope>,
    pub valid_from_utc_ns: u64,
    pub valid_until_utc_ns: Option<u64>,
    pub subject: LeaseSubject,
    pub terms: LeaseTerms,
    /// Digest of the authority's decision; supplied by the caller, never
    /// synthesized or upgraded by this pure state machine.
    pub authority_digest: String,
}

/// Kind of a recorded decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// Preflight accepted caller-supplied evidence for one scope and issued a lease.
    Admitted,
    /// Preflight rejected caller-supplied evidence for one scope.
    PreflightDenied,
    /// A permitted phase transition was applied.
    Advanced,
    /// A phase transition was denied; the phase did not change.
    Denied,
}

/// One immutable decision record. Sequence numbers start at one and are
/// consecutive in a log. `to` names the requested target even when a
/// transition is denied, so replay can reproduce the denial exactly.
/// `lease_digest` is present only for transitions that consumed a lease.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedDecision {
    pub sequence: u64,
    pub from: ConnectorState,
    pub to: ConnectorState,
    pub kind: DecisionKind,
    pub reason_code: Option<LifecycleReason>,
    pub scope: Option<OperationScope>,
    pub lease_digest: Option<String>,
}

/// Trusted UTC clock seam. The pure machine never calls this trait; only the
/// integration boundary does, through [`observe`].
pub trait TrustedUtcClock {
    /// Current UTC time in nanoseconds since the Unix epoch.
    ///
    /// # Errors
    /// Returns [`LifecycleReason::RightsNotAdmitted`] when a trustworthy
    /// reading is unavailable, so evaluation fails closed.
    fn now_utc_ns(&self) -> Result<u64, LifecycleError>;
}

/// System-clock implementation of the trusted boundary clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemUtcClock;

impl TrustedUtcClock for SystemUtcClock {
    fn now_utc_ns(&self) -> Result<u64, LifecycleError> {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| rights_denial("trusted clock precedes the Unix epoch"))?;
        u64::try_from(elapsed.as_nanos())
            .map_err(|_| rights_denial("trusted clock exceeds u64 nanoseconds"))
    }
}

/// Opaque, digest-sealed clock observation. Only [`observe`] can produce one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedObservation {
    now_utc_ns: u64,
    seal: String,
}

impl TrustedObservation {
    fn seal(now_utc_ns: u64) -> String {
        digest_parts(&[
            "fieldbook-p13-trusted-observation-v1".to_owned(),
            now_utc_ns.to_string(),
        ])
    }

    fn authentic(&self) -> bool {
        self.seal == Self::seal(self.now_utc_ns)
    }

    /// Trusted reading used by lease issuance and currency checks.
    #[must_use]
    pub const fn as_utc_ns(&self) -> u64 {
        self.now_utc_ns
    }
}

/// Read the trusted clock once at the integration boundary.
///
/// # Errors
/// Returns [`LifecycleReason::RightsNotAdmitted`] when the clock cannot give a
/// trustworthy reading.
pub fn observe(clock: &impl TrustedUtcClock) -> Result<TrustedObservation, LifecycleError> {
    let now_utc_ns = clock.now_utc_ns()?;
    Ok(TrustedObservation {
        now_utc_ns,
        seal: TrustedObservation::seal(now_utc_ns),
    })
}

fn digest_parts(parts: &[String]) -> String {
    let mut input = String::new();
    for part in parts {
        input.push_str(&part.len().to_string());
        input.push(':');
        input.push_str(part);
    }
    sha256_hex(input.as_bytes())
}

fn is_authority_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Single-use operation authorisation issued from validated evidence at the
/// integration boundary. Fields are private so a caller cannot synthesize a
/// grant from a caller-supplied timestamp or an `Admitted` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationLease {
    lease_ref: String,
    subject: LeaseSubject,
    operation_ref: String,
    scope: OperationScope,
    terms: LeaseTerms,
    not_before_utc_ns: u64,
    valid_until_utc_ns: u64,
    authority_digest: String,
    seal: String,
}

impl OperationLease {
    fn new(
        evidence: &OperationRightsEvidence,
        request: &OperationRequest,
        observation: &TrustedObservation,
    ) -> Self {
        let valid_until_utc_ns = evidence
            .valid_until_utc_ns
            .unwrap_or(observation.as_utc_ns());
        let lease_ref = request.lease_ref.clone();
        let mut lease = Self {
            lease_ref,
            subject: request.subject.clone(),
            operation_ref: request.operation_ref.clone(),
            scope: request.required_scope,
            terms: request.terms.clone(),
            not_before_utc_ns: evidence.valid_from_utc_ns,
            valid_until_utc_ns,
            authority_digest: evidence.authority_digest.clone(),
            seal: String::new(),
        };
        lease.seal = lease.compute_seal();
        lease
    }

    fn compute_seal(&self) -> String {
        let permitted_uses = self
            .terms
            .permitted_uses
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        digest_parts(&[
            "fieldbook-p13-operation-lease-v1".to_owned(),
            self.lease_ref.clone(),
            self.subject.source_id.clone(),
            self.subject.provider_id.clone(),
            self.subject.product_ref.clone(),
            self.subject.instrument_ref.clone(),
            self.operation_ref.clone(),
            self.scope.as_str().to_owned(),
            self.terms.retention_until_utc_ns.to_string(),
            permitted_uses,
            self.not_before_utc_ns.to_string(),
            self.valid_until_utc_ns.to_string(),
            self.authority_digest.clone(),
        ])
    }

    fn recompute_seal(&self) -> String {
        self.compute_seal()
    }

    /// Whether this lease is authentic, unexpired and active at the trusted
    /// observation. A caller-declared time cannot satisfy this check.
    #[must_use]
    pub fn is_current_at(&self, observation: &TrustedObservation) -> bool {
        observation.authentic()
            && self.seal == self.recompute_seal()
            && observation.as_utc_ns() >= self.not_before_utc_ns
            && observation.as_utc_ns() < self.valid_until_utc_ns
    }

    /// Digest used to enforce single use and bind the lease to the decision log.
    #[must_use]
    pub fn digest(&self) -> String {
        self.seal.clone()
    }

    /// Operation scope this lease authorises.
    #[must_use]
    pub const fn scope(&self) -> OperationScope {
        self.scope
    }

    /// Operation this lease authorises.
    #[must_use]
    pub fn operation_ref(&self) -> &str {
        &self.operation_ref
    }

    /// Exact identity this lease is bound to.
    #[must_use]
    pub const fn subject(&self) -> &LeaseSubject {
        &self.subject
    }

    /// Retention and permitted-use terms this lease is bound to.
    #[must_use]
    pub const fn terms(&self) -> &LeaseTerms {
        &self.terms
    }
}

/// Pure preflight evaluation over caller-supplied declarations and a trusted
/// clock observation. This is the only way to issue an [`OperationLease`].
///
/// # Errors
/// Returns [`LifecycleReason::RightsNotAdmitted`] when the observation is not
/// authentic, the request or evidence is incomplete, the evidence is bound to
/// another operation/identity/terms, its declared state is not admitted, the
/// required scope is absent, the authority digest is malformed, or the trusted
/// observation lies outside the evidence's validity interval. The caller's
/// `declared_observed_at_utc_ns` is ignored: it is not a rights grant.
pub fn evaluate_preflight(
    evidence: Option<&OperationRightsEvidence>,
    request: &OperationRequest,
    observation: &TrustedObservation,
) -> Result<OperationLease, LifecycleError> {
    if !observation.authentic() {
        return Err(rights_denial("trusted clock observation is not authentic"));
    }
    if !request.complete() {
        return Err(rights_denial("operation request is incomplete"));
    }
    let Some(evidence) = evidence else {
        return Err(rights_denial("rights evidence is missing"));
    };
    if evidence.evidence_ref.trim().is_empty()
        || !evidence.subject.complete()
        || !evidence.terms.complete()
        || !is_authority_digest(&evidence.authority_digest)
    {
        return Err(rights_denial(
            "operation-level rights evidence is incomplete",
        ));
    }
    if evidence.operation_ref != request.operation_ref {
        return Err(rights_denial(
            "rights evidence is bound to another operation",
        ));
    }
    if evidence.subject != request.subject {
        return Err(rights_denial(
            "rights evidence is bound to another source or instrument",
        ));
    }
    if evidence.terms != request.terms {
        return Err(rights_denial(
            "rights evidence is bound to different retention or use terms",
        ));
    }
    let state_detail = match evidence.state {
        RightsEvidenceState::Admitted => None,
        RightsEvidenceState::Unknown => Some("rights state is unknown"),
        RightsEvidenceState::Expired => Some("rights state is expired"),
        RightsEvidenceState::OutOfScope => Some("rights state is out of scope"),
    };
    if let Some(detail) = state_detail {
        return Err(rights_denial(detail));
    }
    if !evidence.granted_scopes.contains(&request.required_scope) {
        return Err(rights_denial("required scope is absent from the evidence"));
    }
    let Some(valid_until) = evidence.valid_until_utc_ns else {
        return Err(rights_denial("rights evidence has no declared expiry"));
    };
    if evidence.valid_from_utc_ns >= valid_until {
        return Err(rights_denial(
            "rights evidence has an empty validity interval",
        ));
    }
    let now = observation.as_utc_ns();
    if now < evidence.valid_from_utc_ns {
        return Err(rights_denial("rights evidence is not yet valid"));
    }
    if now >= valid_until {
        return Err(rights_denial(
            "rights evidence expired at the trusted observation",
        ));
    }
    Ok(OperationLease::new(evidence, request, observation))
}

/// Operation scope required by an ordered phase transition.
///
/// Cleanup branches (`Quarantine` and `Closed`) need no capability: they are
/// always allowed so a denied machine can still be closed without publishing,
/// extending retention or admitting data.
#[must_use]
pub const fn required_scope_for_transition(
    from: ConnectorState,
    to: ConnectorState,
) -> Option<OperationScope> {
    if !from.allows(to) {
        return None;
    }
    match (from, to) {
        (ConnectorState::Preflight, ConnectorState::Connect)
        | (ConnectorState::Connect, ConnectorState::Discover)
        | (ConnectorState::Discover, ConnectorState::Subscribe) => {
            Some(OperationScope::ProviderConnection)
        }
        (ConnectorState::Subscribe, ConnectorState::Capture) => Some(OperationScope::LocalCapture),
        (ConnectorState::Capture, ConnectorState::Decode)
        | (ConnectorState::Decode, ConnectorState::Validate) => {
            Some(OperationScope::DecodeTransform)
        }
        (ConnectorState::Validate, ConnectorState::Archive) => Some(OperationScope::Retention),
        (ConnectorState::Archive, ConnectorState::Publish) => Some(OperationScope::Publication),
        _ => None,
    }
}

/// Operation name bound to an ordered phase transition.
#[must_use]
pub const fn required_operation_for_transition(
    from: ConnectorState,
    to: ConnectorState,
) -> Option<&'static str> {
    match required_scope_for_transition(from, to) {
        Some(scope) => Some(scope.as_str()),
        None => None,
    }
}

fn scope_allows(
    admitted: &BTreeSet<OperationScope>,
    denied: &BTreeSet<OperationScope>,
    scope: OperationScope,
) -> bool {
    admitted.contains(&scope) && !denied.contains(&scope)
}

/// Pure scope-level transition decision. Phase order is checked first, then
/// the operation scope bound to the requested transition. Lease currency is
/// checked separately by [`ConnectorLifecycle::advance`].
///
/// # Errors
/// Returns [`LifecycleReason::InvalidTransition`] for an out-of-order request,
/// [`LifecycleReason::CaptureBeforePreflight`] when capture lacks its own
/// scope, or [`LifecycleReason::RightsNotAdmitted`] when any other required
/// scope is not currently admitted.
pub fn decide_transition(
    from: ConnectorState,
    to: ConnectorState,
    admitted: &BTreeSet<OperationScope>,
    denied: &BTreeSet<OperationScope>,
) -> Result<(), LifecycleError> {
    if !from.allows(to) {
        return Err(LifecycleError::new(
            LifecycleReason::InvalidTransition,
            format!("{} cannot transition to {}", from.as_str(), to.as_str()),
        ));
    }
    let Some(scope) = required_scope_for_transition(from, to) else {
        return Ok(());
    };
    if !scope_allows(admitted, denied, scope) {
        if to == ConnectorState::Capture {
            return Err(LifecycleError::new(
                LifecycleReason::CaptureBeforePreflight,
                "capture requires a successful local-capture preflight",
            ));
        }
        return Err(rights_denial(format!(
            "scope {} is not currently admitted",
            scope.as_str()
        )));
    }
    Ok(())
}

/// Lifecycle state, operation-scoped rights, consumed leases and recorded
/// decisions. No I/O and no clock read is performed by any method on this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorLifecycle {
    state: ConnectorState,
    admitted_scopes: BTreeSet<OperationScope>,
    denied_scopes: BTreeSet<OperationScope>,
    used_leases: BTreeSet<String>,
    log: Vec<RecordedDecision>,
}

impl ConnectorLifecycle {
    /// New machine at `Preflight` with no admitted or denied scope and an
    /// empty log.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: ConnectorState::Preflight,
            admitted_scopes: BTreeSet::new(),
            denied_scopes: BTreeSet::new(),
            used_leases: BTreeSet::new(),
            log: Vec::new(),
        }
    }

    /// Current phase.
    #[must_use]
    pub const fn state(&self) -> ConnectorState {
        self.state
    }

    /// Scopes currently admitted and not denied.
    #[must_use]
    pub fn admitted_scopes(&self) -> &BTreeSet<OperationScope> {
        &self.admitted_scopes
    }

    /// Scopes denied by a past decision. A denial is never restored.
    #[must_use]
    pub fn denied_scopes(&self) -> &BTreeSet<OperationScope> {
        &self.denied_scopes
    }

    /// Digests of leases already consumed by an advanced transition.
    #[must_use]
    pub fn used_leases(&self) -> &BTreeSet<String> {
        &self.used_leases
    }

    /// Whether one operation scope is currently usable.
    #[must_use]
    pub fn scope_admitted(&self, scope: OperationScope) -> bool {
        scope_allows(&self.admitted_scopes, &self.denied_scopes, scope)
    }

    /// Whether one operation scope was denied by a past decision.
    #[must_use]
    pub fn scope_denied(&self, scope: OperationScope) -> bool {
        self.denied_scopes.contains(&scope)
    }

    /// All decisions, including denials, in sequence order.
    #[must_use]
    pub fn log(&self) -> &[RecordedDecision] {
        &self.log
    }

    /// Whether any recorded decision advanced into capture.
    #[must_use]
    pub fn reached_capture(&self) -> bool {
        self.log.iter().any(|record| {
            record.kind == DecisionKind::Advanced && record.to == ConnectorState::Capture
        })
    }

    /// Consume operation evidence and issue a lease for one scope.
    ///
    /// An admission enables only the requested scope. A denial revokes that
    /// scope permanently: later preflights for it deny instead of restoring an
    /// earlier admission. The phase never moves. The returned lease is the
    /// only authorisation a later advanced transition will accept.
    ///
    /// # Errors
    /// Returns the fail-closed denial from [`evaluate_preflight`], or a denial
    /// when the scope was previously denied.
    pub fn preflight(
        &mut self,
        evidence: Option<&OperationRightsEvidence>,
        request: &OperationRequest,
        observation: &TrustedObservation,
    ) -> Result<OperationLease, LifecycleError> {
        let scope = request.required_scope;
        let phase = self.state;
        let outcome = if self.denied_scopes.contains(&scope) {
            Err(rights_denial(format!(
                "scope {} was denied earlier and cannot be restored",
                scope.as_str()
            )))
        } else {
            evaluate_preflight(evidence, request, observation)
        };
        match &outcome {
            Ok(_) => {
                self.admitted_scopes.insert(scope);
                self.record(
                    phase,
                    phase,
                    DecisionKind::Admitted,
                    None,
                    Some(scope),
                    None,
                );
            }
            Err(error) => {
                self.admitted_scopes.remove(&scope);
                self.denied_scopes.insert(scope);
                self.record(
                    phase,
                    phase,
                    DecisionKind::PreflightDenied,
                    Some(error.reason),
                    Some(scope),
                    None,
                );
            }
        }
        outcome
    }

    /// Revoke an operation scope after a lease was issued. Outstanding leases
    /// for that scope can no longer authorise any operation.
    pub fn revoke(&mut self, scope: OperationScope) {
        self.admitted_scopes.remove(&scope);
        self.denied_scopes.insert(scope);
        let phase = self.state;
        self.record(
            phase,
            phase,
            DecisionKind::PreflightDenied,
            Some(LifecycleReason::RightsNotAdmitted),
            Some(scope),
            None,
        );
    }

    /// Apply an advanced phase transition using one current lease.
    ///
    /// The lease must be bound to the operation and scope of this transition,
    /// be authentic and current at the trusted observation, and be unused. A
    /// scope-level rights denial revokes the scope permanently; a lease that
    /// is expired, misbound or already consumed denies only that operation.
    ///
    /// # Errors
    /// Returns [`LifecycleReason::InvalidTransition`] for cleanup targets and
    /// out-of-order steps, or [`LifecycleReason::RightsNotAdmitted`] when the
    /// scope or lease does not authorise this operation.
    pub fn advance(
        &mut self,
        target: ConnectorState,
        lease: &OperationLease,
        observation: &TrustedObservation,
    ) -> Result<(), LifecycleError> {
        let from = self.state;
        let scope = required_scope_for_transition(from, target);
        let mut outcome =
            decide_transition(from, target, &self.admitted_scopes, &self.denied_scopes);
        if outcome.is_ok() {
            outcome = match scope {
                Some(scope) => self.check_lease(from, target, scope, lease, observation),
                None => Err(LifecycleError::new(
                    LifecycleReason::InvalidTransition,
                    "cleanup targets require quarantine or close, not a lease",
                )),
            };
        }
        let lease_digest = if outcome.is_ok() {
            Some(lease.digest())
        } else {
            None
        };
        match &outcome {
            Ok(()) => {
                self.used_leases.insert(lease.digest());
                self.record(
                    from,
                    target,
                    DecisionKind::Advanced,
                    None,
                    scope,
                    lease_digest,
                );
                self.state = target;
            }
            Err(error) => {
                let revoked = error.reason != LifecycleReason::InvalidTransition
                    && !Self::lease_only_denial(error);
                if revoked && let Some(scope) = scope {
                    self.admitted_scopes.remove(&scope);
                    self.denied_scopes.insert(scope);
                }
                self.record(
                    from,
                    target,
                    DecisionKind::Denied,
                    Some(error.reason),
                    scope,
                    None,
                );
            }
        }
        outcome
    }

    fn check_lease(
        &self,
        from: ConnectorState,
        target: ConnectorState,
        scope: OperationScope,
        lease: &OperationLease,
        observation: &TrustedObservation,
    ) -> Result<(), LifecycleError> {
        if lease.scope() != scope {
            return Err(rights_denial("lease is bound to another operation scope"));
        }
        if required_operation_for_transition(from, target) != Some(lease.operation_ref()) {
            return Err(rights_denial("lease is bound to another operation"));
        }
        if !lease.is_current_at(observation) {
            return Err(rights_denial("operation lease is not current"));
        }
        if self.used_leases.contains(&lease.digest()) {
            return Err(rights_denial("operation lease was already consumed"));
        }
        Ok(())
    }

    fn lease_only_denial(error: &LifecycleError) -> bool {
        error.detail.contains("lease")
    }

    /// Abort into `Quarantine` from any nonterminal phase. Cleanup needs no
    /// capability and changes no rights, retention or admission state.
    ///
    /// # Errors
    /// Returns [`LifecycleReason::InvalidTransition`] only from a terminal
    /// phase.
    pub fn quarantine(&mut self) -> Result<(), LifecycleError> {
        self.cleanup(ConnectorState::Quarantine)
    }

    /// Close from `Publish`, `Quarantine` or any nonterminal phase. Cleanup
    /// needs no capability and changes no rights, retention or admission state.
    ///
    /// # Errors
    /// Returns [`LifecycleReason::InvalidTransition`] only from `Closed`.
    pub fn close(&mut self) -> Result<(), LifecycleError> {
        self.cleanup(ConnectorState::Closed)
    }

    fn cleanup(&mut self, target: ConnectorState) -> Result<(), LifecycleError> {
        let from = self.state;
        let outcome =
            if from.allows(target) && required_scope_for_transition(from, target).is_none() {
                Ok(())
            } else {
                Err(LifecycleError::new(
                    LifecycleReason::InvalidTransition,
                    format!(
                        "{} cannot be cleaned up to {}",
                        from.as_str(),
                        target.as_str()
                    ),
                ))
            };
        match &outcome {
            Ok(()) => {
                self.record(from, target, DecisionKind::Advanced, None, None, None);
                self.state = target;
            }
            Err(error) => self.record(
                from,
                target,
                DecisionKind::Denied,
                Some(error.reason),
                None,
                None,
            ),
        }
        outcome
    }

    /// Explicit gate for research use, which has no phase in this machine but
    /// still needs a current lease bound to its own operation scope.
    ///
    /// # Errors
    /// Returns [`LifecycleReason::RightsNotAdmitted`] unless research use is
    /// admitted and the lease is current and bound to `research_use`.
    pub fn research_use(
        &self,
        lease: &OperationLease,
        observation: &TrustedObservation,
    ) -> Result<(), LifecycleError> {
        let scope = OperationScope::ResearchUse;
        if !self.scope_admitted(scope) {
            return Err(rights_denial("research use is not currently admitted"));
        }
        if lease.scope() != scope || lease.operation_ref() != "research_use" {
            return Err(rights_denial(
                "lease is not bound to the research use operation",
            ));
        }
        if !lease.is_current_at(observation) {
            return Err(rights_denial("research use lease is not current"));
        }
        Ok(())
    }

    /// Reconstruct a machine from a recorded decision log.
    ///
    /// The log is treated as untrusted input: consecutive sequence numbers,
    /// from-state agreement, legal advanced transitions, scope and lease
    /// binding, single-use leases, cleanup records with no capability, and
    /// denied decisions that leave the phase unchanged are all re-verified.
    ///
    /// # Errors
    /// Returns [`LifecycleReason::LogMismatch`] if any record is inconsistent
    /// with the decisions that would have produced it.
    pub fn replay(records: &[RecordedDecision]) -> Result<Self, LifecycleError> {
        let mut lifecycle = Self::new();
        for (index, record) in records.iter().enumerate() {
            let expected = u64::try_from(index + 1).unwrap_or(u64::MAX);
            if record.sequence != expected {
                return Err(Self::mismatch("decision sequence is not consecutive"));
            }
            if record.from != lifecycle.state {
                return Err(Self::mismatch("recorded from-state does not match replay"));
            }
            match record.kind {
                DecisionKind::Admitted => {
                    if record.to != record.from
                        || record.reason_code.is_some()
                        || record.lease_digest.is_some()
                    {
                        return Err(Self::mismatch("preflight admission changed the phase"));
                    }
                    let Some(scope) = record.scope else {
                        return Err(Self::mismatch("preflight admission has no scope"));
                    };
                    if lifecycle.denied_scopes.contains(&scope) {
                        return Err(Self::mismatch("a denied scope was restored"));
                    }
                    lifecycle.admitted_scopes.insert(scope);
                }
                DecisionKind::PreflightDenied => {
                    if record.to != record.from || record.lease_digest.is_some() {
                        return Err(Self::mismatch("preflight denial changed the phase"));
                    }
                    let Some(reason) = record.reason_code else {
                        return Err(Self::mismatch("preflight denial has no reason"));
                    };
                    if reason != LifecycleReason::RightsNotAdmitted {
                        return Err(Self::mismatch("preflight denial has the wrong reason"));
                    }
                    let Some(scope) = record.scope else {
                        return Err(Self::mismatch("preflight denial has no scope"));
                    };
                    lifecycle.admitted_scopes.remove(&scope);
                    lifecycle.denied_scopes.insert(scope);
                }
                DecisionKind::Advanced => {
                    if record.reason_code.is_some()
                        || decide_transition(
                            record.from,
                            record.to,
                            &lifecycle.admitted_scopes,
                            &lifecycle.denied_scopes,
                        )
                        .is_err()
                    {
                        return Err(Self::mismatch("advanced transition is not legal"));
                    }
                    if record.scope != required_scope_for_transition(record.from, record.to) {
                        return Err(Self::mismatch("advanced scope does not match the phase"));
                    }
                    match record.scope {
                        Some(_) => {
                            let Some(digest) = &record.lease_digest else {
                                return Err(Self::mismatch("advanced transition has no lease"));
                            };
                            if !is_authority_digest(digest)
                                || !lifecycle.used_leases.insert(digest.clone())
                            {
                                return Err(Self::mismatch("lease digest is reused or malformed"));
                            }
                            if record.to == ConnectorState::Publish
                                && record.scope != Some(OperationScope::Publication)
                            {
                                return Err(Self::mismatch("publication is not authorised"));
                            }
                        }
                        None => {
                            if record.lease_digest.is_some()
                                || !matches!(
                                    record.to,
                                    ConnectorState::Quarantine | ConnectorState::Closed
                                )
                            {
                                return Err(Self::mismatch("cleanup granted a capability"));
                            }
                        }
                    }
                    lifecycle.state = record.to;
                }
                DecisionKind::Denied => {
                    let Some(reason) = record.reason_code else {
                        return Err(Self::mismatch("denied decision has no reason"));
                    };
                    let Err(error) = decide_transition(
                        record.from,
                        record.to,
                        &lifecycle.admitted_scopes,
                        &lifecycle.denied_scopes,
                    ) else {
                        return Err(Self::mismatch("denied transition is legal"));
                    };
                    if error.reason != reason {
                        return Err(Self::mismatch("denied reason is not reproducible"));
                    }
                    if record.scope != required_scope_for_transition(record.from, record.to)
                        || record.lease_digest.is_some()
                    {
                        return Err(Self::mismatch("denied scope does not match the phase"));
                    }
                    if let Some(scope) = record.scope {
                        lifecycle.admitted_scopes.remove(&scope);
                        lifecycle.denied_scopes.insert(scope);
                    }
                }
            }
            lifecycle.log.push(record.clone());
        }
        Ok(lifecycle)
    }

    fn record(
        &mut self,
        from: ConnectorState,
        to: ConnectorState,
        kind: DecisionKind,
        reason_code: Option<LifecycleReason>,
        scope: Option<OperationScope>,
        lease_digest: Option<String>,
    ) {
        let sequence = u64::try_from(self.log.len() + 1).unwrap_or(u64::MAX);
        self.log.push(RecordedDecision {
            sequence,
            from,
            to,
            kind,
            reason_code,
            scope,
            lease_digest,
        });
    }

    fn mismatch(detail: &'static str) -> LifecycleError {
        LifecycleError::new(LifecycleReason::LogMismatch, detail)
    }
}

impl Default for ConnectorLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;

    const OBSERVED_AT: u64 = 1_700_000_000_000_000_000;
    const VALID_UNTIL: u64 = 1_700_000_000_100_000_000;
    const LONG_SESSION_LATER: u64 = 1_800_000_000_000_000_000;

    #[derive(Debug)]
    struct FixedClock {
        now: Cell<u64>,
    }

    impl FixedClock {
        fn at(now: u64) -> Self {
            Self {
                now: Cell::new(now),
            }
        }
    }

    impl TrustedUtcClock for FixedClock {
        fn now_utc_ns(&self) -> Result<u64, LifecycleError> {
            Ok(self.now.get())
        }
    }

    fn observation(clock: &FixedClock) -> TrustedObservation {
        observe(clock).expect("a fixed clock is a trusted boundary clock")
    }

    fn subject() -> LeaseSubject {
        LeaseSubject {
            source_id: "fixture-source".to_owned(),
            provider_id: "fixture-provider".to_owned(),
            product_ref: "fixture-product".to_owned(),
            instrument_ref: "fixture-instrument".to_owned(),
        }
    }

    fn terms() -> LeaseTerms {
        LeaseTerms {
            retention_until_utc_ns: 1_900_000_000_000_000_000,
            permitted_uses: BTreeSet::from(["local_research".to_owned()]),
        }
    }

    static LEASE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn request(scope: OperationScope) -> OperationRequest {
        let sequence = LEASE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        OperationRequest {
            lease_ref: format!("fixture-lease-{sequence}"),
            operation_ref: scope.as_str().to_owned(),
            required_scope: scope,
            subject: subject(),
            terms: terms(),
            declared_observed_at_utc_ns: 0,
        }
    }

    fn valid_evidence(scope: OperationScope) -> OperationRightsEvidence {
        OperationRightsEvidence {
            evidence_ref: format!("evidence-{}", scope.as_str()),
            operation_ref: scope.as_str().to_owned(),
            state: RightsEvidenceState::Admitted,
            granted_scopes: BTreeSet::from([scope]),
            valid_from_utc_ns: OBSERVED_AT - 1,
            valid_until_utc_ns: Some(VALID_UNTIL),
            subject: subject(),
            terms: terms(),
            authority_digest: "a".repeat(64),
        }
    }

    fn evidence_valid(
        scope: OperationScope,
        valid_from_utc_ns: u64,
        valid_until_utc_ns: u64,
    ) -> OperationRightsEvidence {
        let mut evidence = valid_evidence(scope);
        evidence.valid_from_utc_ns = valid_from_utc_ns;
        evidence.valid_until_utc_ns = Some(valid_until_utc_ns);
        evidence
    }

    fn issue(scope: OperationScope, clock: &FixedClock) -> OperationLease {
        evaluate_preflight(
            Some(&valid_evidence(scope)),
            &request(scope),
            &observation(clock),
        )
        .expect("valid evidence issues a lease")
    }

    fn issue_valid(
        scope: OperationScope,
        valid_from_utc_ns: u64,
        valid_until_utc_ns: u64,
        clock: &FixedClock,
    ) -> OperationLease {
        evaluate_preflight(
            Some(&evidence_valid(
                scope,
                valid_from_utc_ns,
                valid_until_utc_ns,
            )),
            &request(scope),
            &observation(clock),
        )
        .expect("valid evidence issues a lease")
    }

    fn admit(lifecycle: &mut ConnectorLifecycle, scope: OperationScope, clock: &FixedClock) {
        lifecycle
            .preflight(
                Some(&valid_evidence(scope)),
                &request(scope),
                &observation(clock),
            )
            .expect("admitted evidence passes preflight for the requested scope");
    }

    fn admit_valid(
        lifecycle: &mut ConnectorLifecycle,
        scope: OperationScope,
        valid_from_utc_ns: u64,
        valid_until_utc_ns: u64,
        clock: &FixedClock,
    ) {
        lifecycle
            .preflight(
                Some(&evidence_valid(
                    scope,
                    valid_from_utc_ns,
                    valid_until_utc_ns,
                )),
                &request(scope),
                &observation(clock),
            )
            .expect("admitted evidence passes preflight for the requested scope");
    }

    fn deny(lifecycle: &mut ConnectorLifecycle, scope: OperationScope) {
        let mut unknown = valid_evidence(scope);
        unknown.state = RightsEvidenceState::Unknown;
        lifecycle
            .preflight(
                Some(&unknown),
                &request(scope),
                &observation(&FixedClock::at(OBSERVED_AT)),
            )
            .expect_err("unknown evidence denies the requested scope");
    }

    fn advance(lifecycle: &mut ConnectorLifecycle, target: ConnectorState, clock: &FixedClock) {
        if target == ConnectorState::Closed {
            lifecycle.close().expect("cleanup closes the machine");
            return;
        }
        if target == ConnectorState::Quarantine {
            lifecycle
                .quarantine()
                .expect("cleanup quarantines the machine");
            return;
        }
        let scope = required_scope_for_transition(lifecycle.state(), target)
            .expect("an advanced transition has an operation scope");
        admit(lifecycle, scope, clock);
        let lease = issue(scope, clock);
        lifecycle
            .advance(target, &lease, &observation(clock))
            .expect("an ordered transition with a current lease succeeds");
    }

    fn through_subscribe(clock: &FixedClock) -> ConnectorLifecycle {
        let mut lifecycle = ConnectorLifecycle::new();
        for target in [
            ConnectorState::Connect,
            ConnectorState::Discover,
            ConnectorState::Subscribe,
        ] {
            advance(&mut lifecycle, target, clock);
        }
        lifecycle
    }

    fn through_phase(target: ConnectorState, clock: &FixedClock) -> ConnectorLifecycle {
        if target == ConnectorState::Preflight {
            return ConnectorLifecycle::new();
        }
        let mut lifecycle = ConnectorLifecycle::new();
        for phase in [
            ConnectorState::Connect,
            ConnectorState::Discover,
            ConnectorState::Subscribe,
            ConnectorState::Capture,
            ConnectorState::Decode,
            ConnectorState::Validate,
            ConnectorState::Archive,
        ] {
            advance(&mut lifecycle, phase, clock);
            if phase == target {
                break;
            }
        }
        lifecycle
    }

    fn nonterminal_phases() -> [ConnectorState; 8] {
        [
            ConnectorState::Preflight,
            ConnectorState::Connect,
            ConnectorState::Discover,
            ConnectorState::Subscribe,
            ConnectorState::Capture,
            ConnectorState::Decode,
            ConnectorState::Validate,
            ConnectorState::Archive,
        ]
    }

    #[test]
    fn unknown_rights_are_denied_with_the_stable_code() {
        let clock = FixedClock::at(OBSERVED_AT);
        let scope = OperationScope::ProviderConnection;
        let mut unknown = valid_evidence(scope);
        unknown.state = RightsEvidenceState::Unknown;
        let mut lifecycle = ConnectorLifecycle::new();
        let error = lifecycle
            .preflight(Some(&unknown), &request(scope), &observation(&clock))
            .expect_err("unknown rights are denied");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "denial code is exact"
        );
        assert!(
            !lifecycle.scope_admitted(scope),
            "unknown rights are not admitted"
        );
        assert!(
            lifecycle.scope_denied(scope),
            "the denied scope is recorded"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Preflight,
            "the phase did not move"
        );
        let lease = issue(scope, &clock);
        let blocked = lifecycle
            .advance(ConnectorState::Connect, &lease, &observation(&clock))
            .expect_err("a denied connection scope blocks connect");
        assert_eq!(
            blocked.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "the operation scope is enforced at connect"
        );
    }

    #[test]
    fn missing_expired_and_out_of_scope_rights_are_denied() {
        let clock = FixedClock::at(OBSERVED_AT);
        let obs = observation(&clock);
        let scope = OperationScope::ProviderConnection;
        let error = evaluate_preflight(None, &request(scope), &obs)
            .expect_err("missing evidence is denied");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "missing evidence code"
        );
        let mut expired = valid_evidence(scope);
        expired.valid_until_utc_ns = Some(OBSERVED_AT);
        let error = evaluate_preflight(Some(&expired), &request(scope), &obs)
            .expect_err("expired evidence is denied");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED, "expiry code");
        let mut out_of_scope = valid_evidence(scope);
        out_of_scope.state = RightsEvidenceState::OutOfScope;
        let error = evaluate_preflight(Some(&out_of_scope), &request(scope), &obs)
            .expect_err("out-of-scope evidence is denied");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED, "scope-state code");
    }

    #[test]
    fn binding_and_declared_time_are_enforced() {
        let clock = FixedClock::at(OBSERVED_AT);
        let scope = OperationScope::ProviderConnection;
        let mut wrong_operation = request(scope);
        wrong_operation.operation_ref = "another-operation".to_owned();
        let mut evidence = valid_evidence(scope);
        evidence.subject.instrument_ref = "another-instrument".to_owned();
        let mut wrong_terms = request(scope);
        wrong_terms.terms.permitted_uses = BTreeSet::from(["other_use".to_owned()]);
        for request in [&wrong_operation, &wrong_terms] {
            evaluate_preflight(Some(&valid_evidence(scope)), request, &observation(&clock))
                .expect_err("a mismatched request is denied");
        }
        evaluate_preflight(Some(&evidence), &request(scope), &observation(&clock))
            .expect_err("identity-bound evidence is denied");
        evidence = valid_evidence(scope);
        evidence.authority_digest = "z".repeat(64);
        evaluate_preflight(Some(&evidence), &request(scope), &observation(&clock))
            .expect_err("a malformed authority digest is denied");
        let mut declared = request(scope);
        declared.declared_observed_at_utc_ns = LONG_SESSION_LATER;
        let lease = evaluate_preflight(
            Some(&valid_evidence(scope)),
            &declared,
            &observation(&clock),
        )
        .expect("a caller-declared time is not a grant and cannot revoke one");
        assert!(
            lease.is_current_at(&observation(&clock)),
            "a declared time cannot make a trusted observation stale"
        );
    }

    #[test]
    fn missing_operation_scope_is_denied() {
        let clock = FixedClock::at(OBSERVED_AT);
        let scope = OperationScope::LocalCapture;
        let mut evidence = valid_evidence(scope);
        evidence.granted_scopes = BTreeSet::from([OperationScope::Retention]);
        let error = evaluate_preflight(Some(&evidence), &request(scope), &observation(&clock))
            .expect_err("a scope absent from the evidence is denied");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "missing scope code"
        );
        assert!(error.detail.contains("scope"), "the denial names the scope");
    }

    #[test]
    fn ordering_is_enforced_even_after_admitted_preflight() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = ConnectorLifecycle::new();
        admit(&mut lifecycle, OperationScope::ProviderConnection, &clock);
        let lease = issue(OperationScope::ProviderConnection, &clock);
        let error = lifecycle
            .advance(ConnectorState::Capture, &lease, &observation(&clock))
            .expect_err("capture cannot skip phases");
        assert_eq!(
            error.reason_code(),
            "INVALID_TRANSITION",
            "out-of-order transition has a stable code"
        );
        let error = lifecycle
            .advance(ConnectorState::Discover, &lease, &observation(&clock))
            .expect_err("discover cannot precede connect");
        assert_eq!(
            error.reason,
            LifecycleReason::InvalidTransition,
            "skipped phase has the same reason"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Preflight,
            "state is unchanged"
        );
        lifecycle
            .advance(ConnectorState::Connect, &lease, &observation(&clock))
            .expect("connect follows preflight");
        let error = lifecycle
            .advance(ConnectorState::Connect, &lease, &observation(&clock))
            .expect_err("a repeated phase is not a transition");
        assert_eq!(
            error.reason,
            LifecycleReason::InvalidTransition,
            "repeated phase is denied"
        );
    }

    #[test]
    fn denied_provider_scope_blocks_all_later_provider_phases() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = ConnectorLifecycle::new();
        deny(&mut lifecycle, OperationScope::ProviderConnection);
        let lease = issue(OperationScope::ProviderConnection, &clock);
        let connect = lifecycle
            .advance(ConnectorState::Connect, &lease, &observation(&clock))
            .expect_err("a denied connection capability blocks connect");
        assert_eq!(
            connect.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "connect is gated by the denied capability"
        );
        let scope = OperationScope::ProviderConnection;
        lifecycle
            .preflight(
                Some(&valid_evidence(scope)),
                &request(scope),
                &observation(&clock),
            )
            .expect_err("the denied capability is never restored");
        let capture = lifecycle
            .advance(ConnectorState::Capture, &lease, &observation(&clock))
            .expect_err("capture is unreachable from preflight");
        assert_eq!(
            capture.reason_code(),
            "INVALID_TRANSITION",
            "capture is also out of order"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Preflight,
            "no denied transition advanced the machine"
        );
        assert!(
            !lifecycle.reached_capture(),
            "no decision advanced into capture"
        );
    }

    #[test]
    fn denial_at_capture_blocks_decode() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_phase(ConnectorState::Capture, &clock);
        deny(&mut lifecycle, OperationScope::DecodeTransform);
        let lease = issue(OperationScope::DecodeTransform, &clock);
        let error = lifecycle
            .advance(ConnectorState::Decode, &lease, &observation(&clock))
            .expect_err("decode needs the denied transform scope");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "Capture->Decode is gated by the denied capability"
        );
        lifecycle
            .preflight(
                Some(&valid_evidence(OperationScope::DecodeTransform)),
                &request(OperationScope::DecodeTransform),
                &observation(&clock),
            )
            .expect_err("a later admission cannot restore a denied scope");
        assert!(
            !lifecycle.scope_admitted(OperationScope::DecodeTransform),
            "earlier admission is never restored"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Capture,
            "phase did not move"
        );
    }

    #[test]
    fn denial_at_decode_blocks_validate() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_phase(ConnectorState::Decode, &clock);
        deny(&mut lifecycle, OperationScope::DecodeTransform);
        let lease = issue(OperationScope::DecodeTransform, &clock);
        let error = lifecycle
            .advance(ConnectorState::Validate, &lease, &observation(&clock))
            .expect_err("validate needs the denied transform scope");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "Decode->Validate is gated by the denied capability"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Decode,
            "phase did not move"
        );
    }

    #[test]
    fn denial_at_validate_blocks_archive() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_phase(ConnectorState::Validate, &clock);
        deny(&mut lifecycle, OperationScope::Retention);
        let lease = issue(OperationScope::Retention, &clock);
        let error = lifecycle
            .advance(ConnectorState::Archive, &lease, &observation(&clock))
            .expect_err("archive needs the denied retention scope");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "Validate->Archive is gated by the denied capability"
        );
        assert!(
            !lifecycle.scope_admitted(OperationScope::Retention),
            "retention is not admitted after denial"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Validate,
            "phase did not move"
        );
    }

    #[test]
    fn denial_at_archive_blocks_publish() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_phase(ConnectorState::Archive, &clock);
        deny(&mut lifecycle, OperationScope::Publication);
        let lease = issue(OperationScope::Publication, &clock);
        let error = lifecycle
            .advance(ConnectorState::Publish, &lease, &observation(&clock))
            .expect_err("publish needs the denied publication scope");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "Archive->Publish is gated by the denied capability"
        );
        assert!(
            !lifecycle.scope_admitted(OperationScope::Publication),
            "publication is not admitted after denial"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Archive,
            "phase did not move"
        );
    }

    #[test]
    fn quarantine_branch_bypasses_publication() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_phase(ConnectorState::Validate, &clock);
        lifecycle.quarantine().expect("quarantine follows validate");
        let lease = issue(OperationScope::Publication, &clock);
        let error = lifecycle
            .advance(ConnectorState::Archive, &lease, &observation(&clock))
            .expect_err("quarantine cannot archive");
        assert_eq!(
            error.reason,
            LifecycleReason::InvalidTransition,
            "quarantine blocks the publication path"
        );
        lifecycle.close().expect("quarantine closes");
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Closed,
            "machine is closed"
        );
        assert!(
            lifecycle
                .log()
                .iter()
                .all(|record| record.to != ConnectorState::Publish),
            "no publish decision was recorded"
        );
    }

    #[test]
    fn cleanup_after_denial_never_publishes_extends_retention_or_admits_data() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_phase(ConnectorState::Archive, &clock);
        deny(&mut lifecycle, OperationScope::Publication);
        let mark = lifecycle.log().len();
        let scopes_before = lifecycle.admitted_scopes().clone();
        let denied_before = lifecycle.denied_scopes().clone();
        let leases_before = lifecycle.used_leases().clone();
        lifecycle
            .quarantine()
            .expect("cleanup is allowed after denial");
        lifecycle.close().expect("closing is allowed after denial");
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Closed,
            "machine is closed"
        );
        assert!(
            lifecycle.log()[mark..]
                .iter()
                .all(|record| record.scope.is_none() && record.lease_digest.is_none()),
            "cleanup grants no capability and admits no data"
        );
        assert!(
            lifecycle.log()[mark..]
                .iter()
                .all(|record| record.to != ConnectorState::Publish),
            "cleanup never publishes"
        );
        assert_eq!(
            lifecycle.admitted_scopes(),
            &scopes_before,
            "cleanup cannot admit a scope"
        );
        assert_eq!(
            lifecycle.denied_scopes(),
            &denied_before,
            "cleanup cannot revoke or restore a scope"
        );
        assert_eq!(
            lifecycle.used_leases(),
            &leases_before,
            "cleanup cannot consume a lease"
        );
        let lease = issue(OperationScope::Publication, &clock);
        let error = lifecycle
            .advance(ConnectorState::Publish, &lease, &observation(&clock))
            .expect_err("a closed machine cannot publish");
        assert_eq!(
            error.reason,
            LifecycleReason::InvalidTransition,
            "publication is impossible during cleanup"
        );
    }

    #[test]
    fn denial_and_cleanup_are_reachable_from_every_phase() {
        let clock = FixedClock::at(OBSERVED_AT);
        for phase in nonterminal_phases() {
            let mut lifecycle = through_phase(phase, &clock);
            let scope = required_scope_for_transition(phase, advanced_target(phase))
                .expect("every nonterminal phase has an advanced successor");
            lifecycle.revoke(scope);
            let lease = issue(scope, &clock);
            let denied = lifecycle
                .advance(advanced_target(phase), &lease, &observation(&clock))
                .expect_err("a revoked scope denies the next operation");
            let denial_message = format!(
                "denial is reachable from {}: {}",
                phase.as_str(),
                denied.reason_code()
            );
            assert!(
                matches!(
                    denied.reason_code(),
                    RIGHTS_NOT_ADMITTED | "CAPTURE_BEFORE_PREFLIGHT"
                ),
                "{denial_message}"
            );
            lifecycle
                .quarantine()
                .expect("quarantine is reachable from every nonterminal phase");
            assert_eq!(
                lifecycle.state(),
                ConnectorState::Quarantine,
                "abort lands in quarantine"
            );
            lifecycle.close().expect("quarantine then closes");
            let replayed =
                ConnectorLifecycle::replay(lifecycle.log()).expect("the decision log replays");
            assert_eq!(replayed, lifecycle, "replay reproduces the machine");
            assert_eq!(
                replayed.state(),
                ConnectorState::Closed,
                "final state is closed"
            );
            assert!(
                replayed.log().iter().all(|record| {
                    record.kind != DecisionKind::Advanced || record.to != ConnectorState::Publish
                }),
                "no publication is reachable through cleanup"
            );
        }
    }

    fn advanced_target(phase: ConnectorState) -> ConnectorState {
        match phase {
            ConnectorState::Preflight => ConnectorState::Connect,
            ConnectorState::Connect => ConnectorState::Discover,
            ConnectorState::Discover => ConnectorState::Subscribe,
            ConnectorState::Subscribe => ConnectorState::Capture,
            ConnectorState::Capture => ConnectorState::Decode,
            ConnectorState::Decode => ConnectorState::Validate,
            ConnectorState::Validate => ConnectorState::Archive,
            ConnectorState::Archive => ConnectorState::Publish,
            _ => ConnectorState::Closed,
        }
    }

    #[test]
    fn recorded_log_replays_to_the_same_machine() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_subscribe(&clock);
        for target in [
            ConnectorState::Capture,
            ConnectorState::Decode,
            ConnectorState::Validate,
            ConnectorState::Archive,
            ConnectorState::Publish,
            ConnectorState::Closed,
        ] {
            advance(&mut lifecycle, target, &clock);
        }
        let replayed = ConnectorLifecycle::replay(lifecycle.log()).expect("the full log replays");
        assert_eq!(replayed, lifecycle, "replay reconstructs the same machine");
        assert_eq!(
            replayed.state(),
            ConnectorState::Closed,
            "final phase is closed"
        );
        assert!(
            replayed.reached_capture(),
            "capture is present in the replay"
        );
    }

    #[test]
    fn replay_rejects_a_tampered_log() {
        let clock = FixedClock::at(OBSERVED_AT);
        let lifecycle = through_subscribe(&clock);
        let mut records = lifecycle.log().to_vec();
        records[2].sequence = 99;
        let error =
            ConnectorLifecycle::replay(&records).expect_err("tampered sequence is rejected");
        assert_eq!(
            error.reason,
            LifecycleReason::LogMismatch,
            "stable replay reason"
        );
        let mut records = lifecycle.log().to_vec();
        records[1].to = ConnectorState::Capture;
        let error =
            ConnectorLifecycle::replay(&records).expect_err("tampered transition is rejected");
        assert_eq!(
            error.reason,
            LifecycleReason::LogMismatch,
            "stable replay reason"
        );
        let mut records = lifecycle.log().to_vec();
        records[0].scope = Some(OperationScope::Retention);
        let error = ConnectorLifecycle::replay(&records).expect_err("tampered scope is rejected");
        assert_eq!(
            error.reason,
            LifecycleReason::LogMismatch,
            "stable replay reason"
        );
        let mut records = lifecycle.log().to_vec();
        records[1].lease_digest = Some("tampered".to_owned());
        let error = ConnectorLifecycle::replay(&records).expect_err("a tampered lease is rejected");
        assert_eq!(
            error.reason,
            LifecycleReason::LogMismatch,
            "stable replay reason"
        );
    }

    #[test]
    fn replay_reproduces_denial_and_never_restores_admission() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_phase(ConnectorState::Decode, &clock);
        deny(&mut lifecycle, OperationScope::DecodeTransform);
        let lease = issue(OperationScope::DecodeTransform, &clock);
        lifecycle
            .advance(ConnectorState::Validate, &lease, &observation(&clock))
            .expect_err("validate is blocked by the denial");
        let mut replayed =
            ConnectorLifecycle::replay(lifecycle.log()).expect("a denied log replays faithfully");
        assert_eq!(replayed, lifecycle, "replay mirrors the denied machine");
        assert!(
            replayed.scope_denied(OperationScope::DecodeTransform),
            "the denied state is reproduced"
        );
        assert!(
            !replayed.scope_admitted(OperationScope::DecodeTransform),
            "earlier admission is not restored by replay"
        );
        replayed
            .preflight(
                Some(&valid_evidence(OperationScope::DecodeTransform)),
                &request(OperationScope::DecodeTransform),
                &observation(&clock),
            )
            .expect_err("even a valid preflight cannot restore a denied scope");
        let expected_phase = ConnectorState::Decode;
        assert_eq!(
            replayed.state(),
            expected_phase,
            "the replayed phase is unchanged"
        );
    }

    #[test]
    fn every_denial_kind_marks_the_scope_denied() {
        let clock = FixedClock::at(OBSERVED_AT);
        let scope = OperationScope::DecodeTransform;
        let mut unknown = valid_evidence(scope);
        unknown.state = RightsEvidenceState::Unknown;
        let mut expired = valid_evidence(scope);
        expired.valid_until_utc_ns = Some(OBSERVED_AT);
        let mut out_of_scope = valid_evidence(scope);
        out_of_scope.state = RightsEvidenceState::OutOfScope;
        let obs = observation(&clock);
        for evidence in [None, Some(&unknown), Some(&expired), Some(&out_of_scope)] {
            let mut lifecycle = through_phase(ConnectorState::Capture, &clock);
            lifecycle
                .preflight(evidence, &request(scope), &obs)
                .expect_err("each non-admitted evidence kind denies");
            assert!(
                lifecycle.scope_denied(scope),
                "each denial marks the operation scope denied"
            );
            let lease = issue(scope, &clock);
            let denied = lifecycle
                .advance(ConnectorState::Decode, &lease, &obs)
                .expect_err("the denied capability blocks decode");
            assert_eq!(
                denied.reason_code(),
                RIGHTS_NOT_ADMITTED,
                "all denial kinds block the dependent transition"
            );
        }
    }

    #[test]
    fn preflight_records_the_phase_and_scope() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_subscribe(&clock);
        let before = lifecycle.log().len();
        let scope = OperationScope::ResearchUse;
        admit(&mut lifecycle, scope, &clock);
        let record = &lifecycle.log()[before];
        assert_eq!(
            record.from,
            ConnectorState::Subscribe,
            "from is the actual phase"
        );
        assert_eq!(record.to, record.from, "preflight does not move a phase");
        assert_eq!(record.scope, Some(scope), "the operation scope is recorded");
        assert!(
            record.lease_digest.is_none(),
            "issuance is not an advanced transition"
        );
    }

    #[test]
    fn replay_is_faithful_with_repeated_preflights_and_mixed_denials() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_subscribe(&clock);
        admit(&mut lifecycle, OperationScope::ResearchUse, &clock);
        admit(&mut lifecycle, OperationScope::LocalCapture, &clock);
        advance(&mut lifecycle, ConnectorState::Capture, &clock);
        admit(&mut lifecycle, OperationScope::DecodeTransform, &clock);
        advance(&mut lifecycle, ConnectorState::Decode, &clock);
        deny(&mut lifecycle, OperationScope::ResearchUse);
        let research_lease = issue(OperationScope::ResearchUse, &clock);
        lifecycle
            .research_use(&research_lease, &observation(&clock))
            .expect_err("research use stays denied after a denial");
        admit(&mut lifecycle, OperationScope::Retention, &clock);
        advance(&mut lifecycle, ConnectorState::Validate, &clock);
        advance(&mut lifecycle, ConnectorState::Archive, &clock);
        lifecycle.quarantine().expect("quarantine follows archive");
        lifecycle.close().expect("quarantine closes");

        let replayed = ConnectorLifecycle::replay(lifecycle.log()).expect("the mixed log replays");
        assert_eq!(replayed, lifecycle, "replay rebuilds the exact machine");
        assert_eq!(
            replayed.state(),
            ConnectorState::Closed,
            "final phase is closed"
        );
        assert!(
            replayed.scope_denied(OperationScope::ResearchUse),
            "the research denial is reproduced"
        );
        assert!(
            !replayed.scope_admitted(OperationScope::Publication),
            "publication was never admitted"
        );
        assert!(
            replayed.reached_capture(),
            "capture is present in the replay"
        );
    }

    #[test]
    fn research_use_requires_its_own_operation_scope() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = ConnectorLifecycle::new();
        let lease = issue(OperationScope::ResearchUse, &clock);
        lifecycle
            .research_use(&lease, &observation(&clock))
            .expect_err("research use is denied without its own scope");
        admit(&mut lifecycle, OperationScope::ResearchUse, &clock);
        lifecycle
            .research_use(&lease, &observation(&clock))
            .expect("research use is admitted with a current lease");
        assert!(
            !lifecycle.scope_admitted(OperationScope::ProviderConnection),
            "research admission does not admit provider connection"
        );
        assert_eq!(OperationScope::ALL.len(), 6, "all six scopes are defined");
    }

    #[test]
    fn leases_expire_before_every_operation() {
        let clock = FixedClock::at(OBSERVED_AT);
        for phase in nonterminal_phases() {
            let target = advanced_target(phase);
            let scope = required_scope_for_transition(phase, target)
                .expect("every advanced target has a scope");
            let mut lifecycle = through_phase(phase, &clock);
            admit(&mut lifecycle, scope, &clock);
            let lease = issue(scope, &clock);
            clock.now.set(VALID_UNTIL);
            let expired = lifecycle
                .advance(target, &lease, &observation(&clock))
                .expect_err("an expired lease denies the operation");
            let expiry_message = format!("expiry denies {} -> {}", phase.as_str(), target.as_str());
            assert_eq!(
                expired.reason_code(),
                RIGHTS_NOT_ADMITTED,
                "{expiry_message}"
            );
            assert_eq!(lifecycle.state(), phase, "expiry never advances the phase");
            assert!(
                lifecycle.scope_admitted(scope),
                "expiry does not permanently deny the scope"
            );
            clock.now.set(OBSERVED_AT);
            let fresh = issue(scope, &clock);
            admit(&mut lifecycle, scope, &clock);
            lifecycle
                .advance(target, &fresh, &observation(&clock))
                .expect("a fresh lease permits the operation");
        }
    }

    #[test]
    fn revocation_before_every_operation_blocks_the_lease() {
        let clock = FixedClock::at(OBSERVED_AT);
        for phase in nonterminal_phases() {
            let target = advanced_target(phase);
            let scope = required_scope_for_transition(phase, target)
                .expect("every advanced target has a scope");
            let mut lifecycle = through_phase(phase, &clock);
            let lease = issue(scope, &clock);
            lifecycle.revoke(scope);
            let denied = lifecycle
                .advance(target, &lease, &observation(&clock))
                .expect_err("revocation denies the outstanding lease");
            let revocation_message = format!(
                "revocation denies {} -> {}: {}",
                phase.as_str(),
                target.as_str(),
                denied.reason_code()
            );
            assert!(
                matches!(
                    denied.reason_code(),
                    RIGHTS_NOT_ADMITTED | "CAPTURE_BEFORE_PREFLIGHT"
                ),
                "{revocation_message}"
            );
            assert_eq!(
                lifecycle.state(),
                phase,
                "revocation never advances the phase"
            );
            let replayed =
                ConnectorLifecycle::replay(lifecycle.log()).expect("the revocation log replays");
            assert_eq!(replayed, lifecycle, "replay reproduces the revocation");
        }
    }

    #[test]
    fn long_lived_session_cannot_reuse_a_stale_lease() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_phase(ConnectorState::Validate, &clock);
        let retention = issue(OperationScope::Retention, &clock);
        admit(&mut lifecycle, OperationScope::Retention, &clock);
        lifecycle
            .advance(ConnectorState::Archive, &retention, &observation(&clock))
            .expect("the first archive lease is current");

        // A long-lived session crosses the original lease's validity interval.
        clock.now.set(LONG_SESSION_LATER);
        admit_valid(
            &mut lifecycle,
            OperationScope::Publication,
            LONG_SESSION_LATER - 1,
            LONG_SESSION_LATER + 1_000,
            &clock,
        );
        let error = lifecycle
            .advance(ConnectorState::Publish, &retention, &observation(&clock))
            .expect_err("a stale lease cannot authorise a later operation");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "a long-lived session cannot revive an expired lease"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Archive,
            "the stale lease did not move the machine"
        );
        let fresh = issue_valid(
            OperationScope::Publication,
            LONG_SESSION_LATER - 1,
            LONG_SESSION_LATER + 1_000,
            &clock,
        );
        lifecycle
            .advance(ConnectorState::Publish, &fresh, &observation(&clock))
            .expect("a fresh lease works after a long session");
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Publish,
            "publication required its own current lease"
        );
        assert!(
            lifecycle.used_leases().contains(&retention.digest()),
            "the consumed stale lease stays consumed"
        );
    }

    #[test]
    fn tampered_lease_or_observation_is_not_a_grant() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = ConnectorLifecycle::new();
        admit(&mut lifecycle, OperationScope::ProviderConnection, &clock);
        let mut tampered = issue(OperationScope::ProviderConnection, &clock);
        tampered.authority_digest = "b".repeat(64);
        assert!(
            !tampered.is_current_at(&observation(&clock)),
            "a mutated authority digest breaks the lease seal"
        );
        let error = lifecycle
            .advance(ConnectorState::Connect, &tampered, &observation(&clock))
            .expect_err("a tampered lease cannot authorise a transition");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "tampering fails closed"
        );
        let fake_observation = TrustedObservation {
            now_utc_ns: OBSERVED_AT,
            seal: String::new(),
        };
        let genuine = issue(OperationScope::ProviderConnection, &clock);
        let error = lifecycle
            .advance(ConnectorState::Connect, &genuine, &fake_observation)
            .expect_err("a caller-supplied observation is not trusted");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "observation authenticity is checked"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Preflight,
            "tampering never moved the machine"
        );
    }

    #[test]
    fn a_consumed_lease_cannot_be_reused_for_another_operation() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = ConnectorLifecycle::new();
        let lease = issue(OperationScope::ProviderConnection, &clock);
        admit(&mut lifecycle, OperationScope::ProviderConnection, &clock);
        lifecycle
            .advance(ConnectorState::Connect, &lease, &observation(&clock))
            .expect("the lease authorises connect");
        let error = lifecycle
            .advance(ConnectorState::Discover, &lease, &observation(&clock))
            .expect_err("the same lease cannot authorise discover");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "each operation consumes its own lease"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Connect,
            "reuse did not advance the phase"
        );
    }
}
