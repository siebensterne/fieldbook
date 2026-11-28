// SPDX-License-Identifier: Apache-2.0
//! Transport-independent connector lifecycle state machine.
//!
//! The machine records decisions about a sequence of phases:
//! `Preflight` → `Connect` → `Discover` → `Subscribe` → `Capture` → `Decode` →
//! `Validate` → `Archive` → `Publish`, with `Quarantine` and `Closed` as
//! cleanup branches reachable from every nonterminal phase, and `Revoked` and
//! `Retracted` as post-publication withdrawal branches. There is no concrete
//! provider, socket, storage or market payload in this module.
//!
//! THIS MODULE DOES NOT GRANT REAL RIGHTS. It grants no legal permission, no
//! access to any source, no collection capability and no authority over any
//! artifact. It is a pure decision recorder: the only authority it recognises
//! is a verified MAC produced by a configured `LeaseAuthority` key at the
//! trusted boundary. Caller-declared evidence, caller-declared time and a
//! caller-supplied `authority_digest` are references, never proof.
//!
//! Rights are bound to *operations*, never to one global boolean. The six
//! operation scopes are provider connection/collection, local capture/storage,
//! decoding/transformation, retention, publication/downstream use and research
//! use. Every externally relevant transition consumes an authority-signed
//! operation lease bound to the immutable session subject
//! `(source_id, provider, product, instrument scope)`, exact operation,
//! retention maximum, permitted uses and validity interval. Each operation
//! passes the actual target identity; a mismatched target denies before any
//! state change.
//!
//! Time comes only from a fresh observation obtained *inside* the operation
//! boundary from a sealed trusted time source. The machine rejects any
//! observation that rolls back a previously observed value, so wall-clock
//! rollback fails closed. `SystemUtcClock` is the only production source;
//! injectable clocks exist only in test builds.
//!
//! Lease consumption is claimed through a shared `IdempotencyClaim`. The pure
//! state machine can guarantee that a claim is attempted only after every
//! check succeeds and before a decision is committed, and that a failed claim
//! changes no lifecycle state. It cannot, on its own, guarantee exactly-once
//! behaviour across process restarts or crashes: that requires the injected
//! store to make the claim durable and atomic with the caller's side effect.
//!
//! Audit records carry a keyed, chained MAC. `verify_audit_log` fails closed
//! without an authority key and rejects any tampered record. `replay_state`
//! proves only deterministic lifecycle-state reconstruction; it never proves
//! authority, authenticity or that any right was actually granted.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::sync::Mutex;

use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

use crate::util::sha256_hex;

/// Exact denial code for rights evidence that is unknown, missing, expired,
/// out of scope, already denied, unauthenticated or backed by a non-current
/// lease.
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
    Revoked,
    Retracted,
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
            Self::Revoked => "revoked",
            Self::Retracted => "retracted",
        }
    }

    /// Legal successor phases from this phase.
    ///
    /// Every nonterminal phase can abort into `Quarantine` and then `Closed`.
    /// `Publish` has exactly one predecessor: an authorised `Archive` step.
    /// A published artifact can only be withdrawn into `Revoked` or `Retracted`
    /// and then closed; neither withdrawal permits further publication.
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
            Self::Publish => matches!(target, Self::Revoked | Self::Retracted | Self::Closed),
            Self::Quarantine | Self::Closed | Self::Revoked | Self::Retracted => {
                matches!(target, Self::Closed)
            }
        }
    }
}

/// Operation-scoped rights capability. A phase may only advance when the
/// scope for its operation has a current, unconsumed, authority-signed lease.
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
///
/// `retention_until_utc_ns` is a MAXIMUM retention limit, never an extension:
/// an operation at or beyond that instant is denied, and cleanup never moves
/// the limit.
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
/// set. Presence of this value is not a grant: it is only a reference that the
/// authority signs at the trusted boundary.
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
    /// Digest of the authority's decision, supplied by the caller as a
    /// reference. It is covered by the authority MAC but is never proof.
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
    /// The one-shot research-use decision consumed its lease.
    ResearchUsed,
    /// A published artifact was revoked and marked inactive.
    PublicationRevoked,
    /// A published artifact was retracted and marked inactive.
    PublicationRetracted,
}

impl DecisionKind {
    /// Stable audit spelling of this decision kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admitted => "admitted",
            Self::PreflightDenied => "preflight_denied",
            Self::Advanced => "advanced",
            Self::Denied => "denied",
            Self::ResearchUsed => "research_used",
            Self::PublicationRevoked => "publication_revoked",
            Self::PublicationRetracted => "publication_retracted",
        }
    }
}

/// One immutable decision record. Sequence numbers start at one and are
/// consecutive in a log. `to` names the requested target even when a
/// transition is denied, so state replay can reproduce the denial exactly.
/// `lease_digest` is present only for decisions that consumed a lease.
/// `authority_mac` is a keyed, chained MAC over every other field; it is the
/// authenticated authority evidence checked by `verify_audit_log`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedDecision {
    pub sequence: u64,
    pub from: ConnectorState,
    pub to: ConnectorState,
    pub kind: DecisionKind,
    pub reason_code: Option<LifecycleReason>,
    pub scope: Option<OperationScope>,
    pub lease_digest: Option<String>,
    pub observed_at_utc_ns: u64,
    pub authority_mac: String,
}

/// Sealing prevents an arbitrary caller type from masquerading as a trusted
/// time source or authority verifier in production builds.
mod private {
    pub trait Sealed {}
}

/// Sealed trusted time source. Only the integration boundary can supply a
/// reading; caller-supplied clocks are never accepted as authority. The trait
/// is sealed, and injectable implementations exist only in test builds.
pub trait TrustedTimeSource: private::Sealed {
    /// Current UTC time in nanoseconds since the Unix epoch.
    ///
    /// # Errors
    /// Returns `RIGHTS_NOT_ADMITTED` when a trustworthy reading is
    /// unavailable, so evaluation fails closed.
    fn now_utc_ns(&self) -> Result<u64, LifecycleError>;
}

/// System-clock implementation of the trusted boundary time source.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemUtcClock;

impl private::Sealed for SystemUtcClock {}

impl TrustedTimeSource for SystemUtcClock {
    fn now_utc_ns(&self) -> Result<u64, LifecycleError> {
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| rights_denial("trusted clock precedes the Unix epoch"))?;
        u64::try_from(elapsed.as_nanos())
            .map_err(|_| rights_denial("trusted clock exceeds u64 nanoseconds"))
    }
}

/// Single-use trusted time observation. It is deliberately not `Clone`, is
/// created only by `observe`, and is consumed inside an operation boundary;
/// a caller cannot supply or replay one.
///
/// ```compile_fail
/// use fieldbook::governance::connector_lifecycle::{observe, SystemUtcClock};
/// let observation = observe(&SystemUtcClock).expect("a trusted clock reading");
/// let _copy = observation.clone();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct TrustedObservation {
    now_utc_ns: u64,
}

impl TrustedObservation {
    /// Trusted reading obtained at the operation boundary.
    #[must_use]
    pub const fn as_utc_ns(&self) -> u64 {
        self.now_utc_ns
    }
}

/// Read the trusted clock once at the integration boundary.
///
/// # Errors
/// Returns `RIGHTS_NOT_ADMITTED` when the source cannot give a trustworthy
/// reading.
pub fn observe(source: &impl TrustedTimeSource) -> Result<TrustedObservation, LifecycleError> {
    let now_utc_ns = source.now_utc_ns()?;
    Ok(TrustedObservation { now_utc_ns })
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

fn hmac_sha256_hex(key: &[u8; 32], payload: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (index, byte) in key.iter().enumerate() {
        ipad[index] ^= byte;
        opad[index] ^= byte;
    }
    let mut inner = Vec::with_capacity(BLOCK.saturating_add(payload.len()));
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(payload);
    let inner_digest = Sha256::digest(&inner);
    let mut outer = Vec::with_capacity(BLOCK.saturating_add(inner_digest.len()));
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_digest);
    sha256_hex(&outer)
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left_byte, right_byte) in left.bytes().zip(right.bytes()) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

/// Proof that a specific payload was accepted by the configured authority.
/// The token is returned only by a successful `LeaseAuthority::verify` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityVerification {
    payload_digest: String,
}

impl AuthorityVerification {
    /// Digest of the payload that the authority authenticated.
    #[must_use]
    pub fn payload_digest(&self) -> &str {
        &self.payload_digest
    }
}

/// Authority-verification boundary. The pure machine holds no key of its own:
/// every operation must obtain an `AuthorityVerification` from the configured
/// authority before any state change. An unconfigured authority denies
/// everything.
pub trait LeaseAuthority: private::Sealed {
    /// Produce the authority MAC for one canonical payload.
    ///
    /// # Errors
    /// Returns `RIGHTS_NOT_ADMITTED` when no trusted key is configured.
    fn sign(&self, payload: &[u8]) -> Result<String, LifecycleError>;

    /// Verify a MAC over one canonical payload and return the decision token.
    ///
    /// # Errors
    /// Returns `RIGHTS_NOT_ADMITTED` when no key is configured or the MAC is
    /// not authentic. Verification never falls back to an unkeyed digest.
    fn verify(&self, payload: &[u8], mac: &str) -> Result<AuthorityVerification, LifecycleError>;
}

/// Production authority implementation. `unconfigured` has no trusted key and
/// therefore fails closed for both signing and verification; a key must be
/// injected by the trusted boundary before any lease can be issued.
#[derive(Debug, Clone, Copy)]
pub struct KeyedLeaseAuthority {
    key: Option<[u8; 32]>,
}

impl KeyedLeaseAuthority {
    /// Create an authority with no trusted key. Every decision is denied.
    #[must_use]
    pub const fn unconfigured() -> Self {
        Self { key: None }
    }

    /// Create an authority from a key supplied by the trusted boundary.
    #[must_use]
    pub const fn from_key(key: [u8; 32]) -> Self {
        Self { key: Some(key) }
    }
}

impl private::Sealed for KeyedLeaseAuthority {}

impl LeaseAuthority for KeyedLeaseAuthority {
    fn sign(&self, payload: &[u8]) -> Result<String, LifecycleError> {
        let key = self
            .key
            .ok_or_else(|| rights_denial("no trusted authority key is configured"))?;
        Ok(hmac_sha256_hex(&key, payload))
    }

    fn verify(&self, payload: &[u8], mac: &str) -> Result<AuthorityVerification, LifecycleError> {
        let key = self
            .key
            .ok_or_else(|| rights_denial("no trusted authority key is configured"))?;
        let expected = hmac_sha256_hex(&key, payload);
        if !constant_time_eq(&expected, mac) {
            return Err(rights_denial(
                "lease is not signed by the trusted authority",
            ));
        }
        Ok(AuthorityVerification {
            payload_digest: sha256_hex(payload),
        })
    }
}

/// Atomic lease-claim seam. The claim must be shared by all attempts for one
/// decision. A durable implementation is supplied by the caller at the
/// integration boundary; the in-memory implementation here proves the
/// in-process semantics only.
pub trait IdempotencyClaim {
    /// Atomically claim one lease digest. Return `false` when it was already
    /// claimed, so the caller must deny the duplicate without a side effect.
    ///
    /// # Errors
    /// Returns `RIGHTS_NOT_ADMITTED` when the store cannot decide atomically.
    fn claim(&self, lease_digest: &str) -> Result<bool, LifecycleError>;
}

/// Shared in-memory claim store. It is atomic within one process, not durable
/// across restarts; a restart-safe store must be injected for that guarantee.
#[derive(Debug, Default)]
pub struct AtomicIdempotency {
    claimed: Mutex<BTreeSet<String>>,
}

impl AtomicIdempotency {
    /// Create an empty claim store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl IdempotencyClaim for AtomicIdempotency {
    fn claim(&self, lease_digest: &str) -> Result<bool, LifecycleError> {
        let mut claimed = self
            .claimed
            .lock()
            .map_err(|_| rights_denial("idempotency claim store is poisoned"))?;
        Ok(claimed.insert(lease_digest.to_owned()))
    }
}

impl<T: IdempotencyClaim + ?Sized> IdempotencyClaim for Arc<T> {
    fn claim(&self, lease_digest: &str) -> Result<bool, LifecycleError> {
        (**self).claim(lease_digest)
    }
}

/// Single-use operation authorisation issued from validated evidence at the
/// integration boundary. Fields are private and the type deliberately has no
/// public `Deserialize` implementation: a caller cannot synthesize a grant
/// from JSON. Authenticity comes only from the authority MAC in `signature`.
///
/// ```compile_fail
/// use fieldbook::governance::connector_lifecycle::OperationLease;
/// let _: OperationLease = serde_json::from_str("{}").expect("cannot forge a lease from JSON");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationLease {
    lease_ref: String,
    subject: LeaseSubject,
    operation_ref: String,
    scope: OperationScope,
    terms: LeaseTerms,
    not_before_utc_ns: u64,
    valid_until_utc_ns: u64,
    authority_digest: String,
    signature: String,
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
        Self {
            lease_ref: request.lease_ref.clone(),
            subject: request.subject.clone(),
            operation_ref: request.operation_ref.clone(),
            scope: request.required_scope,
            terms: request.terms.clone(),
            not_before_utc_ns: evidence.valid_from_utc_ns,
            valid_until_utc_ns,
            authority_digest: evidence.authority_digest.clone(),
            signature: String::new(),
        }
    }

    /// Canonical bytes covered by the authority MAC. The MAC itself is
    /// excluded, and every authoritative field is included.
    #[must_use]
    pub fn signing_payload(&self) -> Vec<u8> {
        let permitted_uses = self
            .terms
            .permitted_uses
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        digest_parts(&[
            "fieldbook-p15-operation-lease-v1".to_owned(),
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
        .into_bytes()
    }

    /// Authority MAC over `signing_payload`. Also the single-use claim key.
    #[must_use]
    pub fn signature(&self) -> &str {
        &self.signature
    }

    /// Whether this lease's validity interval contains the trusted observation.
    /// Authenticity is checked separately by `verify` before any operation.
    #[must_use]
    pub fn is_current_at(&self, observation: &TrustedObservation) -> bool {
        observation.as_utc_ns() >= self.not_before_utc_ns
            && observation.as_utc_ns() < self.valid_until_utc_ns
    }

    /// Authority-authenticated digest used for single use and the decision log.
    #[must_use]
    pub fn digest(&self) -> String {
        self.signature.clone()
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

    /// Exact immutable identity this lease is bound to.
    #[must_use]
    pub const fn subject(&self) -> &LeaseSubject {
        &self.subject
    }

    /// Retention maximum and permitted uses this lease is bound to.
    #[must_use]
    pub const fn terms(&self) -> &LeaseTerms {
        &self.terms
    }
}

/// Pure preflight evaluation over caller-supplied declarations and a trusted
/// clock observation. This is the only way to issue an `OperationLease`, and
/// it requires the authority to sign the lease payload.
///
/// # Errors
/// Returns `RIGHTS_NOT_ADMITTED` when the request or evidence is incomplete,
/// the evidence is bound to another operation/identity/terms, its declared
/// state is not admitted, the required scope is absent, the authority digest
/// is malformed, the trusted observation lies outside the validity interval,
/// the retention maximum has elapsed, or the authority has no key. The
/// caller's `declared_observed_at_utc_ns` is ignored: it is not a rights grant.
pub fn evaluate_preflight(
    evidence: Option<&OperationRightsEvidence>,
    request: &OperationRequest,
    observation: &TrustedObservation,
    authority: &impl LeaseAuthority,
) -> Result<OperationLease, LifecycleError> {
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
    if now >= request.terms.retention_until_utc_ns {
        return Err(rights_denial("lease retention maximum has already elapsed"));
    }
    let lease = OperationLease::new(evidence, request, observation);
    let signature = authority.sign(&lease.signing_payload())?;
    Ok(OperationLease { signature, ..lease })
}

/// Operation scope required by an ordered phase transition.
///
/// Cleanup branches (`Quarantine`, `Closed`, `Revoked`, `Retracted`) need no
/// capability: they are always allowed so a denied machine can still be withdrawn
/// without publishing, extending retention or admitting data.
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

/// Operation-to-permitted-use policy. A lease may be used only for the use
/// named by the operation it was issued for; no other use is implied.
#[must_use]
pub const fn required_permitted_use(scope: OperationScope) -> &'static str {
    match scope {
        OperationScope::ProviderConnection => "provider_connection",
        OperationScope::LocalCapture => "local_capture",
        OperationScope::DecodeTransform => "decode_transform",
        OperationScope::Retention => "retention",
        OperationScope::Publication => "publication",
        OperationScope::ResearchUse => "local_research",
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
/// the operation scope bound to the requested transition. Lease currency and
/// authority are checked separately by `ConnectorLifecycle::advance`.
///
/// # Errors
/// Returns `InvalidTransition` for an out-of-order request,
/// `CaptureBeforePreflight` when capture lacks its own scope, or
/// `RIGHTS_NOT_ADMITTED` when any other required scope is not currently
/// admitted.
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

/// Initial link of the audit MAC chain.
const INITIAL_AUDIT_MAC: &str = "0000000000000000000000000000000000000000000000000000000000000000";

struct DecisionInput {
    from: ConnectorState,
    to: ConnectorState,
    kind: DecisionKind,
    reason_code: Option<LifecycleReason>,
    scope: Option<OperationScope>,
    lease_digest: Option<String>,
    observed_at_utc_ns: u64,
}

fn audit_payload(record: &RecordedDecision, previous_mac: &str) -> Vec<u8> {
    digest_parts(&[
        "fieldbook-p15-audit-v1".to_owned(),
        record.sequence.to_string(),
        record.from.as_str().to_owned(),
        record.to.as_str().to_owned(),
        record.kind.as_str().to_owned(),
        record
            .reason_code
            .map(LifecycleReason::as_str)
            .unwrap_or("-")
            .to_owned(),
        record
            .scope
            .map(OperationScope::as_str)
            .unwrap_or("-")
            .to_owned(),
        record.lease_digest.clone().unwrap_or_default(),
        record.observed_at_utc_ns.to_string(),
        previous_mac.to_owned(),
    ])
    .into_bytes()
}

/// Lifecycle state, immutable session subject, operation-scoped rights,
/// consumed lease claims, trusted-time watermark and authenticated decisions.
/// There is no I/O and no clock access on any method: time enters only via an
/// injected sealed source at the operation boundary. `ConnectorLifecycle` is
/// deliberately not `Clone`: a cloned state could bypass the shared claim
/// store and replay a consumed lease.
///
/// ```compile_fail
/// use fieldbook::governance::connector_lifecycle::{ConnectorLifecycle, LeaseSubject};
/// let subject = LeaseSubject {
///     source_id: "s".to_owned(), provider_id: "p".to_owned(),
///     product_ref: "x".to_owned(), instrument_ref: "i".to_owned(),
/// };
/// let lifecycle = ConnectorLifecycle::new(subject).expect("a complete subject");
/// let _clone = lifecycle.clone();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ConnectorLifecycle {
    state: ConnectorState,
    subject: LeaseSubject,
    admitted_scopes: BTreeSet<OperationScope>,
    denied_scopes: BTreeSet<OperationScope>,
    used_leases: BTreeSet<String>,
    log: Vec<RecordedDecision>,
    last_observation_ns: u64,
    artifact_active: bool,
}

impl ConnectorLifecycle {
    /// New machine at `Preflight`, bound immutably to one subject.
    ///
    /// # Errors
    /// Returns `RIGHTS_NOT_ADMITTED` when the subject is incomplete, so a
    /// session can never operate on an unspecified target.
    pub fn new(subject: LeaseSubject) -> Result<Self, LifecycleError> {
        if !subject.complete() {
            return Err(rights_denial("session subject is incomplete"));
        }
        Ok(Self {
            state: ConnectorState::Preflight,
            subject,
            admitted_scopes: BTreeSet::new(),
            denied_scopes: BTreeSet::new(),
            used_leases: BTreeSet::new(),
            log: Vec::new(),
            last_observation_ns: 0,
            artifact_active: false,
        })
    }

    /// Current phase.
    #[must_use]
    pub const fn state(&self) -> ConnectorState {
        self.state
    }

    /// Immutable subject this lifecycle session is bound to.
    #[must_use]
    pub const fn subject(&self) -> &LeaseSubject {
        &self.subject
    }

    /// Whether a published artifact is currently active.
    #[must_use]
    pub const fn artifact_active(&self) -> bool {
        self.artifact_active
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

    /// Digests of leases already claimed by a committed decision.
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

    fn fresh_observation(
        &mut self,
        source: &impl TrustedTimeSource,
    ) -> Result<TrustedObservation, LifecycleError> {
        let observation = observe(source)?;
        let now = observation.as_utc_ns();
        if now < self.last_observation_ns {
            return Err(rights_denial("trusted time observation rolled back"));
        }
        self.last_observation_ns = now;
        Ok(observation)
    }

    /// Consume operation evidence and issue an authority-signed lease for one
    /// scope. The request subject must be the immutable session subject. An
    /// admission enables only the requested scope; a denial revokes that scope
    /// permanently. The phase never moves.
    ///
    /// # Errors
    /// Returns the fail-closed denial from `evaluate_preflight`, a denial when
    /// the scope was previously denied or the target is not the session
    /// subject, or an error when the decision cannot be audit-signed.
    pub fn preflight(
        &mut self,
        evidence: Option<&OperationRightsEvidence>,
        request: &OperationRequest,
        source: &impl TrustedTimeSource,
        authority: &impl LeaseAuthority,
    ) -> Result<OperationLease, LifecycleError> {
        let observation = self.fresh_observation(source)?;
        let scope = request.required_scope;
        let phase = self.state;
        let outcome = if self.denied_scopes.contains(&scope) {
            Err(rights_denial(format!(
                "scope {} was denied earlier and cannot be restored",
                scope.as_str()
            )))
        } else if request.subject != self.subject {
            Err(rights_denial(
                "request target is not the session lease subject",
            ))
        } else {
            evaluate_preflight(evidence, request, &observation, authority)
        };
        let (kind, reason_code) = match &outcome {
            Ok(_) => (DecisionKind::Admitted, None),
            Err(error) => (DecisionKind::PreflightDenied, Some(error.reason)),
        };
        match &outcome {
            Ok(_) => {
                self.admitted_scopes.insert(scope);
            }
            Err(_) => {
                self.admitted_scopes.remove(&scope);
                self.denied_scopes.insert(scope);
            }
        }
        self.record(
            DecisionInput {
                from: phase,
                to: phase,
                kind,
                reason_code,
                scope: Some(scope),
                lease_digest: None,
                observed_at_utc_ns: observation.as_utc_ns(),
            },
            authority,
        )?;
        outcome
    }

    /// Revoke an operation scope. Outstanding leases for that scope can no
    /// longer authorise any operation.
    ///
    /// # Errors
    /// Returns an error when the trusted boundary cannot supply time or audit
    /// evidence.
    pub fn revoke(
        &mut self,
        scope: OperationScope,
        source: &impl TrustedTimeSource,
        authority: &impl LeaseAuthority,
    ) -> Result<(), LifecycleError> {
        let observation = self.fresh_observation(source)?;
        self.admitted_scopes.remove(&scope);
        self.denied_scopes.insert(scope);
        let phase = self.state;
        self.record(
            DecisionInput {
                from: phase,
                to: phase,
                kind: DecisionKind::PreflightDenied,
                reason_code: Some(LifecycleReason::RightsNotAdmitted),
                scope: Some(scope),
                lease_digest: None,
                observed_at_utc_ns: observation.as_utc_ns(),
            },
            authority,
        )
    }

    /// Apply an advanced phase transition using one current, authority-signed
    /// lease and the actual target identity.
    ///
    /// The lease must be bound to the operation, scope, subject, permitted use
    /// and retention maximum of this transition, be current at a fresh trusted
    /// observation, verify under the configured authority, and be claimed
    /// atomically by the shared idempotency store. A scope-level rights denial
    /// revokes the scope permanently; a lease-specific denial denies only the
    /// operation.
    ///
    /// # Errors
    /// Returns `InvalidTransition` for cleanup targets and out-of-order steps,
    /// or `RIGHTS_NOT_ADMITTED` when the scope, target, authority, time or
    /// lease does not authorise this operation.
    pub fn advance(
        &mut self,
        target: ConnectorState,
        lease: &OperationLease,
        target_subject: &LeaseSubject,
        source: &impl TrustedTimeSource,
        authority: &impl LeaseAuthority,
        idempotency: &impl IdempotencyClaim,
    ) -> Result<(), LifecycleError> {
        let observation = self.fresh_observation(source)?;
        let from = self.state;
        let scope = required_scope_for_transition(from, target);
        let mut outcome =
            decide_transition(from, target, &self.admitted_scopes, &self.denied_scopes);
        if outcome.is_ok() {
            outcome = match scope {
                Some(scope) => {
                    let operation_ref = required_operation_for_transition(from, target);
                    self.check_lease(
                        scope,
                        operation_ref.unwrap_or(""),
                        lease,
                        target_subject,
                        &observation,
                        authority,
                    )
                    .map(|_| ())
                }
                None => Err(LifecycleError::new(
                    LifecycleReason::InvalidTransition,
                    "cleanup targets require quarantine or close, not a lease",
                )),
            };
        }
        if outcome.is_ok() {
            outcome = match idempotency.claim(&lease.digest()) {
                Ok(true) => Ok(()),
                Ok(false) => Err(rights_denial(
                    "operation lease was already consumed by an idempotency claim",
                )),
                Err(error) => Err(error),
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
                    DecisionInput {
                        from,
                        to: target,
                        kind: DecisionKind::Advanced,
                        reason_code: None,
                        scope,
                        lease_digest,
                        observed_at_utc_ns: observation.as_utc_ns(),
                    },
                    authority,
                )?;
                self.state = target;
                if target == ConnectorState::Publish {
                    self.artifact_active = true;
                }
            }
            Err(error) => {
                let revoked = error.reason != LifecycleReason::InvalidTransition
                    && !Self::lease_only_denial(error);
                if revoked && let Some(scope) = scope {
                    self.admitted_scopes.remove(&scope);
                    self.denied_scopes.insert(scope);
                }
                self.record(
                    DecisionInput {
                        from,
                        to: target,
                        kind: DecisionKind::Denied,
                        reason_code: Some(error.reason),
                        scope,
                        lease_digest: None,
                        observed_at_utc_ns: observation.as_utc_ns(),
                    },
                    authority,
                )?;
            }
        }
        outcome
    }

    fn check_lease(
        &self,
        scope: OperationScope,
        operation_ref: &str,
        lease: &OperationLease,
        target_subject: &LeaseSubject,
        observation: &TrustedObservation,
        authority: &impl LeaseAuthority,
    ) -> Result<AuthorityVerification, LifecycleError> {
        if lease.scope() != scope {
            return Err(rights_denial("lease is bound to another operation scope"));
        }
        if operation_ref != lease.operation_ref() {
            return Err(rights_denial("lease is bound to another operation"));
        }
        if lease.subject() != target_subject
            || target_subject != &self.subject
            || lease.subject() != &self.subject
        {
            return Err(rights_denial(
                "lease subject does not match the actual operation target",
            ));
        }
        if !lease
            .terms()
            .permitted_uses
            .contains(required_permitted_use(scope))
        {
            return Err(rights_denial("lease does not permit this operation use"));
        }
        if observation.as_utc_ns() >= lease.terms().retention_until_utc_ns {
            return Err(rights_denial(
                "lease retention maximum has elapsed at the operation time",
            ));
        }
        let verification = authority.verify(&lease.signing_payload(), lease.signature())?;
        if !lease.is_current_at(observation) {
            return Err(rights_denial("operation lease is not current"));
        }
        if self.used_leases.contains(&lease.digest()) {
            return Err(rights_denial("operation lease was already consumed"));
        }
        Ok(verification)
    }

    fn lease_only_denial(error: &LifecycleError) -> bool {
        error.detail.contains("lease")
    }

    /// Abort into `Quarantine` from any nonterminal phase. Cleanup needs no
    /// capability: it changes no rights, retention or admission state and
    /// marks any published artifact inactive.
    ///
    /// # Errors
    /// Returns `InvalidTransition` only from a terminal phase.
    pub fn quarantine(
        &mut self,
        source: &impl TrustedTimeSource,
        authority: &impl LeaseAuthority,
    ) -> Result<(), LifecycleError> {
        self.cleanup(ConnectorState::Quarantine, source, authority)
    }

    /// Close from `Publish`, `Quarantine` or any nonterminal phase. Cleanup
    /// needs no capability and changes no rights, retention or admission state.
    ///
    /// # Errors
    /// Returns `InvalidTransition` only from `Closed`.
    pub fn close(
        &mut self,
        source: &impl TrustedTimeSource,
        authority: &impl LeaseAuthority,
    ) -> Result<(), LifecycleError> {
        self.cleanup(ConnectorState::Closed, source, authority)
    }

    fn cleanup(
        &mut self,
        target: ConnectorState,
        source: &impl TrustedTimeSource,
        authority: &impl LeaseAuthority,
    ) -> Result<(), LifecycleError> {
        let observation = self.fresh_observation(source)?;
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
        let (kind, reason_code) = match &outcome {
            Ok(()) => (DecisionKind::Advanced, None),
            Err(error) => (DecisionKind::Denied, Some(error.reason)),
        };
        self.record(
            DecisionInput {
                from,
                to: target,
                kind,
                reason_code,
                scope: None,
                lease_digest: None,
                observed_at_utc_ns: observation.as_utc_ns(),
            },
            authority,
        )?;
        if outcome.is_ok() {
            self.state = target;
            self.artifact_active = false;
        }
        outcome
    }

    /// One-shot research-use gate. Research use has no lifecycle phase, so
    /// this method consumes its lease through the shared idempotency store and
    /// records a `ResearchUsed` decision. A second use of the same lease is
    /// denied; there is no reusable research method here.
    ///
    /// # Errors
    /// Returns `RIGHTS_NOT_ADMITTED` unless research use is admitted and the
    /// lease is authentic, current, bound to the target, permitted for
    /// `local_research` and not already claimed.
    pub fn research_use(
        &mut self,
        lease: &OperationLease,
        target_subject: &LeaseSubject,
        source: &impl TrustedTimeSource,
        authority: &impl LeaseAuthority,
        idempotency: &impl IdempotencyClaim,
    ) -> Result<(), LifecycleError> {
        let observation = self.fresh_observation(source)?;
        let scope = OperationScope::ResearchUse;
        let phase = self.state;
        let mut outcome = if !self.scope_admitted(scope) {
            Err(rights_denial("research use is not currently admitted"))
        } else {
            self.check_lease(
                scope,
                "research_use",
                lease,
                target_subject,
                &observation,
                authority,
            )
            .map(|_| ())
        };
        if outcome.is_ok() {
            outcome = match idempotency.claim(&lease.digest()) {
                Ok(true) => Ok(()),
                Ok(false) => Err(rights_denial(
                    "research use lease was already consumed by an idempotency claim",
                )),
                Err(error) => Err(error),
            };
        }
        let (kind, reason_code, lease_digest) = match &outcome {
            Ok(()) => (DecisionKind::ResearchUsed, None, Some(lease.digest())),
            Err(error) => (DecisionKind::Denied, Some(error.reason), None),
        };
        if outcome.is_ok() {
            self.used_leases.insert(lease.digest());
        }
        self.record(
            DecisionInput {
                from: phase,
                to: phase,
                kind,
                reason_code,
                scope: Some(scope),
                lease_digest,
                observed_at_utc_ns: observation.as_utc_ns(),
            },
            authority,
        )?;
        outcome
    }

    /// Revoke a published artifact. It is marked inactive and can only be
    /// closed afterwards; further publication is impossible. Revocation needs
    /// no capability because leaving an unauthorised artifact active is never
    /// acceptable.
    ///
    /// # Errors
    /// Returns `InvalidTransition` unless the artifact is currently published.
    pub fn revoke_publication(
        &mut self,
        source: &impl TrustedTimeSource,
        authority: &impl LeaseAuthority,
    ) -> Result<(), LifecycleError> {
        self.withdraw(
            ConnectorState::Revoked,
            DecisionKind::PublicationRevoked,
            source,
            authority,
        )
    }

    /// Retract a published artifact. It is marked inactive and can only be
    /// closed afterwards; further publication is impossible.
    ///
    /// # Errors
    /// Returns `InvalidTransition` unless the artifact is currently published.
    pub fn retract_publication(
        &mut self,
        source: &impl TrustedTimeSource,
        authority: &impl LeaseAuthority,
    ) -> Result<(), LifecycleError> {
        self.withdraw(
            ConnectorState::Retracted,
            DecisionKind::PublicationRetracted,
            source,
            authority,
        )
    }

    fn withdraw(
        &mut self,
        target: ConnectorState,
        success_kind: DecisionKind,
        source: &impl TrustedTimeSource,
        authority: &impl LeaseAuthority,
    ) -> Result<(), LifecycleError> {
        let observation = self.fresh_observation(source)?;
        let from = self.state;
        let outcome = if from == ConnectorState::Publish && self.artifact_active {
            Ok(())
        } else {
            Err(LifecycleError::new(
                LifecycleReason::InvalidTransition,
                format!("{} has no active artifact to withdraw", from.as_str()),
            ))
        };
        let (kind, reason_code) = match &outcome {
            Ok(()) => (success_kind, None),
            Err(error) => (DecisionKind::Denied, Some(error.reason)),
        };
        self.record(
            DecisionInput {
                from,
                to: target,
                kind,
                reason_code,
                scope: None,
                lease_digest: None,
                observed_at_utc_ns: observation.as_utc_ns(),
            },
            authority,
        )?;
        if outcome.is_ok() {
            self.state = target;
            self.artifact_active = false;
        }
        outcome
    }

    /// Deterministic lifecycle-STATE replay of an untrusted decision log.
    ///
    /// This proves only that the recorded decisions reproduce the same phase,
    /// scope, lease-claim and cleanup state. It does NOT verify authority,
    /// authenticity, signatures or that any real right was granted; use
    /// `verify_audit_log` for that. The subject is supplied by the caller and
    /// is not derived from the log.
    ///
    /// # Errors
    /// Returns `LogMismatch` if any record is inconsistent with the decisions
    /// that would have produced it.
    pub fn replay_state(
        records: &[RecordedDecision],
        subject: LeaseSubject,
    ) -> Result<Self, LifecycleError> {
        if !subject.complete() {
            return Err(Self::mismatch("replay subject is incomplete"));
        }
        let mut lifecycle = Self {
            state: ConnectorState::Preflight,
            subject,
            admitted_scopes: BTreeSet::new(),
            denied_scopes: BTreeSet::new(),
            used_leases: BTreeSet::new(),
            log: Vec::new(),
            last_observation_ns: 0,
            artifact_active: false,
        };
        for (index, record) in records.iter().enumerate() {
            let expected = u64::try_from(index + 1).unwrap_or(u64::MAX);
            if record.sequence != expected {
                return Err(Self::mismatch("decision sequence is not consecutive"));
            }
            if record.from != lifecycle.state {
                return Err(Self::mismatch("recorded from-state does not match replay"));
            }
            if record.observed_at_utc_ns < lifecycle.last_observation_ns {
                return Err(Self::mismatch("replayed trusted observation rolled back"));
            }
            lifecycle.last_observation_ns = record.observed_at_utc_ns;
            if !is_authority_digest(&record.authority_mac) {
                return Err(Self::mismatch("decision has no authority evidence"));
            }
            lifecycle.apply_record(record)?;
            lifecycle.log.push(record.clone());
        }
        Ok(lifecycle)
    }

    fn apply_record(&mut self, record: &RecordedDecision) -> Result<(), LifecycleError> {
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
                if self.denied_scopes.contains(&scope) {
                    return Err(Self::mismatch("a denied scope was restored"));
                }
                self.admitted_scopes.insert(scope);
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
                self.admitted_scopes.remove(&scope);
                self.denied_scopes.insert(scope);
            }
            DecisionKind::Advanced => {
                if record.reason_code.is_some()
                    || decide_transition(
                        record.from,
                        record.to,
                        &self.admitted_scopes,
                        &self.denied_scopes,
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
                        if !is_authority_digest(digest) || !self.used_leases.insert(digest.clone())
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
                self.state = record.to;
                if record.to == ConnectorState::Publish {
                    self.artifact_active = true;
                }
                if matches!(
                    record.to,
                    ConnectorState::Quarantine | ConnectorState::Closed
                ) {
                    self.artifact_active = false;
                }
            }
            DecisionKind::Denied => {
                let Some(reason) = record.reason_code else {
                    return Err(Self::mismatch("denied decision has no reason"));
                };
                if record.lease_digest.is_some() {
                    return Err(Self::mismatch("denied decision consumed a lease"));
                }
                if record.to == record.from && record.scope == Some(OperationScope::ResearchUse) {
                    if reason != LifecycleReason::RightsNotAdmitted {
                        return Err(Self::mismatch("research denial has the wrong reason"));
                    }
                    // A one-shot research-use denial consumes no lease and
                    // never revokes the scope permanently.
                    return Ok(());
                }
                let Err(error) = decide_transition(
                    record.from,
                    record.to,
                    &self.admitted_scopes,
                    &self.denied_scopes,
                ) else {
                    return Err(Self::mismatch("denied transition is legal"));
                };
                if error.reason != reason {
                    return Err(Self::mismatch("denied reason is not reproducible"));
                }
                if record.scope != required_scope_for_transition(record.from, record.to) {
                    return Err(Self::mismatch("denied scope does not match the phase"));
                }
                if let Some(scope) = record.scope {
                    self.admitted_scopes.remove(&scope);
                    self.denied_scopes.insert(scope);
                }
            }
            DecisionKind::ResearchUsed => {
                if record.to != record.from
                    || record.reason_code.is_some()
                    || record.scope != Some(OperationScope::ResearchUse)
                {
                    return Err(Self::mismatch("research use changed the phase"));
                }
                let Some(digest) = &record.lease_digest else {
                    return Err(Self::mismatch("research use has no lease"));
                };
                if !is_authority_digest(digest) || !self.used_leases.insert(digest.clone()) {
                    return Err(Self::mismatch(
                        "research lease digest is reused or malformed",
                    ));
                }
            }
            DecisionKind::PublicationRevoked | DecisionKind::PublicationRetracted => {
                let expected = if record.kind == DecisionKind::PublicationRevoked {
                    ConnectorState::Revoked
                } else {
                    ConnectorState::Retracted
                };
                if record.from != ConnectorState::Publish
                    || record.to != expected
                    || record.reason_code.is_some()
                    || record.scope.is_some()
                    || record.lease_digest.is_some()
                    || !self.artifact_active
                {
                    return Err(Self::mismatch("publication withdrawal is not legal"));
                }
                self.state = expected;
                self.artifact_active = false;
            }
        }
        Ok(())
    }

    fn record(
        &mut self,
        input: DecisionInput,
        authority: &impl LeaseAuthority,
    ) -> Result<(), LifecycleError> {
        let sequence = u64::try_from(self.log.len() + 1).unwrap_or(u64::MAX);
        let previous = self
            .log
            .last()
            .map_or(INITIAL_AUDIT_MAC, |record| record.authority_mac.as_str());
        let mut record = RecordedDecision {
            sequence,
            from: input.from,
            to: input.to,
            kind: input.kind,
            reason_code: input.reason_code,
            scope: input.scope,
            lease_digest: input.lease_digest,
            observed_at_utc_ns: input.observed_at_utc_ns,
            authority_mac: String::new(),
        };
        let payload = audit_payload(&record, previous);
        record.authority_mac = authority.sign(&payload)?;
        self.log.push(record);
        Ok(())
    }

    fn mismatch(detail: &'static str) -> LifecycleError {
        LifecycleError::new(LifecycleReason::LogMismatch, detail)
    }
}

/// Result of an authenticated audit-log verification. State replay alone is
/// never an authority result; this token additionally requires an authority
/// key and an intact MAC chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditVerification {
    pub record_count: usize,
    pub final_state: ConnectorState,
    pub subject: LeaseSubject,
    pub authority_digest: String,
}

/// Verify that an audit log is authenticated and tamper-evident, then replay
/// its lifecycle state. Fails closed without a configured authority key, with
/// an empty log, with a broken MAC chain or with any tampered decision.
///
/// # Errors
/// Returns `RIGHTS_NOT_ADMITTED` when authority evidence is missing or
/// unauthenticated, or `LogMismatch` when the state is not reproducible.
pub fn verify_audit_log(
    records: &[RecordedDecision],
    subject: LeaseSubject,
    authority: &impl LeaseAuthority,
) -> Result<AuditVerification, LifecycleError> {
    if records.is_empty() {
        return Err(rights_denial(
            "audit log is empty: there is no authenticated authority evidence",
        ));
    }
    let mut previous: &str = INITIAL_AUDIT_MAC;
    let mut consumed = 0usize;
    for (index, record) in records.iter().enumerate() {
        if record.sequence != u64::try_from(index + 1).unwrap_or(u64::MAX) {
            return Err(ConnectorLifecycle::mismatch(
                "audit decision sequence is not consecutive",
            ));
        }
        let payload = audit_payload(record, previous);
        authority.verify(&payload, &record.authority_mac)?;
        if let Some(digest) = &record.lease_digest {
            if !is_authority_digest(digest) {
                return Err(rights_denial("audit lease evidence is malformed"));
            }
            consumed = consumed.saturating_add(1);
        }
        previous = record.authority_mac.as_str();
    }
    if consumed == 0 {
        return Err(rights_denial(
            "audit log has no authority-issued lease evidence",
        ));
    }
    let replayed = ConnectorLifecycle::replay_state(records, subject.clone())?;
    Ok(AuditVerification {
        record_count: records.len(),
        final_state: replayed.state(),
        subject: replayed.subject().clone(),
        authority_digest: previous.to_owned(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::thread;

    const OBSERVED_AT: u64 = 1_700_000_000_000_000_000;
    const VALID_UNTIL: u64 = 1_700_000_000_100_000_000;
    const LONG_SESSION_LATER: u64 = 1_800_000_000_000_000_000;
    const RETENTION_LIMIT: u64 = 1_900_000_000_000_000_000;
    const TEST_KEY: [u8; 32] = [0x11; 32];

    /// TEST-ONLY authority verifier. It never appears in a production build.
    #[derive(Debug, Clone, Copy)]
    struct TestLeaseAuthority;

    impl private::Sealed for TestLeaseAuthority {}

    impl LeaseAuthority for TestLeaseAuthority {
        fn sign(&self, payload: &[u8]) -> Result<String, LifecycleError> {
            Ok(hmac_sha256_hex(&TEST_KEY, payload))
        }

        fn verify(
            &self,
            payload: &[u8],
            mac: &str,
        ) -> Result<AuthorityVerification, LifecycleError> {
            let expected = hmac_sha256_hex(&TEST_KEY, payload);
            if !constant_time_eq(&expected, mac) {
                return Err(rights_denial(
                    "test authority rejected an unauthentic lease",
                ));
            }
            Ok(AuthorityVerification {
                payload_digest: sha256_hex(payload),
            })
        }
    }

    fn authority() -> &'static TestLeaseAuthority {
        static AUTHORITY: TestLeaseAuthority = TestLeaseAuthority;
        &AUTHORITY
    }

    #[derive(Debug)]
    struct FixedClock {
        now: AtomicU64,
    }

    impl FixedClock {
        fn at(now: u64) -> Self {
            Self {
                now: AtomicU64::new(now),
            }
        }

        fn set(&self, now: u64) {
            self.now.store(now, Ordering::Relaxed);
        }
    }

    impl private::Sealed for FixedClock {}

    impl TrustedTimeSource for FixedClock {
        fn now_utc_ns(&self) -> Result<u64, LifecycleError> {
            Ok(self.now.load(Ordering::Relaxed))
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

    fn other_source() -> LeaseSubject {
        LeaseSubject {
            source_id: "other-source".to_owned(),
            ..subject()
        }
    }

    fn other_instrument() -> LeaseSubject {
        LeaseSubject {
            instrument_ref: "other-instrument".to_owned(),
            ..subject()
        }
    }

    fn terms() -> LeaseTerms {
        LeaseTerms {
            retention_until_utc_ns: RETENTION_LIMIT,
            permitted_uses: BTreeSet::from([
                "provider_connection".to_owned(),
                "local_capture".to_owned(),
                "decode_transform".to_owned(),
                "retention".to_owned(),
                "publication".to_owned(),
                "local_research".to_owned(),
            ]),
        }
    }

    fn terms_with_uses(uses: &[&str]) -> LeaseTerms {
        LeaseTerms {
            retention_until_utc_ns: RETENTION_LIMIT,
            permitted_uses: uses.iter().map(|value| (*value).to_owned()).collect(),
        }
    }

    fn lifecycle() -> ConnectorLifecycle {
        ConnectorLifecycle::new(subject()).expect("a complete subject binds a session")
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

    fn request_with_terms(scope: OperationScope, bound_terms: &LeaseTerms) -> OperationRequest {
        let mut value = request(scope);
        value.terms = bound_terms.clone();
        value
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

    fn evidence_with_terms(
        scope: OperationScope,
        bound_terms: &LeaseTerms,
    ) -> OperationRightsEvidence {
        let mut value = valid_evidence(scope);
        value.terms = bound_terms.clone();
        value
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

    fn evaluate(
        evidence: &OperationRightsEvidence,
        bound_request: &OperationRequest,
        clock: &FixedClock,
    ) -> Result<OperationLease, LifecycleError> {
        evaluate_preflight(
            Some(evidence),
            bound_request,
            &observation(clock),
            authority(),
        )
    }

    fn issue(scope: OperationScope, clock: &FixedClock) -> OperationLease {
        evaluate(&valid_evidence(scope), &request(scope), clock)
            .expect("valid evidence issues a signed lease")
    }

    fn issue_valid(
        scope: OperationScope,
        valid_from_utc_ns: u64,
        valid_until_utc_ns: u64,
        clock: &FixedClock,
    ) -> OperationLease {
        evaluate(
            &evidence_valid(scope, valid_from_utc_ns, valid_until_utc_ns),
            &request(scope),
            clock,
        )
        .expect("valid evidence issues a signed lease")
    }

    fn admit(lifecycle: &mut ConnectorLifecycle, scope: OperationScope, clock: &FixedClock) {
        lifecycle
            .preflight(
                Some(&valid_evidence(scope)),
                &request(scope),
                clock,
                authority(),
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
                clock,
                authority(),
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
                &FixedClock::at(OBSERVED_AT),
                authority(),
            )
            .expect_err("unknown evidence denies the requested scope");
    }

    fn advance(lifecycle: &mut ConnectorLifecycle, target: ConnectorState, clock: &FixedClock) {
        if target == ConnectorState::Closed {
            lifecycle
                .close(clock, authority())
                .expect("cleanup closes the machine");
            return;
        }
        if target == ConnectorState::Quarantine {
            lifecycle
                .quarantine(clock, authority())
                .expect("cleanup quarantines the machine");
            return;
        }
        let scope = required_scope_for_transition(lifecycle.state(), target)
            .expect("an advanced transition has an operation scope");
        admit(lifecycle, scope, clock);
        let lease = issue(scope, clock);
        lifecycle
            .advance(
                target,
                &lease,
                &subject(),
                clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect("an ordered transition with a current lease succeeds");
    }

    fn through_subscribe(clock: &FixedClock) -> ConnectorLifecycle {
        let mut lifecycle = lifecycle();
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
            return lifecycle();
        }
        let mut lifecycle = lifecycle();
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

    fn through_published(clock: &FixedClock) -> ConnectorLifecycle {
        let mut lifecycle = through_phase(ConnectorState::Archive, clock);
        advance(&mut lifecycle, ConnectorState::Publish, clock);
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
        let mut lifecycle = lifecycle();
        let error = lifecycle
            .preflight(Some(&unknown), &request(scope), &clock, authority())
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
            .advance(
                ConnectorState::Connect,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
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
        let error = evaluate_preflight(None, &request(scope), &obs, authority())
            .expect_err("missing evidence is denied");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "missing evidence code"
        );
        let mut expired = valid_evidence(scope);
        expired.valid_until_utc_ns = Some(OBSERVED_AT);
        let error = evaluate_preflight(Some(&expired), &request(scope), &obs, authority())
            .expect_err("expired evidence is denied");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED, "expiry code");
        let mut out_of_scope = valid_evidence(scope);
        out_of_scope.state = RightsEvidenceState::OutOfScope;
        let error = evaluate_preflight(Some(&out_of_scope), &request(scope), &obs, authority())
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
        for bound_request in [&wrong_operation, &wrong_terms] {
            evaluate_preflight(
                Some(&valid_evidence(scope)),
                bound_request,
                &observation(&clock),
                authority(),
            )
            .expect_err("a mismatched request is denied");
        }
        evaluate_preflight(
            Some(&evidence),
            &request(scope),
            &observation(&clock),
            authority(),
        )
        .expect_err("identity-bound evidence is denied");
        evidence = valid_evidence(scope);
        evidence.authority_digest = "z".repeat(64);
        evaluate_preflight(
            Some(&evidence),
            &request(scope),
            &observation(&clock),
            authority(),
        )
        .expect_err("a malformed authority digest is denied");
        let mut declared = request(scope);
        declared.declared_observed_at_utc_ns = LONG_SESSION_LATER;
        let lease = evaluate_preflight(
            Some(&valid_evidence(scope)),
            &declared,
            &observation(&clock),
            authority(),
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
        let error = evaluate_preflight(
            Some(&evidence),
            &request(scope),
            &observation(&clock),
            authority(),
        )
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
        let mut lifecycle = lifecycle();
        admit(&mut lifecycle, OperationScope::ProviderConnection, &clock);
        let lease = issue(OperationScope::ProviderConnection, &clock);
        let store = AtomicIdempotency::new();
        let error = lifecycle
            .advance(
                ConnectorState::Capture,
                &lease,
                &subject(),
                &clock,
                authority(),
                &store,
            )
            .expect_err("capture cannot skip phases");
        assert_eq!(
            error.reason_code(),
            "INVALID_TRANSITION",
            "out-of-order transition has a stable code"
        );
        let error = lifecycle
            .advance(
                ConnectorState::Discover,
                &lease,
                &subject(),
                &clock,
                authority(),
                &store,
            )
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
            .advance(
                ConnectorState::Connect,
                &lease,
                &subject(),
                &clock,
                authority(),
                &store,
            )
            .expect("connect follows preflight");
        let error = lifecycle
            .advance(
                ConnectorState::Connect,
                &lease,
                &subject(),
                &clock,
                authority(),
                &store,
            )
            .expect_err("a repeated phase is not a transition");
        assert_eq!(
            error.reason,
            LifecycleReason::InvalidTransition,
            "repeated phase is denied"
        );
        assert!(
            !lifecycle.used_leases().is_empty(),
            "only the successful transition consumed the lease"
        );
    }

    #[test]
    fn denied_provider_scope_blocks_all_later_provider_phases() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = lifecycle();
        deny(&mut lifecycle, OperationScope::ProviderConnection);
        let lease = issue(OperationScope::ProviderConnection, &clock);
        let connect = lifecycle
            .advance(
                ConnectorState::Connect,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
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
                &clock,
                authority(),
            )
            .expect_err("the denied capability is never restored");
        let capture = lifecycle
            .advance(
                ConnectorState::Capture,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
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
            .advance(
                ConnectorState::Decode,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
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
                &clock,
                authority(),
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
            .advance(
                ConnectorState::Validate,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
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
            .advance(
                ConnectorState::Archive,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
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
            .advance(
                ConnectorState::Publish,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
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
        lifecycle
            .quarantine(&clock, authority())
            .expect("quarantine follows validate");
        let lease = issue(OperationScope::Publication, &clock);
        let error = lifecycle
            .advance(
                ConnectorState::Archive,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("quarantine cannot archive");
        assert_eq!(
            error.reason,
            LifecycleReason::InvalidTransition,
            "quarantine blocks the publication path"
        );
        lifecycle
            .close(&clock, authority())
            .expect("quarantine closes");
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
            .quarantine(&clock, authority())
            .expect("cleanup is allowed after denial");
        lifecycle
            .close(&clock, authority())
            .expect("closing is allowed after denial");
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
            .advance(
                ConnectorState::Publish,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
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
            lifecycle
                .revoke(scope, &clock, authority())
                .expect("revocation records an authenticated decision");
            let lease = issue(scope, &clock);
            let denied = lifecycle
                .advance(
                    advanced_target(phase),
                    &lease,
                    &subject(),
                    &clock,
                    authority(),
                    &AtomicIdempotency::new(),
                )
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
                .quarantine(&clock, authority())
                .expect("quarantine is reachable from every nonterminal phase");
            assert_eq!(
                lifecycle.state(),
                ConnectorState::Quarantine,
                "abort lands in quarantine"
            );
            lifecycle
                .close(&clock, authority())
                .expect("quarantine then closes");
            let replayed = ConnectorLifecycle::replay_state(lifecycle.log(), subject())
                .expect("the decision log replays");
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
        let replayed = ConnectorLifecycle::replay_state(lifecycle.log(), subject())
            .expect("the full log replays");
        assert_eq!(replayed, lifecycle, "state replay reconstructs the machine");
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
        let error = ConnectorLifecycle::replay_state(&records, subject())
            .expect_err("tampered sequence is rejected");
        assert_eq!(
            error.reason,
            LifecycleReason::LogMismatch,
            "stable replay reason"
        );
        let mut records = lifecycle.log().to_vec();
        records[1].to = ConnectorState::Capture;
        let error = ConnectorLifecycle::replay_state(&records, subject())
            .expect_err("tampered transition is rejected");
        assert_eq!(
            error.reason,
            LifecycleReason::LogMismatch,
            "stable replay reason"
        );
        let mut records = lifecycle.log().to_vec();
        records[0].scope = Some(OperationScope::Retention);
        let error = ConnectorLifecycle::replay_state(&records, subject())
            .expect_err("tampered scope is rejected");
        assert_eq!(
            error.reason,
            LifecycleReason::LogMismatch,
            "stable replay reason"
        );
        let mut records = lifecycle.log().to_vec();
        records[1].lease_digest = Some("tampered".to_owned());
        let error = ConnectorLifecycle::replay_state(&records, subject())
            .expect_err("a tampered lease is rejected");
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
            .advance(
                ConnectorState::Validate,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("validate is blocked by the denial");
        let mut replayed = ConnectorLifecycle::replay_state(lifecycle.log(), subject())
            .expect("a denied log replays faithfully");
        assert_eq!(
            replayed, lifecycle,
            "state replay mirrors the denied machine"
        );
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
                &clock,
                authority(),
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
        for evidence in [None, Some(&unknown), Some(&expired), Some(&out_of_scope)] {
            let mut lifecycle = through_phase(ConnectorState::Capture, &clock);
            lifecycle
                .preflight(evidence, &request(scope), &clock, authority())
                .expect_err("each non-admitted evidence kind denies");
            assert!(
                lifecycle.scope_denied(scope),
                "each denial marks the operation scope denied"
            );
            let lease = issue(scope, &clock);
            let denied = lifecycle
                .advance(
                    ConnectorState::Decode,
                    &lease,
                    &subject(),
                    &clock,
                    authority(),
                    &AtomicIdempotency::new(),
                )
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
        assert!(
            is_authority_digest(&record.authority_mac),
            "every decision carries authority evidence"
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
            .research_use(
                &research_lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("research use stays denied after a denial");
        admit(&mut lifecycle, OperationScope::Retention, &clock);
        advance(&mut lifecycle, ConnectorState::Validate, &clock);
        advance(&mut lifecycle, ConnectorState::Archive, &clock);
        lifecycle
            .quarantine(&clock, authority())
            .expect("quarantine follows archive");
        lifecycle
            .close(&clock, authority())
            .expect("quarantine closes");

        let replayed = ConnectorLifecycle::replay_state(lifecycle.log(), subject())
            .expect("the mixed log replays");
        assert_eq!(
            replayed, lifecycle,
            "state replay rebuilds the exact machine"
        );
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
        let mut lifecycle = lifecycle();
        let lease = issue(OperationScope::ResearchUse, &clock);
        lifecycle
            .research_use(
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("research use is denied without its own scope");
        admit(&mut lifecycle, OperationScope::ResearchUse, &clock);
        lifecycle
            .research_use(
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
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
            clock.set(OBSERVED_AT);
            let target = advanced_target(phase);
            let scope = required_scope_for_transition(phase, target)
                .expect("every advanced target has a scope");
            let mut lifecycle = through_phase(phase, &clock);
            admit(&mut lifecycle, scope, &clock);
            let lease = issue(scope, &clock);
            clock.set(VALID_UNTIL);
            let expired = lifecycle
                .advance(
                    target,
                    &lease,
                    &subject(),
                    &clock,
                    authority(),
                    &AtomicIdempotency::new(),
                )
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
            // Time never moves backwards: issue a fresh lease for the later
            // observation instead of rewinding the trusted clock.
            clock.set(VALID_UNTIL + 1);
            let fresh = issue_valid(scope, VALID_UNTIL, VALID_UNTIL + 1_000, &clock);
            admit_valid(
                &mut lifecycle,
                scope,
                VALID_UNTIL,
                VALID_UNTIL + 1_000,
                &clock,
            );
            lifecycle
                .advance(
                    target,
                    &fresh,
                    &subject(),
                    &clock,
                    authority(),
                    &AtomicIdempotency::new(),
                )
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
            lifecycle
                .revoke(scope, &clock, authority())
                .expect("revocation records an authenticated decision");
            let denied = lifecycle
                .advance(
                    target,
                    &lease,
                    &subject(),
                    &clock,
                    authority(),
                    &AtomicIdempotency::new(),
                )
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
            let replayed = ConnectorLifecycle::replay_state(lifecycle.log(), subject())
                .expect("the revocation log replays");
            assert_eq!(
                replayed, lifecycle,
                "state replay reproduces the revocation"
            );
        }
    }

    #[test]
    fn long_lived_session_cannot_reuse_a_stale_lease() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_phase(ConnectorState::Validate, &clock);
        let retention = issue(OperationScope::Retention, &clock);
        admit(&mut lifecycle, OperationScope::Retention, &clock);
        lifecycle
            .advance(
                ConnectorState::Archive,
                &retention,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect("the first archive lease is current");

        // A long-lived session crosses the original lease's validity interval.
        clock.set(LONG_SESSION_LATER);
        admit_valid(
            &mut lifecycle,
            OperationScope::Publication,
            LONG_SESSION_LATER - 1,
            LONG_SESSION_LATER + 1_000,
            &clock,
        );
        let error = lifecycle
            .advance(
                ConnectorState::Publish,
                &retention,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
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
            .advance(
                ConnectorState::Publish,
                &fresh,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
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
    fn forged_or_modified_leases_are_rejected() {
        let clock = FixedClock::at(OBSERVED_AT);
        let scope = OperationScope::ProviderConnection;
        let mut lifecycle = lifecycle();
        admit(&mut lifecycle, scope, &clock);
        let mut tampered = issue(scope, &clock);
        tampered.authority_digest = "b".repeat(64);
        assert!(
            tampered.is_current_at(&observation(&clock)),
            "a time-only check is not an authority check"
        );
        let error = lifecycle
            .advance(
                ConnectorState::Connect,
                &tampered,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("a modified lease cannot authorise a transition");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "modification fails closed"
        );
        let unconfigured = KeyedLeaseAuthority::unconfigured();
        let error = evaluate_preflight(
            Some(&valid_evidence(scope)),
            &request(scope),
            &observation(&clock),
            &unconfigured,
        )
        .expect_err("an authority without a key cannot issue a lease");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "production authority fails closed"
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
        let mut lifecycle = lifecycle();
        let lease = issue(OperationScope::ProviderConnection, &clock);
        admit(&mut lifecycle, OperationScope::ProviderConnection, &clock);
        let store = AtomicIdempotency::new();
        lifecycle
            .advance(
                ConnectorState::Connect,
                &lease,
                &subject(),
                &clock,
                authority(),
                &store,
            )
            .expect("the lease authorises connect");
        let error = lifecycle
            .advance(
                ConnectorState::Discover,
                &lease,
                &subject(),
                &clock,
                authority(),
                &store,
            )
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

    #[test]
    fn session_requires_a_complete_subject() {
        let incomplete = LeaseSubject {
            instrument_ref: String::new(),
            ..subject()
        };
        ConnectorLifecycle::new(incomplete).expect_err("an unbound session cannot start");
        assert_eq!(
            lifecycle().subject(),
            &subject(),
            "a complete session keeps its immutable subject"
        );
    }

    #[test]
    fn cross_source_lease_substitution_is_denied() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = lifecycle();
        let scope = OperationScope::ProviderConnection;
        admit(&mut lifecycle, scope, &clock);
        let lease = issue(scope, &clock);
        let error = lifecycle
            .advance(
                ConnectorState::Connect,
                &lease,
                &other_source(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("a connection lease cannot be used for another source");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
        assert!(error.detail.contains("subject"), "the binding is named");
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Preflight,
            "substitution never changed the phase"
        );
        // A lease issued for source A cannot capture source B either.
        admit(&mut lifecycle, OperationScope::LocalCapture, &clock);
        let capture = issue(OperationScope::LocalCapture, &clock);
        let mut at_connect = through_subscribe(&clock);
        admit(&mut at_connect, OperationScope::LocalCapture, &clock);
        let error = at_connect
            .advance(
                ConnectorState::Capture,
                &capture,
                &other_source(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("a lease for source A cannot capture source B");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
        assert_eq!(
            at_connect.state(),
            ConnectorState::Subscribe,
            "cross-source capture never advanced the phase"
        );
    }

    #[test]
    fn cross_instrument_lease_substitution_is_denied() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_subscribe(&clock);
        let scope = OperationScope::LocalCapture;
        admit(&mut lifecycle, scope, &clock);
        let lease = issue(scope, &clock);
        let error = lifecycle
            .advance(
                ConnectorState::Capture,
                &lease,
                &other_instrument(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("a lease for one instrument cannot capture another");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Subscribe,
            "cross-instrument substitution never advanced the phase"
        );
    }

    #[test]
    fn rollback_of_trusted_time_fails_closed() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = lifecycle();
        admit(&mut lifecycle, OperationScope::ProviderConnection, &clock);
        let lease = issue(OperationScope::ProviderConnection, &clock);
        lifecycle
            .advance(
                ConnectorState::Connect,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect("the trusted observation is fresh");
        clock.set(OBSERVED_AT - 1);
        let error = lifecycle
            .preflight(
                Some(&valid_evidence(OperationScope::LocalCapture)),
                &request(OperationScope::LocalCapture),
                &clock,
                authority(),
            )
            .expect_err("a wall-clock rollback is denied");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "rollback fails closed"
        );
        assert!(
            error.detail.contains("rolled back"),
            "the rollback is named"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Connect,
            "rollback never changes the phase"
        );
    }

    #[test]
    fn concurrent_duplicate_claims_only_one_commits() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = lifecycle();
        admit(&mut lifecycle, OperationScope::ProviderConnection, &clock);
        let lease = issue(OperationScope::ProviderConnection, &clock);
        let shared = Arc::new(AtomicIdempotency::new());
        let shared_clock = Arc::new(FixedClock::at(OBSERVED_AT));
        let machine = Arc::new(Mutex::new(lifecycle));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let machine = Arc::clone(&machine);
            let claims = Arc::clone(&shared);
            let worker_clock = Arc::clone(&shared_clock);
            let attempted_lease = lease.clone();
            handles.push(thread::spawn(move || {
                let mut guard = machine.lock().expect("machine lock is available");
                guard.advance(
                    ConnectorState::Connect,
                    &attempted_lease,
                    &subject(),
                    &*worker_clock,
                    authority(),
                    &claims,
                )
            }));
        }
        let successes = handles
            .into_iter()
            .map(|handle| handle.join().expect("worker joined").is_ok())
            .filter(|committed| *committed)
            .count();
        assert_eq!(successes, 1, "exactly one duplicate attempt commits");
        assert_eq!(
            machine.lock().expect("machine lock is available").state(),
            ConnectorState::Connect,
            "the committed attempt advanced exactly once"
        );
    }

    #[test]
    fn restart_does_not_revive_a_consumed_lease() {
        let clock = FixedClock::at(OBSERVED_AT);
        let shared = AtomicIdempotency::new();
        let scope = OperationScope::ProviderConnection;
        let lease = issue(scope, &clock);
        let mut first = lifecycle();
        admit(&mut first, scope, &clock);
        first
            .advance(
                ConnectorState::Connect,
                &lease,
                &subject(),
                &clock,
                authority(),
                &shared,
            )
            .expect("the lease authorises connect before restart");
        let mut restarted = lifecycle();
        admit(&mut restarted, scope, &clock);
        let error = restarted
            .advance(
                ConnectorState::Connect,
                &lease,
                &subject(),
                &clock,
                authority(),
                &shared,
            )
            .expect_err("a restart cannot revive a claimed lease");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
        assert_eq!(
            restarted.state(),
            ConnectorState::Preflight,
            "the restarted machine did not move"
        );
    }

    #[test]
    fn research_use_is_one_shot_and_records_its_decision() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = lifecycle();
        admit(&mut lifecycle, OperationScope::ResearchUse, &clock);
        let lease = issue(OperationScope::ResearchUse, &clock);
        let store = AtomicIdempotency::new();
        lifecycle
            .research_use(&lease, &subject(), &clock, authority(), &store)
            .expect("the first research use consumes the lease");
        let error = lifecycle
            .research_use(&lease, &subject(), &clock, authority(), &store)
            .expect_err("a second research use is denied");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
        let records: Vec<_> = lifecycle
            .log()
            .iter()
            .filter(|record| record.kind == DecisionKind::ResearchUsed)
            .collect();
        assert_eq!(
            records.len(),
            1,
            "exactly one research decision is recorded"
        );
        assert_eq!(
            records[0].lease_digest.as_deref(),
            Some(lease.signature()),
            "the decision is bound to the consumed lease"
        );
        let replayed = ConnectorLifecycle::replay_state(lifecycle.log(), subject())
            .expect("the one-shot log replays");
        assert_eq!(replayed, lifecycle, "state replay mirrors one-shot use");
    }

    #[test]
    fn unpermitted_research_use_is_denied() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = lifecycle();
        admit(&mut lifecycle, OperationScope::ResearchUse, &clock);
        let bound_terms = terms_with_uses(&["publication"]);
        let evidence = evidence_with_terms(OperationScope::ResearchUse, &bound_terms);
        let bound_request = request_with_terms(OperationScope::ResearchUse, &bound_terms);
        let lease = evaluate(&evidence, &bound_request, &clock)
            .expect("a signed lease can carry an unpermitted use");
        let error = lifecycle
            .research_use(
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("research use is not a permitted use of this lease");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
        assert!(error.detail.contains("permit"), "the use policy is named");
    }

    #[test]
    fn archive_beyond_retention_maximum_is_denied() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_phase(ConnectorState::Validate, &clock);
        admit(&mut lifecycle, OperationScope::Retention, &clock);
        let bound_terms = LeaseTerms {
            retention_until_utc_ns: OBSERVED_AT,
            permitted_uses: terms().permitted_uses,
        };
        let evidence = evidence_with_terms(OperationScope::Retention, &bound_terms);
        let bound_request = request_with_terms(OperationScope::Retention, &bound_terms);
        // Issuance happens before the maximum; the operation happens at it.
        let issuance_clock = FixedClock::at(OBSERVED_AT - 1);
        let lease = evaluate(&evidence, &bound_request, &issuance_clock)
            .expect("a signed lease can be issued before its retention maximum");
        let error = lifecycle
            .advance(
                ConnectorState::Archive,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("an elapsed retention maximum denies archive");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
        assert!(
            error.detail.contains("retention"),
            "the retention boundary is named"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Validate,
            "no archive happened"
        );
    }

    #[test]
    fn zero_retention_is_denied() {
        let clock = FixedClock::at(OBSERVED_AT);
        let scope = OperationScope::Retention;
        let zero = LeaseTerms {
            retention_until_utc_ns: 0,
            permitted_uses: terms().permitted_uses,
        };
        let error = evaluate_preflight(
            Some(&evidence_with_terms(scope, &zero)),
            &request_with_terms(scope, &zero),
            &observation(&clock),
            authority(),
        )
        .expect_err("a missing retention maximum cannot issue a lease");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
        let mut lifecycle = through_phase(ConnectorState::Validate, &clock);
        admit(&mut lifecycle, scope, &clock);
        let mut lease = issue(scope, &clock);
        lease.terms.retention_until_utc_ns = 0;
        let error = lifecycle
            .advance(
                ConnectorState::Archive,
                &lease,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("a zero retention maximum denies the operation");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
        assert_eq!(lifecycle.state(), ConnectorState::Validate);
    }

    #[test]
    fn verify_audit_log_requires_key_and_detects_tampering() {
        let clock = FixedClock::at(OBSERVED_AT);
        let lifecycle = through_published(&clock);
        let records = lifecycle.log();
        let verified = verify_audit_log(records, subject(), authority())
            .expect("an authenticated, intact log verifies");
        assert_eq!(verified.record_count, records.len());
        assert_eq!(verified.final_state, ConnectorState::Publish);
        assert_eq!(verified.subject, subject());
        let unconfigured = KeyedLeaseAuthority::unconfigured();
        let error = verify_audit_log(records, subject(), &unconfigured)
            .expect_err("verification fails closed without a key");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
        let mut tampered = records.to_vec();
        tampered[1].reason_code = Some(LifecycleReason::InvalidTransition);
        let error = verify_audit_log(&tampered, subject(), authority())
            .expect_err("a tampered decision breaks the MAC chain");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
        let mut tampered = records.to_vec();
        tampered[0].authority_mac = "a".repeat(64);
        let error = verify_audit_log(&tampered, subject(), authority())
            .expect_err("a replaced authority MAC is rejected");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
        let error = verify_audit_log(&[], subject(), authority())
            .expect_err("an empty log has no authority evidence");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED);
    }

    #[test]
    fn state_replay_alone_is_not_an_authority_result() {
        let clock = FixedClock::at(OBSERVED_AT);
        let lifecycle = through_published(&clock);
        let state = ConnectorLifecycle::replay_state(lifecycle.log(), subject())
            .expect("state replay succeeds without any authority key");
        assert_eq!(state.state(), ConnectorState::Publish);
        let unconfigured = KeyedLeaseAuthority::unconfigured();
        assert!(
            verify_audit_log(lifecycle.log(), subject(), &unconfigured).is_err(),
            "state replay never proves authority"
        );
    }

    #[test]
    fn publication_revocation_marks_artifact_inactive_and_blocks_reuse() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_published(&clock);
        assert!(
            lifecycle.artifact_active(),
            "publication activates the artifact"
        );
        lifecycle
            .revoke_publication(&clock, authority())
            .expect("revocation is always available after publication");
        assert_eq!(lifecycle.state(), ConnectorState::Revoked);
        assert!(
            !lifecycle.artifact_active(),
            "revocation never leaves an unauthorised artifact active"
        );
        let last = lifecycle.log().last().expect("a revocation record exists");
        assert_eq!(last.kind, DecisionKind::PublicationRevoked);
        assert_eq!(last.to, ConnectorState::Revoked);
        let error = lifecycle
            .revoke_publication(&clock, authority())
            .expect_err("a second revocation has no active artifact");
        assert_eq!(
            error.reason_code(),
            "INVALID_TRANSITION",
            "reuse of revocation is denied"
        );
        let publication = issue(OperationScope::Publication, &clock);
        let error = lifecycle
            .advance(
                ConnectorState::Publish,
                &publication,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("a revoked artifact cannot be published again");
        assert_eq!(error.reason_code(), "INVALID_TRANSITION");
        let replayed = ConnectorLifecycle::replay_state(lifecycle.log(), subject())
            .expect("the revocation log replays");
        assert_eq!(replayed, lifecycle, "state replay mirrors revocation");
        lifecycle
            .close(&clock, authority())
            .expect("a revoked artifact can be closed");
    }

    #[test]
    fn publication_retraction_marks_artifact_inactive_and_blocks_reuse() {
        let clock = FixedClock::at(OBSERVED_AT);
        let mut lifecycle = through_published(&clock);
        lifecycle
            .retract_publication(&clock, authority())
            .expect("retraction is available after publication");
        assert_eq!(lifecycle.state(), ConnectorState::Retracted);
        assert!(
            !lifecycle.artifact_active(),
            "retraction marks the artifact inactive"
        );
        let last = lifecycle.log().last().expect("a retraction record exists");
        assert_eq!(last.kind, DecisionKind::PublicationRetracted);
        let error = lifecycle
            .retract_publication(&clock, authority())
            .expect_err("a second retraction is denied");
        assert_eq!(error.reason_code(), "INVALID_TRANSITION");
        let error = lifecycle
            .revoke_publication(&clock, authority())
            .expect_err("a retracted artifact cannot be revoked");
        assert_eq!(error.reason_code(), "INVALID_TRANSITION");
        let publication = issue(OperationScope::Publication, &clock);
        let error = lifecycle
            .advance(
                ConnectorState::Publish,
                &publication,
                &subject(),
                &clock,
                authority(),
                &AtomicIdempotency::new(),
            )
            .expect_err("a retracted artifact cannot be published again");
        assert_eq!(error.reason_code(), "INVALID_TRANSITION");
        let replayed = ConnectorLifecycle::replay_state(lifecycle.log(), subject())
            .expect("the retraction log replays");
        assert_eq!(replayed, lifecycle, "state replay mirrors retraction");
    }
}
