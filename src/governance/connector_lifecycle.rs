// SPDX-License-Identifier: Apache-2.0
//! Transport-independent connector lifecycle state machine.
//!
//! The machine records decisions about a sequence of phases:
//! `Preflight` → `Connect` → `Discover` → `Subscribe` → `Capture` → `Decode` →
//! `Validate` → `Archive` → `Publish`, with `Quarantine` and `Closed` as
//! terminal branches. There is no concrete provider, socket, clock, storage
//! or market payload in this module. Every input is a caller-supplied value
//! and every output is a typed decision plus a replayable log.
//!
//! Rights are bound to *operations*, never to one global boolean. The six
//! operation scopes are provider connection/collection, local capture/storage,
//! decoding/transformation, retention, publication/downstream use and research
//! use. Each phase transition requires the scope for that operation to be
//! currently admitted and not denied. A denial marks the scope denied: every
//! later transition needing that capability stays blocked, an earlier
//! admission is never restored, and only cleanup (`Quarantine`/`Closed`) is
//! still allowed. Cleanup never publishes, extends retention or admits data.
//!
//! Preflight is a local decision over caller-supplied evidence. This module
//! does not grant rights or issue entitlements: it fails closed with
//! [`RIGHTS_NOT_ADMITTED`] when evidence is absent, incomplete, bound to
//! another operation, unknown, expired, out of scope or already denied.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;

/// Exact denial code for rights evidence that is unknown, missing, expired,
/// out of scope or already denied.
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
    #[must_use]
    pub const fn allows(self, target: Self) -> bool {
        match self {
            Self::Preflight => matches!(target, Self::Connect),
            Self::Connect => matches!(target, Self::Discover),
            Self::Discover => matches!(target, Self::Subscribe),
            Self::Subscribe => matches!(target, Self::Capture),
            Self::Capture => matches!(target, Self::Decode | Self::Quarantine),
            Self::Decode => matches!(target, Self::Validate | Self::Quarantine),
            Self::Validate => matches!(target, Self::Archive | Self::Quarantine),
            Self::Archive => matches!(target, Self::Publish | Self::Quarantine),
            Self::Publish => matches!(target, Self::Closed),
            Self::Quarantine => matches!(target, Self::Closed),
            Self::Closed => false,
        }
    }
}

/// Operation-scoped rights capability. A phase may only advance when the
/// scope for its operation is currently admitted and not denied.
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

/// State of caller-supplied, operation-level rights evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RightsEvidenceState {
    Admitted,
    Unknown,
    Expired,
    OutOfScope,
}

/// The operation the caller asks to perform and the scope it needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRequest {
    pub operation_ref: String,
    pub required_scope: OperationScope,
    /// Caller-supplied observation time; no clock is read here.
    pub observed_at_utc_ns: u64,
}

/// Caller-supplied rights evidence bound to one operation and a scope set.
///
/// Presence of this value is not a grant. Every decision is derived from the
/// declared state, scope set and expiry, and all non-admitted cases deny.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRightsEvidence {
    pub evidence_ref: String,
    pub operation_ref: String,
    pub state: RightsEvidenceState,
    pub granted_scopes: BTreeSet<OperationScope>,
    pub valid_until_utc_ns: Option<u64>,
}

/// Kind of a recorded decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// Preflight accepted the caller-supplied evidence for one scope.
    Admitted,
    /// Preflight rejected the caller-supplied evidence for one scope.
    PreflightDenied,
    /// A permitted phase transition was applied.
    Advanced,
    /// A phase transition was denied; the phase did not change.
    Denied,
}

/// One immutable decision record. Sequence numbers start at one and are
/// consecutive in a log. `to` names the requested target even when a
/// transition is denied, so replay can reproduce the denial exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedDecision {
    pub sequence: u64,
    pub from: ConnectorState,
    pub to: ConnectorState,
    pub kind: DecisionKind,
    pub reason_code: Option<LifecycleReason>,
    pub scope: Option<OperationScope>,
}

/// Pure preflight gate for caller-supplied rights evidence.
///
/// # Errors
/// Returns [`LifecycleReason::RightsNotAdmitted`] when the evidence is absent,
/// incomplete, bound to another operation, unknown, expired, out of scope or
/// has no declared expiry.
pub fn evaluate_preflight(
    evidence: Option<&OperationRightsEvidence>,
    request: &OperationRequest,
) -> Result<(), LifecycleError> {
    let Some(evidence) = evidence else {
        return Err(rights_denial("rights evidence is missing"));
    };
    if evidence.evidence_ref.trim().is_empty()
        || request.operation_ref.trim().is_empty()
        || request.required_scope.as_str().is_empty()
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
    if valid_until <= request.observed_at_utc_ns {
        return Err(rights_denial(
            "rights evidence expired at the observed time",
        ));
    }
    Ok(())
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

fn scope_allows(
    admitted: &BTreeSet<OperationScope>,
    denied: &BTreeSet<OperationScope>,
    scope: OperationScope,
) -> bool {
    admitted.contains(&scope) && !denied.contains(&scope)
}

/// Pure transition decision. Phase order is checked first, then the operation
/// scope bound to the requested transition.
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

/// Lifecycle state, operation-scoped rights and its recorded decisions.
/// No I/O is performed by any method on this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorLifecycle {
    state: ConnectorState,
    admitted_scopes: BTreeSet<OperationScope>,
    denied_scopes: BTreeSet<OperationScope>,
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

    /// Explicit gate for research use, which has no phase in this machine but
    /// is still an operation-scoped capability.
    ///
    /// # Errors
    /// Returns [`LifecycleReason::RightsNotAdmitted`] unless research use is
    /// currently admitted and not denied.
    pub fn research_use(&self) -> Result<(), LifecycleError> {
        if self.scope_admitted(OperationScope::ResearchUse) {
            Ok(())
        } else {
            Err(rights_denial("research use is not currently admitted"))
        }
    }

    /// Consume operation-level rights evidence for one scope and record the
    /// decision.
    ///
    /// An admission enables only the requested scope. A denial revokes that
    /// scope permanently: later preflights for it deny instead of restoring an
    /// earlier admission. The phase never moves, and the log record names the
    /// phase where the decision actually ran.
    ///
    /// # Errors
    /// Returns the fail-closed denial from [`evaluate_preflight`], or a denial
    /// when the scope was previously denied.
    pub fn preflight(
        &mut self,
        evidence: Option<&OperationRightsEvidence>,
        request: &OperationRequest,
    ) -> Result<(), LifecycleError> {
        let scope = request.required_scope;
        let outcome = if self.denied_scopes.contains(&scope) {
            Err(rights_denial(format!(
                "scope {} was denied earlier and cannot be restored",
                scope.as_str()
            )))
        } else {
            evaluate_preflight(evidence, request)
        };
        let phase = self.state;
        match &outcome {
            Ok(()) => {
                self.admitted_scopes.insert(scope);
                self.record(phase, phase, DecisionKind::Admitted, None, Some(scope));
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
                );
            }
        }
        outcome
    }

    /// Request a phase transition and record the decision.
    ///
    /// A denial revokes the scope that would have been needed, so all later
    /// transitions requiring that capability stay blocked. Cleanup branches
    /// require no scope and remain usable.
    ///
    /// # Errors
    /// Returns the fail-closed denial from [`decide_transition`].
    pub fn transition(&mut self, target: ConnectorState) -> Result<(), LifecycleError> {
        let from = self.state;
        let scope = required_scope_for_transition(from, target);
        let outcome = decide_transition(from, target, &self.admitted_scopes, &self.denied_scopes);
        match &outcome {
            Ok(()) => {
                self.record(from, target, DecisionKind::Advanced, None, scope);
                self.state = target;
            }
            Err(error) => {
                if let Some(scope) = scope {
                    self.admitted_scopes.remove(&scope);
                    self.denied_scopes.insert(scope);
                }
                self.record(
                    from,
                    target,
                    DecisionKind::Denied,
                    Some(error.reason),
                    scope,
                );
            }
        }
        outcome
    }

    /// Branch to `Quarantine` from any processing phase. Cleanup needs no
    /// capability and is always allowed.
    ///
    /// # Errors
    /// Returns the fail-closed denial from [`Self::transition`].
    pub fn quarantine(&mut self) -> Result<(), LifecycleError> {
        self.transition(ConnectorState::Quarantine)
    }

    /// Close the machine from `Publish` or `Quarantine`. Cleanup needs no
    /// capability and is always allowed.
    ///
    /// # Errors
    /// Returns the fail-closed denial from [`Self::transition`].
    pub fn close(&mut self) -> Result<(), LifecycleError> {
        self.transition(ConnectorState::Closed)
    }

    /// Reconstruct a machine from a recorded decision log.
    ///
    /// The log is treated as untrusted input: consecutive sequence numbers,
    /// from-state agreement, legal advanced transitions, scope binding and
    /// denied decisions that leave the phase unchanged are all re-verified. A
    /// denied scope is reproduced as denied, so a recorded later admission of
    /// that same scope fails closed.
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
                    if record.to != record.from || record.reason_code.is_some() {
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
                    if record.to != record.from {
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
                    // Evidence itself is not stored in the log, so replay
                    // cannot re-evaluate it. What it can verify is the effect:
                    // the scope is revoked and stays denied, while a later
                    // admission of that same scope would fail closed.
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
                    if record.scope != required_scope_for_transition(record.from, record.to) {
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
    ) {
        let sequence = u64::try_from(self.log.len() + 1).unwrap_or(u64::MAX);
        self.log.push(RecordedDecision {
            sequence,
            from,
            to,
            kind,
            reason_code,
            scope,
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

    const OBSERVED_AT: u64 = 1_700_000_000_000_000_000;
    const VALID_UNTIL: u64 = 1_700_000_000_100_000_000;

    fn request(scope: OperationScope) -> OperationRequest {
        OperationRequest {
            operation_ref: format!("operation-{}", scope.as_str()),
            required_scope: scope,
            observed_at_utc_ns: OBSERVED_AT,
        }
    }

    fn admitted_evidence(scope: OperationScope) -> OperationRightsEvidence {
        OperationRightsEvidence {
            evidence_ref: format!("evidence-{}", scope.as_str()),
            operation_ref: format!("operation-{}", scope.as_str()),
            state: RightsEvidenceState::Admitted,
            granted_scopes: BTreeSet::from([scope]),
            valid_until_utc_ns: Some(VALID_UNTIL),
        }
    }

    fn admit(lifecycle: &mut ConnectorLifecycle, scope: OperationScope) {
        lifecycle
            .preflight(Some(&admitted_evidence(scope)), &request(scope))
            .expect("admitted evidence passes preflight for the requested scope");
    }

    fn deny(lifecycle: &mut ConnectorLifecycle, scope: OperationScope) {
        let mut evidence = admitted_evidence(scope);
        evidence.state = RightsEvidenceState::Unknown;
        lifecycle
            .preflight(Some(&evidence), &request(scope))
            .expect_err("unknown evidence denies the requested scope");
    }

    fn advance(lifecycle: &mut ConnectorLifecycle, target: ConnectorState) {
        if let Some(scope) = required_scope_for_transition(lifecycle.state(), target)
            && !lifecycle.scope_admitted(scope)
        {
            admit(lifecycle, scope);
        }
        lifecycle
            .transition(target)
            .expect("an ordered transition with an admitted scope succeeds");
    }

    fn through_subscribe() -> ConnectorLifecycle {
        let mut lifecycle = ConnectorLifecycle::new();
        for target in [
            ConnectorState::Connect,
            ConnectorState::Discover,
            ConnectorState::Subscribe,
        ] {
            advance(&mut lifecycle, target);
        }
        lifecycle
    }

    fn through_phase(target: ConnectorState) -> ConnectorLifecycle {
        let mut lifecycle = through_subscribe();
        for phase in [
            ConnectorState::Capture,
            ConnectorState::Decode,
            ConnectorState::Validate,
            ConnectorState::Archive,
        ] {
            advance(&mut lifecycle, phase);
            if phase == target {
                break;
            }
        }
        lifecycle
    }

    #[test]
    fn unknown_rights_are_denied_with_the_stable_code() {
        let scope = OperationScope::ProviderConnection;
        let mut evidence = admitted_evidence(scope);
        evidence.state = RightsEvidenceState::Unknown;
        let mut lifecycle = ConnectorLifecycle::new();
        let error = lifecycle
            .preflight(Some(&evidence), &request(scope))
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
        let blocked = lifecycle
            .transition(ConnectorState::Connect)
            .expect_err("a denied connection scope blocks connect");
        assert_eq!(
            blocked.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "the operation scope is enforced at connect"
        );
    }

    #[test]
    fn missing_expired_and_out_of_scope_rights_are_denied() {
        let scope = OperationScope::ProviderConnection;
        let error =
            evaluate_preflight(None, &request(scope)).expect_err("missing evidence is denied");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "missing evidence code"
        );
        let mut expired = admitted_evidence(scope);
        expired.valid_until_utc_ns = Some(OBSERVED_AT);
        let error = evaluate_preflight(Some(&expired), &request(scope))
            .expect_err("expired evidence is denied");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED, "expiry code");
        let mut out_of_scope = admitted_evidence(scope);
        out_of_scope.state = RightsEvidenceState::OutOfScope;
        let error = evaluate_preflight(Some(&out_of_scope), &request(scope))
            .expect_err("out-of-scope evidence is denied");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED, "scope-state code");
    }

    #[test]
    fn missing_operation_scope_is_denied() {
        let scope = OperationScope::LocalCapture;
        let mut evidence = admitted_evidence(scope);
        evidence.granted_scopes = BTreeSet::from([OperationScope::Retention]);
        let error = evaluate_preflight(Some(&evidence), &request(scope))
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
        let mut lifecycle = ConnectorLifecycle::new();
        admit(&mut lifecycle, OperationScope::ProviderConnection);
        let error = lifecycle
            .transition(ConnectorState::Capture)
            .expect_err("capture cannot skip phases");
        assert_eq!(
            error.reason_code(),
            "INVALID_TRANSITION",
            "out-of-order transition has a stable code"
        );
        let error = lifecycle
            .transition(ConnectorState::Discover)
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
            .transition(ConnectorState::Connect)
            .expect("connect follows preflight");
        let error = lifecycle
            .transition(ConnectorState::Connect)
            .expect_err("a repeated phase is not a transition");
        assert_eq!(
            error.reason,
            LifecycleReason::InvalidTransition,
            "repeated phase is denied"
        );
    }

    #[test]
    fn denied_provider_scope_blocks_all_later_provider_phases() {
        let mut lifecycle = ConnectorLifecycle::new();
        deny(&mut lifecycle, OperationScope::ProviderConnection);
        let connect = lifecycle
            .transition(ConnectorState::Connect)
            .expect_err("a denied connection capability blocks connect");
        assert_eq!(
            connect.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "connect is gated by the denied capability"
        );
        let scope = OperationScope::ProviderConnection;
        lifecycle
            .preflight(Some(&admitted_evidence(scope)), &request(scope))
            .expect_err("the denied capability is never restored");
        let capture = lifecycle
            .transition(ConnectorState::Capture)
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
        let mut lifecycle = through_phase(ConnectorState::Capture);
        deny(&mut lifecycle, OperationScope::DecodeTransform);
        let error = lifecycle
            .transition(ConnectorState::Decode)
            .expect_err("decode needs the denied transform scope");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "Capture->Decode is gated by the denied capability"
        );
        lifecycle
            .preflight(
                Some(&admitted_evidence(OperationScope::DecodeTransform)),
                &request(OperationScope::DecodeTransform),
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
        let mut lifecycle = through_phase(ConnectorState::Decode);
        deny(&mut lifecycle, OperationScope::DecodeTransform);
        let error = lifecycle
            .transition(ConnectorState::Validate)
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
        let mut lifecycle = through_phase(ConnectorState::Validate);
        deny(&mut lifecycle, OperationScope::Retention);
        let error = lifecycle
            .transition(ConnectorState::Archive)
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
        let mut lifecycle = through_phase(ConnectorState::Archive);
        deny(&mut lifecycle, OperationScope::Publication);
        let error = lifecycle
            .transition(ConnectorState::Publish)
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
        let mut lifecycle = through_phase(ConnectorState::Validate);
        lifecycle.quarantine().expect("quarantine follows validate");
        let error = lifecycle
            .transition(ConnectorState::Archive)
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
        let mut lifecycle = through_phase(ConnectorState::Archive);
        deny(&mut lifecycle, OperationScope::Publication);
        let mark = lifecycle.log().len();
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
                .all(|record| record.scope.is_none()),
            "cleanup grants no capability and admits no data"
        );
        assert!(
            lifecycle.log()[mark..]
                .iter()
                .all(|record| record.to != ConnectorState::Publish),
            "cleanup never publishes"
        );
        let error = lifecycle
            .transition(ConnectorState::Publish)
            .expect_err("a closed machine cannot publish");
        assert_eq!(
            error.reason,
            LifecycleReason::InvalidTransition,
            "publication is impossible during cleanup"
        );
    }

    #[test]
    fn recorded_log_replays_to_the_same_machine() {
        let mut lifecycle = through_subscribe();
        for target in [
            ConnectorState::Capture,
            ConnectorState::Decode,
            ConnectorState::Validate,
            ConnectorState::Archive,
            ConnectorState::Publish,
            ConnectorState::Closed,
        ] {
            advance(&mut lifecycle, target);
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
        let lifecycle = through_subscribe();
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
    }

    #[test]
    fn replay_reproduces_denial_and_never_restores_admission() {
        let mut lifecycle = through_phase(ConnectorState::Decode);
        deny(&mut lifecycle, OperationScope::DecodeTransform);
        lifecycle
            .transition(ConnectorState::Validate)
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
                Some(&admitted_evidence(OperationScope::DecodeTransform)),
                &request(OperationScope::DecodeTransform),
            )
            .expect_err("even a valid preflight cannot restore a denied scope");
        assert_eq!(
            replayed.state(),
            ConnectorState::Decode,
            "the replayed phase is unchanged"
        );
    }

    #[test]
    fn every_denial_kind_marks_the_scope_denied() {
        let scope = OperationScope::DecodeTransform;
        let mut unknown = admitted_evidence(scope);
        unknown.state = RightsEvidenceState::Unknown;
        let mut expired = admitted_evidence(scope);
        expired.valid_until_utc_ns = Some(OBSERVED_AT);
        let mut out_of_scope = admitted_evidence(scope);
        out_of_scope.state = RightsEvidenceState::OutOfScope;
        for evidence in [None, Some(&unknown), Some(&expired), Some(&out_of_scope)] {
            let mut lifecycle = through_phase(ConnectorState::Capture);
            lifecycle
                .preflight(evidence, &request(scope))
                .expect_err("each non-admitted evidence kind denies");
            assert!(
                lifecycle.scope_denied(scope),
                "each denial marks the operation scope denied"
            );
            let denied = lifecycle
                .transition(ConnectorState::Decode)
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
        let mut lifecycle = through_subscribe();
        let before = lifecycle.log().len();
        let scope = OperationScope::ResearchUse;
        admit(&mut lifecycle, scope);
        let record = &lifecycle.log()[before];
        assert_eq!(
            record.from,
            ConnectorState::Subscribe,
            "from is the actual phase"
        );
        assert_eq!(record.to, record.from, "preflight does not move a phase");
        assert_eq!(record.scope, Some(scope), "the operation scope is recorded");
    }

    #[test]
    fn replay_is_faithful_with_repeated_preflights_and_mixed_denials() {
        let mut lifecycle = through_subscribe();
        admit(&mut lifecycle, OperationScope::ResearchUse);
        admit(&mut lifecycle, OperationScope::LocalCapture);
        advance(&mut lifecycle, ConnectorState::Capture);
        admit(&mut lifecycle, OperationScope::DecodeTransform);
        advance(&mut lifecycle, ConnectorState::Decode);
        deny(&mut lifecycle, OperationScope::ResearchUse);
        lifecycle
            .research_use()
            .expect_err("research use stays denied after a denial");
        admit(&mut lifecycle, OperationScope::Retention);
        advance(&mut lifecycle, ConnectorState::Validate);
        advance(&mut lifecycle, ConnectorState::Archive);
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
        let mut lifecycle = ConnectorLifecycle::new();
        lifecycle
            .research_use()
            .expect_err("research use is denied without its own scope");
        admit(&mut lifecycle, OperationScope::ResearchUse);
        lifecycle.research_use().expect("research use is admitted");
        assert!(
            !lifecycle.scope_admitted(OperationScope::ProviderConnection),
            "research admission does not admit provider connection"
        );
        assert_eq!(OperationScope::ALL.len(), 6, "all six scopes are defined");
    }
}
