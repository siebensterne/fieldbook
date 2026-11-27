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
//! Preflight consumes operation-level rights evidence. This module does not
//! grant rights: it only checks the evidence supplied by the caller and fails
//! closed with [`RIGHTS_NOT_ADMITTED`] when that evidence is unknown, missing,
//! expired or out of scope. No capture transition is possible before a
//! successful preflight decision.

use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;

/// Exact denial code for rights evidence that is unknown, missing, expired or
/// out of scope.
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
    pub required_scope_ref: String,
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
    pub granted_scope_refs: BTreeSet<String>,
    pub valid_until_utc_ns: Option<u64>,
}

/// Kind of a recorded decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionKind {
    /// Preflight accepted the caller-supplied evidence.
    Admitted,
    /// A permitted phase transition was applied.
    Advanced,
    /// A denial; the phase did not change.
    Denied,
}

/// One immutable decision record. Sequence numbers start at one and are
/// consecutive in a log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedDecision {
    pub sequence: u64,
    pub from: ConnectorState,
    pub to: ConnectorState,
    pub kind: DecisionKind,
    pub reason_code: Option<LifecycleReason>,
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
        || request.required_scope_ref.trim().is_empty()
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
    if !evidence
        .granted_scope_refs
        .contains(&request.required_scope_ref)
    {
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

/// Pure transition decision. Capture is gated separately from phase order so
/// a caller cannot step straight into capture with admitted rights either.
///
/// # Errors
/// Returns [`LifecycleReason::CaptureBeforePreflight`] when capture is
/// requested without a successful preflight, or
/// [`LifecycleReason::InvalidTransition`] for an out-of-order request.
pub fn decide_transition(
    from: ConnectorState,
    to: ConnectorState,
    rights_admitted: bool,
) -> Result<(), LifecycleError> {
    if to == ConnectorState::Capture && !rights_admitted {
        return Err(LifecycleError::new(
            LifecycleReason::CaptureBeforePreflight,
            "capture requires a successful preflight",
        ));
    }
    if !from.allows(to) {
        return Err(LifecycleError::new(
            LifecycleReason::InvalidTransition,
            format!("{} cannot transition to {}", from.as_str(), to.as_str()),
        ));
    }
    Ok(())
}

/// Lifecycle state plus its recorded decisions. No I/O is performed by any
/// method on this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorLifecycle {
    state: ConnectorState,
    rights_admitted: bool,
    log: Vec<RecordedDecision>,
}

impl ConnectorLifecycle {
    /// New machine at `Preflight` with no rights decision and an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: ConnectorState::Preflight,
            rights_admitted: false,
            log: Vec::new(),
        }
    }

    /// Current phase.
    #[must_use]
    pub const fn state(&self) -> ConnectorState {
        self.state
    }

    /// Whether a successful preflight decision was recorded.
    #[must_use]
    pub const fn rights_admitted(&self) -> bool {
        self.rights_admitted
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

    /// Consume operation-level rights evidence and record the decision.
    ///
    /// A denial leaves `rights_admitted` false; it never advances the phase.
    ///
    /// # Errors
    /// Returns the fail-closed denial from [`evaluate_preflight`].
    pub fn preflight(
        &mut self,
        evidence: Option<&OperationRightsEvidence>,
        request: &OperationRequest,
    ) -> Result<(), LifecycleError> {
        let outcome = evaluate_preflight(evidence, request);
        let (kind, reason_code) = match &outcome {
            Ok(()) => (DecisionKind::Admitted, None),
            Err(error) => (DecisionKind::Denied, Some(error.reason)),
        };
        self.record(
            ConnectorState::Preflight,
            ConnectorState::Preflight,
            kind,
            reason_code,
        );
        if outcome.is_ok() {
            self.rights_admitted = true;
        }
        outcome
    }

    /// Request a phase transition and record the decision.
    ///
    /// # Errors
    /// Returns the fail-closed denial from [`decide_transition`].
    pub fn transition(&mut self, target: ConnectorState) -> Result<(), LifecycleError> {
        let from = self.state;
        let outcome = decide_transition(from, target, self.rights_admitted);
        let (kind, reason_code, to) = match &outcome {
            Ok(()) => (DecisionKind::Advanced, None, target),
            Err(error) => (DecisionKind::Denied, Some(error.reason), from),
        };
        self.record(from, to, kind, reason_code);
        if outcome.is_ok() {
            self.state = target;
        }
        outcome
    }

    /// Branch to `Quarantine` from a processing phase.
    ///
    /// # Errors
    /// Returns the fail-closed denial from [`Self::transition`].
    pub fn quarantine(&mut self) -> Result<(), LifecycleError> {
        self.transition(ConnectorState::Quarantine)
    }

    /// Close the machine from `Publish` or `Quarantine`.
    ///
    /// # Errors
    /// Returns the fail-closed denial from [`Self::transition`].
    pub fn close(&mut self) -> Result<(), LifecycleError> {
        self.transition(ConnectorState::Closed)
    }

    /// Reconstruct a machine from a recorded decision log.
    ///
    /// The log is treated as untrusted input: consecutive sequence numbers,
    /// from-state agreement, legal advanced transitions and denied records
    /// that leave the phase unchanged are all re-verified.
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
                    if record.to != ConnectorState::Preflight || lifecycle.rights_admitted {
                        return Err(Self::mismatch("preflight admission is not repeatable"));
                    }
                    lifecycle.rights_admitted = true;
                }
                DecisionKind::Advanced => {
                    if decide_transition(record.from, record.to, lifecycle.rights_admitted).is_err()
                    {
                        return Err(Self::mismatch("advanced transition is not legal"));
                    }
                    lifecycle.state = record.to;
                }
                DecisionKind::Denied => {
                    if record.to != record.from {
                        return Err(Self::mismatch("denied decision changed the phase"));
                    }
                    let Some(reason) = record.reason_code else {
                        return Err(Self::mismatch("denied decision has no reason"));
                    };
                    match reason {
                        LifecycleReason::RightsNotAdmitted => {
                            if record.from != ConnectorState::Preflight {
                                return Err(Self::mismatch("rights denial outside preflight"));
                            }
                        }
                        LifecycleReason::InvalidTransition
                        | LifecycleReason::CaptureBeforePreflight => {
                            if decide_transition(record.from, record.to, lifecycle.rights_admitted)
                                .is_ok()
                            {
                                return Err(Self::mismatch("denied transition is legal"));
                            }
                        }
                        LifecycleReason::LogMismatch => {
                            return Err(Self::mismatch("log reason cannot be a denial"));
                        }
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
    ) {
        let sequence = u64::try_from(self.log.len() + 1).unwrap_or(u64::MAX);
        self.log.push(RecordedDecision {
            sequence,
            from,
            to,
            kind,
            reason_code,
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

    fn request() -> OperationRequest {
        OperationRequest {
            operation_ref: "operation-capture".to_owned(),
            required_scope_ref: "scope-a".to_owned(),
            observed_at_utc_ns: 1_700_000_000_000_000_000,
        }
    }

    fn admitted_evidence() -> OperationRightsEvidence {
        OperationRightsEvidence {
            evidence_ref: "evidence-a".to_owned(),
            operation_ref: "operation-capture".to_owned(),
            state: RightsEvidenceState::Admitted,
            granted_scope_refs: BTreeSet::from(["scope-a".to_owned()]),
            valid_until_utc_ns: Some(1_700_000_000_100_000_000),
        }
    }

    fn through_subscribe() -> ConnectorLifecycle {
        let mut lifecycle = ConnectorLifecycle::new();
        lifecycle
            .preflight(Some(&admitted_evidence()), &request())
            .expect("admitted evidence passes preflight");
        for target in [
            ConnectorState::Connect,
            ConnectorState::Discover,
            ConnectorState::Subscribe,
        ] {
            lifecycle
                .transition(target)
                .expect("ordered transition succeeds");
        }
        lifecycle
    }

    #[test]
    fn unknown_rights_are_denied_with_the_stable_code() {
        let mut evidence = admitted_evidence();
        evidence.state = RightsEvidenceState::Unknown;
        let mut lifecycle = ConnectorLifecycle::new();
        let error = lifecycle
            .preflight(Some(&evidence), &request())
            .expect_err("unknown rights are denied");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "denial code is exact"
        );
        assert!(
            !lifecycle.rights_admitted(),
            "unknown rights are not admitted"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Preflight,
            "phase did not move"
        );
    }

    #[test]
    fn missing_expired_and_out_of_scope_rights_are_denied() {
        let mut lifecycle = ConnectorLifecycle::new();
        let error = lifecycle
            .preflight(None, &request())
            .expect_err("missing evidence is denied");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "missing evidence code"
        );
        let mut expired = admitted_evidence();
        expired.valid_until_utc_ns = Some(request().observed_at_utc_ns);
        let error =
            evaluate_preflight(Some(&expired), &request()).expect_err("expired evidence is denied");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED, "expiry code");
        let out_of_scope = RightsEvidenceState::OutOfScope;
        let mut evidence = admitted_evidence();
        evidence.state = out_of_scope;
        let error = evaluate_preflight(Some(&evidence), &request())
            .expect_err("out-of-scope evidence is denied");
        assert_eq!(error.reason_code(), RIGHTS_NOT_ADMITTED, "scope-state code");
    }

    #[test]
    fn missing_operation_scope_is_denied() {
        let mut evidence = admitted_evidence();
        evidence.granted_scope_refs = BTreeSet::from(["scope-other".to_owned()]);
        let error = evaluate_preflight(Some(&evidence), &request())
            .expect_err("a scope absent from the evidence is denied");
        assert_eq!(
            error.reason_code(),
            RIGHTS_NOT_ADMITTED,
            "missing scope code"
        );
        assert!(
            error.detail.contains("scope"),
            "the denial names the missing scope"
        );
    }

    #[test]
    fn ordering_is_enforced_even_after_admitted_preflight() {
        let mut lifecycle = ConnectorLifecycle::new();
        lifecycle
            .preflight(Some(&admitted_evidence()), &request())
            .expect("admitted evidence passes preflight");
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
    fn denied_preflight_never_reaches_capture() {
        let mut evidence = admitted_evidence();
        evidence.state = RightsEvidenceState::Unknown;
        let mut lifecycle = ConnectorLifecycle::new();
        lifecycle
            .preflight(Some(&evidence), &request())
            .expect_err("unknown rights are denied");
        let error = lifecycle
            .transition(ConnectorState::Capture)
            .expect_err("capture is gated by rights");
        assert_eq!(
            error.reason_code(),
            "CAPTURE_BEFORE_PREFLIGHT",
            "capture denial is attributable to preflight"
        );
        for target in [
            ConnectorState::Connect,
            ConnectorState::Discover,
            ConnectorState::Subscribe,
        ] {
            lifecycle
                .transition(target)
                .expect("non-capture phases can advance");
        }
        let error = lifecycle
            .transition(ConnectorState::Capture)
            .expect_err("capture stays gated after earlier phases");
        assert_eq!(
            error.reason_code(),
            "CAPTURE_BEFORE_PREFLIGHT",
            "the rights gate is still active"
        );
        assert!(
            !lifecycle.reached_capture(),
            "no decision advanced into capture"
        );
        assert_eq!(
            lifecycle.state(),
            ConnectorState::Subscribe,
            "phase is not capture"
        );
        assert!(
            lifecycle
                .log()
                .iter()
                .all(|record| record.to != ConnectorState::Capture),
            "the log contains no capture attempt that advanced"
        );
    }

    #[test]
    fn quarantine_branch_bypasses_publication() {
        let mut lifecycle = through_subscribe();
        lifecycle
            .transition(ConnectorState::Capture)
            .expect("capture is allowed after preflight");
        lifecycle
            .transition(ConnectorState::Decode)
            .expect("decode follows capture");
        lifecycle
            .transition(ConnectorState::Validate)
            .expect("validate follows decode");
        lifecycle.quarantine().expect("quarantine follows validate");
        let error = lifecycle
            .transition(ConnectorState::Archive)
            .expect_err("quarantine cannot archive");
        assert_eq!(
            error.reason,
            LifecycleReason::InvalidTransition,
            "quarantine blocks publication path"
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
            lifecycle
                .transition(target)
                .expect("ordered transition succeeds");
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
    }
}
