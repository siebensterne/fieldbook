// SPDX-License-Identifier: Apache-2.0
//! Typed operation plans.
//!
//! A command never grants its pipeline by declaring one operation. A caller
//! supplies an [`OperationPlan`] whose steps each bind one actor, one action,
//! one full data object, one source scope and one side-effect boundary to a
//! written grant reference. Every step is authorized independently and
//! reauthorized at its own side-effect boundary. A plan is installed atomically:
//! a later failing step leaves no earlier step authorized.

use std::{collections::BTreeSet, path::Path, sync::Arc};

use anyhow::Context as _;
use serde::Deserialize;
use serde::Serialize;

use crate::{
    config::Settings,
    egress_intent::{
        AUTHORITY_REFRESH_TIMEOUT, CHECKPOINT_INTERVAL, Clock, DecisionTime, EgressIntent,
        GrantSnapshot, InMemoryAuthority, LEASE_RENEWAL_MARGIN, SystemClock,
    },
    rights::{
        Actor, AuditContext, AuditSink, AuthorizationGate, AuthorizationRequest,
        AuthorizationScope, DataObject, DecisionAudit, DecisionAuditEvent, Operation,
        ProofInstallation, RightsContext, RightsError, default_gate,
    },
    time::now_us,
};

/// Which plane an operation belongs to. Provider-egress operations may open a
/// socket; local-data-use operations may only touch already-held local data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationClass {
    ProviderEgress,
    LocalDataUse,
}

impl OperationClass {
    /// Stable audit string for this class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderEgress => "provider_egress",
            Self::LocalDataUse => "local_data_use",
        }
    }
}

/// Classify an operation. The vocabulary is the existing 14-value
/// [`Operation`] enum; no second producer action enum is introduced.
#[must_use]
pub const fn class_for(operation: Operation) -> OperationClass {
    match operation {
        Operation::SourceContact
        | Operation::ReferenceDataRetrieval
        | Operation::HistoricalDataRetrieval
        | Operation::RealTimeCapture => OperationClass::ProviderEgress,
        Operation::RawStorage
        | Operation::Normalization
        | Operation::Replay
        | Operation::Backup
        | Operation::InternalAnalytics
        | Operation::DerivedDataCreation
        | Operation::Retention
        | Operation::Deletion
        | Operation::Display
        | Operation::ExternalRedistribution => OperationClass::LocalDataUse,
    }
}

/// The single side effect a step may perform. It is audited and checked at
/// the boundary; it is never inferred from a command name or another step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideEffectBoundary {
    /// DNS, TCP, TLS or a protocol upgrade toward a provider.
    ProviderContact,
    /// Creating durable local artifacts: capture, segments, journal, backups.
    DurableStorage,
    /// Reading retained local data into a decoder, verifier or replayer.
    LocalDataRead,
    /// Publishing files to staging, a release or an external recipient.
    Publication,
}

impl SideEffectBoundary {
    /// Stable audit string for this boundary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderContact => "provider_contact",
            Self::DurableStorage => "durable_storage",
            Self::LocalDataRead => "local_data_read",
            Self::Publication => "publication",
        }
    }
}

/// The only boundary that an operation may declare. A request that names a
/// different boundary is refused before any gate check.
#[must_use]
pub const fn required_boundary(operation: Operation) -> SideEffectBoundary {
    match operation {
        Operation::SourceContact
        | Operation::ReferenceDataRetrieval
        | Operation::HistoricalDataRetrieval
        | Operation::RealTimeCapture => SideEffectBoundary::ProviderContact,
        Operation::RawStorage | Operation::Backup | Operation::Retention => {
            SideEffectBoundary::DurableStorage
        }
        Operation::Replay
        | Operation::Normalization
        | Operation::InternalAnalytics
        | Operation::Display
        | Operation::Deletion => SideEffectBoundary::LocalDataRead,
        Operation::DerivedDataCreation | Operation::ExternalRedistribution => {
            SideEffectBoundary::Publication
        }
    }
}

/// Decision of one declared step. A step starts `Pending`; only a completed
/// full-plan authorization may set it to `Permitted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanDecision {
    #[default]
    Pending,
    Permitted,
    Denied,
}

/// Source identity scope of a step. It is identity, never permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceScope {
    pub provider_id: String,
    pub source_product_id: String,
    pub venue_id: String,
    pub segment_id: String,
    pub dataset_id: String,
}

/// The caller-supplied request carried by a step. A provider step needs an
/// endpoint; a local step has none and is never sent to a
/// provider transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request_kind", rename_all = "snake_case")]
pub enum PlanRequest {
    Egress(EgressIntent),
    Local(AuthorizationRequest),
}

impl PlanRequest {
    /// Validate the request without consulting any grant.
    ///
    /// # Errors
    /// Returns the fail-closed rights error for the first invalid field.
    pub fn validate(&self) -> Result<(), RightsError> {
        match self {
            Self::Egress(intent) => intent.validate(),
            Self::Local(scope) => scope.validate(),
        }
    }

    /// The request as a scope, for full identity comparison.
    #[must_use]
    pub fn to_scope(&self) -> AuthorizationScope {
        match self {
            Self::Egress(intent) => intent.to_scope(),
            Self::Local(scope) => scope.clone(),
        }
    }

    /// The declared action of this request.
    #[must_use]
    pub fn operation(&self) -> Operation {
        match self {
            Self::Egress(intent) => intent.operation,
            Self::Local(scope) => scope.operation,
        }
    }
}

/// One declared step of an operation plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanStep {
    /// Stable, caller-declared identity of this step within the plan.
    pub step_id: String,
    /// Full request: actor, action, object, source scope and recipient.
    pub request: PlanRequest,
    /// Written evidence reference. It is a declaration, not a permission.
    pub grant_reference: String,
    /// Endpoint resource class accepted for HTTP dispatch, when applicable.
    #[serde(default)]
    pub approved_resource_class: Option<String>,
    /// HTTP method accepted for dispatch by this step, when applicable.
    #[serde(default)]
    pub approved_http_method: Option<String>,
    #[serde(default)]
    pub decision: PlanDecision,
    /// Id of the committed audit event that authorized this step.
    #[serde(default)]
    pub audit_reference: Option<String>,
    /// The one side effect this step permits.
    pub side_effect_boundary: SideEffectBoundary,
}

impl PlanStep {
    /// Declared actor. Never supplied by a command or an installed proof.
    #[must_use]
    pub fn actor(&self) -> Actor {
        self.request.to_scope().actor
    }

    /// Declared 14-value action.
    #[must_use]
    pub fn action(&self) -> Operation {
        self.request.operation()
    }

    /// Full object identity: kind, id and version.
    #[must_use]
    pub fn object(&self) -> DataObject {
        self.request.to_scope().data_object
    }

    /// Declared source scope.
    #[must_use]
    pub fn source_scope(&self) -> SourceScope {
        let scope = self.request.to_scope();
        SourceScope {
            provider_id: scope.provider_id,
            source_product_id: scope.product_id,
            venue_id: scope.venue,
            segment_id: scope.segment,
            dataset_id: scope.dataset_id,
        }
    }

    /// Whether this step belongs to the provider-egress plane.
    #[must_use]
    pub fn is_egress(&self) -> bool {
        class_for(self.action()) == OperationClass::ProviderEgress
    }

    /// Validate the step's shape before any authorization is attempted.
    ///
    /// # Errors
    /// Returns the first fail-closed plan error.
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.step_id.trim().is_empty() {
            return Err(PlanError::MissingStepIdentity);
        }
        if self.grant_reference.trim().is_empty() {
            return Err(PlanError::MissingGrantReference {
                step_id: self.step_id.clone(),
            });
        }
        self.request
            .validate()
            .map_err(|error| PlanError::InvalidRequest {
                step_id: self.step_id.clone(),
                reason: error.to_string(),
            })?;
        let action = self.action();
        let expected_class = class_for(action);
        let actual_class = match self.request {
            PlanRequest::Egress(_) => OperationClass::ProviderEgress,
            PlanRequest::Local(_) => OperationClass::LocalDataUse,
        };
        if expected_class != actual_class {
            return Err(PlanError::WrongPlane {
                step_id: self.step_id.clone(),
                operation: action.as_str().to_owned(),
                plane: actual_class.as_str().to_owned(),
            });
        }
        if self.side_effect_boundary != required_boundary(action) {
            return Err(PlanError::WrongBoundary {
                step_id: self.step_id.clone(),
                operation: action.as_str().to_owned(),
            });
        }
        if self.is_egress() && self.approved_resource_class.is_none() {
            return Err(PlanError::MissingResourceClass {
                step_id: self.step_id.clone(),
            });
        }
        if self.is_egress()
            && self
                .approved_http_method
                .as_deref()
                .is_none_or(|method| method.trim().is_empty())
        {
            return Err(PlanError::MissingHttpMethod {
                step_id: self.step_id.clone(),
            });
        }
        Ok(())
    }
}

/// Fail-closed operation plan errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("operation plan id is missing")]
    MissingPlanId,
    #[error("operation plan has no steps")]
    EmptyPlan,
    #[error("a plan step has no declared identity")]
    MissingStepIdentity,
    #[error("plan step `{step_id}` has no written grant reference")]
    MissingGrantReference { step_id: String },
    #[error("plan step `{step_id}` has an invalid request: {reason}")]
    InvalidRequest { step_id: String, reason: String },
    #[error("plan step `{step_id}` puts operation `{operation}` in the wrong plane `{plane}`")]
    WrongPlane {
        step_id: String,
        operation: String,
        plane: String,
    },
    #[error("plan step `{step_id}` declares the wrong side-effect boundary for `{operation}`")]
    WrongBoundary { step_id: String, operation: String },
    #[error("plan step `{step_id}` has no approved HTTP resource class")]
    MissingResourceClass { step_id: String },
    #[error("plan step `{step_id}` has no approved HTTP method")]
    MissingHttpMethod { step_id: String },
    #[error("plan step id `{step_id}` is declared more than once")]
    DuplicateStep { step_id: String },
    #[error("operation `{operation}` is declared more than once")]
    DuplicateOperation { operation: String },
    #[error("operation plan is incomplete: missing `{operation}`")]
    IncompletePlan { operation: String },
    #[error("operation `{operation}` has no step in the plan")]
    NoStepForOperation { operation: String },
    #[error("plan step `{step_id}` is not authorized")]
    StepNotPermitted { step_id: String },
    #[error("the declared plan has not been authorized")]
    PlanNotAuthorized,
    #[error("unsupported operation plan schema version {version}")]
    UnsupportedSchemaVersion { version: u32 },
}

/// A caller-declared set of independent operation steps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationPlan {
    /// Stable identity of this plan, carried into every audit event.
    pub plan_id: String,
    /// Declared steps. Order is significant only for audit correlation.
    pub steps: Vec<PlanStep>,
}

/// Versioned TOML wrapper for a caller-declared [`OperationPlan`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPlanFile {
    pub schema_version: u32,
    pub plan: OperationPlan,
}

impl OperationPlan {
    /// Build and validate a plan. Each step is independent; no step grants
    /// another step's operation.
    ///
    /// # Errors
    /// Returns the first fail-closed plan error.
    pub fn new(plan_id: impl Into<String>, steps: Vec<PlanStep>) -> Result<Self, PlanError> {
        let plan_id = plan_id.into();
        if plan_id.trim().is_empty() {
            return Err(PlanError::MissingPlanId);
        }
        if steps.is_empty() {
            return Err(PlanError::EmptyPlan);
        }
        let mut step_ids = std::collections::BTreeSet::new();
        let mut operations = std::collections::BTreeSet::new();
        for step in &steps {
            step.validate()?;
            if !step_ids.insert(step.step_id.clone()) {
                return Err(PlanError::DuplicateStep {
                    step_id: step.step_id.clone(),
                });
            }
            if !operations.insert(step.action()) {
                return Err(PlanError::DuplicateOperation {
                    operation: step.action().as_str().to_owned(),
                });
            }
        }
        Ok(Self { plan_id, steps })
    }

    /// Load a versioned plan declaration from TOML. The file is a request,
    /// not a grant; loading it never authorizes a step.
    ///
    /// # Errors
    /// Returns an error for a missing, unreadable, malformed or invalid file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading operation plan `{}`", path.display()))?;
        let file: OperationPlanFile = toml::from_str(&text)
            .with_context(|| format!("parsing operation plan `{}`", path.display()))?;
        anyhow::ensure!(
            file.schema_version == 1,
            "{}",
            PlanError::UnsupportedSchemaVersion {
                version: file.schema_version
            }
        );
        Self::new(file.plan.plan_id, file.plan.steps).map_err(anyhow::Error::from)
    }

    /// A step by its declared identity.
    #[must_use]
    pub fn step(&self, step_id: &str) -> Option<&PlanStep> {
        self.steps.iter().find(|step| step.step_id == step_id)
    }

    /// The single step for an operation.
    #[must_use]
    pub fn step_for_operation(&self, operation: Operation) -> Option<&PlanStep> {
        self.steps.iter().find(|step| step.action() == operation)
    }

    /// Fail when any required operation has no declared step. This check runs
    /// before command start; an incomplete plan never reaches a side effect.
    ///
    /// # Errors
    /// Returns the first missing operation.
    pub fn require_complete(&self, operations: &[Operation]) -> Result<(), PlanError> {
        for operation in operations {
            if self.step_for_operation(*operation).is_none() {
                return Err(PlanError::IncompletePlan {
                    operation: operation.as_str().to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Whether every declared step has been authorized.
    #[must_use]
    pub fn is_fully_authorized(&self) -> bool {
        self.steps
            .iter()
            .all(|step| step.decision == PlanDecision::Permitted)
    }
}

/// Retained handle to one authorized plan.
///
/// Every step shares one refreshable authority. A runtime revision advance,
/// revocation or refresh failure on that handle is therefore visible to every
/// gate checkpoint; no snapshot is frozen at installation time.
#[derive(Debug, Clone)]
pub struct PlanAuthorization {
    pub plan_id: String,
    pub plan: OperationPlan,
    pub gate: AuthorizationGate,
    pub authority: Arc<dyn crate::egress_intent::AuthorityRefresh>,
    pub live_authority: Arc<InMemoryAuthority>,
    pub sink: AuditSink,
    pub lease_id: String,
    pub lease_duration_us: u64,
    pub registry_revision: u64,
    pub snapshots: Vec<String>,
    pub evidence: DecisionAudit,
    pub wall_issued_at_us: i64,
    pub monotonic_issued_at_us: u64,
}

/// Authorize every step of a plan from the runtime rights file and install the
/// proofs atomically into the process-wide gate. The returned handle must be
/// retained by the long-running session so it can refresh and revoke authority.
///
/// # Errors
/// Returns the first fail-closed denial. No step is permitted on failure.
pub fn authorize_plan(
    settings: &Settings,
    plan: &mut OperationPlan,
) -> anyhow::Result<PlanAuthorization> {
    authorize_plan_with_clock(settings, plan, default_gate(), &SystemClock)
}

/// Authorize a plan against a specific gate and clock.
///
/// Step decisions and audit references are updated only after the whole batch
/// commits, so a failed step never marks another step permitted.
///
/// # Errors
/// Returns the first fail-closed denial. No step is permitted on failure.
pub fn authorize_plan_on(
    settings: &Settings,
    plan: &mut OperationPlan,
    gate: &AuthorizationGate,
) -> anyhow::Result<PlanAuthorization> {
    authorize_plan_with_clock(settings, plan, gate, &SystemClock)
}

/// Authorize a plan with an injected clock. The wall reading decides contract
/// validity; the monotonic reading anchors the lease deadline used by the
/// receive loop.
///
/// # Errors
/// Returns the first fail-closed denial. No step is permitted on failure.
pub fn authorize_plan_with_clock(
    settings: &Settings,
    plan: &mut OperationPlan,
    gate: &AuthorizationGate,
    clock: &dyn Clock,
) -> anyhow::Result<PlanAuthorization> {
    let path = settings.governance.rights_file.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "operation plans require a runtime authorization file: set [governance].rights_file or --rights-file"
        )
    })?;
    let audit_dir = settings.governance.audit_dir.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "operation plans require a configured audit directory: set [governance].audit_dir or --rights-audit-dir"
        )
    })?;
    for step in &plan.steps {
        step.validate()?;
    }
    let context = RightsContext::load(path, audit_dir)?;
    let time = DecisionTime::from_clock(clock)?;
    let mut proofs = Vec::with_capacity(plan.steps.len());
    let mut committed = Vec::with_capacity(plan.steps.len());
    for step in &plan.steps {
        let audit_context = AuditContext {
            plan_id: Some(plan.plan_id.clone()),
            step_id: Some(step.step_id.clone()),
            side_effect_boundary: Some(step.side_effect_boundary.as_str().to_owned()),
            ..AuditContext::default()
        };
        let (proof, event): (crate::rights::AuthorizationProof, DecisionAuditEvent) = context
            .authorize_with_context(&step.request.to_scope(), time.wall_us, audit_context)?;
        proofs.push(proof);
        committed.push(event);
    }
    anyhow::ensure!(!proofs.is_empty(), "an operation plan has no steps");
    let registry_revision = proofs[0].registry_revision;
    let snapshots: Vec<String> = proofs
        .iter()
        .map(|proof| proof.grant_snapshot_id.clone())
        .collect();
    let lease_duration_us = proofs
        .iter()
        .map(|proof| proof.lease_duration_us)
        .min()
        .unwrap_or(0);
    let authority = Arc::new(InMemoryAuthority::new_with_snapshots(
        registry_revision,
        snapshots.clone(),
    ));
    let authority_refresh: Arc<dyn crate::egress_intent::AuthorityRefresh> = authority.clone();
    let deadline = time
        .monotonic_us
        .map(|now| now.saturating_add(lease_duration_us));
    let lease_id = GrantSnapshot::new(
        registry_revision,
        snapshots[0].clone(),
        lease_duration_us,
        time.wall_us,
    )?
    .lease_id;
    let evidence = DecisionAudit {
        licence_reference: proofs[0].licence_reference.clone(),
        licence_document_hash: proofs[0].licence_document_hash.clone(),
        contract_revision: proofs[0].contract_revision,
        recorded_at_us: proofs[0].at_us,
        authority: proofs[0].recording_authority.clone(),
    };
    let mut installations = Vec::with_capacity(proofs.len());
    for (index, proof) in proofs.iter().enumerate() {
        installations.push(ProofInstallation {
            authority: Some(authority_refresh.clone()),
            proof: proof.clone(),
            sink: context.sink().clone(),
            plan_id: Some(plan.plan_id.clone()),
            step_id: Some(plan.steps[index].step_id.clone()),
            side_effect_boundary: Some(plan.steps[index].side_effect_boundary.as_str().to_owned()),
            lease_deadline_monotonic_us: deadline,
        });
    }
    // Atomic gate commit. A later duplicate or invalid proof denies the whole
    // plan and leaves no earlier step installed.
    gate.install_batch(installations)?;
    for (step, event) in plan.steps.iter_mut().zip(committed) {
        step.decision = PlanDecision::Permitted;
        step.audit_reference = Some(event.event_id);
    }
    let authorized = plan.clone();
    Ok(PlanAuthorization {
        plan_id: authorized.plan_id.clone(),
        plan: authorized,
        gate: gate.clone(),
        authority: authority_refresh,
        live_authority: authority,
        sink: context.sink().clone(),
        lease_id,
        lease_duration_us,
        registry_revision,
        snapshots,
        evidence,
        wall_issued_at_us: time.wall_us,
        monotonic_issued_at_us: time.monotonic_us.unwrap_or(0),
    })
}

/// Outcome of one authorization checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckpointOutcome {
    pub renewed: bool,
    pub lease_epoch: u64,
    pub monotonic_deadline_us: Option<u64>,
}

/// Evidence returned when a session is halted. Counts are the frames and
/// decoded events read on the connection that were not yet committed by the
/// coordinator; they are reported, never silently dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HaltOutcome {
    pub reason: String,
    pub lease_id: String,
    pub lease_epoch: u64,
    pub buffered_frames: u64,
    pub uncommitted_events: u64,
    pub cancel_committed: bool,
}

/// Authorization lifecycle carried by the long-running receive loop.
#[derive(Debug, Clone)]
pub struct SessionAuthorization {
    pub auth: PlanAuthorization,
    pub clock: Arc<dyn Clock>,
    pub checkpoint_interval_us: u64,
    pub refresh_timeout_us: u64,
    pub renewal_margin_us: u64,
    next_checkpoint_tick: u64,
    halted: bool,
}

impl SessionAuthorization {
    /// Bind an authorized plan to an injected clock. A fresh authorization is
    /// mandatory: no session is resumed from persisted gate state.
    ///
    /// # Errors
    /// Returns an error when the plan has no provider-egress step.
    pub fn new(auth: PlanAuthorization, clock: Arc<dyn Clock>) -> anyhow::Result<Self> {
        let interval = CHECKPOINT_INTERVAL.as_micros().min(u64::MAX as u128) as u64;
        let next_checkpoint_tick = clock.monotonic_us().saturating_add(interval);
        let session = Self {
            auth,
            clock,
            checkpoint_interval_us: interval,
            refresh_timeout_us: AUTHORITY_REFRESH_TIMEOUT.as_micros().min(u64::MAX as u128) as u64,
            renewal_margin_us: LEASE_RENEWAL_MARGIN.as_micros().min(u64::MAX as u128) as u64,
            next_checkpoint_tick,
            halted: false,
        };
        session.primary_intent()?;
        Ok(session)
    }

    /// Replace the clock used for abstract timing (test fault injection).
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.next_checkpoint_tick = clock
            .monotonic_us()
            .saturating_add(self.checkpoint_interval_us);
        self.clock = clock;
        self
    }

    /// Whether a checkpoint is due on the monotonic timeline.
    #[must_use]
    pub fn checkpoint_due(&self) -> bool {
        self.clock.monotonic_us() >= self.next_checkpoint_tick
    }

    /// Whether the session has been halted and must never receive again.
    #[must_use]
    pub fn is_halted(&self) -> bool {
        self.halted
    }

    /// The declared provider intent that carries this session's receive scope.
    fn primary_intent(&self) -> anyhow::Result<EgressIntent> {
        self.auth
            .plan
            .steps
            .iter()
            .find_map(|step| match &step.request {
                PlanRequest::Egress(intent) => Some(intent.clone()),
                PlanRequest::Local(_) => None,
            })
            .context("a receive session requires a declared provider-egress step")
    }

    fn step_context(&self, step: &PlanStep) -> AuditContext {
        AuditContext {
            plan_id: Some(self.auth.plan_id.clone()),
            step_id: Some(step.step_id.clone()),
            side_effect_boundary: Some(step.side_effect_boundary.as_str().to_owned()),
            lease_id: Some(self.auth.lease_id.clone()),
            grant_identity: Some(format!(
                "{}#{}",
                self.auth.snapshots[0], self.auth.registry_revision
            )),
            ..AuditContext::default()
        }
    }

    /// Run one checkpoint: check the monotonic lease deadline, reauthorize every
    /// step of the active plan, enforce the refresh timeout, renew if needed,
    /// then commit the checkpoint audit. Any failure halts the session.
    ///
    /// # Errors
    /// Returns the fail-closed denial that also stops the receive loop.
    pub fn checkpoint(&mut self) -> anyhow::Result<CheckpointOutcome> {
        if self.halted {
            return Err(RightsError::SessionCancelled {
                reason: "session already halted".to_owned(),
            }
            .into());
        }
        let time = DecisionTime::from_clock(self.clock.as_ref())?;
        let intent = self.primary_intent()?;
        let session = self.auth.gate.session_lease(&intent)?;
        if time.lease_expired(session.expires_at_us, session.lease_deadline_monotonic_us) {
            // Commit the authoritative expiry event through the gate before
            // the final halt record. The gate removes the session in the same
            // audited transaction.
            let _ = self
                .auth
                .gate
                .require_egress_with_time(&intent, time, AuditContext::default());
            let _ = self.halt("authorization lease expired", 0, 0);
            return Err(RightsError::LeaseExpired.into());
        }

        let before = self.clock.monotonic_us();
        for step in &self.auth.plan.steps {
            require_plan_step_with_time(
                &self.auth.plan,
                step.action(),
                &self.auth.gate,
                time,
                self.step_context(step),
            )?;
        }
        let consumed = self.clock.monotonic_us().saturating_sub(before);
        if consumed > self.refresh_timeout_us {
            let _ = self.halt("authority refresh timeout", 0, 0);
            return Err(RightsError::AuthorityRefreshFailed.into());
        }
        let mut renewed = false;
        let remaining = session
            .lease_deadline_monotonic_us
            .map(|deadline| deadline.saturating_sub(time.monotonic_us.unwrap_or(0)));
        if remaining.is_some_and(|value| value <= self.renewal_margin_us) {
            let step = self
                .auth
                .plan
                .step_for_operation(Operation::RealTimeCapture)
                .context("renewal requires a capture step")?;
            let renewal =
                self.auth
                    .gate
                    .renew_lease_with_time(&intent, time, self.step_context(step))?;
            renewed = true;
            self.next_checkpoint_tick = renewal
                .monotonic_deadline_us
                .unwrap_or_else(|| time.monotonic_us.unwrap_or(0))
                .min(
                    self.clock
                        .monotonic_us()
                        .saturating_add(self.checkpoint_interval_us),
                );
        } else {
            self.next_checkpoint_tick = self
                .clock
                .monotonic_us()
                .saturating_add(self.checkpoint_interval_us);
        }

        let scope = intent.to_scope();
        let checkpoint_step = self
            .auth
            .plan
            .step_for_operation(Operation::RealTimeCapture)
            .context("checkpoint audit requires a capture step")?;
        let mut context = self.step_context(checkpoint_step);
        context.event_kind = Some("checkpoint".to_owned());
        context.lease_epoch = Some(self.auth.gate.session_lease(&intent)?.lease_epoch);
        context.lease_expires_at_us = Some(self.auth.gate.session_lease(&intent)?.expires_at_us);
        context.monotonic_deadline_us = self
            .auth
            .gate
            .session_lease(&intent)?
            .lease_deadline_monotonic_us;
        self.auth.sink.record_with_context(
            &scope,
            "authorization_checkpoint",
            None,
            Some(&self.auth.evidence),
            time.wall_us,
            context,
        )?;
        let final_session = self.auth.gate.session_lease(&intent)?;
        Ok(CheckpointOutcome {
            renewed,
            lease_epoch: final_session.lease_epoch,
            monotonic_deadline_us: final_session.lease_deadline_monotonic_us,
        })
    }

    /// Stop receive, cancel the session transactionally and commit the final
    /// audit state. Buffered and uncommitted counts are reported for
    /// reconciliation; nothing is silently discarded.
    ///
    /// # Errors
    /// Returns an error only when the clock or the primary intent is invalid.
    pub fn halt(
        &mut self,
        reason: &str,
        buffered_frames: u64,
        uncommitted_events: u64,
    ) -> anyhow::Result<HaltOutcome> {
        let time = DecisionTime::from_clock(self.clock.as_ref())?;
        let intent = self.primary_intent()?;
        let session = self.auth.gate.session_lease(&intent).ok();
        let lease_id = session.as_ref().map_or_else(
            || self.auth.lease_id.clone(),
            |value| value.lease_id.clone(),
        );
        let lease_epoch = session.as_ref().map_or(0, |value| value.lease_epoch);
        let cancel_committed = self.auth.gate.cancel(&intent, reason, time.wall_us).is_ok();
        let step = self
            .auth
            .plan
            .step_for_operation(Operation::RealTimeCapture)
            .context("halt audit requires a capture step")?;
        let mut context = self.step_context(step);
        context.event_kind = Some(
            if reason.contains("revoke") || reason.contains("authority") {
                "revocation"
            } else if reason.contains("lease") {
                "expiry"
            } else {
                "cancellation"
            }
            .to_owned(),
        );
        context.lease_epoch = Some(lease_epoch);
        let _ = self.auth.sink.record_with_context(
            &intent.to_scope(),
            "session_halted",
            Some(format!(
                "{reason}; buffered_frames={buffered_frames}; uncommitted_events={uncommitted_events}"
            )),
            Some(&self.auth.evidence),
            time.wall_us,
            context,
        );
        self.halted = true;
        Ok(HaltOutcome {
            reason: reason.to_owned(),
            lease_id,
            lease_epoch,
            buffered_frames,
            uncommitted_events,
            cancel_committed,
        })
    }

    /// Recheck a widened subscription against the live gate before the worker
    /// transmits it. Named symbols are an explicit request set; a set outside
    /// the grant's declared instruments denies before any socket action.
    ///
    /// # Errors
    /// Returns the fail-closed denial from the gate.
    pub fn recheck_subscription(&self, desired: &BTreeSet<String>) -> anyhow::Result<()> {
        if self.halted {
            return Err(RightsError::SessionCancelled {
                reason: "session already halted".to_owned(),
            }
            .into());
        }
        let time = DecisionTime::from_clock(self.clock.as_ref())?;
        let mut intent = self.primary_intent()?;
        intent.instruments = crate::rights::ScopeSet::Named(desired.iter().cloned().collect());
        self.auth.gate.check_active_with_time(&intent, time)?;
        Ok(())
    }

    /// Reauthorize before resuming after a process restart. A restarted process
    /// never inherits a live gate: it must install a fresh plan authorization
    /// and recheck every step against the live authority before activity.
    ///
    /// # Errors
    /// Returns an error when the fresh authorization is stale or denied.
    pub fn resume(fresh: PlanAuthorization, clock: Arc<dyn Clock>) -> anyhow::Result<Self> {
        let time = DecisionTime::from_clock(clock.as_ref())?;
        for step in &fresh.plan.steps {
            require_plan_step_with_time(
                &fresh.plan,
                step.action(),
                &fresh.gate,
                time,
                AuditContext::default(),
            )?;
        }
        Self::new(fresh, clock)
    }
}

/// Reauthorize one step immediately before its side effect. This is the
/// separate provider/local gate: a step for another operation, an
/// unauthorized step or a stale gate state denies before any DNS, socket,
/// file read or publication.
///
/// # Errors
/// Returns the fail-closed denial from the gate.
pub fn require_plan_step(
    plan: &OperationPlan,
    operation: Operation,
    gate: &AuthorizationGate,
    at_us: i64,
) -> anyhow::Result<()> {
    let metadata = plan
        .step_for_operation(operation)
        .map(|step| AuditContext {
            plan_id: Some(plan.plan_id.clone()),
            step_id: Some(step.step_id.clone()),
            side_effect_boundary: Some(step.side_effect_boundary.as_str().to_owned()),
            ..AuditContext::default()
        })
        .unwrap_or_default();
    require_plan_step_with_time(
        plan,
        operation,
        gate,
        DecisionTime::wall_only(at_us),
        metadata,
    )
}

/// Reauthorize one step with explicit wall/monotonic decision times and audit
/// metadata. This is the form used by the long-running checkpoint.
///
/// # Errors
/// Returns the fail-closed denial from the gate.
pub fn require_plan_step_with_time(
    plan: &OperationPlan,
    operation: Operation,
    gate: &AuthorizationGate,
    time: DecisionTime,
    metadata: AuditContext,
) -> anyhow::Result<()> {
    let step = plan
        .step_for_operation(operation)
        .ok_or_else(|| PlanError::NoStepForOperation {
            operation: operation.as_str().to_owned(),
        })?;
    if step.decision != PlanDecision::Permitted {
        return Err(PlanError::StepNotPermitted {
            step_id: step.step_id.clone(),
        }
        .into());
    }
    if step.side_effect_boundary != required_boundary(operation) {
        return Err(PlanError::WrongBoundary {
            step_id: step.step_id.clone(),
            operation: operation.as_str().to_owned(),
        }
        .into());
    }
    match &step.request {
        PlanRequest::Egress(intent) => gate.require_egress_with_time(intent, time, metadata),
        PlanRequest::Local(scope) => gate.check_scope_active_with_time(scope, time, metadata),
    }
}

/// Convenience wrapper for the process-wide gate used by the binary.
///
/// # Errors
/// Returns the fail-closed denial from [`require_plan_step`].
pub fn require_declared_step(plan: &OperationPlan, operation: Operation) -> anyhow::Result<()> {
    let at_us = now_us().context("reading the clock for plan reauthorization")?;
    require_plan_step(plan, operation, default_gate(), at_us)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn checked_in_plan_example_parses() {
        let plan = OperationPlan::load(Path::new("operation-plan.example.toml"))
            .expect("the checked-in plan example must parse");
        assert_eq!(plan.steps.len(), 2, "the example declares two steps");
        assert!(
            plan.step_for_operation(Operation::SourceContact).is_some(),
            "the example declares a provider step"
        );
        assert!(
            plan.step_for_operation(Operation::RawStorage).is_some(),
            "the example declares a local-data step"
        );
    }

    #[test]
    fn operation_planes_and_boundaries_partition_the_enum() {
        let egress = [
            Operation::SourceContact,
            Operation::ReferenceDataRetrieval,
            Operation::HistoricalDataRetrieval,
            Operation::RealTimeCapture,
        ];
        for operation in egress {
            assert_eq!(
                class_for(operation),
                OperationClass::ProviderEgress,
                "egress class"
            );
            let boundary = required_boundary(operation);
            assert_eq!(
                boundary,
                SideEffectBoundary::ProviderContact,
                "contact boundary"
            );
        }
        let local = [
            (Operation::RawStorage, SideEffectBoundary::DurableStorage),
            (Operation::Normalization, SideEffectBoundary::LocalDataRead),
            (Operation::Replay, SideEffectBoundary::LocalDataRead),
            (Operation::Backup, SideEffectBoundary::DurableStorage),
            (
                Operation::InternalAnalytics,
                SideEffectBoundary::LocalDataRead,
            ),
            (
                Operation::DerivedDataCreation,
                SideEffectBoundary::Publication,
            ),
            (Operation::Retention, SideEffectBoundary::DurableStorage),
            (Operation::Deletion, SideEffectBoundary::LocalDataRead),
            (Operation::Display, SideEffectBoundary::LocalDataRead),
            (
                Operation::ExternalRedistribution,
                SideEffectBoundary::Publication,
            ),
        ];
        for (operation, boundary) in local {
            assert_eq!(
                class_for(operation),
                OperationClass::LocalDataUse,
                "local class"
            );
            assert_eq!(required_boundary(operation), boundary, "local boundary");
        }
    }

    #[test]
    fn plan_identity_and_completeness_fail_closed() {
        let error = OperationPlan::new("", vec![]).unwrap_err();
        assert_eq!(error, PlanError::MissingPlanId, "missing id denied");
        let error = OperationPlan::new("plan", vec![]).unwrap_err();
        assert_eq!(error, PlanError::EmptyPlan, "empty plan denied");
    }
}
