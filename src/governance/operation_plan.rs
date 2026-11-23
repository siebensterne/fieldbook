// SPDX-License-Identifier: Apache-2.0
//! Typed operation plans.
//!
//! A command never grants its pipeline by declaring one operation. A caller
//! supplies an [`OperationPlan`] whose steps each bind one actor, one action,
//! one full data object, one source scope and one side-effect boundary to a
//! written grant reference. Every step is authorized independently and
//! reauthorized at its own side-effect boundary. A plan is installed atomically:
//! a later failing step leaves no earlier step authorized.

use std::path::Path;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use crate::{
    config::Settings,
    egress_intent::{AuthorityRefresh, EgressIntent, InMemoryAuthority},
    rights::{
        Actor, AuditContext, AuthorizationGate, AuthorizationRequest, AuthorizationScope,
        DataObject, DecisionAuditEvent, Operation, ProofInstallation, RightsContext, RightsError,
        default_gate,
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
/// endpoint; a local step deliberately has none and is never sent to a
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

fn installation_authority(
    proof: &crate::rights::AuthorizationProof,
) -> std::sync::Arc<dyn AuthorityRefresh> {
    std::sync::Arc::new(InMemoryAuthority::new(
        proof.registry_revision,
        proof.grant_snapshot_id.clone(),
    ))
}

/// Authorize every step of a plan from the runtime rights file and install the
/// proofs atomically into the process-wide gate.
///
/// # Errors
/// Returns the first fail-closed denial. No step is permitted on failure.
pub fn authorize_plan(settings: &Settings, plan: &mut OperationPlan) -> anyhow::Result<()> {
    authorize_plan_on(settings, plan, default_gate())
}

/// Authorize a plan against a specific gate. Library callers and offline tests
/// use this instance-scoped form; the binary uses [`authorize_plan`].
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
) -> anyhow::Result<()> {
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
    let at_us = now_us()?;
    let mut installations = Vec::with_capacity(plan.steps.len());
    let mut committed = Vec::with_capacity(plan.steps.len());
    for step in &plan.steps {
        let audit_context = AuditContext {
            plan_id: Some(plan.plan_id.clone()),
            step_id: Some(step.step_id.clone()),
            side_effect_boundary: Some(step.side_effect_boundary.as_str().to_owned()),
            ..AuditContext::default()
        };
        let (proof, event): (crate::rights::AuthorizationProof, DecisionAuditEvent) =
            context.authorize_with_context(&step.request.to_scope(), at_us, audit_context)?;
        installations.push(ProofInstallation {
            authority: Some(installation_authority(&proof)),
            proof: proof.clone(),
            sink: context.sink().clone(),
            plan_id: Some(plan.plan_id.clone()),
            step_id: Some(step.step_id.clone()),
            side_effect_boundary: Some(step.side_effect_boundary.as_str().to_owned()),
        });
        committed.push(event);
    }
    // Atomic gate commit. A later duplicate or invalid proof denies the whole
    // plan and leaves no earlier step installed.
    gate.install_batch(installations)?;
    for (step, event) in plan.steps.iter_mut().zip(committed) {
        step.decision = PlanDecision::Permitted;
        step.audit_reference = Some(event.event_id);
    }
    Ok(())
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
    let metadata = AuditContext {
        plan_id: Some(plan.plan_id.clone()),
        step_id: Some(step.step_id.clone()),
        side_effect_boundary: Some(step.side_effect_boundary.as_str().to_owned()),
        ..AuditContext::default()
    };
    match &step.request {
        PlanRequest::Egress(intent) => {
            gate.require_egress_with_plan_context(intent, at_us, metadata)
        }
        PlanRequest::Local(scope) => gate.check_scope_active_with_context(scope, at_us, metadata),
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
            assert_eq!(class_for(operation), OperationClass::ProviderEgress);
            assert_eq!(
                required_boundary(operation),
                SideEffectBoundary::ProviderContact
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
            assert_eq!(class_for(operation), OperationClass::LocalDataUse);
            assert_eq!(required_boundary(operation), boundary);
        }
    }

    #[test]
    fn plan_identity_and_completeness_fail_closed() {
        let error = OperationPlan::new("", vec![]).unwrap_err();
        assert_eq!(error, PlanError::MissingPlanId);
        let error = OperationPlan::new("plan", vec![]).unwrap_err();
        assert_eq!(error, PlanError::EmptyPlan);
    }
}
