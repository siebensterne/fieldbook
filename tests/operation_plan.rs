// SPDX-License-Identifier: Apache-2.0
//! Abstract-value tests for typed operation plans.
//!
//! Every identifier is a scalar, every endpoint is a reserved `.invalid` host
//! or loopback, and every network/file side effect is an injected closure. A
//! passing test proves that a denial happened before DNS, a socket, an archive
//! read or a publication. No provider is contacted and no market observation
//! is created.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "offline governance tests use the same assertion style as other test crates"
)]
#![allow(
    clippy::allow_attributes,
    reason = "test crates relax the production lint set wholesale; `expect` cannot express lints that may not fire"
)]

use std::{
    fs,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use fieldbook::{
    config::Settings,
    distribution::cli::{Command, local_data_operations, provider_egress_operations},
    egress::{
        HttpEgressRequest, authorize_http_request, authorize_redirect_on, dispatch_http_request,
        http_request_for_plan_step,
    },
    egress_intent::{EgressIntent, EndpointIdentity},
    governance::operation_plan::{
        OperationPlan, PlanDecision, PlanError, PlanRequest, PlanStep, SideEffectBoundary,
        authorize_plan_on, require_plan_step,
    },
    rights::{
        Actor, AuditSink, AuthorizationGate, AuthorizationRecord, AuthorizationScope, DataObject,
        DecisionAudit, DecisionAuditEvent, DeliveryMethod, Licensee, Modality, ObjectKind,
        Operation, Purpose, RecipientClass, RecipientIdentity, Retention, RightDecision,
        RightsContext, RightsFile, ScopeSet, TimeWindow, UsageMode, UsageRight,
    },
    taxonomy::CountryCode,
    ws::{self, ConnectOptions, DenialTransport},
};

const ENDPOINT: &str = "wss://venue-a.invalid:443";

fn scope_for(operation: Operation, id: &str) -> AuthorizationScope {
    let (kind, not_applicable) = match operation {
        Operation::ReferenceDataRetrieval => (ObjectKind::SourceReferenceRecord, false),
        Operation::Replay | Operation::Backup => (ObjectKind::RawArchive, false),
        Operation::InternalAnalytics => (ObjectKind::ResearchDataset, false),
        Operation::DerivedDataCreation => (ObjectKind::DerivedArtifact, false),
        Operation::Display => (ObjectKind::NdcRelease, false),
        _ => (
            ObjectKind::RawSourceRecord,
            operation == Operation::SourceContact,
        ),
    };
    let mut builder = AuthorizationScope::request()
        .actor(Actor::FieldbookProducer)
        .data_object(DataObject::new(kind, id, "v1").expect("abstract object identity"))
        .licensee(Licensee::new("licensee-a").expect("licensee"))
        .venue("venue-a")
        .provider_id("provider-a")
        .source_id("source-a")
        .dataset_id("quotes")
        .product_id("product-a")
        .segment("venue-a-equity-cash")
        .territory(CountryCode::new("US").expect("country"))
        .operation(operation)
        .usage_right(UsageRight::HistoricalStorage)
        .usage_mode(UsageMode::NonDisplay)
        .recipient_class(RecipientClass::Internal)
        .recipient_identity(RecipientIdentity::new("recipient-a").expect("recipient"))
        .purpose(Purpose::ProprietaryOwnAccountTradingResearch)
        .delivery_method(DeliveryMethod::Stream)
        .retention(if not_applicable {
            Retention::NONE
        } else {
            Retention::bounded(86_400)
        })
        .instruments(if not_applicable {
            ScopeSet::NotApplicable
        } else {
            ScopeSet::Named(vec!["inst-a".to_owned()])
        })
        .fields(if not_applicable {
            ScopeSet::NotApplicable
        } else {
            ScopeSet::Named(vec!["bid".to_owned()])
        })
        .modalities(if not_applicable {
            ScopeSet::NotApplicable
        } else {
            ScopeSet::Named(vec![Modality::L2])
        })
        .data_time_window(if not_applicable {
            TimeWindow::default()
        } else {
            TimeWindow {
                from_us: Some(1_000),
                to_us: Some(9_000),
            }
        });
    if operation != Operation::SourceContact {
        builder = builder
            .endpoint(ENDPOINT)
            .expect("abstract approved endpoint");
    }
    builder.build().expect("abstract grant scope")
}

fn intent_for(scope: &AuthorizationScope) -> EgressIntent {
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
        .endpoint_identity(
            EndpointIdentity::from_url(ENDPOINT).expect("reserved endpoint identity"),
        )
        .build()
        .expect("abstract egress intent")
}

fn step_for(operation: Operation, id: &str) -> PlanStep {
    let scope = scope_for(operation, id);
    let request = match fieldbook::governance::operation_plan::class_for(operation) {
        fieldbook::governance::operation_plan::OperationClass::ProviderEgress => {
            PlanRequest::Egress(intent_for(&scope))
        }
        fieldbook::governance::operation_plan::OperationClass::LocalDataUse => {
            PlanRequest::Local(scope)
        }
    };
    PlanStep {
        step_id: format!("{}-{}", operation.as_str(), id),
        request,
        grant_reference: "contract-abstract/1".to_owned(),
        approved_resource_class: (operation == Operation::SourceContact
            || operation == Operation::ReferenceDataRetrieval
            || operation == Operation::RealTimeCapture)
            .then(|| "market-data/reference".to_owned()),
        approved_http_method: (operation == Operation::SourceContact
            || operation == Operation::ReferenceDataRetrieval
            || operation == Operation::RealTimeCapture)
            .then(|| "GET".to_owned()),
        decision: PlanDecision::Pending,
        audit_reference: None,
        side_effect_boundary: fieldbook::governance::operation_plan::required_boundary(operation),
    }
}

fn write_rights(tmp: &Path, operations: &[(Operation, &str)]) -> std::path::PathBuf {
    let file = RightsFile {
        schema_version: 1,
        licensee: Licensee::new("licensee-a").expect("licensee"),
        territory: "US".to_owned(),
        recipient_class: RecipientClass::Internal,
        recipient_identity: RecipientIdentity::new("recipient-a").expect("recipient"),
        rights: operations
            .iter()
            .map(|(operation, id)| AuthorizationRecord {
                identity: fieldbook::rights::AuthorizationIdentity {
                    scope: scope_for(*operation, id),
                    valid_from: 0,
                    valid_until: None,
                },
                decision: RightDecision::Permitted,
                audit: DecisionAudit {
                    licence_reference: "contract-abstract/1".to_owned(),
                    licence_document_hash: "a".repeat(64),
                    contract_revision: 1,
                    recorded_at_us: 0,
                    authority: "contract-registry".to_owned(),
                },
            })
            .collect(),
    };
    let path = tmp.join("rights.toml");
    let serialized = toml::to_string(&file).expect("serialize rights");
    fs::write(&path, &serialized).expect("write rights");
    path
}

fn settings_with(tmp: &Path, operations: &[(Operation, &str)]) -> Settings {
    let mut settings = Settings::for_venue("venue-a");
    settings.governance.rights_file = Some(write_rights(tmp, operations));
    settings.governance.audit_dir = Some(tmp.join("audit"));
    settings
}

fn authorized_plan(
    tmp: &Path,
    operations: &[(Operation, &str)],
) -> (Settings, OperationPlan, AuthorizationGate) {
    let settings = settings_with(tmp, operations);
    let gate = AuthorizationGate::new();
    let mut plan = OperationPlan::new(
        "plan-abstract",
        operations
            .iter()
            .map(|(operation, id)| step_for(*operation, id))
            .collect(),
    )
    .expect("valid abstract plan");
    authorize_plan_on(&settings, &mut plan, &gate).expect("full plan authorizes");
    (settings, plan, gate)
}

#[test]
fn one_valid_step_does_not_authorize_another() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let (_, mut plan, gate) =
        authorized_plan(tmp.path(), &[(Operation::RealTimeCapture, "object-a")]);
    // A second, never-authorized step is added to the same plan. Its neighbor
    // being permitted does not grant it anything.
    plan.steps.push(step_for(Operation::RawStorage, "object-a"));
    assert_eq!(
        plan.step_for_operation(Operation::RawStorage)
            .expect("storage step")
            .decision,
        PlanDecision::Pending,
        "the added step stays pending"
    );
    assert!(
        require_plan_step(&plan, Operation::RealTimeCapture, &gate, 1).is_ok(),
        "the authorized step still works"
    );
    let error = require_plan_step(&plan, Operation::RawStorage, &gate, 1)
        .expect_err("a pending step is not authorized");
    assert!(
        format!("{error:#}").contains("not authorized"),
        "denial names the unauthorized step: {error:#}"
    );
}

#[test]
fn incomplete_plan_blocks_startup() {
    let command = Command::Collect;
    let mut required = provider_egress_operations(&command).to_vec();
    required.extend(local_data_operations(&command));
    let plan = OperationPlan::new(
        "incomplete-plan",
        vec![step_for(Operation::SourceContact, "object-a")],
    )
    .expect("valid one-step plan");
    assert_eq!(
        plan.require_complete(&required),
        Err(PlanError::IncompletePlan {
            operation: Operation::ReferenceDataRetrieval.as_str().to_owned()
        }),
        "a partially declared command plan is refused"
    );
    let replay = Command::Replay {
        input: std::path::PathBuf::from("events.jsonl"),
    };
    assert_eq!(
        local_data_operations(&replay),
        &[Operation::Replay],
        "replay is a local-data operation, not provider egress"
    );
    assert!(
        provider_egress_operations(&replay).is_empty(),
        "replay does not authorize provider egress"
    );
}

#[test]
fn capture_without_storage_persists_nothing() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let (_, mut plan, gate) =
        authorized_plan(tmp.path(), &[(Operation::RealTimeCapture, "object-a")]);
    plan.steps.push(step_for(Operation::RawStorage, "object-a"));
    let archive = tmp.path().join("must-not-exist.sbe");
    let durable_write = || -> anyhow::Result<()> {
        require_plan_step(&plan, Operation::RawStorage, &gate, 1)?;
        fs::write(&archive, b"durable").map_err(|error| anyhow::anyhow!("writing archive: {error}"))
    };
    assert!(
        durable_write().is_err(),
        "capture permission alone must not create an archive"
    );
    assert!(!archive.exists(), "no durable archive was created");
    assert!(
        require_plan_step(&plan, Operation::RealTimeCapture, &gate, 1).is_ok(),
        "capture itself remains authorized"
    );
}

#[test]
fn reference_retrieval_does_not_imply_capture() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let (_, plan, gate) =
        authorized_plan(tmp.path(), &[(Operation::ReferenceDataRetrieval, "ref-a")]);
    assert!(
        require_plan_step(&plan, Operation::ReferenceDataRetrieval, &gate, 1).is_ok(),
        "the declared retrieval is authorized"
    );
    assert!(
        require_plan_step(&plan, Operation::RealTimeCapture, &gate, 1).is_err(),
        "retrieval does not grant capture"
    );
}

#[test]
fn raw_storage_does_not_imply_replay() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let (_, plan, gate) = authorized_plan(tmp.path(), &[(Operation::RawStorage, "object-a")]);
    assert!(
        require_plan_step(&plan, Operation::Replay, &gate, 1).is_err(),
        "storage does not grant event-payload replay"
    );
    assert!(
        require_plan_step(&plan, Operation::RawStorage, &gate, 1).is_ok(),
        "storage itself is authorized"
    );
}

#[test]
fn wrong_http_resource_path_is_denied_before_dispatch() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let (_, plan, gate) = authorized_plan(tmp.path(), &[(Operation::RealTimeCapture, "object-a")]);
    let intent = match &plan.steps[0].request {
        PlanRequest::Egress(intent) => intent.clone(),
        PlanRequest::Local(_) => panic!("capture step must be an egress step"),
    };
    let calls = AtomicU64::new(0);
    let binding = HttpEgressRequest {
        intent: &intent,
        url: ENDPOINT,
        method: "GET",
        resource_class: "events/reference",
        approved_resource_class: "market-data/reference",
        approved_method: "GET",
        gate: &gate,
        at_us: 1,
    };
    let error = dispatch_http_request(&binding, || {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    })
    .expect_err("unapproved resource class is denied");
    assert!(
        format!("{error:#}").contains("resource class"),
        "denial names the resource class: {error:#}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "dispatch was never called");
    let wrong_url = HttpEgressRequest {
        url: "wss://other.invalid:443/reference",
        resource_class: "market-data/reference",
        ..binding
    };
    assert!(
        authorize_http_request(&wrong_url).is_err(),
        "the actual URL must match the authorized endpoint"
    );
}

#[test]
fn http_binding_uses_plan_declared_class_and_method() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let (_, plan, gate) = authorized_plan(tmp.path(), &[(Operation::RealTimeCapture, "object-a")]);
    let binding = http_request_for_plan_step(
        &plan,
        Operation::RealTimeCapture,
        ENDPOINT,
        "POST",
        "market-data/reference",
        &gate,
        1,
    )
    .expect("authorized plan step produces a binding");
    assert_eq!(
        binding.approved_method, "GET",
        "the method comes from the plan"
    );
    assert!(
        authorize_http_request(&binding).is_err(),
        "a method outside the declared step is denied"
    );
}

#[test]
fn redirect_to_unapproved_authority_is_denied() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let (_, plan, gate) = authorized_plan(tmp.path(), &[(Operation::RealTimeCapture, "object-a")]);
    let intent = match &plan.steps[0].request {
        PlanRequest::Egress(intent) => intent.clone(),
        PlanRequest::Local(_) => panic!("capture step must be an egress step"),
    };
    assert!(
        authorize_redirect_on(&intent, "wss://venue-a.invalid:443/v2", &gate, 1),
        "same-authority redirect is reauthorized"
    );
    assert!(
        !authorize_redirect_on(&intent, "wss://other.invalid:443/v2", &gate, 1),
        "a different authority is never followed"
    );
}

#[test]
fn wider_subscription_is_denied_before_send() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let (_, plan, gate) = authorized_plan(tmp.path(), &[(Operation::RealTimeCapture, "object-a")]);
    let intent = match &plan.steps[0].request {
        PlanRequest::Egress(intent) => intent.clone(),
        PlanRequest::Local(_) => panic!("capture step must be an egress step"),
    };
    let calls = AtomicU64::new(0);
    let send = || -> anyhow::Result<()> {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    };
    let denied = ws::send_plan_subscription(
        &plan,
        Operation::RealTimeCapture,
        &intent,
        ScopeSet::Named(vec![Modality::L2, Modality::L3]),
        &gate,
        1,
        send,
    )
    .expect_err("a wider subscription is denied");
    assert!(
        format!("{denied:#}").contains("no live proof"),
        "denial is a gate decision: {denied:#}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing was transmitted");
}

#[test]
fn denied_local_replay_reads_no_archive() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let settings = settings_with(tmp.path(), &[]);
    let gate = AuthorizationGate::new();
    let plan = OperationPlan::new(
        "replay-plan",
        vec![step_for(Operation::Replay, "archive-a")],
    )
    .expect("valid replay plan");
    let _ = settings;
    let archive = tmp.path().join("archive.sbe");
    fs::write(&archive, b"abstract-event-payload").expect("create local archive");
    let reads = AtomicU64::new(0);
    let read = || -> anyhow::Result<()> {
        reads.fetch_add(1, Ordering::SeqCst);
        fs::read(&archive).map(|_| ()).map_err(anyhow::Error::from)
    };
    let result = (|| -> anyhow::Result<()> {
        require_plan_step(&plan, Operation::Replay, &gate, 1)?;
        read()
    })();
    assert!(result.is_err(), "an unauthorized replay is denied");
    assert_eq!(reads.load(Ordering::SeqCst), 0, "no archive was read");
}

#[test]
fn denied_export_publishes_no_files() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let gate = AuthorizationGate::new();
    let plan = OperationPlan::new(
        "export-plan",
        vec![step_for(Operation::DerivedDataCreation, "artifact-a")],
    )
    .expect("valid export plan");
    let staging = tmp.path().join("staging");
    let publishes = AtomicU64::new(0);
    let publish = || -> anyhow::Result<()> {
        publishes.fetch_add(1, Ordering::SeqCst);
        fs::create_dir_all(&staging)?;
        fs::write(staging.join("rows.ndjson"), b"not-published")?;
        Ok(())
    };
    let result = (|| -> anyhow::Result<()> {
        require_plan_step(&plan, Operation::DerivedDataCreation, &gate, 1)?;
        publish()
    })();
    assert!(result.is_err(), "an unauthorized export is denied");
    assert_eq!(publishes.load(Ordering::SeqCst), 0, "no file was published");
    assert!(!staging.exists(), "no staging directory was created");
}

#[tokio::test]
async fn denied_websocket_does_not_reach_dns_tcp_tls_or_upgrade() {
    let transport = DenialTransport::default();
    let intent = EgressIntent::loopback_test();
    let options = ConnectOptions {
        venue: "venue-a".to_owned(),
        connect_timeout: Duration::from_millis(100),
        intent: Some(intent),
        denial_transport: Some(transport.clone()),
        ..ConnectOptions::default()
    };
    let error = ws::connect(ENDPOINT, &[], &options)
        .await
        .expect_err("ungated provider websocket denies");
    assert!(
        format!("{error:#}").contains("intent") || format!("{error:#}").contains("authorization"),
        "denial is an authorization decision: {error:#}"
    );
    assert!(transport.untouched(), "no network layer was reached");
}

#[test]
fn audit_event_carries_plan_step_and_boundary() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let settings = settings_with(tmp.path(), &[(Operation::RealTimeCapture, "object-a")]);
    let dir = tmp.path().join("plan-audit");
    let context = RightsContext::load(
        settings
            .governance
            .rights_file
            .as_deref()
            .expect("rights file"),
        &dir,
    )
    .expect("rights context");
    let (_, event): (fieldbook::rights::AuthorizationProof, DecisionAuditEvent) = context
        .authorize_with_context(
            &scope_for(Operation::RealTimeCapture, "object-a"),
            1,
            fieldbook::rights::AuditContext {
                plan_id: Some("plan-abstract".to_owned()),
                step_id: Some("capture-object-a".to_owned()),
                side_effect_boundary: Some(SideEffectBoundary::ProviderContact.as_str().to_owned()),
                ..Default::default()
            },
        )
        .expect("audited grant");
    assert_eq!(event.plan_id.as_deref(), Some("plan-abstract"));
    assert_eq!(event.step_id.as_deref(), Some("capture-object-a"));
    assert_eq!(
        event.side_effect_boundary.as_deref(),
        Some("provider_contact")
    );
    let _ = AuditSink::new(&dir, 1).expect("audit directory is writable");
}
