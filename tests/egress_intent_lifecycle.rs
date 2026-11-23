// SPDX-License-Identifier: Apache-2.0
//! Abstract-value tests for caller-supplied egress intent and active sessions.
//!
//! Every value below is a scalar identifier, an abstract instant or a reserved
//! `.invalid` host. No provider is contacted, no market observation is created,
//! and the `market-shaped-tests` feature stays disabled.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "offline governance tests use explicit assertion helpers"
)]
#![allow(
    clippy::allow_attributes,
    reason = "test crates relax the production lint set wholesale"
)]

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use fieldbook::{
    egress::authorize_redirect_on,
    egress_intent::{EgressIntent, InMemoryAuthority, MAX_LEASE_DURATION},
    rights::{
        AuditSink, AuthorizationGate, AuthorizationProof, AuthorizationScope, DecisionAudit,
        DeliveryMethod, Licensee, Modality, Operation, Purpose, Recipient, Retention,
        RetentionLimit, RightsContext, RightsFile, ScopeSet, TimeWindow, UsageMode, UsageRight,
    },
    taxonomy::CountryCode,
    ws::{self, ConnectOptions, DenialTransport},
};

const ENDPOINT: &str = "wss://venue-a.example:443";

type Mutation = (&'static str, fn(&mut EgressIntent));

fn scope() -> AuthorizationScope {
    AuthorizationScope::request()
        .licensee(Licensee::new("licensee-a").expect("licensee"))
        .venue("venue-a")
        .provider_id("provider-a")
        .source_id("source-a")
        .dataset_id("quotes")
        .product_id("product-a")
        .segment("venue-a-equity-cash")
        .territory(CountryCode::new("US").expect("country"))
        .operation(Operation::RealTimeCapture)
        .usage_right(UsageRight::HistoricalStorage)
        .usage_mode(UsageMode::NonDisplay)
        .recipient(Recipient::Internal)
        .purpose(Purpose::ProprietaryOwnAccountTradingResearch)
        .delivery_method(DeliveryMethod::Stream)
        .retention(Retention::bounded(86_400))
        .instruments(ScopeSet::Named(vec!["inst-a".to_owned()]))
        .fields(ScopeSet::Named(vec!["bid".to_owned()]))
        .modalities(ScopeSet::Named(vec![Modality::L2]))
        .data_time_window(TimeWindow {
            from_us: Some(1_000),
            to_us: Some(9_000),
        })
        .endpoint(ENDPOINT)
        .expect("approved endpoint")
        .build()
        .expect("abstract grant scope")
}

fn intent_for(scope: &AuthorizationScope) -> EgressIntent {
    EgressIntent::builder()
        .provider_id(scope.provider_id.clone())
        .source_id(scope.source_id.clone())
        .source_product_id(scope.product_id.clone())
        .venue_id(scope.venue.clone())
        .segment_id(scope.segment.clone())
        .dataset_id(scope.dataset_id.clone())
        .operation(scope.operation)
        .purpose(scope.purpose)
        .usage_mode(scope.usage_mode)
        .usage_right(scope.usage_right)
        .licensee(scope.licensee.clone())
        .recipient(scope.recipient)
        .territory(scope.territory.clone())
        .instruments(scope.instruments.clone())
        .fields(scope.fields.clone())
        .modalities(scope.modalities.clone())
        .data_time_window(scope.data_time_window)
        .retention_request(scope.retention)
        .delivery_method(scope.delivery_method)
        .endpoint_identity(
            scope
                .approved_endpoints
                .first()
                .cloned()
                .expect("approved endpoint"),
        )
        .build()
        .expect("abstract egress intent")
}

fn audit(dir: &Path) -> AuditSink {
    AuditSink::new(dir, 1).expect("audit sink")
}

fn proof_for(scope: &AuthorizationScope, lease_us: u64, issued_at_us: i64) -> AuthorizationProof {
    AuthorizationProof {
        scope: scope.clone(),
        at_us: issued_at_us,
        valid_from: 0,
        valid_until: None,
        licence_reference: "contract-1".to_owned(),
        licence_document_hash: "a".repeat(64),
        contract_revision: 1,
        registry_revision: 7,
        grant_snapshot_id: "snapshot-1".to_owned(),
        lease_duration_us: lease_us,
        recording_authority: "contract-registry".to_owned(),
    }
}

fn make_gate(
    tmp: &Path,
    scope: &AuthorizationScope,
) -> (AuthorizationGate, Arc<InMemoryAuthority>) {
    let gate = AuthorizationGate::new();
    let authority = Arc::new(InMemoryAuthority::new(7, "snapshot-1"));
    gate.install_with_authority(
        proof_for(scope, MAX_LEASE_DURATION.as_micros() as u64, 0),
        audit(&tmp.join("audit")),
        Some(authority.clone()),
    )
    .expect("install grant");
    (gate, authority)
}

fn event_with_decision(dir: &Path, decision: &str) -> bool {
    let Ok(entries) = fs::read_dir(dir) else {
        return false;
    };
    entries.into_iter().any(|entry| {
        let Ok(entry) = entry else {
            return false;
        };
        fs::read_to_string(entry.path())
            .unwrap_or_default()
            .contains(decision)
    })
}

fn written_file(tmp: &Path, scope: &AuthorizationScope) -> PathBuf {
    let audit_dir = tmp.join("rights-audit");
    let context = RightsContext::load(&rights_file(tmp, scope), &audit_dir).expect("rights load");
    context
        .authorize(scope, 1)
        .expect("abstract grant authorizes its own scope");
    audit_dir
}

fn rights_file(tmp: &Path, scope: &AuthorizationScope) -> PathBuf {
    let file = RightsFile {
        schema_version: 1,
        licensee: scope.licensee.clone(),
        territory: "US".to_owned(),
        recipient: Recipient::Internal,
        rights: vec![fieldbook::rights::AuthorizationRecord {
            identity: fieldbook::rights::AuthorizationIdentity {
                scope: scope.clone(),
                valid_from: 0,
                valid_until: None,
            },
            decision: fieldbook::rights::RightDecision::Permitted,
            audit: DecisionAudit {
                licence_reference: "contract-1".to_owned(),
                licence_document_hash: "a".repeat(64),
                contract_revision: 1,
                recorded_at_us: 0,
                authority: "contract-registry".to_owned(),
            },
        }],
    };
    let path = tmp.join("rights.toml");
    fs::write(&path, toml::to_string(&file).expect("serialize rights")).expect("write rights");
    path
}

#[test]
fn exact_grant_permits_and_audits_before_egress() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let granted = scope();
    let (gate, _authority) = make_gate(tmp.path(), &granted);
    let intent = intent_for(&granted);

    gate.require_egress(&intent, 1)
        .expect("exact grant permits");
    assert!(
        event_with_decision(&tmp.path().join("audit"), "egress_permitted"),
        "a permitted egress event is committed before the caller proceeds"
    );
    assert!(
        event_with_decision(&tmp.path().join("audit"), "grant"),
        "the grant itself is audited"
    );
}

#[test]
fn every_declared_dimension_mismatch_denies() {
    let granted = scope();
    let mut mutations: Vec<Mutation> = vec![
        ("operation", |intent| {
            intent.operation = Operation::SourceContact
        }),
        ("provider", |intent| {
            intent.provider_id = "provider-b".to_owned()
        }),
        ("source", |intent| intent.source_id = "source-b".to_owned()),
        ("product", |intent| {
            intent.source_product_id = "product-b".to_owned()
        }),
        ("segment", |intent| {
            intent.segment_id = "venue-a-other".to_owned()
        }),
        ("dataset", |intent| {
            intent.dataset_id = "other-dataset".to_owned()
        }),
        ("venue", |intent| intent.venue_id = "venue-b".to_owned()),
        ("instrument", |intent| {
            intent.instruments = ScopeSet::Named(vec!["inst-b".to_owned()])
        }),
        ("field", |intent| {
            intent.fields = ScopeSet::Named(vec!["ask".to_owned()])
        }),
        ("modality", |intent| {
            intent.modalities = ScopeSet::Named(vec![Modality::L3])
        }),
        ("time window", |intent| {
            intent.data_time_window.to_us = Some(10_000)
        }),
        ("purpose", |intent| {
            intent.purpose = Purpose::InternalAnalysis
        }),
        ("recipient", |intent| intent.recipient = Recipient::Customer),
        ("territory", |intent| {
            intent.territory = CountryCode::new("GB").expect("GB")
        }),
        ("licensee", |intent| {
            intent.licensee = Licensee::new("licensee-b").expect("other licensee")
        }),
        ("usage right", |intent| {
            intent.usage_right = UsageRight::DerivedData
        }),
        ("usage mode", |intent| {
            intent.usage_mode = UsageMode::Display
        }),
        ("delivery", |intent| {
            intent.delivery_method = DeliveryMethod::File
        }),
        ("retention", |intent| {
            intent.retention_request = Retention {
                limit: RetentionLimit::Indefinite,
                purge_required: false,
            }
        }),
        ("endpoint", |intent| {
            intent.endpoint_identity = fieldbook::egress_intent::EndpointIdentity {
                scheme: "wss".to_owned(),
                host: "other.example".to_owned(),
                port: 443,
            }
        }),
    ];
    for (name, mutate) in mutations.drain(..) {
        let mut intent = intent_for(&granted);
        mutate(&mut intent);
        assert!(
            fieldbook::rights::default_gate()
                .require_egress(&intent, 1)
                .is_err(),
            "{name} mismatch must not become a permission"
        );
    }
    // The comparison is a pure gate property: an owned gate denies every
    // mutation even when a different grant is installed in the process.
    let tmp = tempfile::tempdir().expect("temporary directory");
    let (gate, _authority) = make_gate(tmp.path(), &granted);
    let owned_mutations: [Mutation; 4] = [
        ("operation", |intent| {
            intent.operation = Operation::SourceContact
        }),
        ("provider", |intent| {
            intent.provider_id = "provider-b".to_owned()
        }),
        ("product", |intent| {
            intent.source_product_id = "product-b".to_owned()
        }),
        ("segment", |intent| {
            intent.segment_id = "venue-a-other".to_owned()
        }),
    ];
    for (name, mutate) in owned_mutations {
        let mut intent = intent_for(&granted);
        mutate(&mut intent);
        assert!(
            gate.require_egress(&intent, 1).is_err(),
            "{name} mismatch must deny at an owned gate"
        );
    }
}

#[test]
fn missing_licensee_is_rejected_before_any_gate_check() {
    let missing = EgressIntent::builder().venue_id("venue-a").build();
    assert!(
        matches!(
            missing,
            Err(fieldbook::rights::RightsError::MissingField { .. })
        ),
        "a caller intent without a licensee cannot be built"
    );
}

#[test]
fn expired_grant_and_missing_audit_never_permit() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let path = rights_file(tmp.path(), &scope());
    let context = RightsContext::load(&path, &tmp.path().join("audit")).expect("rights load");
    let proof = context.authorize(&scope(), 1).expect("grant decision");
    let gate = AuthorizationGate::new();
    gate.install(proof, audit(&tmp.path().join("gate-audit")))
        .expect("install proof");
    let mut unapproved = intent_for(&scope());
    unapproved.endpoint_identity = fieldbook::egress_intent::EndpointIdentity {
        scheme: "wss".to_owned(),
        host: "other.example".to_owned(),
        port: 443,
    };
    assert!(
        gate.require_egress(&unapproved, 1).is_err(),
        "a request for an unapproved endpoint denies"
    );
    let empty = AuthorizationGate::new();
    assert!(
        empty.require_egress(&intent_for(&scope()), 1).is_err(),
        "an absent audit trail and absent proof cannot become permission"
    );
    assert!(
        !event_with_decision(&tmp.path().join("gate-audit"), "egress_permitted"),
        "no denial produced a permitted event"
    );
}

#[test]
fn audit_failure_prevents_installation_and_egress() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let blocker = tmp.path().join("blocker.json");
    fs::write(&blocker, "not a directory").expect("blocker file");
    let broken = AuditSink::without_probe(&blocker, 1);
    let gate = AuthorizationGate::new();
    assert!(
        gate.install(
            proof_for(&scope(), MAX_LEASE_DURATION.as_micros() as u64, 0),
            broken
        )
        .is_err(),
        "a grant that cannot be audited is not installed"
    );
    assert!(!gate.is_active(), "denial never installs authority");
}

#[test]
fn retention_exceed_denies_but_narrower_request_permits() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let (gate, _authority) = make_gate(tmp.path(), &scope());
    let mut narrow = intent_for(&scope());
    narrow.retention_request = Retention::bounded(60);
    assert!(
        gate.require_egress(&narrow, 1).is_ok(),
        "narrower retention fits"
    );
    let mut wide = intent_for(&scope());
    wide.retention_request = Retention {
        limit: RetentionLimit::Indefinite,
        purge_required: false,
    };
    assert!(
        gate.require_egress(&wide, 1).is_err(),
        "wider retention denies"
    );
}

#[test]
fn lease_expiry_renewal_and_authority_failure_are_audited() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let granted = scope();
    let intent = intent_for(&granted);
    let gate = AuthorizationGate::new();
    let authority = Arc::new(InMemoryAuthority::new(7, "snapshot-1"));
    gate.install_with_authority(
        proof_for(&granted, 10, 0),
        audit(&tmp.path().join("audit")),
        Some(authority.clone()),
    )
    .expect("install short lease");
    gate.renew_lease(&intent, 5).expect("renew before expiry");
    assert!(
        event_with_decision(&tmp.path().join("audit"), "lease_renewed"),
        "renewal is audited"
    );
    assert!(
        gate.require_egress(&intent, 12).is_ok(),
        "renewed lease is live"
    );

    let authority2 = Arc::new(InMemoryAuthority::new(7, "snapshot-1"));
    let gate2 = AuthorizationGate::new();
    gate2
        .install_with_authority(
            proof_for(&granted, 10, 0),
            audit(&tmp.path().join("audit2")),
            Some(authority2.clone()),
        )
        .expect("install short lease");
    assert!(
        matches!(gate2.require_egress(&intent, 11), Err(error) if error.to_string().contains("lease expired")),
        "lease expiry denies egress"
    );
    assert!(
        event_with_decision(&tmp.path().join("audit2"), "lease_expired"),
        "expiry is audited"
    );

    let authority3 = Arc::new(InMemoryAuthority::new(7, "snapshot-1"));
    let gate3 = AuthorizationGate::new();
    gate3
        .install_with_authority(
            proof_for(&granted, MAX_LEASE_DURATION.as_micros() as u64, 0),
            audit(&tmp.path().join("audit3")),
            Some(authority3.clone()),
        )
        .expect("install grant");
    authority3.set_failing(true);
    assert!(
        gate3.require_egress(&intent, 1).is_err(),
        "an unreachable authority fails closed"
    );
    authority3.set_failing(false);
    authority3.advance_revision(8, ["snapshot-2".to_owned()]);
    assert!(
        gate3.require_egress(&intent, 2).is_err(),
        "a policy revision invalidates the grant snapshot"
    );
    assert!(
        event_with_decision(&tmp.path().join("audit3"), "grant_revoked"),
        "revocation is audited"
    );
    authority3.revoke("snapshot-1");
    assert!(
        gate3.cancel(&intent, "operator requested stop", 3).is_err(),
        "an invalidated session is already gone"
    );
}

#[test]
fn cancellation_removes_the_active_session() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let granted = scope();
    let intent = intent_for(&granted);
    let (gate, _authority) = make_gate(tmp.path(), &granted);
    gate.cancel(&intent, "operator stop", 1)
        .expect("cancel session");
    assert!(
        event_with_decision(&tmp.path().join("audit"), "session_cancelled"),
        "cancellation is audited"
    );
    assert!(
        gate.require_egress(&intent, 2).is_err(),
        "cancelled session denies"
    );
}

#[test]
fn two_independent_authorizations_coexist_in_one_gate() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let first = scope();
    let mut second = scope();
    second.provider_id = "provider-b".to_owned();
    second.product_id = "product-b".to_owned();
    second.operation = Operation::ReferenceDataRetrieval;
    let gate = AuthorizationGate::new();
    gate.install(
        proof_for(&first, MAX_LEASE_DURATION.as_micros() as u64, 0),
        audit(&tmp.path().join("audit")),
    )
    .expect("first grant");
    gate.install(
        proof_for(&second, MAX_LEASE_DURATION.as_micros() as u64, 0),
        audit(&tmp.path().join("audit")),
    )
    .expect("second grant");
    assert!(
        gate.require_egress(&intent_for(&first), 1).is_ok(),
        "first grant permits egress"
    );
    assert!(
        gate.require_egress(&intent_for(&second), 1).is_ok(),
        "second grant permits egress"
    );
    let mut crossed = intent_for(&second);
    crossed.provider_id = "provider-a".to_owned();
    assert!(
        gate.require_egress(&crossed, 1).is_err(),
        "one provider cannot borrow another's grant"
    );
}

#[test]
fn redirect_to_unapproved_authority_is_denied() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let granted = scope();
    let intent = intent_for(&granted);
    let (gate, _authority) = make_gate(tmp.path(), &granted);

    assert!(
        authorize_redirect_on(&intent, "wss://venue-a.example:443/v2", &gate, 1),
        "a redirect inside the approved authority is reauthorized"
    );
    assert!(
        !authorize_redirect_on(&intent, "wss://other.example:443/feed", &gate, 1),
        "a different authority is never followed unchecked"
    );
    assert!(
        !authorize_redirect_on(&intent, "not a url", &gate, 1),
        "an unparseable redirect denies"
    );
}

#[test]
fn subscription_widening_is_reauthorized() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let granted = scope();
    let intent = intent_for(&granted);
    let (gate, _authority) = make_gate(tmp.path(), &granted);
    assert!(
        ws::recheck_subscription(&intent, ScopeSet::Named(vec![Modality::L2]), &gate, 1).is_ok(),
        "same subscription scope permits"
    );
    assert!(
        ws::recheck_subscription(
            &intent,
            ScopeSet::Named(vec![Modality::L2, Modality::L3]),
            &gate,
            1,
        )
        .is_err(),
        "widened subscription denies"
    );
}

#[tokio::test]
async fn denial_never_reaches_dns_tcp_tls_or_upgrade() {
    let transport = DenialTransport::default();
    let granted = scope();
    let mut intent = intent_for(&granted);
    intent = intent
        .for_endpoint("wss://venue-a.invalid:443")
        .expect("reserved test endpoint");
    let options = ConnectOptions {
        venue: "venue-a".to_owned(),
        connect_timeout: Duration::from_millis(100),
        intent: Some(intent),
        denial_transport: Some(transport.clone()),
        ..ConnectOptions::default()
    };
    // No authorization is installed in this test process, so the deny is at
    // the gate. The injected probe fails closed if any layer is reached.
    let error = ws::connect("wss://venue-a.invalid:443", &[], &options)
        .await
        .expect_err("ungated provider websocket must deny");
    assert!(
        format!("{error:#}").contains("authorization"),
        "the failure is an authorization denial: {error:#}"
    );
    assert!(
        transport.untouched(),
        "DNS/TCP/TLS/upgrade counters must all be zero on denial"
    );
}

#[test]
fn rights_file_root_consistency_and_actual_recording_authority() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let granted = scope();
    let mut file = RightsFile {
        schema_version: 1,
        licensee: Licensee::new("different-licensee").expect("licensee"),
        territory: "US".to_owned(),
        recipient: Recipient::Internal,
        rights: Vec::new(),
    };
    file.rights.push(fieldbook::rights::AuthorizationRecord {
        identity: fieldbook::rights::AuthorizationIdentity {
            scope: granted.clone(),
            valid_from: 0,
            valid_until: None,
        },
        decision: fieldbook::rights::RightDecision::Permitted,
        audit: DecisionAudit {
            licence_reference: "contract-1".to_owned(),
            licence_document_hash: "a".repeat(64),
            contract_revision: 1,
            recorded_at_us: 0,
            authority: "contract-registry".to_owned(),
        },
    });
    let contradictory = tmp.path().join("contradictory.toml");
    fs::write(&contradictory, toml::to_string(&file).expect("serialize")).expect("write");
    assert!(
        RightsContext::load(&contradictory, &tmp.path().join("audit-a")).is_err(),
        "a record that contradicts the root licensee is refused"
    );

    let audit_dir = written_file(tmp.path(), &granted);
    assert!(
        event_with_decision(&audit_dir, "contract-registry"),
        "the actual recording authority is preserved in audit events"
    );
    assert!(
        !event_with_decision(&audit_dir, "\"decision\":\"rights-file\""),
        "no literal placeholder authority is substituted"
    );
}
