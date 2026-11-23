// SPDX-License-Identifier: Apache-2.0
//! Abstract-value tests for the long-running authorization session path.
//!
//! Every identifier is a scalar, every endpoint is a reserved `.invalid` host,
//! every clock is abstract and every transport is injected. Frames are empty
//! idle frames: no market-shaped input, provider contact, experiment or data
//! action is created. The `market-shaped-tests` feature stays off.

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
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use tokio::sync::{Semaphore, broadcast, mpsc};

use fieldbook::{
    config::Settings,
    egress_intent::{
        AbstractClock, Clock, DecisionTime, MAX_LEASE_DURATION, revocation_propagation_bound,
    },
    governance::operation_plan::{
        OperationPlan, PlanDecision, PlanRequest, PlanStep, SessionAuthorization,
        SideEffectBoundary, authorize_plan_with_clock,
    },
    model::{Control, SourceId},
    rights::{
        Actor, AuditContext, AuthorizationGate, AuthorizationRecord, AuthorizationScope,
        DataObject, DecisionAudit, DeliveryMethod, Licensee, Modality, ObjectKind, Operation,
        Purpose, RecipientClass, RecipientIdentity, Retention, RightDecision, RightsFile, ScopeSet,
        TimeWindow, UsageMode, UsageRight,
    },
    session::{
        HeartbeatRequest, MarketDataSession, SessionFactory, SessionFrame, WorkerConfig,
        WorkerEvent, run_worker,
    },
    taxonomy::CountryCode,
};

const ENDPOINT: &str = "wss://venue-a.invalid:443";
const ABSOLUTE_WALL_US: i64 = 1_700_000_000_000_000;
const ABSOLUTE_MONOTONIC_US: u64 = 1_000;

fn capture_scope() -> AuthorizationScope {
    AuthorizationScope::request()
        .actor(Actor::FieldbookProducer)
        .data_object(
            DataObject::new(ObjectKind::RawSourceRecord, "object-a", "v1").expect("object"),
        )
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
        .recipient_class(RecipientClass::Internal)
        .recipient_identity(RecipientIdentity::new("recipient-a").expect("recipient"))
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
        .expect("reserved endpoint")
        .build()
        .expect("abstract grant")
}

fn capture_intent(scope: &AuthorizationScope) -> fieldbook::egress_intent::EgressIntent {
    fieldbook::egress_intent::EgressIntent::builder()
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
            scope
                .approved_endpoints
                .first()
                .cloned()
                .expect("reserved endpoint"),
        )
        .build()
        .expect("abstract intent")
}

fn capture_step() -> PlanStep {
    PlanStep {
        step_id: "capture".to_owned(),
        request: PlanRequest::Egress(capture_intent(&capture_scope())),
        grant_reference: "contract-abstract/1".to_owned(),
        approved_resource_class: Some("market-data/reference".to_owned()),
        approved_http_method: Some("GET".to_owned()),
        decision: PlanDecision::Pending,
        audit_reference: None,
        side_effect_boundary: SideEffectBoundary::ProviderContact,
    }
}

fn settings_with(tmp: &Path) -> Settings {
    let file = RightsFile {
        schema_version: 1,
        licensee: Licensee::new("licensee-a").expect("licensee"),
        territory: "US".to_owned(),
        recipient_class: RecipientClass::Internal,
        recipient_identity: RecipientIdentity::new("recipient-a").expect("recipient"),
        rights: vec![AuthorizationRecord {
            identity: fieldbook::rights::AuthorizationIdentity {
                scope: capture_scope(),
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
        }],
    };
    let path = tmp.join("rights.toml");
    fs::write(&path, toml::to_string(&file).expect("serialize rights")).expect("write rights");
    let mut settings = Settings::for_venue("venue-a");
    settings.governance.rights_file = Some(path);
    settings.governance.audit_dir = Some(tmp.join("audit"));
    settings
}

fn authorize(
    tmp: &Path,
    clock: Arc<AbstractClock>,
) -> fieldbook::governance::operation_plan::PlanAuthorization {
    let settings = settings_with(tmp);
    let gate = AuthorizationGate::new();
    let mut plan = OperationPlan::new("plan-session", vec![capture_step()]).expect("abstract plan");
    authorize_plan_with_clock(&settings, &mut plan, &gate, clock.as_ref()).expect("plan authorizes")
}

fn audit_dir(tmp: &Path) -> PathBuf {
    tmp.join("audit")
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

fn decisions_in(dir: &Path, decision: &str) -> usize {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .into_iter()
        .filter(|entry| {
            entry
                .as_ref()
                .ok()
                .and_then(|value| fs::read_to_string(value.path()).ok())
                .is_some_and(|text| text.contains(decision))
        })
        .count()
}

fn halted(events: &[(WorkerEvent, u64)]) -> Option<(&str, u64)> {
    events.iter().find_map(|(event, tick)| match event {
        WorkerEvent::AuthorizationHalted { reason, .. } => Some((reason.as_str(), *tick)),
        _ => None,
    })
}

#[derive(Debug, Default)]
struct FakeState {
    frames: AtomicUsize,
    closes: AtomicUsize,
    connects: AtomicUsize,
    subscriptions: std::sync::Mutex<Vec<BTreeSet<String>>>,
    tick_per_frame: AtomicU64,
}

struct FakeSession {
    state: Arc<FakeState>,
    clock: Arc<AbstractClock>,
}

#[async_trait]
impl MarketDataSession for FakeSession {
    fn heartbeat_spec(&self) -> fieldbook::session::HeartbeatSpec {
        fieldbook::session::HeartbeatSpec::disabled()
    }

    async fn connect(&mut self) -> Result<(), fieldbook::session::SessionFailure> {
        self.state.connects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn apply_subscriptions(
        &mut self,
        desired: &BTreeSet<String>,
    ) -> Result<(), fieldbook::session::SessionFailure> {
        self.state
            .subscriptions
            .lock()
            .expect("subscription lock")
            .push(desired.clone());
        Ok(())
    }

    /// An always-ready socket. Abstract monotonic time advances per read so a
    /// checkpoint deadline is crossed without any wall-clock sleep.
    async fn next_frame(&mut self) -> Result<SessionFrame, fieldbook::session::SessionFailure> {
        let index = self.state.frames.fetch_add(1, Ordering::SeqCst);
        // Yield so injected faults and controls are scheduled even when the
        // transport is always ready; a ready socket must not starve them.
        tokio::task::yield_now().await;
        let tick = self.state.tick_per_frame.load(Ordering::SeqCst);
        if tick > 0 {
            self.clock.advance_monotonic_us(tick);
        }
        if index >= 512 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        Ok(SessionFrame::idle(0))
    }

    async fn send_keepalive(
        &mut self,
    ) -> Result<HeartbeatRequest, fieldbook::session::SessionFailure> {
        Ok(HeartbeatRequest::default())
    }

    async fn request_snapshot(
        &mut self,
        _symbols: &[String],
    ) -> Result<(), fieldbook::session::SessionFailure> {
        Ok(())
    }

    async fn close(&mut self) {
        self.state.closes.fetch_add(1, Ordering::SeqCst);
    }
}

struct FakeFactory {
    state: Arc<FakeState>,
    clock: Arc<AbstractClock>,
}

#[async_trait]
impl SessionFactory for FakeFactory {
    async fn create_session(
        &self,
        _source: SourceId,
    ) -> anyhow::Result<Box<dyn MarketDataSession>> {
        Ok(Box::new(FakeSession {
            state: Arc::clone(&self.state),
            clock: Arc::clone(&self.clock),
        }))
    }
}

type FaultTrigger = dyn FnOnce(
    Arc<AbstractClock>,
    Arc<fieldbook::egress_intent::InMemoryAuthority>,
    Arc<FakeState>,
    mpsc::Sender<Control>,
);

async fn run_session(
    tmp: &Path,
    clock: Arc<AbstractClock>,
    tick_per_frame: u64,
    stop_after_frames: usize,
    on_start: Box<FaultTrigger>,
) -> (Vec<(WorkerEvent, u64)>, Arc<FakeState>) {
    let authorization = authorize(tmp, Arc::clone(&clock));
    let authority = authorization.live_authority.clone();
    let session = SessionAuthorization::new(authorization, Arc::clone(&clock) as Arc<dyn Clock>)
        .expect("session");
    let state = Arc::new(FakeState {
        tick_per_frame: AtomicU64::new(tick_per_frame),
        ..FakeState::default()
    });
    let (command_tx, command_rx) = mpsc::channel(8);
    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let config = WorkerConfig {
        status_interval: Duration::from_secs(3_600),
        idle_timeout: Duration::from_secs(3_600),
        reconnect_after: Duration::from_secs(3_600),
        reconnect_base_backoff: Duration::from_millis(10),
        reconnect_max_backoff: Duration::from_millis(20),
        connect_permits: Arc::new(Semaphore::new(1)),
        journal: None,
        authorization: Some(session),
    };
    let worker = tokio::spawn(run_worker(
        Arc::new(FakeFactory {
            state: Arc::clone(&state),
            clock: Arc::clone(&clock),
        }),
        SourceId::new(0, 0),
        command_rx,
        event_tx,
        config,
        shutdown_rx,
    ));
    on_start(
        Arc::clone(&clock),
        authority,
        Arc::clone(&state),
        command_tx.clone(),
    );

    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(5);
    let mut observed = Vec::new();
    loop {
        if state.frames.load(Ordering::SeqCst) >= stop_after_frames && !observed.is_empty() {
            break;
        }
        // Poll in short slices: an always-ready transport need not emit a
        // worker event for every frame, so frame-count stop conditions must be
        // observed independently of the event channel.
        let received = tokio::time::timeout(Duration::from_millis(2), event_rx.recv()).await;
        match received {
            Ok(Some(event)) => {
                let tick = clock.monotonic_us();
                let is_halt = matches!(event, WorkerEvent::AuthorizationHalted { .. });
                observed.push((event, tick));
                if is_halt {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => {}
        }
        if state.frames.load(Ordering::SeqCst) >= stop_after_frames
            || tokio::time::Instant::now() >= deadline
        {
            break;
        }
    }
    let _ = shutdown_tx.send(());
    let _ = worker.await;
    drop(command_tx);
    (observed, state)
}

/// Wait until the injected transport has read at least `count` frames. All
/// faults are applied on that abstract boundary, never on a wall-clock sleep.
async fn after_frames(state: Arc<FakeState>, count: usize) {
    while state.frames.load(Ordering::SeqCst) < count {
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn checkpoint_fires_on_a_continuously_ready_socket() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let clock = Arc::new(AbstractClock::new(ABSOLUTE_WALL_US, ABSOLUTE_MONOTONIC_US));
    let (events, state) =
        run_session(tmp.path(), clock, 1_000_000, 40, Box::new(|_, _, _, _| {})).await;
    assert!(
        state.frames.load(Ordering::SeqCst) > 3,
        "the injected transport was read continuously"
    );
    let count = decisions_in(&audit_dir(tmp.path()), "authorization_checkpoint");
    assert!(
        count >= 2,
        "a ready socket did not starve the checkpoint: {count} checkpoint audit events"
    );
    assert!(
        halted(&events).is_none(),
        "a live grant does not halt the session"
    );
}

#[tokio::test]
async fn lease_expiry_stops_receive_and_does_not_follow_the_wall_clock() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let clock = Arc::new(AbstractClock::new(ABSOLUTE_WALL_US, ABSOLUTE_MONOTONIC_US));
    let lease = MAX_LEASE_DURATION.as_micros() as u64;
    let (events, state) = run_session(
        tmp.path(),
        Arc::clone(&clock),
        0,
        200,
        Box::new(move |clock, _, state, _| {
            tokio::spawn(async move {
                after_frames(state, 4).await;
                // A wall-clock jump in either direction cannot move a
                // monotonic lease deadline. Only the monotonic advance below
                // may expire it.
                clock.set_wall_us(ABSOLUTE_WALL_US + 86_400_000_000);
                clock.advance_monotonic_us(lease.saturating_add(1));
            });
        }),
    )
    .await;
    let (reason, _) = halted(&events).expect("lease expiry halts the session");
    assert!(
        reason.contains("lease expired"),
        "halt reason is the lease expiry: {reason}"
    );
    assert!(
        state.closes.load(Ordering::SeqCst) >= 1,
        "transport was closed after the halt"
    );
    assert!(
        event_with_decision(&audit_dir(tmp.path()), "lease_expired"),
        "expiry is committed to the final audit state"
    );
    assert!(
        event_with_decision(&audit_dir(tmp.path()), "session_halted"),
        "the halted session accounts for buffered work"
    );
}

#[tokio::test]
async fn revocation_stops_within_the_measured_abstract_bound() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let clock = Arc::new(AbstractClock::new(ABSOLUTE_WALL_US, ABSOLUTE_MONOTONIC_US));
    let revoked_at = Arc::new(AtomicU64::new(0));
    let observed_revocation = Arc::clone(&revoked_at);
    let (events, _) = run_session(
        tmp.path(),
        Arc::clone(&clock),
        100_000,
        200,
        Box::new(move |clock, authority, state, _| {
            let revoked_at = observed_revocation;
            tokio::spawn(async move {
                after_frames(state, 4).await;
                let snapshot = authority
                    .snapshot_ids()
                    .into_iter()
                    .next()
                    .expect("installed snapshot");
                revoked_at.store(clock.monotonic_us(), Ordering::SeqCst);
                authority.revoke(&snapshot);
            });
        }),
    )
    .await;
    let (reason, observed_halt) = halted(&events).expect("revocation halts the session");
    assert!(
        reason.contains("grant snapshot is no longer valid"),
        "halt reason is revocation: {reason}"
    );
    let elapsed = observed_halt.saturating_sub(revoked_at.load(Ordering::SeqCst));
    let bound = revocation_propagation_bound().as_micros() as u64;
    assert!(
        elapsed <= bound,
        "measured stop {elapsed}us must be <= bound {bound}us"
    );
    assert!(
        elapsed <= MAX_LEASE_DURATION.as_micros() as u64,
        "measured stop also respects lease expiry"
    );
    assert!(
        event_with_decision(&audit_dir(tmp.path()), "grant_revoked"),
        "revocation is committed to the audit trail"
    );
}

#[tokio::test]
async fn authority_unavailable_stops_the_session() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let clock = Arc::new(AbstractClock::new(ABSOLUTE_WALL_US, ABSOLUTE_MONOTONIC_US));
    let (events, _) = run_session(
        tmp.path(),
        Arc::clone(&clock),
        250_000,
        200,
        Box::new(move |_, authority, state, _| {
            tokio::spawn(async move {
                after_frames(state, 4).await;
                authority.set_failing(true);
            });
        }),
    )
    .await;
    let (reason, _) = halted(&events).expect("an unreachable authority halts the session");
    assert!(
        reason.contains("authority could not be refreshed"),
        "the failure is fail-closed: {reason}"
    );
}

#[test]
fn renewal_with_a_failed_audit_commit_never_extends_the_lease() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let clock = Arc::new(AbstractClock::new(ABSOLUTE_WALL_US, ABSOLUTE_MONOTONIC_US));
    let authorization = authorize(tmp.path(), Arc::clone(&clock));
    let intent = fieldbook::egress_intent::EgressIntent::builder()
        .provider_id("provider-a")
        .source_id("source-a")
        .source_product_id("product-a")
        .venue_id("venue-a")
        .segment_id("venue-a-equity-cash")
        .dataset_id("quotes")
        .actor(Actor::FieldbookProducer)
        .operation(Operation::RealTimeCapture)
        .data_object(
            DataObject::new(ObjectKind::RawSourceRecord, "object-a", "v1").expect("object"),
        )
        .purpose(Purpose::ProprietaryOwnAccountTradingResearch)
        .usage_mode(UsageMode::NonDisplay)
        .usage_right(UsageRight::HistoricalStorage)
        .licensee(Licensee::new("licensee-a").expect("licensee"))
        .recipient_class(RecipientClass::Internal)
        .recipient_identity(RecipientIdentity::new("recipient-a").expect("recipient"))
        .territory(CountryCode::new("US").expect("country"))
        .instruments(ScopeSet::Named(vec!["inst-a".to_owned()]))
        .fields(ScopeSet::Named(vec!["bid".to_owned()]))
        .modalities(ScopeSet::Named(vec![Modality::L2]))
        .data_time_window(TimeWindow {
            from_us: Some(1_000),
            to_us: Some(9_000),
        })
        .retention_request(Retention::bounded(86_400))
        .delivery_method(DeliveryMethod::Stream)
        .endpoint_identity(
            fieldbook::egress_intent::EndpointIdentity::from_url(ENDPOINT).expect("endpoint"),
        )
        .build()
        .expect("intent");
    let before = authorization
        .gate
        .session_lease(&intent)
        .expect("live session");
    authorization.gate.set_audit_failure(true);
    let time = DecisionTime {
        wall_us: ABSOLUTE_WALL_US + 1_000,
        monotonic_us: before
            .lease_deadline_monotonic_us
            .map(|deadline| deadline.saturating_sub(1_000)),
    };
    assert!(
        authorization
            .gate
            .renew_lease_with_time(&intent, time, AuditContext::default())
            .is_err(),
        "a renewal whose audit cannot commit is denied"
    );
    let after = authorization
        .gate
        .session_lease(&intent)
        .expect("session is still live but not extended");
    assert_eq!(
        after.lease_epoch, before.lease_epoch,
        "epoch did not advance"
    );
    assert_eq!(
        after.lease_deadline_monotonic_us, before.lease_deadline_monotonic_us,
        "monotonic deadline did not extend"
    );
    assert_eq!(
        after.expires_at_us, before.expires_at_us,
        "wall expiry did not extend"
    );
    assert!(
        authorization.gate.reconciliation_evidence().is_empty(),
        "no state transition happened, so no reconciliation evidence is needed"
    );
    authorization.gate.set_audit_failure(false);
    assert!(
        authorization
            .gate
            .require_egress_with_time(&intent, time, AuditContext::default())
            .is_ok(),
        "the unchanged lease still authorizes before its deadline"
    );
}

#[test]
fn cancel_and_revocation_keep_audit_before_state_with_reconciliation() {
    let clock = Arc::new(AbstractClock::new(ABSOLUTE_WALL_US, ABSOLUTE_MONOTONIC_US));
    let temp_a = tempfile::tempdir().expect("temporary directory");
    let revoked = authorize(temp_a.path(), Arc::clone(&clock));
    let intent = capture_intent(&capture_scope());
    let time = DecisionTime {
        wall_us: ABSOLUTE_WALL_US + 2_000,
        monotonic_us: Some(ABSOLUTE_MONOTONIC_US + 2_000),
    };
    revoked.gate.set_audit_failure(true);
    let snapshot = revoked
        .live_authority
        .snapshot_ids()
        .into_iter()
        .next()
        .expect("installed snapshot");
    revoked.live_authority.revoke(&snapshot);
    assert!(
        revoked
            .gate
            .require_egress_with_time(&intent, time, AuditContext::default())
            .is_err(),
        "a revoked snapshot denies before any side effect"
    );
    assert_eq!(
        revoked.gate.active_count(),
        0,
        "revoked session is not active"
    );
    assert!(
        !event_with_decision(&audit_dir(temp_a.path()), "grant_revoked"),
        "an uncommitted revocation event was not written"
    );
    let evidence = revoked.gate.reconciliation_evidence();
    assert_eq!(evidence.len(), 1, "the failed decision is retained");
    assert_eq!(evidence[0].decision, "grant_revoked");
    assert_eq!(
        evidence[0].context.event_kind.as_deref(),
        Some("revocation")
    );

    let temp_b = tempfile::tempdir().expect("temporary directory");
    let cancelled = authorize(temp_b.path(), Arc::clone(&clock));
    cancelled.gate.set_audit_failure(true);
    assert!(
        cancelled
            .gate
            .cancel(&intent, "operator stop", ABSOLUTE_WALL_US + 3_000)
            .is_err(),
        "a cancel whose audit cannot commit is reported as failed"
    );
    assert_eq!(
        cancelled.gate.active_count(),
        0,
        "cancel cannot leave activity live"
    );
    assert!(
        !event_with_decision(&audit_dir(temp_b.path()), "session_cancelled"),
        "an uncommitted cancellation was not written"
    );
    let evidence = cancelled.gate.reconciliation_evidence();
    assert_eq!(evidence.len(), 1, "cancellation evidence is retained");
    assert_eq!(evidence[0].decision, "session_cancelled");
}

#[test]
fn restart_requires_fresh_authorization_before_resuming() {
    let clock = Arc::new(AbstractClock::new(ABSOLUTE_WALL_US, ABSOLUTE_MONOTONIC_US));
    let temp_a = tempfile::tempdir().expect("temporary directory");
    let stale = authorize(temp_a.path(), Arc::clone(&clock));
    let snapshot = stale
        .live_authority
        .snapshot_ids()
        .into_iter()
        .next()
        .expect("installed snapshot");
    stale.live_authority.revoke(&snapshot);
    assert!(
        SessionAuthorization::resume(stale, Arc::clone(&clock) as Arc<dyn Clock>).is_err(),
        "a stale authorization cannot be resumed"
    );

    let temp_b = tempfile::tempdir().expect("temporary directory");
    let fresh = authorize(temp_b.path(), Arc::clone(&clock));
    let session = SessionAuthorization::resume(fresh, Arc::clone(&clock) as Arc<dyn Clock>)
        .expect("fresh authorization reauthorizes before activity");
    assert!(!session.is_halted(), "the fresh session is live");
}

#[tokio::test]
async fn widened_subscription_is_rechecked_before_transmission() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let clock = Arc::new(AbstractClock::new(ABSOLUTE_WALL_US, ABSOLUTE_MONOTONIC_US));
    let (events, state) = run_session(
        tmp.path(),
        Arc::clone(&clock),
        100_000,
        200,
        Box::new(move |_, _, state, commands| {
            tokio::spawn(async move {
                after_frames(state, 4).await;
                let widened = BTreeSet::from(["inst-a".to_owned(), "inst-b".to_owned()]);
                let _ = commands.send(Control::SetSubscriptions(widened)).await;
            });
        }),
    )
    .await;
    let (reason, _) = halted(&events).expect("a widened subscription halts the session");
    assert!(
        reason.contains("subscription reauthorization denied"),
        "the denial is an authorization decision: {reason}"
    );
    let subscriptions = state.subscriptions.lock().expect("subscription lock");
    assert!(
        subscriptions.iter().all(|set| !set.contains("inst-b")),
        "the widened set never reached the transport"
    );
}

/// A clock whose monotonic reading advances on every observation. It models
/// an authority whose refresh consumes the whole declared budget.
#[derive(Debug)]
struct SteppingClock {
    wall_us: i64,
    tick: AtomicU64,
    step: u64,
}

impl Clock for SteppingClock {
    fn wall_us(&self) -> anyhow::Result<i64> {
        Ok(self.wall_us)
    }

    fn monotonic_us(&self) -> u64 {
        self.tick.fetch_add(self.step, Ordering::SeqCst)
    }
}

#[test]
fn refresh_timeout_halts_the_session_fail_closed() {
    let tmp = tempfile::tempdir().expect("temporary directory");
    let base = Arc::new(AbstractClock::new(ABSOLUTE_WALL_US, ABSOLUTE_MONOTONIC_US));
    let authorization = authorize(tmp.path(), Arc::clone(&base));
    let stepping = Arc::new(SteppingClock {
        wall_us: ABSOLUTE_WALL_US,
        tick: AtomicU64::new(ABSOLUTE_MONOTONIC_US),
        step: fieldbook::egress_intent::AUTHORITY_REFRESH_TIMEOUT.as_micros() as u64 + 1,
    });
    let mut session = SessionAuthorization::new(authorization, stepping).expect("session");
    assert!(
        session.checkpoint().is_err(),
        "a refresh that exhausts its monotonic budget is denied"
    );
    assert!(session.is_halted(), "the denial stops the session");
    assert!(
        event_with_decision(&audit_dir(tmp.path()), "session_halted"),
        "the timeout is committed as final audit state"
    );
}

#[test]
fn bound_formula_is_declared_and_never_exceeds_the_lease() {
    let bound = revocation_propagation_bound();
    assert!(
        bound <= MAX_LEASE_DURATION,
        "the propagation bound respects the lease ceiling"
    );
    assert!(
        bound.as_micros() as u64 > 0,
        "a concrete, nonzero bound is published"
    );
    assert_eq!(
        bound,
        fieldbook::egress_intent::CHECKPOINT_INTERVAL
            + fieldbook::egress_intent::AUTHORITY_REFRESH_TIMEOUT
            + fieldbook::egress_intent::MAX_SCHEDULER_LATENCY
            + fieldbook::egress_intent::MAX_CANCEL_LATENCY,
        "the bound is the declared four-term sum clipped to the lease"
    );
}
