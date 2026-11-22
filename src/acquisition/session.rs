//! Generic websocket supervisor. Exchange adapters implement
//! [`MarketDataSession`]; this module owns reconnects, heartbeats, status
//! reporting, and command handling.

use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::sync::{Semaphore, broadcast, mpsc};
use tracing::{info, warn};

use crate::{
    config::CollectorSettings,
    journal::{DecodeOutcome, JournalHandle, RawFrame},
    model::{
        Control, ExchangeEvent, HeartbeatState, ResetReason, SourceId, SourceStatus, TransportState,
    },
    protocol::{ControlOpcode, SendResult, TransportObservation},
    time::now_us,
};

/// The venue's heartbeat mechanism and the typed session signal are shared
/// with the journal through `crate::protocol`; re-export them here so
/// existing session-facing imports keep working.
pub use crate::protocol::{HeartbeatMechanism, SessionSignal};

/// A batch of normalized events decoded from one websocket payload.
#[derive(Debug, Default)]
pub struct SessionFrame {
    pub events: Vec<ExchangeEvent>,
    pub bytes: usize,
    /// Exact payload, retained for the raw-frame journal. Native transport
    /// control frames carry no application payload and leave this empty.
    pub raw: Option<RawFrame>,
    pub decode: DecodeOutcome,
    pub received_at_us: Option<i64>,
    /// What kind of observation this frame carries, typed at the adapter or
    /// transport boundary. Never inferred from an empty event list.
    pub signal: SessionSignal,
    /// The venue's heartbeat mechanism, assigned by the adapter.
    pub mechanism: HeartbeatMechanism,
    /// Every observation retained for this read, in worker observation order:
    /// the inbound data frame, or the native control exchange (inbound Ping
    /// followed by the outbound Pong response).
    pub observations: Vec<TransportObservation>,
    /// Set when an inbound control frame was observed but the outbound
    /// response could not be sent. The worker journals the evidence first and
    /// then treats the connection as unusable.
    pub transport_failure: Option<String>,
}

// The typed observation vocabulary lives in [`crate::protocol`] so the journal
// never depends on the session module. A heartbeat acknowledgement and a
// market event are different facts: a PONG must not update an instrument's
// market-data timestamp, and market data must never satisfy a heartbeat.

impl SessionFrame {
    #[must_use]
    pub fn idle(bytes: usize) -> Self {
        Self {
            events: Vec::new(),
            bytes,
            raw: None,
            decode: DecodeOutcome::default(),
            received_at_us: None,
            signal: SessionSignal::ProtocolControl,
            mechanism: HeartbeatMechanism::Disabled,
            observations: Vec::new(),
            transport_failure: None,
        }
    }

    /// A data (or ignorable application) payload. The typed inbound data
    /// observation is derived here and can be reclassified with
    /// [`SessionFrame::with_signal`] without losing the payload evidence.
    #[must_use]
    pub fn data(
        events: Vec<ExchangeEvent>,
        bytes: usize,
        raw: RawFrame,
        decode: DecodeOutcome,
        received_at_us: i64,
    ) -> Self {
        let signal = SessionSignal::MarketData;
        let observation = TransportObservation::inbound_data(
            raw.kind,
            raw.payload.clone(),
            signal.clone(),
            HeartbeatMechanism::Disabled,
        );
        Self {
            events,
            bytes,
            raw: Some(raw),
            decode,
            received_at_us: Some(received_at_us),
            signal,
            mechanism: HeartbeatMechanism::Disabled,
            observations: vec![observation],
            transport_failure: None,
        }
    }

    /// A native heartbeat acknowledgement as a control observation. Used by
    /// session-level tests and adapters that model a PONG without a data
    /// payload.
    #[must_use]
    pub fn heartbeat_ack(correlation: Option<Vec<u8>>) -> Self {
        let payload = correlation.clone().unwrap_or_default();
        let signal = SessionSignal::HeartbeatAck { correlation };
        Self {
            bytes: payload.len(),
            observations: vec![TransportObservation::inbound_control(
                ControlOpcode::Pong,
                payload,
                signal.clone(),
                HeartbeatMechanism::WebSocketControl,
            )],
            signal,
            mechanism: HeartbeatMechanism::WebSocketControl,
            ..Self::idle(0)
        }
    }

    /// Build a frame for a native WebSocket control read, preserving the
    /// inbound evidence and (for a peer Ping) the outbound Pong result.
    ///
    /// `pong_signal` is the venue's interpretation of an inbound native Pong:
    /// `HeartbeatAck` where native Pong acknowledges a client heartbeat
    /// (Kalshi), `ProtocolControl` where it does not (Polymarket).
    #[must_use]
    pub fn native_control(
        payload: crate::ws::WsPayload,
        response: Option<crate::ws::WsResponse>,
        mechanism: HeartbeatMechanism,
        pong_signal: SessionSignal,
        received_at_us: i64,
    ) -> Self {
        match payload {
            crate::ws::WsPayload::Ping(payload) => {
                let mut observations = vec![TransportObservation::inbound_control(
                    ControlOpcode::Ping,
                    payload.clone(),
                    SessionSignal::PeerPing,
                    mechanism,
                )];
                let mut bytes = payload.len();
                let mut transport_failure = None;
                if let Some(response) = response {
                    bytes = bytes.saturating_add(response.payload.len());
                    let send_result = match &response.result {
                        Ok(()) => SendResult::Sent,
                        Err(error) => {
                            transport_failure =
                                Some(format!("failed to answer a native ping: {error}"));
                            SendResult::Failed {
                                error: error.clone(),
                            }
                        }
                    };
                    observations.push(TransportObservation::outbound_control(
                        ControlOpcode::Pong,
                        response.payload,
                        SessionSignal::PeerPong,
                        mechanism,
                        send_result,
                    ));
                }
                Self {
                    bytes,
                    received_at_us: Some(received_at_us),
                    signal: SessionSignal::PeerPing,
                    mechanism,
                    observations,
                    transport_failure,
                    ..Self::idle(0)
                }
            }
            crate::ws::WsPayload::Pong(payload) => {
                let bytes = payload.len();
                Self {
                    bytes,
                    received_at_us: Some(received_at_us),
                    signal: pong_signal.clone(),
                    mechanism,
                    observations: vec![TransportObservation::inbound_control(
                        ControlOpcode::Pong,
                        payload,
                        pong_signal,
                        mechanism,
                    )],
                    ..Self::idle(0)
                }
            }
            // Data frames are decoded by the adapter, not here.
            _ => Self {
                received_at_us: Some(received_at_us),
                ..Self::idle(0)
            }
            .with_signal(SessionSignal::MarketData),
        }
    }

    /// Reclassify the frame signal, keeping data observations consistent.
    #[must_use]
    pub fn with_signal(mut self, signal: SessionSignal) -> Self {
        self.signal = signal.clone();
        for observation in &mut self.observations {
            observation.signal = signal.clone();
        }
        self
    }

    /// Attach the venue heartbeat mechanism to the frame and its
    /// observations.
    pub fn set_mechanism(&mut self, mechanism: HeartbeatMechanism) {
        self.mechanism = mechanism;
        for observation in &mut self.observations {
            observation.mechanism = mechanism;
        }
    }
}

/// Failure classification for an exchange session.
#[derive(Debug)]
pub enum SessionFailure {
    /// Transient transport failure: drop this socket, reconnect with backoff.
    Reconnect(anyhow::Error),
    /// The exchange sent data that could not be decoded. The raw payload is
    /// retained when the adapter reached the payload bytes.
    Decode {
        error: anyhow::Error,
        frame: Option<RawFrame>,
        received_at_us: i64,
    },
    /// A decoded frame violated the exchange protocol (sequence gap, server
    /// error). The raw payload is retained when one was read, so protocol
    /// rejects are journaled exactly like decode failures.
    Protocol {
        error: anyhow::Error,
        frame: Option<RawFrame>,
        received_at_us: i64,
    },
    /// Configuration or authentication failure: retrying cannot help.
    Fatal(anyhow::Error),
}

impl SessionFailure {
    /// A protocol violation observed before any payload was read (for
    /// example, a pending-command acknowledgement timeout).
    #[must_use]
    pub fn protocol(error: anyhow::Error) -> Self {
        Self::Protocol {
            error,
            frame: None,
            received_at_us: crate::time::now_us().unwrap_or(0),
        }
    }

    /// A protocol violation with the exact payload that triggered it.
    #[must_use]
    pub fn protocol_with_frame(error: anyhow::Error, frame: RawFrame, received_at_us: i64) -> Self {
        Self::Protocol {
            error,
            frame: Some(frame),
            received_at_us,
        }
    }
}

impl From<anyhow::Error> for SessionFailure {
    fn from(error: anyhow::Error) -> Self {
        Self::Reconnect(error)
    }
}

/// One websocket connection implementing an exchange protocol.
#[async_trait]
pub trait MarketDataSession: Send {
    /// The heartbeat contract this adapter's venue uses. The worker executes
    /// it without knowing whether the venue uses text frames or native
    /// WebSocket control frames.
    fn heartbeat_spec(&self) -> HeartbeatSpec {
        HeartbeatSpec::disabled()
    }

    async fn connect(&mut self) -> Result<(), SessionFailure>;
    /// Reconcile the server-side subscription with `desired`. Called after each
    /// successful connect and whenever the desired set changes.
    async fn apply_subscriptions(
        &mut self,
        desired: &BTreeSet<String>,
    ) -> Result<(), SessionFailure>;
    /// Read exactly one websocket payload (or a control frame) and decode it.
    async fn next_frame(&mut self) -> Result<SessionFrame, SessionFailure>;
    /// Send the venue's heartbeat and return the correlation the
    /// acknowledgement must carry (the PING payload for native control
    /// frames, `None` for a nonce-less text protocol).
    async fn send_keepalive(&mut self) -> Result<HeartbeatRequest, SessionFailure>;
    /// Ask the exchange for fresh snapshots without changing membership when
    /// supported; otherwise resubscribe the symbols.
    async fn request_snapshot(&mut self, symbols: &[String]) -> Result<(), SessionFailure>;
    async fn close(&mut self);
}

/// The correlation a successful heartbeat send established, plus the
/// outbound observation the worker must journal. `None` correlation means the
/// venue's mechanism carries no request nonce (application text), so the
/// single-outstanding window is the correlation rule.
#[derive(Debug, Clone, Default)]
pub struct HeartbeatRequest {
    pub correlation: Option<Vec<u8>>,
    /// Outbound observations retained only after the send succeeds.
    pub observations: Vec<TransportObservation>,
}

/// Creates sessions for a source. Implemented by each exchange adapter.
#[async_trait]
pub trait SessionFactory: Send + Sync + 'static {
    async fn create_session(&self, source: SourceId) -> anyhow::Result<Box<dyn MarketDataSession>>;
}

/// Events sent from a source worker to the coordinator.
#[derive(Debug)]
pub enum WorkerEvent {
    Events {
        source: SourceId,
        events: Vec<ExchangeEvent>,
    },
    Status(SourceStatus),
    /// The last subscription set this worker successfully applied to its
    /// session. Sent after `apply_subscriptions` returns `Ok` on connect and
    /// on control-driven reconciliation, never on periodic status. Symbols
    /// are native exchange identifiers.
    ///
    /// This is a local acceptance record: it proves the worker transmitted the
    /// subscription request, not that the venue emitted a wire
    /// acknowledgement. Per-symbol `snapshot-anchored` evidence is what the
    /// `coverage` command requires before certifying a universe.
    Subscribed {
        source: SourceId,
        symbols: Vec<String>,
    },
    Fatal {
        source: SourceId,
        error: String,
    },
    /// Confirmation that a recovery control was applied. The receive fence is
    /// the worker's last read `(connection_epoch, receive_seq)` at that
    /// moment. Snapshot events sent later by this worker carry a strictly
    /// greater fence, so the core can reject frames read before the request.
    RecoveryReady {
        source: SourceId,
        /// Exact native instruments this acknowledgement covers. A batch
        /// acknowledgement must enumerate every target it fenced.
        targets: Vec<String>,
        generation: u64,
        connection_epoch: u64,
        receive_seq: u64,
    },
    Stopped {
        source: SourceId,
    },
}

#[derive(Debug, Clone)]
pub struct WorkerConfig {
    pub status_interval: Duration,
    pub idle_timeout: Duration,
    pub reconnect_after: Duration,
    pub reconnect_base_backoff: Duration,
    pub reconnect_max_backoff: Duration,
    /// Shared across every worker so the process never exceeds the configured
    /// number of simultaneous websocket handshakes.
    pub connect_permits: Arc<Semaphore>,
    /// Raw-frame journal shared by every source worker.
    pub journal: Option<JournalHandle>,
}

/// The complete heartbeat contract an adapter supplies for its session.
/// Every threshold is a client policy parameter, not a venue guarantee.
#[derive(Debug, Clone, Copy)]
pub struct HeartbeatSpec {
    pub mechanism: HeartbeatMechanism,
    pub send_interval: Duration,
    /// How long a sent heartbeat may stay unanswered before it counts as
    /// missed. Monotonic.
    pub response_deadline: Duration,
    /// Misses in a row before the heartbeat state becomes `Suspect`.
    pub miss_threshold: u32,
    /// Misses in a row before the worker applies the reconnect action.
    pub reconnect_after_misses: u32,
}

impl HeartbeatSpec {
    /// The application-text contract for a 10-second venue heartbeat: a
    /// response deadline well under the send interval bounds detection; one
    /// missed response makes the connection suspect, three in a row
    /// reconnect it.
    #[must_use]
    pub fn ten_second_application_text() -> Self {
        Self {
            mechanism: HeartbeatMechanism::ApplicationText,
            send_interval: Duration::from_secs(10),
            response_deadline: Duration::from_secs(5),
            miss_threshold: 1,
            reconnect_after_misses: 3,
        }
    }

    /// The native WebSocket control contract: same client policy, different
    /// mechanism (ack correlation via the control payload).
    #[must_use]
    pub fn ten_second_websocket_control() -> Self {
        Self {
            mechanism: HeartbeatMechanism::WebSocketControl,
            send_interval: Duration::from_secs(10),
            response_deadline: Duration::from_secs(5),
            miss_threshold: 1,
            reconnect_after_misses: 3,
        }
    }

    /// No client-driven heartbeat: the worker sends nothing and the
    /// heartbeat state stays `Disabled`. The scheduling fields are zero:
    /// the absence of a schedule is represented by the mechanism, never by
    /// a sentinel duration.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            mechanism: HeartbeatMechanism::Disabled,
            send_interval: Duration::ZERO,
            response_deadline: Duration::ZERO,
            miss_threshold: 0,
            reconnect_after_misses: 0,
        }
    }

    /// Reject an adapter policy that cannot be executed before any socket
    /// opens. Invalid policy must fail during session setup, never cause a
    /// timer anomaly mid-run.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.mechanism == HeartbeatMechanism::Disabled {
            return Ok(());
        }
        anyhow::ensure!(
            !self.send_interval.is_zero(),
            "heartbeat send interval must be nonzero for an enabled mechanism"
        );
        anyhow::ensure!(
            !self.response_deadline.is_zero(),
            "heartbeat response deadline must be nonzero for an enabled mechanism"
        );
        anyhow::ensure!(
            self.miss_threshold >= 1,
            "heartbeat miss threshold must be at least 1 for an enabled mechanism"
        );
        anyhow::ensure!(
            self.reconnect_after_misses >= self.miss_threshold,
            "heartbeat reconnect threshold ({}) must be at least the miss              threshold ({})",
            self.reconnect_after_misses,
            self.miss_threshold
        );
        Ok(())
    }
}

impl WorkerConfig {
    #[must_use]
    pub fn from_settings(settings: &CollectorSettings) -> Self {
        Self {
            status_interval: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(settings.connection_idle_timeout_secs),
            reconnect_after: Duration::from_secs(settings.reconnect_after_secs),
            reconnect_base_backoff: Duration::from_millis(500),
            reconnect_max_backoff: Duration::from_secs(30),
            connect_permits: Arc::new(Semaphore::new(settings.connect_concurrency.max(1))),
            journal: None,
        }
    }
}

/// Supervisor task for one source.
pub async fn run_worker(
    factory: Arc<dyn SessionFactory>,
    source: SourceId,
    mut commands: mpsc::Receiver<Control>,
    events: mpsc::Sender<WorkerEvent>,
    config: WorkerConfig,
    mut shutdown: broadcast::Receiver<()>,
) {
    let mut desired = BTreeSet::new();
    let mut status = SourceStatus::new(source);
    let mut session: Option<Box<dyn MarketDataSession>> = None;
    let mut backoff = config.reconnect_base_backoff;
    let mut attempts = 0u64;
    // Local receive fence. The epoch changes on every successful connection;
    // the sequence is reset and then advanced for every frame read, before any
    // decoding or filtering can hide a frame from recovery ordering.
    let mut connection_epoch = 0u64;
    let mut receive_seq = 0u64;

    loop {
        if session.is_none() {
            match factory.create_session(source).await {
                Ok(new_session) => session = Some(new_session),
                Err(error) => {
                    let message = format!("{error:#}");
                    warn!(%source, error = %message, "failed to construct session");
                    let _ = events
                        .send(WorkerEvent::Fatal {
                            source,
                            error: message,
                        })
                        .await;
                    break;
                }
            }
        }

        let Some(active) = session.as_mut() else {
            break;
        };
        // The adapter owns the heartbeat contract; the worker executes it
        // without knowing the venue's mechanism. An invalid policy fails
        // during session setup - never as a timer anomaly mid-run.
        let spec = active.heartbeat_spec();
        if let Err(error) = spec.validate() {
            let message = format!("{error:#}");
            warn!(%source, error = %message, "invalid adapter heartbeat policy");
            let _ = events
                .send(WorkerEvent::Fatal {
                    source,
                    error: message,
                })
                .await;
            break;
        }
        let permit = tokio::select! {
            permit = config.connect_permits.clone().acquire_owned() => match permit {
                Ok(permit) => permit,
                Err(_) => {
                    close_and_stop(session.take(), &mut status, &events).await;
                    return;
                }
            },
            _ = shutdown.recv() => {
                close_and_stop(session.take(), &mut status, &events).await;
                return;
            }
        };
        let connect_result = active.connect().await;
        drop(permit);
        if let Err(failure) = connect_result {
            match failure {
                SessionFailure::Fatal(error) => {
                    let message = format!("{error:#}");
                    warn!(%source, error = %message, "fatal session error");
                    let _ = events
                        .send(WorkerEvent::Fatal {
                            source,
                            error: message,
                        })
                        .await;
                    break;
                }
                SessionFailure::Reconnect(error) | SessionFailure::Protocol { error, .. } => {
                    warn!(%source, error = %format!("{error:#}"), "connect failed");
                    status.last_error = Some(truncate_error(&error));
                    status.connected = false;
                    let _ = events.send(WorkerEvent::Status(status.clone())).await;
                }
                SessionFailure::Decode { error, .. } => {
                    warn!(%source, error = %format!("{error:#}"), "connect failed");
                    status.last_error = Some(truncate_error(&error));
                    status.connected = false;
                    let _ = events.send(WorkerEvent::Status(status.clone())).await;
                }
            }
            if let Some(mut failed) = session.take() {
                failed.close().await;
            }
            attempts = attempts.saturating_add(1);
            backoff = next_backoff(backoff, config.reconnect_max_backoff);
            if !backoff_or_stop(
                &mut commands,
                &mut desired,
                &events,
                &mut status,
                &mut shutdown,
                backoff,
                connection_epoch,
                receive_seq,
            )
            .await
            {
                close_and_stop(session.take(), &mut status, &events).await;
                return;
            }
            continue;
        }

        attempts = attempts.saturating_add(1);
        if attempts > 1 {
            status.reconnects = status.reconnects.saturating_add(1);
        }
        connection_epoch = connection_epoch.saturating_add(1);
        receive_seq = 0;
        status.connected = true;
        status.subscriptions = desired.len();
        status.last_error = None;
        status.transport_state = TransportState::Connected;
        // A fresh connection has answered nothing yet: the heartbeat state
        // honestly says so instead of claiming health. Book continuity is
        // untouched: a reconnect can only re-anchor books
        // through accepted recovery snapshots, never through connection
        // success.
        status.missed_heartbeats = 0;
        status.unmatched_heartbeats = 0;
        status.last_pong_received_us = None;
        status.heartbeat_rtt_us = None;
        status.heartbeat_state = if spec.mechanism == HeartbeatMechanism::Disabled {
            HeartbeatState::Disabled
        } else {
            HeartbeatState::AwaitingFirstAck
        };
        let mut tracker = HeartbeatTracker::new(spec);
        let now = Instant::now();
        let next_periodic_reconnect =
            now + config.reconnect_after + Duration::from_millis(rand::random::<u64>() % 60_000);
        let mut idle_deadline = now + config.idle_timeout;
        let mut next_keepalive = if spec.mechanism == HeartbeatMechanism::Disabled {
            None
        } else {
            Some(now + spec.send_interval)
        };
        let mut next_status = now + config.status_interval;

        if !desired.is_empty() {
            let reset = ExchangeEvent::StreamReset {
                native_symbols: desired.iter().cloned().collect(),
                reason: ResetReason::Connected,
                received_at_us: now_us().unwrap_or(0),
            };
            if events
                .send(WorkerEvent::Events {
                    source,
                    events: vec![reset],
                })
                .await
                .is_err()
            {
                break;
            }
        }
        if let Err(failure) = active.apply_subscriptions(&desired).await {
            warn!(%source, error = %format!("{failure:?}"), "subscription reconciliation failed");
            status.connected = false;
            status.subscriptions = 0;
            status.last_error = Some(failure_message(&failure));
            let _ = events.send(WorkerEvent::Status(status.clone())).await;
            if let Some(mut failed) = session.take() {
                failed.close().await;
            }
            attempts = attempts.saturating_add(1);
            backoff = next_backoff(backoff, config.reconnect_max_backoff);
            if !backoff_or_stop(
                &mut commands,
                &mut desired,
                &events,
                &mut status,
                &mut shutdown,
                backoff,
                connection_epoch,
                receive_seq,
            )
            .await
            {
                close_and_stop(session.take(), &mut status, &events).await;
                return;
            }
            continue;
        }
        status.subscriptions = desired.len();
        status.reconnects = status.reconnects.max(attempts.saturating_sub(1));
        backoff = config.reconnect_base_backoff;
        let _ = events
            .send(WorkerEvent::Subscribed {
                source,
                symbols: desired.iter().cloned().collect(),
            })
            .await;
        let _ = events.send(WorkerEvent::Status(status.clone())).await;
        info!(%source, subscriptions = desired.len(), "source connected");

        let mut must_reconnect = false;
        let mut should_stop = false;
        while !must_reconnect && !should_stop {
            // Drain already-queued controls before polling the socket. This
            // keeps subscription changes responsive even when frames arrive
            // continuously, without letting a ready frame be discarded.
            loop {
                match commands.try_recv() {
                    Ok(Control::Shutdown) | Err(mpsc::error::TryRecvError::Disconnected) => {
                        should_stop = true;
                        break;
                    }
                    Ok(Control::Reconnect(reason)) => {
                        warn!(%source, reason, "reconnect requested");
                        must_reconnect = true;
                        break;
                    }
                    Ok(action) => {
                        must_reconnect = handle_control(
                            action,
                            &mut desired,
                            &mut status,
                            &mut session,
                            &events,
                            connection_epoch,
                            receive_seq,
                        )
                        .await;
                        if must_reconnect {
                            break;
                        }
                    }
                    Err(mpsc::error::TryRecvError::Empty) => break,
                }
            }
            if must_reconnect || should_stop {
                status.transport_state = if should_stop {
                    TransportState::Stopped
                } else {
                    TransportState::Reconnecting
                };
                break;
            }

            let now = Instant::now();
            // Heartbeat accounting before any new send: an outstanding
            // heartbeat that passed its response deadline is a miss. A
            // heartbeat is missed because the deadline expired - never
            // because another scheduled send arrived (the one-outstanding
            // design below gates sends until the window closes).
            if tracker.on_deadline_check(now) {
                must_reconnect = true;
            }
            sync_heartbeat_state(&mut status, &tracker);
            if let Some(next) = next_keepalive
                && now >= next
            {
                if let Some(active) = session.as_mut() {
                    // One outstanding heartbeat: a new heartbeat is sent
                    // only when none is in flight. While one is outstanding
                    // the send is skipped; the miss is the deadline's
                    // verdict, not the next send's.
                    if tracker.can_send() {
                        match active.send_keepalive().await {
                            Ok(request) => {
                                // A successful send is evidence: retain the
                                // outbound request observation (text or native
                                // control) with its direction and send result.
                                if !journal_observations(
                                    source,
                                    connection_epoch,
                                    &mut status,
                                    config.journal.as_ref(),
                                    &events,
                                    &request.observations,
                                    now_us().unwrap_or(0),
                                )
                                .await
                                {
                                    should_stop = true;
                                }
                                // Only a successful send starts the response
                                // window; a failed attempt is a transport
                                // error and must not be recorded as a
                                // heartbeat send. The adapter supplies the
                                // correlation its venue's mechanism supports.
                                if tracker.on_ping_sent(now, request.correlation) {
                                    status.last_ping_sent_us = now_us().ok();
                                }
                            }
                            Err(failure) => {
                                warn!(%source, error = %format!("{failure:?}"), "keepalive failed");
                                status.last_error = Some(failure_message(&failure));
                                must_reconnect = true;
                            }
                        }
                    }
                }
                next_keepalive = Some(now + spec.send_interval);
            }
            if now >= next_status {
                let _ = events.send(WorkerEvent::Status(status.clone())).await;
                next_status = now + config.status_interval;
            }
            if now >= next_periodic_reconnect {
                info!(%source, "periodic websocket refresh");
                must_reconnect = true;
            }
            if now >= idle_deadline {
                warn!(%source, "websocket idle timeout");
                status.last_error = Some("idle timeout".to_owned());
                must_reconnect = true;
            }
            if must_reconnect || should_stop {
                break;
            }

            let wake = next_keepalive
                .unwrap_or(next_status)
                .min(next_status)
                .min(next_periodic_reconnect)
                .min(idle_deadline)
                .min(tracker.next_deadline().unwrap_or(next_status));
            let mut pending_control: Option<Control> = None;
            tokio::select! {
                // Prefer a ready frame. A dropped poll loses no data: the
                // read state lives in the session's transport, and a decoded
                // data frame is returned without further await points.
                biased;
                frame = read_next_frame(&mut session) => {
                    match frame {
                        Ok(mut frame) => {
                            // The frame's actual receive instant, captured
                            // before any await point. Heartbeat deadline and
                            // RTT accounting must use this - not the loop-top
                            // `now`, which was sampled before the asynchronous
                            // wait and can be arbitrarily stale by the time a
                            // frame arrives.
                            let frame_received_at = Instant::now();
                            let received_at_us = frame.received_at_us.unwrap_or_else(|| {
                                now_us().unwrap_or(0)
                            });
                            // Independent ingress evidence: count the data
                            // frame before journal ingress consumes its raw
                            // payload, and count a decoded order-book delta
                            // from the normalized events. These are separate
                            // boundaries from application and writer counts.
                            if frame.raw.is_some() {
                                status.data_frames_received =
                                    status.data_frames_received.saturating_add(1);
                            }
                            let decoded_delta_events = frame
                                .events
                                .iter()
                                .filter(|event| matches!(event, ExchangeEvent::LevelChange { .. }))
                                .count();
                            if decoded_delta_events > 0 {
                                status.delta_events_decoded = status
                                    .delta_events_decoded
                                    .saturating_add(decoded_delta_events as u64);
                            }
                            // The adapter owns the venue mechanism; the worker
                            // stamps it before journaling so every observation
                            // carries typed evidence.
                            frame.set_mechanism(spec.mechanism);
                            // One payload read, one fence advance, one journal
                            // record — before any decode or protocol decision.
                            // Native controls are journaled as observations and
                            // never advance the data fence.
                            if !journal_ingress(
                                source,
                                connection_epoch,
                                &mut receive_seq,
                                &mut status,
                                config.journal.as_ref(),
                                &events,
                                &mut frame,
                                received_at_us,
                            )
                            .await
                            {
                                should_stop = true;
                                break;
                            }
                            if let Some(error) = frame.transport_failure.take() {
                                // The inbound evidence was journaled; a failed
                                // transport response still makes the
                                // connection unusable.
                                warn!(%source, error = %error, "transport response failed");
                                status.last_error = Some(error);
                                must_reconnect = true;
                            }
                            stamp_frame(&mut frame, connection_epoch, receive_seq);
                            status.messages = status.messages.saturating_add(1);
                            status.last_frame_us = now_us().ok();
                            idle_deadline = Instant::now() + config.idle_timeout;
                            // A heartbeat acknowledgement is a different fact
                            // from market data: it updates heartbeat state and
                            // nothing else. Market data must never satisfy a
                            // heartbeat, and a PONG must never touch
                            // instrument activity. An acknowledgement is
                            // accepted only when a heartbeat is outstanding
                            // and the response arrives inside the policy's
                            // deadline; unsolicited, duplicate and late PONGs
                            // are recorded as unmatched and never restore
                            // health or clear a miss.
                            if let SessionSignal::HeartbeatAck { correlation } =
                                &frame.signal
                            {
                                // Wall-clock receipt from the frame itself
                                // (the transport stamped it on read), not the
                                // post-journal processing time.
                                status.last_pong_received_us = Some(received_at_us);
                                match tracker.on_ack_received(
                                    frame_received_at,
                                    correlation.as_deref(),
                                ) {
                                    HeartbeatAck::Matched { rtt_us } => {
                                        status.heartbeat_rtt_us = Some(rtt_us);
                                        // The heartbeat state itself is
                                        // synchronized from the tracker at the
                                        // top of the loop
                                        // (sync_heartbeat_state): the tracker
                                        // already returned to Healthy on a
                                        // matched response. Special-casing only
                                        // Suspect here would leave
                                        // AwaitingFirstAck stale and let the
                                        // status disagree with the tracker.
                                    }
                                    HeartbeatAck::Late => {
                                        status.unmatched_heartbeats = status
                                            .unmatched_heartbeats
                                            .saturating_add(1);
                                    }
                                    HeartbeatAck::Unsolicited => {
                                        status.unmatched_heartbeats = status
                                            .unmatched_heartbeats
                                            .saturating_add(1);
                                    }
                                    HeartbeatAck::Mismatched => {
                                        // A response with the wrong
                                        // correlation is not this request's
                                        // acknowledgement: unmatched, and the
                                        // window stays open.
                                        status.unmatched_heartbeats = status
                                            .unmatched_heartbeats
                                            .saturating_add(1);
                                    }
                                }
                            }
                            update_latency(&mut status, &frame.events);
                            if !frame.events.is_empty()
                                && events
                                    .send(WorkerEvent::Events {
                                        source,
                                        events: frame.events,
                                    })
                                    .await
                                    .is_err()
                            {
                                should_stop = true;
                            }
                        }
                        Err(failure) => {
                            match failure {
                                SessionFailure::Fatal(error) => {
                                    let message = format!("{error:#}");
                                    warn!(%source, error = %message, "fatal session error");
                                    let _ = events.send(WorkerEvent::Fatal {
                                        source,
                                        error: message,
                                    }).await;
                                    should_stop = true;
                                }
                                SessionFailure::Decode {
                                    error,
                                    frame,
                                    received_at_us,
                                } => {
                                    warn!(%source, error = %format!("{error:#}"), "websocket decode failed");
                                    // A malformed frame was physically received.
                                    // Count it at the transport boundary before
                                    // its decode failure is classified.
                                    if frame.is_some() {
                                        status.data_frames_received =
                                            status.data_frames_received.saturating_add(1);
                                    }
                                    status.messages = status.messages.saturating_add(1);
                                    status.decode_errors = status.decode_errors.saturating_add(1);
                                    status.last_error = Some(truncate_error(&error));
                                    // The payload is journaled with its stable
                                    // rejection category even though decoding
                                    // failed.
                                    if !journal_data(
                                        source,
                                        connection_epoch,
                                        &mut receive_seq,
                                        &mut status,
                                        config.journal.as_ref(),
                                        &events,
                                        frame,
                                        received_at_us,
                                        DecodeOutcome::rejected(decode_error_category(&error)),
                                        SessionSignal::MarketData,
                                        spec.mechanism,
                                    )
                                    .await
                                    {
                                        should_stop = true;
                                        break;
                                    }
                                    must_reconnect = true;
                                }
                                SessionFailure::Protocol {
                                    error,
                                    frame,
                                    received_at_us,
                                } => {
                                    warn!(%source, error = %format!("{error:#}"), "websocket protocol error");
                                    if frame.is_some() {
                                        status.data_frames_received =
                                            status.data_frames_received.saturating_add(1);
                                    }
                                    status.protocol_errors = status.protocol_errors.saturating_add(1);
                                    status.last_error = Some(truncate_error(&error));
                                    // A protocol reject is still a payload the
                                    // exchange sent: it advances the fence and
                                    // is journaled with its exact bytes.
                                    if !journal_data(
                                        source,
                                        connection_epoch,
                                        &mut receive_seq,
                                        &mut status,
                                        config.journal.as_ref(),
                                        &events,
                                        frame,
                                        received_at_us,
                                        DecodeOutcome::rejected("protocol_violation"),
                                        SessionSignal::MarketData,
                                        spec.mechanism,
                                    )
                                    .await
                                    {
                                        should_stop = true;
                                        break;
                                    }
                                    must_reconnect = true;
                                }
                                SessionFailure::Reconnect(error) => {
                                    warn!(%source, error = %format!("{error:#}"), "websocket read failed");
                                    status.last_error = Some(truncate_error(&error));
                                    must_reconnect = true;
                                }
                            }
                        }
                    }
                }
                _ = shutdown.recv() => {
                    should_stop = true;
                }
                command = commands.recv() => {
                    match command {
                        None | Some(Control::Shutdown) => should_stop = true,
                        Some(Control::Reconnect(reason)) => {
                            warn!(%source, reason, "reconnect requested");
                            must_reconnect = true;
                        }
                        Some(action) => pending_control = Some(action),
                    }
                }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {}
            }

            if let Some(action) = pending_control {
                must_reconnect = handle_control(
                    action,
                    &mut desired,
                    &mut status,
                    &mut session,
                    &events,
                    connection_epoch,
                    receive_seq,
                )
                .await;
            }
        }

        if should_stop {
            close_and_stop(session.take(), &mut status, &events).await;
            return;
        }

        status.connected = false;
        status.subscriptions = 0;
        let _ = events.send(WorkerEvent::Status(status.clone())).await;
        if let Some(mut old) = session.take() {
            old.close().await;
        }
        backoff = next_backoff(backoff, config.reconnect_max_backoff);
        if !backoff_or_stop(
            &mut commands,
            &mut desired,
            &events,
            &mut status,
            &mut shutdown,
            backoff,
            connection_epoch,
            receive_seq,
        )
        .await
        {
            close_and_stop(session.take(), &mut status, &events).await;
            return;
        }
    }

    status.connected = false;
    status.subscriptions = 0;
    let _ = events.send(WorkerEvent::Status(status)).await;
    let _ = events.send(WorkerEvent::Stopped { source }).await;
}

async fn handle_control(
    action: Control,
    desired: &mut BTreeSet<String>,
    status: &mut SourceStatus,
    session: &mut Option<Box<dyn MarketDataSession>>,
    events: &mpsc::Sender<WorkerEvent>,
    connection_epoch: u64,
    receive_seq: u64,
) -> bool {
    match action {
        Control::SetSubscriptions(next) => {
            *desired = next;
            status.subscriptions = desired.len();
            let mut reconnect = false;
            if let Some(active) = session.as_mut()
                && let Err(failure) = active.apply_subscriptions(desired).await
            {
                warn!(
                    source = %status.source,
                    error = %format!("{failure:?}"),
                    "failed to update subscriptions"
                );
                status.last_error = Some(failure_message(&failure));
                reconnect = true;
            }
            if !reconnect {
                let _ = events
                    .send(WorkerEvent::Subscribed {
                        source: status.source,
                        symbols: desired.iter().cloned().collect(),
                    })
                    .await;
            }
            let _ = events.send(WorkerEvent::Status(status.clone())).await;
            reconnect
        }
        Control::RequestSnapshot(symbols) => {
            if let Some(active) = session.as_mut()
                && let Err(failure) = active.request_snapshot(&symbols).await
            {
                warn!(
                    source = %status.source,
                    error = %format!("{failure:?}"),
                    "snapshot request failed"
                );
                status.last_error = Some(failure_message(&failure));
                return true;
            }
            false
        }
        Control::Recover {
            generation,
            symbols,
            reconnect,
        } => {
            // Acknowledge before any action can push frames back through the
            // same event channel. The fence is the last frame read before this
            // control was applied; any later recovery snapshot must be newer.
            let ack = WorkerEvent::RecoveryReady {
                source: status.source,
                targets: symbols.clone(),
                generation,
                connection_epoch,
                receive_seq,
            };
            if reconnect {
                let _ = events.send(ack).await;
                warn!(source = %status.source, generation, "recovery reconnect requested");
                return true;
            }
            let mut failed = false;
            if let Some(active) = session.as_mut()
                && let Err(failure) = active.request_snapshot(&symbols).await
            {
                warn!(
                    source = %status.source,
                    error = %format!("{failure:?}"),
                    "recovery snapshot request failed"
                );
                status.last_error = Some(failure_message(&failure));
                failed = true;
            }
            let _ = events.send(ack).await;
            failed
        }
        Control::Reconnect(reason) => {
            warn!(source = %status.source, reason, "reconnect requested");
            true
        }
        Control::Shutdown => false,
    }
}

/// Read one frame for the supervisor's `select!`.
///
/// Cancellation safety lives in the session contract, not in a buffer here: a
/// poll dropped while awaiting a read loses no data because the transport
/// keeps read state inside the session, and a decoded data frame is returned
/// without further await points. Control-frame handling that does await
/// (Kalshi's reconcile and rate-limit backoff) is re-driven by its
/// acknowledgement timeout, which self-heals through a reconnect.
async fn read_next_frame(
    session: &mut Option<Box<dyn MarketDataSession>>,
) -> Result<SessionFrame, SessionFailure> {
    match session.as_mut() {
        Some(active) => active.next_frame().await,
        None => Err(SessionFailure::Reconnect(anyhow::anyhow!(
            "missing session"
        ))),
    }
}

async fn close_and_stop(
    session: Option<Box<dyn MarketDataSession>>,
    status: &mut SourceStatus,
    events: &mpsc::Sender<WorkerEvent>,
) {
    if let Some(mut session) = session {
        session.close().await;
    }
    status.connected = false;
    status.subscriptions = 0;
    status.transport_state = TransportState::Stopped;
    let _ = events.send(WorkerEvent::Status(status.clone())).await;
    let _ = events
        .send(WorkerEvent::Stopped {
            source: status.source,
        })
        .await;
}

/// During backoff, keep accepting control messages so subscription changes and
/// shutdown do not have to wait for the retry timer.
#[expect(
    clippy::too_many_arguments,
    reason = "reconnect bookkeeping spans the command channel, desired set, journal and clock"
)]
async fn backoff_or_stop(
    commands: &mut mpsc::Receiver<Control>,
    desired: &mut BTreeSet<String>,
    events: &mpsc::Sender<WorkerEvent>,
    status: &mut SourceStatus,
    shutdown: &mut broadcast::Receiver<()>,
    duration: Duration,
    connection_epoch: u64,
    receive_seq: u64,
) -> bool {
    status.transport_state = TransportState::Backoff;
    let _ = events.send(WorkerEvent::Status(status.clone())).await;
    let sleep = tokio::time::sleep(duration);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            _ = &mut sleep => return true,
            _ = shutdown.recv() => return false,
            command = commands.recv() => match command {
                None | Some(Control::Shutdown) => return false,
                Some(Control::SetSubscriptions(next)) => {
                    *desired = next;
                    status.subscriptions = desired.len();
                    let _ = events.send(WorkerEvent::Status(status.clone())).await;
                }
                Some(Control::Recover {
                    generation,
                    reconnect: _,
                    symbols,
                }) => {
                    // No frame can be read while backing off. The next
                    // connection increments the epoch, which makes any
                    // subsequent exchange snapshot strictly newer than this
                    // acknowledgement.
                    let _ = events
                        .send(WorkerEvent::RecoveryReady {
                            source: status.source,
                            targets: symbols,
                            generation,
                            connection_epoch,
                            receive_seq,
                        })
                        .await;
                }
                Some(Control::Reconnect(_)) | Some(Control::RequestSnapshot(_)) => {}
            },
        }
    }
}

fn next_backoff(current: Duration, maximum: Duration) -> Duration {
    let doubled = current.saturating_mul(2).min(maximum);
    let jitter = 0.8 + rand::random::<f64>() * 0.4;
    doubled.mul_f64(jitter).min(maximum)
}

/// The outcome of a heartbeat acknowledgement attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatAck {
    /// An eligible acknowledgement of the outstanding heartbeat inside the
    /// response deadline, correlated where the mechanism supplies it.
    Matched { rtt_us: i64 },
    /// An acknowledgement that arrived past the response deadline. The
    /// deadline accounting owns the miss; this response stays unmatched.
    Late,
    /// No heartbeat was outstanding (unsolicited or duplicate response).
    Unsolicited,
    /// A response whose payload does not match the outstanding request's
    /// correlation. The window stays open; the real acknowledgement may
    /// still arrive inside the deadline.
    Mismatched,
}

/// The deterministic heartbeat state machine. No networking, tasks, logging
/// or filesystem dependencies: monotonic instants in, transitions out, so
/// deadline behavior is owned by logic rather than timing luck. One
/// outstanding heartbeat at a time - the text protocols this worker serves
/// carry no request nonce to correlate a second in-flight ping.
#[derive(Debug)]
pub struct HeartbeatTracker {
    spec: HeartbeatSpec,
    outstanding: Option<OutstandingHeartbeat>,
    missed: u64,
    unmatched: u64,
    state: HeartbeatState,
}

/// One sent heartbeat awaiting its acknowledgement. The correlation payload
/// is what the venue must echo back when the mechanism supports it
/// (native WebSocket control frames); `None` for a nonce-less text
/// protocol, where the single-outstanding window is the correlation rule.
#[derive(Debug)]
pub struct OutstandingHeartbeat {
    sent_at: Instant,
    correlation: Option<Vec<u8>>,
}

impl HeartbeatTracker {
    #[must_use]
    pub fn new(spec: HeartbeatSpec) -> Self {
        let state = if spec.mechanism == HeartbeatMechanism::Disabled {
            HeartbeatState::Disabled
        } else {
            HeartbeatState::AwaitingFirstAck
        };
        Self {
            spec,
            outstanding: None,
            missed: 0,
            unmatched: 0,
            state,
        }
    }

    #[must_use]
    pub fn state(&self) -> HeartbeatState {
        self.state
    }

    #[must_use]
    pub fn missed(&self) -> u64 {
        self.missed
    }

    #[must_use]
    pub fn unmatched(&self) -> u64 {
        self.unmatched
    }

    /// The instant the outstanding heartbeat's response deadline expires,
    /// if one is outstanding.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.outstanding
            .as_ref()
            .map(|sent| sent.sent_at + self.spec.response_deadline)
    }

    /// Whether a new heartbeat may be sent: only when no heartbeat is
    /// outstanding and the mechanism drives one.
    #[must_use]
    pub fn can_send(&self) -> bool {
        self.spec.mechanism != HeartbeatMechanism::Disabled && self.outstanding.is_none()
    }

    /// Record a successful heartbeat send. Returns `true` when the send
    /// started a response window (a send is suppressed while one is
    /// outstanding). The correlation is what the acknowledgement must echo
    /// when the mechanism supports it.
    pub fn on_ping_sent(&mut self, now: Instant, correlation: Option<Vec<u8>>) -> bool {
        if !self.can_send() {
            return false;
        }
        self.outstanding = Some(OutstandingHeartbeat {
            sent_at: now,
            correlation,
        });
        true
    }

    /// Run the response-deadline accounting. Returns `true` when the
    /// policy's reconnect action fires. A miss is counted exactly once per
    /// expired heartbeat: the outstanding window is cleared when counted.
    pub fn on_deadline_check(&mut self, now: Instant) -> bool {
        let Some(outstanding) = self.outstanding.as_ref() else {
            return false;
        };
        if now.duration_since(outstanding.sent_at) < self.spec.response_deadline {
            return false;
        }
        self.outstanding = None;
        self.missed = self.missed.saturating_add(1);
        if self.missed >= u64::from(self.spec.reconnect_after_misses) {
            self.state = HeartbeatState::Failed;
            return true;
        }
        if self.missed >= u64::from(self.spec.miss_threshold) {
            self.state = HeartbeatState::Suspect;
        }
        false
    }

    /// Classify an acknowledgement against the outstanding heartbeat. A
    /// native control-frame response must echo the outstanding request's
    /// correlation payload; a nonce-less text protocol accepts any response
    /// inside the outstanding window (the venue's stated contract).
    pub fn on_ack_received(&mut self, now: Instant, correlation: Option<&[u8]>) -> HeartbeatAck {
        let Some(outstanding) = self.outstanding.as_ref() else {
            self.unmatched = self.unmatched.saturating_add(1);
            return HeartbeatAck::Unsolicited;
        };
        let elapsed = now.duration_since(outstanding.sent_at);
        if elapsed >= self.spec.response_deadline {
            // Late: the deadline accounting owns the miss; this response
            // stays unmatched and must not restore health.
            self.unmatched = self.unmatched.saturating_add(1);
            return HeartbeatAck::Late;
        }
        // Correlation is enforced only where the venue supplies it.
        if let Some(expected) = &outstanding.correlation
            && correlation != Some(expected.as_slice())
        {
            // A response with the wrong payload is not this request's
            // acknowledgement: unmatched, and the window stays open.
            self.unmatched = self.unmatched.saturating_add(1);
            return HeartbeatAck::Mismatched;
        }
        self.outstanding = None;
        self.missed = 0;
        self.state = HeartbeatState::Healthy;
        HeartbeatAck::Matched {
            rtt_us: i64::try_from(elapsed.as_micros()).unwrap_or(i64::MAX),
        }
    }

    /// Reset for a fresh connection: an old connection's outstanding
    /// heartbeat cannot be acknowledged by the new one.
    pub fn reset(&mut self) {
        self.outstanding = None;
        self.missed = 0;
        self.unmatched = 0;
        self.state = if self.spec.mechanism == HeartbeatMechanism::Disabled {
            HeartbeatState::Disabled
        } else {
            HeartbeatState::AwaitingFirstAck
        };
    }
}

/// Mirror the tracker's heartbeat state into the reportable status and
/// return `true` when the policy's reconnect action has fired.
fn sync_heartbeat_state(status: &mut SourceStatus, tracker: &HeartbeatTracker) -> bool {
    status.missed_heartbeats = tracker.missed();
    status.unmatched_heartbeats = tracker.unmatched();
    status.heartbeat_state = tracker.state();
    match tracker.state() {
        HeartbeatState::Failed => {
            status.last_error = Some(format!(
                "heartbeat: {} consecutive PONG responses missed",
                tracker.missed()
            ));
            true
        }
        HeartbeatState::Suspect => {
            status.last_error = Some(format!(
                "heartbeat: {} consecutive PONG responses missed",
                tracker.missed()
            ));
            false
        }
        _ => false,
    }
}

/// Attach the supervisor's receive fence to every decoded event.
fn stamp_frame(frame: &mut SessionFrame, connection_epoch: u64, receive_seq: u64) {
    for event in &mut frame.events {
        match event {
            ExchangeEvent::Snapshot { meta, .. }
            | ExchangeEvent::LevelChange { meta, .. }
            | ExchangeEvent::Lifecycle { meta, .. } => {
                meta.connection_epoch = connection_epoch;
                meta.receive_seq = receive_seq;
            }
            ExchangeEvent::StreamReset { .. } => {}
        }
    }
}

fn update_latency(status: &mut SourceStatus, events: &[ExchangeEvent]) {
    for event in events {
        let meta = match event {
            ExchangeEvent::Snapshot { meta, .. }
            | ExchangeEvent::LevelChange { meta, .. }
            | ExchangeEvent::Lifecycle { meta, .. } => Some(meta),
            ExchangeEvent::StreamReset { .. } => None,
        };
        let Some(meta) = meta else {
            continue;
        };
        let Some(exchange_ts) = meta.exchange_ts_us else {
            continue;
        };
        let latency = meta.received_at_us.saturating_sub(exchange_ts);
        if !(0..=60_000_000).contains(&latency) {
            continue;
        }
        status.latency_ewma_us = Some(match status.latency_ewma_us {
            Some(previous) => (previous * 4 + latency) / 5,
            None => latency,
        });
    }
}

fn failure_message(failure: &SessionFailure) -> String {
    match failure {
        SessionFailure::Reconnect(error)
        | SessionFailure::Protocol { error, .. }
        | SessionFailure::Fatal(error) => truncate_error(error),
        SessionFailure::Decode { error, .. } => truncate_error(error),
    }
}

/// Account for one decoded session frame at the single ingress boundary.
///
/// An application data payload advances the receive fence exactly once and is
/// journaled with its exact bytes. Native controls are journaled as
/// observations in the order the worker retained them and never advance the
/// receive fence. Returns `false` after a fatal journal error that must stop
/// the worker.
#[expect(
    clippy::too_many_arguments,
    reason = "the ingress boundary is identified by source, epoch, and both sequence/timestamp domains"
)]
async fn journal_ingress(
    source: SourceId,
    connection_epoch: u64,
    receive_seq: &mut u64,
    status: &mut SourceStatus,
    journal: Option<&JournalHandle>,
    events: &mpsc::Sender<WorkerEvent>,
    frame: &mut SessionFrame,
    received_at_us: i64,
) -> bool {
    if let Some(payload) = frame.raw.take() {
        return journal_data(
            source,
            connection_epoch,
            receive_seq,
            status,
            journal,
            events,
            Some(payload),
            received_at_us,
            frame.decode.clone(),
            frame.signal.clone(),
            frame.mechanism,
        )
        .await;
    }
    journal_observations(
        source,
        connection_epoch,
        status,
        journal,
        events,
        &frame.observations,
        received_at_us,
    )
    .await
}

/// Account for one application data payload.
#[expect(
    clippy::too_many_arguments,
    reason = "an ingress journal record is identified by source, epoch and both timestamps"
)]
async fn journal_data(
    source: SourceId,
    connection_epoch: u64,
    receive_seq: &mut u64,
    status: &mut SourceStatus,
    journal: Option<&JournalHandle>,
    events: &mpsc::Sender<WorkerEvent>,
    payload: Option<RawFrame>,
    received_at_us: i64,
    decode: DecodeOutcome,
    signal: SessionSignal,
    mechanism: HeartbeatMechanism,
) -> bool {
    let Some(payload) = payload else {
        return true;
    };
    *receive_seq = receive_seq.saturating_add(1);
    status.bytes_received = status
        .bytes_received
        .saturating_add(payload.payload.len() as u64);
    let Some(journal) = journal else {
        return true;
    };
    if let Err(error) = journal.record(crate::journal::DataRecord {
        source,
        connection_epoch,
        receive_seq: *receive_seq,
        received_at_us,
        frame: payload,
        outcome: decode,
        signal,
        mechanism,
    }) {
        return journal_failure(source, status, events, error).await;
    }
    true
}

/// Account for the native control observations of one read. These advance
/// `control_seq`/`observation_seq` only, never the data fence.
async fn journal_observations(
    source: SourceId,
    connection_epoch: u64,
    status: &mut SourceStatus,
    journal: Option<&JournalHandle>,
    events: &mpsc::Sender<WorkerEvent>,
    observations: &[TransportObservation],
    received_at_us: i64,
) -> bool {
    if observations.is_empty() {
        return true;
    }
    for observation in observations {
        status.bytes_received = status
            .bytes_received
            .saturating_add(observation.payload.len() as u64);
    }
    let Some(journal) = journal else {
        return true;
    };
    for observation in observations {
        if let Err(error) = journal.observe(crate::journal::ObservationRecord {
            source,
            connection_epoch,
            received_at_us,
            direction: observation.direction,
            classification: observation.classification,
            signal: observation.signal.clone(),
            mechanism: observation.mechanism,
            payload: observation.payload.clone(),
            send_result: observation.send_result.clone(),
        }) {
            return journal_failure(source, status, events, error).await;
        }
    }
    true
}

async fn journal_failure(
    source: SourceId,
    status: &mut SourceStatus,
    events: &mpsc::Sender<WorkerEvent>,
    error: anyhow::Error,
) -> bool {
    let message = format!("raw-frame journal rejected a frame: {error:#}");
    warn!(%source, error = %message, "journal write failed");
    status.last_error = Some(truncate_error(&error));
    let _ = events
        .send(WorkerEvent::Fatal {
            source,
            error: message,
        })
        .await;
    false
}

/// Stable classification for a rejected frame, recorded in the journal.
fn decode_error_category(error: &anyhow::Error) -> &'static str {
    if error
        .chain()
        .any(|cause| cause.downcast_ref::<serde_json::Error>().is_some())
    {
        "invalid_json"
    } else {
        "invalid_payload"
    }
}

fn truncate_error(error: &anyhow::Error) -> String {
    let mut message = format!("{error:#}");
    const LIMIT: usize = 512;
    if message.len() > LIMIT {
        let mut end = LIMIT;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
        message.push('…');
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::Exchange as _;
    use crate::protocol::{FrameClassification, FrameDirection};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn truncates_errors_on_utf8_boundaries() {
        let error = anyhow::anyhow!("x{}", "é".repeat(300));
        let message = truncate_error(&error);
        assert!(message.ends_with('…'));
        assert!(message.len() <= 512 + '…'.len_utf8());
    }

    fn test_journal(root: &std::path::Path) -> JournalHandle {
        use crate::journal::{JournalConfig, JournalMeta, SyncMode};

        JournalHandle::start(
            JournalConfig {
                directory: root.to_path_buf(),
                queue_capacity: 16,
                enqueue_timeout: Duration::from_millis(250),
                flush_interval: Duration::from_millis(10),
                sync_interval: Duration::from_millis(20),
                segment_max_bytes: 0,
                segment_max_seconds: 0,
                sync_mode: SyncMode::Interval,
            },
            JournalMeta {
                run_id: "run".to_owned(),
                venue: "test".to_owned(),
                code_commit: "test".to_owned(),
                config_sha256: "test".to_owned(),
                route: None,
            },
        )
        .expect("journal start")
    }

    #[test]
    fn failed_pong_response_preserves_the_inbound_ping_observation() {
        use crate::ws::{WsPayload, WsResponse};

        let frame = SessionFrame::native_control(
            WsPayload::Ping(b"probe".to_vec()),
            Some(WsResponse {
                payload: b"probe".to_vec(),
                result: Err("write failed".to_owned()),
            }),
            HeartbeatMechanism::WebSocketControl,
            SessionSignal::HeartbeatAck { correlation: None },
            7,
        );

        assert!(frame.raw.is_none(), "a control frame is not a data record");
        assert!(frame.events.is_empty(), "a control frame is not an event");
        assert_eq!(frame.signal, SessionSignal::PeerPing);
        assert_eq!(
            frame.transport_failure.as_deref(),
            Some("failed to answer a native ping: write failed")
        );
        assert_eq!(frame.observations.len(), 2);

        let inbound = &frame.observations[0];
        assert_eq!(inbound.direction, FrameDirection::Inbound);
        assert_eq!(
            inbound.classification,
            FrameClassification::Control {
                opcode: ControlOpcode::Ping
            }
        );
        assert_eq!(inbound.signal, SessionSignal::PeerPing);
        assert_eq!(inbound.payload, b"probe");
        assert_eq!(inbound.send_result, None);

        let outbound = &frame.observations[1];
        assert_eq!(outbound.direction, FrameDirection::Outbound);
        assert_eq!(
            outbound.classification,
            FrameClassification::Control {
                opcode: ControlOpcode::Pong
            }
        );
        assert_eq!(outbound.signal, SessionSignal::PeerPong);
        assert_eq!(outbound.payload, b"probe");
        assert_eq!(
            outbound.send_result,
            Some(SendResult::Failed {
                error: "write failed".to_owned()
            })
        );
    }

    #[tokio::test]
    async fn transport_controls_are_observed_without_advancing_the_data_fence() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let handle = test_journal(&temp.path().join("journal"));
        let source = SourceId::new(0, 0);
        let (events, _events_rx) = mpsc::channel(4);
        let mut status = SourceStatus::new(source);
        let mut receive_seq = 0u64;

        // A frame with no payload and no observation (for example a protocol
        // failure raised before any payload was read) consumes nothing.
        let mut empty = SessionFrame::idle(0);
        assert!(
            journal_ingress(
                source,
                1,
                &mut receive_seq,
                &mut status,
                Some(&handle),
                &events,
                &mut empty,
                1,
            )
            .await
        );
        assert_eq!(receive_seq, 0);

        // A native control is evidence: it becomes an observation but never
        // consumes the application receive fence.
        let mut control = SessionFrame::heartbeat_ack(Some(b"journal-pong".to_vec()));
        assert!(
            journal_ingress(
                source,
                1,
                &mut receive_seq,
                &mut status,
                Some(&handle),
                &events,
                &mut control,
                2,
            )
            .await
        );
        assert_eq!(receive_seq, 0);

        // The first actual payload takes sequence 1, not 3.
        let mut data = SessionFrame::data(
            Vec::new(),
            7,
            RawFrame::text("payload".to_owned()),
            DecodeOutcome::decoded(1),
            3,
        );
        assert!(
            journal_ingress(
                source,
                1,
                &mut receive_seq,
                &mut status,
                Some(&handle),
                &events,
                &mut data,
                3,
            )
            .await
        );
        assert_eq!(receive_seq, 1);

        let summary = handle
            .shutdown(Duration::from_secs(2))
            .expect("journal shutdown");
        assert_eq!(summary.record_count, 2);
        let run_directory = std::path::Path::new(&summary.run_directory);
        let records = crate::journal::read_records(run_directory).expect("read records");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].receive_seq, 1);
        assert_eq!(records[0].payload, b"payload");
        let observations =
            crate::journal::read_observations(run_directory).expect("read observations");
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].control_seq, Some(1));
        assert_eq!(observations[0].receive_seq, None);
        assert_eq!(observations[1].receive_seq, Some(1));
    }

    #[tokio::test]
    async fn stalled_connect_reports_status_and_stops_cleanly() {
        // A TCP listener that accepts and never upgrades the handshake. The
        // connect deadline must turn this into a bounded, reported failure
        // rather than a wedge.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });

        let mut settings =
            crate::config::Settings::for_exchange(crate::config::ExchangeKind::Polymarket);
        settings.polymarket.ws_url = format!("ws://{address}");
        settings.network.connect_timeout_secs = 1;
        // This is an offline loopback test: use the loopback transport identity
        // so no provider rights are needed for the local HTTP client or socket.
        settings.network.venue = "loopback".to_owned();
        let exchange = std::sync::Arc::new(
            crate::exchange::polymarket::PolymarketExchange::new(
                settings.polymarket.clone(),
                settings.network.clone(),
            )
            .unwrap(),
        );
        let factory = exchange.session_factory();

        let (event_tx, mut event_rx) = mpsc::channel(64);
        let (_command_tx, command_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let config = WorkerConfig::from_settings(&settings.collector);
        let worker = tokio::spawn(run_worker(
            factory,
            SourceId::new(0, 0),
            command_rx,
            event_tx,
            config,
            shutdown_rx,
        ));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let mut saw_failure = false;
        while !saw_failure && tokio::time::Instant::now() < deadline {
            let event = match tokio::time::timeout_at(deadline, event_rx.recv()).await {
                Ok(Some(event)) => event,
                _ => break,
            };
            if let WorkerEvent::Status(status) = event
                && !status.connected
                && status
                    .last_error
                    .as_deref()
                    .is_some_and(|error| error.contains("timed out"))
            {
                saw_failure = true;
            }
        }
        assert!(
            saw_failure,
            "the stalled handshake must fail within the connect deadline and be reported"
        );

        // Shutdown still stops the worker promptly, even after a stalled
        // attempt.
        let _ = shutdown_tx.send(());
        let stopped = tokio::time::timeout(Duration::from_secs(10), worker).await;
        assert!(stopped.is_ok(), "worker did not stop after shutdown");
    }

    struct ConnectGauge {
        current: AtomicUsize,
        maximum: AtomicUsize,
    }

    struct GaugeSession {
        gauge: Arc<ConnectGauge>,
    }

    #[async_trait]
    impl MarketDataSession for GaugeSession {
        async fn connect(&mut self) -> Result<(), SessionFailure> {
            let current = self.gauge.current.fetch_add(1, Ordering::SeqCst) + 1;
            self.gauge.maximum.fetch_max(current, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(100)).await;
            self.gauge.current.fetch_sub(1, Ordering::SeqCst);
            Err(SessionFailure::Fatal(anyhow::anyhow!(
                "connect attempt finished"
            )))
        }

        async fn apply_subscriptions(
            &mut self,
            _desired: &BTreeSet<String>,
        ) -> Result<(), SessionFailure> {
            Ok(())
        }

        async fn next_frame(&mut self) -> Result<SessionFrame, SessionFailure> {
            Err(SessionFailure::Fatal(anyhow::anyhow!("unused")))
        }

        async fn send_keepalive(&mut self) -> Result<HeartbeatRequest, SessionFailure> {
            Ok(HeartbeatRequest::default())
        }

        async fn request_snapshot(&mut self, _symbols: &[String]) -> Result<(), SessionFailure> {
            Ok(())
        }

        async fn close(&mut self) {}
    }

    struct GaugeFactory {
        gauge: Arc<ConnectGauge>,
    }

    #[async_trait]
    impl SessionFactory for GaugeFactory {
        async fn create_session(
            &self,
            _source: SourceId,
        ) -> anyhow::Result<Box<dyn MarketDataSession>> {
            Ok(Box::new(GaugeSession {
                gauge: Arc::clone(&self.gauge),
            }))
        }
    }

    #[tokio::test]
    async fn connect_concurrency_is_bounded_across_workers() {
        let mut settings =
            crate::config::Settings::for_exchange(crate::config::ExchangeKind::Polymarket);
        settings.collector.connect_concurrency = 2;
        let gauge = Arc::new(ConnectGauge {
            current: AtomicUsize::new(0),
            maximum: AtomicUsize::new(0),
        });
        let factory: Arc<dyn SessionFactory> = Arc::new(GaugeFactory {
            gauge: Arc::clone(&gauge),
        });
        let config = WorkerConfig::from_settings(&settings.collector);
        let mut workers = Vec::new();
        let mut shutdown_senders = Vec::new();
        for index in 0..8u16 {
            let (event_tx, mut event_rx) = mpsc::channel(16);
            let (_command_tx, command_rx) = mpsc::channel(8);
            let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
            shutdown_senders.push(shutdown_tx);
            let factory = Arc::clone(&factory);
            let config = config.clone();
            workers.push(tokio::spawn(async move {
                run_worker(
                    factory,
                    SourceId::new(0, index),
                    command_rx,
                    event_tx,
                    config,
                    shutdown_rx,
                )
                .await;
                // Drain until the channel closes so status/fatal sends never
                // block a worker on a full test channel.
                while event_rx.recv().await.is_some() {}
            }));
        }
        for worker in workers {
            tokio::time::timeout(Duration::from_secs(10), worker)
                .await
                .expect("worker did not stop")
                .unwrap();
        }
        let maximum = gauge.maximum.load(Ordering::SeqCst);
        assert_eq!(
            maximum, 2,
            "connect concurrency should reach but never exceed the limit"
        );
    }
}

#[cfg(test)]
mod heartbeat_pin_tests {
    use super::*;
    use crate::model::{Price, QuantityChange, QuantityDelta};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A session whose server never answers a heartbeat: market data keeps
    /// flowing, `send_keepalive` succeeds, and `next_frame` never yields a
    /// PONG. This is the exact blind spot the feed-continuity contracts
    /// close: market traffic must not be able to mask heartbeat failure.
    pub(super) struct SilentServerSession {
        pub(super) spec: HeartbeatSpec,
        pub(super) pings: Arc<AtomicU64>,
        pub(super) frames_served: Arc<AtomicU64>,
        /// When set, the first frame served after this many prior frames is
        /// a scripted application-text heartbeat acknowledgement; the rest
        /// are market data. Used to pin the first-ack state transition.
        pub(super) ack_after_frames: Option<u64>,
    }

    impl SilentServerSession {
        fn market_frame(&self) -> SessionFrame {
            let event = ExchangeEvent::LevelChange {
                native_symbol: "HOT".to_owned(),
                side: crate::Side::Buy,
                price: Price::from_raw(400_000),
                change: QuantityChange::Delta(QuantityDelta::from_raw(1_000_000)),
                meta: crate::model::EventMeta {
                    received_at_us: 0,
                    exchange_ts_us: None,
                    seq: None,
                    clock: None,
                    connection_epoch: 0,
                    receive_seq: 0,
                },
            };
            SessionFrame::data(
                vec![event],
                64,
                RawFrame::text(format!(
                    r#"{{"type":"market","seq":{}}}"#,
                    self.frames_served.fetch_add(1, Ordering::Relaxed)
                )),
                crate::journal::DecodeOutcome::decoded(1),
                crate::time::now_us().unwrap_or(0),
            )
        }
    }

    #[async_trait]
    impl MarketDataSession for SilentServerSession {
        fn heartbeat_spec(&self) -> HeartbeatSpec {
            // Deterministic adapter contract (or the test's override): a
            // PONG must arrive within 50ms of its ping, one miss makes the
            // connection suspect, and the policy never reconnects during
            // the window so the suspect state is observable rather than
            // immediately rotated.
            self.spec
        }

        async fn connect(&mut self) -> Result<(), SessionFailure> {
            Ok(())
        }

        async fn apply_subscriptions(
            &mut self,
            _desired: &BTreeSet<String>,
        ) -> Result<(), SessionFailure> {
            Ok(())
        }

        async fn next_frame(&mut self) -> Result<SessionFrame, SessionFailure> {
            // Market data keeps arriving continuously - a frame every
            // millisecond of test time - so the worker's inbound-idle
            // deadline never fires on its own.
            tokio::time::sleep(Duration::from_millis(1)).await;
            if let Some(after) = self.ack_after_frames
                && self.frames_served.load(Ordering::Relaxed) == after
            {
                return Ok(SessionFrame::heartbeat_ack(None));
            }
            Ok(self.market_frame())
        }

        async fn send_keepalive(&mut self) -> Result<HeartbeatRequest, SessionFailure> {
            self.pings.fetch_add(1, Ordering::Relaxed);
            Ok(HeartbeatRequest::default())
        }

        async fn request_snapshot(&mut self, _symbols: &[String]) -> Result<(), SessionFailure> {
            Ok(())
        }

        async fn close(&mut self) {}
    }

    pub(super) struct SilentServerFactory {
        pub(super) spec_override: Option<HeartbeatSpec>,
        pub(super) pings: Arc<AtomicU64>,
        pub(super) frames_served: Arc<AtomicU64>,
        pub(super) ack_after_frames: Option<u64>,
    }

    #[async_trait]
    impl SessionFactory for SilentServerFactory {
        async fn create_session(
            &self,
            _source: SourceId,
        ) -> anyhow::Result<Box<dyn MarketDataSession>> {
            Ok(Box::new(SilentServerSession {
                spec: self.spec_override.unwrap_or_else(|| HeartbeatSpec {
                    mechanism: HeartbeatMechanism::ApplicationText,
                    send_interval: Duration::from_millis(10),
                    response_deadline: Duration::from_millis(50),
                    miss_threshold: 1,
                    reconnect_after_misses: u32::MAX,
                }),
                pings: self.pings.clone(),
                frames_served: self.frames_served.clone(),
                ack_after_frames: self.ack_after_frames,
            }))
        }
    }

    /// M1 pin two (feed-continuity contracts): market-data traffic must
    /// never satisfy a heartbeat acknowledgement. The server keeps sending
    /// market frames and never returns a PONG; after the heartbeat
    /// response deadline expires, the worker must record the heartbeat
    /// failure while the socket stays connected - not silently treat the
    /// connection as healthy because frames keep arriving.
    ///
    /// Red against the current worker: `send_keepalive` is timestamped and
    /// the inbound-idle deadline is reset by every frame, but no PONG
    /// receipt is tracked and no heartbeat failure is ever recorded.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn market_data_without_pong_records_a_heartbeat_failure() {
        let pings = Arc::new(AtomicU64::new(0));
        let frames_served = Arc::new(AtomicU64::new(0));
        let factory = Arc::new(SilentServerFactory {
            spec_override: None,
            pings: pings.clone(),
            frames_served: frames_served.clone(),
            ack_after_frames: None,
        });
        let source = SourceId::new(0, 0);
        // Hold the command sender for the whole test: a closed command
        // channel is the worker's shutdown signal.
        let (_commands_tx, commands_rx) = mpsc::channel(8);
        let (events, mut events_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let config = WorkerConfig {
            status_interval: Duration::from_millis(10),
            idle_timeout: Duration::from_secs(10),
            reconnect_after: Duration::from_secs(3_600),
            reconnect_base_backoff: Duration::from_millis(10),
            reconnect_max_backoff: Duration::from_millis(20),
            connect_permits: Arc::new(tokio::sync::Semaphore::new(1)),
            journal: None,
        };
        let worker = tokio::spawn(run_worker(
            factory,
            source,
            commands_rx,
            events.clone(),
            config,
            shutdown_rx,
        ));
        drop(events);

        // Collect statuses while market frames flow and pings go unanswered.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(600);
        let mut statuses: Vec<SourceStatus> = Vec::new();
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout_at(deadline, events_rx.recv()).await {
                Ok(Some(WorkerEvent::Status(status))) => statuses.push(status),
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        let _ = shutdown_tx.send(());
        let _ = worker.await;

        assert!(
            pings.load(Ordering::Relaxed) >= 10,
            "the worker must keep sending heartbeats on schedule"
        );
        assert!(
            frames_served.load(Ordering::Relaxed) >= 50,
            "market data must keep flowing for the whole window"
        );
        let last = statuses
            .last()
            .expect("the worker must publish periodic status");
        assert!(last.connected, "the socket itself never failed");
        // Market data kept flowing: transport frames advanced throughout.
        assert!(
            last.last_frame_us.is_some(),
            "market frames must have been received and recorded"
        );
        // No PONG ever arrived, so the acknowledgement time stays unset for
        // the whole run: market data must never satisfy a heartbeat.
        assert_eq!(
            last.last_pong_received_us, None,
            "market traffic must not be recorded as a heartbeat acknowledgement"
        );
        // The deterministic policy expired the response deadline: the
        // failure is counted, the health state leaves Healthy, and the
        // reason is recorded.
        assert!(
            statuses.iter().any(|status| status.missed_heartbeats >= 1),
            "missed heartbeats must be counted while PONGs are absent"
        );
        assert_eq!(
            last.heartbeat_state,
            HeartbeatState::Suspect,
            "the heartbeat must become suspect on missed responses"
        );
        assert_eq!(
            last.transport_state,
            TransportState::Connected,
            "the transport itself never failed"
        );
        assert!(
            statuses.iter().any(|status| status
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("heartbeat"))),
            "a heartbeat failure must be recorded while market data continues; \
             statuses={}",
            statuses.len()
        );
    }
}

#[cfg(test)]
mod heartbeat_tracker_tests {
    use super::*;
    use crate::model::HeartbeatState as Hs;

    fn spec() -> HeartbeatSpec {
        HeartbeatSpec {
            mechanism: HeartbeatMechanism::ApplicationText,
            send_interval: Duration::from_secs(10),
            response_deadline: Duration::from_millis(50),
            miss_threshold: 1,
            reconnect_after_misses: 3,
        }
    }

    /// Deterministic base instant; every offset is a supplied monotonic
    /// instant, so deadline behavior is owned by logic, not timing luck.
    fn base() -> Instant {
        Instant::now()
    }

    #[test]
    fn no_ack_before_the_deadline_is_no_miss() {
        let t0 = base();
        let mut tracker = HeartbeatTracker::new(spec());
        assert!(tracker.on_ping_sent(t0, None));
        assert!(!tracker.on_deadline_check(t0 + Duration::from_millis(49)));
        assert_eq!(tracker.missed(), 0);
        assert_eq!(tracker.state(), Hs::AwaitingFirstAck);
    }

    #[test]
    fn deadline_expiry_advances_the_miss_exactly_once() {
        let t0 = base();
        let mut tracker = HeartbeatTracker::new(spec());
        assert!(tracker.on_ping_sent(t0, None));
        // The return value is the reconnect action, not the miss itself:
        // with reconnect_after_misses = 3, the first miss returns false but
        // is counted, and the state leaves AwaitingFirstAck.
        assert!(!tracker.on_deadline_check(t0 + Duration::from_millis(50)));
        assert_eq!(tracker.missed(), 1);
        assert_eq!(tracker.state(), Hs::Suspect);
        // The window is closed once the miss is counted: later checks must
        // not count the same heartbeat again.
        assert!(!tracker.on_deadline_check(t0 + Duration::from_millis(51)));
        assert_eq!(tracker.missed(), 1);
        assert_eq!(tracker.state(), Hs::Suspect);
    }

    #[test]
    fn an_eligible_ack_returns_the_monotonic_rtt_and_resets_the_streak() {
        let t0 = base();
        let mut tracker = HeartbeatTracker::new(spec());
        assert!(tracker.on_ping_sent(t0, None));
        assert_eq!(
            tracker.on_ack_received(t0 + Duration::from_millis(20), None),
            HeartbeatAck::Matched { rtt_us: 20_000 }
        );
        assert_eq!(tracker.missed(), 0);
        assert_eq!(tracker.state(), Hs::Healthy);
        assert!(tracker.can_send(), "the window closed with the ack");
    }

    #[test]
    fn an_unsolicited_pong_never_clears_or_restores_anything() {
        let t0 = base();
        let mut tracker = HeartbeatTracker::new(spec());
        // No ping was ever sent.
        assert_eq!(tracker.on_ack_received(t0, None), HeartbeatAck::Unsolicited);
        assert_eq!(tracker.unmatched(), 1);
        assert_eq!(tracker.state(), Hs::AwaitingFirstAck);
        // After a real exchange, a duplicate PONG is unsolicited too: the
        // outstanding window already closed with the first ack.
        assert!(tracker.on_ping_sent(t0 + Duration::from_millis(10), None));
        assert_eq!(
            tracker.on_ack_received(t0 + Duration::from_millis(15), None),
            HeartbeatAck::Matched { rtt_us: 5_000 }
        );
        assert_eq!(
            tracker.on_ack_received(t0 + Duration::from_millis(16), None),
            HeartbeatAck::Unsolicited
        );
        assert_eq!(tracker.unmatched(), 2);
        assert_eq!(tracker.state(), Hs::Healthy);
    }

    #[test]
    fn a_late_pong_is_unmatched_and_the_miss_remains() {
        let t0 = base();
        let mut tracker = HeartbeatTracker::new(spec());
        assert!(tracker.on_ping_sent(t0, None));
        // Real delivery order: the worker's biased select hands the frame
        // to the ack path before the next loop top reaps the deadline, so
        // the late response is classified as late - not as unsolicited.
        assert_eq!(
            tracker.on_ack_received(t0 + Duration::from_millis(51), None),
            HeartbeatAck::Late
        );
        assert_eq!(tracker.unmatched(), 1);
        assert!(
            !tracker.on_deadline_check(t0 + Duration::from_millis(52)),
            "the deadline accounting owns the miss (the reconnect action is separate)"
        );
        assert_eq!(tracker.missed(), 1, "the late ack must not clear the miss");
        assert_eq!(tracker.state(), Hs::Suspect);
    }

    #[test]
    fn a_pong_from_a_previous_connection_cannot_ack_the_current_heartbeat() {
        let t0 = base();
        let mut tracker = HeartbeatTracker::new(spec());
        assert!(tracker.on_ping_sent(t0, None));
        // Reconnect: the tracker resets with the connection.
        tracker.reset();
        assert_eq!(
            tracker.on_ack_received(t0 + Duration::from_millis(10), None),
            HeartbeatAck::Unsolicited,
            "an old epoch's acknowledgement is not this connection's evidence"
        );
        assert_eq!(tracker.state(), Hs::AwaitingFirstAck);
        assert_eq!(tracker.missed(), 0);
    }

    #[test]
    fn only_one_heartbeat_is_outstanding_at_a_time() {
        let t0 = base();
        let mut tracker = HeartbeatTracker::new(spec());
        assert!(tracker.on_ping_sent(t0, None));
        assert!(
            !tracker.can_send(),
            "a second in-flight ping cannot be correlated without a nonce"
        );
        assert!(
            !tracker.on_ping_sent(t0 + Duration::from_millis(10), None),
            "a superseding send is suppressed, never a miss"
        );
        // The window closes via ack or deadline - then a send is possible.
        assert_eq!(
            tracker.on_ack_received(t0 + Duration::from_millis(20), None),
            HeartbeatAck::Matched { rtt_us: 20_000 }
        );
        assert!(tracker.can_send());
    }

    #[test]
    fn the_reconnect_action_fires_only_at_the_policy_threshold() {
        let t0 = base();
        let mut tracker = HeartbeatTracker::new(HeartbeatSpec {
            reconnect_after_misses: 3,
            ..spec()
        });
        assert!(tracker.on_ping_sent(t0, None));
        assert!(!tracker.on_deadline_check(t0 + Duration::from_millis(50)));
        assert!(tracker.on_ping_sent(t0 + Duration::from_millis(60), None));
        assert!(!tracker.on_deadline_check(t0 + Duration::from_millis(110)));
        assert!(tracker.on_ping_sent(t0 + Duration::from_millis(120), None));
        assert!(
            tracker.on_deadline_check(t0 + Duration::from_millis(170)),
            "the third consecutive miss applies the reconnect action"
        );
        assert_eq!(tracker.state(), Hs::Failed);
    }

    #[test]
    fn a_disabled_mechanism_never_sends_and_stays_disabled() {
        let t0 = base();
        let mut tracker = HeartbeatTracker::new(HeartbeatSpec::disabled());
        assert!(!tracker.can_send());
        assert!(!tracker.on_ping_sent(t0, None));
        assert!(!tracker.on_deadline_check(t0 + Duration::from_secs(60)));
        assert_eq!(tracker.state(), Hs::Disabled);
    }

    #[test]
    fn a_mismatched_pong_is_unmatched_and_the_window_stays_open() {
        let t0 = base();
        let mut tracker = HeartbeatTracker::new(spec());
        assert!(tracker.on_ping_sent(t0, Some(b"nonce-1".to_vec())));
        // A response with the wrong correlation payload is not this
        // request's acknowledgement: unmatched, no health restore, and the
        // window stays open so the real echo can still arrive in time.
        assert_eq!(
            tracker.on_ack_received(t0 + Duration::from_millis(20), Some(b"other".as_slice())),
            HeartbeatAck::Mismatched
        );
        assert_eq!(tracker.unmatched(), 1);
        assert_eq!(tracker.missed(), 0);
        assert_eq!(tracker.state(), Hs::AwaitingFirstAck);
        assert!(
            !tracker.can_send(),
            "the outstanding request is still awaiting its echo"
        );
        // The real echo inside the deadline matches.
        assert_eq!(
            tracker.on_ack_received(t0 + Duration::from_millis(30), Some(b"nonce-1".as_slice())),
            HeartbeatAck::Matched { rtt_us: 30_000 }
        );
        assert_eq!(tracker.state(), Hs::Healthy);
    }

    #[test]
    fn a_native_pong_which_fails_to_echo_the_nonce_is_matched_only_by_payload() {
        let t0 = base();
        let mut tracker = HeartbeatTracker::new(HeartbeatSpec::ten_second_websocket_control());
        assert!(tracker.on_ping_sent(t0, Some(0x1234u64.to_be_bytes().to_vec())));
        // An empty-payload PONG does not correlate with the nonce request.
        assert_eq!(
            tracker.on_ack_received(t0 + Duration::from_millis(100), Some(&[])),
            HeartbeatAck::Mismatched
        );
        // The echoed nonce does.
        assert_eq!(
            tracker.on_ack_received(
                t0 + Duration::from_millis(200),
                Some(&0x1234u64.to_be_bytes())
            ),
            HeartbeatAck::Matched { rtt_us: 200_000 }
        );
        assert_eq!(tracker.state(), Hs::Healthy);
    }
}

#[cfg(test)]
mod first_ack_pin_tests {
    use super::heartbeat_pin_tests::SilentServerFactory;
    use super::*;
    use crate::model::{HeartbeatState, TransportState};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// M2.1 pin (Finding 1): the first eligible acknowledgement must move
    /// the reported heartbeat state from `AwaitingFirstAck` to `Healthy`.
    /// The tracker already makes that transition; the worker previously
    /// mirrored it only from `Suspect`, so tracker and status disagreed
    /// exactly when the first PONG arrived.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn first_matched_pong_reports_heartbeat_healthy() {
        let pings = Arc::new(AtomicU64::new(0));
        let frames_served = Arc::new(AtomicU64::new(0));
        let factory = Arc::new(SilentServerFactory {
            spec_override: None,
            pings: pings.clone(),
            frames_served: frames_served.clone(),
            ack_after_frames: Some(3),
        });
        let source = SourceId::new(0, 0);
        let (_commands_tx, commands_rx) = mpsc::channel(8);
        let (events, mut events_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let config = WorkerConfig {
            status_interval: Duration::from_millis(10),
            idle_timeout: Duration::from_secs(10),
            reconnect_after: Duration::from_secs(3_600),
            reconnect_base_backoff: Duration::from_millis(10),
            reconnect_max_backoff: Duration::from_millis(20),
            connect_permits: Arc::new(tokio::sync::Semaphore::new(1)),
            journal: None,
        };

        let worker = tokio::spawn(run_worker(
            factory,
            source,
            commands_rx,
            events.clone(),
            config,
            shutdown_rx,
        ));
        drop(events);

        let deadline = tokio::time::Instant::now() + Duration::from_millis(600);
        let mut statuses: Vec<SourceStatus> = Vec::new();
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout_at(deadline, events_rx.recv()).await {
                Ok(Some(WorkerEvent::Status(status))) => statuses.push(status),
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        let _ = shutdown_tx.send(());
        let _ = worker.await;

        let last = statuses
            .last()
            .expect("the worker must publish periodic status");
        assert!(
            pings.load(Ordering::Relaxed) >= 1,
            "the worker must have sent a heartbeat"
        );
        assert!(
            statuses
                .iter()
                .any(|status| status.last_pong_received_us.is_some()),
            "the acknowledgement must be observed"
        );
        assert_eq!(
            last.transport_state,
            TransportState::Connected,
            "the transport stays connected"
        );
        assert_eq!(
            last.heartbeat_state,
            HeartbeatState::Healthy,
            "the first matched acknowledgement must report Healthy, got {:?}",
            last.heartbeat_state
        );
        assert_eq!(last.missed_heartbeats, 0);
    }

    /// M2.1 pin (Finding 2, discriminating case): the acknowledgement is
    /// delivered by a queue push while the worker is blocked in the frame
    /// wait that spans the response deadline. The loop-top `now` was
    /// sampled at the last timer wake - before the ping's window closed -
    /// so a stale pre-wait timestamp would classify the ack as timely.
    /// The classification must use the frame's actual receive instant.
    ///
    /// The worker's biased select cancels a pending frame read on every
    /// timer wake, so lateness cannot be modeled with an in-next_frame
    /// sleep; it is modeled by real-time queue delivery: a 1-second send
    /// interval, a 50ms deadline, and an ack pushed 1.2 seconds in.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ack_pushed_after_the_deadline_is_never_matched() {
        use std::collections::VecDeque;
        use std::sync::Mutex;

        struct QueuedSession {
            queue: Arc<Mutex<VecDeque<SessionFrame>>>,
        }

        impl QueuedSession {
            async fn next_frame_from_queue(&mut self) -> SessionFrame {
                loop {
                    if let Some(frame) = self.queue.lock().unwrap().pop_front() {
                        return frame;
                    }
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        }

        #[async_trait]
        impl MarketDataSession for QueuedSession {
            fn heartbeat_spec(&self) -> HeartbeatSpec {
                HeartbeatSpec {
                    mechanism: HeartbeatMechanism::ApplicationText,
                    send_interval: Duration::from_secs(1),
                    response_deadline: Duration::from_millis(50),
                    miss_threshold: 1,
                    reconnect_after_misses: u32::MAX,
                }
            }

            async fn connect(&mut self) -> Result<(), SessionFailure> {
                Ok(())
            }

            async fn apply_subscriptions(
                &mut self,
                _desired: &BTreeSet<String>,
            ) -> Result<(), SessionFailure> {
                Ok(())
            }

            async fn next_frame(&mut self) -> Result<SessionFrame, SessionFailure> {
                Ok(self.next_frame_from_queue().await)
            }

            async fn send_keepalive(&mut self) -> Result<HeartbeatRequest, SessionFailure> {
                Ok(HeartbeatRequest::default())
            }

            async fn request_snapshot(
                &mut self,
                _symbols: &[String],
            ) -> Result<(), SessionFailure> {
                Ok(())
            }

            async fn close(&mut self) {}
        }

        struct QueuedFactory {
            queue: Arc<Mutex<VecDeque<SessionFrame>>>,
        }

        #[async_trait]
        impl SessionFactory for QueuedFactory {
            async fn create_session(
                &self,
                _source: SourceId,
            ) -> anyhow::Result<Box<dyn MarketDataSession>> {
                Ok(Box::new(QueuedSession {
                    queue: self.queue.clone(),
                }))
            }
        }

        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let factory = Arc::new(QueuedFactory {
            queue: queue.clone(),
        });
        let source = SourceId::new(0, 0);
        let (_commands_tx, commands_rx) = mpsc::channel(8);
        let (events, mut events_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let config = WorkerConfig {
            status_interval: Duration::from_millis(50),
            idle_timeout: Duration::from_secs(60),
            reconnect_after: Duration::from_secs(3_600),
            reconnect_base_backoff: Duration::from_millis(10),
            reconnect_max_backoff: Duration::from_millis(20),
            connect_permits: Arc::new(tokio::sync::Semaphore::new(1)),
            journal: None,
        };

        // Push the acknowledgement 1.2 seconds in: the ping is sent at the
        // 1-second keepalive wake, so the ack arrives roughly 200ms after
        // the ping and 150ms past the 50ms deadline.
        let push_queue = queue.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1_200)).await;
            push_queue
                .lock()
                .unwrap()
                .push_back(SessionFrame::heartbeat_ack(None));
        });

        let worker = tokio::spawn(run_worker(
            factory,
            source,
            commands_rx,
            events.clone(),
            config,
            shutdown_rx,
        ));
        drop(events);

        let deadline = tokio::time::Instant::now() + Duration::from_millis(2_500);
        let mut statuses: Vec<SourceStatus> = Vec::new();
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout_at(deadline, events_rx.recv()).await {
                Ok(Some(WorkerEvent::Status(status))) => statuses.push(status),
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        let _ = shutdown_tx.send(());
        let _ = worker.await;

        let last = statuses
            .last()
            .expect("the worker must publish periodic status");
        assert_eq!(
            last.heartbeat_state,
            HeartbeatState::Suspect,
            "an acknowledgement pushed past the response deadline must never \
             be matched; a stale pre-wait timestamp would have classified it \
             as timely and reported Healthy"
        );
        assert!(
            last.unmatched_heartbeats >= 1,
            "the late acknowledgement must be recorded as unmatched"
        );
        assert!(
            last.heartbeat_rtt_us.is_none(),
            "a late acknowledgement must not produce an RTT"
        );
    }

    /// M2.1 pin (Finding 4): a disabled heartbeat schedule must be absent,
    /// not a sentinel duration. The worker runs with market frames flowing
    /// and time advancing; no heartbeat may be sent, the state stays
    /// `Disabled`, and no `Instant + Duration::MAX` overflow may occur.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disabled_heartbeat_worker_never_sends_and_never_overflows() {
        let pings = Arc::new(AtomicU64::new(0));
        let frames_served = Arc::new(AtomicU64::new(0));
        let factory = Arc::new(SilentServerFactory {
            spec_override: Some(HeartbeatSpec::disabled()),
            pings: pings.clone(),
            frames_served: frames_served.clone(),
            ack_after_frames: None,
        });
        let source = SourceId::new(0, 0);
        let (_commands_tx, commands_rx) = mpsc::channel(8);
        let (events, mut events_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let config = WorkerConfig {
            status_interval: Duration::from_millis(20),
            idle_timeout: Duration::from_secs(60),
            reconnect_after: Duration::from_secs(3_600),
            reconnect_base_backoff: Duration::from_millis(10),
            reconnect_max_backoff: Duration::from_millis(20),
            connect_permits: Arc::new(tokio::sync::Semaphore::new(1)),
            journal: None,
        };

        let worker = tokio::spawn(run_worker(
            factory,
            source,
            commands_rx,
            events.clone(),
            config,
            shutdown_rx,
        ));
        drop(events);

        let deadline = tokio::time::Instant::now() + Duration::from_millis(400);
        let mut statuses: Vec<SourceStatus> = Vec::new();
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout_at(deadline, events_rx.recv()).await {
                Ok(Some(WorkerEvent::Status(status))) => statuses.push(status),
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        let _ = shutdown_tx.send(());
        let _ = worker.await;

        assert_eq!(
            pings.load(Ordering::Relaxed),
            0,
            "a disabled mechanism must never send a heartbeat"
        );
        assert!(
            frames_served.load(Ordering::Relaxed) >= 10,
            "market frames must keep flowing"
        );
        let last = statuses.last().expect("status must keep publishing");
        assert_eq!(last.heartbeat_state, HeartbeatState::Disabled);
        assert_eq!(last.transport_state, TransportState::Connected);
        assert!(last.last_ping_sent_us.is_none());
    }

    /// M2.1 pin (Finding 4): an adapter policy that cannot be executed must
    /// fail during session setup with an explicit error - never surface as
    /// a timer anomaly or a silent misbehavior.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_heartbeat_policy_fails_at_session_setup() {
        let pings = Arc::new(AtomicU64::new(0));
        let frames_served = Arc::new(AtomicU64::new(0));
        let invalid = HeartbeatSpec {
            mechanism: HeartbeatMechanism::ApplicationText,
            send_interval: Duration::from_millis(10),
            response_deadline: Duration::from_millis(50),
            miss_threshold: 3,
            reconnect_after_misses: 2,
        };
        assert!(invalid.validate().is_err());
        let factory = Arc::new(SilentServerFactory {
            spec_override: Some(invalid),
            pings: pings.clone(),
            frames_served: frames_served.clone(),
            ack_after_frames: None,
        });
        let source = SourceId::new(0, 0);
        let (_commands_tx, commands_rx) = mpsc::channel(8);
        let (events, mut events_rx) = mpsc::channel(64);
        let (_shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let config = WorkerConfig {
            status_interval: Duration::from_millis(20),
            idle_timeout: Duration::from_secs(60),
            reconnect_after: Duration::from_secs(3_600),
            reconnect_base_backoff: Duration::from_millis(10),
            reconnect_max_backoff: Duration::from_millis(20),
            connect_permits: Arc::new(tokio::sync::Semaphore::new(1)),
            journal: None,
        };

        let worker = tokio::spawn(run_worker(
            factory,
            source,
            commands_rx,
            events.clone(),
            config,
            shutdown_rx,
        ));
        drop(events);

        let deadline = tokio::time::Instant::now() + Duration::from_millis(2_000);
        let mut fatal_message = None;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout_at(deadline, events_rx.recv()).await {
                Ok(Some(WorkerEvent::Fatal { error, .. })) => {
                    fatal_message = Some(error);
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        let _ = worker.await;

        let message = fatal_message.expect("an invalid policy must fail the worker at setup");
        assert!(
            message.contains("heartbeat"),
            "the setup failure must name the heartbeat policy: {message}"
        );
        assert_eq!(
            pings.load(Ordering::Relaxed),
            0,
            "no heartbeat may be sent under an invalid policy"
        );
    }

    /// M2.1 pin (Finding 3): a native control-frame acknowledgement must
    /// echo the correlation payload the adapter sent. A PONG with the wrong
    /// payload is unmatched and leaves the window open; only the correctly
    /// correlated PONG acknowledges the request.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn native_pong_with_a_mismatched_payload_is_never_matched() {
        use std::collections::VecDeque;
        use std::sync::Mutex;

        const NONCE: &[u8] = &[0x5a, 0xa5, 0x5a, 0xa5, 0x01, 0x02, 0x03, 0x04];

        struct CorrelatedSession {
            queue: Arc<Mutex<VecDeque<SessionFrame>>>,
        }

        impl CorrelatedSession {
            async fn next_frame_from_queue(&mut self) -> SessionFrame {
                if let Some(frame) = self.queue.lock().unwrap().pop_front() {
                    return frame;
                }
                // Keep the worker cycling while the queue is empty: an idle
                // transport frame carries no payload and no market data.
                tokio::time::sleep(Duration::from_millis(1)).await;
                SessionFrame::idle(0)
            }
        }

        #[async_trait]
        impl MarketDataSession for CorrelatedSession {
            fn heartbeat_spec(&self) -> HeartbeatSpec {
                HeartbeatSpec {
                    mechanism: HeartbeatMechanism::WebSocketControl,
                    send_interval: Duration::from_millis(10),
                    response_deadline: Duration::from_millis(5_000),
                    miss_threshold: 1,
                    reconnect_after_misses: u32::MAX,
                }
            }

            async fn connect(&mut self) -> Result<(), SessionFailure> {
                Ok(())
            }

            async fn apply_subscriptions(
                &mut self,
                _desired: &BTreeSet<String>,
            ) -> Result<(), SessionFailure> {
                Ok(())
            }

            async fn next_frame(&mut self) -> Result<SessionFrame, SessionFailure> {
                Ok(self.next_frame_from_queue().await)
            }

            async fn send_keepalive(&mut self) -> Result<HeartbeatRequest, SessionFailure> {
                Ok(HeartbeatRequest {
                    correlation: Some(NONCE.to_vec()),
                    observations: Vec::new(),
                })
            }

            async fn request_snapshot(
                &mut self,
                _symbols: &[String],
            ) -> Result<(), SessionFailure> {
                Ok(())
            }

            async fn close(&mut self) {}
        }

        struct CorrelatedFactory {
            queue: Arc<Mutex<VecDeque<SessionFrame>>>,
        }

        #[async_trait]
        impl SessionFactory for CorrelatedFactory {
            async fn create_session(
                &self,
                _source: SourceId,
            ) -> anyhow::Result<Box<dyn MarketDataSession>> {
                Ok(Box::new(CorrelatedSession {
                    queue: self.queue.clone(),
                }))
            }
        }

        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let factory = Arc::new(CorrelatedFactory {
            queue: queue.clone(),
        });
        // The server answers with the wrong payload first, then the
        // correctly correlated echo.
        queue
            .lock()
            .unwrap()
            .push_back(SessionFrame::heartbeat_ack(Some(b"not-my-nonce".to_vec())));
        queue
            .lock()
            .unwrap()
            .push_back(SessionFrame::heartbeat_ack(Some(NONCE.to_vec())));

        let source = SourceId::new(0, 0);
        let (_commands_tx, commands_rx) = mpsc::channel(8);
        let (events, mut events_rx) = mpsc::channel(256);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        let config = WorkerConfig {
            status_interval: Duration::from_millis(10),
            idle_timeout: Duration::from_secs(60),
            reconnect_after: Duration::from_secs(3_600),
            reconnect_base_backoff: Duration::from_millis(10),
            reconnect_max_backoff: Duration::from_millis(20),
            connect_permits: Arc::new(tokio::sync::Semaphore::new(1)),
            journal: None,
        };

        let worker = tokio::spawn(run_worker(
            factory,
            source,
            commands_rx,
            events.clone(),
            config,
            shutdown_rx,
        ));
        drop(events);

        let deadline = tokio::time::Instant::now() + Duration::from_millis(2_000);
        let mut statuses: Vec<SourceStatus> = Vec::new();
        let mut ping_seen = false;
        let mut echoed = false;
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout_at(deadline, events_rx.recv()).await {
                Ok(Some(WorkerEvent::Status(status))) => {
                    if !ping_seen && status.last_ping_sent_us.is_some() {
                        // The nonce-carrying PING is outstanding (5s
                        // deadline): deliver the correctly correlated echo.
                        ping_seen = true;
                        queue
                            .lock()
                            .unwrap()
                            .push_back(SessionFrame::heartbeat_ack(Some(NONCE.to_vec())));
                    }
                    if ping_seen && echoed && status.heartbeat_state == HeartbeatState::Healthy {
                        statuses.push(status);
                        break;
                    }
                    if ping_seen {
                        echoed = true;
                    }
                    statuses.push(status);
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        let _ = shutdown_tx.send(());
        let _ = worker.await;

        let last = statuses
            .last()
            .expect("the worker must publish periodic status");
        assert!(ping_seen, "the nonce-carrying ping must have been sent");
        assert_eq!(
            last.heartbeat_state,
            HeartbeatState::Healthy,
            "the correlated echo must acknowledge the request; \
             statuses={} last={:?}",
            statuses.len(),
            last
        );
        assert!(
            last.unmatched_heartbeats >= 1,
            "the mismatched PONG must be recorded as unmatched"
        );
        assert_eq!(last.missed_heartbeats, 0, "no deadline expired");
        assert!(
            last.heartbeat_rtt_us.is_some(),
            "the matched ack has an RTT"
        );
    }
}
