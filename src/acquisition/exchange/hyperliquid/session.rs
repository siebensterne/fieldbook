//! Hyperliquid selected-book websocket session (H1 telemetry + H2 books).
//!
//! Connects to the public websocket and reconciles an exact desired set. The
//! H1 telemetry channels `allMids` and `fastAssetCtxs` remain journaled
//! `ProtocolControl` observations. H2 additionally subscribes `l2Book` and
//! `trades` for exactly the configured selected perpetuals: `l2Book` pushes
//! become normalized `ExchangeEvent::Snapshot` events and `trades` stay
//! telemetry that never anchors or produces a delta. There is no venue
//! heartbeat and no `LevelChange` on this venue. `assetCtxs` is not subscribed
//! because no golden fixture pins its wire shape.

use std::collections::BTreeSet;

use anyhow::Context;
use async_trait::async_trait;
use serde_json::Value;

use crate::{
    config::{HyperliquidSettings, NetworkSettings},
    exchange::hyperliquid::{
        books::{self, CHANNEL_L2_BOOK, CHANNEL_TRADES, into_snapshot},
        telemetry::{TelemetryFrame, decode_telemetry, subscription_request},
    },
    journal::{DecodeOutcome, FrameKind, RawFrame},
    model::SourceId,
    protocol::{HeartbeatMechanism, SessionSignal},
    session::{
        HeartbeatRequest, HeartbeatSpec, MarketDataSession, SessionFactory, SessionFailure,
        SessionFrame,
    },
    time::now_us,
    ws::{self, ConnectOptions, WsPayload, WsStream},
};

/// Unique per-connection ordinal used to derive distinct pinned source ports.
/// Mirrors the Kalshi and Polymarket adapters.
fn source_ordinal(source: SourceId) -> u32 {
    u32::from(source.shard) * 256 + u32::from(source.replica)
}

/// Factory for H1 telemetry / H2 selected-book sessions. Holds only
/// configuration; transport options are derived per source so egress policy is
/// honoured identically to the other venues.
pub struct HyperliquidSessionFactory {
    settings: HyperliquidSettings,
    network: NetworkSettings,
}

impl HyperliquidSessionFactory {
    pub fn new(settings: HyperliquidSettings, network: NetworkSettings) -> Self {
        Self { settings, network }
    }
}

#[async_trait]
impl SessionFactory for HyperliquidSessionFactory {
    async fn create_session(&self, source: SourceId) -> anyhow::Result<Box<dyn MarketDataSession>> {
        let connect_options = self
            .network
            .connect_options()
            .with_context(|| format!("deriving transport options for source {source}"))?
            .for_ordinal(source_ordinal(source))
            .with_context(|| format!("deriving connect options for source {source}"))?;
        Ok(Box::new(HyperliquidSession::new(
            self.settings.clone(),
            connect_options,
        )))
    }
}

/// One Hyperliquid websocket connection: H1 telemetry plus the exact H2
/// selected-perpetual book universe.
pub struct HyperliquidSession {
    settings: HyperliquidSettings,
    connect_options: ConnectOptions,
    stream: Option<WsStream>,
    telemetry_subscribed: bool,
    /// Desired native symbols reported by the supervisor.
    desired: BTreeSet<String>,
    /// Native symbols with an acknowledged `l2Book` subscription on this connection.
    subscribed_books: BTreeSet<String>,
}

impl HyperliquidSession {
    pub fn new(settings: HyperliquidSettings, connect_options: ConnectOptions) -> Self {
        Self {
            settings,
            connect_options,
            stream: None,
            telemetry_subscribed: false,
            desired: BTreeSet::new(),
            subscribed_books: BTreeSet::new(),
        }
    }

    fn stream_mut(&mut self) -> Result<&mut WsStream, SessionFailure> {
        self.stream.as_mut().ok_or_else(|| {
            SessionFailure::Reconnect(anyhow::anyhow!("Hyperliquid session is not connected"))
        })
    }

    async fn send_json(&mut self, value: Value) -> Result<(), SessionFailure> {
        let text = serde_json::to_string(&value)
            .context("serializing Hyperliquid command")
            .map_err(SessionFailure::Reconnect)?;
        ws::send_text(self.stream_mut()?, text)
            .await
            .map_err(SessionFailure::Reconnect)
    }

    /// The exact book universe: the worker's desired set intersected with the
    /// configured finite perpetual list. Spot and unlisted perps are excluded.
    fn selected_books(&self) -> BTreeSet<String> {
        books::selected_symbols(&self.desired, &self.settings.books.perpetuals)
    }

    /// Send a subscribe or unsubscribe command for one selected book symbol.
    /// `trades` is subscribed alongside `l2Book` only when configured, and is
    /// always telemetry rather than depth.
    async fn send_book_command(
        &mut self,
        method: &str,
        symbol: &str,
    ) -> Result<(), SessionFailure> {
        let (dex, coin) = books::parse_native_symbol(symbol)
            .with_context(|| {
                format!("refusing to subscribe a non-perpetual book symbol `{symbol}`")
            })
            .map_err(SessionFailure::Fatal)?;
        let l2 = books::subscription_request(method, CHANNEL_L2_BOOK, &coin, &dex)
            .map_err(SessionFailure::Fatal)?;
        self.send_json(l2).await?;
        if self.settings.books.trades_telemetry {
            let trades = books::subscription_request(method, CHANNEL_TRADES, &coin, &dex)
                .map_err(SessionFailure::Fatal)?;
            self.send_json(trades).await?;
        }
        Ok(())
    }

    /// Decode an `l2Book` push. An unsubscribed coin is ignored rather than
    /// anchoring a book the worker did not ask for (exact selected coverage).
    fn decode_l2_book(
        &self,
        text: &str,
        bytes: usize,
        raw: RawFrame,
        received_at_us: i64,
    ) -> Result<SessionFrame, SessionFailure> {
        let frame = match books::decode_l2_book(text) {
            Ok(frame) => frame,
            Err(error) => {
                return Err(SessionFailure::Decode {
                    error: error.context("decoding Hyperliquid l2Book frame"),
                    frame: Some(raw),
                    received_at_us,
                });
            }
        };
        let native = books::native_symbol(&frame.dex, &frame.coin);
        if !self.subscribed_books.contains(&native) {
            return Ok(SessionFrame::data(
                Vec::new(),
                bytes,
                raw,
                DecodeOutcome::ignored("unsubscribed_book"),
                received_at_us,
            )
            .with_signal(SessionSignal::ProtocolControl));
        }
        let event = into_snapshot(frame, received_at_us);
        Ok(SessionFrame::data(
            vec![event],
            bytes,
            raw,
            DecodeOutcome::decoded(1),
            received_at_us,
        ))
    }

    /// Decode one application payload. Only a subscribed `l2Book` push becomes
    /// a normalized snapshot; telemetry, trades and unknown additive channels
    /// stay raw `ProtocolControl` observations with zero events.
    fn decode_text(
        &self,
        text: String,
        kind: FrameKind,
        received_at_us: i64,
    ) -> Result<SessionFrame, SessionFailure> {
        let bytes = text.len();
        let raw = RawFrame {
            kind,
            payload: text.as_bytes().to_vec(),
        };
        let channel = match books::frame_channel(&text) {
            Ok(channel) => channel,
            Err(error) => {
                return Err(SessionFailure::Decode {
                    error: error.context("decoding Hyperliquid frame envelope"),
                    frame: Some(raw),
                    received_at_us,
                });
            }
        };
        if channel == CHANNEL_L2_BOOK {
            return self.decode_l2_book(&text, bytes, raw, received_at_us);
        }
        if channel == CHANNEL_TRADES {
            // Trades are parsed and validated exactly, then kept as telemetry.
            // No snapshot or level change is ever synthesized from a print.
            return match books::decode_trades(&text) {
                Ok(_) => Ok(SessionFrame::data(
                    Vec::new(),
                    bytes,
                    raw,
                    DecodeOutcome::ignored("hyperliquid_trades"),
                    received_at_us,
                )
                .with_signal(SessionSignal::ProtocolControl)),
                Err(error) => Err(SessionFailure::Decode {
                    error: error.context("decoding Hyperliquid trades frame"),
                    frame: Some(raw),
                    received_at_us,
                }),
            };
        }
        // H1 telemetry is validated by its own fixture-pinned codec; unknown
        // additive channels are ignored. Neither can anchor a book.
        let decoded = match decode_telemetry(&text) {
            Ok(decoded) => decoded,
            Err(error) => {
                return Err(SessionFailure::Decode {
                    error: error.context("decoding Hyperliquid telemetry frame"),
                    frame: Some(raw),
                    received_at_us,
                });
            }
        };
        let decode = match decoded {
            TelemetryFrame::Ignored(reason) => DecodeOutcome::ignored(&reason),
            TelemetryFrame::AllMids(_) | TelemetryFrame::FastAssetCtxs(_) => {
                DecodeOutcome::ignored("hyperliquid_telemetry")
            }
        };
        Ok(
            SessionFrame::data(Vec::new(), bytes, raw, decode, received_at_us)
                .with_signal(SessionSignal::ProtocolControl),
        )
    }
}

#[async_trait]
impl MarketDataSession for HyperliquidSession {
    fn heartbeat_spec(&self) -> HeartbeatSpec {
        // No fixture proves a venue heartbeat in H1. Liveness comes from frame
        // receipt and the worker's idle timeout; telemetry never satisfies a
        // heartbeat or a stale-probe budget.
        HeartbeatSpec::disabled()
    }

    async fn connect(&mut self) -> Result<(), SessionFailure> {
        self.close().await;
        let stream = ws::connect(&self.settings.ws_url, &[], &self.connect_options)
            .await
            .map_err(|error| {
                SessionFailure::Reconnect(error.context("connecting to Hyperliquid websocket"))
            })?;
        self.stream = Some(stream);
        self.telemetry_subscribed = false;
        self.subscribed_books.clear();
        Ok(())
    }

    async fn apply_subscriptions(
        &mut self,
        desired: &BTreeSet<String>,
    ) -> Result<(), SessionFailure> {
        self.desired = desired.clone();
        // Telemetry is venue-wide, not symbol-scoped: send those channel
        // subscriptions exactly once per connection.
        if !self.telemetry_subscribed {
            let channels = self.settings.telemetry.subscriptions.clone();
            for channel in &channels {
                let request = subscription_request(channel).map_err(SessionFailure::Fatal)?;
                self.send_json(request).await?;
            }
            self.telemetry_subscribed = true;
        }
        // Books are reconciled to the exact selected set. A symbol that is no
        // longer desired is unsubscribed; a newly desired one is subscribed.
        let selected = self.selected_books();
        let removals: Vec<String> = self
            .subscribed_books
            .difference(&selected)
            .cloned()
            .collect();
        let additions: Vec<String> = selected
            .difference(&self.subscribed_books)
            .cloned()
            .collect();
        for symbol in removals {
            self.send_book_command("unsubscribe", &symbol).await?;
        }
        for symbol in additions {
            self.send_book_command("subscribe", &symbol).await?;
        }
        self.subscribed_books = selected;
        Ok(())
    }

    async fn next_frame(&mut self) -> Result<SessionFrame, SessionFailure> {
        let read = ws::next_payload(self.stream_mut()?)
            .await
            .map_err(SessionFailure::Reconnect)?;
        let received_at_us = now_us().unwrap_or(0);
        match read.payload {
            // Native controls are transport plumbing. A PONG is not an
            // acknowledgement: the H1 heartbeat mechanism is Disabled.
            WsPayload::Ping(payload) => Ok(SessionFrame::native_control(
                WsPayload::Ping(payload),
                read.response,
                HeartbeatMechanism::Disabled,
                SessionSignal::ProtocolControl,
                received_at_us,
            )),
            WsPayload::Pong(payload) => Ok(SessionFrame::native_control(
                WsPayload::Pong(payload),
                None,
                HeartbeatMechanism::Disabled,
                SessionSignal::ProtocolControl,
                received_at_us,
            )),
            WsPayload::Text(text) => self.decode_text(text, FrameKind::Text, received_at_us),
            WsPayload::Binary(bytes) => match String::from_utf8(bytes.clone()) {
                Ok(text) => self.decode_text(text, FrameKind::Binary, received_at_us),
                Err(error) => Err(SessionFailure::Decode {
                    error: anyhow::Error::new(error)
                        .context("Hyperliquid binary frame was not UTF-8 JSON"),
                    frame: Some(RawFrame {
                        kind: FrameKind::Binary,
                        payload: bytes,
                    }),
                    received_at_us,
                }),
            },
        }
    }

    async fn send_keepalive(&mut self) -> Result<HeartbeatRequest, SessionFailure> {
        // Never called: the heartbeat spec is Disabled. Returning a default
        // keeps the seam total without inventing a venue heartbeat.
        Ok(HeartbeatRequest::default())
    }

    async fn request_snapshot(&mut self, symbols: &[String]) -> Result<(), SessionFailure> {
        // Hyperliquid has no request/ack snapshot opcode. Cycling the exact
        // selected subscription makes the venue push a fresh full l2Book; the
        // worker's RecoveryReady fence ensures only a later frame is promoted.
        // An empty or non-selected symbol list can never manufacture an anchor.
        let desired: BTreeSet<String> = symbols.iter().cloned().collect();
        for symbol in books::selected_symbols(&desired, &self.settings.books.perpetuals) {
            self.send_book_command("unsubscribe", &symbol).await?;
            self.send_book_command("subscribe", &symbol).await?;
        }
        Ok(())
    }

    async fn close(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = ws::close(stream).await;
        }
        self.telemetry_subscribed = false;
        self.subscribed_books.clear();
    }
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use std::time::Duration;

    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::{WebSocketStream, tungstenite::Message};

    use super::*;
    use crate::{
        journal::FrameKind as JournalFrameKind,
        protocol::{FrameClassification, FrameDirection},
    };

    type ServerWs = WebSocketStream<tokio::net::TcpStream>;

    async fn read_subscribe(ws: &mut ServerWs) -> String {
        let message = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("server read timed out")
            .expect("server stream ended")
            .expect("server websocket error");
        match message {
            Message::Text(text) => text.to_string(),
            other => panic!("expected a subscription text frame, got {other:?}"),
        }
    }

    async fn read_commands(ws: &mut ServerWs, count: usize) -> Vec<serde_json::Value> {
        let mut commands = Vec::with_capacity(count);
        for _ in 0..count {
            let text = read_subscribe(ws).await;
            commands.push(serde_json::from_str(&text).expect("command is JSON"));
        }
        commands
    }

    #[tokio::test]
    async fn reconciliation_removes_stale_books_and_snapshot_requests_resubscribe() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            // Initial: 2 telemetry + BTC l2Book/trades.
            let initial = read_commands(&mut ws, 4).await;
            assert_eq!(initial[0]["subscription"]["type"], "allMids");
            assert_eq!(initial[1]["subscription"]["type"], "fastAssetCtxs");
            assert_eq!(initial[2]["subscription"]["type"], "l2Book");
            assert_eq!(initial[3]["subscription"]["type"], "trades");
            // Reconciliation: ETH added, BTC removed (BTreeSet order: ETH < BTC false;
            // removals then additions, both singletons here).
            let changed = read_commands(&mut ws, 4).await;
            assert_eq!(changed[0]["method"], "unsubscribe");
            assert_eq!(changed[0]["subscription"]["coin"], "BTC");
            assert_eq!(changed[1]["method"], "unsubscribe");
            assert_eq!(changed[1]["subscription"]["type"], "trades");
            assert_eq!(changed[2]["method"], "subscribe");
            assert_eq!(changed[2]["subscription"]["coin"], "ETH");
            assert_eq!(changed[3]["subscription"]["type"], "trades");
            // request_snapshot is a wait-for-next-l2Book resubscribe of the
            // selected symbol only; DOGE and spot are ignored.
            let refresh = read_commands(&mut ws, 4).await;
            assert_eq!(refresh[0]["method"], "unsubscribe");
            assert_eq!(refresh[0]["subscription"]["coin"], "ETH");
            assert_eq!(refresh[2]["method"], "subscribe");
            assert_eq!(refresh[2]["subscription"]["coin"], "ETH");
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let mut settings = HyperliquidSettings {
            ws_url: format!("ws://{address}"),
            ..HyperliquidSettings::default()
        };
        settings.books.perpetuals = vec!["BTC".to_owned(), "ETH".to_owned()];
        let mut session = HyperliquidSession::new(settings, ConnectOptions::default());
        session.connect().await.unwrap();
        let btc = BTreeSet::from(["hyperliquid:perp::BTC".to_owned()]);
        session.apply_subscriptions(&btc).await.unwrap();
        let eth = BTreeSet::from([
            "hyperliquid:perp::ETH".to_owned(),
            "hyperliquid:perp::DOGE".to_owned(),
            "hyperliquid:spot:PURR/USDC".to_owned(),
        ]);
        session.apply_subscriptions(&eth).await.unwrap();
        session
            .request_snapshot(&[
                "hyperliquid:perp::ETH".to_owned(),
                "hyperliquid:perp::DOGE".to_owned(),
            ])
            .await
            .unwrap();
        session.close().await;
        server.await.unwrap();
    }
}
