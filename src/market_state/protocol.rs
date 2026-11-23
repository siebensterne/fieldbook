//! Transport and session protocol facts shared by adapters and the journal.
//!
//! These types are venue-neutral. Adapters assign the
//! venue-specific interpretation (heartbeat mechanism, session signal) at the
//! boundary where the frame is observed; the journal stores that interpretation
//! instead of inferring it from payload bytes during replay.

use serde::{Deserialize, Serialize};

/// WebSocket data-frame kind preserved in the journal record header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameKind {
    Text,
    #[default]
    Binary,
}

/// Direction of one retained transport observation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameDirection {
    #[default]
    Inbound,
    Outbound,
}

/// Native WebSocket control opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlOpcode {
    Ping,
    Pong,
}

/// Wire class of one observation: application data or a native control frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record_kind", rename_all = "snake_case")]
pub enum FrameClassification {
    Data { frame_kind: FrameKind },
    Control { opcode: ControlOpcode },
}

impl FrameClassification {
    #[must_use]
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Control { .. })
    }

    #[must_use]
    pub const fn is_inbound_data(self, direction: FrameDirection) -> bool {
        matches!(
            (self, direction),
            (Self::Data { .. }, FrameDirection::Inbound)
        )
    }
}

/// The heartbeat mechanism a venue uses. Adapter-owned: one venue's
/// heartbeat assumptions must not leak into another's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatMechanism {
    /// Application-level text `PING`/`PONG`: one outstanding
    /// heartbeat, no request nonce, ack typed from the text frame.
    ApplicationText,
    /// Native WebSocket control frames: PONG payload correlates
    /// with the client ping.
    WebSocketControl,
    /// The venue carries no client-driven heartbeat; liveness comes from
    /// frame receipt and the idle timeout alone.
    #[default]
    Disabled,
}

/// One typed observation from a session.
///
/// A heartbeat acknowledgement and a market event are different facts: a PONG
/// must not update an instrument's market-data timestamp, and market data must
/// never satisfy a heartbeat.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "signal", rename_all = "snake_case")]
pub enum SessionSignal {
    /// Decoded market data (or an ignorable payload the adapter chose not to
    /// decode). The only signal that may advance instrument activity.
    #[default]
    MarketData,
    /// One outbound heartbeat request the adapter sent successfully.
    HeartbeatRequest,
    /// The venue acknowledged the client's heartbeat. The payload is the
    /// correlation evidence: `Some(bytes)` for a native WebSocket PONG
    /// (which echoes the client ping's payload), `None` for an
    /// application-text PONG (a text protocol carries no
    /// nonce - correlation there is the single-outstanding-window
    /// contract, an explicit venue limitation).
    HeartbeatAck { correlation: Option<Vec<u8>> },
    /// The venue sent its own heartbeat probe (server `PING`). A different
    /// observation from an acknowledgement of a client ping.
    PeerPing,
    /// This client answered a peer probe with a native PONG.
    PeerPong,
    /// Session control the adapter handled (subscribe acknowledgements and
    /// similar) that is neither market data nor a heartbeat exchange.
    ProtocolControl,
}

/// Result of one outbound send. Present only on outbound observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SendResult {
    /// The frame was handed to the websocket transport successfully.
    Sent,
    /// The send attempt failed. The error is retained as evidence; the
    /// inbound frame that provoked the response is never discarded because of
    /// it.
    Failed { error: String },
}

impl SendResult {
    #[must_use]
    pub const fn is_sent(&self) -> bool {
        matches!(self, Self::Sent)
    }
}

/// One retained inbound or outbound observation, typed at the boundary where
/// it was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportObservation {
    pub direction: FrameDirection,
    pub classification: FrameClassification,
    pub signal: SessionSignal,
    pub mechanism: HeartbeatMechanism,
    pub payload: Vec<u8>,
    /// `Some` for outbound observations only.
    pub send_result: Option<SendResult>,
}

impl TransportObservation {
    #[must_use]
    pub fn inbound_data(
        frame_kind: FrameKind,
        payload: Vec<u8>,
        signal: SessionSignal,
        mechanism: HeartbeatMechanism,
    ) -> Self {
        Self {
            direction: FrameDirection::Inbound,
            classification: FrameClassification::Data { frame_kind },
            signal,
            mechanism,
            payload,
            send_result: None,
        }
    }

    #[must_use]
    pub fn inbound_control(
        opcode: ControlOpcode,
        payload: Vec<u8>,
        signal: SessionSignal,
        mechanism: HeartbeatMechanism,
    ) -> Self {
        Self {
            direction: FrameDirection::Inbound,
            classification: FrameClassification::Control { opcode },
            signal,
            mechanism,
            payload,
            send_result: None,
        }
    }

    #[must_use]
    pub fn outbound_data(
        frame_kind: FrameKind,
        payload: Vec<u8>,
        signal: SessionSignal,
        mechanism: HeartbeatMechanism,
        send_result: SendResult,
    ) -> Self {
        Self {
            direction: FrameDirection::Outbound,
            classification: FrameClassification::Data { frame_kind },
            signal,
            mechanism,
            payload,
            send_result: Some(send_result),
        }
    }

    #[must_use]
    pub fn outbound_control(
        opcode: ControlOpcode,
        payload: Vec<u8>,
        signal: SessionSignal,
        mechanism: HeartbeatMechanism,
        send_result: SendResult,
    ) -> Self {
        Self {
            direction: FrameDirection::Outbound,
            classification: FrameClassification::Control { opcode },
            signal,
            mechanism,
            payload,
            send_result: Some(send_result),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_round_trips_through_serde() {
        let data = FrameClassification::Data {
            frame_kind: FrameKind::Text,
        };
        let control = FrameClassification::Control {
            opcode: ControlOpcode::Pong,
        };
        for value in [data, control] {
            let json = serde_json::to_string(&value).unwrap();
            assert_eq!(
                serde_json::from_str::<FrameClassification>(&json).unwrap(),
                value
            );
        }
        assert!(data.is_inbound_data(FrameDirection::Inbound));
        assert!(!data.is_inbound_data(FrameDirection::Outbound));
        assert!(control.is_control());
        assert!(!data.is_control());
    }

    #[test]
    fn sessions_signals_serialize_with_their_variant() {
        let ack = SessionSignal::HeartbeatAck {
            correlation: Some(vec![1, 2, 3]),
        };
        let json = serde_json::to_string(&ack).unwrap();
        assert!(json.contains("\"signal\":\"heartbeat_ack\""));
        assert_eq!(serde_json::from_str::<SessionSignal>(&json).unwrap(), ack);
        let default = SessionSignal::default();
        assert_eq!(default, SessionSignal::MarketData);
    }
}
