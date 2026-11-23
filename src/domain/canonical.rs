//! Canonical event envelope and normalized event taxonomy (Platform M4, Phase 1).
//!
//! This module adds canonical event types without changing [`crate::model::ExchangeEvent`]. The legacy type remains
//! the market-specific collector/SBE/replay wire contract and is **not**
//! changed here. Nothing in this module alters the SBE writer, raw-frame
//! journal, replay JSONL, or catalog checksums. No dependency is added, and no
//! database, connector or durable storage is implemented.
//!
//! The taxonomy separates event kinds that the legacy wire contract conflates
//! or omits. A snapshot is a full book anchor; a delta is a single level change;
//! a trade is a trade; a best-bid-offer is a top-of-book quote and is never an
//! L2 book; telemetry/assets are asset context and never a book delta. There is
//! no `From` conversion that manufactures a trade, BBO, asset-context or gap
//! event from a non-trade `ExchangeEvent`.
//!
//! Every envelope carries provenance: an opaque deterministic [`EventId`], the
//! source/feed identity, the connection epoch, optional sequence metadata,
//! source and receive times, and an optional raw observation reference. The
//! raw journal remains the independent source of truth; a canonical envelope
//! only points back to it. [`CanonicalReader`] fails closed on an unsupported
//! [`CANONICAL_SCHEMA_VERSION`] or on missing provenance.
//!
//! [`NormalizedStore`] is a contract, not a new storage subsystem. The only
//! implementation here is [`InMemoryNormalizedStore`], used for tests.

use std::{
    collections::BTreeMap,
    fmt::{self, Display, Formatter},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    Side,
    identity::{FeedId, InstrumentId, OpaqueId},
    model,
};

/// Version of the canonical envelope schema. Envelopes serialize with this
/// value; readers reject any other value.
pub const CANONICAL_SCHEMA_VERSION: u32 = 1;

/// Opaque, deterministic identity of one canonical event. It is derived from
/// explicit provenance inputs, never from a wall clock or a display label.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventId(OpaqueId);

impl EventId {
    /// Derive an event id from an explicit immutable assertion.
    #[must_use]
    pub fn derive(namespace: &str, authority: &str, stable_key: &str) -> Self {
        Self(OpaqueId::derive("evt", namespace, authority, stable_key))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Display for EventId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// Ordering metadata carried by an event. Receive order is local and
/// independent of any venue sequence or exchange clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceMetadata {
    /// Per-subscription venue sequence, when the feed supplies one.
    pub source_seq: Option<u64>,
    /// Exchange-wide ordering clock, when the feed supplies one.
    pub exchange_clock: Option<i64>,
    /// Local monotonically increasing frame number in the connection epoch.
    pub receive_seq: u64,
}

/// Stable discriminant of a canonical event kind. These strings are part of
/// the serialized contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalKind {
    BookSnapshot,
    BookDelta,
    Trade,
    BestBidOffer,
    AssetContext,
    InstrumentLifecycle,
    StreamGap,
    StreamReset,
}

impl CanonicalKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BookSnapshot => "book_snapshot",
            Self::BookDelta => "book_delta",
            Self::Trade => "trade",
            Self::BestBidOffer => "best_bid_offer",
            Self::AssetContext => "asset_context",
            Self::InstrumentLifecycle => "instrument_lifecycle",
            Self::StreamGap => "stream_gap",
            Self::StreamReset => "stream_reset",
        }
    }
}

impl Display for CanonicalKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One canonical price level, expressed as raw i64 coefficients. Scale and
/// unit stay in instrument metadata; no floating point is introduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalLevel {
    pub price: i64,
    pub quantity: i64,
}

impl From<&model::Level> for CanonicalLevel {
    fn from(level: &model::Level) -> Self {
        Self {
            price: level.price.raw(),
            quantity: level.quantity.raw(),
        }
    }
}

/// A full two-sided book anchor. Only an `ExchangeEvent::Snapshot` maps here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookSnapshot {
    pub native_symbol: String,
    pub bids: Vec<CanonicalLevel>,
    pub asks: Vec<CanonicalLevel>,
}

impl From<(&str, &model::BookSnapshot)> for BookSnapshot {
    fn from((native_symbol, book): (&str, &model::BookSnapshot)) -> Self {
        Self {
            native_symbol: native_symbol.to_owned(),
            bids: book.bids.iter().map(CanonicalLevel::from).collect(),
            asks: book.asks.iter().map(CanonicalLevel::from).collect(),
        }
    }
}

/// Absolute replacement or signed adjustment of one level. An absolute change
/// and a delta change have distinct meanings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanonicalChange {
    Absolute { quantity: i64 },
    Delta { quantity: i64 },
}

/// One level change. Only an `ExchangeEvent::LevelChange` maps here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookDelta {
    pub native_symbol: String,
    pub side: Side,
    pub price: i64,
    pub change: CanonicalChange,
}

/// An executed trade. There is no `From<&ExchangeEvent>` for this type: only an
/// explicit trade observation may construct it. In particular a level change,
/// telemetry record or asset context is never a trade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trade {
    pub native_symbol: String,
    pub side: Option<Side>,
    pub price: i64,
    pub quantity: i64,
}

impl Trade {
    #[must_use]
    pub fn from_trade_observation(
        native_symbol: impl Into<String>,
        side: Option<Side>,
        price: i64,
        quantity: i64,
    ) -> Self {
        Self {
            native_symbol: native_symbol.into(),
            side,
            price,
            quantity,
        }
    }
}

/// Top-of-book best bid and best offer. This is a quote projection, not an L2
/// book: it carries at most one level per side and is never a `BookSnapshot`
/// or `BookDelta`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BestBidOffer {
    pub native_symbol: String,
    pub best_bid: Option<CanonicalLevel>,
    pub best_offer: Option<CanonicalLevel>,
}

impl BestBidOffer {
    #[must_use]
    pub fn from_bbo_observation(
        native_symbol: impl Into<String>,
        best_bid: Option<CanonicalLevel>,
        best_offer: Option<CanonicalLevel>,
    ) -> Self {
        Self {
            native_symbol: native_symbol.into(),
            best_bid,
            best_offer,
        }
    }
}

/// Asset or venue-wide context (for example venue statistics or
/// `fastAssetCtxs`). Telemetry and asset records are context, never a book
/// anchor, book delta or trade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetContext {
    pub asset: String,
    pub channel: String,
    pub fields: BTreeMap<String, String>,
}

impl AssetContext {
    #[must_use]
    pub fn from_telemetry(
        asset: impl Into<String>,
        channel: impl Into<String>,
        fields: BTreeMap<String, String>,
    ) -> Self {
        Self {
            asset: asset.into(),
            channel: channel.into(),
            fields,
        }
    }
}

/// Exact price band carried by a lifecycle update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalPriceRange {
    pub start_us: i64,
    pub end_us: i64,
    pub step_us: i64,
}

impl From<&model::PriceRange> for CanonicalPriceRange {
    fn from(range: &model::PriceRange) -> Self {
        Self {
            start_us: range.start_us,
            end_us: range.end_us,
            step_us: range.step_us,
        }
    }
}

/// Instrument reference-data lifecycle notification. Only an
/// `ExchangeEvent::Lifecycle` maps here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstrumentLifecycle {
    pub native_symbol: String,
    pub kind: String,
    pub close_time_us: Option<i64>,
    pub title: Option<String>,
    pub tick_size_us: Option<i64>,
    pub price_ranges: Vec<CanonicalPriceRange>,
    pub price_level_structure: Option<String>,
}

/// An observed sequence gap. It is never derived from `StreamReset`: a reset
/// is a deliberate invalidation, a gap is an unexplained missing frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamGap {
    pub native_symbol: String,
    pub reason: String,
    pub expected_seq: Option<u64>,
    pub observed_seq: Option<u64>,
}

impl StreamGap {
    #[must_use]
    pub fn from_sequence_gap(
        native_symbol: impl Into<String>,
        reason: impl Into<String>,
        expected_seq: Option<u64>,
        observed_seq: Option<u64>,
    ) -> Self {
        Self {
            native_symbol: native_symbol.into(),
            reason: reason.into(),
            expected_seq,
            observed_seq,
        }
    }
}

/// Invalidated symbols awaiting fresh snapshots. Only an
/// `ExchangeEvent::StreamReset` maps here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamReset {
    pub native_symbols: Vec<String>,
    pub reason: String,
}

/// The typed canonical taxonomy. Every variant is a distinct event kind with
/// no silent coercion between them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CanonicalEvent {
    BookSnapshot(BookSnapshot),
    BookDelta(BookDelta),
    Trade(Trade),
    BestBidOffer(BestBidOffer),
    AssetContext(AssetContext),
    InstrumentLifecycle(InstrumentLifecycle),
    StreamGap(StreamGap),
    StreamReset(StreamReset),
}

impl CanonicalEvent {
    #[must_use]
    pub const fn kind(&self) -> CanonicalKind {
        match self {
            Self::BookSnapshot(_) => CanonicalKind::BookSnapshot,
            Self::BookDelta(_) => CanonicalKind::BookDelta,
            Self::Trade(_) => CanonicalKind::Trade,
            Self::BestBidOffer(_) => CanonicalKind::BestBidOffer,
            Self::AssetContext(_) => CanonicalKind::AssetContext,
            Self::InstrumentLifecycle(_) => CanonicalKind::InstrumentLifecycle,
            Self::StreamGap(_) => CanonicalKind::StreamGap,
            Self::StreamReset(_) => CanonicalKind::StreamReset,
        }
    }
}

/// Exact, total mapping from the unchanged market-specific wire event to the
/// canonical taxonomy. Only semantics that are already present are mapped:
///
/// - `Snapshot` -> `BookSnapshot`
/// - `LevelChange` -> `BookDelta`
/// - `Lifecycle` -> `InstrumentLifecycle`
/// - `StreamReset` -> `StreamReset`
///
/// No variant maps to `Trade`, `BestBidOffer`, `AssetContext` or `StreamGap`;
/// those require their own explicit observation and are never fabricated here.
impl From<&model::ExchangeEvent> for CanonicalEvent {
    fn from(event: &model::ExchangeEvent) -> Self {
        match event {
            model::ExchangeEvent::Snapshot {
                native_symbol,
                book,
                ..
            } => Self::BookSnapshot(BookSnapshot::from((native_symbol.as_str(), book))),
            model::ExchangeEvent::LevelChange {
                native_symbol,
                side,
                price,
                change,
                ..
            } => Self::BookDelta(BookDelta {
                native_symbol: native_symbol.clone(),
                side: *side,
                price: price.raw(),
                change: match change {
                    model::QuantityChange::Absolute(quantity) => CanonicalChange::Absolute {
                        quantity: quantity.raw(),
                    },
                    model::QuantityChange::Delta(delta) => CanonicalChange::Delta {
                        quantity: delta.raw(),
                    },
                },
            }),
            model::ExchangeEvent::Lifecycle {
                native_symbol,
                kind,
                close_time_us,
                title,
                tick_size_us,
                price_ranges,
                price_level_structure,
                ..
            } => Self::InstrumentLifecycle(InstrumentLifecycle {
                native_symbol: native_symbol.clone(),
                kind: lifecycle_kind(kind),
                close_time_us: *close_time_us,
                title: title.clone(),
                tick_size_us: *tick_size_us,
                price_ranges: price_ranges
                    .as_ref()
                    .map(|ranges| ranges.iter().map(CanonicalPriceRange::from).collect())
                    .unwrap_or_default(),
                price_level_structure: price_level_structure.clone(),
            }),
            model::ExchangeEvent::StreamReset {
                native_symbols,
                reason,
                ..
            } => Self::StreamReset(StreamReset {
                native_symbols: native_symbols.clone(),
                reason: reason.to_string(),
            }),
        }
    }
}

fn lifecycle_kind(kind: &model::LifecycleKind) -> String {
    match kind {
        model::LifecycleKind::Created => "created",
        model::LifecycleKind::Activated => "activated",
        model::LifecycleKind::Deactivated => "deactivated",
        model::LifecycleKind::CloseDateUpdated => "close_date_updated",
        model::LifecycleKind::Determined => "determined",
        model::LifecycleKind::Settled => "settled",
        model::LifecycleKind::PriceStructureUpdated => "price_structure_updated",
        model::LifecycleKind::MetadataUpdated => "metadata_updated",
        model::LifecycleKind::NewMarket => "new_market",
        model::LifecycleKind::Resolved => "resolved",
        model::LifecycleKind::Other(detail) => return format!("other:{detail}"),
    }
    .to_owned()
}

/// Explicit inputs that the legacy wire event does not carry: identities,
/// provenance pointer and the derivation namespace/authority. Passing them
/// explicitly prevents identity from being guessed from a mutable title or
/// from an unresolvable display symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizationContext {
    pub source_id: OpaqueId,
    pub feed_id: Option<FeedId>,
    pub instrument_id: Option<InstrumentId>,
    /// Exact raw bytes or a stable reference into the independent raw journal.
    pub raw_observation: Option<String>,
    pub namespace: String,
    pub authority: String,
    /// Used only for events that carry no venue metadata (for example reset).
    pub connection_epoch: u64,
}

/// Generic canonical envelope. `T` is one payload from the taxonomy or the
/// `CanonicalEvent` sum type. Provenance and schema version are invariants a
/// reader enforces, not optional hints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalEnvelope<T> {
    pub event_id: EventId,
    pub instrument_id: Option<InstrumentId>,
    pub source_id: OpaqueId,
    pub feed_id: Option<FeedId>,
    pub connection_epoch: u64,
    pub sequence: Option<SequenceMetadata>,
    pub source_time: Option<i64>,
    pub receive_time: i64,
    pub raw_observation: Option<String>,
    pub schema_version: u32,
    pub payload: T,
}

impl<T> CanonicalEnvelope<T> {
    /// Validate the invariants a reader requires before accepting an envelope.
    pub fn validate(&self) -> Result<(), CanonicalError> {
        if self.schema_version != CANONICAL_SCHEMA_VERSION {
            return Err(CanonicalError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: CANONICAL_SCHEMA_VERSION,
            });
        }
        match &self.raw_observation {
            Some(reference) if !reference.trim().is_empty() => Ok(()),
            _ => Err(CanonicalError::MissingProvenance),
        }
    }
}

impl CanonicalEnvelope<CanonicalEvent> {
    /// Build an envelope from an unchanged `ExchangeEvent` and explicit
    /// context. Receive time and all venue/local ordering metadata are copied
    /// exactly; no clock is read and no event kind is invented.
    #[must_use]
    pub fn from_exchange(event: &model::ExchangeEvent, context: &NormalizationContext) -> Self {
        let payload = CanonicalEvent::from(event);
        let native_symbol = match event {
            model::ExchangeEvent::Snapshot { native_symbol, .. }
            | model::ExchangeEvent::LevelChange { native_symbol, .. }
            | model::ExchangeEvent::Lifecycle { native_symbol, .. } => native_symbol.as_str(),
            model::ExchangeEvent::StreamReset { .. } => "global",
        };
        let (connection_epoch, sequence, source_time, receive_time) = match event {
            model::ExchangeEvent::Snapshot { meta, .. }
            | model::ExchangeEvent::LevelChange { meta, .. }
            | model::ExchangeEvent::Lifecycle { meta, .. } => (
                meta.connection_epoch,
                Some(SequenceMetadata {
                    source_seq: meta.seq,
                    exchange_clock: meta.clock,
                    receive_seq: meta.receive_seq,
                }),
                meta.exchange_ts_us,
                meta.received_at_us,
            ),
            model::ExchangeEvent::StreamReset { received_at_us, .. } => {
                (context.connection_epoch, None, None, *received_at_us)
            }
        };
        let feed = context
            .feed_id
            .as_ref()
            .map_or_else(|| "none".to_owned(), |id| id.as_str().to_owned());
        let seq = sequence.map_or_else(
            || "no-sequence".to_owned(),
            |metadata| {
                format!(
                    "{}:{}",
                    metadata.receive_seq,
                    metadata
                        .source_seq
                        .map_or_else(|| "none".to_owned(), |value| value.to_string())
                )
            },
        );
        let stable_key = format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            native_symbol,
            context.source_id.as_str(),
            feed,
            connection_epoch,
            seq,
            receive_time,
            payload.kind().as_str(),
        );
        Self {
            event_id: EventId::derive(&context.namespace, &context.authority, &stable_key),
            instrument_id: context.instrument_id.clone(),
            source_id: context.source_id.clone(),
            feed_id: context.feed_id.clone(),
            connection_epoch,
            sequence,
            source_time,
            receive_time,
            raw_observation: context.raw_observation.clone(),
            schema_version: CANONICAL_SCHEMA_VERSION,
            payload,
        }
    }
}

/// Errors from the canonical reader/store boundary. Both are fail-closed: an
/// envelope that cannot be trusted is never admitted.
#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("unsupported canonical schema version {found}; reader supports {supported}")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },
    #[error("canonical envelope is missing raw provenance")]
    MissingProvenance,
    #[error("canonical envelope decode failed: {0}")]
    Decode(#[from] serde_json::Error),
}

/// Decodes and validates canonical envelopes. This is a reader contract only:
/// it neither writes the raw journal nor projects the SBE output.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalReader;

impl CanonicalReader {
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Decode a serialized envelope and enforce schema version and provenance.
    pub fn decode(&self, json: &str) -> Result<CanonicalEnvelope<CanonicalEvent>, CanonicalError> {
        let envelope: CanonicalEnvelope<CanonicalEvent> = serde_json::from_str(json)?;
        envelope.validate()?;
        Ok(envelope)
    }
}

/// Receipt returned for one accepted append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendReceipt {
    pub event_id: EventId,
    pub position: u64,
}

/// Conceptual normalized durability contract. No durable implementation exists
/// in Phase 1: the raw-frame journal remains the independent record and the
/// in-memory store below exists for tests only. Implementations must preserve
/// raw provenance; appending an invalid envelope is rejected.
pub trait NormalizedStore {
    /// Append one validated envelope and return its stable position.
    fn append(
        &mut self,
        envelope: CanonicalEnvelope<CanonicalEvent>,
    ) -> Result<AppendReceipt, CanonicalError>;

    /// Provide envelopes in append order, starting at `from` when supplied.
    /// The returned iterator borrows the store and never reads the raw journal.
    fn replay<'a>(
        &'a self,
        from: Option<&'a EventId>,
    ) -> Box<dyn Iterator<Item = &'a CanonicalEnvelope<CanonicalEvent>> + 'a>;
}

/// Test-only in-memory normalized store. It is not durable, not concurrent,
/// and not a production storage subsystem.
#[derive(Debug, Clone, Default)]
pub struct InMemoryNormalizedStore {
    events: Vec<CanonicalEnvelope<CanonicalEvent>>,
}

impl NormalizedStore for InMemoryNormalizedStore {
    fn append(
        &mut self,
        envelope: CanonicalEnvelope<CanonicalEvent>,
    ) -> Result<AppendReceipt, CanonicalError> {
        envelope.validate()?;
        let event_id = envelope.event_id.clone();
        self.events.push(envelope);
        Ok(AppendReceipt {
            event_id,
            position: (self.events.len() - 1) as u64,
        })
    }

    fn replay<'a>(
        &'a self,
        from: Option<&'a EventId>,
    ) -> Box<dyn Iterator<Item = &'a CanonicalEnvelope<CanonicalEvent>> + 'a> {
        match from {
            None => Box::new(self.events.iter()),
            Some(id) => Box::new(
                self.events
                    .iter()
                    .skip_while(move |event| event.event_id != *id),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(raw: &str) -> NormalizationContext {
        NormalizationContext {
            source_id: OpaqueId::derive("source", "test", "authority", "source-1"),
            feed_id: Some(FeedId::derive("test", "authority", "feed-1")),
            instrument_id: Some(InstrumentId::derive("test", "authority", "KX-A")),
            raw_observation: Some(raw.to_owned()),
            namespace: "canonical-test".to_owned(),
            authority: "test".to_owned(),
            connection_epoch: 4,
        }
    }

    fn meta() -> model::EventMeta {
        let mut meta = model::EventMeta::new(1_000);
        meta.exchange_ts_us = Some(900);
        meta.seq = Some(7);
        meta.clock = Some(42);
        meta.connection_epoch = 3;
        meta.receive_seq = 11;
        meta
    }

    fn snapshot_event() -> model::ExchangeEvent {
        let book = model::BookSnapshot {
            bids: vec![model::Level::new(10, 5).expect("bid")],
            asks: vec![model::Level::new(11, 6).expect("ask")],
        };
        model::ExchangeEvent::Snapshot {
            native_symbol: "KX-A".to_owned(),
            book,
            meta: meta(),
        }
    }

    #[test]
    fn canonical_kinds_are_distinct_and_stable() {
        let kinds = [
            CanonicalKind::BookSnapshot,
            CanonicalKind::BookDelta,
            CanonicalKind::Trade,
            CanonicalKind::BestBidOffer,
            CanonicalKind::AssetContext,
            CanonicalKind::InstrumentLifecycle,
            CanonicalKind::StreamGap,
            CanonicalKind::StreamReset,
        ];
        let strings: Vec<&str> = kinds.iter().map(|kind| kind.as_str()).collect();
        assert_eq!(
            strings,
            vec![
                "book_snapshot",
                "book_delta",
                "trade",
                "best_bid_offer",
                "asset_context",
                "instrument_lifecycle",
                "stream_gap",
                "stream_reset",
            ]
        );
        let unique: std::collections::BTreeSet<&str> = strings.into_iter().collect();
        assert_eq!(unique.len(), 8);
        assert_eq!(CanonicalKind::BookDelta.to_string(), "book_delta");
    }

    #[test]
    fn snapshot_converts_to_book_snapshot_with_provenance_and_receive_time() {
        let event = snapshot_event();
        let envelope = CanonicalEnvelope::from_exchange(&event, &context("journal:run/s0@12"));
        assert_eq!(envelope.receive_time, 1_000);
        assert_eq!(envelope.source_time, Some(900));
        assert_eq!(envelope.connection_epoch, 3);
        assert_eq!(
            envelope.sequence,
            Some(SequenceMetadata {
                source_seq: Some(7),
                exchange_clock: Some(42),
                receive_seq: 11,
            })
        );
        assert_eq!(
            envelope.instrument_id,
            Some(InstrumentId::derive("test", "authority", "KX-A"))
        );
        assert_eq!(
            envelope.raw_observation.as_deref(),
            Some("journal:run/s0@12")
        );
        assert_eq!(envelope.schema_version, CANONICAL_SCHEMA_VERSION);
        assert_eq!(envelope.payload.kind(), CanonicalKind::BookSnapshot);
        assert!(matches!(
            &envelope.payload,
            CanonicalEvent::BookSnapshot(book)
                if book.native_symbol == "KX-A" && book.bids.len() == 1 && book.asks.len() == 1
        ));
        envelope.validate().expect("valid envelope");
    }

    #[test]
    fn level_change_converts_to_book_delta_with_provenance_and_receive_time() {
        let event = model::ExchangeEvent::LevelChange {
            native_symbol: "KX-A".to_owned(),
            side: Side::Buy,
            price: model::Price::from_raw(10),
            change: model::QuantityChange::Delta(model::QuantityDelta::from_raw(-2)),
            meta: meta(),
        };
        let envelope = CanonicalEnvelope::from_exchange(&event, &context("journal:run/s0@13"));
        assert_eq!(envelope.receive_time, 1_000);
        assert_eq!(
            envelope.raw_observation.as_deref(),
            Some("journal:run/s0@13")
        );
        assert_eq!(envelope.payload.kind(), CanonicalKind::BookDelta);
        assert!(matches!(
            &envelope.payload,
            CanonicalEvent::BookDelta(delta)
                if delta.side == Side::Buy
                    && delta.price == 10
                    && delta.change == CanonicalChange::Delta { quantity: -2 }
        ));
    }

    #[test]
    fn lifecycle_converts_to_instrument_lifecycle_with_provenance() {
        let event = model::ExchangeEvent::Lifecycle {
            native_symbol: "KX-A".to_owned(),
            kind: model::LifecycleKind::Settled,
            close_time_us: Some(2_000),
            title: Some("mutable title".to_owned()),
            tick_size_us: Some(1),
            price_ranges: Some(vec![model::PriceRange {
                start_us: 0,
                end_us: 10,
                step_us: 1,
            }]),
            price_level_structure: Some("grid".to_owned()),
            meta: meta(),
        };
        let envelope = CanonicalEnvelope::from_exchange(&event, &context("journal:run/s0@14"));
        assert_eq!(envelope.receive_time, 1_000);
        assert_eq!(envelope.payload.kind(), CanonicalKind::InstrumentLifecycle);
        assert!(matches!(
            &envelope.payload,
            CanonicalEvent::InstrumentLifecycle(lifecycle)
                if lifecycle.kind == "settled"
                    && lifecycle.close_time_us == Some(2_000)
                    && lifecycle.price_ranges.len() == 1
        ));
    }

    #[test]
    fn stream_reset_converts_to_stream_reset_and_never_to_stream_gap() {
        let event = model::ExchangeEvent::StreamReset {
            native_symbols: vec!["KX-A".to_owned(), "KX-B".to_owned()],
            reason: model::ResetReason::SequenceGap,
            received_at_us: 5_000,
        };
        let envelope = CanonicalEnvelope::from_exchange(&event, &context("journal:run/s0@15"));
        assert_eq!(envelope.receive_time, 5_000);
        assert_eq!(envelope.source_time, None);
        assert_eq!(envelope.sequence, None);
        assert_eq!(envelope.connection_epoch, 4);
        assert_eq!(envelope.payload.kind(), CanonicalKind::StreamReset);
        assert_ne!(envelope.payload.kind(), CanonicalKind::StreamGap);
        assert!(matches!(
            &envelope.payload,
            CanonicalEvent::StreamReset(reset)
                if reset.native_symbols.len() == 2 && reset.reason == "sequence-gap"
        ));
    }

    #[test]
    fn exchange_conversions_never_fabricate_trades_bbo_assets_or_gaps() {
        let event = snapshot_event();
        let converted = CanonicalEvent::from(&event);
        assert_eq!(converted.kind(), CanonicalKind::BookSnapshot);
        for forbidden in [
            CanonicalKind::Trade,
            CanonicalKind::BestBidOffer,
            CanonicalKind::AssetContext,
            CanonicalKind::StreamGap,
        ] {
            assert_ne!(converted.kind(), forbidden);
        }

        let level_change = model::ExchangeEvent::LevelChange {
            native_symbol: "KX-A".to_owned(),
            side: Side::Sell,
            price: model::Price::from_raw(9),
            change: model::QuantityChange::Absolute(model::Quantity::ZERO),
            meta: meta(),
        };
        assert_eq!(
            CanonicalEvent::from(&level_change).kind(),
            CanonicalKind::BookDelta
        );
        let reset = model::ExchangeEvent::StreamReset {
            native_symbols: vec!["KX-A".to_owned()],
            reason: model::ResetReason::Connected,
            received_at_us: 1,
        };
        assert_eq!(
            CanonicalEvent::from(&reset).kind(),
            CanonicalKind::StreamReset
        );

        // One wire event produces exactly one canonical event; no fan-out into
        // a trade or an extra book event.
        let envelopes = [&event, &level_change, &reset]
            .into_iter()
            .map(|wire| CanonicalEnvelope::from_exchange(wire, &context("journal:ref")))
            .collect::<Vec<_>>();
        assert_eq!(envelopes.len(), 3);
        assert!(envelopes.iter().all(|envelope| !matches!(
            envelope.payload.kind(),
            CanonicalKind::Trade
                | CanonicalKind::BestBidOffer
                | CanonicalKind::AssetContext
                | CanonicalKind::StreamGap
        )));
    }

    #[test]
    fn bbo_is_best_bid_offer_never_l2() {
        let bbo = CanonicalEvent::BestBidOffer(BestBidOffer::from_bbo_observation(
            "hyperliquid:BTC",
            Some(CanonicalLevel {
                price: 10,
                quantity: 1,
            }),
            Some(CanonicalLevel {
                price: 11,
                quantity: 2,
            }),
        ));
        assert_eq!(bbo.kind(), CanonicalKind::BestBidOffer);
        assert_ne!(bbo.kind(), CanonicalKind::BookDelta);
        assert_ne!(bbo.kind(), CanonicalKind::BookSnapshot);
        assert!(matches!(&bbo, CanonicalEvent::BestBidOffer(_)));
    }

    #[test]
    fn telemetry_and_assets_are_asset_context_never_book_delta() {
        let fields = BTreeMap::from([("mid".to_owned(), "42000.0".to_owned())]);
        let telemetry =
            CanonicalEvent::AssetContext(AssetContext::from_telemetry("BTC", "allMids", fields));
        assert_eq!(telemetry.kind(), CanonicalKind::AssetContext);
        assert_ne!(telemetry.kind(), CanonicalKind::BookDelta);
        assert_ne!(telemetry.kind(), CanonicalKind::BookSnapshot);
        assert!(matches!(
            &telemetry,
            CanonicalEvent::AssetContext(asset)
                if asset.channel == "allMids" && asset.fields.len() == 1
        ));
    }

    #[test]
    fn trades_are_trade_never_book_delta() {
        let trade = CanonicalEvent::Trade(Trade::from_trade_observation(
            "hyperliquid:BTC",
            Some(Side::Buy),
            42_000,
            3,
        ));
        assert_eq!(trade.kind(), CanonicalKind::Trade);
        assert_ne!(trade.kind(), CanonicalKind::BookDelta);
        assert!(matches!(
            &trade,
            CanonicalEvent::Trade(value) if value.quantity == 3 && value.side == Some(Side::Buy)
        ));
    }

    #[test]
    fn envelope_serde_round_trip_carries_schema_version() {
        let envelope = CanonicalEnvelope::from_exchange(&snapshot_event(), &context("journal:ref"));
        let json = serde_json::to_string(&envelope).expect("serializable envelope");
        assert!(json.contains("\"schema_version\":1"));
        let decoded: CanonicalEnvelope<CanonicalEvent> =
            serde_json::from_str(&json).expect("deserializable envelope");
        assert_eq!(decoded, envelope);
        let reader = CanonicalReader::new();
        assert_eq!(
            reader.decode(&json).expect("reader accepts valid envelope"),
            envelope
        );
    }

    #[test]
    fn unsupported_schema_version_is_rejected_by_reader() {
        let mut envelope =
            CanonicalEnvelope::from_exchange(&snapshot_event(), &context("journal:ref"));
        let json = serde_json::to_string(&envelope).expect("serializable envelope");
        envelope.schema_version = CANONICAL_SCHEMA_VERSION + 1;
        assert!(matches!(
            envelope.validate(),
            Err(CanonicalError::UnsupportedSchemaVersion { .. })
        ));
        let tampered = json.replace(
            &format!("\"schema_version\":{CANONICAL_SCHEMA_VERSION}"),
            &format!("\"schema_version\":{}", CANONICAL_SCHEMA_VERSION + 1),
        );
        assert!(matches!(
            CanonicalReader::new().decode(&tampered),
            Err(CanonicalError::UnsupportedSchemaVersion { .. })
        ));
    }

    #[test]
    fn missing_provenance_is_rejected_by_reader_and_store() {
        let mut envelope =
            CanonicalEnvelope::from_exchange(&snapshot_event(), &context("journal:ref"));
        envelope.raw_observation = None;
        assert!(matches!(
            envelope.validate(),
            Err(CanonicalError::MissingProvenance)
        ));
        let json = serde_json::to_string(&envelope).expect("serializable envelope");
        assert!(matches!(
            CanonicalReader::new().decode(&json),
            Err(CanonicalError::MissingProvenance)
        ));

        envelope.raw_observation = Some("   ".to_owned());
        let mut store = InMemoryNormalizedStore::default();
        assert!(matches!(
            store.append(envelope),
            Err(CanonicalError::MissingProvenance)
        ));
        assert_eq!(store.replay(None).count(), 0);
    }

    #[test]
    fn in_memory_store_appends_and_replays_from_event_id() {
        let mut store = InMemoryNormalizedStore::default();
        let first = CanonicalEnvelope::from_exchange(&snapshot_event(), &context("journal:1"));
        let second = CanonicalEnvelope::from_exchange(
            &model::ExchangeEvent::LevelChange {
                native_symbol: "KX-A".to_owned(),
                side: Side::Buy,
                price: model::Price::from_raw(10),
                change: model::QuantityChange::Delta(model::QuantityDelta::from_raw(1)),
                meta: meta(),
            },
            &context("journal:2"),
        );
        let first_id = first.event_id.clone();
        let second_id = second.event_id.clone();

        let first_receipt = store.append(first).expect("first append");
        let second_receipt = store.append(second).expect("second append");
        assert_eq!(first_receipt.event_id, first_id);
        assert_eq!(first_receipt.position, 0);
        assert_eq!(second_receipt.event_id, second_id);
        assert_eq!(second_receipt.position, 1);

        assert_eq!(store.replay(None).count(), 2);
        let from_second: Vec<&EventId> = store
            .replay(Some(&second_id))
            .map(|envelope| &envelope.event_id)
            .collect();
        assert_eq!(from_second, vec![&second_id]);
        assert_eq!(store.replay(Some(&first_id)).count(), 2);
        let unknown = EventId::derive("canonical-test", "test", "missing");
        assert_eq!(store.replay(Some(&unknown)).count(), 0);
    }

    #[test]
    fn event_id_is_deterministic_from_provenance() {
        let first = CanonicalEnvelope::from_exchange(&snapshot_event(), &context("journal:ref"));
        let second = CanonicalEnvelope::from_exchange(&snapshot_event(), &context("journal:ref"));
        assert_eq!(first.event_id, second.event_id);
        let mut other_context = context("journal:ref");
        other_context.source_id = OpaqueId::derive("source", "test", "authority", "source-2");
        let third = CanonicalEnvelope::from_exchange(&snapshot_event(), &other_context);
        assert_ne!(first.event_id, third.event_id);
    }

    #[test]
    fn append_rejects_invalid_schema_version_fail_closed() {
        let mut envelope =
            CanonicalEnvelope::from_exchange(&snapshot_event(), &context("journal:ref"));
        envelope.schema_version = 0;
        let mut store = InMemoryNormalizedStore::default();
        assert!(matches!(
            store.append(envelope),
            Err(CanonicalError::UnsupportedSchemaVersion { .. })
        ));
        assert_eq!(store.replay(None).count(), 0);
    }
}
