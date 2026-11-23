//! Hyperliquid selected-book codec (H2).
//!
//! Decodes the venue's full-book `l2Book` pushes into normalized
//! [`ExchangeEvent::Snapshot`] values and treats `trades` as telemetry only.
//! There is no delta stream on this venue: this module never constructs a
//! [`ExchangeEvent::LevelChange`].
//!
//! Identity and numeric semantics are inherited from H0: a native symbol is
//! `hyperliquid:perp:<dex>:<coin>` (the empty DEX is the main DEX) and every
//! wire price/size string is parsed exactly at the canonical SBE scale, with
//! inexact values rejected rather than rounded. Spot instruments are never
//! selected for books.

use std::collections::BTreeSet;

use anyhow::{Context, bail};
use serde_json::{Value, json};

use crate::{
    fixed,
    model::{BookSnapshot, EventMeta, ExchangeEvent, Level},
};

/// Canonical SBE decimal scale. Mirrors `fixed::DECIMALS`; a unit test keeps
/// the two in lockstep.
const SCALE: u8 = 6;

/// Venue channel pushing complete two-sided level arrays.
pub const CHANNEL_L2_BOOK: &str = "l2Book";
/// Venue channel pushing trade prints. Telemetry only, never depth.
pub const CHANNEL_TRADES: &str = "trades";

/// Prefix of a H0 perpetual native symbol. Spot identities do not carry it
/// and are therefore excluded from book selection.
const PERP_PREFIX: &str = "hyperliquid:perp:";

/// One decoded price level (exact coefficient at `SCALE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BookLevel {
    pub price: i64,
    pub quantity: i64,
}

/// One decoded `l2Book` frame, before it is mapped to a native symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BookFrame {
    pub coin: String,
    /// DEX from the wire frame; empty is the main DEX.
    pub dex: String,
    /// Advisory feed timestamp in microseconds. Never an ordering clock.
    pub exchange_ts_us: Option<i64>,
    pub bids: Vec<BookLevel>,
    pub asks: Vec<BookLevel>,
}

/// One decoded trade print. Retained only as raw/telemetry evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trade {
    pub side: String,
    pub price: i64,
    pub quantity: i64,
    pub id: Option<u64>,
}

/// One decoded `trades` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TradeFrame {
    pub coin: String,
    pub dex: String,
    pub exchange_ts_us: Option<i64>,
    pub trades: Vec<Trade>,
}

/// One application frame dispatched by channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BookWireFrame {
    L2Book(BookFrame),
    Trades(TradeFrame),
    /// A recognised telemetry channel (validated by the H1 codec) or an
    /// additive channel this build does not subscribe to.
    Ignored(String),
}

/// Build a H0 perpetual native symbol from its DEX and coin.
#[must_use]
pub fn native_symbol(dex: &str, coin: &str) -> String {
    if dex.is_empty() {
        format!("{PERP_PREFIX}:{coin}")
    } else {
        format!("{PERP_PREFIX}{dex}:{coin}")
    }
}

/// Split a H0 perpetual native symbol into `(dex, coin)`.
///
/// Spot (and any non-perp) identity returns `None`, so it can never be
/// subscribed to a book feed.
#[must_use]
pub fn parse_native_symbol(symbol: &str) -> Option<(String, String)> {
    let rest = symbol.strip_prefix(PERP_PREFIX)?;
    let mut parts = rest.split(':');
    let dex = parts.next()?.to_owned();
    let coin = parts.next()?.to_owned();
    if parts.next().is_some() || coin.is_empty() || coin.contains('/') || dex.contains('/') {
        return None;
    }
    Some((dex, coin))
}

/// Whether a native symbol is a configured selected perpetual.
#[must_use]
pub fn is_selected_perp(symbol: &str, selected: &[String]) -> bool {
    let Some((_, coin)) = parse_native_symbol(symbol) else {
        return false;
    };
    selected.iter().any(|candidate| candidate == &coin)
}

/// Intersect a worker's desired set with the configured selected perpetuals.
/// This is the only universe the H2 session will subscribe to: no spot, no
/// unselected perpetual, no full-universe expansion.
#[must_use]
pub fn selected_symbols(desired: &BTreeSet<String>, selected: &[String]) -> BTreeSet<String> {
    desired
        .iter()
        .filter(|symbol| is_selected_perp(symbol, selected))
        .cloned()
        .collect()
}

/// Build a Hyperliquid subscription command for a selected book channel.
///
/// `coin` is the venue wire name; a non-empty `dex` scopes the command to a
/// non-main DEX so a shared coin name cannot be silently consolidated.
pub fn subscription_request(
    method: &str,
    channel: &str,
    coin: &str,
    dex: &str,
) -> anyhow::Result<Value> {
    anyhow::ensure!(!coin.is_empty(), "empty Hyperliquid book coin");
    if channel != CHANNEL_L2_BOOK && channel != CHANNEL_TRADES {
        bail!("unsupported Hyperliquid book channel `{channel}`");
    }
    let mut subscription = serde_json::Map::new();
    subscription.insert("type".to_owned(), json!(channel));
    subscription.insert("coin".to_owned(), json!(coin));
    if !dex.is_empty() {
        subscription.insert("dex".to_owned(), json!(dex));
    }
    Ok(json!({
        "method": method,
        "subscription": Value::Object(subscription),
    }))
}

fn channel_of(value: &Value) -> anyhow::Result<&str> {
    value
        .get("channel")
        .and_then(Value::as_str)
        .context("Hyperliquid frame has no string `channel`")
}

fn required_coin(data: &Value) -> anyhow::Result<String> {
    let coin = data
        .get("coin")
        .and_then(Value::as_str)
        .context("Hyperliquid book frame has no string `coin`")?;
    anyhow::ensure!(!coin.is_empty(), "empty Hyperliquid book coin");
    Ok(coin.to_owned())
}

fn dex_field(data: &Value) -> anyhow::Result<String> {
    match data.get("dex") {
        None | Some(Value::Null) => Ok(String::new()),
        Some(value) => Ok(value
            .as_str()
            .context("Hyperliquid book frame has a non-string `dex`")?
            .to_owned()),
    }
}

fn exchange_ts_field(data: &Value) -> anyhow::Result<Option<i64>> {
    match data.get("time") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let millis = value
                .as_i64()
                .context("Hyperliquid frame has a non-integer `time`")?;
            let micros = millis
                .checked_mul(1_000)
                .context("Hyperliquid feed timestamp overflows microseconds")?;
            Ok(Some(micros))
        }
    }
}

fn numeric_string(value: Option<&Value>, field: &str, context: &str) -> anyhow::Result<i64> {
    let raw = value.with_context(|| format!("{context} has no `{field}`"))?;
    let text = raw
        .as_str()
        .with_context(|| format!("{context} has a non-string `{field}`"))?;
    fixed::parse_scaled(text, SCALE)
        .with_context(|| format!("parsing `{field}`=`{text}` in {context}"))
}

fn parse_levels(data: &Value, side: &str) -> anyhow::Result<Vec<BookLevel>> {
    let levels = data
        .get("levels")
        .and_then(Value::as_array)
        .with_context(|| "l2Book data has no `levels` array")?;
    let index = match side {
        "bids" => 0,
        "asks" => 1,
        other => bail!("unknown book side `{other}`"),
    };
    let entries = levels
        .get(index)
        .and_then(Value::as_array)
        .with_context(|| format!("l2Book `levels[{index}]` is not an array"))?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let context = format!("l2Book {side} level");
        let price = numeric_string(entry.get("px"), "px", &context)?;
        let quantity = numeric_string(entry.get("sz"), "sz", &context)?;
        anyhow::ensure!(quantity >= 0, "negative l2Book size in {context}");
        out.push(BookLevel { price, quantity });
    }
    Ok(out)
}

/// Decode one `l2Book` frame. Full two-sided snapshots are the only Hyperliquid
/// feed that can anchor a book; the decoder never produces deltas.
pub fn decode_l2_book(text: &str) -> anyhow::Result<BookFrame> {
    let value: Value = serde_json::from_str(text).context("parsing Hyperliquid l2Book JSON")?;
    anyhow::ensure!(
        channel_of(&value)? == CHANNEL_L2_BOOK,
        "frame is not an l2Book push"
    );
    let data = value.get("data").context("l2Book frame has no `data`")?;
    Ok(BookFrame {
        coin: required_coin(data)?,
        dex: dex_field(data)?,
        exchange_ts_us: exchange_ts_field(data)?,
        bids: parse_levels(data, "bids")?,
        asks: parse_levels(data, "asks")?,
    })
}

/// Decode one `trades` frame. Every print is validated exactly, then retained
/// only as telemetry; no level change or snapshot is ever derived from it.
pub fn decode_trades(text: &str) -> anyhow::Result<TradeFrame> {
    let value: Value = serde_json::from_str(text).context("parsing Hyperliquid trades JSON")?;
    anyhow::ensure!(
        channel_of(&value)? == CHANNEL_TRADES,
        "frame is not a trades push"
    );
    let data = value.get("data").context("trades frame has no `data`")?;
    let entries = data
        .as_array()
        .context("Hyperliquid trades data is not an array")?;
    let coin = entries
        .first()
        .map(required_coin)
        .transpose()?
        .context("Hyperliquid trades frame has no entries")?;
    let dex = entries
        .first()
        .map(dex_field)
        .transpose()?
        .unwrap_or_default();
    let exchange_ts_us = entries
        .first()
        .map(exchange_ts_field)
        .transpose()?
        .flatten();
    let mut trades = Vec::with_capacity(entries.len());
    for entry in entries {
        let context = "trades entry";
        anyhow::ensure!(
            required_coin(entry)? == coin,
            "mixed coins in one Hyperliquid trades frame"
        );
        let side = entry
            .get("side")
            .and_then(Value::as_str)
            .context("trades entry has no string `side`")?
            .to_owned();
        anyhow::ensure!(!side.is_empty(), "empty trades side");
        let price = numeric_string(entry.get("px"), "px", context)?;
        let quantity = numeric_string(entry.get("sz"), "sz", context)?;
        anyhow::ensure!(quantity >= 0, "negative trade size in {context}");
        let id = match entry.get("tid") {
            None | Some(Value::Null) => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .context("trades entry has a non-integer `tid`")?,
            ),
        };
        trades.push(Trade {
            side,
            price,
            quantity,
            id,
        });
    }
    Ok(TradeFrame {
        coin,
        dex,
        exchange_ts_us,
        trades,
    })
}

/// Return the channel of one application frame, or a decode error when the
/// envelope is malformed. The caller dispatches to the fixture-pinned codecs.
pub fn frame_channel(text: &str) -> anyhow::Result<String> {
    let value: Value = serde_json::from_str(text).context("parsing Hyperliquid JSON frame")?;
    Ok(channel_of(&value)?.to_owned())
}

/// Convert a decoded book frame into a normalized snapshot event. `received_at_us`
/// is the exact transport read time supplied by the session; the supervisor
/// later stamps the `(connection_epoch, receive_seq)` receive fence.
#[must_use]
pub fn into_snapshot(frame: BookFrame, received_at_us: i64) -> ExchangeEvent {
    let to_level = |level: BookLevel| Level {
        price: crate::model::Price::from_raw(level.price),
        quantity: crate::model::Quantity::new(level.quantity).unwrap_or_default(),
    };
    let book = BookSnapshot {
        bids: frame.bids.into_iter().map(to_level).collect(),
        asks: frame.asks.into_iter().map(to_level).collect(),
    };
    let meta = EventMeta {
        received_at_us,
        exchange_ts_us: frame.exchange_ts_us,
        seq: None,
        clock: None,
        connection_epoch: 0,
        receive_seq: 0,
    };
    ExchangeEvent::Snapshot {
        native_symbol: native_symbol(&frame.dex, &frame.coin),
        book,
        meta,
    }
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;

    #[test]
    fn canonical_scale_matches_the_fixed_pipeline() {
        assert_eq!(usize::from(SCALE), fixed::DECIMALS);
    }

    #[test]
    fn identity_keeps_dex_in_scope_and_excludes_spot() {
        assert_eq!(native_symbol("", "BTC"), "hyperliquid:perp::BTC");
        assert_eq!(native_symbol("xyz", "BTC"), "hyperliquid:perp:xyz:BTC");
        assert_eq!(
            parse_native_symbol("hyperliquid:perp::BTC"),
            Some((String::new(), "BTC".to_owned()))
        );
        assert_eq!(
            parse_native_symbol("hyperliquid:perp:xyz:BTC"),
            Some(("xyz".to_owned(), "BTC".to_owned()))
        );
        assert_eq!(parse_native_symbol("hyperliquid:spot:PURR/USDC"), None);
        assert_eq!(parse_native_symbol("hyperliquid:perp::"), None);
    }

    #[test]
    fn selection_is_exact_and_never_includes_spot_or_unlisted_perps() {
        let selected = vec!["BTC".to_owned(), "ETH".to_owned()];
        let desired: BTreeSet<String> = [
            "hyperliquid:perp::BTC".to_owned(),
            "hyperliquid:perp::ETH".to_owned(),
            "hyperliquid:perp::DOGE".to_owned(),
            "hyperliquid:spot:PURR/USDC".to_owned(),
        ]
        .into_iter()
        .collect();
        let chosen = selected_symbols(&desired, &selected);
        assert_eq!(
            chosen,
            [
                "hyperliquid:perp::BTC".to_owned(),
                "hyperliquid:perp::ETH".to_owned()
            ]
            .into_iter()
            .collect()
        );
        assert!(is_selected_perp("hyperliquid:perp:xyz:BTC", &selected));
        assert!(!is_selected_perp("hyperliquid:spot:PURR/USDC", &selected));
    }

    #[test]
    fn subscription_commands_cover_exactly_l2_book_and_trades() {
        assert_eq!(
            subscription_request("subscribe", CHANNEL_L2_BOOK, "BTC", "").expect("l2Book command"),
            json!({"method":"subscribe","subscription":{"type":"l2Book","coin":"BTC"}})
        );
        assert_eq!(
            subscription_request("unsubscribe", CHANNEL_TRADES, "BTC", "xyz")
                .expect("trades command"),
            json!({"method":"unsubscribe","subscription":{"type":"trades","coin":"BTC","dex":"xyz"}})
        );
        assert!(
            subscription_request("subscribe", "assetCtxs", "BTC", "").is_err(),
            "only fixture-pinned book channels are subscribable"
        );
    }

    #[test]
    fn malformed_envelope_is_a_decode_error() {
        assert!(frame_channel("not json").is_err());
        assert!(frame_channel(r#"{"data":{}}"#).is_err());
        assert!(decode_l2_book(r#"{"channel":"trades","data":[]}"#).is_err());
    }
}
