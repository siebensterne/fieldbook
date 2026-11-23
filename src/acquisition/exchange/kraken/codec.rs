//! Kraken reference-data codec (H0).
//!
//! Parses an offline or live `AssetPairs` document into validated `MarketInfo`
//! records. H0 decodes reference data only: no price or depth frame is
//! decoded here, and no socket is opened. Unknown additive fields are ignored,
//! numeric strings are parsed exactly, and anything that cannot be represented
//! at the canonical SBE scale is rejected rather than silently rounded.

use anyhow::Context as _;
use serde_json::Value;

use crate::model::{MarketInfo, NumericSpec, PriceUnit, Quantity, QuantityUnit};

/// Canonical SBE scale used by the collector.
const SCALE: u32 = 6;
const SCALE_U8: u8 = 6;

/// Only a fully online pair is active reference data. Kraken's restricted
/// states (`cancel_only`, `limit_only`, `post_only`, `maintenance`) are excluded
/// rather than inferred to be tradeable.
const ACTIVE_STATUS: &str = "online";

/// Convert a decimal string such as `0.1` into an exact raw step at the
/// canonical SBE scale. More than six fractional digits cannot be represented
/// exactly and is rejected, never rounded.
fn parse_tick_size(raw: &str) -> anyhow::Result<i64> {
    let trimmed = raw.trim();
    anyhow::ensure!(!trimmed.is_empty(), "empty tick_size");
    let (whole, fraction) = match trimmed.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (trimmed, None),
    };
    anyhow::ensure!(
        !whole.is_empty() && whole.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid tick_size `{raw}`"
    );
    let whole: i64 = whole
        .parse()
        .with_context(|| format!("parsing tick_size `{raw}`"))?;
    let mut fraction_raw = 0i64;
    if let Some(fraction) = fraction {
        anyhow::ensure!(
            !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit()),
            "invalid tick_size `{raw}`"
        );
        anyhow::ensure!(
            fraction.len() <= SCALE as usize,
            "tick_size `{raw}` has {} fractional digits, exceeding canonical scale {SCALE}; value cannot be represented exactly",
            fraction.len()
        );
        for (index, byte) in fraction.bytes().enumerate() {
            let power = SCALE as usize - index - 1;
            fraction_raw += i64::from(byte - b'0') * 10i64.pow(power as u32);
        }
    }
    let step = whole
        .checked_mul(10i64.pow(SCALE))
        .and_then(|scaled| scaled.checked_add(fraction_raw))
        .with_context(|| format!("tick_size `{raw}` overflows canonical scale"))?;
    anyhow::ensure!(step > 0, "non-positive tick_size `{raw}`");
    Ok(step)
}

/// Derive the exact quantity step from Kraken's `lot_decimals` (the number of
/// fractional digits in the minimum lot). More than six decimals cannot be
/// represented at the canonical scale and is rejected.
fn lot_step(decimals: u32) -> anyhow::Result<Quantity> {
    anyhow::ensure!(
        decimals <= SCALE,
        "lot_decimals {decimals} exceed canonical SBE scale {SCALE}; lot size cannot be represented exactly"
    );
    Quantity::new(
        10i64
            .checked_pow(SCALE - decimals)
            .context("computing lot step")?,
    )
    .context("invalid lot step")
}

/// Canonicalize Kraken's legacy asset codes. The map is explicit: an unknown
/// code is passed through unchanged rather than guessed from prefixes.
fn normalize_code(code: &str) -> &str {
    match code {
        "XXBT" | "XBT" => "XBT",
        "XETH" | "ETH" => "ETH",
        "XXRP" | "XRP" => "XRP",
        "XLTC" | "LTC" => "LTC",
        "XDG" | "DOGE" => "DOGE",
        "XADA" | "ADA" => "ADA",
        "XSOL" | "SOL" => "SOL",
        "XDOT" | "DOT" => "DOT",
        "ZUSD" | "USD" => "USD",
        "ZEUR" | "EUR" => "EUR",
        "ZGBP" | "GBP" => "GBP",
        "ZJPY" | "JPY" => "JPY",
        "ZCAD" | "CAD" => "CAD",
        "USDT" => "USDT",
        "USDC" => "USDC",
        other => other,
    }
}

fn required_str<'a>(value: &'a Value, field: &str, context: &str) -> anyhow::Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("missing or invalid `{field}` in {context}"))
}

fn required_u32(value: &Value, field: &str, context: &str) -> anyhow::Result<u32> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
        .with_context(|| format!("missing or invalid `{field}` in {context}"))
}

/// Decode one `AssetPairs` entry. Returns `None` for a non-active pair.
pub fn decode_pair(key: &str, entry: &Value) -> anyhow::Result<Option<MarketInfo>> {
    let context = format!("AssetPairs entry `{key}`");
    let status = required_str(entry, "status", &context)?;
    if status != ACTIVE_STATUS {
        return Ok(None);
    }
    let base = normalize_code(required_str(entry, "base", &context)?);
    let quote = normalize_code(required_str(entry, "quote", &context)?);
    anyhow::ensure!(
        !base.is_empty() && !quote.is_empty() && base != quote,
        "invalid base/quote in {context}"
    );

    // Prefer the v2 websocket name; fall back to normalized legacy base/quote
    // when a pair has no `wsname`. Both routes yield the same namespace.
    let pair_name = match entry.get("wsname").and_then(Value::as_str) {
        Some(wsname) => {
            let (ws_base, ws_quote) = wsname
                .split_once('/')
                .with_context(|| format!("invalid wsname `{wsname}` in {context}"))?;
            let ws_base = normalize_code(ws_base);
            let ws_quote = normalize_code(ws_quote);
            anyhow::ensure!(
                !ws_base.is_empty() && !ws_quote.is_empty() && ws_base != ws_quote,
                "invalid wsname `{wsname}` in {context}"
            );
            format!("{ws_base}/{ws_quote}")
        }
        None => format!("{base}/{quote}"),
    };
    let native_symbol = format!("kraken:spot:{pair_name}");
    let title = entry
        .get("altname")
        .and_then(Value::as_str)
        .unwrap_or(&pair_name)
        .to_owned();

    let tick_size_us = parse_tick_size(required_str(entry, "tick_size", &context)?)?;
    let lot_decimals = required_u32(entry, "lot_decimals", &context)?;
    let step = lot_step(lot_decimals)?;
    let spec = NumericSpec {
        price_scale: SCALE_U8,
        quantity_scale: SCALE_U8,
        price_unit: PriceUnit::Currency(quote.to_owned()),
        quantity_unit: QuantityUnit::Currency(base.to_owned()),
        tick_schedule: Vec::new(),
        quantity_step: Some(step),
        lot_size: Some(step),
        contract_multiplier: None,
    };
    spec.validate().context("invalid Kraken numeric spec")?;
    Ok(Some(MarketInfo {
        exchange: "kraken".to_owned(),
        native_symbol: native_symbol.clone(),
        symbol: native_symbol,
        title: Some(title),
        outcome: None,
        exchange_market_id: Some(key.to_owned()),
        close_time_us: None,
        tick_size_us: Some(tick_size_us),
        price_ranges: Vec::new(),
        price_level_structure: Some("linear_tick".to_owned()),
        numeric_spec: spec,
    }))
}

/// Parse a full `AssetPairs` envelope (`error` plus `result`). Every decoded
/// identity must be unique; a duplicate is rejected rather than merged.
pub fn parse_asset_pairs(value: &Value) -> anyhow::Result<Vec<MarketInfo>> {
    if let Some(errors) = value.get("error") {
        let errors = errors
            .as_array()
            .with_context(|| "AssetPairs `error` is not an array")?;
        anyhow::ensure!(
            errors.is_empty(),
            "AssetPairs response carried an error: {}",
            errors
                .first()
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
        );
    }
    let result = value
        .get("result")
        .and_then(Value::as_object)
        .with_context(|| "AssetPairs response has no result object")?;
    let mut markets = Vec::with_capacity(result.len());
    for (key, entry) in result {
        if let Some(market) = decode_pair(key, entry)? {
            anyhow::ensure!(
                !markets
                    .iter()
                    .any(|existing: &MarketInfo| existing.native_symbol == market.native_symbol),
                "duplicate Kraken identity `{}`",
                market.native_symbol
            );
            markets.push(market);
        }
    }
    Ok(markets)
}

/// Alias retained for callers that treat the fixture as a generic reference
/// document. The decoded shape is the same `AssetPairs` envelope.
pub fn parse_reference_document(value: &Value) -> anyhow::Result<Vec<MarketInfo>> {
    parse_asset_pairs(value)
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;

    #[test]
    fn excessive_price_precision_is_rejected_not_rounded() {
        let value: Value = serde_json::from_str(
            r#"{"error":[],"result":{"X":{"base":"XETH","quote":"ZUSD","status":"online","lot_decimals":2,"tick_size":"0.0000001"}}}"#,
        )
        .unwrap();
        assert!(parse_asset_pairs(&value).is_err());
    }

    #[test]
    fn excessive_lot_decimals_are_rejected_not_rounded() {
        let value: Value = serde_json::from_str(
            r#"{"error":[],"result":{"X":{"base":"XETH","quote":"ZUSD","status":"online","lot_decimals":9,"tick_size":"0.01"}}}"#,
        )
        .unwrap();
        assert!(parse_asset_pairs(&value).is_err());
    }

    #[test]
    fn non_empty_envelope_error_is_rejected() {
        let value: Value =
            serde_json::from_str(r#"{"error":["EGeneral:invalid"],"result":{}}"#).unwrap();
        assert!(parse_asset_pairs(&value).is_err());
    }
}
