//! Hyperliquid reference-data codec (H0).
//!
//! Parses `/info` `meta` and `spotMeta` documents into validated
//! `MarketInfo` records. No price or depth frame is decoded here; H1/H2 add
//! those boundaries separately.

use anyhow::{Context as _, bail};
use serde_json::Value;

use crate::model::{MarketInfo, NumericSpec, PriceUnit, Quantity, QuantityUnit};

/// Canonical SBE scale used by the collector.
const SCALE: u32 = 6;
const SCALE_U8: u8 = 6;

fn scale_step(decimals: u32) -> anyhow::Result<i64> {
    if decimals > SCALE {
        bail!(
            "Hyperliquid decimals {decimals} exceed canonical SBE scale {SCALE}; value cannot be represented exactly"
        );
    }
    10i64
        .checked_pow(SCALE - decimals)
        .with_context(|| format!("computing step for {decimals} decimals"))
}

fn common_market(
    exchange: &str,
    native_symbol: String,
    title: String,
    quantity_scale_decimals: u32,
    price_scale_decimals: Option<u32>,
    price_unit: PriceUnit,
    quantity_unit: QuantityUnit,
) -> anyhow::Result<MarketInfo> {
    let step = Quantity::new(scale_step(quantity_scale_decimals)?)?;
    let tick_size_us = price_scale_decimals.map(scale_step).transpose()?;
    let spec = NumericSpec {
        price_scale: SCALE_U8,
        quantity_scale: SCALE_U8,
        price_unit,
        quantity_unit,
        tick_schedule: Vec::new(),
        quantity_step: Some(step),
        lot_size: Some(step),
        contract_multiplier: None,
    };
    spec.validate()
        .context("invalid Hyperliquid numeric spec")?;
    Ok(MarketInfo {
        exchange: exchange.to_owned(),
        native_symbol: native_symbol.clone(),
        symbol: native_symbol,
        title: Some(title),
        outcome: None,
        exchange_market_id: None,
        close_time_us: None,
        tick_size_us,
        price_ranges: Vec::new(),
        price_level_structure: Some("linear_cent".to_owned()),
        numeric_spec: spec,
    })
}

fn u32_field(value: &Value, field: &str, context: &str) -> anyhow::Result<u32> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|number| u32::try_from(number).ok())
        .with_context(|| format!("missing or invalid `{field}` in {context}"))
}

/// Parse a perpetual `meta` universe for one DEX. `dex` is the empty string
/// for the main DEX and is part of the instrument identity for others.
pub fn parse_perp_universe(value: &Value, dex: &str) -> anyhow::Result<Vec<MarketInfo>> {
    let universe = value
        .get("universe")
        .and_then(Value::as_array)
        .with_context(|| "Hyperliquid meta has no universe array")?;
    let mut markets = Vec::with_capacity(universe.len());
    for entry in universe {
        let coin = entry
            .get("name")
            .and_then(Value::as_str)
            .with_context(|| "perp universe entry has no name")?;
        if coin.is_empty() || coin.contains(':') || coin.contains('/') {
            bail!("invalid Hyperliquid perp coin `{coin}`");
        }
        let sz_decimals = u32_field(entry, "szDecimals", "perp universe entry")?;
        let px_decimals = entry
            .get("pxDecimals")
            .and_then(Value::as_u64)
            .and_then(|number| u32::try_from(number).ok());
        let native_symbol = if dex.is_empty() {
            format!("hyperliquid:perp::{coin}")
        } else {
            format!("hyperliquid:perp:{dex}:{coin}")
        };
        markets.push(common_market(
            "hyperliquid",
            native_symbol,
            coin.to_owned(),
            sz_decimals,
            px_decimals,
            PriceUnit::Currency("USDC".to_owned()),
            QuantityUnit::Contracts,
        )?);
    }
    if markets.is_empty() {
        bail!("Hyperliquid perp universe for DEX `{dex}` is empty");
    }
    Ok(markets)
}

/// Parse `spotMeta` into canonical spot markets. Token indices resolve to
/// names; non-canonical variants are excluded rather than merged silently.
pub fn parse_spot_meta(value: &Value) -> anyhow::Result<Vec<MarketInfo>> {
    let tokens: std::collections::BTreeMap<u64, String> = value
        .get("tokens")
        .and_then(Value::as_array)
        .with_context(|| "spotMeta has no tokens array")?
        .iter()
        .map(|token| {
            let index = token
                .get("index")
                .and_then(Value::as_u64)
                .context("spot token has no index")?;
            let name = token
                .get("name")
                .and_then(Value::as_str)
                .context("spot token has no name")?;
            Ok((index, name.to_owned()))
        })
        .collect::<anyhow::Result<_>>()?;
    let universe = value
        .get("universe")
        .and_then(Value::as_array)
        .with_context(|| "spotMeta has no universe array")?;
    let mut markets = Vec::new();
    for entry in universe {
        let canonical = entry
            .get("isCanonical")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !canonical {
            continue;
        }
        let pair = entry
            .get("name")
            .and_then(Value::as_str)
            .with_context(|| "spot universe entry has no name")?;
        let (base, quote) = if let Some((left, right)) = pair.split_once('/') {
            (left.to_owned(), right.to_owned())
        } else {
            let indices = entry
                .get("tokens")
                .and_then(Value::as_array)
                .with_context(|| "spot pair without slash has no token indices")?;
            if indices.len() != 2 {
                bail!("spot pair `{pair}` does not name exactly two tokens");
            }
            let base_index = indices[0]
                .as_u64()
                .with_context(|| "invalid spot base token index")?;
            let quote_index = indices[1]
                .as_u64()
                .with_context(|| "invalid spot quote token index")?;
            (
                tokens
                    .get(&base_index)
                    .with_context(|| format!("unknown base token index {base_index}"))?
                    .clone(),
                tokens
                    .get(&quote_index)
                    .with_context(|| format!("unknown quote token index {quote_index}"))?
                    .clone(),
            )
        };
        if base.is_empty() || quote.is_empty() || base == quote {
            bail!("invalid canonical spot pair `{pair}`");
        }
        let native_symbol = format!("hyperliquid:spot:{base}/{quote}");
        if markets
            .iter()
            .any(|market: &MarketInfo| market.native_symbol == native_symbol)
        {
            continue;
        }
        // H0 freezes spot quantity scale at the canonical SBE scale; per-token
        // decimals are a H2 precision gate, not a silent rounding allowance.
        markets.push(common_market(
            "hyperliquid",
            native_symbol,
            pair.to_owned(),
            0,
            None,
            PriceUnit::Currency(quote),
            QuantityUnit::Currency(base),
        )?);
    }
    Ok(markets)
}

/// Parse an offline reference document containing `dexes` and optional
/// `spotMeta` for H0 tests and deterministic catalog checkpoints.
pub fn parse_reference_document(
    value: &Value,
    dexs: &[String],
    spot_enabled: bool,
) -> anyhow::Result<Vec<MarketInfo>> {
    let entries = value
        .get("dexes")
        .and_then(Value::as_array)
        .with_context(|| "reference document has no dexes array")?;
    let mut markets = Vec::new();
    for dex in dexs {
        let entry = entries
            .iter()
            .find(|entry| entry.get("name").and_then(Value::as_str).unwrap_or("") == dex.as_str())
            .with_context(|| format!("configured DEX `{dex}` missing from reference document"))?;
        markets.extend(parse_perp_universe(entry, dex)?);
    }
    if spot_enabled {
        let spot = value
            .get("spotMeta")
            .with_context(|| "reference document has no spotMeta")?;
        markets.extend(parse_spot_meta(spot)?);
    }
    Ok(markets)
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;
    use crate::model::Price;

    #[test]
    fn excessive_precision_is_rejected_not_rounded() {
        let value: serde_json::Value =
            serde_json::from_str(r#"{"universe":[{"name":"BTC","szDecimals":9,"pxDecimals":2}]}"#)
                .unwrap();
        assert!(parse_perp_universe(&value, "").is_err());
    }

    #[test]
    fn price_and_quantity_scale_are_canonical() {
        assert_eq!(Price::from_raw(1_000_000).raw(), 1_000_000);
        assert_eq!(SCALE, 6);
    }
}
