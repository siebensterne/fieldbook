//! Binance reference-data codec (H0).
//!
//! Decodes an offline `exchangeInfo`-style document into validated
//! [`MarketInfo`] records. There is no websocket or price-frame path here;
//! later stages add their own boundaries. The decoder rejects values that cannot be represented:
//! a value that cannot be represented exactly at the canonical SBE scale is
//! rejected rather than silently rounded.

use anyhow::{Context as _, bail};
use serde_json::Value;

use crate::model::{MarketInfo, NumericSpec, PriceUnit, Quantity, QuantityUnit};

/// Canonical SBE scale used by the collector.
const SCALE: u32 = 6;
const SCALE_U8: u8 = 6;

/// Product qualifier used in Binance `native_symbol` identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Product {
    Spot,
    Perp,
}

impl Product {
    const fn namespace(self) -> &'static str {
        match self {
            Self::Spot => "spot",
            Self::Perp => "perp",
        }
    }
}

/// Parse a Binance decimal string into an exact `(coefficient, decimals)` pair.
///
/// Trailing fractional zeros are removed before counting decimals, so the
/// common Binance spelling `0.01000000` is understood as two decimals (0.01).
/// Signs, exponents, separators and non-digit characters are rejected; there
/// is no floating-point conversion anywhere in this path.
fn parse_decimal(value: &str) -> anyhow::Result<(u128, u32)> {
    anyhow::ensure!(!value.is_empty(), "empty decimal value");
    anyhow::ensure!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.'),
        "invalid decimal value `{value}`"
    );
    anyhow::ensure!(
        value.bytes().filter(|byte| *byte == b'.').count() <= 1,
        "invalid decimal value `{value}`"
    );
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (value, ""),
    };
    anyhow::ensure!(
        !whole.is_empty() || !fraction.is_empty(),
        "invalid decimal value `{value}`"
    );
    let trimmed = fraction.trim_end_matches('0');
    let decimals = u32::try_from(trimmed.len()).context("decimal precision overflow")?;
    let digits = if whole.is_empty() { "0" } else { whole };
    let coefficient = format!("{digits}{trimmed}")
        .parse::<u128>()
        .with_context(|| format!("decimal coefficient overflow in `{value}`"))?;
    Ok((coefficient, decimals))
}

/// Convert a Binance `tickSize`/`stepSize` string into an exact quantity step
/// at the canonical SBE scale and its raw micro-unit value.
fn exact_step(value: &str, context: &str) -> anyhow::Result<(Quantity, i64)> {
    let (coefficient, decimals) =
        parse_decimal(value).with_context(|| format!("invalid {context} value `{value}`"))?;
    if decimals > SCALE {
        bail!(
            "{context} `{value}` needs {decimals} decimals, beyond canonical SBE scale {SCALE}; value is rejected, not rounded"
        );
    }
    let factor = 10u128
        .checked_pow(SCALE - decimals)
        .with_context(|| format!("computing step factor for {context} `{value}`"))?;
    let micros = coefficient
        .checked_mul(factor)
        .and_then(|value| i64::try_from(value).ok())
        .with_context(|| format!("{context} `{value}` overflows micro-unit representation"))?;
    anyhow::ensure!(micros > 0, "non-positive {context} `{value}`");
    Ok((Quantity::new(micros)?, micros))
}

fn filter_field<'a>(entry: &'a Value, filter_type: &str, field: &str) -> anyhow::Result<&'a str> {
    entry
        .get("filters")
        .and_then(Value::as_array)
        .with_context(|| "exchangeInfo symbol has no filters array")?
        .iter()
        .find(|filter| filter.get("filterType").and_then(Value::as_str) == Some(filter_type))
        .with_context(|| format!("exchangeInfo symbol has no {filter_type} filter"))?
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("{filter_type} filter has no string `{field}`"))
}

fn string_field<'a>(entry: &'a Value, field: &str) -> anyhow::Result<&'a str> {
    entry
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("exchangeInfo symbol has no string `{field}`"))
}

fn is_canonical_quote(quote: &str, quotes: &[String]) -> bool {
    quotes
        .iter()
        .any(|canonical| canonical.eq_ignore_ascii_case(quote))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains(':') && !name.contains('/')
}

/// Build one validated `MarketInfo` from a single exchangeInfo symbol entry.
fn build_market(
    product: Product,
    native_symbol: String,
    title: String,
    entry: &Value,
    quote: &str,
) -> anyhow::Result<MarketInfo> {
    let (_, tick_size_us) =
        exact_step(filter_field(entry, "PRICE_FILTER", "tickSize")?, "tickSize")?;
    let (quantity_step, _) = exact_step(filter_field(entry, "LOT_SIZE", "stepSize")?, "stepSize")?;
    let spec = NumericSpec {
        price_scale: SCALE_U8,
        quantity_scale: SCALE_U8,
        // A canonical quote is required by `is_canonical_quote` at the caller.
        price_unit: PriceUnit::Currency(quote.to_owned()),
        // Spot quantity is denominated in the base asset; a linear perpetual
        // is denominated in contracts. Both are frozen in H0.
        quantity_unit: match product {
            Product::Spot => QuantityUnit::Currency(string_field(entry, "baseAsset")?.to_owned()),
            Product::Perp => QuantityUnit::Contracts,
        },
        tick_schedule: Vec::new(),
        quantity_step: Some(quantity_step),
        lot_size: Some(quantity_step),
        contract_multiplier: None,
    };
    spec.validate().context("invalid Binance numeric spec")?;
    let market = MarketInfo {
        exchange: "binance".to_owned(),
        native_symbol: native_symbol.clone(),
        symbol: native_symbol,
        title: Some(title),
        outcome: None,
        exchange_market_id: None,
        close_time_us: None,
        tick_size_us: Some(tick_size_us),
        price_ranges: Vec::new(),
        price_level_structure: Some("linear".to_owned()),
        numeric_spec: spec,
    };
    market.validate().context("invalid Binance market")?;
    Ok(market)
}

/// Parse one product section of a reference document.
///
/// Only `TRADING` symbols quoting a canonical asset are admitted. An additive
/// or unknown field is ignored; a malformed filter, an inexact step, or a
/// malformed identity is fatal. Spot identities are `binance:spot:BASE/QUOTE`,
/// perpetual identities are `binance:perp:SYMBOL` (the venue's contract name).
fn parse_section(
    value: &Value,
    product: Product,
    quotes: &[String],
) -> anyhow::Result<Vec<MarketInfo>> {
    let section = value.get(product.namespace()).with_context(|| {
        format!(
            "reference document has no `{}` section",
            product.namespace()
        )
    })?;
    let symbols = section
        .get("symbols")
        .and_then(Value::as_array)
        .with_context(|| format!("`{}` section has no symbols array", product.namespace()))?;
    let mut markets = Vec::with_capacity(symbols.len());
    for entry in symbols {
        if entry.get("status").and_then(Value::as_str) != Some("TRADING") {
            continue;
        }
        let quote = string_field(entry, "quoteAsset")?;
        if !is_canonical_quote(quote, quotes) {
            continue;
        }
        let base = string_field(entry, "baseAsset")?;
        if !valid_name(base) || !valid_name(quote) || base == quote {
            bail!("invalid Binance base/quote `{base}/{quote}`");
        }
        let venue_symbol = string_field(entry, "symbol")?;
        if venue_symbol.is_empty() || venue_symbol.contains(':') {
            bail!("invalid Binance symbol `{venue_symbol}`");
        }
        match product {
            Product::Spot => {
                if entry.get("isSpotTradingAllowed").and_then(Value::as_bool) != Some(true) {
                    continue;
                }
            }
            Product::Perp => {
                if entry.get("contractType").and_then(Value::as_str) != Some("PERPETUAL") {
                    continue;
                }
            }
        }
        let native_symbol = match product {
            Product::Spot => format!("binance:spot:{base}/{quote}"),
            Product::Perp => format!("binance:perp:{venue_symbol}"),
        };
        if markets
            .iter()
            .any(|market: &MarketInfo| market.native_symbol == native_symbol)
        {
            bail!("duplicate Binance identity `{native_symbol}`");
        }
        let title = match product {
            Product::Spot => format!("{base}/{quote}"),
            Product::Perp => venue_symbol.to_owned(),
        };
        markets.push(build_market(product, native_symbol, title, entry, quote)?);
    }
    Ok(markets)
}

/// Parse the offline `exchangeInfo`-style reference document.
///
/// `quotes` is the configured canonical-quote allowlist. Spot and perpetual
/// sections are independent; both may share base assets while keeping distinct
/// namespaced identities.
pub fn parse_reference_document(
    value: &Value,
    quotes: &[String],
) -> anyhow::Result<Vec<MarketInfo>> {
    parse_reference_document_selected(value, quotes, true, true)
}

/// Variant that honours the configured product-section switches.
pub fn parse_reference_document_selected(
    value: &Value,
    quotes: &[String],
    spot_enabled: bool,
    perp_enabled: bool,
) -> anyhow::Result<Vec<MarketInfo>> {
    anyhow::ensure!(
        !quotes.is_empty(),
        "Binance requires a canonical quote asset"
    );
    anyhow::ensure!(
        spot_enabled || perp_enabled,
        "Binance discovery requires at least one enabled product section"
    );
    let mut markets = Vec::new();
    if spot_enabled {
        markets.extend(parse_section(value, Product::Spot, quotes)?);
    }
    if perp_enabled {
        markets.extend(parse_section(value, Product::Perp, quotes)?);
    }
    markets.sort_by(|left, right| left.native_symbol.cmp(&right.native_symbol));
    let mut seen = std::collections::BTreeSet::new();
    for market in &markets {
        anyhow::ensure!(
            seen.insert(market.native_symbol.as_str()),
            "duplicate Binance identity `{}`",
            market.native_symbol
        );
    }
    Ok(markets)
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;
    use crate::model::Price;

    #[test]
    fn precision_beyond_canonical_scale_is_rejected_not_rounded() {
        assert!(exact_step("0.0000001", "tickSize").is_err());
        assert!(exact_step("0.1234567", "stepSize").is_err());
        let (step, micros) = exact_step("0.00001000", "stepSize").unwrap();
        assert_eq!(step, Quantity::new(10).unwrap());
        assert_eq!(micros, 10);
    }
}
