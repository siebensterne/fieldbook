//! Coinbase Exchange reference-data codec (H0).
//!
//! Decodes an offline `products`-style document into validated `MarketInfo`
//! records with explicit `coinbase:spot:<BASE>/<QUOTE>` identity. Price and
//! quantity steps are derived exactly from `quote_increment` and
//! `base_increment`; increments finer than the canonical SBE scale are
//! rejected rather than silently rounded. No price or depth frame is decoded
//! here — H0 opens no socket and emits no market events.

use anyhow::{Context as _, bail};
use serde_json::Value;

use crate::{
    fixed::{DECIMALS, parse_scaled},
    model::{MarketInfo, NumericSpec, PriceUnit, Quantity, QuantityUnit},
};

/// Canonical SBE scale used by the collector.
const SCALE: u32 = DECIMALS as u32;
const SCALE_U8: u8 = DECIMALS as u8;

fn required_str<'a>(value: &'a Value, field: &str, id: &str) -> anyhow::Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .with_context(|| format!("missing or invalid `{field}` for Coinbase product `{id}`"))
}

/// Count fractional digits in a plain decimal string, rejecting signs,
/// exponents and non-digit characters before any numeric conversion.
fn decimal_places(text: &str, field: &str, id: &str) -> anyhow::Result<u8> {
    let text = text.trim();
    anyhow::ensure!(
        !text.is_empty()
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.'),
        "invalid Coinbase {field} `{text}` for product `{id}`"
    );
    let places = match text.split_once('.') {
        Some((whole, fraction)) => {
            anyhow::ensure!(
                !whole.is_empty() && !fraction.is_empty(),
                "invalid Coinbase {field} `{text}` for product `{id}`"
            );
            fraction.len()
        }
        None => 0,
    };
    u8::try_from(places).with_context(|| {
        format!("Coinbase {field} `{text}` for product `{id}` has too many digits")
    })
}

/// Parse one Coinbase increment into an exact step at the canonical SBE scale.
///
/// The returned tuple is `(decimal_places, step_micros)`. An increment with
/// more fractional digits than the SBE scale cannot be represented exactly, so
/// it is rejected instead of being rounded.
pub fn parse_increment(value: &Value, field: &str, id: &str) -> anyhow::Result<(u8, i64)> {
    let text = required_str(value, field, id)?;
    let places = decimal_places(text, field, id)?;
    anyhow::ensure!(
        u32::from(places) <= SCALE,
        "Coinbase {field} `{text}` for product `{id}` has {places} fractional digits; \
         SBE scale {SCALE} cannot represent it exactly"
    );
    let step = parse_scaled(text, SCALE_U8)
        .with_context(|| format!("parsing Coinbase {field} `{text}` for product `{id}`"))?;
    anyhow::ensure!(
        step > 0,
        "non-positive Coinbase {field} `{text}` for product `{id}`"
    );
    Ok((places, step))
}

fn validate_currency(code: &str, field: &str, id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !code.is_empty()
            && !code.contains(':')
            && !code.contains('/')
            && code.bytes().all(|byte| !byte.is_ascii_whitespace()),
        "invalid Coinbase {field} `{code}` for product `{id}`"
    );
    Ok(())
}

/// Decode one product record. `Ok(None)` means the product is filtered out by
/// the active-status gate, not that the record was malformed.
fn parse_product(value: &Value, require_online: bool) -> anyhow::Result<Option<MarketInfo>> {
    let id = required_str(value, "id", "<product>")?;
    let status = value.get("status").and_then(Value::as_str).unwrap_or("");
    let trading_disabled = value
        .get("trading_disabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if require_online && (status != "online" || trading_disabled) {
        return Ok(None);
    }

    let base = required_str(value, "base_currency", id)?;
    let quote = required_str(value, "quote_currency", id)?;
    validate_currency(base, "base_currency", id)?;
    validate_currency(quote, "quote_currency", id)?;
    anyhow::ensure!(
        base != quote,
        "Coinbase product `{id}` has identical base and quote currency `{base}`"
    );
    let (_, quote_step) = parse_increment(value, "quote_increment", id)?;
    let (_, base_step) = parse_increment(value, "base_increment", id)?;

    let native_symbol = format!("coinbase:spot:{base}/{quote}");
    let spec = NumericSpec {
        price_scale: SCALE_U8,
        quantity_scale: SCALE_U8,
        price_unit: PriceUnit::Currency(quote.to_owned()),
        quantity_unit: QuantityUnit::Currency(base.to_owned()),
        tick_schedule: Vec::new(),
        quantity_step: Some(Quantity::new(base_step)?),
        lot_size: Some(Quantity::new(base_step)?),
        contract_multiplier: None,
    };
    spec.validate().context("invalid Coinbase numeric spec")?;
    let market = MarketInfo {
        exchange: "coinbase".to_owned(),
        native_symbol: native_symbol.clone(),
        symbol: native_symbol,
        title: Some(id.to_owned()),
        outcome: None,
        exchange_market_id: None,
        close_time_us: None,
        tick_size_us: Some(quote_step),
        price_ranges: Vec::new(),
        price_level_structure: Some("coinbase_power_of_ten_increments".to_owned()),
        numeric_spec: spec,
    };
    market.validate().context("invalid Coinbase market")?;
    Ok(Some(market))
}

/// Decode a `products` array. Duplicate identities are rejected rather than
/// collapsed, so a shared base with a different quote stays a distinct market
/// but two records for the same base/quote pair are an error.
pub fn parse_products(value: &Value, require_online: bool) -> anyhow::Result<Vec<MarketInfo>> {
    let products = value
        .get("products")
        .and_then(Value::as_array)
        .with_context(|| "Coinbase reference document has no products array")?;
    let mut markets = Vec::with_capacity(products.len());
    for entry in products {
        let Some(market) = parse_product(entry, require_online)? else {
            continue;
        };
        anyhow::ensure!(
            !markets
                .iter()
                .any(|other: &MarketInfo| other.native_symbol == market.native_symbol),
            "duplicate Coinbase product identity `{}`",
            market.native_symbol
        );
        markets.push(market);
    }
    if markets.is_empty() {
        bail!("Coinbase reference document has no active products");
    }
    Ok(markets)
}

/// Parse an offline `products` reference document. Kept as the named codec
/// entry point for discovery and catalog checkpoints.
pub fn parse_reference_document(
    value: &Value,
    require_online: bool,
) -> anyhow::Result<Vec<MarketInfo>> {
    parse_products(value, require_online)
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;

    const REFERENCE: &str = include_str!("../../../../fixtures/coinbase/reference.json");

    fn document() -> Value {
        serde_json::from_str(REFERENCE).expect("fixture JSON")
    }

    #[test]
    fn identity_is_unique_and_explicitly_namespaced() {
        let markets = parse_reference_document(&document(), true).unwrap();
        assert_eq!(markets.len(), 5);
        let symbols: Vec<_> = markets
            .iter()
            .map(|market| market.native_symbol.as_str())
            .collect();
        let unique: std::collections::BTreeSet<_> = symbols.iter().copied().collect();
        assert_eq!(unique.len(), symbols.len());
        for market in &markets {
            assert_eq!(market.exchange, "coinbase");
            assert_eq!(market.symbol, market.native_symbol);
            assert!(market.native_symbol.starts_with("coinbase:spot:"));
            assert!(market.outcome.is_none());
            assert!(market.exchange_market_id.is_none());
        }
        // Shared base, distinct quote: two independent markets.
        assert!(symbols.contains(&"coinbase:spot:BTC/USD"));
        assert!(symbols.contains(&"coinbase:spot:BTC/USDT"));
    }

    #[test]
    fn numeric_spec_is_exact_from_increments() {
        let markets = parse_reference_document(&document(), true).unwrap();
        let btc = markets
            .iter()
            .find(|market| market.native_symbol == "coinbase:spot:BTC/USD")
            .unwrap();
        assert_eq!(btc.tick_size_us, Some(10_000)); // quote_increment 0.01
        assert_eq!(
            btc.numeric_spec.quantity_step,
            Some(Quantity::new(1).unwrap())
        );
        assert_eq!(btc.numeric_spec.lot_size, Some(Quantity::new(1).unwrap()));
        assert_eq!(btc.numeric_spec.price_scale, SCALE_U8);
        assert_eq!(btc.numeric_spec.quantity_scale, SCALE_U8);
        assert_eq!(
            btc.numeric_spec.price_unit,
            PriceUnit::Currency("USD".to_owned())
        );
        assert_eq!(
            btc.numeric_spec.quantity_unit,
            QuantityUnit::Currency("BTC".to_owned())
        );

        let link = markets
            .iter()
            .find(|market| market.native_symbol == "coinbase:spot:LINK/USD")
            .unwrap();
        assert_eq!(link.tick_size_us, Some(1)); // quote_increment 0.000001
        assert_eq!(
            link.numeric_spec.quantity_step,
            Some(Quantity::new(1000).unwrap())
        ); // base_increment 0.001
        for market in &markets {
            market.validate().unwrap();
            market.numeric_spec.validate().unwrap();
        }
    }

    #[test]
    fn excess_precision_is_rejected_not_rounded() {
        let base: Value = serde_json::from_str(
            r#"{"id":"BTC-USD","base_currency":"BTC","quote_currency":"USD",
                "base_increment":"0.00000001","quote_increment":"0.01",
                "status":"online","trading_disabled":false}"#,
        )
        .unwrap();
        assert!(
            parse_product(&base, true)
                .unwrap_err()
                .to_string()
                .contains("fractional digits")
        );
        let quote: Value = serde_json::from_str(
            r#"{"id":"BTC-USD","base_currency":"BTC","quote_currency":"USD",
                "base_increment":"0.001","quote_increment":"0.0000001",
                "status":"online","trading_disabled":false}"#,
        )
        .unwrap();
        assert!(parse_product(&quote, true).is_err());
    }

    #[test]
    fn inactive_products_are_excluded() {
        let markets = parse_reference_document(&document(), true).unwrap();
        let symbols: Vec<_> = markets
            .iter()
            .map(|market| market.native_symbol.as_str())
            .collect();
        assert!(!symbols.contains(&"coinbase:spot:DOGE/USD")); // status offline
        assert!(!symbols.contains(&"coinbase:spot:XRP/USD")); // trading_disabled
        // Relaxing the gate admits them, but still requires a valid spec.
        let all = parse_reference_document(&document(), false).unwrap();
        assert_eq!(all.len(), 7);
        let missing_status: Value = serde_json::from_str(
            r#"{"id":"ADA-USD","base_currency":"ADA","quote_currency":"USD",
                "base_increment":"1","quote_increment":"0.01"}"#,
        )
        .unwrap();
        assert!(parse_product(&missing_status, true).unwrap().is_none());
    }

    #[test]
    fn duplicate_identity_and_malformed_fields_are_rejected() {
        let duplicate: Value = serde_json::from_str(
            r#"{"products":[
                {"id":"BTC-USD","base_currency":"BTC","quote_currency":"USD",
                 "base_increment":"0.001","quote_increment":"0.01",
                 "status":"online","trading_disabled":false},
                {"id":"BTC-USD-2","base_currency":"BTC","quote_currency":"USD",
                 "base_increment":"0.001","quote_increment":"0.01",
                 "status":"online","trading_disabled":false}]}"#,
        )
        .unwrap();
        assert!(
            parse_products(&duplicate, true)
                .unwrap_err()
                .to_string()
                .contains("duplicate Coinbase product identity")
        );

        for bad in [
            r#"{"id":"X-USD","base_currency":"X","quote_currency":"USD","base_increment":"0","quote_increment":"0.01","status":"online"}"#,
            r#"{"id":"X-USD","base_currency":"X","quote_currency":"USD","base_increment":"abc","quote_increment":"0.01","status":"online"}"#,
            r#"{"id":"X-USD","base_currency":"X","quote_currency":"USD","base_increment":"1","quote_increment":"1e-2","status":"online"}"#,
            r#"{"id":"X-USD","base_currency":"","quote_currency":"USD","base_increment":"1","quote_increment":"0.01","status":"online"}"#,
        ] {
            let value: Value = serde_json::from_str(bad).unwrap();
            assert!(parse_product(&value, true).is_err(), "accepted `{bad}`");
        }
    }
}
