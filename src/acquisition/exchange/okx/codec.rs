//! OKX reference-data codec (H0).
//!
//! Decodes an offline `/api/v5/public/instruments` style document into
//! validated [`MarketInfo`] records. No price or depth frame is decoded here;
//! H1-H3 add those boundaries separately. Every recognised numeric is parsed
//! exactly at the canonical SBE scale or the whole document is rejected — no
//! silent rounding is ever performed.

use anyhow::{Context as _, bail};
use serde_json::Value;

use crate::model::{MarketInfo, NumericSpec, PriceUnit, Quantity, QuantityUnit};

/// Canonical SBE scale used by the collector.
const SCALE: u32 = 6;
const SCALE_U8: u8 = 6;
const INST_TYPE_SPOT: &str = "SPOT";
const INST_TYPE_SWAP: &str = "SWAP";
const LIVE_STATE: &str = "live";

/// Parse an OKX decimal size string (for example `tickSz` or `lotSz`) into an
/// exact `Quantity` at the canonical `SCALE`. A value with more fractional
/// digits than the scale carries, a non-decimal string, or a zero is rejected;
/// it is never truncated or rounded to fit.
fn exact_size(value: &Value, field: &str, context: &str) -> anyhow::Result<Quantity> {
    let text = value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("missing or invalid `{field}` in {context}"))?;
    anyhow::ensure!(!text.is_empty(), "empty `{field}` in {context}");
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    anyhow::ensure!(
        !whole.is_empty() || !fraction.is_empty(),
        "empty `{field}` in {context}"
    );
    anyhow::ensure!(
        whole.bytes().all(|byte| byte.is_ascii_digit()),
        "non-decimal `{field}` `{text}` in {context}"
    );
    anyhow::ensure!(
        fraction.bytes().all(|byte| byte.is_ascii_digit()),
        "non-decimal `{field}` `{text}` in {context}"
    );
    let decimals = fraction.len();
    if decimals > SCALE as usize {
        bail!(
            "OKX `{field}` `{text}` in {context} has {decimals} decimals, exceeding canonical SBE scale {SCALE}; value cannot be represented exactly"
        );
    }
    let digits = format!("{whole}{fraction}");
    let mantissa: u128 = digits
        .parse()
        .with_context(|| format!("parsing `{field}` `{text}` in {context}"))?;
    let multiplier = 10u128.pow((SCALE as usize - decimals) as u32);
    let raw = mantissa
        .checked_mul(multiplier)
        .with_context(|| format!("`{field}` `{text}` in {context} overflows"))?;
    anyhow::ensure!(raw > 0, "zero `{field}` in {context}");
    let raw = i64::try_from(raw)
        .with_context(|| format!("`{field}` `{text}` in {context} exceeds i64"))?;
    Quantity::new(raw).with_context(|| format!("invalid `{field}` in {context}"))
}

/// Resolve base/quote from an OKX `instId` for one product type. OKX spot ids
/// are `BASE-QUOTE` and swap ids are `BASE-QUOTE-SWAP`; any other shape is
/// rejected rather than guessed.
fn base_quote(inst_id: &str, inst_type: &str, context: &str) -> anyhow::Result<(String, String)> {
    let parts: Vec<&str> = inst_id.split('-').collect();
    let (base, quote) = match (inst_type, parts.as_slice()) {
        (INST_TYPE_SPOT, [base, quote]) => (*base, *quote),
        (INST_TYPE_SWAP, [base, quote, "SWAP"]) => (*base, *quote),
        _ => bail!("invalid OKX {inst_type} instId `{inst_id}` in {context}"),
    };
    anyhow::ensure!(
        !base.is_empty() && !quote.is_empty() && base != quote,
        "invalid OKX {inst_type} instId `{inst_id}` in {context}"
    );
    anyhow::ensure!(
        !base.contains(':') && !base.contains('/') && !quote.contains(':') && !quote.contains('/'),
        "invalid OKX {inst_type} instId `{inst_id}` in {context}"
    );
    Ok((base.to_owned(), quote.to_owned()))
}

fn currency(entry: &Value, field: &str, fallback: &str) -> anyhow::Result<String> {
    let code = entry
        .get(field)
        .and_then(Value::as_str)
        .filter(|code| !code.is_empty())
        .unwrap_or(fallback);
    anyhow::ensure!(!code.trim().is_empty(), "empty OKX {field}");
    Ok(code.to_owned())
}

/// Explicit, product-type-qualified identity. The namespace is the lowercased
/// `instType`, so a spot `BTC/USDT` and a swap `BTC/USDT` sharing an underlying
/// are distinct symbols rather than colliding on bare coin text.
fn native_symbol(inst_type: &str, base: &str, quote: &str) -> String {
    format!("okx:{}:{base}/{quote}", inst_type.to_ascii_lowercase())
}

/// Decode an OKX instruments document. `inst_types` is the configured scope:
/// instruments with an unconfigured or unsupported product type are filtered
/// out, as are instruments whose `state` is not `live`. Unknown additive fields
/// are ignored; recognised fields are validated exactly.
pub fn parse_instruments_document(
    value: &Value,
    inst_types: &[String],
) -> anyhow::Result<Vec<MarketInfo>> {
    if let Some(code) = value.get("code").and_then(Value::as_str) {
        anyhow::ensure!(
            code == "0",
            "OKX instruments response code `{code}` is not success"
        );
    }
    let data = value
        .get("data")
        .and_then(Value::as_array)
        .with_context(|| "OKX instruments document has no data array")?;
    let mut markets: Vec<MarketInfo> = Vec::with_capacity(data.len());
    for (index, entry) in data.iter().enumerate() {
        let context = format!("OKX instruments[{index}]");
        let inst_type = entry
            .get("instType")
            .and_then(Value::as_str)
            .with_context(|| format!("missing instType in {context}"))?;
        // Product-type scoping is explicit: unsupported types are never
        // silently admitted even if a configuration names them.
        if inst_type != INST_TYPE_SPOT && inst_type != INST_TYPE_SWAP {
            continue;
        }
        if !inst_types.iter().any(|configured| configured == inst_type) {
            continue;
        }
        // Live-state filter: an absent or non-live `state` is unconfirmed and
        // is excluded rather than merged into the universe.
        if entry
            .get("state")
            .and_then(Value::as_str)
            .is_none_or(|state| state != LIVE_STATE)
        {
            continue;
        }
        let inst_id = entry
            .get("instId")
            .and_then(Value::as_str)
            .with_context(|| format!("missing instId in {context}"))?;
        let (base, quote) = base_quote(inst_id, inst_type, &context)?;
        let tick = exact_size(entry, "tickSz", &context)?;
        let lot = exact_size(entry, "lotSz", &context)?;
        // `minSz` is the venue's minimum increment and is an exact lot size.
        // It is optional; when absent the lot step is the minimum.
        let lot_size = if entry.get("minSz").is_some() {
            exact_size(entry, "minSz", &context)?
        } else {
            Quantity::new(lot.raw())?
        };
        // Only SPOT and SWAP reach this branch; the remaining case is SWAP.
        let (price_unit, quantity_unit) = if inst_type == INST_TYPE_SPOT {
            (
                PriceUnit::Currency(currency(entry, "quoteCcy", &quote)?),
                QuantityUnit::Currency(base.clone()),
            )
        } else {
            (
                PriceUnit::Currency(currency(entry, "settleCcy", &quote)?),
                QuantityUnit::Contracts,
            )
        };
        let symbol = native_symbol(inst_type, &base, &quote);
        anyhow::ensure!(
            !markets.iter().any(|market| market.symbol == symbol),
            "duplicate OKX identity `{symbol}` in {context}"
        );
        let spec = NumericSpec {
            price_scale: SCALE_U8,
            quantity_scale: SCALE_U8,
            price_unit,
            quantity_unit,
            tick_schedule: Vec::new(),
            quantity_step: Some(lot),
            lot_size: Some(lot_size),
            contract_multiplier: None,
        };
        spec.validate()
            .with_context(|| format!("invalid OKX numeric spec in {context}"))?;
        let market = MarketInfo {
            exchange: "okx".to_owned(),
            native_symbol: symbol.clone(),
            symbol,
            title: Some(inst_id.to_owned()),
            outcome: None,
            exchange_market_id: None,
            close_time_us: None,
            tick_size_us: Some(tick.raw()),
            price_ranges: Vec::new(),
            price_level_structure: Some("linear".to_owned()),
            numeric_spec: spec,
        };
        market
            .validate()
            .with_context(|| format!("invalid OKX market in {context}"))?;
        markets.push(market);
    }
    anyhow::ensure!(
        !markets.is_empty(),
        "OKX instruments document produced no live in-scope instruments"
    );
    markets.sort_by(|left, right| left.native_symbol.cmp(&right.native_symbol));
    Ok(markets)
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;

    const REFERENCE: &str = include_str!("../../../../fixtures/okx/reference.json");

    fn reference() -> Value {
        serde_json::from_str(REFERENCE).expect("fixture JSON")
    }

    fn scope() -> Vec<String> {
        vec![INST_TYPE_SPOT.to_owned(), INST_TYPE_SWAP.to_owned()]
    }

    #[test]
    fn reference_document_decodes_namespaced_markets_with_exact_scales() {
        let markets = parse_instruments_document(&reference(), &scope()).expect("valid document");
        // Six records, one of which is non-live and excluded.
        assert_eq!(markets.len(), 5);
        for market in &markets {
            market.validate().expect("valid market");
            market.numeric_spec.validate().expect("valid numeric spec");
            assert_eq!(market.exchange, "okx");
            assert_eq!(market.symbol, market.native_symbol);
            assert!(market.exchange_market_id.is_none());
            assert!(market.outcome.is_none());
            assert_eq!(market.numeric_spec.price_scale, SCALE_U8);
            assert_eq!(market.numeric_spec.quantity_scale, SCALE_U8);
        }
        let spot = markets
            .iter()
            .find(|market| market.native_symbol == "okx:spot:BTC/USDT")
            .expect("spot BTC/USDT");
        assert_eq!(spot.tick_size_us, Some(10_000)); // 0.01 at 1e-6
        assert_eq!(
            spot.numeric_spec.quantity_step,
            Some(Quantity::new(10).unwrap())
        ); // 0.00001
        assert_eq!(spot.numeric_spec.lot_size, Some(Quantity::new(10).unwrap()));
        assert_eq!(
            spot.numeric_spec.price_unit,
            PriceUnit::Currency("USDT".to_owned())
        );
        assert_eq!(
            spot.numeric_spec.quantity_unit,
            QuantityUnit::Currency("BTC".to_owned())
        );
        let swap = markets
            .iter()
            .find(|market| market.native_symbol == "okx:swap:BTC/USDT")
            .expect("swap BTC/USDT");
        assert_eq!(swap.tick_size_us, Some(100_000)); // 0.1
        assert_eq!(
            swap.numeric_spec.quantity_step,
            Some(Quantity::new(1_000_000).unwrap())
        );
        assert_eq!(swap.numeric_spec.quantity_unit, QuantityUnit::Contracts);
    }

    #[test]
    fn identity_is_unique_across_product_types_with_a_shared_underlying() {
        let markets = parse_instruments_document(&reference(), &scope()).expect("valid document");
        let identities: std::collections::BTreeSet<&str> = markets
            .iter()
            .map(|market| market.native_symbol.as_str())
            .collect();
        assert_eq!(identities.len(), markets.len(), "identities must be unique");
        assert!(identities.contains("okx:spot:BTC/USDT"));
        assert!(identities.contains("okx:swap:BTC/USDT"));
        assert!(identities.contains("okx:spot:ETH/USDT"));
        assert!(identities.contains("okx:swap:ETH/USDT"));
        assert!(identities.contains("okx:swap:SOL/USDT"));
    }

    #[test]
    fn product_type_scoping_filters_unconfigured_inst_types() {
        let value = reference();
        let spot = parse_instruments_document(&value, &["SPOT".to_owned()]).unwrap();
        assert_eq!(spot.len(), 2);
        assert!(
            spot.iter()
                .all(|market| market.symbol.starts_with("okx:spot:"))
        );
        let swaps = parse_instruments_document(&value, &["SWAP".to_owned()]).unwrap();
        assert_eq!(swaps.len(), 3);
        assert!(
            swaps
                .iter()
                .all(|market| market.symbol.starts_with("okx:swap:"))
        );
    }

    #[test]
    fn non_live_instruments_are_excluded() {
        let markets = parse_instruments_document(&reference(), &scope()).unwrap();
        assert!(
            !markets
                .iter()
                .any(|market| market.title.as_deref() == Some("DOGE-USDT")),
            "the suspended DOGE-USDT instrument must be excluded"
        );
        let all_non_live: Value = serde_json::from_str(
            r#"{"code":"0","data":[{"instType":"SPOT","instId":"BTC-USDT","baseCcy":"BTC","quoteCcy":"USDT","tickSz":"0.01","lotSz":"1","state":"suspended"}]}"#,
        )
        .unwrap();
        assert!(parse_instruments_document(&all_non_live, &scope()).is_err());
    }

    #[test]
    fn excessive_precision_is_rejected_not_rounded() {
        let base = |tick: &str, lot: &str| -> Value {
            serde_json::json!({
                "code": "0",
                "data": [{
                    "instType": "SPOT", "instId": "BTC-USDT",
                    "baseCcy": "BTC", "quoteCcy": "USDT",
                    "tickSz": tick, "lotSz": lot, "state": "live"
                }]
            })
        };
        assert!(parse_instruments_document(&base("0.0000001", "1"), &scope()).is_err());
        assert!(parse_instruments_document(&base("0.01", "0.0000001"), &scope()).is_err());
        assert!(parse_instruments_document(&base("abc", "1"), &scope()).is_err());
        assert!(parse_instruments_document(&base("0", "1"), &scope()).is_err());
        // An additive unknown field does not affect acceptance.
        let mut additive = base("0.01", "1");
        additive["data"][0]["aFutureField"] = serde_json::json!({"nested": 1});
        assert!(parse_instruments_document(&additive, &scope()).is_ok());
    }

    #[test]
    fn malformed_inst_id_and_error_code_are_rejected() {
        let value: Value = serde_json::from_str(
            r#"{"code":"1","msg":"bad","data":[{"instType":"SPOT","instId":"BTC-USDT","baseCcy":"BTC","quoteCcy":"USDT","tickSz":"0.01","lotSz":"1","state":"live"}]}"#,
        )
        .unwrap();
        assert!(parse_instruments_document(&value, &scope()).is_err());
        let malformed: Value = serde_json::from_str(
            r#"{"code":"0","data":[{"instType":"SPOT","instId":"BTC","baseCcy":"BTC","quoteCcy":"USDT","tickSz":"0.01","lotSz":"1","state":"live"}]}"#,
        )
        .unwrap();
        assert!(parse_instruments_document(&malformed, &scope()).is_err());
    }
}
