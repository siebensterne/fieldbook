//! Hyperliquid telemetry codec (H1).
//!
//! Decodes the venue-wide `allMids` and `fastAssetCtxs` channels into typed,
//! validated observations. These frames are telemetry only: no price level,
//! depth, or book anchor is derived from them and no `ExchangeEvent` is ever
//! produced here.
//!
//! `fastAssetCtxs` is the venue's compressed channel. Its wire `data` is a
//! base64 string; the decoded bytes are a *raw* DEFLATE stream (RFC 1951, no
//! zlib or gzip wrapper) carrying a UTF-8 JSON object keyed by coin. This is
//! the format published in the Hyperliquid subscription documentation and is
//! confirmed by the raw frames retained in live journals. Both the JSON object
//! and the older array shape used by historical fixtures are accepted so an
//! old capture remains decodable.
//!
//! The venue publishes more fractional digits than the canonical SBE scale can
//! carry. Telemetry is never written to SBE, so those values are retained
//! verbatim as exact strings: a value is never rounded, and a value that does
//! not fit the SBE scale is not fabricated into a coefficient it cannot have.
//!
//! `assetCtxs` is not subscribed in H1: no checked-in golden
//! fixture pins its wire shape. Adding it is a later, fixture-gated change.

use std::io::Read;

use anyhow::{Context, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use flate2::read::DeflateDecoder;
use serde_json::{Value, json};

use crate::fixed;

/// Canonical SBE decimal scale. Mirrors `fixed::DECIMALS`; the assertion in
/// the test module keeps the two in lockstep.
const SCALE: u8 = 6;

/// Upper bound on the inflated `fastAssetCtxs` JSON. The venue sends a few
/// hundred kilobytes; a larger payload is treated as a hostile decompression
/// stream rather than being buffered without limit.
const MAX_INFLATED_FAST_CTX_BYTES: u64 = 16 * 1024 * 1024;

/// Longest accepted decimal string for a telemetry price field. Well beyond
/// any venue value while keeping a runaway string out of the journal's typed
/// view.
const MAX_PRICE_TEXT_LEN: usize = 64;

/// Venue channel carrying a map of coin to mid price.
pub const CHANNEL_ALL_MIDS: &str = "allMids";
/// Venue channel carrying per-coin statistics at high frequency.
pub const CHANNEL_FAST_ASSET_CTXS: &str = "fastAssetCtxs";
/// Documented as not subscribed in H1 (no golden fixture). Listed so the
/// omission is explicit rather than an accidental oversight.
pub const CHANNEL_ASSET_CTXS_NOT_SUBSCRIBED: &str = "assetCtxs";

/// One coin's mid price from an `allMids` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mid {
    pub coin: String,
    /// Exact venue value; finer-than-SBE precision is retained verbatim and
    /// never rounded into a coefficient the schema cannot carry.
    pub mid: ExactPrice,
}

/// One exact venue decimal, retained without alteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactPrice {
    /// The exact decimal string exactly as received on the wire.
    pub raw: String,
    /// Canonical SBE-scale coefficient, present only when the received value
    /// is representable at `SCALE` without rounding. `None` never means zero
    /// and is never a rounded approximation.
    pub scaled: Option<i64>,
}

/// Per-coin statistics from a `fastAssetCtxs` frame. Only price fields are
/// retained; funding/open-interest/volume-style fields are additive telemetry
/// that H1 ignores (and must not round).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetCtx {
    pub coin: String,
    pub mark_px: Option<ExactPrice>,
    pub mid_px: Option<ExactPrice>,
    pub oracle_px: Option<ExactPrice>,
}

/// A decoded telemetry frame. `Ignored` is returned for an additive channel
/// this build does not recognise; it is never a decode error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TelemetryFrame {
    AllMids(Vec<Mid>),
    FastAssetCtxs(Vec<AssetCtx>),
    Ignored(String),
}

/// Build the wire subscription request for a telemetry channel.
///
/// Only the two fixture-proven H1 channels are allowed. `assetCtxs` and any
/// other channel are rejected so an operator cannot silently subscribe to a
/// feed whose wire shape has not been pinned by a golden fixture.
pub fn subscription_request(channel: &str) -> anyhow::Result<Value> {
    match channel {
        CHANNEL_ALL_MIDS | CHANNEL_FAST_ASSET_CTXS => Ok(json!({
            "method": "subscribe",
            "subscription": { "type": channel },
        })),
        other => bail!(
            "Hyperliquid channel `{other}` is not subscribed in H1; only `allMids` and \
             `fastAssetCtxs` are supported (`assetCtxs` has no golden fixture)"
        ),
    }
}

/// Parse one optional telemetry price without ever rounding it.
///
/// The string is validated as a plain decimal. When it fits the canonical
/// scale the exact coefficient is supplied alongside the verbatim string;
/// when the venue publishes more precision, the coefficient is absent and the
/// exact string is still retained. Neither case is a decode error: both are
/// faithful representations of what the venue sent.
fn parse_exact_price_text(text: &str, field: &str, context: &str) -> anyhow::Result<ExactPrice> {
    anyhow::ensure!(
        !text.is_empty() && text.len() <= MAX_PRICE_TEXT_LEN,
        "`{field}`=`{text}` in {context} has an invalid length"
    );
    let unsigned = text.trim().trim_start_matches(['-', '+']);
    let mut pieces = unsigned.split('.');
    let whole = pieces.next().unwrap_or_default();
    let fraction = pieces.next();
    anyhow::ensure!(
        pieces.next().is_none(),
        "`{field}`=`{text}` in {context} has multiple decimal points"
    );
    let whole_is_decimal = if whole.is_empty() {
        fraction.is_some_and(|fraction| !fraction.is_empty())
    } else {
        whole.bytes().all(|byte| byte.is_ascii_digit())
    };
    anyhow::ensure!(
        whole_is_decimal,
        "`{field}`=`{text}` in {context} has invalid whole-number digits"
    );
    if let Some(fraction) = fraction {
        anyhow::ensure!(
            !fraction.is_empty() && fraction.bytes().all(|byte| byte.is_ascii_digit()),
            "`{field}`=`{text}` in {context} has invalid fractional digits"
        );
    }
    Ok(ExactPrice {
        raw: text.to_owned(),
        scaled: fixed::parse_scaled(text, SCALE).ok(),
    })
}

fn exact_price_field(
    value: &Value,
    field: &str,
    context: &str,
) -> anyhow::Result<Option<ExactPrice>> {
    let Some(raw) = value.get(field) else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    let text = raw
        .as_str()
        .with_context(|| format!("`{field}` in {context} is not a string"))?;
    Ok(Some(parse_exact_price_text(text, field, context)?))
}

fn coin_field(value: &Value, context: &str) -> anyhow::Result<String> {
    let coin = value
        .get("coin")
        .and_then(Value::as_str)
        .with_context(|| format!("{context} has no string `coin`"))?;
    anyhow::ensure!(!coin.is_empty(), "{context} has an empty `coin`");
    Ok(coin.to_owned())
}

fn parse_all_mids(data: &Value) -> anyhow::Result<TelemetryFrame> {
    // Canonical shape is `data.mids`; accept a bare coin map as well so a
    // venue variation does not force a lossy fallback. Both are telemetry.
    let mids = data
        .get("mids")
        .and_then(Value::as_object)
        .or_else(|| data.as_object())
        .context("allMids data has no `mids` object")?;
    let mut out = Vec::with_capacity(mids.len());
    for (coin, value) in mids {
        anyhow::ensure!(!coin.is_empty(), "allMids has an empty coin");
        let text = value
            .as_str()
            .with_context(|| format!("allMids mid for `{coin}` is not a string"))?;
        let context = format!("allMids mid for `{coin}`");
        let mid = parse_exact_price_text(text, "mid", &context)?;
        out.push(Mid {
            coin: coin.clone(),
            mid,
        });
    }
    out.sort_by(|left, right| left.coin.cmp(&right.coin));
    Ok(TelemetryFrame::AllMids(out))
}

/// Decode the venue's compressed `fastAssetCtxs` wire payload.
///
/// The steps are the venue-published ones, in order: base64 decode, raw
/// DEFLATE inflate (no zlib/gzip wrapper), UTF-8 JSON parse of a coin-keyed
/// object. Each step is contextualised so a failure is explained rather than
/// reported as an opaque decode error.
fn parse_fast_asset_ctxs_wire(encoded: &str) -> anyhow::Result<TelemetryFrame> {
    let compressed = BASE64
        .decode(encoded)
        .context("decoding fastAssetCtxs base64 payload")?;
    let mut decoder = DeflateDecoder::new(compressed.as_slice());
    let mut text = String::new();
    decoder
        .by_ref()
        .take(MAX_INFLATED_FAST_CTX_BYTES)
        .read_to_string(&mut text)
        .context("inflating raw DEFLATE fastAssetCtxs payload")?;
    let value: Value =
        serde_json::from_str(&text).context("parsing inflated fastAssetCtxs JSON")?;
    let entries = value
        .as_object()
        .context("inflated fastAssetCtxs payload is not a coin-keyed object")?;
    let mut out = Vec::with_capacity(entries.len());
    for (coin, ctx) in entries {
        anyhow::ensure!(!coin.is_empty(), "fastAssetCtxs has an empty coin key");
        anyhow::ensure!(
            ctx.is_object(),
            "fastAssetCtxs entry for `{coin}` is not an object"
        );
        let context = format!("fastAssetCtxs entry `{coin}`");
        out.push(AssetCtx {
            coin: coin.clone(),
            mark_px: exact_price_field(ctx, "markPx", &context)?,
            mid_px: exact_price_field(ctx, "midPx", &context)?,
            oracle_px: exact_price_field(ctx, "oraclePx", &context)?,
        });
    }
    out.sort_by(|left, right| left.coin.cmp(&right.coin));
    Ok(TelemetryFrame::FastAssetCtxs(out))
}

/// Decode the historical array shape retained by older golden fixtures.
fn parse_fast_asset_ctxs_array(data: &Value) -> anyhow::Result<TelemetryFrame> {
    let entries = data
        .as_array()
        .context("fastAssetCtxs data is neither a compressed wire string nor a historical array")?;
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let context = "fastAssetCtxs entry";
        out.push(AssetCtx {
            coin: coin_field(entry, context)?,
            mark_px: exact_price_field(entry, "markPx", context)?,
            mid_px: exact_price_field(entry, "midPx", context)?,
            oracle_px: exact_price_field(entry, "oraclePx", context)?,
        });
    }
    Ok(TelemetryFrame::FastAssetCtxs(out))
}

fn parse_fast_asset_ctxs(data: &Value) -> anyhow::Result<TelemetryFrame> {
    match data {
        Value::String(encoded) => parse_fast_asset_ctxs_wire(encoded),
        _ => parse_fast_asset_ctxs_array(data),
    }
}

/// Decode one inbound text payload as a Hyperliquid telemetry frame.
///
/// Unknown additive fields at every level are ignored. A malformed numeric
/// value in a field this codec recognises rejects the whole frame, which the
/// session reports as a decode failure with the exact raw bytes retained.
pub fn decode_telemetry(text: &str) -> anyhow::Result<TelemetryFrame> {
    let value: Value = serde_json::from_str(text).context("parsing Hyperliquid telemetry JSON")?;
    let channel = value
        .get("channel")
        .and_then(Value::as_str)
        .context("Hyperliquid frame has no string `channel`")?;
    let data = value
        .get("data")
        .context("Hyperliquid frame has no `data`")?;
    match channel {
        CHANNEL_ALL_MIDS => parse_all_mids(data),
        CHANNEL_FAST_ASSET_CTXS => parse_fast_asset_ctxs(data),
        other => Ok(TelemetryFrame::Ignored(other.to_owned())),
    }
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;

    const ALL_MIDS: &str = include_str!("../../../../fixtures/hyperliquid/all_mids.json");
    const ALL_MIDS_MALFORMED: &str =
        include_str!("../../../../fixtures/hyperliquid/all_mids_malformed.json");
    const FAST_CTX: &str = include_str!("../../../../fixtures/hyperliquid/fast_asset_ctxs.json");
    const FAST_CTX_MALFORMED: &str =
        include_str!("../../../../fixtures/hyperliquid/fast_asset_ctxs_malformed.json");
    const FAST_CTX_WIRE: &str =
        include_str!("../../../../fixtures/hyperliquid/fast_asset_ctxs_wire.json");

    /// The vendor-published example from the Hyperliquid subscription docs.
    /// It exercises base64 + raw DEFLATE + coin-keyed JSON without depending
    /// on a live capture for a deterministic unit test.
    const DOCS_EXAMPLE_B64: &str =
        "q1ZyCnFWsqpWyk0syg6oULJSsjQ3NTDQM1Wq1VFyDfFAkTI2MzXQMwJLVVRWWfmFuTiiyBuamOoZKdXWAgA=";

    fn price(text: &str) -> ExactPrice {
        ExactPrice {
            raw: text.to_owned(),
            scaled: fixed::parse_scaled(text, SCALE).ok(),
        }
    }

    fn exact(text: &str) -> Option<ExactPrice> {
        Some(price(text))
    }

    #[test]
    fn canonical_scale_matches_the_fixed_point_pipeline() {
        assert_eq!(usize::from(SCALE), fixed::DECIMALS);
    }

    #[test]
    fn all_mids_decodes_exact_values_and_ignores_additive_fields() {
        let frame = decode_telemetry(ALL_MIDS).expect("valid allMids fixture");
        assert_eq!(
            frame,
            TelemetryFrame::AllMids(vec![
                Mid {
                    coin: "BTC".to_owned(),
                    mid: price("67890.125")
                },
                Mid {
                    coin: "ETH".to_owned(),
                    mid: price("3512.5")
                },
            ])
        );
    }

    #[test]
    fn fast_asset_ctxs_decodes_exact_values_and_ignores_additive_fields() {
        let frame = decode_telemetry(FAST_CTX).expect("valid fastAssetCtxs fixture");
        assert_eq!(
            frame,
            TelemetryFrame::FastAssetCtxs(vec![
                AssetCtx {
                    coin: "BTC".to_owned(),
                    mark_px: exact("67890"),
                    mid_px: exact("67890.125"),
                    oracle_px: exact("67800"),
                },
                AssetCtx {
                    coin: "ETH".to_owned(),
                    mark_px: None,
                    mid_px: exact("3512.5"),
                    oracle_px: None,
                },
            ])
        );
    }

    #[test]
    fn compressed_wire_shape_decodes_the_vendor_example() {
        let envelope = json!({"channel":"fastAssetCtxs","data":DOCS_EXAMPLE_B64}).to_string();
        let frame = decode_telemetry(&envelope).expect("vendor fastAssetCtxs example");
        let TelemetryFrame::FastAssetCtxs(entries) = frame else {
            panic!("compressed envelope must decode to asset contexts");
        };
        assert_eq!(entries.len(), 3);
        let btc = entries.iter().find(|entry| entry.coin == "BTC").unwrap();
        assert_eq!(
            btc.mark_px.as_ref().map(|price| price.raw.as_str()),
            Some("97500.5")
        );
        assert_eq!(
            btc.mark_px.as_ref().and_then(|price| price.scaled),
            Some(97_500_500_000)
        );
        assert!(entries.iter().any(|entry| entry.coin == "xyz:NVDA"));
    }

    #[test]
    fn real_wire_frame_preserves_high_precision_without_rounding() {
        let frame = decode_telemetry(FAST_CTX_WIRE).expect("captured fastAssetCtxs wire frame");
        let TelemetryFrame::FastAssetCtxs(entries) = frame else {
            panic!("captured wire frame must decode to asset contexts");
        };
        assert!(
            entries.len() > 1_000,
            "the captured venue snapshot carries the full coin universe"
        );
        assert!(
            entries.iter().any(|entry| entry.coin == "BTC"
                && entry
                    .mark_px
                    .as_ref()
                    .is_some_and(|price| price.scaled.is_some())),
            "BTC must carry an exact SBE-scale mark price"
        );
        let high_precision = entries
            .iter()
            .find(|entry| entry.coin == "@74")
            .expect("the captured frame contains high-precision token prices");
        assert_eq!(
            high_precision
                .mark_px
                .as_ref()
                .map(|price| price.raw.as_str()),
            Some("0.0000034")
        );
        assert!(
            high_precision
                .mark_px
                .as_ref()
                .and_then(|price| price.scaled)
                .is_none(),
            "a value finer than the SBE scale must not be rounded into a coefficient"
        );
    }

    #[test]
    fn excessive_precision_is_preserved_not_rounded_or_rejected() {
        let frame = decode_telemetry(FAST_CTX_MALFORMED)
            .expect("a finer-than-SBE decimal is valid venue telemetry");
        let TelemetryFrame::FastAssetCtxs(entries) = frame else {
            panic!("expected asset contexts");
        };
        assert_eq!(entries[0].mark_px.as_ref().unwrap().raw, "67890.1234567");
        assert!(entries[0].mark_px.as_ref().unwrap().scaled.is_none());
    }

    #[test]
    fn all_mids_excessive_precision_is_preserved_not_rounded_or_rejected() {
        let frame = decode_telemetry(ALL_MIDS_MALFORMED)
            .expect("a finer-than-SBE mid is valid venue telemetry");
        let TelemetryFrame::AllMids(mids) = frame else {
            panic!("expected mids");
        };
        assert_eq!(mids[0].mid.raw, "67890.1234567");
        assert!(mids[0].mid.scaled.is_none());
    }

    #[test]
    fn malformed_numeric_strings_are_rejected_not_rounded() {
        for bad in [
            r#"{"channel":"allMids","data":{"mids":{"BTC":"not-a-number"}}}"#,
            r#"{"channel":"allMids","data":{"mids":{"BTC":"1e3"}}}"#,
            r#"{"channel":"allMids","data":{"mids":{"BTC":"1.2.3"}}}"#,
            r#"{"channel":"fastAssetCtxs","data":[{"coin":"BTC","markPx":123}]}"#,
            r#"{"channel":"fastAssetCtxs","data":[{"coin":"BTC","markPx":"not-a-number"}]}"#,
            r#"{"channel":"fastAssetCtxs","data":"!!not-base64!!"}"#,
        ] {
            assert!(decode_telemetry(bad).is_err(), "expected rejection: {bad}");
        }
    }

    #[test]
    fn unknown_additive_fields_are_ignored_not_rejected() {
        let frame = decode_telemetry(
            r#"{
                "channel":"fastAssetCtxs",
                "futureEnvelopeField":{"anything":true},
                "data":[{
                    "coin":"BTC",
                    "midPx":"1.000001",
                    "funding":"0.0000125",
                    "impactPxs":["1.0","1.1"],
                    "openInterest":"123.456789",
                    "aFieldFromTheFuture":"not even numeric"
                }]
            }"#,
        )
        .expect("additive fields must not reject the frame");
        assert_eq!(
            frame,
            TelemetryFrame::FastAssetCtxs(vec![AssetCtx {
                coin: "BTC".to_owned(),
                mark_px: None,
                mid_px: exact("1.000001"),
                oracle_px: None,
            }])
        );
    }

    #[test]
    fn unknown_channel_is_ignored_not_rejected() {
        let frame = decode_telemetry(r#"{"channel":"newFancyFeed","data":{"x":1}}"#)
            .expect("unknown additive channel is ignored");
        assert_eq!(frame, TelemetryFrame::Ignored("newFancyFeed".to_owned()));
    }

    #[test]
    fn subscription_requests_cover_exactly_the_two_supported_channels() {
        assert_eq!(
            subscription_request(CHANNEL_ALL_MIDS).expect("allMids subscription"),
            json!({"method":"subscribe","subscription":{"type":"allMids"}})
        );
        assert_eq!(
            subscription_request(CHANNEL_FAST_ASSET_CTXS).expect("fastAssetCtxs subscription"),
            json!({"method":"subscribe","subscription":{"type":"fastAssetCtxs"}})
        );
        assert!(
            subscription_request(CHANNEL_ASSET_CTXS_NOT_SUBSCRIBED).is_err(),
            "assetCtxs is not subscribed in H1 without a golden fixture"
        );
    }
}
