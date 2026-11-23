//! Binance reference-data discovery (H0).
//!
//! H0 is offline: discovery reads only an explicitly configured
//! `exchangeInfo`-style fixture. No socket or HTTP client is created, so a
//! Binance collector cannot silently reach the network before a later stage
//! implements and gates that boundary.

use std::time::Instant;

use anyhow::Context as _;
use serde_json::Value;

use crate::{
    capacity::count_selected_markets, config::BinanceSettings, exchange::DiscoveryResult,
    model::MarketInfo, time::now_us,
};

use super::codec::parse_reference_document_selected;

/// Read and decode the configured offline reference fixture.
fn read_reference(settings: &BinanceSettings) -> anyhow::Result<Value> {
    let path = settings.reference_fixture.as_ref().with_context(|| {
        "Binance H0 discovery requires an explicit offline reference fixture; network discovery is not implemented"
    })?;
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading Binance reference fixture `{}`", path.display()))?;
    serde_json::from_str(&text).context("parsing Binance reference fixture")
}

/// Discover the configured reference universe from the offline fixture.
pub async fn discover(
    settings: &BinanceSettings,
    max_markets: usize,
) -> anyhow::Result<Vec<MarketInfo>> {
    Ok(discover_with_stats(settings, max_markets).await?.markets)
}

/// Discover with page/record telemetry. One page is counted per enabled
/// product section, mirroring the other adapters' discovery telemetry.
pub async fn discover_with_stats(
    settings: &BinanceSettings,
    max_markets: usize,
) -> anyhow::Result<DiscoveryResult> {
    let started = Instant::now();
    let started_at_us = now_us().unwrap_or(0);
    let document = read_reference(settings)?;
    let mut markets = parse_reference_document_selected(
        &document,
        &settings.canonical_quotes,
        settings.spot_enabled,
        settings.perp_enabled,
    )?;
    markets.sort_by(|left, right| left.native_symbol.cmp(&right.native_symbol));
    if max_markets > 0 && markets.len() > max_markets {
        markets.truncate(max_markets);
    }
    let pages = u64::from(settings.spot_enabled) + u64::from(settings.perp_enabled);
    let selected_markets = count_selected_markets(&markets) as u64;
    let outcome_symbols = markets.len() as u64;
    Ok(DiscoveryResult {
        markets,
        stats: crate::exchange::DiscoveryStats {
            pages,
            selected_markets,
            outcome_symbols,
            malformed_records: 0,
            retries: 0,
            duration_ms: started.elapsed().as_millis() as u64,
            started_at_us,
            finished_at_us: now_us().unwrap_or(started_at_us),
        },
    })
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;
    use crate::config::BinanceSettings;

    #[tokio::test]
    async fn network_discovery_is_unavailable_in_h0() {
        let error = discover_with_stats(&BinanceSettings::default(), 0)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("offline reference fixture"),
            "unexpected error: {error}"
        );
    }
}
