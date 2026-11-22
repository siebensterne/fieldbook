//! OKX reference-data discovery (H0).
//!
//! H0 opens no socket. Discovery reads an explicitly configured offline
//! `instruments` document and decodes it with the exact codec. Live REST
//! discovery is an H1 stage; until then a missing fixture fails closed instead
//! of dialling a venue.

use std::time::Instant;

use anyhow::{Context as _, bail};
use serde_json::Value;

use crate::{
    capacity::count_selected_markets, config::OkxSettings, exchange::DiscoveryResult,
    model::MarketInfo, time::now_us,
};

use super::codec::parse_instruments_document;

/// Discover the configured reference universe (market records only).
pub async fn discover(
    settings: &OkxSettings,
    max_markets: usize,
) -> anyhow::Result<Vec<MarketInfo>> {
    Ok(discover_with_stats(settings, max_markets).await?.markets)
}

/// Discover with page/record telemetry. The offline document is one page; no
/// network retries are possible in H0, so `retries` and `malformed_records`
/// stay zero and any decode error fails the round.
pub async fn discover_with_stats(
    settings: &OkxSettings,
    max_markets: usize,
) -> anyhow::Result<DiscoveryResult> {
    let started = Instant::now();
    let started_at_us = now_us().unwrap_or(0);
    let Some(path) = &settings.reference_fixture else {
        bail!(
            "OKX H0 discovery requires okx.reference_fixture: live REST discovery is planned for H1"
        );
    };
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading OKX reference fixture `{}`", path.display()))?;
    let document: Value = serde_json::from_str(&text).context("parsing OKX reference fixture")?;
    let mut markets = parse_instruments_document(&document, &settings.inst_types)?;
    markets.sort_by(|left, right| left.native_symbol.cmp(&right.native_symbol));
    if max_markets > 0 && markets.len() > max_markets {
        markets.truncate(max_markets);
    }
    let selected_markets = count_selected_markets(&markets) as u64;
    let outcome_symbols = markets.len() as u64;
    Ok(DiscoveryResult {
        markets,
        stats: crate::exchange::DiscoveryStats {
            pages: 1,
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

    fn fixture_settings() -> OkxSettings {
        OkxSettings {
            reference_fixture: Some(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("fixtures/okx/reference.json"),
            ),
            ..OkxSettings::default()
        }
    }

    #[tokio::test]
    async fn offline_discovery_reconciles_stats() {
        let result = discover_with_stats(&fixture_settings(), 0).await.unwrap();
        assert_eq!(result.markets.len(), 5);
        assert_eq!(result.stats.selected_markets, 5);
        assert_eq!(result.stats.outcome_symbols, 5);
        assert_eq!(result.stats.pages, 1);
        assert_eq!(result.stats.malformed_records, 0);
        assert_eq!(result.stats.retries, 0);
        assert_eq!(
            result.markets.first().map(|market| market.symbol.as_str()),
            Some("okx:spot:BTC/USDT")
        );
    }

    #[tokio::test]
    async fn discovery_fails_closed_without_a_fixture_and_honours_the_cap() {
        let mut settings = OkxSettings::default();
        assert!(discover_with_stats(&settings, 0).await.is_err());
        settings = fixture_settings();
        let result = discover_with_stats(&settings, 2).await.unwrap();
        assert_eq!(result.markets.len(), 2);
        assert_eq!(result.stats.outcome_symbols, 2);
    }
}
