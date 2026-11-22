//! Coinbase Exchange adapter.
//!
//! H0 implements reference data only: deterministic discovery of public spot
//! products from an offline `products` fixture or the `/products` REST endpoint,
//! decoded into validated `MarketInfo` records with explicit
//! `coinbase:spot:<BASE>/<QUOTE>` identity and exact price/quantity steps from
//! `quote_increment`/`base_increment`. The session is a no-network stub with a
//! disabled heartbeat; H1-H3 (telemetry, selected books, capacity) are planned
//! behind the same seams and are explicitly not implemented here.

pub mod codec;
pub mod discovery;
pub mod session;

use std::{collections::BTreeSet, sync::Arc};

use anyhow::Context as _;
use async_trait::async_trait;

use crate::{
    config::{CoinbaseSettings, ExchangeKind, NetworkSettings},
    exchange::{DiscoveryResult, Exchange, ExchangeCapabilities},
    model::MarketInfo,
    products::{
        BackpressureBehavior, HeartbeatMechanism, OrderingScope, PrecisionModel, RecoveryMode,
        SourceCapabilities, SubscriptionTopology, UpdateModel,
    },
    session::SessionFactory,
};

pub use codec::parse_reference_document;

/// Coinbase exchange adapter (H0 reference data only).
pub struct CoinbaseExchange {
    settings: CoinbaseSettings,
    client: reqwest::Client,
}

impl CoinbaseExchange {
    pub fn new(settings: CoinbaseSettings, network: NetworkSettings) -> anyhow::Result<Self> {
        let client = crate::egress::http_client(
            concat!("fieldbook-collector/", env!("CARGO_PKG_VERSION")),
            std::time::Duration::from_secs(settings.request_timeout_secs.max(1)),
            &network,
        )
        .context("building Coinbase HTTP client")?;
        Ok(Self { settings, client })
    }

    #[must_use]
    pub fn settings(&self) -> &CoinbaseSettings {
        &self.settings
    }
}

#[async_trait]
impl Exchange for CoinbaseExchange {
    fn name(&self) -> &'static str {
        "coinbase"
    }

    fn environment(&self) -> &'static str {
        "public"
    }

    fn capabilities(&self) -> ExchangeCapabilities {
        ExchangeCapabilities::new(false)
    }

    fn source_capabilities(&self) -> SourceCapabilities {
        typed_capabilities()
    }

    async fn discover_markets(&self, max_markets: usize) -> anyhow::Result<Vec<MarketInfo>> {
        discovery::discover(&self.settings, &self.client, max_markets).await
    }

    async fn discover_markets_with_stats(
        &self,
        max_markets: usize,
    ) -> anyhow::Result<DiscoveryResult> {
        discovery::discover_with_stats(&self.settings, &self.client, max_markets).await
    }

    fn session_factory(self: Arc<Self>) -> Arc<dyn SessionFactory> {
        Arc::new(session::CoinbaseSessionFactory)
    }
}

/// Coinbase H0 declares no cross-replica sequence clock. Any feed timestamp or
/// sequence field is deferred to a later, fixture-gated stage.
pub fn capabilities() -> ExchangeCapabilities {
    ExchangeCapabilities::new(false)
}

/// H0 is reference-data-only: no socket, no live products and no heartbeat.
/// The `products` set is empty; reference data is declared
/// separately rather than disguised as a live product.
#[must_use]
pub fn typed_capabilities() -> SourceCapabilities {
    SourceCapabilities {
        products: BTreeSet::new(),
        provides_reference_data: true,
        update_model: UpdateModel::ReferenceData,
        ordering_scope: OrderingScope::NotApplicable,
        recovery_mode: RecoveryMode::NotApplicable,
        heartbeat: HeartbeatMechanism::Disabled,
        subscription_topology: SubscriptionTopology::NotApplicable,
        telemetry_topology: SubscriptionTopology::NotApplicable,
        precision: PrecisionModel::ExactDecimal,
        backpressure: BackpressureBehavior::NotApplicable,
        has_sequence_clock: false,
    }
}

#[must_use]
pub const fn kind() -> ExchangeKind {
    ExchangeKind::Coinbase
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CoinbaseSettings, Settings};

    const REFERENCE: &str = include_str!("../../../../fixtures/coinbase/reference.json");

    fn fixture_settings() -> CoinbaseSettings {
        CoinbaseSettings {
            reference_fixture: Some(
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("fixtures/coinbase/reference.json"),
            ),
            ..CoinbaseSettings::default()
        }
    }

    #[test]
    fn h0_reference_document_produces_valid_namespaced_markets() {
        let value: serde_json::Value = serde_json::from_str(REFERENCE).expect("fixture JSON");
        let markets = parse_reference_document(&value, true).expect("valid reference document");
        assert_eq!(markets.len(), 5);
        for market in &markets {
            market.validate().expect("valid market");
            market.numeric_spec.validate().expect("valid numeric spec");
            assert_eq!(market.exchange, "coinbase");
            assert_eq!(market.symbol, market.native_symbol);
            assert!(market.native_symbol.starts_with("coinbase:spot:"));
            assert!(market.exchange_market_id.is_none());
            assert!(market.outcome.is_none());
        }
        assert!(
            markets
                .iter()
                .any(|market| market.native_symbol == "coinbase:spot:BTC/USD")
        );
        assert!(
            markets
                .iter()
                .any(|market| market.native_symbol == "coinbase:spot:BTC/USDT")
        );
    }

    #[tokio::test]
    async fn h0_discovery_is_offline_and_reconciles_stats() {
        let exchange =
            CoinbaseExchange::new(fixture_settings(), NetworkSettings::default()).unwrap();
        let result = exchange.discover_markets_with_stats(0).await.unwrap();
        assert_eq!(result.markets.len(), 5);
        assert_eq!(result.stats.pages, 1);
        assert_eq!(result.stats.selected_markets, 5);
        assert_eq!(result.stats.outcome_symbols, 5);
        assert_eq!(result.stats.malformed_records, 0);
        assert_eq!(result.stats.retries, 0);
        assert!(
            result
                .markets
                .windows(2)
                .all(|pair| pair[0].native_symbol <= pair[1].native_symbol)
        );
    }

    #[test]
    fn h0_uses_clockless_capabilities_and_no_lifecycle_plane() {
        let exchange =
            CoinbaseExchange::new(CoinbaseSettings::default(), NetworkSettings::default()).unwrap();
        assert_eq!(exchange.name(), "coinbase");
        assert_eq!(exchange.environment(), "public");
        assert!(!exchange.capabilities().has_sequence_clock);
        assert_eq!(capabilities(), exchange.capabilities());
        assert_eq!(kind(), ExchangeKind::Coinbase);
        let shared = Arc::new(
            CoinbaseExchange::new(CoinbaseSettings::default(), NetworkSettings::default()).unwrap(),
        );
        assert!(Exchange::lifecycle_session_factory(shared).is_none());
        let settings = Settings::for_exchange(ExchangeKind::Coinbase);
        assert_eq!(settings.exchange, ExchangeKind::Coinbase);
        assert_eq!(
            settings.coinbase.rest_url,
            "https://api.exchange.coinbase.com"
        );
    }
}
