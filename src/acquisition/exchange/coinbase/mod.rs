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
            network.declared_intent.as_ref(),
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

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;
    use crate::config::{CoinbaseSettings, Settings};

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
