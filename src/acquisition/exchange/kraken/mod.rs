//! Kraken adapter.
//!
//! H0 implements reference data only: deterministic discovery of active spot
//! instruments from an `AssetPairs` document. No websocket is opened and no
//! book or telemetry event is produced. Later stages extend this module
//! without changing the normalized core.

pub mod codec;
pub mod discovery;
pub mod session;

use std::{collections::BTreeSet, sync::Arc};

use anyhow::Context as _;
use async_trait::async_trait;

use crate::{
    config::{ExchangeKind, KrakenSettings, NetworkSettings},
    exchange::{DiscoveryResult, Exchange, ExchangeCapabilities},
    model::MarketInfo,
    products::{
        BackpressureBehavior, HeartbeatMechanism, OrderingScope, PrecisionModel, RecoveryMode,
        SourceCapabilities, SubscriptionTopology, UpdateModel,
    },
    session::SessionFactory,
};

pub use codec::parse_reference_document;

/// Kraken exchange adapter (H0 reference data).
pub struct KrakenExchange {
    settings: KrakenSettings,
    client: reqwest::Client,
}

impl KrakenExchange {
    pub fn new(settings: KrakenSettings, network: NetworkSettings) -> anyhow::Result<Self> {
        let client = crate::egress::http_client(
            concat!("fieldbook-collector/", env!("CARGO_PKG_VERSION")),
            std::time::Duration::from_secs(settings.request_timeout_secs.max(1)),
            &network,
            network.declared_intent.as_ref(),
        )
        .context("building Kraken HTTP client")?;
        Ok(Self { settings, client })
    }

    #[must_use]
    pub fn settings(&self) -> &KrakenSettings {
        &self.settings
    }
}

#[async_trait]
impl Exchange for KrakenExchange {
    fn name(&self) -> &'static str {
        "kraken"
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
        Arc::new(session::KrakenSessionFactory)
    }
}

pub fn capabilities() -> ExchangeCapabilities {
    ExchangeCapabilities::new(false)
}

/// H0 is reference-data-only: no socket, no live products and no heartbeat.
/// Reference data is declared separately from the empty live-product set.
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
    ExchangeKind::Kraken
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;
    use crate::config::Settings;

    #[test]
    fn h0_uses_clockless_capabilities_and_no_lifecycle_plane() {
        let exchange =
            KrakenExchange::new(KrakenSettings::default(), NetworkSettings::default()).unwrap();
        assert_eq!(exchange.name(), "kraken");
        assert!(!exchange.capabilities().has_sequence_clock);
        assert_eq!(capabilities(), exchange.capabilities());
        assert_eq!(kind(), ExchangeKind::Kraken);
        let settings = Settings::for_exchange(ExchangeKind::Kraken);
        assert_eq!(settings.exchange, ExchangeKind::Kraken);
    }
}
