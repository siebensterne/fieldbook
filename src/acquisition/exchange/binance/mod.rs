//! Binance adapter.
//!
//! H0 implements reference data only: deterministic discovery of spot and
//! perpetual instruments from an offline `exchangeInfo`-style fixture, with
//! explicit `binance:spot:BASE/QUOTE` / `binance:perp:SYMBOL` identities and
//! exact numeric specs. No socket is opened, no book or telemetry event is
//! produced, and no live or performance claim is made. H1-H3 are planned gates,
//! not implemented behavior; see `docs/BINANCE_INTEGRATION_PLAN.md`.

pub mod codec;
pub mod discovery;
pub mod session;

use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;

use crate::{
    config::{BinanceSettings, ExchangeKind, NetworkSettings},
    exchange::{DiscoveryResult, Exchange, ExchangeCapabilities},
    model::MarketInfo,
    products::{
        BackpressureBehavior, HeartbeatMechanism, OrderingScope, PrecisionModel, RecoveryMode,
        SourceCapabilities, SubscriptionTopology, UpdateModel,
    },
    session::SessionFactory,
};

pub use codec::parse_reference_document;

/// Binance exchange adapter (H0 reference data).
pub struct BinanceExchange {
    settings: BinanceSettings,
    // Retained to match the composition-root signature of the other adapters;
    // unused because H0 opens no transport of any kind.
    _network: NetworkSettings,
}

impl BinanceExchange {
    pub fn new(settings: BinanceSettings, network: NetworkSettings) -> anyhow::Result<Self> {
        Ok(Self {
            settings,
            _network: network,
        })
    }

    #[must_use]
    pub fn settings(&self) -> &BinanceSettings {
        &self.settings
    }
}

#[async_trait]
impl Exchange for BinanceExchange {
    fn name(&self) -> &'static str {
        "binance"
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
        discovery::discover(&self.settings, max_markets).await
    }

    async fn discover_markets_with_stats(
        &self,
        max_markets: usize,
    ) -> anyhow::Result<DiscoveryResult> {
        discovery::discover_with_stats(&self.settings, max_markets).await
    }

    fn session_factory(self: Arc<Self>) -> Arc<dyn SessionFactory> {
        Arc::new(session::BinanceSessionFactory::new(
            self.settings.clone(),
            NetworkSettings::default(),
        ))
    }
}

pub fn capabilities() -> ExchangeCapabilities {
    ExchangeCapabilities::new(false)
}

/// H0 is offline reference-data-only: no socket, no live products, no
/// heartbeat and no venue ordering authority.
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
    ExchangeKind::Binance
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;
    use crate::{capacity, config::Settings, exchange::capabilities_for};

    #[test]
    fn h0_capability_is_clockless_and_lifecycle_plane_absent() {
        let exchange =
            BinanceExchange::new(BinanceSettings::default(), NetworkSettings::default()).unwrap();
        assert_eq!(exchange.name(), "binance");
        assert_eq!(exchange.environment(), "public");
        assert!(!exchange.capabilities().has_sequence_clock);
        assert_eq!(capabilities(), exchange.capabilities());
        assert!(!capabilities_for(kind()).has_sequence_clock);
        assert_eq!(kind(), ExchangeKind::Binance);

        let settings = Settings::for_exchange(ExchangeKind::Binance);
        assert_eq!(settings.exchange, ExchangeKind::Binance);
        let exchange: Arc<dyn Exchange> = Arc::new(
            BinanceExchange::new(settings.binance.clone(), settings.network.clone()).unwrap(),
        );
        let lifecycle: Option<Arc<dyn SessionFactory>> =
            Exchange::lifecycle_session_factory(Arc::clone(&exchange));
        assert!(lifecycle.is_none());
        // No phantom lifecycle socket is charged in capacity planning.
        let plan = capacity::plan(&settings, &[]).expect("capacity plan");
        assert_eq!(plan.lifecycle_connections, 0);
    }
}
