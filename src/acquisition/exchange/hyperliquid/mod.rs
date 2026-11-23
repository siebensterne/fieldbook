//! Hyperliquid adapter.
//!
//! H0 implements reference data: deterministic discovery of perpetual and spot
//! instruments from `meta`/`spotMeta` documents. H1 adds a telemetry-only
//! websocket session for `allMids` and `fastAssetCtxs`; those frames are
//! journaled evidence, never book events or coverage anchors. H2 adds a
//! selected-perpetual book feed: `l2Book` full snapshots become
//! [`crate::model::ExchangeEvent::Snapshot`], `trades` stay telemetry, and no
//! `LevelChange` is ever produced. No ADR-0001 reference-model migration, spot
//! book or full-universe subscription is implemented here.

pub mod books;
pub mod codec;
pub mod discovery;
pub mod session;
pub mod telemetry;

use std::{collections::BTreeSet, sync::Arc};

use anyhow::Context as _;
use async_trait::async_trait;

use crate::{
    config::{ExchangeKind, HyperliquidSettings, NetworkSettings},
    exchange::{DiscoveryResult, Exchange, ExchangeCapabilities},
    model::MarketInfo,
    products::{
        BackpressureBehavior, HeartbeatMechanism, OrderingScope, PrecisionModel, ProductKind,
        RecoveryMode, SourceCapabilities, SubscriptionTopology, UpdateModel,
    },
    session::SessionFactory,
};

pub use codec::parse_reference_document;

/// Hyperliquid exchange adapter (H0 reference data, H1 telemetry, H2 selected books).
pub struct HyperliquidExchange {
    settings: HyperliquidSettings,
    network: NetworkSettings,
    client: reqwest::Client,
}

impl HyperliquidExchange {
    pub fn new(settings: HyperliquidSettings, network: NetworkSettings) -> anyhow::Result<Self> {
        let client = crate::egress::http_client(
            concat!("fieldbook-collector/", env!("CARGO_PKG_VERSION")),
            std::time::Duration::from_secs(settings.request_timeout_secs.max(1)),
            &network,
            network.declared_intent.as_ref(),
        )
        .context("building Hyperliquid HTTP client")?;
        Ok(Self {
            settings,
            network,
            client,
        })
    }

    #[must_use]
    pub fn settings(&self) -> &HyperliquidSettings {
        &self.settings
    }
}

#[async_trait]
impl Exchange for HyperliquidExchange {
    fn name(&self) -> &'static str {
        "hyperliquid"
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

    fn subscribed_universe(&self, markets: Vec<MarketInfo>) -> Vec<MarketInfo> {
        // H2 subscribes l2Book/trades only for the configured finite set of
        // perpetuals. Everything else is discovery context, not part of this
        // run's subscribed universe; counting it as expected would demand
        // anchors that the session never requests.
        markets
            .into_iter()
            .filter(|market| {
                books::is_selected_perp(&market.native_symbol, &self.settings.books.perpetuals)
            })
            .collect()
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
        Arc::new(session::HyperliquidSessionFactory::new(
            self.settings.clone(),
            self.network.clone(),
        ))
    }
}

pub fn capabilities() -> ExchangeCapabilities {
    ExchangeCapabilities::new(false)
}

/// H1 telemetry (`allMids`, `fastAssetCtxs`) is venue-global; H2 books and
/// trades are per-instrument. `l2Book` supplies full snapshots only, numbers
/// are decoded exactly, and no venue sequence clock is claimed.
#[must_use]
pub fn typed_capabilities() -> SourceCapabilities {
    SourceCapabilities {
        products: BTreeSet::from([
            ProductKind::OrderBookL2,
            ProductKind::Trades,
            ProductKind::AssetContext,
            ProductKind::GlobalStatistics,
        ]),
        provides_reference_data: true,
        update_model: UpdateModel::SnapshotOnly,
        ordering_scope: OrderingScope::ReceiveFence,
        recovery_mode: RecoveryMode::ResubscribeAndReanchor,
        heartbeat: HeartbeatMechanism::Disabled,
        subscription_topology: SubscriptionTopology::PerInstrument,
        telemetry_topology: SubscriptionTopology::Global,
        precision: PrecisionModel::ExactDecimal,
        backpressure: BackpressureBehavior::BoundedFailClosed,
        has_sequence_clock: false,
    }
}

#[must_use]
pub const fn kind() -> ExchangeKind {
    ExchangeKind::Hyperliquid
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;
    use crate::config::Settings;

    #[test]
    fn h0_uses_clockless_capabilities_and_no_lifecycle_plane() {
        let exchange =
            HyperliquidExchange::new(HyperliquidSettings::default(), NetworkSettings::default())
                .unwrap();
        assert_eq!(exchange.name(), "hyperliquid");
        assert!(!exchange.capabilities().has_sequence_clock);
        assert_eq!(capabilities(), exchange.capabilities());
        assert_eq!(kind(), ExchangeKind::Hyperliquid);
        let settings = Settings::for_exchange(ExchangeKind::Hyperliquid);
        assert_eq!(settings.exchange, ExchangeKind::Hyperliquid);
    }

    #[test]
    fn h1_settings_defaults_are_backward_compatible() {
        // An H0 configuration that predates ws_url/telemetry still parses.
        let old: HyperliquidSettings = toml::from_str(
            r#"
            info_url = "https://example.invalid/info"
            dexs = [""]
            request_timeout_secs = 5
            "#,
        )
        .expect("H0-only configuration still deserializes");
        assert_eq!(old.ws_url, "wss://api.hyperliquid.xyz/ws");
        assert_eq!(
            old.telemetry.subscriptions,
            vec!["allMids".to_owned(), "fastAssetCtxs".to_owned()]
        );
        let settings = Settings::for_exchange(ExchangeKind::Hyperliquid);
        assert!(settings.hyperliquid.ws_url.starts_with("wss://"));
    }
}
