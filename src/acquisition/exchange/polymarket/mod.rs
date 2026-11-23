//! Polymarket public CLOB adapter.

mod codec;
mod discovery;
mod session;

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use async_trait::async_trait;
use reqwest::Client;

pub use session::{PolymarketExchange, PolymarketSessionFactory};

use crate::{
    config::{ExchangeKind, NetworkSettings, PolymarketSettings},
    exchange::{DiscoveryResult, Exchange, ExchangeCapabilities, capabilities_for},
    model::MarketInfo,
    products::{
        BackpressureBehavior, HeartbeatMechanism, OrderingScope, PrecisionModel, ProductKind,
        RecoveryMode, SourceCapabilities, SubscriptionTopology, UpdateModel,
    },
    session::SessionFactory,
};

#[async_trait]
impl Exchange for PolymarketExchange {
    fn name(&self) -> &'static str {
        "polymarket"
    }

    fn environment(&self) -> &'static str {
        "public"
    }

    fn capabilities(&self) -> ExchangeCapabilities {
        capabilities_for(ExchangeKind::Polymarket)
    }

    fn source_capabilities(&self) -> SourceCapabilities {
        typed_capabilities()
    }

    async fn discover_markets(&self, max_markets: usize) -> anyhow::Result<Vec<MarketInfo>> {
        Ok(self.fetch_markets(max_markets).await?.markets)
    }

    async fn discover_markets_with_stats(
        &self,
        max_markets: usize,
    ) -> anyhow::Result<DiscoveryResult> {
        self.fetch_markets(max_markets).await
    }

    fn session_factory(self: Arc<Self>) -> Arc<dyn SessionFactory> {
        self
    }
}

/// Polymarket books are per-instrument outcome-token subscriptions. There is
/// no cross-replica comparable venue clock, and the heartbeat is application
/// text rather than a native control frame.
#[must_use]
pub fn typed_capabilities() -> SourceCapabilities {
    SourceCapabilities {
        products: BTreeSet::from([ProductKind::OrderBookL2]),
        provides_reference_data: true,
        update_model: UpdateModel::SnapshotAndDelta,
        ordering_scope: OrderingScope::ReceiveFence,
        recovery_mode: RecoveryMode::ResubscribeAndReanchor,
        heartbeat: HeartbeatMechanism::ApplicationText,
        subscription_topology: SubscriptionTopology::PerInstrument,
        telemetry_topology: SubscriptionTopology::NotApplicable,
        precision: PrecisionModel::FixedPoint,
        backpressure: BackpressureBehavior::BoundedFailClosed,
        has_sequence_clock: false,
    }
}

impl PolymarketExchange {
    pub fn new(settings: PolymarketSettings, network: NetworkSettings) -> anyhow::Result<Self> {
        let client = crate::egress::http_client(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
             AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 \
             EngineeringChallengeCollector/0.3",
            Duration::from_secs(settings.request_timeout_secs),
            &network,
            network.declared_intent.as_ref(),
        )
        .map_err(|error| anyhow::anyhow!("building Polymarket HTTP client: {error}"))?;
        Ok(Self {
            settings,
            client,
            network,
        })
    }

    #[must_use]
    pub fn settings(&self) -> &PolymarketSettings {
        &self.settings
    }

    pub(crate) fn client(&self) -> &Client {
        &self.client
    }
}
