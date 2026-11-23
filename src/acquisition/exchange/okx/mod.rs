//! OKX adapter.
//!
//! H0 implements reference data only: deterministic decoding of an offline
//! `instruments`-style document into validated `MarketInfo` records with
//! explicit product-type-qualified identity and exact numeric scales. No
//! socket is opened, no subscription is sent and no book event is produced;
//! the session is an inert stub with a disabled heartbeat. H1 (planned) adds
//! REST discovery and a telemetry-only websocket, H2 (planned) adds a selected
//! book feed, and H3 (planned) adds capacity expansion behind the same seams.

pub mod codec;
pub mod discovery;
pub mod session;

use std::{collections::BTreeSet, sync::Arc};

use async_trait::async_trait;

use crate::{
    config::{ExchangeKind, OkxSettings},
    exchange::{DiscoveryResult, Exchange, ExchangeCapabilities},
    model::MarketInfo,
    products::{
        BackpressureBehavior, HeartbeatMechanism, OrderingScope, PrecisionModel, RecoveryMode,
        SourceCapabilities, SubscriptionTopology, UpdateModel,
    },
    session::SessionFactory,
};

pub use codec::parse_instruments_document;

/// OKX exchange adapter (H0 reference data only).
pub struct OkxExchange {
    settings: OkxSettings,
}

impl OkxExchange {
    #[must_use]
    pub fn new(settings: OkxSettings) -> Self {
        Self { settings }
    }

    #[must_use]
    pub fn settings(&self) -> &OkxSettings {
        &self.settings
    }
}

#[async_trait]
impl Exchange for OkxExchange {
    fn name(&self) -> &'static str {
        "okx"
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
        Arc::new(session::OkxSessionFactory)
    }

    // No separate lifecycle channel exists on OKX public feeds. The trait
    // default returns None; H0 states this explicitly for the capability map.
}

/// OKX declares no cross-replica comparable sequence clock. H0-H3 order by the
/// supervisor's receive fence, never by a venue field.
#[must_use]
pub fn capabilities() -> ExchangeCapabilities {
    ExchangeCapabilities::new(false)
}

/// H0 is reference-data-only: no socket, no live products and no heartbeat.
/// Ordering comes from the supervisor's receive fence, never a venue field.
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
    ExchangeKind::Okx
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;
    use crate::config::Settings;

    #[test]
    fn h0_uses_clockless_capabilities_and_no_lifecycle_plane() {
        let exchange = OkxExchange::new(OkxSettings::default());
        assert_eq!(exchange.name(), "okx");
        assert_eq!(exchange.environment(), "public");
        assert!(!exchange.capabilities().has_sequence_clock);
        assert_eq!(capabilities(), exchange.capabilities());
        assert_eq!(kind(), ExchangeKind::Okx);
        let adapter: Arc<dyn Exchange> = Arc::new(OkxExchange::new(OkxSettings::default()));
        assert!(adapter.lifecycle_session_factory().is_none());
    }

    #[test]
    fn h0_settings_defaults_are_backward_compatible_and_lowercase() {
        let old: OkxSettings = toml::from_str(
            r#"
            inst_types = ["SPOT", "SWAP"]
            request_timeout_secs = 5
            "#,
        )
        .expect("minimal OKX H0 configuration deserializes");
        assert_eq!(old.inst_types, vec!["SPOT", "SWAP"]);
        assert!(old.reference_fixture.is_none());
        assert_eq!(
            old.rest_url,
            "https://www.okx.com/api/v5/public/instruments"
        );
        let settings = Settings::for_exchange(ExchangeKind::Okx);
        assert_eq!(settings.exchange, ExchangeKind::Okx);
        assert_eq!(settings.exchange.to_string(), "okx");
    }
}
