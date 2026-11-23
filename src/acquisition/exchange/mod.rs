//! Exchange adapter abstraction and common discovery/session interface.
//!
//! The seven crypto and prediction-market adapter families were retired under
//! RRP-003. This module keeps only the venue-neutral contract: no concrete
//! adapter is registered here. A securities venue adapter is added only after
//! its source, rights and NDC projection are qualified (workspace W4).

use std::{sync::Arc, time::Instant};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    capacity::count_selected_markets, model::MarketInfo, products::SourceCapabilities,
    session::SessionFactory, time::now_us,
};

/// Venue features that an exchange adapter reports to the collector core.
///
/// The core consumes these values instead of identifying a venue by name, so
/// adding an exchange requires a new adapter and capability declaration, not a
/// change to the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExchangeCapabilities {
    /// The venue supplies a sequence number or clock that can verify backup
    /// book freshness and quantify a recovery gap.
    pub has_sequence_clock: bool,
}

impl ExchangeCapabilities {
    #[must_use]
    pub const fn new(has_sequence_clock: bool) -> Self {
        Self { has_sequence_clock }
    }
}

/// Conservative capability declaration used when no adapter is present.
///
/// Replay and offline inspection have no live venue to interrogate. They use
/// this clockless declaration rather than assuming a sequence clock, so a
/// replay never claims ordering guarantees it cannot verify.
#[must_use]
pub fn capabilities_for() -> ExchangeCapabilities {
    ExchangeCapabilities::default()
}

/// Conservative typed source-capability declaration for offline paths.
///
/// The composition root obtains typed capabilities from a constructed adapter.
/// With no adapter registered, the offline declaration is empty by construction:
/// no live products, no reference-data claim and no sequence clock.
#[must_use]
pub fn source_capabilities_for() -> SourceCapabilities {
    SourceCapabilities::from_legacy(false)
}

/// Telemetry for one complete discovery round.
///
/// `selected_markets` counts venue records; `outcome_symbols` counts the
/// subscribable tokens those records produced. The two differ when one
/// discovery record expands into several outcome tokens.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryStats {
    pub pages: u64,
    pub selected_markets: u64,
    pub outcome_symbols: u64,
    pub malformed_records: u64,
    pub retries: u64,
    pub duration_ms: u64,
    pub started_at_us: i64,
    pub finished_at_us: i64,
}

/// A complete discovery result with its telemetry.
#[derive(Debug, Clone)]
pub struct DiscoveryResult {
    pub markets: Vec<MarketInfo>,
    pub stats: DiscoveryStats,
}

/// One exchange's discovery and websocket implementation.
#[async_trait]
pub trait Exchange: Send + Sync + 'static {
    /// Stable lowercase exchange name used in SBE symbols and reports.
    fn name(&self) -> &'static str;

    /// Human-readable environment (`production`, `demo`, or `public`).
    fn environment(&self) -> &'static str;

    /// Features the collector core may rely on for this venue.
    fn capabilities(&self) -> ExchangeCapabilities;

    /// Typed products and delivery contract for this venue. The default is a
    /// conservative projection of the legacy flag so adapters without a
    /// declaration keep compiling; adapters with typed products override it.
    fn source_capabilities(&self) -> SourceCapabilities {
        SourceCapabilities::from_legacy(self.capabilities().has_sequence_clock)
    }

    /// Persistent identity assertions for the markets this adapter discovers.
    ///
    /// The default is empty so existing adapters compile unchanged. Overrides
    /// must derive identities from immutable venue wire keys, never from
    /// titles, slugs or output symbols (ADR-0001).
    fn identity_assertions(
        &self,
        markets: &[MarketInfo],
    ) -> anyhow::Result<Vec<crate::identity::VenueInstrumentMapping>> {
        Ok(crate::identity::venue_mappings_from_markets(
            self.name(),
            markets,
        ))
    }

    /// Narrow one discovery round to the markets this collector
    /// subscribes. The default keeps every discovered market; a venue whose
    /// runtime subscribes only a configured subset overrides it so metadata,
    /// desired subscriptions, acknowledgements and coverage all describe the
    /// same universe instead of counting markets the session never requests.
    fn subscribed_universe(&self, markets: Vec<MarketInfo>) -> Vec<MarketInfo> {
        markets
    }

    /// Fetch the current live, non-MVE market set. Implementations cap the
    /// result when `max_markets` is non-zero.
    async fn discover_markets(&self, max_markets: usize) -> anyhow::Result<Vec<MarketInfo>>;

    /// Fetch a discovery round with page and record telemetry.
    ///
    /// The default implementation preserves adapters that do not publish
    /// page-level counters; adapters with telemetry override it.
    async fn discover_markets_with_stats(
        &self,
        max_markets: usize,
    ) -> anyhow::Result<DiscoveryResult> {
        let started = Instant::now();
        let started_at_us = now_us().unwrap_or(0);
        let markets = self.discover_markets(max_markets).await?;
        let stats = DiscoveryStats {
            pages: 1,
            selected_markets: count_selected_markets(&markets) as u64,
            outcome_symbols: markets.len() as u64,
            duration_ms: started.elapsed().as_millis() as u64,
            started_at_us,
            finished_at_us: now_us().unwrap_or(started_at_us),
            ..DiscoveryStats::default()
        };
        Ok(DiscoveryResult { markets, stats })
    }

    /// Build the factory used by websocket source workers.
    fn session_factory(self: Arc<Self>) -> Arc<dyn SessionFactory>;

    /// Optional dedicated market-lifecycle control plane.
    ///
    /// Venues with a separate lifecycle channel return a factory whose
    /// sessions subscribe only to that channel. The coordinator spawns
    /// `collector.lifecycle_replicas` workers from it; book shards never
    /// carry lifecycle subscriptions. Returns `None` (the default) for
    /// venues without a separate lifecycle channel, or when the lifecycle
    /// plane cannot operate (for example, missing credentials).
    fn lifecycle_session_factory(self: Arc<Self>) -> Option<Arc<dyn SessionFactory>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct LegacyOnlyExchange;

    #[async_trait]
    impl Exchange for LegacyOnlyExchange {
        fn name(&self) -> &'static str {
            "legacy"
        }

        fn environment(&self) -> &'static str {
            "test"
        }

        fn capabilities(&self) -> ExchangeCapabilities {
            ExchangeCapabilities::new(true)
        }

        async fn discover_markets(&self, _max_markets: usize) -> anyhow::Result<Vec<MarketInfo>> {
            Ok(Vec::new())
        }

        fn session_factory(self: Arc<Self>) -> Arc<dyn SessionFactory> {
            Arc::new(NoopSessionFactory)
        }
    }

    struct NoopSessionFactory;

    #[async_trait]
    impl SessionFactory for NoopSessionFactory {
        async fn create_session(
            &self,
            _source: crate::model::SourceId,
        ) -> anyhow::Result<Box<dyn crate::session::MarketDataSession>> {
            anyhow::bail!("no session in the capability default test")
        }
    }

    #[test]
    fn exchange_trait_default_capabilities_are_legacy_equivalent() {
        let adapter = LegacyOnlyExchange;
        let declared = adapter.source_capabilities();
        assert_eq!(declared, SourceCapabilities::from_legacy(true));
        assert!(declared.has_sequence_clock);
        assert!(declared.products.is_empty());
    }

    #[test]
    fn offline_capability_declarations_are_conservative() {
        assert!(!capabilities_for().has_sequence_clock);
        assert!(!source_capabilities_for().has_sequence_clock);
        assert!(source_capabilities_for().products.is_empty());
    }
}
