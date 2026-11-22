//! Binance H0 no-network session stub.
//!
//! H0 implements reference data only. The session factory exists so the
//! adapter satisfies the shared [`SessionFactory`] seam, but the returned
//! session opens no socket, accepts no subscriptions and reads no frames. The
//! heartbeat is explicitly disabled. A later staged gate replaces this stub;
//! until then, a Binance collector cannot reach the network through this session.

use std::collections::BTreeSet;

use anyhow::anyhow;
use async_trait::async_trait;

use crate::{
    config::{BinanceSettings, NetworkSettings},
    session::{
        HeartbeatRequest, HeartbeatSpec, MarketDataSession, SessionFactory, SessionFailure,
        SessionFrame,
    },
};

/// Factory for the H0 no-network session stub.
pub struct BinanceSessionFactory {
    settings: BinanceSettings,
    // Retained so the composition-root signature matches the other adapters;
    // unused because H0 opens no transport of any kind.
    _network: NetworkSettings,
}

impl BinanceSessionFactory {
    pub fn new(settings: BinanceSettings, network: NetworkSettings) -> Self {
        Self {
            settings,
            _network: network,
        }
    }
}

#[async_trait]
impl SessionFactory for BinanceSessionFactory {
    async fn create_session(
        &self,
        _source: crate::model::SourceId,
    ) -> anyhow::Result<Box<dyn MarketDataSession>> {
        Ok(Box::new(BinanceSession {
            settings: self.settings.clone(),
        }))
    }
}

/// H0 Binance session: no transport, no subscriptions, no events.
pub struct BinanceSession {
    settings: BinanceSettings,
}

impl BinanceSession {
    #[must_use]
    pub fn settings(&self) -> &BinanceSettings {
        &self.settings
    }

    fn no_network(operation: &str) -> SessionFailure {
        SessionFailure::Fatal(anyhow!(
            "Binance H0 is reference-data only: {operation} requires a network stage that is not implemented"
        ))
    }
}

#[async_trait]
impl MarketDataSession for BinanceSession {
    fn heartbeat_spec(&self) -> HeartbeatSpec {
        // No fixture pins a venue heartbeat in H0. Liveness is not claimed.
        HeartbeatSpec::disabled()
    }

    async fn connect(&mut self) -> Result<(), SessionFailure> {
        Err(Self::no_network("connect"))
    }

    async fn apply_subscriptions(
        &mut self,
        _desired: &BTreeSet<String>,
    ) -> Result<(), SessionFailure> {
        Err(Self::no_network("subscriptions"))
    }

    async fn next_frame(&mut self) -> Result<SessionFrame, SessionFailure> {
        Err(Self::no_network("frame reads"))
    }

    async fn send_keepalive(&mut self) -> Result<HeartbeatRequest, SessionFailure> {
        Ok(HeartbeatRequest::default())
    }

    async fn request_snapshot(&mut self, _symbols: &[String]) -> Result<(), SessionFailure> {
        Err(Self::no_network("snapshot requests"))
    }

    async fn close(&mut self) {}
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;
    use crate::protocol::HeartbeatMechanism;

    #[tokio::test]
    async fn h0_session_has_disabled_heartbeat_and_refuses_network() {
        let factory =
            BinanceSessionFactory::new(BinanceSettings::default(), NetworkSettings::default());
        let mut session = factory
            .create_session(crate::model::SourceId::new(0, 0))
            .await
            .unwrap();
        assert_eq!(
            session.heartbeat_spec().mechanism,
            HeartbeatMechanism::Disabled
        );
        assert!(matches!(
            session.connect().await,
            Err(SessionFailure::Fatal(_))
        ));
        assert!(matches!(
            session.apply_subscriptions(&BTreeSet::new()).await,
            Err(SessionFailure::Fatal(_))
        ));
        assert!(matches!(
            session.next_frame().await,
            Err(SessionFailure::Fatal(_))
        ));
        assert!(matches!(
            session.request_snapshot(&[]).await,
            Err(SessionFailure::Fatal(_))
        ));
        session.close().await;
    }

    #[test]
    fn h0_session_carries_only_reference_configuration() {
        let factory =
            BinanceSessionFactory::new(BinanceSettings::default(), NetworkSettings::default());
        assert_eq!(factory.settings.canonical_quotes, vec!["USDT".to_owned()]);
    }
}
