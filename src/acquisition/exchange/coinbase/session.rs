//! Coinbase session stub for H0.
//!
//! H0 opens no websocket and produces no market events. The stub exists so the
//! exchange adapter satisfies the composition seam without pretending that a
//! Coinbase book, level2 or heartbeat feed is implemented. H1-H3 are planned
//! behind the same `SessionFactory` / `MarketDataSession` seams.

use async_trait::async_trait;

use crate::{
    model::SourceId,
    session::{
        HeartbeatRequest, HeartbeatSpec, MarketDataSession, SessionFactory, SessionFailure,
        SessionFrame,
    },
};

/// H0 no-network session.
pub struct CoinbaseSession;

#[async_trait]
impl MarketDataSession for CoinbaseSession {
    fn heartbeat_spec(&self) -> HeartbeatSpec {
        // No Coinbase heartbeat is verified in H0. Liveness is a later stage's
        // concern; this stub never claims a venue heartbeat.
        HeartbeatSpec::disabled()
    }

    async fn connect(&mut self) -> Result<(), SessionFailure> {
        Ok(())
    }

    async fn apply_subscriptions(
        &mut self,
        _desired: &std::collections::BTreeSet<String>,
    ) -> Result<(), SessionFailure> {
        Ok(())
    }

    async fn next_frame(&mut self) -> Result<SessionFrame, SessionFailure> {
        Ok(SessionFrame::idle(0))
    }

    async fn send_keepalive(&mut self) -> Result<HeartbeatRequest, SessionFailure> {
        Ok(HeartbeatRequest::default())
    }

    async fn request_snapshot(&mut self, _symbols: &[String]) -> Result<(), SessionFailure> {
        Ok(())
    }

    async fn close(&mut self) {}
}

/// Factory for H0 no-network sessions.
pub struct CoinbaseSessionFactory;

#[async_trait]
impl SessionFactory for CoinbaseSessionFactory {
    async fn create_session(
        &self,
        _source: SourceId,
    ) -> anyhow::Result<Box<dyn MarketDataSession>> {
        Ok(Box::new(CoinbaseSession))
    }
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;
    use crate::protocol::HeartbeatMechanism;

    #[tokio::test]
    async fn h0_session_is_no_network_with_disabled_heartbeat() {
        let mut session = CoinbaseSession;
        assert_eq!(
            session.heartbeat_spec().mechanism,
            HeartbeatMechanism::Disabled
        );
        session.connect().await.unwrap();
        session
            .apply_subscriptions(&std::collections::BTreeSet::new())
            .await
            .unwrap();
        let frame = session.next_frame().await.unwrap();
        assert!(frame.events.is_empty());
        assert!(frame.raw.is_none());
        assert!(frame.observations.is_empty());
        assert_eq!(frame.mechanism, HeartbeatMechanism::Disabled);
        assert!(
            session
                .send_keepalive()
                .await
                .unwrap()
                .correlation
                .is_none()
        );
        session
            .request_snapshot(&["coinbase:spot:BTC/USD".to_owned()])
            .await
            .unwrap();
        session.close().await;

        let factory = CoinbaseSessionFactory;
        let created = factory
            .create_session(SourceId {
                shard: 0,
                replica: 0,
            })
            .await
            .unwrap();
        assert_eq!(
            created.heartbeat_spec().mechanism,
            HeartbeatMechanism::Disabled
        );
    }
}
