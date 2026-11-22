//! OKX H0 no-network session stub.
//!
//! H0 provides reference data only. The adapter opens no socket,
//! subscribes to no channel and produces no frame: the supervisor can be wired
//! through the same seams as other venues, but a live collection attempt fails
//! closed with a fatal error instead of pretending to have a feed. The
//! heartbeat is `Disabled`, so no keepalive or venue clock is invented. H1-H3
//! replace this stub with a real websocket session behind the same traits.

use std::collections::BTreeSet;

use anyhow::anyhow;
use async_trait::async_trait;

use crate::{
    model::SourceId,
    session::{
        HeartbeatRequest, HeartbeatSpec, MarketDataSession, SessionFactory, SessionFailure,
        SessionFrame,
    },
};

/// Factory for the inert H0 session. Holds no configuration because no
/// transport is constructed in H0.
#[derive(Debug, Default, Clone, Copy)]
pub struct OkxSessionFactory;

#[async_trait]
impl SessionFactory for OkxSessionFactory {
    async fn create_session(
        &self,
        _source: SourceId,
    ) -> anyhow::Result<Box<dyn MarketDataSession>> {
        Ok(Box::new(OkxNoNetworkSession))
    }
}

/// A session that represents the absence of an OKX market-data feed in H0.
#[derive(Debug, Default, Clone, Copy)]
pub struct OkxNoNetworkSession;

#[async_trait]
impl MarketDataSession for OkxNoNetworkSession {
    fn heartbeat_spec(&self) -> HeartbeatSpec {
        HeartbeatSpec::disabled()
    }

    async fn connect(&mut self) -> Result<(), SessionFailure> {
        Err(SessionFailure::Fatal(anyhow!(
            "OKX H0 is reference-data only; no websocket session is available"
        )))
    }

    async fn apply_subscriptions(
        &mut self,
        _desired: &BTreeSet<String>,
    ) -> Result<(), SessionFailure> {
        Ok(())
    }

    async fn next_frame(&mut self) -> Result<SessionFrame, SessionFailure> {
        Err(SessionFailure::Fatal(anyhow!(
            "OKX H0 session produces no frames"
        )))
    }

    async fn send_keepalive(&mut self) -> Result<HeartbeatRequest, SessionFailure> {
        // Never called: the heartbeat spec is Disabled. Keeping the seam total
        // avoids inventing a venue heartbeat.
        Ok(HeartbeatRequest::default())
    }

    async fn request_snapshot(&mut self, _symbols: &[String]) -> Result<(), SessionFailure> {
        Ok(())
    }

    async fn close(&mut self) {}
}

#[cfg(all(test, feature = "market-shaped-tests"))]
mod tests {
    use super::*;
    use crate::protocol::HeartbeatMechanism;

    #[tokio::test]
    async fn h0_session_is_inert_and_has_no_heartbeat() {
        let factory = OkxSessionFactory;
        let mut session = factory
            .create_session(SourceId::new(0, 0))
            .await
            .expect("factory creates the inert session");
        assert_eq!(
            session.heartbeat_spec().mechanism,
            HeartbeatMechanism::Disabled
        );
        assert!(
            session.apply_subscriptions(&BTreeSet::new()).await.is_ok(),
            "an empty subscription is a no-op in H0"
        );
        assert!(
            matches!(session.connect().await, Err(SessionFailure::Fatal(_))),
            "H0 must fail closed instead of opening a socket"
        );
        assert!(matches!(
            session.next_frame().await,
            Err(SessionFailure::Fatal(_))
        ));
        assert!(session.send_keepalive().await.is_ok());
        assert!(session.request_snapshot(&[]).await.is_ok());
        session.close().await;
    }
}
