//! Opt-in public Polymarket integration test.
//!
//! This is ignored by default so offline CI never depends on a
//! third-party network. A runtime authorization file is required; an
//! environment attestation cannot grant a right. Run it with:
//! `RUN_LIVE_TESTS=1 LIVE_RIGHTS_FILE=/path/to/rights.toml \
//!  cargo test --test live_polymarket -- --ignored --nocapture`

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "integration tests drive failure paths with unwrap/expect/panic and print diagnostics"
)]
#![allow(
    clippy::allow_attributes,
    reason = "test crates relax the production lint set wholesale; `expect` cannot express lints that may not fire"
)]

use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::Duration,
};

use fieldbook::{
    config::{ExchangeKind, NetworkSettings, PolymarketSettings, Settings},
    exchange::{Exchange, PolymarketExchange},
    model::{ExchangeEvent, SourceId},
    rights::{Operation, authorize_operations},
};
use tokio::time::{Instant, timeout, timeout_at};

static NETWORK: OnceLock<NetworkSettings> = OnceLock::new();

/// Install one venue-scoped authorization for this test process. The rights
/// file is configuration, never a self-attested environment flag.
fn network() -> &'static NetworkSettings {
    NETWORK.get_or_init(|| {
        let path = std::env::var("LIVE_RIGHTS_FILE")
            .expect("LIVE_RIGHTS_FILE must name a contract-derived rights TOML file");
        let mut settings = Settings::for_exchange(ExchangeKind::Polymarket);
        settings.governance.rights_file = Some(PathBuf::from(path));
        settings.governance.audit_dir = Some(
            std::env::var("LIVE_AUDIT_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("target/live-audit")),
        );
        authorize_operations(&settings, &[Operation::RealTimeCapture])
            .expect("rights must authorize this venue and operation");
        settings.network
    })
}

#[tokio::test]
#[ignore = "requires RUN_LIVE_TESTS=1 and public network access"]
async fn discovers_and_subscribes_to_public_polymarket_books() {
    assert_eq!(
        std::env::var("RUN_LIVE_TESTS").as_deref(),
        Ok("1"),
        "set RUN_LIVE_TESTS=1 to run the public-feed integration test"
    );

    let exchange = Arc::new(
        PolymarketExchange::new(PolymarketSettings::default(), network().clone()).unwrap(),
    );
    let markets = timeout(Duration::from_secs(30), exchange.discover_markets(5))
        .await
        .expect("discovery timed out")
        .expect("discovery failed");
    assert!(!markets.is_empty(), "no public markets discovered");
    assert!(
        markets
            .iter()
            .all(|market| !market.native_symbol.is_empty() && !market.symbol.is_empty())
    );

    let factory = Arc::clone(&exchange).session_factory();
    let mut session = factory
        .create_session(SourceId::new(0, 0))
        .await
        .expect("creating session");
    session.connect().await.expect("connecting websocket");
    let desired: BTreeSet<String> = markets
        .iter()
        .take(3)
        .map(|market| market.native_symbol.clone())
        .collect();
    session
        .apply_subscriptions(&desired)
        .await
        .expect("subscribing");

    let mut anchored: BTreeSet<String> = BTreeSet::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline && anchored.len() < desired.len() {
        let frame = match timeout_at(deadline, session.next_frame()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(error)) => panic!("public websocket frame failed: {error:?}"),
            Err(_) => break,
        };
        for event in frame.events {
            if let ExchangeEvent::Snapshot { native_symbol, .. } = event
                && desired.contains(&native_symbol)
            {
                anchored.insert(native_symbol);
            }
        }
    }
    session.close().await;
    let missing: Vec<_> = desired.difference(&anchored).cloned().collect();
    assert!(
        anchored.len() == desired.len(),
        "every selected Polymarket asset must receive its own snapshot; missing: {missing:?}"
    );
}

#[tokio::test]
#[ignore = "requires RUN_LIVE_TESTS=1 and public network access"]
async fn resubscribing_an_asset_returns_a_fresh_book() {
    assert_eq!(
        std::env::var("RUN_LIVE_TESTS").as_deref(),
        Ok("1"),
        "set RUN_LIVE_TESTS=1 to run the public-feed integration test"
    );

    let exchange = Arc::new(
        PolymarketExchange::new(PolymarketSettings::default(), network().clone()).unwrap(),
    );
    let markets = timeout(Duration::from_secs(30), exchange.discover_markets(5))
        .await
        .expect("discovery timed out")
        .expect("discovery failed");
    assert!(!markets.is_empty(), "no public markets discovered");

    let factory = Arc::clone(&exchange).session_factory();
    let mut session = factory
        .create_session(SourceId::new(0, 0))
        .await
        .expect("creating session");
    session.connect().await.expect("connecting websocket");
    let asset = markets[0].native_symbol.clone();
    let desired: BTreeSet<String> = markets
        .iter()
        .take(2)
        .map(|market| market.native_symbol.clone())
        .collect();
    session
        .apply_subscriptions(&desired)
        .await
        .expect("subscribing");

    let mut saw_initial = false;
    for _ in 0..20 {
        let frame = timeout(Duration::from_secs(10), session.next_frame())
            .await
            .expect("timed out waiting for the initial book")
            .expect("reading public frame");
        if frame.events.iter().any(|event| {
            matches!(
                event,
                ExchangeEvent::Snapshot { native_symbol, .. } if *native_symbol == asset
            )
        }) {
            saw_initial = true;
            break;
        }
    }
    assert!(saw_initial, "no initial book for {asset}");

    // A stale probe cycles the subscription; the venue must answer with a
    // fresh authoritative book on the same connection.
    session
        .request_snapshot(std::slice::from_ref(&asset))
        .await
        .expect("requesting a fresh snapshot");

    let mut saw_repair = false;
    for _ in 0..20 {
        let frame = timeout(Duration::from_secs(10), session.next_frame())
            .await
            .expect("timed out waiting for the fresh book")
            .expect("reading public frame");
        if frame.events.iter().any(|event| {
            matches!(
                event,
                ExchangeEvent::Snapshot { native_symbol, .. } if *native_symbol == asset
            )
        }) {
            saw_repair = true;
            break;
        }
    }
    session.close().await;
    assert!(
        saw_repair,
        "resubscribing {asset} did not produce a fresh book"
    );
}
