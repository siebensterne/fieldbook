//! Opt-in authenticated, read-only Kalshi production market-data integration test.
//!
//! Required environment:
//! - `RUN_LIVE_KALSHI_TESTS=1`
//! - `LIVE_RIGHTS_FILE` naming a contract-derived authorization file for this
//!   venue and operation. An environment attestation cannot grant a right.
//! - `KALSHI_API_KEY_ID`
//! - `KALSHI_PRIVATE_KEY_PATH` or `KALSHI_PRIVATE_KEY_PEM`
//!
//! Run with:
//! `RUN_LIVE_KALSHI_TESTS=1 LIVE_RIGHTS_FILE=/path/to/rights.toml \
//!  cargo test --test live_kalshi --locked -- --ignored --nocapture`

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
    config::{ExchangeKind, KalshiSettings, Settings},
    exchange::{Exchange, KalshiExchange},
    model::{ExchangeEvent, SourceId},
    rights::{Operation, authorize_command},
};
use tokio::time::{Instant, timeout, timeout_at};

static NETWORK: OnceLock<fieldbook::config::NetworkSettings> = OnceLock::new();

/// Install one venue-scoped authorization for this test process. The rights
/// file is configuration, never a self-attested environment flag.
fn network() -> &'static fieldbook::config::NetworkSettings {
    NETWORK.get_or_init(|| {
        let path = std::env::var("LIVE_RIGHTS_FILE")
            .expect("LIVE_RIGHTS_FILE must name a contract-derived rights TOML file");
        let mut settings = Settings::for_exchange(ExchangeKind::Kalshi);
        settings.governance.rights_file = Some(PathBuf::from(path));
        authorize_command(&settings, Operation::Collect)
            .expect("rights must authorize this venue and operation");
        settings.network
    })
}

#[tokio::test]
#[ignore = "requires authorized Kalshi read-only market-data access and production API credentials"]
async fn discovers_and_receives_live_production_orderbook_snapshots() {
    assert_eq!(
        std::env::var("RUN_LIVE_KALSHI_TESTS").as_deref(),
        Ok("1"),
        "set RUN_LIVE_KALSHI_TESTS=1 to opt in"
    );
    let mut settings = KalshiSettings {
        key_id: std::env::var("KALSHI_API_KEY_ID")
            .expect("KALSHI_API_KEY_ID must be set for the authenticated websocket handshake"),
        ..KalshiSettings::default()
    };
    if let Ok(path) = std::env::var("KALSHI_PRIVATE_KEY_PATH") {
        settings.private_key_path = Some(PathBuf::from(path));
    }
    // When no path is set, KalshiAuth reads KALSHI_PRIVATE_KEY_PEM directly.
    assert!(
        settings.private_key_path.is_some() || std::env::var_os("KALSHI_PRIVATE_KEY_PEM").is_some(),
        "set KALSHI_PRIVATE_KEY_PATH or KALSHI_PRIVATE_KEY_PEM"
    );

    let exchange = Arc::new(
        KalshiExchange::new(settings, network().clone(), true)
            .expect("constructing authenticated Kalshi production adapter"),
    );
    assert_eq!(exchange.environment(), "production");

    let markets = timeout(Duration::from_secs(45), exchange.discover_markets(5))
        .await
        .expect("Kalshi production market discovery timed out")
        .expect("Kalshi production market discovery failed");
    assert!(
        !markets.is_empty(),
        "Kalshi returned no eligible open markets"
    );
    assert!(markets.iter().all(|market| {
        market.exchange == "kalshi" && !market.native_symbol.is_empty() && !market.symbol.is_empty()
    }));

    let desired: BTreeSet<String> = markets
        .iter()
        .take(3)
        .map(|market| market.native_symbol.clone())
        .collect();
    assert!(!desired.is_empty());

    let factory = Arc::clone(&exchange).session_factory();
    let mut session = factory
        .create_session(SourceId::new(0, 0))
        .await
        .expect("creating Kalshi production session");
    timeout(Duration::from_secs(30), session.connect())
        .await
        .expect("Kalshi authenticated websocket handshake timed out")
        .expect("Kalshi authenticated websocket handshake failed");
    timeout(
        Duration::from_secs(15),
        session.apply_subscriptions(&desired),
    )
    .await
    .expect("Kalshi subscription command timed out")
    .expect("Kalshi subscription command failed");

    let deadline = Instant::now() + Duration::from_secs(75);
    let mut snapshots = 0u64;
    let mut level_changes = 0u64;
    let mut observed_symbols = BTreeSet::new();
    let mut anchored_symbols = BTreeSet::new();
    let mut first_snapshot_at = None;

    while Instant::now() < deadline {
        let frame = match timeout_at(deadline, session.next_frame()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(error)) => panic!("Kalshi websocket frame failed: {error:?}"),
            Err(_) => break,
        };
        for event in frame.events {
            match event {
                ExchangeEvent::Snapshot { native_symbol, .. }
                    if desired.contains(&native_symbol) =>
                {
                    snapshots = snapshots.saturating_add(1);
                    anchored_symbols.insert(native_symbol.clone());
                    observed_symbols.insert(native_symbol);
                    first_snapshot_at.get_or_insert_with(Instant::now);
                }
                ExchangeEvent::LevelChange { native_symbol, .. }
                    if desired.contains(&native_symbol) =>
                {
                    level_changes = level_changes.saturating_add(1);
                    observed_symbols.insert(native_symbol);
                }
                _ => {}
            }
        }
        // Once every selected market is anchored, keep the socket open briefly
        // to observe any subsequent deltas without making a quiet market fail
        // solely because no trade occurred. If any selected market is still
        // unanchored, continue until the deadline so the failure names it.
        let observed_quiet_period =
            first_snapshot_at.is_some_and(|started| started.elapsed() >= Duration::from_secs(15));
        if anchored_symbols.len() == desired.len() && observed_quiet_period {
            break;
        }
    }

    session.close().await;
    let missing: Vec<_> = desired.difference(&anchored_symbols).cloned().collect();
    eprintln!(
        "KALSHI_LIVE_EVIDENCE exchange=kalshi environment=production \
         discovered_markets={} subscribed_markets={} anchored_symbols={}/{} \
         observed_symbols={} snapshots={} level_changes={} missing={missing:?}",
        markets.len(),
        desired.len(),
        anchored_symbols.len(),
        desired.len(),
        observed_symbols.len(),
        snapshots,
        level_changes
    );
    assert!(
        anchored_symbols.len() == desired.len(),
        "every selected Kalshi market must receive its own order-book snapshot; \
         missing anchors: {missing:?}"
    );
}
