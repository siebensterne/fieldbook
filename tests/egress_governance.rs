// SPDX-License-Identifier: Apache-2.0
//! Offline governance checks for provider egress.
//!
//! Every test here uses scalar identifiers and a reserved `.invalid` host. A
//! passing test proves the operation was refused before DNS, TCP, or TLS; no
//! provider is contacted and no market observation is created.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "offline governance tests use the same assertion style as other test crates"
)]
#![allow(
    clippy::allow_attributes,
    reason = "test crates relax the production lint set wholesale; `expect` cannot express lints that may not fire"
)]

use std::time::Duration;

use clap::CommandFactory as _;
use clap::Parser as _;

use fieldbook::{
    config::{CoinbaseSettings, ExchangeKind, KrakenSettings, NetworkSettings, Settings},
    distribution::cli::Cli,
    egress::http_client,
    egress_intent::EgressIntent,
    exchange::{CoinbaseExchange, KrakenExchange},
    rights::{
        DeliveryMethod, Licensee, Operation, Purpose, Recipient, Retention, ScopeSet, TimeWindow,
        UsageMode, UsageRight, authorize_operations, has_active_authorization,
        require_provider_egress,
    },
    taxonomy::CountryCode,
    ws::{self, ConnectOptions},
};

fn rights_toml(venue: &str, decision: &str, valid_until: i64) -> String {
    format!(
        "schema_version = 1\n\
         licensee = \"licensee-a\"\n\
         territory = \"US\"\n\
         recipient = \"internal\"\n\
         \n\
         [[rights]]\n\
         decision = \"{decision}\"\n\
         \n\
         [rights.identity]\n\
         licensee = \"licensee-a\"\n\
         venue = \"{venue}\"\n\
         provider_id = \"kalshi\"\n\
         source_id = \"provider-source\"\n\
         dataset_id = \"market-data\"\n\
         product_id = \"market-data-feed\"\n\
         segment = \"venue-equity-cash\"\n\
         territory = \"US\"\n\
         operation = \"real_time_capture\"\n\
         usage_right = \"real_time_access\"\n\
         usage_mode = \"non_display\"\n\
         recipient = \"internal\"\n\
         purpose = \"internal_analysis\"\n\
         delivery_method = \"stream\"\n\
         instruments = {{ universe = \"governance-universe-1\" }}\n\
         fields = {{ universe = \"governance-universe-1\" }}\n\
         modalities = {{ universe = \"governance-universe-1\" }}\n\
         valid_from = 0\n\
         valid_until = {valid_until}\n\
         \n\
         [rights.identity.retention]\n\
         limit = {{ bounded = 86400 }}\n\
         purge_required = true\n\
         \n\
         [rights.identity.data_time_window]\n\
         \n\
         [rights.audit]\n\
         licence_reference = \"contract-1\"\n\
         licence_document_hash = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n\
         contract_revision = 1\n\
         recorded_at_us = 0\n\
         authority = \"contract-registry\"\n"
    )
}

/// Explicit caller-supplied request matching the abstract rights fixture.
fn egress_intent(venue: &str, operation: Operation) -> EgressIntent {
    let universe = ScopeSet::Universe("governance-universe-1".to_owned());
    EgressIntent::builder()
        .provider_id("kalshi")
        .source_id("provider-source")
        .source_product_id("market-data-feed")
        .venue_id(venue)
        .segment_id("venue-equity-cash")
        .dataset_id("market-data")
        .operation(operation)
        .purpose(Purpose::InternalAnalysis)
        .usage_mode(UsageMode::NonDisplay)
        .usage_right(UsageRight::RealTimeAccess)
        .licensee(Licensee::new("licensee-a").expect("licensee"))
        .recipient(Recipient::Internal)
        .territory(CountryCode::new("US").expect("country"))
        .instruments(universe.clone())
        .fields(universe.clone())
        .modalities(ScopeSet::Universe("governance-universe-1".to_owned()))
        .data_time_window(TimeWindow::default())
        .retention_request(Retention::bounded(86_400))
        .delivery_method(DeliveryMethod::Stream)
        .endpoint("wss://venue-a.example:443")
        .expect("endpoint")
        .build()
        .expect("explicit egress intent")
}

fn settings_with_rights(text: &str) -> (tempfile::TempDir, Settings) {
    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("rights.toml");
    std::fs::write(&path, text).expect("write rights file");
    let mut settings = Settings::for_exchange(ExchangeKind::Kalshi);
    settings.governance.rights_file = Some(path);
    settings.governance.audit_dir = Some(directory.path().join("audit"));
    (directory, settings)
}

#[test]
fn no_subcommand_is_not_a_live_recipe() {
    assert!(
        Cli::try_parse_from(["fieldbook"]).is_err(),
        "the binary must refuse to guess a provider-facing command"
    );
    let help = Cli::command().render_long_help().to_string();
    assert!(
        help.contains("explicit subcommand"),
        "help must state that a command is required: {help}"
    );
}

#[test]
fn collect_without_rights_file_denies_before_egress() {
    assert!(
        !has_active_authorization(),
        "the test process starts ungated"
    );
    let mut settings = Settings::for_exchange(ExchangeKind::Kalshi);
    settings.governance.rights_file = None;
    let error = authorize_operations(&settings, &[Operation::RealTimeCapture])
        .expect_err("collection without a rights file must deny");
    assert!(
        error.to_string().contains("runtime authorization file"),
        "the denial names the missing rights file: {error}"
    );
    assert!(
        !has_active_authorization(),
        "a denied command installs no authorization"
    );
    assert!(
        require_provider_egress(&egress_intent("kalshi", Operation::ReferenceDataRetrieval))
            .is_err(),
        "no proof means no HTTP client"
    );
    assert!(
        http_client(
            "governance-test/1",
            Duration::from_secs(1),
            &settings.network,
            None,
        )
        .is_err(),
        "no HTTP client may be built without authorization"
    );
}

#[test]
fn expired_and_unknown_rights_deny_every_gated_command() {
    let (_expired_dir, expired) = settings_with_rights(&rights_toml("kalshi", "permitted", 1));
    assert!(
        authorize_operations(&expired, &[Operation::RealTimeCapture]).is_err(),
        "an expired right denies collection"
    );
    assert!(
        authorize_operations(&expired, &[Operation::ReferenceDataRetrieval]).is_err(),
        "an expired right denies discovery"
    );
    let (_unknown_dir, unknown) =
        settings_with_rights(&rights_toml("kalshi", "contract_required", i64::MAX));
    assert!(
        authorize_operations(&unknown, &[Operation::SourceContact]).is_err(),
        "an UNKNOWN right denies a network probe"
    );
    assert!(
        !has_active_authorization(),
        "a denied command installs no authorization"
    );
}

#[test]
fn right_without_a_venue_is_refused_at_load() {
    let (_directory, settings) = settings_with_rights(&rights_toml("", "permitted", i64::MAX));
    assert!(
        authorize_operations(&settings, &[Operation::RealTimeCapture]).is_err(),
        "a record without a venue is never a grant"
    );
    assert!(
        !has_active_authorization(),
        "a denied command installs no authorization"
    );
}

#[tokio::test]
async fn websocket_connect_denies_before_resolution_without_a_right() {
    assert!(
        !has_active_authorization(),
        "a denied command installs no authorization"
    );
    let options = ConnectOptions {
        venue: "venue-a".to_owned(),
        connect_timeout: Duration::from_millis(100),
        intent: Some(
            egress_intent("venue-a", Operation::RealTimeCapture)
                .for_endpoint("ws://venue-a.invalid:443")
                .expect("target endpoint"),
        ),
        ..ConnectOptions::default()
    };
    let error = ws::connect("ws://venue-a.invalid:443", &[], &options)
        .await
        .expect_err("the gate must deny before any socket is opened");
    let text = error.to_string();
    assert!(
        text.contains("authorization"),
        "failure must be an authorization denial: {text}"
    );
    assert!(
        !text.contains("resolving") && !text.contains("timed out"),
        "DNS or a transport timeout means the gate was bypassed: {text}"
    );
}

#[tokio::test]
async fn loopback_test_identity_cannot_reach_a_provider_host() {
    let options = ConnectOptions::default();
    let error = ws::connect("ws://venue-a.invalid:443", &[], &options)
        .await
        .expect_err("the loopback test identity must stay on loopback");
    assert!(
        error.to_string().contains("loopback authorization"),
        "unexpected error: {error}"
    );
}

#[test]
fn analytics_export_denial_publishes_nothing() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let staging = directory.path().join("staging");
    std::fs::create_dir(&staging).expect("create staging directory");
    let mut settings = Settings::for_exchange(ExchangeKind::Kalshi);
    settings.governance.rights_file = None;
    assert!(
        authorize_operations(&settings, &[Operation::DerivedDataCreation]).is_err(),
        "derived-data publication requires a right"
    );
    let published: Vec<_> = std::fs::read_dir(&staging)
        .expect("read staging directory")
        .collect();
    assert!(published.is_empty(), "a denial publishes no files");
}

#[test]
fn coinbase_and_kraken_adapter_clients_deny_without_rights() {
    assert!(
        !has_active_authorization(),
        "the test process starts ungated"
    );
    let coinbase_network = Settings::for_exchange(ExchangeKind::Coinbase).network;
    assert_eq!(
        coinbase_network.venue, "coinbase",
        "adapter transport carries the Coinbase venue"
    );
    assert!(
        CoinbaseExchange::new(CoinbaseSettings::default(), coinbase_network).is_err(),
        "Coinbase client construction is gated"
    );
    let kraken_network = Settings::for_exchange(ExchangeKind::Kraken).network;
    assert_eq!(
        kraken_network.venue, "kraken",
        "adapter transport carries the Kraken venue"
    );
    assert!(
        KrakenExchange::new(KrakenSettings::default(), kraken_network).is_err(),
        "Kraken client construction is gated"
    );
}

#[test]
fn unconfigured_transport_default_is_not_a_provider_venue() {
    let network = NetworkSettings::default();
    assert_eq!(
        network.venue, "loopback",
        "a standalone transport is loopback-only"
    );
    assert!(
        http_client("governance-test/1", Duration::from_secs(1), &network, None).is_ok(),
        "a standalone loopback transport may build a client without rights"
    );
    let live = Settings::for_exchange(ExchangeKind::Kalshi).network;
    assert_eq!(
        live.venue, "kalshi",
        "settings derive the venue from the exchange"
    );
    assert!(
        http_client("governance-test/1", Duration::from_secs(1), &live, None).is_err(),
        "a venue transport needs a right even to build a client"
    );
}
