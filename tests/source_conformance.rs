// SPDX-License-Identifier: Apache-2.0
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

//! Deterministic, fixture-only source conformance checks.
//!
//! These tests use no network, no live venue and no historical capture
//! evidence. They verify that a source declaration is tested against actual
//! connector output and rights evidence before it can be certified.

use std::collections::BTreeMap;

use fieldbook::acquisition::codec::{
    CodecRegistry,      //
    DecodeStatus,       //
    DecodedObservation, //
    FeedCodec,          //
};
use fieldbook::adapter::{
    AccessStatus, HistoricalCapability, Protocol, RecoveryCapability, SourceCapabilityManifest,
    TimestampCapability, Transport,
};
use fieldbook::conformance::{
    ConformanceDeclaration, ConformanceFixture, ExpectedObservation, run_conformance,
};
use fieldbook::coverage_certification::ExpectedUniverse;
use fieldbook::modality::{
    AcquisitionModality, //
    SnapshotCapability,  //
    StreamingCapability, //
};
use fieldbook::reference_data::VenueCategory;
use fieldbook::rights::{
    LicensingRecord,   //
    LicensingRegistry, //
    RightDecision,     //
    UsageRight,        //
};
use fieldbook::taxonomy::{
    AssetClass,   //
    CountryCode,  //
    DataCategory, //
    DepthModel,   //
    Frequency,    //
};

struct TradeCodec {
    status: DecodeStatus,
}

impl FeedCodec for TradeCodec {
    fn decode(&self, payload: &[u8]) -> anyhow::Result<Vec<DecodedObservation>> {
        Ok(vec![DecodedObservation {
            packet_id: String::new(),
            source: String::new(),
            schema_version: 0,
            kind: "trade".to_owned(),
            payload_json: String::from_utf8(payload.to_vec())?,
            status: self.status,
            reason: None,
        }])
    }

    fn schema_version(&self) -> u32 {
        1
    }
}

fn declaration() -> ConformanceDeclaration {
    ConformanceDeclaration {
        source_id: "fixture-source".to_owned(),
        dataset: "trades".to_owned(),
        manifest: SourceCapabilityManifest {
            source_id: "fixture-source".to_owned(),
            provider: "fixture-provider".to_owned(),
            venue_mic: Some("XFIX".to_owned()),
            country: CountryCode::new("US").expect("country code"),
            venue_category: VenueCategory::Exchange,
            asset_classes: vec![AssetClass::Equity],
            data_categories: vec![DataCategory::Trades],
            protocols: vec![Protocol::WebSocket, Protocol::Rest],
            transports: vec![Transport::WebSocket, Transport::Http],
            book_model: DepthModel::Level2,
            timestamps: TimestampCapability {
                exchange_event_time: false,
                exchange_publication_time: false,
                packet_capture_time: true,
                sequence_numbers: false,
                clock_source: "host_clock".to_owned(),
            },
            recovery: RecoveryCapability {
                snapshot: false,
                incremental_recovery: false,
                packet_sequence: false,
                exchange_sequence: false,
                gap_request: false,
            },
            historical: HistoricalCapability {
                available: false,
                earliest_us: None,
                frequency: Frequency::RealTime,
            },
            access: AccessStatus::Public,
            schema_version: 1,
            modalities: vec![
                AcquisitionModality::Streaming,
                AcquisitionModality::Snapshot,
            ],
            streaming: Some(StreamingCapability {
                continuous: true,
                sequence_numbers: false,
                recovery: RecoveryCapability {
                    snapshot: false,
                    incremental_recovery: false,
                    packet_sequence: false,
                    exchange_sequence: false,
                    gap_request: false,
                },
            }),
            snapshot: Some(SnapshotCapability {
                keyed_lookup: true,
                pagination: false,
                as_of: false,
            }),
            batch: None,
            document: None,
            on_chain: None,
        },
        expected_universe: Some(ExpectedUniverse::Unmeasurable {
            reason: "opaque OTC market".to_owned(),
        }),
        declared_kinds: vec!["trade".to_owned()],
        rights_required: vec![UsageRight::InternalProcessing],
    }
}

fn fixture() -> ConformanceFixture {
    ConformanceFixture {
        name: "deterministic-trade".to_owned(),
        packet_id: "packet-1".to_owned(),
        schema_version: 1,
        raw_payload: b"{\"trade_id\":\"t-1\",\"price_mantissa\":10,\"quantity_mantissa\":2}"
            .to_vec(),
        expected: vec![ExpectedObservation {
            kind: "trade".to_owned(),
            payload_json: "{\"trade_id\":\"t-1\",\"price_mantissa\":10,\"quantity_mantissa\":2}"
                .to_owned(),
            status: DecodeStatus::Decoded,
        }],
    }
}

fn codecs(status: DecodeStatus) -> CodecRegistry {
    let mut registry = CodecRegistry::new();
    registry
        .register("fixture-source", Box::new(TradeCodec { status }))
        .expect("register fixture codec");
    registry
}

fn licensing() -> LicensingRegistry {
    let mut registry = LicensingRegistry::new();
    registry.register(LicensingRecord {
        provider: "fixture-provider".to_owned(),
        dataset: "trades".to_owned(),
        territory: CountryCode::new("US").expect("country code"),
        rights: BTreeMap::from([(UsageRight::InternalProcessing, RightDecision::Permitted)]),
        valid_until_us: Some(200),
        audit_required: false,
        reference: "fixture-contract".to_owned(),
    });
    registry
}

#[test]
fn fixture_declared_source_is_certified() {
    let report = run_conformance(
        &declaration(),
        &fixture(),
        &codecs(DecodeStatus::Decoded),
        &licensing(),
        100,
    );
    assert!(report.passed(), "all checks must pass: {report:?}");
    assert!(report.certified, "fixture-backed source is certified");
    assert_eq!(
        report.checks.len(),
        7,
        "seven independent checks must be reported"
    );
    assert!(
        report.to_json().is_ok(),
        "report serializes for evidence manifests"
    );
}

#[test]
fn denied_right_blocks_certification() {
    let report = run_conformance(
        &declaration(),
        &fixture(),
        &codecs(DecodeStatus::Decoded),
        &LicensingRegistry::new(),
        100,
    );
    assert!(!report.certified, "rights must gate certification");
    let right_failure = report
        .failures()
        .find(|check| check.name == "rights_gate")
        .expect("rights check failed");
    assert!(
        right_failure.detail.contains("denied rights"),
        "failure reason is explicit"
    );
}

#[test]
fn undeclared_modality_capability_blocks_certification() {
    let mut source = declaration();
    source.manifest.snapshot = None;
    let report = run_conformance(
        &source,
        &fixture(),
        &codecs(DecodeStatus::Decoded),
        &licensing(),
        100,
    );
    assert!(!report.certified, "undeclared capability must fail closed");
    assert!(
        report.failures().any(|check| check.name == "declaration"),
        "declaration check reports the missing capability"
    );
}

#[test]
fn fixture_mismatch_blocks_certification() {
    let report = run_conformance(
        &declaration(),
        &fixture(),
        &codecs(DecodeStatus::Rejected),
        &licensing(),
        100,
    );
    assert!(!report.certified, "connector output must match the fixture");
    assert!(
        report
            .failures()
            .any(|check| check.name == "fixture_decode_matches"),
        "mismatch is reported"
    );
}

#[test]
fn universe_must_be_disclosed() {
    let mut source = declaration();
    source.expected_universe = None;
    let report = run_conformance(
        &source,
        &fixture(),
        &codecs(DecodeStatus::Decoded),
        &licensing(),
        100,
    );
    assert!(!report.certified, "missing universe disclosure must fail");
    let universe = report
        .failures()
        .find(|check| check.name == "universe_disclosed")
        .expect("universe check failed");
    assert_eq!(
        universe.detail, "no universe declaration",
        "missing denominator is explicit"
    );
}

#[test]
fn opaque_market_declares_no_denominator() {
    let report = run_conformance(
        &declaration(),
        &fixture(),
        &codecs(DecodeStatus::Decoded),
        &licensing(),
        100,
    );
    let universe = report
        .checks
        .iter()
        .find(|check| check.name == "universe_disclosed")
        .expect("universe check reported");
    assert!(universe.passed, "declared unmeasurability is acceptable");
    assert!(
        universe.detail.contains("no denominator claimed"),
        "the report states that no denominator is claimed"
    );
}
