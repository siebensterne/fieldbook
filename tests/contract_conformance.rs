// SPDX-License-Identifier: Apache-2.0
//! Golden v1 source-event conformance fixtures.
//!
//! Every fixture in `tests/contract_fixtures/` is loaded, digest-checked
//! against the manifest and replayed through the real typed validator plus
//! sequence ledger. Each `expect` entry must match exactly: acceptance or the
//! exact normative rejection code from the v1 contract. This is conformance
//! evidence only: no fixture admits data, grants rights, contacts a provider
//! or enables live execution.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use fieldbook::governance::source_event::SessionSequences;
use fieldbook::governance::source_event::SourceEventEnvelope;
use fieldbook::util::sha256_hex;
use serde::Deserialize;

/// One expectation: exactly one of `accepted` or `rejected_code` is present.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Expectation {
    #[serde(default)]
    accepted: Option<bool>,
    #[serde(default)]
    rejected_code: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    id: String,
    path: String,
    sha256: String,
    expectations: Vec<Expectation>,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    files: Vec<ManifestFile>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    id: String,
    mode: String,
    #[serde(default)]
    events: Vec<serde_json::Value>,
    #[serde(default)]
    raw_events: Vec<String>,
    expect: Vec<Expectation>,
}

#[test]
fn every_golden_v1_fixture_conforms() {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/contract_fixtures");
    let manifest_bytes = fs::read(fixtures_dir.join("manifest.json"))
        .expect("the canonical fixture manifest is readable");
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).expect("the manifest is valid JSON");
    assert_eq!(
        manifest.files.len(),
        14,
        "the canonical fixture set contains 14 files"
    );

    let mut seen = BTreeSet::new();
    for file in manifest.files {
        let duplicate_message = format!("fixture id {} appears twice", file.id);
        assert!(seen.insert(file.id.clone()), "{duplicate_message}");
        let file_name = Path::new(&file.path)
            .file_name()
            .expect("each manifest path names a fixture file");
        let bytes = fs::read(fixtures_dir.join(file_name))
            .expect("each manifest-listed fixture file is present");
        let digest_message = format!("{} bytes match the manifest", file.id);
        assert_eq!(sha256_hex(&bytes), file.sha256, "{digest_message}");
        let fixture: Fixture = serde_json::from_slice(&bytes).expect("each fixture is valid JSON");
        assert_eq!(fixture.id, file.id, "fixture and manifest ids agree");
        assert_eq!(
            fixture.expect, file.expectations,
            "fixture and manifest expectations agree"
        );
        let mode_message = format!("{} declares a supported mode", fixture.id);
        assert!(
            fixture.mode == "events" || fixture.mode == "raw",
            "{mode_message}"
        );

        let inputs: Vec<String> = if fixture.mode == "events" {
            fixture
                .events
                .iter()
                .map(|event| serde_json::to_string(event).expect("an event object is serializable"))
                .collect()
        } else {
            fixture.raw_events.clone()
        };
        let count_message = format!("{} has one expectation per event", fixture.id);
        assert_eq!(inputs.len(), fixture.expect.len(), "{count_message}");

        // Ledgers are scoped to (source_id, session_ref) and shared across the
        // ordered event list of one fixture; they start empty per fixture.
        let mut ledger = SessionSequences::new();
        for (index, (input, expectation)) in inputs.iter().zip(&fixture.expect).enumerate() {
            let outcome =
                SourceEventEnvelope::from_json(input).and_then(|event| ledger.admit(&event));
            match (expectation.accepted, expectation.rejected_code.as_deref()) {
                (Some(true), None) => {
                    let accept_message = format!(
                        "{} event {} must be accepted: {:?}",
                        fixture.id, index, outcome
                    );
                    assert!(outcome.is_ok(), "{accept_message}");
                }
                (None, Some(code)) => {
                    let error = outcome.expect_err("a rejected fixture event must be rejected");
                    let code_message = format!(
                        "{} event {} has the exact normative code",
                        fixture.id, index
                    );
                    assert_eq!(error.reason_code(), code, "{code_message}");
                }
                _ => panic!("{} event {} has an invalid expectation", fixture.id, index),
            }
        }
    }
    assert_eq!(seen.len(), 14, "every canonical fixture was exercised");
}
