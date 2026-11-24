// SPDX-License-Identifier: Apache-2.0
//! Conformance producer for the ratified canonical NDC v2 Profile 1 wire
//! schema. This executable consumes an abstract, non-market JSON spec and
//! writes a complete release: `manifest.json`, `signature.json` and `artifacts/`.
//
//! It exercises the production builder, not a separate wire writer. The same
//! `ndc_release::build_release` boundary validates, signs and publishes every
//! release in this repository; the only conformance-specific inputs are the
//! abstract spec, a test-only key seed and an isolated ledger directory.
//!
//! The fixed test-only Ed25519 seed is bound to
//! [`CONFORMANCE_SIGNING_SEED`]. The seed is a published conformance vector,
//! not a production key. No key material is written into the release package.
//! No provider contact, collection, right, dataset acceptance or live route is
//! involved; a successful run proves only that the production builder mapped
//! the abstract spec to the canonical wire shape.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use ed25519_dalek::SigningKey;

use fieldbook::distribution::ndc_release;
use fieldbook::distribution::ndc_release::BuildRequest;
use fieldbook::distribution::ndc_release::LineageContext;
use fieldbook::distribution::ndc_release::PublicationReceipt;
use fieldbook::distribution::ndc_release::PublicationState;
use fieldbook::distribution::ndc_release::ResourcePolicy;
use fieldbook::distribution::ndc_release::SignatureConfig;
use fieldbook::distribution::ndc_wire;
use fieldbook::distribution::ndc_wire::CONFORMANCE_SIGNING_SEED;
use fieldbook::distribution::ndc_wire::ConformanceSpec;
use fieldbook::distribution::ndc_wire::WireError;

/// Command-line surface of the conformance producer.
#[derive(Debug, Parser)]
#[command(name = "ndc-conformance-producer")]
#[command(about = "Write a canonical NDC v2 Profile 1 release from an abstract spec")]
struct Args {
    /// Path to the abstract non-market JSON spec.
    #[arg(long)]
    spec: PathBuf,
    /// Release root; the release is published under its declared release id.
    #[arg(long)]
    out: PathBuf,
}

/// Conformance-only resource bounds. These numbers bound the vector runner;
/// they are not adopted production maxima and the wire carries no `limits`.
fn conformance_policy() -> ResourcePolicy {
    ResourcePolicy {
        max_manifest_bytes: 1_000_000,
        max_artifact_count: 8,
        max_stored_bytes_per_artifact: 100_000,
        max_uncompressed_bytes_per_artifact: 100_000,
        max_total_stored_bytes: 1_000_000,
        max_total_uncompressed_bytes: 1_000_000,
        max_record_bytes: 4_096,
        max_records_per_artifact: 100,
        max_path_component_bytes: 128,
        max_nesting_depth: 32,
        max_object_members: 64,
        max_array_elements: 64,
        max_sidecar_bytes: 4_096,
        max_intent_bytes: 1_000_000,
    }
}

/// Build an out-of-band predecessor receipt for the declared correction.
///
/// The abstract spec names one immediate predecessor. The production builder
/// requires a matching caller-retained receipt before it admits a correction;
/// this function supplies that abstract receipt. It is not read from any
/// provider, dataset or market source.
fn predecessor_receipts(
    spec: &ConformanceSpec,
) -> (Option<PublicationReceipt>, Vec<PublicationReceipt>) {
    let Some(supersedes) = &spec.manifest.lineage.supersedes else {
        return (None, Vec::new());
    };
    let receipt = PublicationReceipt {
        schema_version: spec.manifest.schema_version,
        release_id: supersedes.supersedes_release_id.clone(),
        manifest_sha256: supersedes.supersedes_manifest_sha256.clone(),
        data_sha256: supersedes.supersedes_data_sha256.clone(),
        publication_operation_id: format!(
            "conformance-predecessor-{}",
            supersedes.supersedes_release_id
        ),
        commit_position: "conformance-predecessor-position".to_owned(),
        result: PublicationState::Available,
        supersedes_release_id: None,
    };
    (Some(receipt.clone()), vec![receipt])
}

/// Parse, convert, sign and publish one abstract spec through the production
/// core. Every refusal is typed.
fn run(args: Args) -> Result<(), WireError> {
    let text = fs::read_to_string(&args.spec)
        .map_err(|error| WireError::Io(format!("read {}", args.spec.display()), error))?;
    let spec = ndc_wire::parse_conformance_spec(&text)?;
    let policy = conformance_policy();
    let (artifacts, observed_event_types) = ndc_wire::spec_to_build_inputs(&spec, &policy)?;
    let signing = SigningKey::from_bytes(&CONFORMANCE_SIGNING_SEED);
    let verifying = signing.verifying_key();
    let (predecessor, known_receipts) = predecessor_receipts(&spec);
    let lineage = LineageContext {
        predecessor: predecessor.as_ref(),
        known_receipts: &known_receipts,
        now_ns: 10_000,
    };
    let signature = SignatureConfig {
        signing_key: &signing,
        verifying_key: &verifying,
        key_id: &spec.manifest.publication_identity.signing_key_id,
    };
    let ledger_dir = args.out.with_extension("ledger");
    fs::create_dir_all(&ledger_dir)
        .map_err(|error| WireError::Io(format!("create {}", ledger_dir.display()), error))?;
    let operation_id = format!(
        "conformance-{}-{}",
        spec.manifest.release_identity.release_id,
        std::process::id()
    );
    let commit_position = "conformance-position".to_owned();
    let request = BuildRequest {
        release_root: &args.out,
        ledger_dir: &ledger_dir,
        operation_id: &operation_id,
        commit_position: &commit_position,
        manifest: &spec.manifest,
        evidence: &spec.evidence,
        observed_event_types: &observed_event_types,
        artifacts: &artifacts,
        signature,
        policy: &policy,
        lineage,
    };
    ndc_release::build_release(&request)
        .map_err(|error| WireError::Spec(format!("production build failed: {error}")))?;
    Ok(())
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ndc-conformance-producer: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;
    use std::fs;
    use std::path::Path;
    use std::path::PathBuf;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use clap::Parser;
    use ed25519_dalek::SigningKey;
    use ed25519_dalek::Verifier as _;
    use fieldbook::distribution::ndc_release::JcsValue;
    use fieldbook::distribution::ndc_release::MANIFEST_FILE_NAME;
    use fieldbook::distribution::ndc_release::ResourcePolicy;
    use fieldbook::distribution::ndc_release::SIDECAR_FILE_NAME;
    use fieldbook::distribution::ndc_release::SIGNING_DOMAIN;
    use fieldbook::distribution::ndc_release::canonicalize_strict;
    use fieldbook::distribution::ndc_release::parse_jcs_value;
    use fieldbook::distribution::ndc_wire;
    use fieldbook::distribution::ndc_wire::CONFORMANCE_SIGNING_SEED;
    use fieldbook::distribution::ndc_wire::WIRE_SCHEMA_VERSION;
    use fieldbook::distribution::ndc_wire::WireError;
    use sha2::Digest as _;
    use sha2::Sha256;
    use tempfile::TempDir;

    use super::Args;
    use super::conformance_policy;
    use super::run;

    type TestResult = Result<(), Box<dyn StdError>>;

    const EXAMPLE_SPEC: &str = include_str!(
        "../../docs/specifications/ndc-conformance-producer-spec-example-2026-11-24.json"
    );
    const RELEASE_ID: &str = "conformance-release-2";
    const ARTIFACT_PATHS: [&str; 2] = [
        "artifacts/sequenced-abstract.jsonl",
        "artifacts/reference-abstract.jsonl.gz",
    ];

    fn spec_file(dir: &Path) -> Result<PathBuf, WireError> {
        let path = dir.join("spec.json");
        fs::write(&path, EXAMPLE_SPEC)
            .map_err(|error| WireError::Io("write example spec".to_owned(), error))?;
        Ok(path)
    }

    /// Run the executable-level boundary and return the spec, release root,
    /// final release directory and isolated ledger directory.
    fn run_release(temp: &TempDir) -> Result<(PathBuf, PathBuf, PathBuf, PathBuf), WireError> {
        let spec = spec_file(temp.path())?;
        let out = temp.path().join("release-root");
        let ledger = out.with_extension("ledger");
        run(Args {
            spec: spec.clone(),
            out: out.clone(),
        })?;
        Ok((spec, out.clone(), out.join(RELEASE_ID), ledger))
    }

    #[test]
    fn cli_requires_spec_and_out() {
        assert!(
            Args::try_parse_from(["ndc-conformance-producer"]).is_err(),
            "asserted condition: Args::try_parse_from([\"ndc-conformance-producer\"]).is_err()"
        );
        let parsed = Args::try_parse_from([
            "ndc-conformance-producer",
            "--spec",
            "abstract.json",
            "--out",
            "release",
        ])
        .expect("valid arguments");
        assert_eq!(
            parsed.spec,
            PathBuf::from("abstract.json"),
            "expected parsed.spec to equal PathBuf::from(\"abstract.json\")"
        );
        assert_eq!(
            parsed.out,
            PathBuf::from("release"),
            "expected parsed.out to equal PathBuf::from(\"release\")"
        );
    }

    #[test]
    fn executable_writes_complete_release_from_spec() -> TestResult {
        let temp = TempDir::new()?;
        let (_, _, release, _) = run_release(&temp)?;
        assert!(
            release.join(MANIFEST_FILE_NAME).is_file(),
            "asserted condition: release.join(MANIFEST_FILE_NAME).is_file()"
        );
        assert!(
            release.join(SIDECAR_FILE_NAME).is_file(),
            "asserted condition: release.join(SIDECAR_FILE_NAME).is_file()"
        );
        for name in ARTIFACT_PATHS {
            assert!(
                release.join(name).is_file(),
                "declared artifact {name} is present under artifacts/"
            );
        }
        Ok(())
    }

    #[test]
    fn final_directory_layout_is_exact() -> TestResult {
        let temp = TempDir::new()?;
        let (_, _, release, _) = run_release(&temp)?;
        let mut root_names = Vec::new();
        for entry in fs::read_dir(&release)? {
            root_names.push(entry?.file_name().to_string_lossy().into_owned());
        }
        root_names.sort();
        assert_eq!(
            root_names,
            vec!["artifacts", "manifest.json", "signature.json"],
            "release root has exactly the manifest, sidecar and artifacts directory"
        );
        let mut artifact_names = Vec::new();
        for entry in fs::read_dir(release.join("artifacts"))? {
            artifact_names.push(entry?.file_name().to_string_lossy().into_owned());
        }
        artifact_names.sort();
        assert_eq!(
            artifact_names,
            vec![
                "reference-abstract.jsonl.gz".to_owned(),
                "sequenced-abstract.jsonl".to_owned()
            ],
            "artifacts directory holds exactly the declared relative paths"
        );
        Ok(())
    }

    #[test]
    fn producer_goes_through_the_production_core() -> TestResult {
        let temp = TempDir::new()?;
        let (_, _, _, ledger) = run_release(&temp)?;
        let mut names = Vec::new();
        for entry in fs::read_dir(&ledger)? {
            names.push(entry?.file_name().to_string_lossy().into_owned());
        }
        assert!(
            names.iter().any(|name| name.ends_with(".receipt.json")),
            "production core wrote a durable receipt into the isolated ledger"
        );
        assert!(
            names.iter().any(|name| name.contains(".stage.")),
            "production core wrote publication stage evidence"
        );
        Ok(())
    }

    #[test]
    fn manifest_and_sidecar_have_ratified_shape() -> TestResult {
        let temp = TempDir::new()?;
        let (_, _, release, _) = run_release(&temp)?;
        let manifest_text = fs::read_to_string(release.join(MANIFEST_FILE_NAME))?;
        let manifest = parse_jcs_value(&manifest_text).expect("canonical manifest parses");
        let JcsValue::Object(entries) = &manifest else {
            return Err("manifest is not an object".into());
        };
        assert_eq!(entries.len(), 13, "expected entries.len() to equal 13");
        assert!(
            entries.iter().any(|(name, _)| name == "contract_version"),
            "asserted condition: entries.iter().any(|(name, _)| name == \"contract_version\")"
        );
        assert!(
            !entries.iter().any(|(name, _)| name == "limits"),
            "asserted condition: !entries.iter().any(|(name, _)| name == \"limits\")"
        );
        let sidecar_text = fs::read_to_string(release.join(SIDECAR_FILE_NAME))?;
        let sidecar =
            parse_jcs_value(sidecar_text.trim_end_matches('\n')).expect("canonical sidecar parses");
        let JcsValue::Object(fields) = &sidecar else {
            return Err("sidecar is not an object".into());
        };
        assert_eq!(fields.len(), 5, "expected fields.len() to equal 5");
        let names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "algorithm",
                "key_id",
                "manifest_sha256",
                "schema_version",
                "signature_b64"
            ],
            "expected names to equal vec![ \"algorithm\", \"key_id\", \"manifest_sha256\", \"schema_version\", \"signature_b64\" ]"
        );
        Ok(())
    }

    #[test]
    fn manifest_bytes_match_the_wire_mapping() -> TestResult {
        let temp = TempDir::new()?;
        let (spec_path, _, release, _) = run_release(&temp)?;
        let text = fs::read_to_string(&spec_path)?;
        let spec = ndc_wire::parse_conformance_spec(&text)?;
        let policy = conformance_policy();
        let signing = SigningKey::from_bytes(&CONFORMANCE_SIGNING_SEED);
        let verifying = signing.verifying_key();
        let (wire, _) = ndc_wire::build_conformance_release(&spec, &policy, &signing, &verifying)?;
        assert_eq!(
            fs::read(release.join(MANIFEST_FILE_NAME))?,
            wire.manifest_bytes,
            "production builder emits byte-identical canonical manifest"
        );
        assert_eq!(
            fs::read(release.join(SIDECAR_FILE_NAME))?,
            wire.signature_bytes,
            "production builder emits byte-identical sidecar"
        );
        Ok(())
    }

    #[test]
    fn sidecar_signature_and_digest_agree() -> TestResult {
        let temp = TempDir::new()?;
        let (_, _, release, _) = run_release(&temp)?;
        let manifest_bytes = fs::read(release.join(MANIFEST_FILE_NAME))?;
        let digest = Sha256::digest(&manifest_bytes);
        let digest_hex = fieldbook::distribution::ndc_release::hex_encode(&digest);
        let sidecar_text = fs::read_to_string(release.join(SIDECAR_FILE_NAME))?;
        let sidecar = parse_jcs_value(sidecar_text.trim_end_matches('\n'))?;
        let JcsValue::Object(fields) = sidecar else {
            return Err("sidecar is not an object".into());
        };
        let mut claimed_digest = "";
        let mut signature_b64 = "";
        for (name, value) in &fields {
            let JcsValue::String(text) = value else {
                continue;
            };
            match name.as_str() {
                "manifest_sha256" => claimed_digest = text,
                "signature_b64" => signature_b64 = text,
                _ => {}
            }
        }
        assert_eq!(
            claimed_digest, digest_hex,
            "sidecar digest binds the exact manifest bytes"
        );
        let mut message = SIGNING_DOMAIN.to_vec();
        message.extend_from_slice(&digest);
        let signature = ed25519_dalek::Signature::from_bytes(
            &BASE64
                .decode(signature_b64)?
                .try_into()
                .map_err(|_| "signature is not 64 bytes")?,
        );
        let signing = SigningKey::from_bytes(&CONFORMANCE_SIGNING_SEED);
        signing
            .verifying_key()
            .verify(&message, &signature)
            .map_err(|error| format!("injected seed does not verify signature: {error}"))?;
        Ok(())
    }

    #[test]
    fn deterministic_bytes_for_same_spec() -> TestResult {
        let temp = TempDir::new()?;
        let spec = spec_file(temp.path())?;
        let first_root = temp.path().join("first-root");
        let second_root = temp.path().join("second-root");
        run(Args {
            spec: spec.clone(),
            out: first_root.clone(),
        })?;
        run(Args {
            spec,
            out: second_root.clone(),
        })?;
        let first = first_root.join(RELEASE_ID);
        let second = second_root.join(RELEASE_ID);
        for name in [MANIFEST_FILE_NAME, SIDECAR_FILE_NAME]
            .into_iter()
            .chain(ARTIFACT_PATHS.iter().copied())
        {
            assert_eq!(
                fs::read(first.join(name))?,
                fs::read(second.join(name))?,
                "expected identical bytes for {name} across two runs"
            );
        }
        Ok(())
    }

    #[test]
    fn no_private_key_bytes_in_release_package() -> TestResult {
        let temp = TempDir::new()?;
        let (_, _, release, _) = run_release(&temp)?;
        let mut files = Vec::new();
        for entry in fs::read_dir(&release)? {
            let path = entry?.path();
            if path.is_file() {
                files.push(path);
            }
        }
        for entry in fs::read_dir(release.join("artifacts"))? {
            files.push(entry?.path());
        }
        for path in files {
            let bytes = fs::read(&path)?;
            assert!(
                !bytes
                    .windows(CONFORMANCE_SIGNING_SEED.len())
                    .any(|window| window == CONFORMANCE_SIGNING_SEED),
                "release file carries the test seed: {path:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_spec_exits_with_error() -> TestResult {
        let temp = TempDir::new()?;
        let spec = temp.path().join("bad.json");
        fs::write(&spec, "{\"spec_version\":2}")?;
        let out = temp.path().join("release");
        let error = run(Args { spec, out }).expect_err("spec must be refused");
        assert!(
            !error.to_string().is_empty(),
            "asserted condition: !error.to_string().is_empty()"
        );
        Ok(())
    }

    #[test]
    fn fixed_seed_is_test_only_signing_vector() -> TestResult {
        let signing = SigningKey::from_bytes(&CONFORMANCE_SIGNING_SEED);
        let other = SigningKey::from_bytes(&[0x12; 32]);
        assert_ne!(
            signing.verifying_key(),
            other.verifying_key(),
            "expected signing.verifying_key() to differ from other.verifying_key()"
        );
        assert_eq!(
            WIRE_SCHEMA_VERSION, 1,
            "expected WIRE_SCHEMA_VERSION to equal 1"
        );
        Ok(())
    }

    #[test]
    fn policy_is_conformance_only() {
        let policy: ResourcePolicy = conformance_policy();
        assert!(
            policy.max_record_bytes <= 4_096,
            "asserted condition: policy.max_record_bytes <= 4_096"
        );
        assert!(
            policy.max_manifest_bytes <= 1_000_000,
            "asserted condition: policy.max_manifest_bytes <= 1_000_000"
        );
    }

    #[test]
    fn canonicalize_refuses_float_scalar() {
        let value = JcsValue::Float(1.0);
        let policy = ResourcePolicy {
            max_nesting_depth: 4,
            ..conformance_policy()
        };
        assert!(
            canonicalize_strict(&value, &policy).is_err(),
            "asserted condition: canonicalize_strict(&value, &policy).is_err()"
        );
    }
}
