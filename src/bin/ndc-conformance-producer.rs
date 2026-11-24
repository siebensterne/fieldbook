// SPDX-License-Identifier: Apache-2.0
//! Conformance producer for the ratified canonical NDC v2 Profile 1 wire
//! schema. This executable consumes an abstract, non-market JSON spec and
//! writes a complete release: `manifest.json`, `signature.json` and `artifacts/`.
//!
//! It uses a fixed test-only Ed25519 seed bound to
//! [`CONFORMANCE_SIGNING_SEED`]. The seed is a published conformance vector,
//! not a production key. No key material is written into the release package.
//! No provider contact, collection, right, dataset acceptance or live route is
//! involved; a successful run proves only that this producer mapped the
//! abstract spec to the canonical wire shape.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use ed25519_dalek::SigningKey;

use fieldbook::distribution::ndc_release::ResourcePolicy;
use fieldbook::distribution::ndc_wire;
use fieldbook::distribution::ndc_wire::CONFORMANCE_SIGNING_SEED;
use fieldbook::distribution::ndc_wire::WireError;

/// Command-line surface of the conformance producer.
#[derive(Debug, Parser)]
#[command(name = "ndc-conformance-producer")]
#[command(about = "Write a canonical NDC v2 Profile 1 release from an abstract spec")]
struct Args {
    /// Path to the abstract non-market JSON spec.
    #[arg(long)]
    spec: PathBuf,
    /// Destination directory; it must not already exist.
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
    }
}

/// Read, map, sign and publish one abstract spec. Every refusal is typed.
fn run(args: Args) -> Result<(), WireError> {
    let text = fs::read_to_string(&args.spec)
        .map_err(|error| WireError::Io(format!("read {}", args.spec.display()), error))?;
    let spec = ndc_wire::parse_conformance_spec(&text)?;
    let signing = SigningKey::from_bytes(&CONFORMANCE_SIGNING_SEED);
    let verifying = signing.verifying_key();
    let policy = conformance_policy();
    let (release, artifacts) =
        ndc_wire::build_conformance_release(&spec, &policy, &signing, &verifying)?;
    ndc_wire::write_release(
        &args.out,
        &release.manifest_bytes,
        &release.signature_bytes,
        &artifacts,
    )
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

    use clap::Parser;
    use ed25519_dalek::SigningKey;
    use fieldbook::distribution::ndc_release::JcsValue;
    use fieldbook::distribution::ndc_release::ResourcePolicy;
    use fieldbook::distribution::ndc_release::canonicalize_strict;
    use fieldbook::distribution::ndc_release::parse_jcs_value;
    use fieldbook::distribution::ndc_wire::CONFORMANCE_SIGNING_SEED;
    use fieldbook::distribution::ndc_wire::WIRE_SCHEMA_VERSION;
    use fieldbook::distribution::ndc_wire::WireError;
    use tempfile::TempDir;

    use super::Args;
    use super::conformance_policy;
    use super::run;

    type TestResult = Result<(), Box<dyn StdError>>;

    const EXAMPLE_SPEC: &str = include_str!(
        "../../docs/specifications/ndc-conformance-producer-spec-example-2026-11-24.json"
    );

    fn spec_file(dir: &Path) -> Result<std::path::PathBuf, WireError> {
        let path = dir.join("spec.json");
        fs::write(&path, EXAMPLE_SPEC)
            .map_err(|error| WireError::Io("write example spec".to_owned(), error))?;
        Ok(path)
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
        let spec = spec_file(temp.path())?;
        let out = temp.path().join("release");
        run(Args {
            spec,
            out: out.clone(),
        })?;
        assert!(
            out.join("manifest.json").is_file(),
            "asserted condition: out.join(\"manifest.json\").is_file()"
        );
        assert!(
            out.join("signature.json").is_file(),
            "asserted condition: out.join(\"signature.json\").is_file()"
        );
        let artifacts = out.join("artifacts");
        assert!(
            artifacts.join("sequenced-abstract.jsonl").is_file(),
            "asserted condition: artifacts.join(\"sequenced-abstract.jsonl\").is_file()"
        );
        assert!(
            artifacts.join("reference-abstract.jsonl.gz").is_file(),
            "asserted condition: artifacts.join(\"reference-abstract.jsonl.gz\").is_file()"
        );
        Ok(())
    }

    #[test]
    fn manifest_and_sidecar_have_ratified_shape() -> TestResult {
        let temp = TempDir::new()?;
        let spec = spec_file(temp.path())?;
        let out = temp.path().join("release");
        run(Args {
            spec,
            out: out.clone(),
        })?;
        let manifest_text = fs::read_to_string(out.join("manifest.json"))?;
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
        let sidecar_text = fs::read_to_string(out.join("signature.json"))?;
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
    fn deterministic_bytes_for_same_spec() -> TestResult {
        let temp = TempDir::new()?;
        let spec = spec_file(temp.path())?;
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        run(Args {
            spec: spec.clone(),
            out: first.clone(),
        })?;
        run(Args {
            spec,
            out: second.clone(),
        })?;
        for name in [
            "manifest.json",
            "signature.json",
            "artifacts/sequenced-abstract.jsonl",
            "artifacts/reference-abstract.jsonl.gz",
        ] {
            assert_eq!(
                fs::read(first.join(name))?,
                fs::read(second.join(name))?,
                "expected fs::read(first.join(name))? to equal fs::read(second.join(name))?"
            );
        }
        Ok(())
    }

    #[test]
    fn no_private_key_bytes_in_release_package() -> TestResult {
        let temp = TempDir::new()?;
        let spec = spec_file(temp.path())?;
        let out = temp.path().join("release");
        run(Args {
            spec,
            out: out.clone(),
        })?;
        let mut files = Vec::new();
        for entry in fs::read_dir(&out)? {
            let path = entry?.path();
            if path.is_file() {
                files.push(path);
            }
        }
        for entry in fs::read_dir(out.join("artifacts"))? {
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
        let policy = conformance_policy();
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
