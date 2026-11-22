use std::{fs, path::Path};

use crate::{command::Cmd, report::Report};

/// Integration test targets that exercise real components through their public
/// boundaries. Every entry is a permitted target from the synthetic-test
/// policy; market-shaped and live-venue targets are excluded.
const SUITES: &[&str] = &[
    "egress_lab",
    "jsonl_postgres_reference",
    "durable_pipeline",
    "bounded_batch",
    "network_source",
    "segmented_runner",
];

/// Test targets registered without `required-features` in Cargo.toml. The
/// e2e runner refuses any other target, including gated market-shaped ones.
const PERMITTED_TARGETS: &[&str] = &[
    "numeric_model",
    "egress_governance",
    "egress_lab",
    "bounded_batch",
    "network_source",
    "durable_pipeline",
    "segmented_durability",
    "jsonl_postgres_reference",
    "segmented_runner",
    "postgres_baseline",
    "postgres_batch_live",
    "postgres_live",
];

fn is_permitted_target(target: &str) -> bool {
    PERMITTED_TARGETS.contains(&target)
}

pub fn run(report: &mut Report, root: &Path, args: &[String]) -> Result<(), String> {
    if args.first().map(String::as_str) == Some("--list-ignored") {
        list_ignored(root);
        return Ok(());
    }
    if args.first().is_some_and(|arg| arg == "--run-ignored") {
        let filter = args
            .get(1)
            .ok_or_else(|| "--run-ignored needs a test name".to_owned())?;
        return run_ignored(report, root, filter);
    }
    for suite in SUITES {
        // The stress suite contains wall-clock recovery cells. Serializing it
        // removes contention from concurrent test threads on shared CI hosts.
        let line = if *suite == "full_universe_stress" {
            "cargo test --test full_universe_stress --locked -- --test-threads=1".to_owned()
        } else {
            format!("cargo test --test {suite} --locked")
        };
        let outcome = Cmd::new(&line).execute(root)?;
        let failed = outcome.status == "failed";
        println!("[{}] {}", outcome.status, line);
        let output_tail = outcome.output_tail.clone();
        report.push(outcome);
        if failed {
            println!("--- failed step output ---");
            println!("{output_tail}");
            return Ok(());
        }
    }
    println!("e2e suites: {}", SUITES.len());
    Ok(())
}

fn run_ignored(report: &mut Report, root: &Path, filter: &str) -> Result<(), String> {
    let allowed = ignored_tests(root)
        .into_iter()
        .find(|(name, _)| name == filter)
        .ok_or_else(|| format!("ignored test `{filter}` is not registered"))?;
    if allowed.1.contains("live") || allowed.0.starts_with("live_") {
        return Err(format!(
            "ignored test `{filter}` requires a live venue; not run"
        ));
    }
    let (target, test_name) = allowed
        .0
        .split_once("::")
        .ok_or_else(|| format!("ignored test `{filter}` has no test target"))?;
    if !is_permitted_target(target) {
        return Err(format!(
            "ignored test `{filter}` belongs to a gated target; not run"
        ));
    }
    let evidence_dir = root.join("target/xtask/ignored-evidence");
    fs::create_dir_all(&evidence_dir)
        .map_err(|error| format!("creating {}: {error}", evidence_dir.display()))?;
    let line =
        format!("cargo test --test {target} --locked -- --ignored --exact {test_name} --nocapture");
    let mut command =
        Cmd::new(&line).with_env("STRESS_MANIFEST_OUT", &evidence_dir.display().to_string());
    if let Some(stage) = capacity_stage(test_name) {
        command = command.with_env("STRESS_CAPACITY_STAGE", &stage);
    }
    let outcome = command.execute(root)?;
    let failed = outcome.status == "failed";
    println!("[{}] {}", outcome.status, line);
    report.push(outcome);
    if failed {
        return Err(format!("ignored test `{filter}` failed"));
    }
    Ok(())
}

fn capacity_stage(test_name: &str) -> Option<String> {
    let tail = test_name.split("_stage_").nth(1)?;
    let digits: String = tail
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect();
    (!digits.is_empty()).then(|| format!("{digits}k"))
}

fn list_ignored(root: &Path) {
    for (name, reason) in ignored_tests(root) {
        println!("{name}: {reason}");
    }
}

/// Read ignored-test declarations from source. Returns `(name, reason)` pairs,
/// where `name` is `<test target>::<test fn>` derived from the file stem.
fn ignored_tests(root: &Path) -> Vec<(String, String)> {
    let tests_dir = root.join("tests");
    let mut found = Vec::new();
    for entry in fs::read_dir(&tests_dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let Some(target) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if !is_permitted_target(target) {
            continue;
        }
        let Ok(source) = fs::read_to_string(&path) else {
            continue;
        };
        let lines: Vec<&str> = source.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("#[ignore") {
                continue;
            }
            let reason = line
                .split_once('"')
                .and_then(|(_, rest)| rest.split_once('"'))
                .map_or("no reason given", |(value, _)| value)
                .to_owned();
            let mut name = String::new();
            for following in lines.iter().skip(index + 1).take(8) {
                let trimmed = following.trim_start();
                if let Some(rest) = trimmed.strip_prefix("async fn ") {
                    name = rest.split(['(', ' ']).next().unwrap_or("").to_owned();
                    break;
                }
                if let Some(rest) = trimmed.strip_prefix("fn ") {
                    name = rest.split(['(', ' ']).next().unwrap_or("").to_owned();
                    break;
                }
            }
            if !name.is_empty() {
                found.push((format!("{target}::{name}"), reason));
            }
        }
    }
    found.sort();
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_stage_is_derived_from_the_test_name() {
        assert_eq!(
            capacity_stage("capacity_stage_10k_short_correctness").as_deref(),
            Some("10k")
        );
        assert_eq!(capacity_stage("reference_hyperliquid_manifest"), None);
    }

    #[test]
    fn suites_are_unique_and_have_no_live_venue_targets() {
        let mut seen = std::collections::BTreeSet::new();
        for suite in SUITES {
            assert!(seen.insert(*suite), "duplicate suite {suite}");
            assert!(
                !suite.starts_with("live_"),
                "live target in default e2e: {suite}"
            );
        }
    }

    #[test]
    fn suites_are_all_permitted_targets() {
        assert!(
            SUITES.iter().all(|suite| is_permitted_target(suite)),
            "e2e suite must be a permitted target"
        );
    }

    #[test]
    fn market_shaped_targets_are_not_permitted() {
        for target in [
            "coverage_certificate",
            "e2e_mock_exchange",
            "evidence_pipeline",
            "full_universe_stress",
            "hyperliquid_books",
            "hyperliquid_capacity",
            "hyperliquid_telemetry",
            "inspect_capture",
            "kalshi_lifecycle_plane",
            "lifecycle_churn",
            "live_kalshi",
            "live_polymarket",
            "replay_fixture",
            "session_recovery",
            "source_conformance",
        ] {
            assert!(
                !is_permitted_target(target),
                "market-shaped target `{target}` must stay gated"
            );
        }
    }
}
