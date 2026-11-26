#![expect(
    clippy::print_stdout,
    reason = "a task runner reports progress on stdout by definition"
)]

mod command;
mod e2e;
mod evidence;
mod report;
mod tasks;

use std::{
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use command::Cmd;
use report::Report;
use tasks::Task;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = root();
    let result = dispatch(&root, &args);
    match result {
        Ok(report) => {
            let path = report::write(&root, &report);
            match path {
                Ok(path) => println!("report: {}", path.display()),
                Err(error) => eprintln!("report write failed: {error}"),
            }
            if report.failed.is_empty() {
                ExitCode::SUCCESS
            } else {
                eprintln!("failed steps: {}", report.failed.join(", "));
                ExitCode::FAILURE
            }
        }
        Err(error) => {
            eprintln!("xtask error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(parent) = manifest.parent() else {
        eprintln!("xtask manifest has no parent directory");
        return PathBuf::from(".");
    };
    parent.to_path_buf()
}

fn dispatch(root: &Path, args: &[String]) -> Result<Report, String> {
    let mut report = Report::new(args);
    let command = canonical_command(args.first().map(String::as_str));
    let Some(task) = Task::parse(command) else {
        return Err(format!(
            "unknown command `{command}`; run `cargo xtask help`"
        ));
    };
    match task {
        Task::Fmt => {
            run(&mut report, root, &[Cmd::new("cargo fmt --all -- --check")])?;
            Ok(report)
        }
        Task::Lint => {
            run(
                &mut report,
                root,
                &[Cmd::new(
                    "cargo clippy --workspace --all-targets --locked -- -D warnings",
                )],
            )?;
            Ok(report)
        }
        Task::Test => {
            run(
                &mut report,
                root,
                &[
                    Cmd::new("cargo test --workspace --all-targets --locked"),
                    Cmd::new("cargo test --workspace --doc --locked"),
                ],
            )?;
            Ok(report)
        }
        Task::Docs => {
            run(
                &mut report,
                root,
                &[
                    Cmd::new("cargo doc --no-deps --workspace --locked").with_env(
                        "RUSTDOCFLAGS",
                        "-D warnings -D rustdoc::broken_intra_doc_links",
                    ),
                ],
            )?;
            Ok(report)
        }
        Task::Style => {
            run(&mut report, root, &style_commands(root)?)?;
            Ok(report)
        }
        Task::StyleFix => {
            run(
                &mut report,
                root,
                &[
                    Cmd::new("python3 -m pyink --config pyproject.toml scripts"),
                    Cmd::new("python3 scripts/check_style.py --fix"),
                ],
            )?;
            Ok(report)
        }
        Task::E2e => {
            e2e::run(&mut report, root, &args[1..])?;
            Ok(report)
        }
        Task::Verify => {
            evidence::checks(&mut report, root)?;
            Ok(report)
        }
        Task::Perf => {
            let label = args.get(1).map(String::as_str).unwrap_or("local");
            if !valid_label(label) {
                return Err(format!(
                    "invalid perf label `{label}`; use [a-z0-9][a-z0-9._-]*"
                ));
            }
            let line = format!("python3 scripts/measure_compile.py --label {label}");
            run(&mut report, root, &[Cmd::new(&line)])?;
            Ok(report)
        }
        Task::Assure => {
            evidence::assure(&mut report, root)?;
            Ok(report)
        }
        Task::Check => {
            run(&mut report, root, &style_commands(root)?)?;
            run(
                &mut report,
                root,
                &[
                    Cmd::new("cargo fmt --all -- --check"),
                    Cmd::new("cargo clippy --workspace --all-targets --locked -- -D warnings"),
                    Cmd::new("cargo test --workspace --all-targets --locked"),
                    Cmd::new("cargo test --workspace --doc --locked"),
                ],
            )?;
            evidence::checks(&mut report, root)?;
            e2e::run(&mut report, root, &[])?;
            Ok(report)
        }
        Task::Ci => {
            run(&mut report, root, &style_commands(root)?)?;
            run(
                &mut report,
                root,
                &[
                    Cmd::new("cargo fmt --all -- --check"),
                    Cmd::new("cargo clippy --workspace --all-targets --locked -- -D warnings"),
                    Cmd::new("cargo test --workspace --all-targets --locked"),
                    Cmd::new("cargo test --workspace --doc --locked"),
                    Cmd::new("cargo build --release --locked"),
                    Cmd::new("python3 scripts/check_sbe_generated.py"),
                    Cmd::new("cargo doc --no-deps --workspace --locked").with_env(
                        "RUSTDOCFLAGS",
                        "-D warnings -D rustdoc::broken_intra_doc_links",
                    ),
                ],
            )?;
            evidence::checks(&mut report, root)?;
            e2e::run(&mut report, root, &[])?;
            Ok(report)
        }
        Task::List => {
            print!("{}", tasks::list());
            Ok(report)
        }
        Task::Help => {
            print!("{}", tasks::help());
            Ok(report)
        }
    }
}

/// Resolve the q added-line gate base to a commit SHA, never a branch name.
///
/// A missing or unresolvable `origin/main` is an error: the checker must
/// never receive an empty base and silently report zero findings.
fn q_style_base_sha(root: &Path) -> Result<String, String> {
    if let Ok(value) = std::env::var("Q_STYLE_BASE_SHA")
        && !value.is_empty()
    {
        return Ok(value);
    }
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "origin/main^{commit}"])
        .current_dir(root)
        .output()
        .map_err(|error| format!("running git rev-parse: {error}"))?;
    if !output.status.success() {
        return Err("cannot resolve origin/main to a commit for the q style gate".to_owned());
    }
    let sha = String::from_utf8(output.stdout)
        .map_err(|error| format!("git rev-parse output is not UTF-8: {error}"))?
        .trim()
        .to_owned();
    if sha.is_empty() {
        return Err("git rev-parse returned an empty SHA for the q style gate".to_owned());
    }
    Ok(sha)
}

/// Every non-Rust language gate, in one place, so `style`, `check` and `ci`
/// cannot drift apart. Tool versions are pinned in requirements-dev.txt.
fn style_commands(root: &Path) -> Result<Vec<Cmd>, String> {
    let base = q_style_base_sha(root)?;
    Ok(vec![
        Cmd::new("python3 scripts/check_style.py"),
        Cmd::new("python3 scripts/ruff_gate.py ."),
        Cmd::new("python3 -m pyink --check --config pyproject.toml scripts"),
        Cmd::new("python3 scripts/check_q_style.py --self-test"),
        Cmd::new("python3 scripts/check_q_style.py").with_env("Q_STYLE_BASE_SHA", &base),
        Cmd::new("python3 scripts/check_quality_contract.py --self-test"),
        Cmd::new("python3 scripts/check_quality_contract.py"),
        Cmd::new("python3 scripts/check_license_provenance.py --self-test"),
        Cmd::new("python3 scripts/check_license_provenance.py"),
        Cmd::new("python3 scripts/check_shellcheck.py"),
        Cmd::new("python3 scripts/check_no_cross_pollution.py"),
        Cmd::new("python3 scripts/check_rust_style.py --self-test"),
    ])
}

/// Normalise CLI aliases to canonical task names.
fn canonical_command(name: Option<&str>) -> &str {
    match name {
        None | Some("--help") | Some("-h") => "help",
        Some("--list") => "list",
        Some(other) => other,
    }
}

/// Reject labels that could add arguments or shell metacharacters.
fn valid_label(label: &str) -> bool {
    let mut chars = label.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

fn run(report: &mut Report, root: &Path, commands: &[Cmd]) -> Result<(), String> {
    for command in commands {
        let outcome = command.execute(root)?;
        let failed = outcome.status == "failed";
        println!("[{}] {}", outcome.status, outcome.command);
        if failed {
            // Keep the failure cause in CI logs, not only in the JSON report.
            eprintln!("--- failed step output ---\n{}", outcome.output_tail);
        }
        report.push(outcome);
        if failed {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perf_label_accepts_safe_tokens() {
        for label in ["local", "ci-1", "nightly.2", "a_b"] {
            assert!(valid_label(label), "label `{label}` should be valid");
        }
    }

    #[test]
    fn perf_label_rejects_injection() {
        for label in ["", "--help", "a b", "a;b", "A", ".hidden", "-x"] {
            assert!(!valid_label(label), "label `{label}` must be rejected");
        }
    }

    #[test]
    fn cli_aliases_normalise_to_registered_tasks() {
        for (alias, expected) in [
            (None, Task::Help),
            (Some("--help"), Task::Help),
            (Some("-h"), Task::Help),
            (Some("--list"), Task::List),
        ] {
            assert_eq!(
                Task::parse(canonical_command(alias)),
                Some(expected),
                "alias {alias:?} must map to {expected:?}"
            );
        }
    }
}
