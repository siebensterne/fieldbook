// SPDX-License-Identifier: Apache-2.0
//! Single source of truth for the task registry.
//!
//! Every command accepted by `cargo xtask` is a [`Task`] variant declared once
//! here. Help, `list` and dispatch all derive from the enum, so they cannot
//! drift: adding a variant without a dispatch arm is a compile error.

/// A task accepted by `cargo xtask`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Task {
    /// All non-Rust language and policy gates.
    Style,
    /// Apply the safe Python and Markdown style fixes.
    StyleFix,
    /// Check Rust formatting.
    Fmt,
    /// Run Clippy with warnings denied.
    Lint,
    /// Run permitted all-target and doc tests.
    Test,
    /// Build rustdoc with warnings and broken links denied.
    Docs,
    /// Run the curated end-to-end suites.
    E2e,
    /// Run matrix, architecture and generated-path gates.
    Verify,
    /// Verify checked-in journal fixtures.
    Fixtures,
    /// Measure compile time and enforce budgets.
    Perf,
    /// Run the full assurance superset.
    Assure,
    /// Style, fmt, lint, tests, verify and e2e.
    Check,
    /// Check plus release build, SBE check and docs.
    Ci,
    /// List every available task.
    List,
    /// Show the help text.
    Help,
}

impl Task {
    /// All variants in help-display order.
    pub const ALL: &'static [Self] = &[
        Self::Style,
        Self::StyleFix,
        Self::Fmt,
        Self::Lint,
        Self::Test,
        Self::Docs,
        Self::E2e,
        Self::Verify,
        Self::Fixtures,
        Self::Perf,
        Self::Assure,
        Self::Check,
        Self::Ci,
        Self::List,
        Self::Help,
    ];

    /// The CLI name of this task.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Style => "style",
            Self::StyleFix => "style-fix",
            Self::Fmt => "fmt",
            Self::Lint => "lint",
            Self::Test => "test",
            Self::Docs => "docs",
            Self::E2e => "e2e",
            Self::Verify => "verify",
            Self::Fixtures => "fixtures",
            Self::Perf => "perf",
            Self::Assure => "assure",
            Self::Check => "check",
            Self::Ci => "ci",
            Self::List => "list",
            Self::Help => "help",
        }
    }

    /// The one-line purpose of this task.
    pub const fn summary(self) -> &'static str {
        match self {
            Self::Style => "all Python, shell, Q, JSON, Markdown, policy and reference gates",
            Self::StyleFix => "apply the safe Python and Markdown style fixes",
            Self::Fmt => "check Rust formatting",
            Self::Lint => "run Clippy with warnings denied",
            Self::Test => "run permitted all-target and doc tests",
            Self::Docs => "build rustdoc with warnings and broken links denied",
            Self::E2e => "run the curated end-to-end suites",
            Self::Verify => "run matrix, architecture and generated-path gates",
            Self::Fixtures => "verify checked-in journal fixtures",
            Self::Perf => "measure compile time and enforce budgets",
            Self::Assure => "run the full assurance superset",
            Self::Check => "style, fmt, lint, tests, verify and e2e",
            Self::Ci => "check plus release build, SBE check and docs (the full gate)",
            Self::List => "list every available task",
            Self::Help => "show this message",
        }
    }

    /// Parse an exact CLI name into a task.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|task| task.name() == name)
    }
}

/// Render the help text from the registry.
pub fn help() -> String {
    let mut out = String::from(
        "xtask - repository task runner\n\nUsage: cargo xtask <task> [args]\n\nTasks:\n",
    );
    for task in Task::ALL {
        out.push_str(&format!("  {:<12} {}\n", task.name(), task.summary()));
    }
    out.push_str(
        "\nEvery task is fail-closed: the first failing step stops the run and\nthe process exits non-zero. Results are written to target/xtask/last-run.json.\n",
    );
    out
}

/// Render the machine-readable task list from the registry.
pub fn list() -> String {
    Task::ALL
        .iter()
        .map(|task| format!("{}\n", task.name()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn task_names_are_unique() {
        let names: HashSet<_> = Task::ALL.iter().map(|task| task.name()).collect();
        assert_eq!(names.len(), Task::ALL.len(), "duplicate task name");
    }

    #[test]
    fn every_task_round_trips_through_parse() {
        for task in Task::ALL {
            assert_eq!(
                Task::parse(task.name()),
                Some(*task),
                "task name must round-trip"
            );
        }
    }

    #[test]
    fn unknown_tasks_are_rejected() {
        assert_eq!(Task::parse("not-a-task"), None, "unknown task must fail");
        assert_eq!(Task::parse(""), None, "empty task must fail");
        assert_eq!(Task::parse("help "), None, "no whitespace trimming");
    }

    #[test]
    fn help_and_list_cover_every_task() {
        let help = help();
        let list = list();
        for task in Task::ALL {
            assert!(help.contains(task.name()), "help must name every task");
            assert!(
                help.contains(task.summary()),
                "help must summarize every task"
            );
            assert!(
                list.contains(&format!("{}\n", task.name())),
                "list must contain every task"
            );
        }
    }

    #[test]
    fn names_are_strict_cli_tokens() {
        for task in Task::ALL {
            assert!(
                task.name()
                    .chars()
                    .all(|c| { c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' }),
                "task name must be a lowercase CLI token"
            );
        }
    }
}
