# Contributing to Fieldbook

<!-- SPDX-License-Identifier: Apache-2.0 -->

This file states the contribution workflow. The linked repository policies are
authoritative when this summary and a policy differ.

## Workflow

1. Create one bounded feature branch for one coherent change.
2. Add tests with behavior changes, including failure paths.
3. Run `make check` for the full gate; use `make check-static` for the fmt,
   lint, docs and style gates without tests.
4. Use `make format-fix` to apply the mutating style fixes, then re-run the
   gates. `make fmt` only checks formatting and does not edit files.
5. Preserve the pinned tool versions in `requirements-dev.txt` and
   `rust-toolchain.toml`.
6. Do not rewrite published history or bypass a red gate.

## Policy sources

- Branches, merges and pull requests: `docs/git-workflow.md`,
  `git-policy.json`.
- Authorship, license and provenance: `ORIGIN.md`.
- Style and formatting: `docs/style-standards.md`.
- Current scope and operating bounds: `docs/operating-envelope.md`.
- Rights and egress enforcement: `docs/rights-enforcement-2026-11-23.md`.

A passing check does not authorize provider contact, dataset collection or
live execution.

## Documentation policy

Prefer the nearest source of truth. Function behavior and invariants belong in
source comments and tests; public Rust API in `///` rustdoc; wire formats in
their schema; cross-repository decisions in an ADR; CI and test results in the
GitHub Actions run; mutable status in the workspace `CURRENT-STATE.json`.

Do not add a Markdown file for a single work package or PR. The PR description,
commit and tests already record routine implementation history. A new Markdown
file is permitted only when it establishes a stable public contract, an
architecture decision affecting multiple modules or repositories, an operator
procedure not derivable from source, a durable rights, legal or security
decision, or formal evidence not preserved by CI or Git. State that
justification in the PR description.

Keep the root `README.md` at 100 lines or fewer and `AGENTS.md` at 2 KB or
fewer. Do not duplicate current status, capability matrices or CI output in
prose. Historical evidence is immutable and is not active navigation.
