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
- Live evidence and egress: `docs/live-evidence-runbook.md`.

A passing check does not authorize provider contact, dataset collection or
live execution.
