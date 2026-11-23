# Security policy for Fieldbook

<!-- SPDX-License-Identifier: Apache-2.0 -->

Report vulnerabilities privately to the repository owner before public
disclosure. Do not attach market data, credentials or account identifiers to a
report.

## Secret handling

- Keep API tokens, TOTP seeds, private keys, account numbers and signed URLs
  out of source control, logs, fixtures and experiment artifacts.
- Inject secrets from a local manager or the environment and redact request
  and response diagnostics.
- Egress is direct or an explicitly configured fail-closed proxy; the rules
  are in `docs/egress-intent-2026-11-23.md`, `docs/operating-envelope.md` and
  `docs/git-workflow.md`.

## Scope

This repository is research and paper infrastructure; it does not ship live
broker order routing. Rights remain `UNKNOWN` until written evidence exists,
and a passing gate does not authorize collection or live execution. Provenance
and authorship rules live in `ORIGIN.md`.
