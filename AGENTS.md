# Agent rules for Fieldbook

<!-- SPDX-License-Identifier: Apache-2.0 -->

Canonical policy for agents working in this repository. The linked sources are
binding when this summary and a policy differ.

## Read first

- `README.md` — current scope and document map.
- `ORIGIN.md` — license, provenance and authorship rules.
- `docs/style-standards.md` — language and formatting standards.
- `docs/git-workflow.md` and `git-policy.json` — branch and merge policy.
- `docs/live-evidence-runbook.md` — live evidence and egress rules.

## Behaviour rules

- Keep provider contact, collection, experiments and live routing disabled
  unless an owner grants bounded, written authorization for the exact scope.
- Keep rights `UNKNOWN` until written evidence exists. A token, a successful
  connection or a checksum grants no retention, replay or analytics right.
- Do not add provider credentials, account identifiers or market data to Git.
- Preserve immutable evidence; add a dated record rather than rewriting one.
- Run `make check` before publishing a change. The static-only surface is
  `make check-static`; neither target authorizes collection or live routing.
- Report exact commands, exit statuses and any unresolved gate.
