# Fieldbook — securities market-data platform

Fieldbook is the authoritative source-acquisition and release platform for the
siebensterne workspace. Its target domain is Indian securities: reference data,
listed cash and derivative instruments, commodity contracts, market
observations, corporate actions and issuer facts, acquired only under written
rights and released as immutable, rights-bound datasets to Nirnay.

The platform owns acquisition, raw-byte archiving, normalization,
point-in-time reference data, coverage and quality certification, replay and
versioned release publication. It does not place orders, hold positions, run
strategies or perform pre-trade risk. Nirnay is the research and execution
consumer; the repositories remain independent and there is no shared crate.

No securities venue adapter is registered in the active tree. An adapter is
onboarded after its source, rights and NDC projection are qualified (workspace
W4). Until then, the composition root refuses `collect`, `discover` and
`latency` before a client or socket is created. No venue capability, live
readiness, capacity or performance claim is made by this repository.

## Implementation versus verification

`Implemented` means code and deterministic offline tests exist in the tree.
`Verified` requires a named commit and a retained, independently reviewed
evidence package with commands, output, digests and stated limits. Generic
acquisition, journal, replay and storage infrastructure is implemented. No
venue path is verified. A green static or test gate is not data rights, a
complete universe, a correct dataset or permission to trade.

## Current state

| Area | Status |
|---|---|
| Venue adapters | None registered. Generic `Exchange`, session, transport and capability contracts remain; the composition root denies live commands. |
| Generic infrastructure | Acquisition session/transport/egress/arbiter/supervisor/codec/packet/evidence/stream-slice/ws, integrity journal/replay, storage, analytics, domain and governance modules remain in the tree. Presence is implementation, not verification. |
| Governance | W1.1/W1.2 rights, egress-intent, coverage-certification and adapter records retained; historical counts and digests unchanged. |
| Rights | `UNKNOWN`. A URL, token, connection or checksum grants no retention, replay, analytics or redistribution right. |
| Live order submission | Disabled. No code or CI task authorizes it. |
| Gates | Local, fail-closed and recorded with exact commits. A green gate is not a venue claim. |
| Current-state authority | Workspace `CURRENT-STATE.json`. This table is a pointer, not a competing record. |

## Document authority

One document owns each topic. Other documents point to that owner rather than
restating it. A status correction is a documentation edit; a substantive
contract change needs a new approved digest; a retirement is a new dated record
rather than a rewrite of history.

| Topic | Single authority |
|---|---|
| Style | `STYLES.md` |
| Actual implementation | `docs/architecture.md` |
| Purpose | `docs/platform-charter.md` |
| Target architecture | `docs/global-data-architecture.md` |
| Decisions | `docs/adr/` (ADRs) |
| Data contract | approved NDC v2 producer requirements, `engineering/ndc-producer-requirements-v2-proposed.md`, and workspace `NDC-REGISTRY.md` |
| Current state | workspace `CURRENT-STATE.json` |
| Requirement-to-test evidence | `docs/requirement-test-matrix.md` |

## Review path

- [Style standards](docs/style-standards.md) — mandated references and gates;
  `STYLES.md` is the primary authority.
- [Programme status](docs/programme-status.md) — pointer to current state.
- [Architecture](docs/architecture.md) — topology and failure model.
- [Requirement-to-test matrix](docs/requirement-test-matrix.md) — evidence per
  requirement.
- [Platform charter](docs/platform-charter.md) — repository scope and ownership.
- [Global data architecture](docs/global-data-architecture.md) — target domain.
- [JSONL-to-target reference](docs/jsonl-postgres-reference.md) —
  non-market-data source/target pipeline.
- [Style guide](docs/style-guide.md) — enforceable rules for every language.
- [Documentation consolidation](docs/documentation-consolidation-2026-11-23.md)
  — RRP-005 change and authority record.
- [Documentation standard adoption](docs/documentation-standard-adoption-2026-11-24.md)
  — dated sweep and gate evidence for the adopted documentation standard.
- [Canonical financial objects](docs/fb-ref-001-canonical-objects-2026-11-24.md)
  — FB-REF-001 object classes, identity, assertions and coverage record.

Format contracts: [replay format](docs/replay-format.md),
[raw-frame journal](docs/raw-frame-journal.md),
[event accounting](docs/event-accounting-contract.md),
[durability](docs/durability-contract.md), and the
[current operating envelope](docs/operating-envelope.md).

Retirement records:
[product-scope retirement](docs/product-scope-retirement-2026-11-23.md) (RRP-003)
and [synthetic asset retirement](docs/synthetic-asset-retirement-2026-11-23.md)
(RRP-002). The earlier W1.1/W1.2 policy record remains at
[`docs/synthetic-test-policy-2026-11-23.md`](docs/synthetic-test-policy-2026-11-23.md)
as an immutable historical document.

## Build and gates

`Makefile` is a thin facade over `cargo xtask`, which owns the gate definitions
and writes a machine-readable report to `target/xtask/last-run.json`. Rust is
pinned in `rust-toolchain.toml`; Python and shell tools are pinned in
`requirements-dev.txt` and installed with `make tools`. CI installs the same
tools and runs the same commands.

```bash
cargo xtask fmt       # rustfmt check
cargo xtask lint      # clippy with warnings denied
cargo xtask docs      # rustdoc with broken links denied
cargo xtask style     # language and policy gates
cargo xtask test      # permitted all-target and doc tests
cargo xtask verify    # matrix, architecture and generated-path gates
cargo xtask check     # style, Rust gates, checks and e2e
```

No provider-contacting command is runnable: no venue adapter is registered and
live commands deny at the composition root. Configuration is venue-neutral;
`config.example.toml` carries no provider endpoint, credential, account
identifier or venue default. The rights model is in
[`docs/rights-enforcement-2026-11-23.md`](docs/rights-enforcement-2026-11-23.md)
and the intent contract in
[`docs/egress-intent-2026-11-23.md`](docs/egress-intent-2026-11-23.md).

Evidence discipline: a failed run is preserved as a failure, with hashes and
logs in dated records; requested evidence tiers and achieved outcomes are
recorded separately. No right or dataset changed and no Git history was
rewritten by the retirements.

## Scope and provenance

`sbe_schemas/` is the supplied schema and `src/util/build.rs` generates the SBE
bridge from it. The aligned reader and writer helpers are challenge-compatible
implementations; changes require template-reader compatibility tests. The rest
of `src/` is the project implementation. Dependency licenses and the pinned
graph are in `Cargo.lock`.

Measured bounds are described in the
[current operating envelope](docs/operating-envelope.md). It is **not a
production certification** for order entry or execution.
