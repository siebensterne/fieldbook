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

The seven crypto and prediction-market adapter families were retired from the
active product under RRP-003 on 2026-11-23. No securities venue adapter is
registered yet: one is added only after its source, rights and NDC projection
are qualified (workspace W4). Until then, the live commands `collect`,
`discover` and `latency` fail closed at the composition root, before a client
or socket is created. No venue capability, live readiness, capacity or
performance claim is made by this repository.

## Current state

| Area | Status |
|---|---|
| Venue adapters | None registered. Generic `Exchange`, session, transport and capability contracts retained; composition root denies. |
| Generic infrastructure | Acquisition session/transport/egress/arbiter/supervisor/codec/packet/evidence/stream-slice/ws, integrity journal/replay, storage, analytics, domain and governance retained. |
| Governance | W1.1/W1.2 rights, egress-intent, coverage-certification and adapter records retained; historical counts and digests unchanged. |
| Rights | `UNKNOWN`. No provider contact, collection, replay, analytics or redistribution right is granted by a URL, token, connection or checksum. |
| Live order submission | Disabled. No code or CI task authorizes it. |
| Gates | Rust and language gates are local, fail-closed and recorded with exact commits; a green gate is not data rights, a complete universe or a correct dataset. |

## Document authority

One canonical document owns each responsibility. `STYLES.md` is the primary
authority for mandated style references; `docs/architecture.md` owns topology
and failure model; `docs/adr/` owns recorded architecture decisions; the
workspace `ADR-REGISTRY.md`, `NDC-REGISTRY.md` and `TOOL-MATRIX.md` own
identities and pinned versions. Approved bytes and historical counts are not
edited casually: a status correction is a documentation edit, a substantive
contract change needs a new approved digest, and a retirement is published as
a new dated record rather than a rewrite of history.

## Review path

- [Style standards](docs/style-standards.md) — mandated references and the
  gates that enforce them; `STYLES.md` is the primary authority.
- [Programme status](docs/programme-status.md) — status by milestone.
- [Architecture](docs/architecture.md) — topology and failure model.
- [Requirement-to-test matrix](docs/requirement-test-matrix.md) — test
  evidence per requirement.
- [Design decisions](docs/design-decisions.md) — why boundaries exist.
- [ADR-0002](docs/adr/0002-persist-transport-observations-without-changing-receive-order.md)
  — journal observation contract.
- [Platform charter](docs/platform-charter.md) — repository scope and ownership.
- [JSONL-to-target reference](docs/jsonl-postgres-reference.md) —
  non-market-data source/target pipeline.
- [Style guide](docs/style-guide.md) — enforceable rules for every language.
- [Measurements index](measurements/README.md) — retired measurement digests
  and preserved non-market durability evidence.

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

## What the platform provides

- A venue-neutral acquisition core: discovery, shard assignment, redundant
  supervised socket workers, typed heartbeats, receive fences and bounded
  recovery decisions.
- A normalized order-book and canonical event model with exact numeric
  semantics and bitemporal reference identity.
- A deterministic replay path and an offline SBE inspect and verify path.
- An optional checksummed raw-frame journal with `journal verify` and
  `journal recover`, and a segmented durable delivery reference path.
- Fail-closed rights, egress-intent and coverage certification: no provider
  command runs without a caller-declared intent and a matching effective-dated
  grant, and no approval is inferred from a command name.
- Direct or explicitly proxied transport with recorded route provenance; no
  silent fallback and no credential stored in configuration or evidence.
- Prometheus text metrics, `/healthz` and `/readyz` when configured.

The three state domains stay independent: a quiet instrument is not an
unhealthy connection, an unhealthy connection is not a broken book, and a green
exit code is not a correct dataset. Connection health is per source, instrument
activity is per instrument, and book continuity is per instrument and source
with receive fences. A stale-probe budget produces a symbol-scoped refresh,
not a source reconnect.

## Offline quick start

Running the binary with no subcommand starts nothing. Offline commands
(`replay`, `inspect`, `verify`, `completeness`, `coverage`, `journal`) need no
rights file. Live commands (`collect`, `discover`, `latency`, `network-probe`,
`analytics-export`) require a caller-declared `EgressIntent` and a matching
rights grant; with no adapter registered, `collect`, `discover` and `latency`
deny at the composition root.

```bash
cargo run --release -- --help
cargo run --release -- replay captures/example.jsonl --output captures/replay.sbe
cargo run --release -- verify captures/replay.sbe
cargo run --release -- journal verify captures/journal/<run-id>
```

The journal writes schema v2: application data frames and native WebSocket
Ping/Pong controls are retained as typed observations with independent
`receive_seq`, `control_seq` and `observation_seq` domains per source and
connection epoch. `journal::read_records()` remains the data-only compatibility
API; `journal::read_observations()` returns the complete data/control stream.
v1 journals remain readable, and controls never become market-data events.

Configuration is venue-neutral: copy `config.example.toml` and fill only the
generic sections. No provider endpoint, credential, account identifier or
venue default exists in the active tree; see
[`docs/rights-enforcement-2026-11-23.md`](docs/rights-enforcement-2026-11-23.md)
for the rights model and
[`docs/egress-intent-2026-11-23.md`](docs/egress-intent-2026-11-23.md) for the
intent contract.

## Build and test

Rust is pinned in `rust-toolchain.toml` (1.99.1); Python formatters and linters
are pinned in `requirements-dev.txt`. Install the latter once with `make tools`
before running the full gate. The polish script certifies the guard scripts
themselves, checks every language, runs the CI-parity core, verifies tree
stability, and can repeat the whole gate (`--loop N`) to surface flaky behavior:

```bash
make tools                          # install pinned Pyink, Ruff and ShellCheck
scripts/assurance/polish.sh         # full gate, once
scripts/assurance/polish.sh --loop 2 # twice: a gate that only passes sometimes is a failing gate
```

`Makefile` is a thin facade over `cargo xtask`, which owns the gate
definitions and writes a machine-readable report to `target/xtask/last-run.json`.
CI installs the same pinned tools and runs the same commands.

```bash
cargo xtask style     # language, added-line Rust and isolation gates
cargo xtask style-fix # apply safe Pyink and Markdown fixes
cargo xtask fmt       # rustfmt check
cargo xtask lint      # clippy -D warnings
cargo xtask test      # permitted all-target and doc tests
cargo xtask docs      # rustdoc with broken links rejected
cargo xtask verify    # matrix, architecture and generated-path gates
cargo xtask e2e       # curated end-to-end suites (no live venues)
cargo xtask e2e --list-ignored       # opt-in tests and why they are skipped
cargo xtask e2e --run-ignored <name> # run one registered opt-in test
cargo xtask check     # style, Rust gates, checks and e2e
cargo xtask ci        # the full gate, including release build
```

Synthetic market-data generators, fixtures, golden journals, mock-exchange
targets and synthetic benchmarks were retired under owner directive D11
(RRP-002). The seven crypto and prediction-market venue adapters, their configs,
scripts, docs, measurements and capability claims were retired under RRP-003.
The `market-shaped-tests` Cargo feature is retained only as a detector for old
synthetic code; no target, task or CI job enables it and no replacement
synthetic data may be introduced without a separate versioned owner decision.
Historical W1.1/W1.2 counts, digests and approved document bytes are unchanged.

The complete cross-language contract is in [`docs/style-guide.md`](docs/style-guide.md).
Rust follows the [Linux kernel Rust guidelines](https://docs.kernel.org/rust/coding-guidelines.html)
and the [Google Rust style guide](https://google.github.io/styleguide/rustguide.html);
Python follows [Google's Python guide](https://google.github.io/styleguide/pyguide.html)
via Pyink and Ruff; shell follows [Google's shell guide](https://google.github.io/styleguide/shellguide.html)
via ShellCheck; Markdown and JSON follow their Google guides. All checks are
fail-closed: there are no warning-level suppressions. The only documented
exceptions are long string constants in three named Python files and
byte-exact immutable evidence, both recorded in the style guide.

Dependency maintenance uses the same gate: `scripts/assurance/update.sh`
refreshes the lockfile and keeps it only if the full polish gate passes,
restoring `Cargo.lock` otherwise. `scripts/assurance/upgrade.sh` moves the
pinned Rust toolchain (in lockstep with the CI workflow) and the lockfile
through the gate, disarming its restore trap only after the gate passes.
`main` accepts only reviewed PR merge commits — the policy and its conditions
are in `git-policy.json`.

Evidence discipline: a failed run is preserved as a failure, with hashes,
reduced reports and logs recorded in dated indexes, and no acceptance
criterion is relaxed to obtain a success. Requested evidence tiers and
achieved outcomes are recorded separately. No provider was contacted by these
retirements, no right or dataset changed, and no Git history was rewritten.

## Scope and provenance

`sbe_schemas/` is the supplied schema. `src/util/build.rs` generates the SBE
bridge from it. The aligned reader and writer helpers are challenge-compatible
implementations; changes require template-reader compatibility tests. The rest
of `src/` is the project implementation. Dependency licenses and the pinned
graph are in `Cargo.lock`.

Measured limits are described in the
[current operating envelope](docs/operating-envelope.md). It is **not a
production certification** for order entry or execution.
