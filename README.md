# Cross-venue market-data collector

A read-only Rust collector for public market data. It discovers venues over
REST, subscribes over websocket, normalizes events, writes the supplied FIX SBE
capture format, and preserves exact inbound frames in a checksummed raw-frame
journal. Kalshi, Polymarket and Hyperliquid share one ingestion core; other
venue connectors are reference-data only unless explicitly stated.

The collector does not place orders, hold positions, or run strategy or
pre-trade risk. It uses no private credentials except the opt-in, read-only
Kalshi test, and never writes credentials or account identifiers into evidence.

## Current state

| Area | Status |
|---|---|
| Hyperliquid | Operator-reported direct, read-only mainnet evidence: five captures, including two clean `HL_LIVE_OK` runs and one `HL_LIVE_RECOVERY_OK` reconnect drill. Artifacts are in the Git-ignored `captures/` directory and are not included in this source export; verify them using `captures/INDEX.md` in the evidence-bearing checkout. |
| Polymarket | Live connections disabled until permitted access is documented. The preserved live run is a failed capture, not certification. |
| Kalshi | Opt-in authenticated read-only test exists; no live capture is claimed. |
| Gates | `cargo xtask ci` and `scripts/assurance/polish.sh` PASS on canonical `main`. Each source export carries `SOURCE_PROVENANCE.json`, which records the exact Git commit, tree hash and archive SHA-256; a ZIP without `.git` metadata is mapped to its commit by that manifest, not by a commit SHA written in prose. |
| Evidence | Synthetic loopback is labelled as such. Only independently verified real captures become live evidence. |

Start with the [live evidence runbook](docs/live-evidence-runbook.md),
[programme status](docs/programme-status.md), and
[architecture](docs/architecture.md). The evidence index at
`captures/INDEX.md` is operator-local and is not part of this source export.

The central rule separates three domains: a quiet instrument is not an
unhealthy connection, an unhealthy connection is not proof of a broken book,
and a green exit code is not a correct dataset. A preserved 60-minute
full-universe Polymarket run completed with zero writer errors and a finalized
journal while 12.34% of snapshots failed SBE reconstruction after 756
websocket errors drove 10 million failover snapshots. The continuity and
recovery work in `main` enforces that separation in the collector itself.

Three state domains are independent: connection health (per source, with typed
heartbeat acknowledgements), instrument activity (per instrument), and book
continuity (per instrument and source, with receive fences). A stale-probe
budget produces a symbol-scoped refresh, not a source reconnect. Recovery
decisions are typed and bounded; acknowledgements fence exact
`(source, instrument, generation)` or `(source, generation)` targets.

Kalshi's margin (perps) API is a separate surface with its own wire contract
and is not covered by these adapters.

## Review path

- [Style standards](docs/style-standards.md) — mandated references and the
  gates that enforce them; `STYLES.md` is the primary authority.
- [Programme status](docs/programme-status.md) — status by milestone.
- The live evidence index at `captures/INDEX.md` is operator-local and is
  omitted from source exports because `captures/` is Git-ignored.
- [Live evidence runbook](docs/live-evidence-runbook.md) — access rules and
  reproduction commands.
- [Architecture](docs/architecture.md) — topology and failure model.
- [Requirement-to-test matrix](docs/requirement-test-matrix.md) — test
  evidence per requirement.
- [Design decisions](docs/design-decisions.md) — why boundaries exist.
- [ADR-0002](docs/adr/0002-persist-transport-observations-without-changing-receive-order.md)
  — journal observation contract.
- [Hyperliquid integration](docs/hyperliquid-integration-plan.md) — venue
  design and H0-H3 history.
- [JSONL-to-target reference](docs/jsonl-postgres-reference.md) —
  non-market-data source/target pipeline.
- [Style guide](docs/style-guide.md) — enforceable rules for every language.

Format contracts: [replay format](docs/replay-format.md),
[raw-frame journal](docs/raw-frame-journal.md),
[event accounting](docs/event-accounting-contract.md),
[durability](docs/durability-contract.md), and
[operating envelope](docs/operating-envelope.md).

## What it does

- Discovers live markets continuously and adds or removes symbols without a
  restart.
- Keeps a book per symbol, applies snapshots and deltas, and rejects invalid
  states.
- Writes a full snapshot every 60 seconds and on failover, recovery, removal,
  and shutdown; writes deltas as they arrive.
- Assigns symbols to fixed shards and opens `replicas` sockets per shard. A
  backup is promoted only when its book is valid and fresh, and promotion is
  anchored by a full snapshot.
- Handles SIGINT and SIGTERM: stops discovery, emits final snapshots, closes
  websockets, flushes and syncs output, and writes sidecars.
- Exposes Prometheus text metrics, `/healthz`, and `/readyz` when configured.
- Provides deterministic replay, offline SBE inspect and verify, and an optional
  checksummed raw-frame journal with `journal verify` and `journal recover`.
- Egress is direct by default or one explicitly configured proxy (HTTP
  CONNECT or SOCKS5), fail-closed with no silent fallback, sharing one policy
  between REST discovery and websockets. Route provenance — mode, kind, host,
  port, DNS mode, fingerprint — is recorded in the journal manifest; the
  `network-probe` subcommand reports the path stage by stage as JSON.

## Quick start (Polymarket, no credentials)

An explicit subcommand is required: running the binary with no command starts
nothing. Live commands (`collect`, `discover`, `latency`, `network-probe`,
`analytics-export`) also need a runtime authorization file; there is no
environment or self-attestation shortcut. Copy `rights.example.toml`, fill in
the contract-derived values, and pass it as `--rights-file`:

```bash
cargo run --release -- --exchange polymarket --max-markets 20 \
  --rights-file /absolute/path/to/rights.toml \
  --output captures/polymarket.sbe \
  --metadata captures/polymarket-markets.json \
  --report captures/polymarket-report.json \
  collect
```

Add `--journal-dir captures/journal` to record raw frames, then verify:

```bash
cargo run --release -- journal verify captures/journal/<run-id>
```

The journal writes schema v2: application data frames and native WebSocket
Ping/Pong controls are retained as typed observations with independent
`receive_seq`, `control_seq`, and `observation_seq` domains per source and
connection epoch. `journal::read_records()` remains the data-only compatibility
API; `journal::read_observations()` returns the complete data/control stream.
v1 journals remain readable, and controls never become market-data events.

Other commands: `replay`, `inspect`, `verify`, `latency`, `discover`, `journal`,
`network-probe`, `completeness`, `coverage`.
See `config.example.toml` and `config.polymarket.example.toml`.

## Build and test

Rust is pinned in `rust-toolchain.toml` (1.99.1); Python formatters and linters
are pinned in `requirements-dev.txt`. Install the latter once with `make tools`
before running the full gate. The one-command pre-commit gate is the polish
script — it certifies the guard scripts themselves, checks every language,
runs the CI-parity core, verifies tree stability, and can repeat the whole
gate (`--loop N`) to surface flaky behavior:

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
cargo xtask test      # all-target and doc tests
cargo xtask docs      # rustdoc with broken links rejected
cargo xtask verify    # matrix, architecture and generated-path gates
cargo xtask e2e       # curated end-to-end suites (no live venues)
cargo xtask e2e --list-ignored       # opt-in tests and why they are skipped
cargo xtask e2e --run-ignored <name> # run one registered opt-in test
cargo xtask check     # style, Rust gates, checks and e2e
cargo xtask ci        # the full gate, including release build
cargo xtask fixtures  # verify checked-in journal fixtures
```

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

Live venue tests are opt-in and must run from an operator-managed machine in a location where access is permitted. Kalshi requires authenticated read-only API credentials and an explicit permission check. Do not use a VPN, proxy, or hosted runner to bypass geographic restrictions, and do not treat a venue's published blocklist as proof that access is permitted. See the [live evidence runbook](docs/live-evidence-runbook.md).

To produce actual SBE and raw-frame evidence for both venues from the local
machine:

```bash
export KALSHI_API_KEY_ID='…'
export KALSHI_PRIVATE_KEY_PATH="$HOME/.config/kalshi/private-key.pem"
LIVE_RIGHTS_FILE=/absolute/path/to/rights.toml \
LIVE_DURATION_SECS=120 LIVE_MAX_MARKETS=5 scripts/run-live-evidence.sh
```

`LIVE_RIGHTS_FILE` only names a contract-derived authorization file; it is not
an attestation. The collector denies before any provider contact when the file
is missing, malformed, expired or out of scope, and records each decision in
the directory named by `--rights-audit-dir` / `LIVE_RIGHTS_AUDIT_DIR`.

The script refuses to claim a dual-venue success if either venue is skipped or a capture/journal verification fails. It certifies per-symbol coverage: every expected symbol in `markets.json` must appear in the run report's acknowledged subscription set and must have its own snapshot in the capture. A five-market run emits `LIVE_SMOKE_OK`, never `LIVE_UNIVERSE_OK`. To claim the universe tier, run `LIVE_RIGHTS_FILE=/absolute/path/to/rights.toml LIVE_EVIDENCE_SCOPE=universe LIVE_MAX_MARKETS=0 LIVE_DURATION_SECS=900 scripts/run-live-evidence.sh` — pass `LIVE_CONFIG=config.live-universe.toml` for the reviewed full-universe capacity envelope (capacity planning uses 548,942 discovered outcome tokens; the failed 2026-11-14 live capture expected 385,604 symbols. These are different runs and different evidence stages, not interchangeable counts; the default envelope is refused fail-closed by the capacity planner). The script then requires the expected set to equal the full discovered universe. `LIVE_SOAK_OK` is reserved for a full-universe run held for the stated soak duration and is not emitted by this script. The manual live workflow runs the same script on the protected runner and uploads the complete `captures/` bundle as a retained artifact.

Evidence discipline: a failed run is preserved as a failure — raw captures are
deleted only after hashing, with the hashes, reduced reports and logs checked
in under `measurements/live/` — and no acceptance criterion is relaxed to
obtain a success. Requested evidence tiers and achieved outcomes are recorded
separately.

## Scope and provenance

`sbe_schemas/` is the supplied challenge schema. `src/util/build.rs` generates
the SBE bridge from it. The aligned reader and writer helpers are
challenge-compatible implementations; changes require template-reader
compatibility tests. The rest of `src/` is the project implementation.
Dependency licenses and the pinned graph are in `Cargo.lock`.

Measured limits, including the 100,000-symbol scale run, are in
[`docs/operating-envelope.md`](docs/operating-envelope.md). This is **not a production certification** for order entry or execution.
