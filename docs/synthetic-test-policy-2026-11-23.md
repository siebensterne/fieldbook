# Synthetic test policy — 2026-11-23

**Record:** `docs/synthetic-test-policy-2026-11-23.md`
**Date:** 2026-11-23
**Status:** implemented; fail-closed compile-time and run-time test gate
**Authority:** owner directive D1-D3 recorded on 2026-11-22, applied to Fieldbook
**Rights effect:** none. No right, dataset, provider operation or experiment is
changed by this record.

## 1. Scope and rule

D1-D3 divide Rust tests into two classes. Pure scalar tests, abstract timestamp
tests and arbitrary byte tests remain executable. Tests built from invented
market observations — books, trades, quotes, orders, synthetic venues or
universes, fabricated exchange events and strategy returns — must not execute
under a default gate.

The gate has two parts. `Cargo.toml` declares `autotests = false` and registers
every test target explicitly. Market-shaped targets carry
`required-features = ["market-shaped-tests"]`; the feature is declared with an
empty default feature list and is enabled by no task, Makefile target, CI job
or assurance script. Market-shaped unit modules carry
`#[cfg(all(test, feature = "market-shaped-tests"))]` at the audited locations.
The `xtask` end-to-end runner holds its own allowlist and refuses any target
outside the permitted set.

## 2. Disabled integration targets

The following 15 test targets are preserved in `tests/` and are not registered
without the opt-in feature. Counts are `#[test]` and `#[tokio::test]`
declarations in the top-level target file; "active" excludes `#[ignore]`
declarations.

| Target file under `tests/` | Declared | Ignored | Active |
|---|---:|---:|---:|
| `coverage_certificate.rs` | 7 | 0 | 7 |
| `e2e_mock_exchange.rs` | 10 | 1 | 9 |
| `evidence_pipeline.rs` | 6 | 0 | 6 |
| `full_universe_stress.rs` | 58 | 14 | 44 |
| `hyperliquid_books.rs` | 3 | 0 | 3 |
| `hyperliquid_capacity.rs` | 5 | 1 | 4 |
| `hyperliquid_telemetry.rs` | 1 | 0 | 1 |
| `inspect_capture.rs` | 9 | 0 | 9 |
| `kalshi_lifecycle_plane.rs` | 4 | 0 | 4 |
| `lifecycle_churn.rs` | 7 | 1 | 6 |
| `live_kalshi.rs` | 1 | 1 | 0 |
| `live_polymarket.rs` | 2 | 2 | 0 |
| `replay_fixture.rs` | 2 | 0 | 2 |
| `session_recovery.rs` | 4 | 0 | 4 |
| `source_conformance.rs` | 6 | 0 | 6 |
| **Total** | **125** | **20** | **105** |

The read-only inventory recorded about 102 active market-shaped integration
tests. The exact source count above is 105 active declarations in 15 targets;
the difference is the inventory's approximate rounding.

### 2.1 Shared support sources

`tests/stress_support/` contains 52 test declarations in 11 files. The module
is included by `mod stress_support;` from three gated targets only:
`full_universe_stress.rs`, `hyperliquid_capacity.rs` and `lifecycle_churn.rs`.
It has no standalone `[[test]]` entry. Its executions are withdrawn together
with those three targets. The owner inventory recorded about 156 executions
from the opt-in stress and capacity cells; those cells are unreachable from
every default gate.

`tests/e2e_mock_exchange/failover.rs` holds 3 further declarations and is
included only by the gated `e2e_mock_exchange.rs` target.

## 3. Disabled unit test modules

| Location | Gated declaration | Tests |
|---|---|---:|
| `src/market_state/collector/state.rs` | `#[cfg(all(test, feature = "market-shaped-tests"))] mod tests;` | 56 |
| `src/distribution/coordinator.rs` | `#[cfg(all(test, feature = "market-shaped-tests"))] mod tests { … }` | 4 |
| `src/acquisition/exchange/` (26 files, 27 attributes) | `#[cfg(all(test, feature = "market-shaped-tests"))]` on each `#[cfg(test)]` item | 187 |
| `src/integrity/journal/tests.rs` line 310 | `#[cfg(all(test, feature = "market-shaped-tests"))]` on `checked_in_fixtures_round_trip_byte_for_byte` | 1 |
| `src/integrity/journal/tests.rs` line 339 | `#[cfg(all(test, feature = "market-shaped-tests"))]` on `checked_in_kalshi_fixtures_round_trip_byte_for_byte` | 1 |
| **Total** | | **249** |

The exchange declarations break down as Kalshi 62, Polymarket 37, Hyperliquid
35, Binance 15, Kraken 13, OKX 13, Coinbase 9 and the exchange registry 3.
The 187 exchange count includes 25 declarations in
`src/acquisition/exchange/kalshi/discovery/tests.rs`, reached through the
`mod tests;` declaration in `kalshi/discovery.rs`, and the test-only helper
`unknown_event_types` in `polymarket/codec.rs`.

The two journal tests named above inject checked-in Polymarket and Kalshi
book, price-change, orderbook-delta and lifecycle fixture bytes. The remaining
47 tests in that file are byte-framing, durability, crash and streaming tests
and stay enabled.

## 4. Permitted test surface

These 12 targets are registered without a feature requirement. Their 81
declarations include 8 `#[ignore]` declarations, leaving 73 active tests.
They cover numeric models, fixed-point arithmetic, byte framing, egress
governance, loopback proxy routes, generic durable delivery, the JSONL to
PostgreSQL reference application and abstract timestamp handling.

`numeric_model`, `egress_governance`, `egress_lab`, `bounded_batch`,
`network_source`, `durable_pipeline`, `segmented_durability`,
`jsonl_postgres_reference`, `segmented_runner`, `postgres_baseline`,
`postgres_batch_live` and `postgres_live` are the registered targets.

`cargo xtask test` runs `cargo test --workspace --all-targets --locked` and
`cargo test --workspace --doc --locked`. `make test` delegates to that task.
CI and `cargo xtask check` use the same commands. No command in the task
registry, the Makefile or the workflows passes `--features market-shaped-tests`
or `--all-features`. `cargo xtask e2e` runs the six permitted suites
`egress_lab`, `jsonl_postgres_reference`, `durable_pipeline`, `bounded_batch`,
`network_source` and `segmented_runner`.

On the verified run, `cargo test --workspace --all-targets --locked` executed
559 tests: 547 passed and 12 ignored. The library contributed 460 passed and 4
ignored; the 12 permitted integration binaries contributed 73 passed and 8
ignored; the `xtask` binary contributed 14 passed. The doc-test command added
1 passed test. Combined current result: 548 passed and 12 ignored.

## 5. Inspecting preserved source

No test source was deleted. Gate edits change registration, `cfg` attributes
and the `xtask` end-to-end allowlist; no assertion or test body was removed.
To inspect a preserved integration target, read its file directly, for example
`tests/hyperliquid_books.rs`. To inspect a preserved unit module, read the
files listed in section 3; the `mod tests;` declarations and module bodies are
still present. Compile-time gating can be confirmed with
`cargo metadata --locked` or with `cargo test --all-targets --locked -- --list`,
neither of which enables the opt-in feature. A `git diff` against
the base commit shows no deleted source file and no removed test body.

## 6. Withdrawn coverage

The gate withdraws execution of the following validation while keeping its
source in the tree:

- order-book snapshot and delta application, anchoring, coverage and
  cross-symbol ordering in the collector state module and the e2e, Kalshi,
  Hyperliquid and stress targets;
- venue codec and session decoding, including Book and LevelChange handling,
  recovery re-anchoring, discovery universes and lifecycle events;
- coordinator failover and reconnect state transitions;
- journal round trips of checked-in Polymarket and Kalshi market fixtures;
- synthetic full-universe, capacity, churn, backpressure and disconnect cells;
- evidence and source-conformance fixtures built from fabricated trade payloads;
- live venue targets, which remain ignored and additionally gated.

Order-book and decoder validation is unavailable until permitted real
observations exist or the owner changes this policy. The withdrawn tests must
not be treated as evidence of current order-book or decoder behavior.

## 7. Historical result status

The historical 1058-pass test result is a historical record and is not the
current test result. It predates this gate and includes executions that are
now withdrawn. The current result is the output of the permitted command in
section 4. The 850 Rust test count in `docs/programme-status.md` is likewise a
dated record of the 2026-11-18 export.

## 8. Reporting category

Implemented and tested with abstract mathematical values. No test in this
change uses permitted real observations, and no order-book or decoder claim is
verified against a real venue. The reporting category for the validation
withdrawn in section 6 is blocked until the owner supplies written permission
and a qualified dataset or changes the policy.
