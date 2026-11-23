# Synthetic asset retirement — 2026-11-23

**Record:** `docs/synthetic-asset-retirement-2026-11-23.md`
**Date:** 2026-11-23
**Programme:** RRP-002 — synthetic market-data asset removal (Fieldbook)
**Authority:** owner directive D11 (RRP-001), gate RRP-002 in `RETIREMENT-ACCEPTANCE.md`
**Reviewed base:** branch `chore/rrp-002`, base commit `3c3279bdaa8df6aa44018184fefb662e98b5e0c1`
**Rights effect:** none. No provider was contacted, no right or dataset changed, no
history rewritten and no replacement synthetic data created.

This record is the dated path/hash/size evidence for the `DELETE` rows of
`FIELD-BOOK-RETIREMENT-MANIFEST.csv` executed in this PR. Blobs remain in Git history
through ordinary `git rm`; no commit was rewritten. Each row below carries the manifest
`sha256` and byte `size` measured at the reviewed head.

## 1. Scope boundary

Only D11-A (generator/fixture), D11-B (market-shaped integration targets and stress
support) and D11-C (synthetic benchmarks) `DELETE` rows were executed. The seven
crypto/prediction-market venue adapters, their configs, scripts and measurements
(D11-D/D11-E) are deliberately **not** removed here; they belong to RRP-003. Generic
acquisition transport, session, egress, arbiter, supervisor and codec modules, integrity
journal/replay, governance and the domain layer are retained. Tests were audited
individually: pure scalar, type-level, rights, hashing/signature and arbitrary-byte
tests stay in the tree, and only fixture-dependent test functions were removed from
retained source files.

## 2. Removal counts

| Manifest classification | Files removed |
|---|---:|
| D11-A synthetic generator/fixture | 43 |
| D11-B market-shaped test/mock exchange | 16 |
| D11-B stress/mock-exchange support | 12 |
| D11-C synthetic benchmark | 4 |
| **Total** | **75** |

Removed bytes at the reviewed head: **903,110**. No `ARCHIVE`, `DEPRECATE`,
`CONSOLIDATE`, `CONDITIONAL` or `KEEP` row was deleted.

## 3. Removed paths with manifest hashes

| Path | SHA-256 | Size (bytes) |
|---|---|---:|
| `examples/write_fixture.rs` | `be7200ce5b316e832caa7160c382e8b1a942190bc1b5675edab0407c7d4065b3` | 4731 |
| `fixtures/binance/reference.json` | `f6365602f9f8e3586a9a258ad78321e91f38664881d4f0dc8c36b884a0e9c592` | 4523 |
| `fixtures/coinbase/reference.json` | `405b1d136741434494b7c4b71c39dde1a01c5a44fd622bb94eb052a1b1951267` | 1974 |
| `fixtures/hyperliquid/all_mids.json` | `88213f6c123bb40add646668613a631308b04c2dd35388689258f679ebfd80da` | 271 |
| `fixtures/hyperliquid/all_mids_malformed.json` | `c788e8875df8963e1300ed2fa08042ec715d1ae2c5c9f56aa28f8b52afca9619` | 116 |
| `fixtures/hyperliquid/fast_asset_ctxs.json` | `d91231e95c810e25f13502ee1af030f9db2815ded71f9d0fa084b7de162eeb14` | 533 |
| `fixtures/hyperliquid/fast_asset_ctxs_malformed.json` | `b140980051ac293f080fe7c7f8c5707c6fb8336a37ac3345b813e5b75f050f3c` | 201 |
| `fixtures/hyperliquid/fast_asset_ctxs_wire.json` | `bfcde02e80aa00f4c8ba0f68c123373de1cfe065573efa8c78df24683733686a` | 24277 |
| `fixtures/hyperliquid/l2_book.json` | `70ee193a97ef6f8425fc5b43f279d8e288b252bd61d50bd076e92690170842ff` | 333 |
| `fixtures/hyperliquid/l2_book_deep.json` | `bb470dd77d16b4906c794b63e07c679d891803192b2c5664c78a20772b777e40` | 373 |
| `fixtures/hyperliquid/l2_book_empty.json` | `cece8442386619483a22517ba80d15e4cf0a3320a0e7d237b13e4f7d840c9509` | 112 |
| `fixtures/hyperliquid/l2_book_malformed.json` | `7f463d72cbd1b58910e5f83557576430de6b1a254102e795d7a4908040b14d52` | 196 |
| `fixtures/hyperliquid/l2_book_one_sided.json` | `8383d420869ef98565b555a1084a77d8ad9a8bc14ad063a60beb17254407e13c` | 158 |
| `fixtures/hyperliquid/l2_book_unknown_additive.json` | `9a2f9e897ef274494ee4cd01dc2666cea63ea7cc10039fad1e3c7a661be19441` | 360 |
| `fixtures/hyperliquid/reference.json` | `7e61bb0ebb16b973c7b1c9077456e0a421b3b3067148e90d73dce704c7be789f` | 665 |
| `fixtures/hyperliquid/trades.json` | `f1c5c43870bfd5890fa5262f68c6b36fe3c2aecba8d8f29c6664813978305eca` | 493 |
| `fixtures/hyperliquid/trades_malformed.json` | `7e045cd0f148d5718937c163aa45d239f76b5dca52653fbbd173cfb60712493c` | 188 |
| `fixtures/journal-v1-golden/golden/00000000.pmj` | `60dcc1c8d0b5945c6f5605e4fd3895a86b0bfbe4cdf4bea8cd34c57e0b876023` | 1755 |
| `fixtures/journal-v1-golden/golden/manifest.json` | `6e4e44f1dc5d9aac731633b009e648e6d41f49e5fa82d2260d15ae2e1eed6f38` | 958 |
| `fixtures/journal-v2-golden/golden/00000000.pmj` | `ec950b332ef5a00d6b2b6092449aac8b8485f9f5adc96977ec8653b2beb283b8` | 3512 |
| `fixtures/journal-v2-golden/golden/manifest.json` | `88d720647b86673ff139817c6c5db01dd05bd3ddb7d62211d4270ed981be6a0d` | 958 |
| `fixtures/kalshi/README.md` | `54c392191fea4a7213e1911de9c357fd013e5a245864e9c4ece975cd4c57718f` | 3135 |
| `fixtures/kalshi/book_snapshot.json` | `3b76a07201cec958df40f90b399b2f90f2250ef28fdaf7fdd30ea578a2d50ebb` | 349 |
| `fixtures/kalshi/book_snapshot_legacy.json` | `2cfb355b6e57d8dc861ec84733aa47fec2ce3bec4a48361ced04ad5da6bab72d` | 178 |
| `fixtures/kalshi/control_error.json` | `234a21b535ed95fb36de0230023ce7241165185909c00480d24ba0579a2fc885` | 105 |
| `fixtures/kalshi/malformed_delta_missing_fields.json` | `5d8761ec2a0e6dccfe51711ea3d3ffc195853431cd19fec9f1a4efc43ad54bfb` | 195 |
| `fixtures/kalshi/market_lifecycle_activated.json` | `f683e292b071ce1a72abe565a1b6ea9814e57ebcca3847234a7ba4e9cfa6cc84` | 289 |
| `fixtures/kalshi/orderbook_delta_no_inverted.json` | `288e3358fb90b13deea091c7310a0de4bab750808f9170dee719245db29bcfd9` | 270 |
| `fixtures/kalshi/orderbook_delta_yes.json` | `ff3d13cd7b047c3b286f12e4f60cbc0a0f06515ed105568ec4f7ac421a4cafe7` | 271 |
| `fixtures/kalshi/ticker_channel_ignored.json` | `84e238b70081b6bc0b3bbb5f240b1ef22fc9683a8663ff31283c5890b38bc9ad` | 261 |
| `fixtures/kraken/reference.json` | `68644e827756ca12315b90a5b561f2c1020de65113f6437e2e40eaa374e2fda9` | 2334 |
| `fixtures/okx/reference.json` | `1493e2c058ca22d7be77fe57ca56303ad2e1ce02267f8fdc24a227522cd04d99` | 2032 |
| `fixtures/polymarket/README.md` | `408099a21e4cad331091d21d93cd6f2e0a52aa52fb75b456ce32afb332e5b086` | 1807 |
| `fixtures/polymarket/best_bid_ask.json` | `ecf471bb7ee1c8d3f66e59354efe6bf9eb9c2358d0b14540af9f49f12a95c423` | 309 |
| `fixtures/polymarket/book_snapshot.json` | `bb969b7cf552346bc7d92f9d5b68d3bd3c3a597bdc886b3b7163f4fcf8ef50fc` | 472 |
| `fixtures/polymarket/malformed_price_change_atomic.json` | `26a64eb56024bbc5ffb54490c1817bd02144204a1b196f188d5dfe1412adc645` | 505 |
| `fixtures/polymarket/market_resolved.json` | `31f388a22f9fe0a8945eb31913aee27c91a2236196ee4da2590907243bd20cda` | 494 |
| `fixtures/polymarket/new_market.json` | `55a646471d1b20291c8f25747a7ad7fd0cdae9ea153d40acb9701e96fcaa697b` | 486 |
| `fixtures/polymarket/price_change_multi_asset.json` | `5b41862dc43bf36f3b41fa6dfe8760a3642f76ecd5cc6a3aaa8d63bbc1d2d70b` | 720 |
| `fixtures/polymarket/tick_size_change.json` | `671063619bf5baf9da2faf6709864a9f395a7febeb1551b0ae0b5495d91a543a` | 304 |
| `fixtures/polymarket/unknown_additive_event.json` | `abc9b926abc41d48b214d0c5337e88547538b493201459e3b2a56fa831d7e8f7` | 217 |
| `fixtures/sample_replay.jsonl` | `bb18c1c1b0cc2d5d1dfafdc169ec9db8ab52e447e24ac48749c651475e6b6cd5` | 3260 |
| `src/acquisition/fixture_connectors.rs` | `ca5b7bb50a39d5b57a9b237eaae29e8b3e5273331a5c8f0fb292d12bc54bb847` | 23349 |
| `tests/coverage_certificate.rs` | `8bbeefe1c8d600161236e351db3a8e343dd259faf636d69e3aff7d335d1ff528` | 9746 |
| `tests/e2e_mock_exchange.rs` | `0f006b3f413730433955efcc19205081b9569577f11d16d00d4355017cc2c930` | 86948 |
| `tests/e2e_mock_exchange/failover.rs` | `3db035a3c52f8dc552c5126bc5d69fb5164aa8ebc241240dd02bdb55ed878df9` | 11648 |
| `tests/evidence_pipeline.rs` | `b2c0404936253b6ef7db3ab2950f7a92ec440d0a7927e72d0e98ad08e16b2625` | 13017 |
| `tests/full_universe_stress.rs` | `06aa3bc8cd2988ba45b417e719538d3157a3d4e7fb01d8d540101d914267c8e6` | 116638 |
| `tests/hyperliquid_books.rs` | `3b7f262290d99a0df366df617357cb9292fb53b45f00d86366544d329dd768a6` | 29819 |
| `tests/hyperliquid_capacity.rs` | `58bc208fa8d597c06f7d3a425e6a5071f112393e0688e48f47f7703f682da2f8` | 10516 |
| `tests/hyperliquid_telemetry.rs` | `7c647ec79fac8e21574252e46b63a4e3534657bd2f70882e7b1a5c489ae43476` | 7911 |
| `tests/inspect_capture.rs` | `c0ad45ff0bb14d9967673534d5756820541058910efafe7ba55c3587a8d6241b` | 6587 |
| `tests/kalshi_lifecycle_plane.rs` | `b437e351dcfee58d4eefb4c44f96085644abb417db1b330b02b61d6c88a1281d` | 24899 |
| `tests/lifecycle_churn.rs` | `5d08477d551528b1fd727c2d2f8c807b694a859ce113acbd4823b38dfc43e96a` | 15597 |
| `tests/live_kalshi.rs` | `8f8a4695d2c756eb1c940bceab45109f2b61a8fda0049a0ba7bc71488ef44314` | 7378 |
| `tests/live_polymarket.rs` | `83050a485bd953c7a9b39afb9c13337cdd2a9fafc16aad0cc706d94601b45fb4` | 7051 |
| `tests/replay_fixture.rs` | `eea0376758b0e7ed3c1208a1d6cd16d0963e4545ba14c02d3e337f579c05ecfa` | 2952 |
| `tests/session_recovery.rs` | `13b8e87fabf40de2de08f00cccb112db7649c18ae119216e5553607a325635d8` | 17622 |
| `tests/source_conformance.rs` | `d21f5e4a5c633bdda076debc7d177d08161dd30c22c73acc35672e828ad8769a` | 11940 |
| `tests/stress_support/backpressure.rs` | `66594131db42afbdbee16797dbc24a55db87a45d34ab42597895cab1e979ec39` | 28045 |
| `tests/stress_support/capacity.rs` | `6ab8a8c63e8f4c8d65627ac6c785c99caf8e78d6b207c86d21f76258ff7ad2d6` | 8671 |
| `tests/stress_support/faults.rs` | `744121de257a30580dbd3104bde0a2e26a0f06c13636211633f4d1531010ea22` | 19658 |
| `tests/stress_support/host.rs` | `7c17c85a69caf7a5ccfc5bf79251e99a5820718f58f67fa258170829562b92a5` | 5285 |
| `tests/stress_support/hyperliquid.rs` | `506dbb8463718794a29c531e2bc1ea67d14fc42e12501eecef0fb886b7596d92` | 59186 |
| `tests/stress_support/lifecycle.rs` | `9144ae8df762a52fcbfd4c906a976ee020cbfac6a82b70e4fc8b146bfcbbd82a` | 21581 |
| `tests/stress_support/manifest.rs` | `b692555c08986a1965191f5e7eadc195bdc9a8ad7ad2a5480b699500dd3ba611` | 24110 |
| `tests/stress_support/mock.rs` | `a12c8a1e3f2002a87d502af1494d8b490e98e88066033be2e43859e1d9614759` | 45874 |
| `tests/stress_support/mod.rs` | `c0c14fce05999468ebf43ec9f82cb2a4ff75e3e1aa0e2105b032fd0e20230bea` | 427 |
| `tests/stress_support/rng.rs` | `4c471a01a9c4c88dc4e65181f40dd20694a0669348d30c2b9569f3a241fb0be8` | 3369 |
| `tests/stress_support/runner.rs` | `db2e3ceaddb7cd5ad9f5301a0188e0b786767e30b71639271589f9e22222c29d` | 181707 |
| `tests/stress_support/universe.rs` | `200296836e82b746400201936452235138ea721ba73fd17d2b6d0608583871e6` | 12881 |
| `benches/codec_normalization.rs` | `eafe4bf2c46d04b36368835fc3da1cb609cb80d8eec5a4c429c4c2f5e0cad5ca` | 3085 |
| `benches/journal_reader.rs` | `169f51832f8b6a6250f408af1c8a16a0a4f5af5b0c6ae465a11c12b0dba00435` | 2115 |
| `benches/numeric_model.rs` | `40777a418d0a22571dd42a83aa679735a2fdc479397aa3f4ec517eb4c6f727f5` | 5934 |
| `benches/pipeline_stages.rs` | `d328cf035d54f473443075349b31e4d02876a8dbf2770bb12838fae899addf38` | 12884 |

## 4. Registration and reference updates

- - `Cargo.toml`: removed the 15 gated `[[test]]` registrations and four `[[bench]]`
  registrations; `autotests = false` is retained. The `market-shaped-tests` feature is
  retained only as a detector for old synthetic code and is enabled by no task, target
  or workflow.
- - `src/acquisition/mod.rs`: removed `pub mod fixture_connectors;`; all other
  acquisition modules remain registered.
- - `src/integrity/conformance.rs`: removed the optional connector-fixture invocation
  and its synthetic connector imports; the generic conformance detector,
  codec/rights/typing checks and statuses remain.
- - `xtask`: removed the `Fixtures` task variant, its dispatch, help/list entries and
  the journal golden allowlist; `e2e` no longer special-cases the stress suite. Retired
  target names remain only as rejection values in the e2e allowlist test.
- - `.github/workflows/live.yml`: removed the live venue test steps, credential
  references and evidence script invocation; the workflow is now a fail-closed
  retirement notice. No provider action is authorised.
- - `scripts/check_architecture.py` and `scripts/check_style.py`: removed responsibility
  mappings and the raw-wire fixture exemption for deleted paths.
- - `scripts/check_matrix_tests.py`: removed the six mandatory mock-exchange evidence
  tests retired with their targets; all remaining requirement rows keep at least one
  file-qualified test reference.
- - `README.md`, `docs/*`, `Cargo.toml` comments and historical records: removed active
  guidance and links to deleted assets. Dated W1.1/W1.2 policy and evidence records are
  preserved verbatim apart from an explicit historical notice; their reported counts are
  not rewritten.

No `Makefile` target in this repository referenced a deleted asset: Fieldbook's
`Makefile` is a facade over `cargo xtask` and never defined `kdb-golden`,
`fundamental-fixture-check` or `cpp-test` (those belong to the paired Nirnay repository
and its own gate). The Fieldbook `cargo xtask fixtures` command was removed as recorded
above.

## 5. Historical counts preserved (not rewritten)

- - `docs/synthetic-test-policy-2026-11-23.md` (W1.1): 558 passed and 12 ignored on the
  verified run, including 105 active declared market-shaped integration tests in 15
  targets, 52 shared support declarations, and 249 gated unit declarations. These are
  historical figures and remain unchanged.
- - `docs/programme-status.md` (W1.2): the 850-test 2026-11-18 export count and
  associated claims remain unchanged.
- No approved document digest in the workspace registry was edited by this PR.

## 6. Current permitted test result (this change)

Measured on branch `chore/rrp-002` with the pinned toolchain; counted by `cargo test
--workspace --all-targets --locked` plus `cargo test --workspace --doc --locked`. These
are Fieldbook-only results and must not be combined with Nirnay Python or Nirnay Rust
counts.

| Command | Passed | Failed | Ignored |
|---|---:|---:|---:|
| `cargo test --workspace --all-targets --locked` | 561 | 0 | 12 |
| `cargo test --workspace --doc --locked` | 1 | 0 | 0 |

Static gates `cargo xtask fmt`, `lint`, `docs`, `style` and `verify` pass on this tree.
Static-gate results and test-suite results are separate claims.

## 7. Coverage withdrawn

The following validation is no longer executable. It must not be treated as evidence of
current order-book, decoder, journal-golden or capacity behavior:

- - mock-exchange end-to-end book continuity, failover, discovery churn, negative
  controls and subscription-scale cells;
- - full-universe stress, hot/quiet, burst, backpressure, disconnect, lifecycle churn
  and capacity cells with their shared support module;
- synthetic Hyperliquid book, telemetry and capacity loopback tests;
- live venue integration targets that used invented test market identities;
- synthetic codec/bench measurements driven by invented market observations;
- checked-in Kalshi/Polymarket golden fixture decode tests and v1/v2 golden journal round trips;
- - source-conformance and evidence-pipeline tests built on fabricated trade payloads,
  and synthetic fixture-connector modality tests.

Retained and executable: scalar/numeric tests, arbitrary-byte journal framing and
durability tests, rights/authorization tests, hashing/signature tests, abstract
timestamp tests, type-level capability declarations and generic storage/reference
pipelines. No replacement synthetic observation, price bar, order book, trade, universe,
reference history or strategy return was created.

## 8. Reporting category

Implemented and statically gated; tests executed with abstract mathematical and
arbitrary-byte inputs only. No order-book, decoder or venue claim is verified against
real observations. Order-book and decoder validation remains blocked until permitted
real data exists or the owner changes D11 through a separate versioned decision.
