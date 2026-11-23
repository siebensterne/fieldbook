# Fieldbook product-scope retirement — 2026-11-23

**Record:** `docs/product-scope-retirement-2026-11-23.md`
**Date:** 2026-11-23
**Programme:** RRP-003 — Fieldbook product-scope retirement
**Authority:** owner directive D11 (RRP-001), gate RRP-003 in `RETIREMENT-ACCEPTANCE.md`
**Branch / base:** `chore/rrp-003`, base commit `b0cbf4d` (Fieldbook)
**Rights effect:** none. No provider was contacted, no right or dataset changed,
no collection, experiment or live execution was run, and no Git history was
rewritten. Every path below was removed with an ordinary `git rm`; the blob and
its history remain. This record adds hashes and counts only — it creates no new
data and no replacement synthetic observation.

This is the dated path/hash/size record for the crypto and prediction-market
product-scope removal. Every SHA-256 and byte size below was measured with
`shasum -a 256` and `stat -f %z` on the bytes actually removed from this branch
head `b0cbf4d`. The Fieldbook retirement manifest measured the same paths at its
reviewed head `3c3279b`; where a value differs, the intervening RRP-002 PR
edited that file (for example, removing market-shaped test modules) before this
retirement. Four paths are absent from the manifest altogether
(`measurements/live/2026-11-14-universe-capacity/*` and
`measurements/remediation/remediation-discover-offset-cap.log`; their message
text is about the retired Polymarket feed) and were hashed directly here.

## 1. Scope boundary

Removed: the seven non-target venue adapter families and their module
registrations; provider-specific configs, scripts and docs; obsolete
prediction-market measurements including the large failed-universe capture
report; synthetic stress artefacts; provider-specific capability claims, CLI
defaults and README commands.

Retained unchanged in kind: `src/acquisition/{session,transport,egress,arbiter,
supervisor,codec,packet,evidence,stream_slice,ws}.rs`, the venue-neutral
`Exchange` contract in `src/acquisition/exchange/mod.rs`, `src/integrity/`
journal and replay, `src/governance/`, the domain layer, storage and analytics,
and all W1.1/W1.2 governance records. Generic infrastructure was audited and
adapted only where it referenced a deleted adapter; none was removed.

## 2. Removal counts

| Group | Files removed | Bytes at reviewed head |
|---|---:|---:|
| D11-D crypto/prediction adapter families | 32 | see section 3 |
| D11-D provider config/script | 5 | see section 3 |
| D11-E obsolete measurement/stress | 61 | see section 3 |
| D11-F provider-specific documentation | 5 | see section 3 |
| **Total** | **103** | **37,008,726** |

The single largest removed file was
`measurements/live/2026-11-14-universe-capture-failed/report-summary.json`
(33,810,927 bytes). No `ARCHIVE`, `DEPRECATE`, `CONDITIONAL` or `KEEP` row was
deleted. `docs/operating-envelope.md` was replaced with a concise current-state
record rather than deleted; `measurements/README.md` was replaced with a dated
index that retains the retired digests.

## 3. Removed paths, digests and sizes

### D11-D — crypto/prediction adapter families
| Path | SHA-256 | Size (bytes) |
|---|---|---:|
| `src/acquisition/exchange/binance/codec.rs` | `9d8640c6ec7fec2515f66cc1123e8d4b92f3fb8128023a915f827eb2252c7d91` | 10,885 |
| `src/acquisition/exchange/binance/discovery.rs` | `5c79c5faa11864c237944f1fd21732b21cabe90eb3318bb75a6a58c29e57970a` | 3,214 |
| `src/acquisition/exchange/binance/mod.rs` | `e8d6575324ae89f1525f0844db73be86c93858f4e1896f23f20e5a7e3ab0c8d3` | 4,876 |
| `src/acquisition/exchange/binance/session.rs` | `f9dc34700194b4bd4c9432f495e7e7ab315c400e2385f46237d425b2dbdac002` | 4,358 |
| `src/acquisition/exchange/coinbase/codec.rs` | `35a0b3d20ab743384465b03d909614dca2f0d835947ccb198893d9b38c1f7aaf` | 9,405 |
| `src/acquisition/exchange/coinbase/discovery.rs` | `bfe903df35b956688c2e77fed8c0e7eeca717629f835eb9ab8da95cec199299d` | 3,000 |
| `src/acquisition/exchange/coinbase/mod.rs` | `0ad2c7aef1a636bdde351a7feb0ebfe841d2a4836ddf0020169ecb1e3dc3351a` | 5,040 |
| `src/acquisition/exchange/coinbase/session.rs` | `4bb2ad4eb6329ab639564a3c20e91eb2456ec31241774453dad55877f891e58d` | 3,357 |
| `src/acquisition/exchange/hyperliquid/books.rs` | `400528eb9a732f5e954588de3d06c097edb0e348bfd43d90ea44492f2aad42e7` | 14,790 |
| `src/acquisition/exchange/hyperliquid/codec.rs` | `d3ce909e39c5aa75d7aeb2fb3676fb23847c2e8ecd69b765e502d92d8374cf09` | 8,748 |
| `src/acquisition/exchange/hyperliquid/discovery.rs` | `67ef8d1694a4dfcb6e3b394ac95e92c51bc001b26a920aa7de9af7b59c8e6434` | 4,537 |
| `src/acquisition/exchange/hyperliquid/mod.rs` | `641c5eb493f7ba8106bc63e9d938a7ad1dcae40d0fe11ec105ce437e827422f3` | 6,394 |
| `src/acquisition/exchange/hyperliquid/session.rs` | `a4a29b5b771e9b7f0d440e34e1469a73183a80ab54b9ad9f0614cc5a267d75e6` | 19,074 |
| `src/acquisition/exchange/hyperliquid/telemetry.rs` | `3b86bc22dfb04ea3a4307d1768af94c80447d596452e509f114925c32aa127fc` | 14,238 |
| `src/acquisition/exchange/kalshi/auth.rs` | `7e2c30790dd5f8d5152c44c2ccfa477a394adaed0ffd6809433640b09900decd` | 8,798 |
| `src/acquisition/exchange/kalshi/codec.rs` | `db196f91566e4f42398ebb60f8a805f52776556d58003099cce3346834ead0fd` | 27,475 |
| `src/acquisition/exchange/kalshi/discovery.rs` | `0f205895f40bb591e73bee4038013b5d5e845b32ef1f1f813b77e443034b0210` | 15,175 |
| `src/acquisition/exchange/kalshi/discovery/tests.rs` | `8aa49813c14a44e1fab9dff8141370752bbd0eb02494f79fa18f1f0d107105af` | 25,861 |
| `src/acquisition/exchange/kalshi/mod.rs` | `9dca58efde954fcb980ee10567484785faa88bc2cd95bb28f7432509a02f58a5` | 4,361 |
| `src/acquisition/exchange/kalshi/session.rs` | `02e7ad358c69914d955235f57fa3a9fad37ebbf204fbde89e3ea5706b60b937c` | 85,447 |
| `src/acquisition/exchange/kraken/codec.rs` | `cb1fa86ed3022a91ccab29a8460b7af39169e8ae644d2d1c1ffe6d72d0be3abf` | 9,705 |
| `src/acquisition/exchange/kraken/discovery.rs` | `a0aab0f7c5ef7bdb9efe5dd1afa85feb87118576789f9fb0d098206103f9544e` | 3,745 |
| `src/acquisition/exchange/kraken/mod.rs` | `56f59343756ba5d2001316ab139cc8c279faf565c871154fc76865c10b4ba3fe` | 4,136 |
| `src/acquisition/exchange/kraken/session.rs` | `a1c95eb84efc3271fd4dfcc11025f887502d9478b009052ee9750db7e827ae73` | 1,687 |
| `src/acquisition/exchange/okx/codec.rs` | `d0710825ecab4321d338a98fb0070e59ce797042686d468df8bc10b42d41f76b` | 10,857 |
| `src/acquisition/exchange/okx/discovery.rs` | `f87141b1944596f556852f1ec0443db2dcab4e5312680774a8038f82dead4711` | 2,523 |
| `src/acquisition/exchange/okx/mod.rs` | `1709750edf9d6b6061935dd50107507fd13aeb084b0fca9115bae4f0b31c0ed1` | 4,957 |
| `src/acquisition/exchange/okx/session.rs` | `a3108ae78317d04ba9ad3a65fb08c774cd134bcb2b0ec6fce5920cba1f749617` | 3,544 |
| `src/acquisition/exchange/polymarket/codec.rs` | `cfa6ed43b45df2810fc3ba67fc4d6a71c2e78fae42c52cd093fb709c18802747` | 23,600 |
| `src/acquisition/exchange/polymarket/discovery.rs` | `fdf0d361a3185556ce95858e4998efa537b1fd19c846e77e1eabf43d28798010` | 39,420 |
| `src/acquisition/exchange/polymarket/mod.rs` | `fb765c81c363e63e3df2b592fe00f1b2e6677f4919bf8c90719f6b93b0e04c23` | 3,259 |
| `src/acquisition/exchange/polymarket/session.rs` | `6abe0f9e29f287920c4fed45e48b1e7899554275c39c759a1ecfb4e86053998d` | 29,600 |

### D11-D — provider configs and scripts
| Path | SHA-256 | Size (bytes) |
|---|---|---:|
| `config.hyperliquid-recovery.example.toml` | `ee69da1fe018a2a58ae8ce13e3126002f711e993fb5043fdef6920efe7e1bcab` | 673 |
| `config.live-universe.toml` | `2bbbe6d9942e55dd9bf44c8da858d6ef5c1ca0e0bc02482fc8444f9392ed2d01` | 1,858 |
| `config.polymarket.example.toml` | `d60b014cdd614f119e9461481153b60557d6ccad7b53646d9197f35cbfc9bf26` | 2,817 |
| `scripts/run-hyperliquid-evidence.sh` | `26a80572a9dab17135eab1d3b6ac9e1fc80f3956846647a707be16598b5773ab` | 12,443 |
| `scripts/run-live-evidence.sh` | `213b81c93036d7169ed0b301fc327fe557d0e25ec3d9a882b9ff3ee01a05d3a2` | 15,739 |

### D11-E — obsolete measurement and stress artefacts
| Path | SHA-256 | Size (bytes) |
|---|---|---:|
| `measurements/live/2026-11-14-polymarket-smoke-verified/README.md` | `1af561e1b0a69518415f61df07a57d638d10e7b1e1a0e489590110b491b8b533` | 1,119 |
| `measurements/live/2026-11-14-polymarket-smoke-verified/completeness.json` | `2e3774e4e9b349e13048ed14599ba9abcd25e29c50586cb85d775e46521087d4` | 862 |
| `measurements/live/2026-11-14-polymarket-smoke-verified/coverage.json` | `4104cf1c7dd15bc06eaf53c97f7b0bfcd5337204c5872c2ad769febc0bfb6b4c` | 1,389 |
| `measurements/live/2026-11-14-polymarket-smoke-verified/evidence.json` | `7847daf5f0b995d4e923897999ba523dfba48dec0edde17457d88794e07f8cdb` | 1,992 |
| `measurements/live/2026-11-14-polymarket-smoke-verified/journal-verify.json` | `3a19ec6fb4cbde2f6e0aefad279fa32f170eed96b3420b514d379e10763f4296` | 700 |
| `measurements/live/2026-11-14-polymarket-smoke-verified/run-manifest.json` | `42281b4af8d3476a3f89192a5c2243e1e16fe9dc725198625eb2dc8229517b51` | 744 |
| `measurements/live/2026-11-14-polymarket-smoke-verified/sbe-verify.json` | `335314cd8f2a49444a08f91512bf46e3a13f724323adf847cb0ee58355197d69` | 884 |
| `measurements/live/2026-11-14-universe-capacity/README.md` | `679466fe3bbe43d8f3f1284f0681cad09889a2074fb26ce3811d072c57cf0e0a` | 1,583 |
| `measurements/live/2026-11-14-universe-capacity/collector.log` | `de1ad154f0ebc36d9f7c0a0701a556ce9ec1efb2dc1e6ceb8d101619c2095eae` | 205 |
| `measurements/live/2026-11-14-universe-capacity/run-manifest.json` | `a81100075241203eeb47b193d3adddb228815162d88408770191da67bc8b3a39` | 601 |
| `measurements/live/2026-11-14-universe-capture-failed/README.md` | `7722f8cd5a2e21235dc1e679413e6b6e612561d1e6d8b7a2fcfa02d74dddc538` | 4,712 |
| `measurements/live/2026-11-14-universe-capture-failed/collector.log` | `82cf00e036eed67388f447fc87b6fd4d45cd817c76c387e1d532848ebeffb764` | 2,107,664 |
| `measurements/live/2026-11-14-universe-capture-failed/hashes.txt` | `db93820fe1167fd75788995a501316286d9a61971807198b44aebb10a8bf05e6` | 407 |
| `measurements/live/2026-11-14-universe-capture-failed/report-summary.json` | `99539956c27e43bbdf828afd4b70e13ba3e38655f9cb243f0e168a1013587ccd` | 33,810,927 |
| `measurements/live/2026-11-14-universe-capture-failed/run-manifest.json` | `013bcb8007cc42bf18c4ffb517bf2da00667711fad7dc4942e69fe236c816382` | 601 |
| `measurements/live/2026-11-14-universe-capture-failed/sbe-verify.json` | `aeb28d621b6fd72b7fbd9b8a2f356e1274cd667318a01da7d25e7d9c08a5bd58` | 57,535 |
| `measurements/live/2026-11-14-universe-capture-failed/sbe-verify.log` | `6b06aade85a542ec320f5c6039fcf04da421cda2061c09b6b26fba0c7a1c192a` | 118 |
| `measurements/polymarket-latency-2026-10-23.json` | `b6023e8e80332f91dfcc07c4f102b4d740e2d73d8708aab0ae7df4d95ae3eaa2` | 853 |
| `measurements/polymarket-latency-2026-11-15.json` | `5c2454197d7f439e43f534406a23571ad00e1c85d31714987888c306aad60b96` | 2,181 |
| `measurements/polymarket-latency-baseline-2026-10-24.json` | `6cbda024f81243699538aa708f0199450c0cd9c9833f64853be5e2572110be13` | 2,181 |
| `measurements/polymarket-latency-nodelay-off-2026-10-24.json` | `ebc471d87c9d892bbade334222291ad43b53894337a5d771637afb7e46a80198` | 2,202 |
| `measurements/polymarket-latency-portpin-2026-10-24.json` | `ce087a0a94dc9827f5c0fbfc7418f905357b1820f5700b9f6b5873915d8321c4` | 2,193 |
| `measurements/polymarket-latency-race4-2026-10-24.json` | `be3686f284587287c62e7a861f790a0da2f79dac172730e9253ccf003b7a2aa4` | 2,180 |
| `measurements/polymarket-smoke-markets.json` | `9f5bcf6417464335d2c8239e4ca7ec2e347d5f03905ba65e6c1f3487dc859513` | 7,857 |
| `measurements/polymarket-smoke-report.json` | `1c36fee1ef16ccbc5949779b22b3b7bc3d17af44463001eb99d1d725e845df43` | 5,375 |
| `measurements/remediation/remediation-discover-offset-cap.log` | `2d33d81e5b4475a43645153749bed9ff7e10cd065b0846e545091db45b5d4061` | 188 |
| `measurements/remediation/remediation-polymarket-scale-markets.json` | `9442010b368cf19d86c61e0edf82ab79dae902f0a515dddacbaebdf1c6c3e9f8` | 31,442 |
| `measurements/remediation/remediation-polymarket-scale-report.json` | `8ff63677e293bd4dcca0a16543453b6020d6ce140044abbfbbca85b1abe14946` | 3,220 |
| `measurements/remediation/remediation-polymarket-smoke-markets.json` | `9036f6e0b19dfdd943d1e35072848996be6f17c3283397e46b33f76e6748e104` | 2,138 |
| `measurements/remediation/remediation-polymarket-smoke-report.json` | `7aa16972d65f598c39c9ef8d1bed54e1bd2d8b465d9d33d1af610a4e2ccca89c` | 2,387 |
| `measurements/stress/README.md` | `a46b68fc52e02904b91aa0e1e9c4bd5a2100eb0465abb9a9acacfa5287ba77f3` | 7,093 |
| `measurements/stress/failed-seed-0009-1000-collector_terminated_early__max_total_connections_must_be____replicas.json` | `680e67e9bc644bd18d1475262eeb728600c7a88e491bba79bb4a2f774847c181` | 6,380 |
| `measurements/stress/failed-seed-000b-200-coverage_set_mismatch.json` | `ac2edeb5e834ec31bddd980dafe4071713bed8f970be1a572e70c7252ba1e4d0` | 6,335 |
| `measurements/stress/failed-seed-000d-300-unexplained_drops.json` | `aa9115d747a865d3a8851a2d4e6f14ff5c4976705e82ce37c39dc179d3fcb9c1` | 6,170 |
| `measurements/stress/failed-seed-000e-200-coverage_set_mismatch.json` | `926213ba691edeb37a7153f7f72cae8c93b66b3e64dc18d0ecc44a325809406d` | 6,396 |
| `measurements/stress/failed-v3-seed-000b-200-coverage_set_mismatch.json` | `d1b5e9931d8847855e628f9aa786c8f1065b932fee20593f7c02e75c0ee593e2` | 6,643 |
| `measurements/stress/failed-v4-seed-000b-200-coverage_set_mismatch.json` | `b238a440155e66c09f2127278a5806fac7e8d9563ca5aba9058f8c60d810d8e9` | 6,958 |
| `measurements/stress/failed-v5-seed-000b-200-coverage_set_mismatch.json` | `97e5e873aa3e65ce0e9f900026e6ba5d6f5b03104452df28252ba36ccb8f72d5` | 7,287 |
| `measurements/stress/index.json` | `3908cbdb809aef21beb6179c9ab0d338d17f5c54236c5b108a099604d29295e2` | 5,593 |
| `measurements/stress/m5-v16-bundle/failed-v16-seed-0029-200-coverage_set_mismatch.json` | `cc0b83ad6280dbde91a5ad334d9b580c28054fd954d498395b550d87fd668885` | 24,631 |
| `measurements/stress/m5-v16-bundle/failed-v16-seed-002b-200-disposition_excess.json` | `7bf695ba1a249bceeec5a82afabe8ada12a5320df3909c7e9caa764247266f54` | 32,125 |
| `measurements/stress/m5-v16-bundle/failed-v16-seed-002c-200-journal_pressure_rejected.json` | `0441c40d1d48d286554ad35b5f170f1310ae39c1796b93675b1a1222c7ad3605` | 14,410 |
| `measurements/stress/m5-v16-bundle/hyperliquid-balanced-v16-seed-000b.json` | `f985e159a9b5b487a2b685ab921fb3573b3472d1440ee9b39f916eba275f5e22` | 5,033 |
| `measurements/stress/m5-v16-bundle/incomplete-v16-seed-0024-2000-drain_incomplete.json` | `d18f8f91c18da8c9ffe232ff8dba7ed923a70e645bf8a11f03c26725e67456d3` | 44,693 |
| `measurements/stress/m5-v16-bundle/index.json` | `e910659319e410c828133a88eac36e77638f3d29f25e9c93bbffd5f93c94fa9f` | 2,839 |
| `measurements/stress/m5-v16-bundle/ledger.json` | `009cb78f89a3e9f9856d9cdaac2a286106d594551bbd923b80eea11382ce3b27` | 3,104 |
| `measurements/stress/m5-v16-bundle/seed-001f-4000-step-v16.json` | `930c3e8d16c724e062ec3e4c5c6e27c2aee83461ad1dc8795eff64eacd2a2166` | 31,914 |
| `measurements/stress/m5-v16-bundle/seed-0029-4000-uniform-lifecycle-churn_under_load-v16.json` | `c780b210940fe4b1d7ee5a4025abcd061b4c164dd48493afc96e580431b13685` | 33,940 |
| `measurements/stress/m5-v16-bundle/seed-002a-200-uniform-v16.json` | `8ac4e8ac06a3537890e8cc4067b3971e17a5dc6c28c52e26456a5df14e8765ea` | 31,860 |
| `measurements/stress/m5-v16-bundle/seed-5eed2710-10000-hotquiet-v16.json` | `810540c8738d7f64b0c9f5a879a1647d08b935616ee1cfe2c6d51ebc3d610040` | 32,886 |
| `measurements/stress/seed-0007-4000-uniform-v3.json` | `fc457b4898020edf19c97574e3b60cc84196dec195be08cfcb3ab00d145498c0` | 6,542 |
| `measurements/stress/seed-0007-4000-uniform-v4.json` | `b3876106052a40834bd6ebb29ee57e46a942fa2437efb38b31bb1ff33f93aa46` | 6,858 |
| `measurements/stress/seed-0007-4000-uniform-v5.json` | `4274630d758d6cedf559932d70462dbcc1e374383b5a2fc2e6590ff2ce9cb4b3` | 7,189 |
| `measurements/stress/seed-0007-4000-uniform.json` | `4f499b179f89d5375a20a12711e49e4798e73498d9ba601b98f893f05ad56704` | 6,118 |
| `measurements/stress/seed-0017-4000-hotquiet-v3.json` | `bab6d9a1f18092b55636c89a60e517f8d3fcf355da3e2840f6a4edc59167a01f` | 6,555 |
| `measurements/stress/seed-0017-4000-hotquiet-v4.json` | `8d70592e0f6b84b8542c88444ed3ea7403bb516365ef6cc4516e60b96e1f1958` | 6,872 |
| `measurements/stress/seed-0017-4000-hotquiet-v5.json` | `d8790eb6f3f5be6ce36a9ff45540818e0abdfc09f180563fb90f985b1396b2f5` | 7,204 |
| `measurements/stress/seed-0017-4000-hotquiet.json` | `b3440eab67f6e4b1b818fd9bb1aaf26aa17f9d44eeca1135b01773bb311855f7` | 6,240 |
| `measurements/stress/seed-001d-4000-hotquiet-v3.json` | `0905907839f809bbc79f58a090163fa4c239ac1d574c156533dc878a09637b99` | 6,558 |
| `measurements/stress/seed-001d-4000-hotquiet-v4.json` | `ede87b38e9e153ca076e9c8d127d0d3c53e82338d4d12fd7afebc5d47ceda446` | 6,875 |
| `measurements/stress/seed-001d-4000-hotquiet-v5.json` | `cc4f4577a8313617ddacb53b0834a427c719af19bfe53e617f5112d3d37d3ea1` | 7,207 |

### D11-F — provider-specific documentation (deleted)
| Path | SHA-256 | Size (bytes) |
|---|---|---:|
| `docs/hyperliquid-integration-plan.md` | `71f87c5690cd1ecc1fc4b67810a19bc016cdf5a993a0fa8680f00a785dc2bd50` | 32,100 |
| `docs/latency.md` | `ae64f283154df8623269fe1e95ae845492626d76da3409ca82834cc77cf41087` | 10,244 |
| `docs/live-evidence-runbook.md` | `451fd46346cf213bf9a683160123ae1d0812ed00af26df0f14d8bb875fa4b921` | 15,786 |
| `docs/stress-lab-design.md` | `2d01fe093ce8bfbdc62bfdae34aec532a3e5bd1463d8524741af7b1bb2dbc814` | 15,046 |
| `docs/workload-spec.md` | `bcd53d9aee56b9a25606d6c7c3544d896039ee04493b7bdddfeb5f0994b08246` | 39,006 |

## 4. Registration and reference updates

- `src/acquisition/exchange/mod.rs`: removed all seven `pub mod` / `pub use`
  adapter registrations and the venue-to-capability mapping tables. The
  venue-neutral `Exchange` trait, `ExchangeCapabilities`, `DiscoveryStats`,
  `DiscoveryResult` and conservative offline capability functions remain.
- `src/distribution/coordinator.rs`: `build_exchange` is the single fail-closed
  composition root; no concrete adapter is constructed. `collect`, `discover`
  and `latency` deny before a client or socket is created.
- `src/governance/config.rs`: removed `ExchangeKind`, `KalshiEnvironment` and
  all seven provider settings types and their fields, CLI/environment defaults,
  endpoint claims and provider validation. Added `Settings::for_venue` for an
  explicit non-secret venue label. Generic collector/network/output/journal/
  metrics/governance config and all validation are retained.
- `src/distribution/cli.rs`: removed `--exchange`, `--kalshi-environment`,
  `--kalshi-key-id` and `--kalshi-private-key`; the command description now
  names the securities platform.
- `src/distribution/probe.rs`, `src/storage/capacity.rs`, `src/storage/report.rs`,
  `src/integrity/replay.rs`, `src/market_state/collector/state.rs`: adapted to
  the generic venue label and fail-closed capability declaration. No generic
  path was deleted.
- Provider-specific tests that constructed deleted adapters or decoded their
  wire formats were removed; scalar, arbitrary-byte, rights, hashing,
  type-level and state-machine tests remain.
- `config.example.toml` rewritten as a venue-neutral template with no
  credentials, venue endpoints or capability claims; the three provider config
  files were deleted.
- `README.md` rewritten for the securities platform; no Kalshi, Polymarket or
  Hyperliquid command or capability claim remains. Single-document authority
  rules are retained.
- `docs/operating-envelope.md` replaced with a concise current-state record.
- `docs/requirement-test-matrix.md`, `docs/performance-methodology.md`,
  `AGENTS.md`, `CONTRIBUTING.md`, `src/integrity/latency.rs`,
  `Cargo.toml` description and `scripts/check_architecture.py` were adapted so
  no active text points at a retired path or test.
- `measurements/README.md` replaced with a dated index of retired digests and
  preserved evidence.
- `scripts/test_check_naming_conventions.py` examples now use retained paths.
- `.github/workflows/live.yml` remains a fail-closed retirement notice; no
  venue credential or secret reference exists in CI.

## 5. Preserved evidence (no market data)

The following non-market durability evidence is retained **in place**, with its
original bytes, commands, hashes and stated limitations. It is listed as
`KEEP` in the Fieldbook retirement manifest and is not provider-origin market
data:

- `measurements/live/2026-11-18-postgres-checkpoint-integrity/`
- `measurements/live/2026-11-18-postgres-checkpoint-integrity-head-7edfb92/`
- `measurements/live/2026-11-18-postgres-source-scoped/`
- `measurements/live/2026-11-18-postgres-source-scoped-merged/`
- `measurements/live/2026-11-19-postgres-legacy-source-mapping/`
- `measurements/live/2026-11-19-postgres-bounded-batch/`
- `measurements/live/2026-11-19-postgres-streaming-runner/`

Recorded limitations stay unchanged: a single local PostgreSQL 18.6 server on a
Unix socket; no cross-host replication, backup, restore or zero-loss claim; no
market-data, provider or redistribution right. The original commands and
per-file SHA-256 values remain in each `command.txt` / `collector.log`,
`evidence.json` and `output.log`. `measurements/perf/p6-1-*` (`CONDITIONAL`)
is unchanged.

## 6. Historical records preserved (not rewritten)

- `docs/synthetic-test-policy-2026-11-23.md` (W1.1) and its reported counts.
- `docs/programme-status.md` (W1.2) historical counts and claims.
- `docs/synthetic-asset-retirement-2026-11-23.md` (RRP-002) digests and counts.
- Workspace approved document digests in `ENGINEERING-DOC-DIGESTS.json`,
  `ADR-REGISTRY.md`, `NDC-REGISTRY.md` and `TOOL-MATRIX.md`.
- Historical venue names remain only in dated retirement records and rejection
  values; they are not active capability claims.

## 7. Test and gate results (this change)

Measured on branch `chore/rrp-003` with the pinned toolchain:

| Command | Result |
|---|---|
| `cargo xtask fmt` | passed |
| `cargo xtask lint` | passed |
| `cargo xtask docs` | passed |
| `cargo xtask style` | passed |
| `cargo xtask verify` | passed |
| `cargo test --workspace --all-targets --locked` | 553 passed, 0 failed, 12 ignored |
| `cargo test --workspace --doc --locked` | 1 passed, 0 failed |

These are Fieldbook-only results, tied to this tree, and must not be combined
with Nirnay Python or Nirnay Rust counts. Static gates and test-suite results
are separate claims; no synthetic market observation was created to obtain them.

## 8. Report category

Implemented and statically gated. Tests were executed with abstract, scalar,
arbitrary-byte and type-level inputs only. No order-book, decoder, venue,
capacity, latency or live-readiness claim is verified against real
observations. No new synthetic observation, price bar, order book, trade,
universe, reference history or strategy return was created.
