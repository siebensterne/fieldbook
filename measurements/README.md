# Measurements index — 2026-11-23 (post RRP-003)

This is the concise dated index of the measurement tree after the Fieldbook
product-scope retirement. It records what was retired (path, SHA-256, byte
size) and what durability evidence is preserved. No file was history-purged:
each retired path was removed with an ordinary `git rm` and its blob remains in
Git history. This index adds no new measurement and contacts no provider.

## 1. Preserved durability evidence (non-market)

The following directories are retained **verbatim** under `measurements/live/`.
They contain real, local-PostgreSQL delivery/checkpoint evidence — not market
observations, not provider-origin data and not a venue capability claim. Each
directory keeps its original `command.txt` / `collector.log`, `evidence.json`
and `output.log` with original bytes, hashes, commands and stated limitations.
They are listed as `KEEP` rows in the Fieldbook retirement manifest.

| Preserved directory | Evidence scope | Command (recorded in `command.txt` / `evidence.json`) |
|---|---|---|
| `measurements/live/2026-11-18-postgres-checkpoint-integrity/` | checkpoint checksum, stale writer, exact retry | `NIRNAY_TEST_PG_URL=... cargo test --test postgres_live --offline -- --ignored --nocapture` |
| `measurements/live/2026-11-18-postgres-checkpoint-integrity-head-7edfb92/` | same test at main head `7edfb92` | same command |
| `measurements/live/2026-11-18-postgres-source-scoped/` | two sources, isolated checkpoints, restart | same command |
| `measurements/live/2026-11-18-postgres-source-scoped-merged/` | same test at merged head `200bbf1` | same command |
| `measurements/live/2026-11-19-postgres-legacy-source-mapping/` | legacy checksum and source-mapping integrity | same command |
| `measurements/live/2026-11-19-postgres-bounded-batch/` | bounded ordered batch delivery | `FIELDBOOK_TEST_PG_URL=... cargo test --test postgres_batch_live -- --ignored --nocapture` |
| `measurements/live/2026-11-19-postgres-streaming-runner/` | durable streaming runner | `FIELDBOOK_TEST_PG_URL=... cargo test --test postgres_live -- --ignored --nocapture` |

Original per-file digests are preserved inside each `evidence.json` and in the
manifest `KEEP` rows. Limitations stay as recorded: a single local PostgreSQL
18.6 server over a Unix socket, no cross-host failure domain, no replication,
backup/restore or zero-loss claim, and no market-data or provider right.

## 2. Retired measurement paths (path, digest, size)

The 61 paths below were removed on 2026-11-23 under RRP-003. They are obsolete
prediction-market crypto captures, timing claims, remediation reports and
synthetic stress artefacts. Per-group totals: Polymarket live captures 17,
Polymarket latency/smoke/remediation JSON 13, stress bundle 31. The 33,810,927
byte `2026-11-14-universe-capture-failed/report-summary.json` was the large
failed-universe capture report.

| Retired path | SHA-256 | Bytes |
|---|---|---:|
| `measurements/live/2026-11-14-polymarket-smoke-verified/README.md` | `1af561e1b0a69518415f61df07a57d638d10e7b1e1a0e489590110b491b8b533` | 1119 |
| `measurements/live/2026-11-14-polymarket-smoke-verified/completeness.json` | `2e3774e4e9b349e13048ed14599ba9abcd25e29c50586cb85d775e46521087d4` | 862 |
| `measurements/live/2026-11-14-polymarket-smoke-verified/coverage.json` | `4104cf1c7dd15bc06eaf53c97f7b0bfcd5337204c5872c2ad769febc0bfb6b4c` | 1389 |
| `measurements/live/2026-11-14-polymarket-smoke-verified/evidence.json` | `7847daf5f0b995d4e923897999ba523dfba48dec0edde17457d88794e07f8cdb` | 1992 |
| `measurements/live/2026-11-14-polymarket-smoke-verified/journal-verify.json` | `3a19ec6fb4cbde2f6e0aefad279fa32f170eed96b3420b514d379e10763f4296` | 700 |
| `measurements/live/2026-11-14-polymarket-smoke-verified/run-manifest.json` | `42281b4af8d3476a3f89192a5c2243e1e16fe9dc725198625eb2dc8229517b51` | 744 |
| `measurements/live/2026-11-14-polymarket-smoke-verified/sbe-verify.json` | `335314cd8f2a49444a08f91512bf46e3a13f724323adf847cb0ee58355197d69` | 884 |
| `measurements/live/2026-11-14-universe-capacity/README.md` | `679466fe3bbe43d8f3f1284f0681cad09889a2074fb26ce3811d072c57cf0e0a` | 1583 |
| `measurements/live/2026-11-14-universe-capacity/collector.log` | `de1ad154f0ebc36d9f7c0a0701a556ce9ec1efb2dc1e6ceb8d101619c2095eae` | 205 |
| `measurements/live/2026-11-14-universe-capacity/run-manifest.json` | `a81100075241203eeb47b193d3adddb228815162d88408770191da67bc8b3a39` | 601 |
| `measurements/live/2026-11-14-universe-capture-failed/README.md` | `7722f8cd5a2e21235dc1e679413e6b6e612561d1e6d8b7a2fcfa02d74dddc538` | 4712 |
| `measurements/live/2026-11-14-universe-capture-failed/collector.log` | `82cf00e036eed67388f447fc87b6fd4d45cd817c76c387e1d532848ebeffb764` | 2107664 |
| `measurements/live/2026-11-14-universe-capture-failed/hashes.txt` | `db93820fe1167fd75788995a501316286d9a61971807198b44aebb10a8bf05e6` | 407 |
| `measurements/live/2026-11-14-universe-capture-failed/report-summary.json` | `99539956c27e43bbdf828afd4b70e13ba3e38655f9cb243f0e168a1013587ccd` | 33810927 |
| `measurements/live/2026-11-14-universe-capture-failed/run-manifest.json` | `013bcb8007cc42bf18c4ffb517bf2da00667711fad7dc4942e69fe236c816382` | 601 |
| `measurements/live/2026-11-14-universe-capture-failed/sbe-verify.json` | `aeb28d621b6fd72b7fbd9b8a2f356e1274cd667318a01da7d25e7d9c08a5bd58` | 57535 |
| `measurements/live/2026-11-14-universe-capture-failed/sbe-verify.log` | `6b06aade85a542ec320f5c6039fcf04da421cda2061c09b6b26fba0c7a1c192a` | 118 |
| `measurements/polymarket-latency-2026-10-23.json` | `b6023e8e80332f91dfcc07c4f102b4d740e2d73d8708aab0ae7df4d95ae3eaa2` | 853 |
| `measurements/polymarket-latency-2026-11-15.json` | `5c2454197d7f439e43f534406a23571ad00e1c85d31714987888c306aad60b96` | 2181 |
| `measurements/polymarket-latency-baseline-2026-10-24.json` | `6cbda024f81243699538aa708f0199450c0cd9c9833f64853be5e2572110be13` | 2181 |
| `measurements/polymarket-latency-nodelay-off-2026-10-24.json` | `ebc471d87c9d892bbade334222291ad43b53894337a5d771637afb7e46a80198` | 2202 |
| `measurements/polymarket-latency-portpin-2026-10-24.json` | `ce087a0a94dc9827f5c0fbfc7418f905357b1820f5700b9f6b5873915d8321c4` | 2193 |
| `measurements/polymarket-latency-race4-2026-10-24.json` | `be3686f284587287c62e7a861f790a0da2f79dac172730e9253ccf003b7a2aa4` | 2180 |
| `measurements/polymarket-smoke-markets.json` | `9f5bcf6417464335d2c8239e4ca7ec2e347d5f03905ba65e6c1f3487dc859513` | 7857 |
| `measurements/polymarket-smoke-report.json` | `1c36fee1ef16ccbc5949779b22b3b7bc3d17af44463001eb99d1d725e845df43` | 5375 |
| `measurements/remediation/remediation-discover-offset-cap.log` | `2d33d81e5b4475a43645153749bed9ff7e10cd065b0846e545091db45b5d4061` | 188 |
| `measurements/remediation/remediation-polymarket-scale-markets.json` | `9442010b368cf19d86c61e0edf82ab79dae902f0a515dddacbaebdf1c6c3e9f8` | 31442 |
| `measurements/remediation/remediation-polymarket-scale-report.json` | `8ff63677e293bd4dcca0a16543453b6020d6ce140044abbfbbca85b1abe14946` | 3220 |
| `measurements/remediation/remediation-polymarket-smoke-markets.json` | `9036f6e0b19dfdd943d1e35072848996be6f17c3283397e46b33f76e6748e104` | 2138 |
| `measurements/remediation/remediation-polymarket-smoke-report.json` | `7aa16972d65f598c39c9ef8d1bed54e1bd2d8b465d9d33d1af610a4e2ccca89c` | 2387 |
| `measurements/stress/README.md` | `a46b68fc52e02904b91aa0e1e9c4bd5a2100eb0465abb9a9acacfa5287ba77f3` | 7093 |
| `measurements/stress/failed-seed-0009-1000-collector_terminated_early__max_total_connections_must_be____replicas.json` | `680e67e9bc644bd18d1475262eeb728600c7a88e491bba79bb4a2f774847c181` | 6380 |
| `measurements/stress/failed-seed-000b-200-coverage_set_mismatch.json` | `ac2edeb5e834ec31bddd980dafe4071713bed8f970be1a572e70c7252ba1e4d0` | 6335 |
| `measurements/stress/failed-seed-000d-300-unexplained_drops.json` | `aa9115d747a865d3a8851a2d4e6f14ff5c4976705e82ce37c39dc179d3fcb9c1` | 6170 |
| `measurements/stress/failed-seed-000e-200-coverage_set_mismatch.json` | `926213ba691edeb37a7153f7f72cae8c93b66b3e64dc18d0ecc44a325809406d` | 6396 |
| `measurements/stress/failed-v3-seed-000b-200-coverage_set_mismatch.json` | `d1b5e9931d8847855e628f9aa786c8f1065b932fee20593f7c02e75c0ee593e2` | 6643 |
| `measurements/stress/failed-v4-seed-000b-200-coverage_set_mismatch.json` | `b238a440155e66c09f2127278a5806fac7e8d9563ca5aba9058f8c60d810d8e9` | 6958 |
| `measurements/stress/failed-v5-seed-000b-200-coverage_set_mismatch.json` | `97e5e873aa3e65ce0e9f900026e6ba5d6f5b03104452df28252ba36ccb8f72d5` | 7287 |
| `measurements/stress/index.json` | `3908cbdb809aef21beb6179c9ab0d338d17f5c54236c5b108a099604d29295e2` | 5593 |
| `measurements/stress/m5-v16-bundle/failed-v16-seed-0029-200-coverage_set_mismatch.json` | `cc0b83ad6280dbde91a5ad334d9b580c28054fd954d498395b550d87fd668885` | 24631 |
| `measurements/stress/m5-v16-bundle/failed-v16-seed-002b-200-disposition_excess.json` | `7bf695ba1a249bceeec5a82afabe8ada12a5320df3909c7e9caa764247266f54` | 32125 |
| `measurements/stress/m5-v16-bundle/failed-v16-seed-002c-200-journal_pressure_rejected.json` | `0441c40d1d48d286554ad35b5f170f1310ae39c1796b93675b1a1222c7ad3605` | 14410 |
| `measurements/stress/m5-v16-bundle/hyperliquid-balanced-v16-seed-000b.json` | `f985e159a9b5b487a2b685ab921fb3573b3472d1440ee9b39f916eba275f5e22` | 5033 |
| `measurements/stress/m5-v16-bundle/incomplete-v16-seed-0024-2000-drain_incomplete.json` | `d18f8f91c18da8c9ffe232ff8dba7ed923a70e645bf8a11f03c26725e67456d3` | 44693 |
| `measurements/stress/m5-v16-bundle/index.json` | `e910659319e410c828133a88eac36e77638f3d29f25e9c93bbffd5f93c94fa9f` | 2839 |
| `measurements/stress/m5-v16-bundle/ledger.json` | `009cb78f89a3e9f9856d9cdaac2a286106d594551bbd923b80eea11382ce3b27` | 3104 |
| `measurements/stress/m5-v16-bundle/seed-001f-4000-step-v16.json` | `930c3e8d16c724e062ec3e4c5c6e27c2aee83461ad1dc8795eff64eacd2a2166` | 31914 |
| `measurements/stress/m5-v16-bundle/seed-0029-4000-uniform-lifecycle-churn_under_load-v16.json` | `c780b210940fe4b1d7ee5a4025abcd061b4c164dd48493afc96e580431b13685` | 33940 |
| `measurements/stress/m5-v16-bundle/seed-002a-200-uniform-v16.json` | `8ac4e8ac06a3537890e8cc4067b3971e17a5dc6c28c52e26456a5df14e8765ea` | 31860 |
| `measurements/stress/m5-v16-bundle/seed-5eed2710-10000-hotquiet-v16.json` | `810540c8738d7f64b0c9f5a879a1647d08b935616ee1cfe2c6d51ebc3d610040` | 32886 |
| `measurements/stress/seed-0007-4000-uniform-v3.json` | `fc457b4898020edf19c97574e3b60cc84196dec195be08cfcb3ab00d145498c0` | 6542 |
| `measurements/stress/seed-0007-4000-uniform-v4.json` | `b3876106052a40834bd6ebb29ee57e46a942fa2437efb38b31bb1ff33f93aa46` | 6858 |
| `measurements/stress/seed-0007-4000-uniform-v5.json` | `4274630d758d6cedf559932d70462dbcc1e374383b5a2fc2e6590ff2ce9cb4b3` | 7189 |
| `measurements/stress/seed-0007-4000-uniform.json` | `4f499b179f89d5375a20a12711e49e4798e73498d9ba601b98f893f05ad56704` | 6118 |
| `measurements/stress/seed-0017-4000-hotquiet-v3.json` | `bab6d9a1f18092b55636c89a60e517f8d3fcf355da3e2840f6a4edc59167a01f` | 6555 |
| `measurements/stress/seed-0017-4000-hotquiet-v4.json` | `8d70592e0f6b84b8542c88444ed3ea7403bb516365ef6cc4516e60b96e1f1958` | 6872 |
| `measurements/stress/seed-0017-4000-hotquiet-v5.json` | `d8790eb6f3f5be6ce36a9ff45540818e0abdfc09f180563fb90f985b1396b2f5` | 7204 |
| `measurements/stress/seed-0017-4000-hotquiet.json` | `b3440eab67f6e4b1b818fd9bb1aaf26aa17f9d44eeca1135b01773bb311855f7` | 6240 |
| `measurements/stress/seed-001d-4000-hotquiet-v3.json` | `0905907839f809bbc79f58a090163fa4c239ac1d574c156533dc878a09637b99` | 6558 |
| `measurements/stress/seed-001d-4000-hotquiet-v4.json` | `ede87b38e9e153ca076e9c8d127d0d3c53e82338d4d12fd7afebc5d47ceda446` | 6875 |
| `measurements/stress/seed-001d-4000-hotquiet-v5.json` | `cc4f4577a8313617ddacb53b0834a427c719af19bfe53e617f5112d3d37d3ea1` | 7207 |

## 3. Retained outside this index

- `measurements/perf/p6-1-*` — `CONDITIONAL` review evidence, unchanged by this retirement.
- `docs/product-scope-retirement-2026-11-23.md` — full repository-wide retirement record, including adapters, configs, scripts, docs and their hashes.
- Historical W1.1/W1.2 counts and approved document digests are unchanged.
