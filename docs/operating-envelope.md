# Operating envelope — current state (2026-11-23)

This document replaces the retired prediction-market capacity envelope under
RRP-003. It records the *generic* bounds of the securities platform. It is not
a venue-support claim, a performance result, a capacity certification or a
production readiness statement.

## Scope after retirement

The seven crypto and prediction-market adapter families, their configs,
scripts, measurements and capability claims were removed from the active tree.
The platform retains generic acquisition, transport, egress, session,
supervision, codec, journal, replay, durability, analytics and governance
infrastructure. No securities venue adapter is registered: one is added only
after source qualification, explicit rights and an accepted NDC projection
(workspace W4). Consequently `collect`, `discover` and `latency` fail closed at
the composition root until a qualified adapter exists.

## Startup admission bounds

These values are planning ceilings from `config.example.toml` and
`Settings::validate`. They are enforced before any source contact, but they do
not establish that a venue, protocol or dataset is supported.

| Control | Default ceiling | Purpose |
|---|---:|---|
| `collector.shards` | derived, `max_shards = 64` | bounds websocket shards |
| `collector.replicas` | 2 | redundant connections per shard |
| `collector.max_total_connections` | 64 | hard `shards * replicas + lifecycle` gate |
| `collector.max_symbols_per_socket` | 5000 | per-socket subscription bound |
| `collector.max_initial_subscription_bytes` | 1 MiB | subscription frame gate |
| `collector.max_estimated_book_memory_mb` | 1024 | resident book-state gate |
| `collector.max_snapshot_bytes_per_sec` | 16 MiB/s | estimated snapshot output gate |
| `network.connect_race` | 1 (max 8) | bounded handshake racing |
| `network.connect_timeout_secs` | 30 | full-handshake deadline |

The capacity planner (`src/storage/capacity.rs`) derives these from the
discovered market set and refuses a topology before opening a socket. No
measured venue universe currently exists in the active tree, so no capacity
number inherited from the retired prediction-market captures is valid here.

## Durability and release boundary

Local journal and replay behavior is exercised with abstract timestamps and
arbitrary bytes only. Retained non-market PostgreSQL delivery evidence is
recorded under `measurements/live/` with its own commands and digests. The
former index is a dated pointer at `measurements/README.md`. Cross-host
replication, backup and restore remain a separately tested tier; zero loss,
nanosecond precision, HFT and live readiness are not claimed. Live order
submission stays disabled.

## Rights boundary

Rights remain `UNKNOWN`. No provider contact, collection, replay, analytics or
redistribution right is granted by this document, by a successful connection,
by a checksum or by a public URL. The `CURRENT-STATE` freeze stays in force.

## Related records

- `docs/product-scope-retirement-2026-11-23.md` — removed paths, hashes, sizes
  and preserved evidence for this retirement.
- `README.md` — current scope and document map.
- `docs/synthetic-asset-retirement-2026-11-23.md` — earlier RRP-002 retirement.
