# Requirement-to-test matrix

This matrix is the single authority for requirement-to-test evidence. Test
references are exact source-file-qualified names of the form
`src/path.rs::test_name` or `tests/path.rs::test_name`. Wildcards, groups and
bare names are rejected. `scripts/check_matrix_tests.py` parses the declared
Rust tests and verifies that each reference names a declared test in an
existing file, that requirements M1-M9, E1-E5, P5 and P6 are present, and that
all mandatory evidence tests remain represented.

The offline suite is run by `cargo test --all-targets --locked`. No venue adapter
is registered after RRP-003; `collect`, `discover` and `latency` deny at the
composition root. A passing gate is implementation evidence, not a venue
verification claim. Gate results and their exact commits are recorded in the
workspace `CURRENT-STATE.json`, not restated here.

## Mandatory requirements

| ID | Requirement | Implementation | Test evidence | Status |
|---|---|---|---|---|
| M1 | Venue-neutral adapter contract with fail-closed composition root | `src/acquisition/exchange/mod.rs`, `src/distribution/coordinator.rs` | `src/acquisition/exchange/mod.rs::offline_capability_declarations_are_conservative`, `src/acquisition/exchange/mod.rs::exchange_trait_default_capabilities_are_legacy_equivalent` | Implemented; live pending |
| M2 | Apply the qualified discovery set to the collector core | `src/market_state/collector/state.rs`, `src/distribution/coordinator.rs` | `src/integrity/coverage.rs::missing_acknowledgement_is_reported` | Implemented (generic core) |
| M3 | Maintain an order book for each symbol | `src/market_state/orderbook.rs`, `src/market_state/collector/state.rs` | `src/market_state/orderbook.rs::applies_absolute_and_delta_updates`, `src/market_state/collector/state/tests.rs::snapshot_anchors_delta_application_in_per_symbol_order`, `tests/numeric_model.rs::price_is_not_interchangeable_with_quantity` | Implemented; offline deterministic tests |
| M4 | Add and retire symbols on discovery without mixing histories | `src/market_state/collector/state.rs`, `src/distribution/coordinator.rs` | `src/market_state/collector/state/tests.rs::discovery_adds_and_removes_with_controls`, `src/market_state/collector/state/tests.rs::removal_emits_empty_snapshot` | Implemented; live churn not forced |
| M5 | Write deltas to the output and anchor periodic snapshots | `src/storage/writer.rs`, `src/distribution/coordinator.rs`, `src/market_state/histogram.rs` | `src/storage/writer.rs::flush_makes_output_visible_to_reader`, `src/market_state/histogram.rs::bucket_boundaries_are_closed_and_disjoint`, `src/storage/writer.rs::normal_shutdown_drains_and_joins` | Implemented; no timing claim |
| M6 | Use the supplied helpers and standard SBE output | `src/util/aligned_sbe_writer.rs`, `src/util/aligned_sbe_reader.rs`, `src/storage/writer.rs` | `src/util/aligned_sbe_writer.rs::short_writes_are_completed_without_data_loss`, `src/storage/writer.rs::default_chunk_output_is_readable_by_default_reader` | Implemented; offline verified |
| M7 | Close sockets and the output file on shutdown | `src/distribution/coordinator.rs`, `src/storage/writer.rs` | `src/storage/writer.rs::normal_shutdown_drains_and_joins`, `src/storage/writer.rs::shutdown_drains_saturated_queue_and_joins`, `src/storage/writer.rs::finish_failure_on_shutdown_is_reported` | Implemented; offline verified |
| M8 | Balance symbols across redundant workers | `src/storage/capacity.rs`, `src/market_state/collector/state.rs` | `src/storage/capacity.rs::explicit_shard_count_must_satisfy_the_per_socket_bound`, `src/market_state/collector/state/tests.rs::clocked_shadow_replica_takes_over_after_source_loss` | Implemented; offline verified |
| M9 | Data completeness, receive-time accuracy and fail-closed governance | `src/market_state/collector/state.rs`, `src/integrity/verify.rs`, `src/governance/` | `src/market_state/collector/state/tests.rs::cross_symbol_output_order_is_processing_order_and_not_globally_sorted`, `src/governance/rights.rs::effective_dated_grant_authorizes_only_inside_its_window`, `src/integrity/conformance.rs::connect_success_is_not_a_certification_signal` | Implemented; no live certification |

## Optional extensions

| ID | Extension | Implementation | Test evidence | Status |
|---|---|---|---|---|
| E1 | Redundant workers and anchoring snapshots on failover | `src/market_state/collector/state.rs`, `src/market_state/recovery.rs` | `src/market_state/collector/state/tests.rs::clocked_shadow_replica_takes_over_after_source_loss`, `src/market_state/collector/state/tests.rs::clocked_failover_anchors_resumed_deltas_and_preserves_receive_times`, `src/market_state/collector/state/tests.rs::clockless_full_recovery_requires_acknowledged_fence_and_fresh_snapshot`, `src/market_state/collector/state/tests.rs::recovery_snapshot_before_ack_is_rejected_without_mutation` | Implemented; offline verified |
| E2 | Subscription monitoring and symbol-scoped refresh | `src/market_state/collector/state.rs`, `src/market_state/recovery.rs` | `src/market_state/recovery.rs::a_quiet_instrument_never_reconnects_its_source`, `src/market_state/recovery.rs::transport_failure_authorizes_a_source_reconnect` | Implemented in core |
| E3 | Generic encode/decode and canonical event model | `src/acquisition/exchange/mod.rs`, `src/domain/products.rs`, `src/domain/canonical.rs` | `src/domain/products.rs::product_keys_are_stable_and_scope_separated`, `src/domain/canonical.rs::canonical_kinds_are_distinct_and_stable` | Implemented; no adapter registered |
| E4 | Offline latency scaffolding, with no venue claim | `src/integrity/latency.rs`, `src/acquisition/ws.rs` | `src/integrity/latency.rs::percentile_is_nearest_rank_without_extrapolation` | Implemented; not a benchmark |
| E5 | Versioned raw-frame journal with durability and verification | `src/integrity/journal.rs`, `src/distribution/coordinator.rs` | `src/integrity/journal/tests.rs::payload_bytes_survive_write_and_read`, `src/integrity/journal/tests.rs::checksum_mismatch_and_corrupt_manifest_fail_verification`, `src/integrity/journal/tests.rs::queue_saturation_then_shutdown_stays_failed`, `src/integrity/journal/tests.rs::concurrent_producers_stop_after_failure`, `src/integrity/journal/tests.rs::successful_shutdown_reconciles_counters`, `src/integrity/journal/tests.rs::blocked_writer_bounds_shutdown`, `src/integrity/journal/tests.rs::blocked_writer_bounds_abort`, `src/integrity/journal/tests.rs::graceful_shutdown_finalizes_rotated_segments` | Implemented; offline fault injection |

## Non-market-data reference applications

| ID | Requirement | Implementation | Test evidence | Status |
|---|---|---|---|---|
| P5 | Source/target independence through a JSONL-to-target application | `src/storage/application.rs`, `src/storage/application/postgres.rs`, `docs/jsonl-postgres-reference.md` | `src/storage/application.rs::jsonl_source_retains_exact_bytes_and_sequence` | Implemented; simulator and optional server path |
| P6 | Durable file-to-target pipeline with bounded resume and checkpoint fencing | `src/storage/application/file_source.rs`, `src/storage/application/durable.rs`, `src/storage/application/postgres.rs`, `docs/durability-contract.md` | `src/storage/application/file_source.rs::streaming_reads_exact_bytes_offsets_and_fingerprint` | Implemented; local durability tier |

## Not claimed

- Live venue capability, depth, continuity or coverage.
- Latency, throughput, capacity or full-universe results.
- Production certification, cross-domain replication or zero-loss durability.
- Any right to acquire, retain, replay or redistribute provider data.

Historical venue plans and measurements are preserved in Git history and in the
dated retirement records, not in this matrix. An approved document keeps its
digest; a substantive contract change needs a new approved digest.
