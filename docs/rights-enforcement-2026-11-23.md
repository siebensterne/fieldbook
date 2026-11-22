# Rights enforcement fix — 2026-11-23

**Record:** `docs/rights-enforcement-2026-11-23.md`
**Date:** 2026-11-23
**Work item:** W1.1-C
**Branch:** `fix/w11-rights-enforcement` on base `777e151`
**Rights effect:** none. No right, dataset, provider operation or experiment is
changed by this record.

## 1. Defects fixed

The former `check_active(venue, operation, at_us)` compared only the venue and
the expiry, while the egress layer passed transport action strings
(`http_client`, `websocket_connect`) instead of the operation held by the
proof. The audit sink was optional, `record_decision` returned `Ok` when it was
absent, denied egress ignored audit write failures, the command name was used
as `product_id`, and a process-wide `OnceLock` held one authorization.

The implementation in `src/governance/rights.rs` replaces that behavior:

- `Operation` is the 14-value lifecycle vocabulary (`source_contact`,
  `reference_data_retrieval`, `historical_data_retrieval`, `real_time_capture`,
  `raw_storage`, `normalization`, `replay`, `backup`, `internal_analytics`,
  `derived_data_creation`, `display`, `external_redistribution`, `retention`,
  `deletion`). `UsageMode`, `Purpose`, `Recipient` and `Licensee` are separate
  types. A command declares the operations it may require in
  `distribution::cli::gated_operations`; the egress boundary passes the actual
  typed operation from the transport caller.
- `AuthorizationGate::check_active` compares the full request. Exact
  dimensions are licensee, venue, provider, source, dataset, product, segment,
  territory, operation, usage right, usage mode, recipient, purpose, delivery
  method and retention. Scoped dimensions (instruments, fields, modalities,
  data time window) must contain the requested subset. The effective interval
  must contain the request instant.
- The audit sink is mandatory. `RightsContext::load` takes a non-optional
  directory and `AuditSink::new` writes and removes a probe through the same
  atomic path used for events. A permitted decision is committed before the
  proof is returned and before egress proceeds; a write failure denies egress.
  Denied decisions are written when a sink exists, and an audit failure keeps
  a denial a denial. Audit events carry an event id, run id, process id,
  sequence, UTC microseconds, monotonic elapsed nanoseconds, the actual
  operation, the full identity and scope, decision, reason, licence reference
  and digest, policy version and software version. They carry no credentials,
  proxy URLs, headers or payload bytes.
- The commit boundary is the `fsync` of the event file bytes, the rename into
  the audit directory and the `fsync` of that directory in
  `crate::report::write_bytes_atomic`. An acknowledgement means the decision
  record is durable, not that a provider was contacted.
- `AuthorizationGate` is an instance-scoped container for many independent
  proofs. Empty gates deny. Library callers construct their own gate; the
  binary uses one lazily created gate instance for its one-command-per-process
  entry point. It no longer uses a single one-shot proof slot.

Capability registries in `src/governance/adapter.rs` and
`src/governance/modality.rs` remain separate from the rights registry.

## 2. Test inventory

All tests use scalar identifiers, abstract instants or temporary directories.
No market observation is created and no provider is contacted. The
`market-shaped-tests` feature stays disabled.

### 2.1 New and rewritten library unit tests in `src/governance/rights.rs`

27 tests total (17 carried forward and rewritten, 10 added):

| Test name | Required case |
|---|---|
| `effective_dated_grant_authorizes_only_inside_its_window` | effective interval |
| `provider_specific_decision_is_not_shared` | provider mismatch |
| `conflicting_decisions_fail_closed` | conflict denied |
| `revocation_blocks_authorization` | revoked |
| `territory_is_scoped` | territory equality |
| `public_access_never_grants_retention` | public retention denied |
| `conflicting_registration_is_rejected` | conflict denied |
| `authorization_proof_carries_audit_identity` | evidence in proof |
| `non_overlapping_decisions_coexist` | dated revisions |
| `revision_keys_include_full_identity` | identity key |
| `reinstatement_supersedes_revocation` | later reinstatement |
| `malformed_interval_and_audit_are_refused` | malformed evidence |
| `venue_is_required_in_both_request_and_record` | venue equality |
| `operation_mismatch_never_authorizes_another_operation` | **operation mismatch** |
| `operation_mismatch_is_enforced_at_the_egress_boundary` | **operation mismatch at egress** |
| `source_product_and_segment_mismatch_deny` | **source product and segment mismatch** |
| `instrument_field_modality_and_time_window_scope_deny` | **instrument, field, modality and time-window scope** |
| `rights_loader_fails_closed_on_missing_and_malformed_files` | fail-closed config |
| `expired_and_unknown_rights_never_authorize` | expired, conditional |
| `missing_audit_dir_is_never_silently_accepted` | **missing audit directory** |
| `audit_write_failure_prevents_egress` | **audit write failure** |
| `successful_egress_commits_its_audit_event_before_returning` | **permitted event committed before egress** |
| `every_decision_writes_a_machine_readable_audit_event` | event field inventory |
| `revocation_and_expiry_during_a_long_running_session_deny_egress` | **revocation and expiry mid-session** |
| `two_independent_source_authorizations_coexist_in_one_gate` | **two independent authorizations in one process** |
| `declared_command_scope_never_uses_the_command_name_as_product` | product identity |
| `display_mode_is_separate_from_usage_right` | separated concepts |

### 2.2 Dependent tests updated for the new typed vocabulary

- `src/distribution/cli.rs`: `only_provider_facing_commands_are_gated` now
  checks the declared operation slice per command.
- `src/governance/coverage_certification.rs`: 7 tests use the full declared
  scope in their licensing fixtures.
- `src/integrity/conformance.rs`: 4 tests use the full declared scope.
- `tests/source_conformance.rs`: 6 market-shaped declarations updated at the
  source level; the target remains feature-gated and unregistered.
- `tests/egress_governance.rs`: 9 tests now use typed operations, a configured
  audit directory and the expanded rights TOML shape.
- `tests/live_kalshi.rs`, `tests/live_polymarket.rs`: ignored live declarations
  updated to the new operation names and mandatory audit directory.

### 2.3 Permitted gate result

`cargo xtask fmt`, `cargo xtask lint`, `cargo xtask docs`, `cargo xtask style`
and `cargo xtask test` pass. The test command executes 470 library tests
(4 ignored), 73 integration tests (8 ignored), 14 `xtask` tests and 1 doc test:
558 passed and 12 ignored. No test target was registered and no assertion was
removed.

## 3. Non-claims

No live venue was contacted, no market observation was used, no right was
granted and no artefact was collected. No commit or push was made in this
worktree.
