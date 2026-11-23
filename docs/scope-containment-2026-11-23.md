# Scope containment fix — 2026-11-23

> Historical record. Test paths named below were retired under RRP-002
> (owner directive D11) and are not available in the active tree. This
> document is preserved unchanged except for this notice; see
> `docs/synthetic-asset-retirement-2026-11-23.md` for the current state.

**Record:** `docs/scope-containment-2026-11-23.md`
**Date:** 2026-11-23
**Work item:** W1.2 C1 (Fieldbook scope containment and explicit requests)
**Branch:** `fix/w12-c1-scope` on base `340f829`
**Normative model:** `NDC-SEMANTIC-MODEL-V2-PROPOSED.md`, sections 1–2, 2.3
and 9 (proposed, not ratified)
**Rights effect:** none. No right, dataset, provider operation or experiment is
granted or changed by this record.

## 1. Corrected semantics

All semantics below are implemented in `src/governance/rights.rs` and defined
there in code, not only in prose.

### 1.1 Time-window containment

`TimeWindow` endpoints use mathematical infinity: `from_us = None` is `-inf`
and `to_us = None` is `+inf`. `TimeWindow::contains` requires the permitted
start to be at or before the requested start and the permitted end to be at or
after the requested end. A bounded endpoint therefore does not cover an
unbounded request endpoint; an unbounded grant endpoint covers a bounded
request endpoint.

| Grant | Request | Result |
|---|---|---|
| `[10, 20]` | `[None, None]` | deny |
| `[None, 20]` | `[None, None]` | deny |
| `[10, None]` | `[None, None]` | deny |
| `[None, None]` | `[10, 20]` | permit |
| `[None, None]` | `[None, None]` | permit |

`TimeWindow::validate` rejects a window whose `from_us` exceeds `to_us`.
`AuthorizationIdentity::validate_interval` performs the same ordering check
on the operational validity interval. Data time and operational validity
remain separate fields; the data window is never used as an effective-date
check.

### 1.2 Explicit request builder

`AuthorizationScope::for_exchange()` is removed. `AuthorizationScope::request()`
returns `AuthorizationRequestBuilder`, which has no default values. Every
identity, dimension, purpose, recipient, delivery method, retention rule and
time window must be supplied; `build()` returns `RightsError::MissingField`
for the first omission. No value is inferred from a command name, an exchange,
an environment variable or an existing proof.

`validate_segment` rejects blank values, `*` and the former operational
placeholders (`source-contact`, `reference`, `history`, `live-capture`,
`analytics`, `display`, `distribution`). A segment must name a real venue
market segment from the written permission.

`authorize_operations(settings, operations)` now fails closed with a denial
that names the missing explicit request; it checks the rights-file and
audit-directory preconditions first so a missing configuration is reported.
`authorize_requests(settings, requests)` authorizes fully specified requests
and is the supported path for a caller that holds an `EgressIntent`.

### 1.3 ScopeSet states

`ScopeSet<T>` has four explicit states:

- `NotApplicable` — the dimension has no meaning for the operation, used for
  `source_contact` instruments, fields and modalities;
- `Named(Vec<T>)` — an explicit enumerated set. An empty `Named` set contains
  no members and is not `All`;
- `Universe(String)` — an explicitly versioned universe, the permitted
  unbounded-but-defined set for capture;
- `All` — unrestricted, written explicitly in an operator rights record and
  never a runtime default or an inferred wildcard.

Containment follows the states: `All` covers any request, `Named` covers a
`Named` subset, `Universe(v)` covers `Universe(v)` and `Named` subsets, and
`NotApplicable` covers only `NotApplicable`. A bounded set does not cover
`All`. `validate_scope_sets` rejects `All` for capture and rejects applicable
scope sets for `source_contact`.

### 1.4 Typed retention

`Retention` is now a typed policy of `limit: RetentionLimit` and
`purge_required: bool`. `RetentionLimit` has exactly three states: `None` (no
retention is granted), `Bounded(u64)` (maximum age in seconds) and
`Indefinite` (explicitly granted unlimited retention). `None` is not an
ambiguous absence. `Retention::contains` permits a narrower request: a
bounded grant covers `None` and smaller bounded requests, an indefinite grant
covers every request, and an `Indefinite` request is not covered by a bounded
grant. A grant that requires purge cannot be weakened by a request. Retention
is a scoped dimension, not an exact-equality dimension.

### 1.5 Declared purpose

`Purpose::ProprietaryOwnAccountTradingResearch` is a distinct enum value with
the exact contract string `proprietary_own_account_trading_research`. It is not
an alias for `internal_analysis`, academic research, non-commercial research
or `historical_archive`. No other enum value is substituted for it.

### 1.6 Dependent call sites

`src/governance/coverage_certification.rs`, `src/integrity/conformance.rs` and
`tests/source_conformance.rs` now build explicit requests through the same
builder. `rights.example.toml`, `tests/egress_governance.rs` and the two
ignored live declarations use the versioned-universe scope shape and the typed
retention shape. No file was deleted.

## 2. Test inventory

Every test uses scalar identifiers, abstract instants or temporary
directories. No market observation is created and no provider is contacted.
The `market-shaped-tests` feature stays disabled.

### 2.1 W1.1-C tests carried forward

All 27 library tests recorded in `docs/rights-enforcement-2026-11-23.md` remain
in `src/governance/rights.rs` with their assertions intact. Fixtures were
updated to the typed scope and retention shapes; two assertions changed to the
new abstract segment value. Dependent test crates were updated to the same
shapes.

### 2.2 Added abstract-value tests in `src/governance/rights.rs`

12 tests were added (39 total in that module):

| Test name | Required case |
|---|---|
| `time_window_containment_truth_table` | bounded grant versus unbounded request; half-bounded variants; unbounded grant versus bounded request |
| `data_time_window_from_must_not_exceed_to` | data-time and operational `from <= to` |
| `unbounded_request_requires_unbounded_grant` | `[10,20]`/`[None,20]` grants deny `[None,None]`; unbounded grant permits bounded and unbounded requests |
| `scope_set_states_are_distinct` | empty `Named` is not `All`; universe versions; `NotApplicable`; default |
| `capture_requires_named_or_versioned_universe` | capture with `All` is rejected; versioned universe is valid |
| `source_contact_uses_not_applicable_scope_sets` | `source_contact` scope-set applicability |
| `retention_policy_containment_and_narrower_requests` | narrower request, `None`, indefinite, bounded exceed, purge |
| `missing_licensee_is_denied` | builder omission and cross-licensee denial |
| `wrong_purpose_is_denied_and_exact_wording_is_preserved` | purpose mismatch and exact wording |
| `wrong_recipient_is_denied` | recipient mismatch |
| `ambiguous_grants_fail_closed` | contradictory overlapping grants |
| `every_exact_identity_dimension_mismatch_denies` | provider, source, dataset, product, segment, venue, territory, delivery |

The following W1.1-C tests supply the remaining required mismatches:
`operation_mismatch_never_authorizes_another_operation` and
`operation_mismatch_is_enforced_at_the_egress_boundary` (operation),
`provider_specific_decision_is_not_shared` (provider),
`source_product_and_segment_mismatch_deny` (source product, segment),
`venue_is_required_in_both_request_and_record` (venue),
`instrument_field_modality_and_time_window_scope_deny` (instrument, field,
modality, time window), `effective_dated_grant_authorizes_only_inside_its_window`
(expiry), `revocation_blocks_authorization` (revocation),
`conflicting_decisions_fail_closed` (ambiguous grants) and
`explicit_request_builder_never_infers_values` (no wildcard inference).

### 2.3 Permitted gate result

`cargo xtask fmt`, `cargo xtask lint`, `cargo xtask docs`, `cargo xtask style`
and `cargo xtask test` pass with the `market-shaped-tests` feature off.
`cargo test --workspace --all-targets --locked` reports 569 passed, 0 failed and
12 ignored; `cargo test --workspace --doc --locked` reports 1 passed. No test
target was registered and no assertion was removed.

## 3. Non-claims

No live venue was contacted, no market observation was used, no right was
granted and no artefact was collected. No commit or push was made in this
worktree. The production command path stays fail-closed until an `EgressIntent`
supplies the actual request in the next work item.
