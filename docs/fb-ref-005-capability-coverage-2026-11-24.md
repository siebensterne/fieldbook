# Fieldbook FB-REF-005 source, product and capability registry — 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

**Record:** `docs/fb-ref-005-capability-coverage-2026-11-24.md`
**Date:** 2026-11-24
**Work item:** W2.3 BATCH A / FB-REF-005 — source, product and capability registry
**Branch:** `feat/fb-ref-005` on base `c4bb2d9`
**Status:** Additive abstract types; no provider, rights or dataset decision

## 1. Scope

`src/domain/capability_registry.rs` declares proof references, capability
assertions, a capability registry, an explicit coverage-promotion allow-list and
a combined capability and coverage registry. The module reuses `ObjectId`,
`ObjectRef`, `ObjectClass`, `CoverageCell`, `CoverageState`, `CoverageRegistry`,
`CoverageScope` and `ReferenceCoreError` from `src/domain/reference_core.rs` and
`Bitemporal` from `src/domain/information.rs`. Product vocabulary from
`src/domain/products.rs` is consumed by callers; no new product kind, capability
enum or coverage state is introduced. The module is declared in
`src/domain/mod.rs` and re-exported from `src/lib.rs`.

## 2. Invariants

| Area | Rule |
|---|---|
| Proof | `EvidenceRef` names retained proof by a kind, a digest of at least sixteen hexadecimal characters and a nonempty origin. The proof bytes are not stored in the assertion. |
| Capability | `CapabilityAssertion` carries a capability identity, a subject limited to `Source`, `DataProduct` or `Feed`, a nonzero revision, bitemporal bounds and a named source. |
| Evidence | `Asserted` carries no proof; `Evidenced` and `Revoked` carry at least one; `Verified` requires both `IndependentVerification` and `ConformanceReport`. A source declaration alone cannot verify a claim. |
| Rights | `RightsState` is stored beside capability state. A capability may be `Verified` while rights stay `Unknown`; qualification still requires rights `Verified`. |
| Registry | Insertion rejects duplicate identities and repeated subject, capability and revision tuples. `resolve` returns `Unresolved`, `Resolved`, `Ambiguous` or `Conflict` with sorted indices and no first-match fallback. |
| Promotion | The allow-list spans the twelve existing `CoverageState` values. `AdapterImplemented` cannot skip to `Qualified`; qualification needs a conformance report, a reconciliation report, a recovery drill and verified rights. Backward transitions to `Suspended`, `Retired` or `Degraded` need a recorded reason reference. |
| Counts | A `Qualified` cell must declare a numerator and a positive denominator. An empty registry has no cells, no capabilities and zero counts in every state. |

## 3. Non-claims

- Source rights remain `UNKNOWN`; this module grants no entitlement.
- No provider was contacted; no adapter, feed or dataset was added.
- Collection stays `DISABLED`; no data was accepted or reconciled.
- No experiment was run; live execution stays `DISABLED` and the budget remains
  INR 0.
- No India-specific feed, adapter, market-shaped test or fixture was added.
  Inline tests use arbitrary strings, hexadecimal digests, integers and opaque
  references. No ticker, venue name, market price, candle or P&L is present.
- No journal, replay, catalog, rights file, shared crate or requirement anchor
  changed. No commit was created.

## 4. Tests

The inline module holds 37 tests covering stable contract strings, proof
validation, short and non-hexadecimal digests, empty origins, evidence rules for
all four capability states, subject-class and revision checks, inverted temporal
bounds, duplicate identities and revisions, revocation with recorded proof,
four-outcome resolution with sorted indices and no first match, historical
knowledge-time queries, stage-specific evidence and rights gates, backward
transitions with a reason, non-mutating promotion, declared-count admission,
qualification of a stored cell, an empty registry and per-state summary counts.

## 5. Gates

The deterministic sweep runs rustfmt, then `python3 scripts/check_style.py`,
`python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'`,
`python3 scripts/check_prose_unified.py --all`, and
`RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps`.
The gate set then runs `cargo xtask fmt`, `lint`, `docs`, `style`, `test`,
`verify` and `python3 scripts/check_architecture.py --check`. One source
responsibility mapping was added; no source anchor was weakened or added.
