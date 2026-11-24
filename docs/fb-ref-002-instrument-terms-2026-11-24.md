# Fieldbook FB-REF-002 instrument classes and typed terms — 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

**Record:** `docs/fb-ref-002-instrument-terms-2026-11-24.md`
**Date:** 2026-11-24
**Work item:** W2.3 BATCH A / FB-REF-002 — instrument classes and typed terms
**Branch:** `feat/fb-ref-002` on base `4c8280`
**Status:** Additive abstract types; no provider, rights or dataset decision

## 1. Scope

`src/domain/instrument_terms.rs` declares unit-bearing exact measures, seven
family-typed term payloads, typed contract families and instances, a revision
validator and an append-only terms registry. The module reuses `ObjectId`,
`ObjectRef`, `ObjectClass`, `BitemporalAssertion`, `BitemporalLedger` and
`LedgerResolution` from `src/domain/reference_core.rs`, `Bitemporal` from
`src/domain/information.rs`, and the scale bound from `src/domain/fixed.rs`. The
broad `AssetClass` enum remains the single asset classification vocabulary.
`DerivativeKind` is a transparent newtype over `InstrumentKind`, admitted only
through `TryFrom<InstrumentKind>` for the six derivative kinds, so no competing
classification enum is introduced. The module is declared in
`src/domain/mod.rs` and re-exported from `src/lib.rs`.

## 2. Invariants

| Area | Rule |
|---|---|
| Units | Every numeric term is an `ExactMeasure` carrying coefficient, scale and a `Unit` with stable snake_case strings and explicit scale semantics. No bare number crosses the contract. |
| Arithmetic | Scale must not exceed `fixed::MAX_SCALE`; addition aligns scales, multiplication sums scales, and both use checked `i128` intermediates. Unit mismatch and overflow fail with typed errors. No floating point type is used. |
| Families | `InstrumentTerms` has distinct equity, debt, fund, derivative, commodity, index and foreign-exchange payloads. Each family validates its own required fields and reports them with stable labels. |
| Classification | `DerivativeKind` stores an `InstrumentKind` and delegates `as_str` to it. `TryFrom` admits `Future`, `Option`, `Swap`, `NonDeliverableForward`, `PerpetualContract` and `EventContract`; other kinds fail with `InvalidClassification`. |
| Contracts | An instance names its family identity, agrees with a dated template or uses an undated template whose expiry is zero, carries a positive lot size and a positive multiplier, and references a permitted underlying class. Identity is opaque; ticker and symbol text is absent. |
| Revisions | A revision validates its payload, carries a nonzero revision and nonempty source, and names a permitted subject class. Insertion into `TermsRegistry` rejects repeated subject and revision pairs and leaves stored records unchanged. |
| Queries | `query` reads explicit valid and knowledge times through the shared ledger and returns `Unresolved`, `Resolved`, `Ambiguous` or `Conflict` without first-record fallback. |

## 3. Non-claims

- Source rights remain `UNKNOWN`; this module grants no entitlement.
- No provider was contacted; no adapter, feed or dataset was added.
- Collection stays `DISABLED`; no data was accepted or reconciled.
- No experiment was run; live execution stays `DISABLED` and the budget remains
  INR 0.
- No India-specific feed, adapter, market-shaped test or fixture was added.
  Inline tests use arbitrary integers, strings and opaque object references.
- No journal, replay, catalog, shared crate or requirement anchor was changed.
  The change remains in the single existing branch commit; no additional commit
  was created.

## 4. Tests

The inline module holds 23 tests covering unit strings and scale semantics,
canonical rendering, scale rejection, checked addition and multiplication,
overflow and unit mismatch, repeatability, derivative taxonomy projection
acceptance and rejection, validation of all seven families, conformance reports,
zero lot and nonpositive multiplier rejection, underlying and subject class
rejection, family and instance agreement, mismatch, dated instances under an
undated template, duplicate revision rejection, historical knowledge queries and
integer-only authority paths.

## 5. Gates

The deterministic sweep runs rustfmt on changed files, then
`python3 scripts/check_style.py`,
`python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'`,
`python3 scripts/check_prose_unified.py --all`, and
`RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps`.
The gate set then runs `cargo xtask fmt`, `lint`, `docs`, `style`, `test`,
`verify` and `python3 scripts/check_architecture.py --check`. One source
responsibility mapping was added for the new module; no anchor requirement was
weakened and no required anchor was added.
