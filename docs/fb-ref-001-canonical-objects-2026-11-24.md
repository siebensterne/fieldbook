# Fieldbook FB-REF-001 canonical financial objects — 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

**Record:** `docs/fb-ref-001-canonical-objects-2026-11-24.md`
**Date:** 2026-11-24
**Work item:** W2.3 BATCH A / FB-REF-001 — canonical financial object and identity core
**Branch:** `feat/fb-ref-001` on base `f27f4a4`
**Status:** Additive abstract types; not a provider, rights or dataset decision

## 1. Scope

`src/domain/reference_core.rs` declares abstract reference-object types. It reuses
`OpaqueId` from `src/domain/identity.rs`, `Bitemporal` from
`src/domain/information.rs`, and the fail-closed resolution vocabulary of
`src/domain/reference_data.rs`. No existing module was rewritten. The module is
declared in `src/domain/mod.rs` and re-exported from `src/lib.rs`.

Twenty-one distinct object classes cover jurisdictions, authorities,
market operators, venues, segments, products, legal entities, securities,
financial instruments, contract families and instances, listings, identifier
assertions, terms revisions, corporate actions, indices, calendars, sources,
data products, feeds and capabilities. A listing remains distinct from an
instrument, an index from a security, and a contract instance from its family.

## 2. Invariants

| Area | Rule |
|---|---|
| Identity | `ObjectId` derives from class, namespace, authority and immutable stable key through `OpaqueId::derive`; no symbol, title or display name is an input. |
| Validation | Empty namespace, authority, stable key, assertion value, assertion authority, assertion source, jurisdiction or capability is rejected with `ReferenceCoreError`. |
| Assertions | Revision is nonzero; validity interval is ordered; an assertion cannot describe another assertion. |
| Time | `applies` reads explicit `valid_us` and `knowledge_us`; no present-day clock is consulted. |
| Resolution | Applicable candidates are sorted by index; zero candidates is `Unresolved`; distinct subjects or values with agreeing claims is `Ambiguous`; disagreeing authorities or revisions with different validity is `Conflict`; one unique claim is `Resolved`. |
| Bitemporal ledger | Insertion rejects duplicate subject/revision pairs, unknown predecessors and predecessor cycles. Queries report `Unresolved`, `Resolved`, `Ambiguous` or `Conflict` with no fallback to a first record. |
| Coverage | `ratio` is present only when both counts are declared and the denominator is positive. An empty scope collection covers nothing; `None` means an unspecified dimension, not an all-values wildcard. |

Supersession is explicit: a higher revision names its predecessor's derived
identity. A single chain head resolves; divergent heads report ambiguity or
conflict. Identical assertion inputs derive identical identities; changing the
authority changes the identity.

## 3. Non-claims

- All source rights remain `UNKNOWN`; the `RightsUnknown` coverage state is a
  declared label and grants nothing.
- No provider was contacted and no market-data API, adapter or feed was added.
- No dataset was accepted, collected or reconciled; collection stays `DISABLED`.
- No experiment was run and live execution stays `DISABLED`; the budget remains
  INR 0.
- No India-specific feed, adapter or market-shaped test or fixture was added.
  Inline tests use arbitrary integers, strings, digests and object classes.
- No journal, replay, catalog or shared crate was changed. No commit was made.

## 4. Tests

Inline tests in `src/domain/reference_core.rs` cover deterministic identity,
authority sensitivity, the 21 unique class strings, empty-input rejection,
assertion validity and knowledge intervals, invalid assertion fields, ordered
candidate indices, absence of first-match resolution, ambiguity across
subjects, conflict across values and authorities, historical knowledge queries,
unknown predecessors, duplicate revisions, predecessor cycles, supersession
chains, unknown and zero denominators, explicit ratios, empty scope coverage
and exact-dimension queries.

## 5. Gates

The deterministic sweep runs rustfmt on changed files, then
`python3 scripts/check_style.py`,
`python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'`,
`python3 scripts/check_prose_unified.py --all`, and
`RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps`.
The gate set then runs `cargo xtask fmt`, `lint`, `docs`, `style`, `test`,
`verify` and `python3 scripts/check_architecture.py --check`. One responsibility
mapping was added for the new module; no anchor requirement was weakened and
no required anchor was added.
