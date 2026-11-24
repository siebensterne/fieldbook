# Fieldbook FB-REF-004 jurisdiction, venue and product registry — 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

**Record:** `docs/fb-ref-004-market-registry-2026-11-24.md`
**Date:** 2026-11-24
**Work item:** W2.3 BATCH A / FB-REF-004 — jurisdiction, venue and product registry
**Branch:** `feat/fb-ref-004` on base `e747051`
**Status:** Additive abstract types; no provider, rights or dataset decision

## 1. Scope

`src/domain/market_registry.rs` declares validated jurisdiction codes, typed
authority, venue, segment and product assertions, versioned country packs and a
fail-closed registry. The module reuses `ObjectId`, `ObjectRef` and `ObjectClass`
from `src/domain/reference_core.rs`, `Bitemporal` from
`src/domain/information.rs`, `VenueCategory` from `src/domain/reference_data.rs`
and `InstrumentKind` from `src/domain/taxonomy.rs`. No competing venue category,
instrument kind, currency or unit enum is introduced. The module is declared in
`src/domain/mod.rs` and re-exported from `src/lib.rs`.

## 2. Invariants

| Area | Rule |
|---|---|
| Identity | `JurisdictionCode` is a validated string of two to eight uppercase ASCII letters, digits or hyphens. Arbitrary territories register without an enum change. Object identity is the opaque `ObjectId`; no symbol or ticker is an identity input. |
| Assertions | Each typed assertion carries an `ObjectRef`, jurisdiction, source, bitemporal interval and nonzero revision. Empty sources and zero revisions fail validation. |
| References | Venue operator, segment venue and product segment must be registered in the same jurisdiction. Product kinds must be admitted by the segment, and terms classes are limited to `Security`, `FinancialInstrument`, `ContractFamily` and `ContractInstance`. |
| Country packs | Pack version must be positive; updates replace a pack only at a higher version. Packs hold versioned settlement, calendar, identifier, regulatory and corporate-action data as records. |
| Resolution | `resolve_venue`, `resolve_product` and `pack` return `Unresolved`, `Resolved`, `Ambiguous` or `Conflict`. Multiple applicable claims with one declaration stay ambiguous; divergent claims conflict. No first-row fallback is used. |
| Selection | `products_for` returns product assertions whose segment names the supplied venue. An absent match yields an empty result; no implicit all-venue selection exists. |

## 3. Non-claims

- Source rights remain `UNKNOWN`; this module grants no entitlement.
- No provider was contacted; no adapter, feed or dataset was added.
- Collection stays `DISABLED`; no data was accepted or reconciled.
- No experiment was run; live execution stays `DISABLED` and the budget remains
  INR 0.
- No India-specific feed, adapter, market-shaped test or fixture was added.
  Inline tests use fictional jurisdiction codes and arbitrary strings, integers
  and opaque references.
- No journal, replay, catalog, shared crate or requirement anchor changed. No
  commit was created.

## 4. Tests

The inline module holds 26 tests covering arbitrary and malformed jurisdiction
codes, stable authority role strings, duplicate identities, missing and
cross-jurisdiction references, revision and source validation, segment kind
admission, terms class restrictions, pack version rules, four-outcome venue and
product resolution, exact segment matching, coexistence of two fictional
jurisdictions, an empty registry, bitemporal boundaries, revision boundaries and
serde round-trip.

## 5. Gates

The deterministic sweep runs rustfmt, then `python3 scripts/check_style.py`,
`python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'`,
`python3 scripts/check_prose_unified.py --all`, and
`RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps`.
The gate set then runs `cargo xtask fmt`, `lint`, `docs`, `style`, `test`,
`verify` and `python3 scripts/check_architecture.py --check`. One source
responsibility mapping was added; no anchor was weakened or added.
