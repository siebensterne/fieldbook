# Fieldbook FB-REF-001A versioned identity derivation — 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

**Record:** `docs/fb-ref-001a-versioned-identity-2026-11-24.md`
**Date:** 2026-11-24
**Work item:** WP-1 / FB-REF-001A — versioned unambiguous identity derivation
**Branch:** `fix/ref-001a-versioned-identity-derivation` on base `78b9d51`
**Algorithm id:** `FB-REF-001A-V2-IDENTITY-DERIVATION`
**Status:** Additive identity correctness change; not a rights, provider or dataset decision

## 1. Defect and scope

`OpaqueId::derive` in `src/domain/identity.rs` concatenated `namespace`, byte
`0x1f`, `authority`, byte `0x1f` and `stable_key`, then truncated SHA-256 to
12 bytes. The prefix stayed outside the digest. A unit separator inside a field
therefore produced the same hash input as a separator between fields:
`("a\x1fb", "c", "d")` and `("a", "b", "c\x1fd")` collided.

This record adds `src/domain/framed_identity.rs` and routes
`ObjectId::from_validated` through it. `OpaqueId::derive`, `InstrumentId`,
`VenueId`, `ListingId`, `EventId`, storage identifiers and every other legacy
identity type remain byte-identical. No legacy persisted or contract identifier
changed.

## 2. Algorithm

| Element | Declaration |
|---|---|
| Domain separator | `FIELDBOOK-REFERENCE-OBJECT-ID-V2` (32 ASCII bytes), fixed prefix of every preimage |
| Format version | `u16` value `2`, encoded big-endian directly after the separator |
| Field order | class, namespace, authority, stable key |
| Length encoding | one `u32` big-endian UTF-8 byte length per field, immediately before that field's bytes |
| Digest | full SHA-256 of the framed preimage, 32 bytes, no truncation |
| Serialized form | `<class>:v2:<64 lowercase hex>`; class token is outside the digest but bound to it by derivation |
| Class binding | class bytes participate in the preimage; `ObjectClass::as_str` supplies the token, and the token grammar is lowercase ASCII initial followed by lowercase ASCII, digits or underscores |
| Text handling | exact UTF-8 bytes; no normalization, trimming or case folding; NFC `é` and NFD `e\u0301` derive different identities |
| Control bytes | embedded NUL and `0x1f` are ordinary field content because fixed-width lengths bound fields |

`FramedPreimage::new` validates all four fields before framing. Each field must
be nonempty and at most `4096` UTF-8 bytes, a documented policy maximum below
`u32::MAX`; lengths are also checked against `u32::MAX` before encoding.
`InvalidClass`, `EmptyField`, `FieldTooLong`, `InvalidText`,
`MalformedIdentityText`, `ConflictingRegistration` and `AmbiguousMigration` are
typed `IdentityV2Error` variants.

## 3. Format boundary

`detect_format` accepts version-2 text only in the exact
`<class>:v2:<64 lowercase hex>` shape and legacy text only in the exact
`<prefix>:<24 lowercase hex>` shape. Any other text yields `InvalidText`.
`parse_legacy_or_v2` delegates to the same detector. No format is coerced into
another and no implicit migration map is retained.

`OpaqueId::from_declared` is an additive constructor that validates declared
text before storing it. `ObjectId::parse_declared` accepts legacy text verbatim
for persisted compatibility and validates version-2 text against the full
shape. `ObjectId::identity_format` reports the detected family. The
`#[serde(transparent)]` derive on `ObjectId` stays for persisted wire
compatibility; ingress validation is an explicit call at the deserialization
boundary rather than a change to the stored shape.

`BitemporalAssertion::assertion_id` now returns a result so framing failures
surface as `ReferenceCoreError`. Ledger query and reachability read stored id
indexes, so their public signatures are unchanged. One inline test in
`src/domain/instrument_terms.rs` was adapted to the fallible assertion-id
signature; no production code there changed.

## 4. Registry

`IdentityRegistry` indexes both identity to subject and subject to identity.
Repeating one identity and subject pair is idempotent. Pairing an identity with
another subject yields `ConflictingRegistration`; pairing a subject with
another identity yields `AmbiguousMigration`. Both directions are checked in
memory with no implicit migration mapping.

## 5. Legacy call-site inventory

Counts are source occurrences at base `78b9d51`. The 50 legacy derive call
sites below are unchanged, including the `identity_type!` macro body in
`src/domain/identity.rs` that generates nine legacy newtypes.

| File | Legacy derive call sites | Types |
|---|---:|---|
| `src/domain/canonical.rs` | 8 | `OpaqueId`, `EventId`, `FeedId`, `InstrumentId` |
| `src/domain/event_model.rs` | 1 | `EventId` |
| `src/domain/identity.rs` | 24 | macro `OpaqueId`, `InstrumentId`, `VenueId`, `ListingId`, `DataProviderId`, `FeedId` |
| `src/domain/information.rs` | 1 | `EventId` |
| `src/domain/reference_core.rs` | 1 | `OpaqueId`; the one call replaced at the migration boundary |
| `src/domain/reference_data.rs` | 6 | `OpaqueId`, `VenueId`, `InstrumentId`, `ListingId` |
| `src/storage/application.rs` | 2 | `OpaqueId`, `EventId` |
| `src/storage/application/file_source.rs` | 1 | `OpaqueId` |
| `src/storage/application/postgres.rs` | 2 | `EventId`, `OpaqueId` |
| `tests/bounded_batch.rs` | 1 | `OpaqueId` |
| `tests/postgres_live.rs` | 3 | `OpaqueId`, `EventId` |
| **Total** | **50** | |

The 13 base `ObjectId::derive` call sites are the migration boundary: two in
`src/domain/capability_registry.rs`, one in `src/domain/instrument_terms.rs`,
one in `src/domain/market_registry.rs`, and nine in
`src/domain/reference_core.rs` including inline tests. Their source text is
unchanged; the resulting identity text is version 2 because
`ObjectId::from_validated` now calls `derive_v2`.

The known legacy vector `("inst", "ns", "authority", "key")` remains
`inst:8864c214ac0e8fd283cc8c99`. An inline regression test asserts this value.

## 6. Tests

Sixteen inline tests in `src/domain/framed_identity.rs` cover deterministic
derivation, per-field and per-version framing changes, a declared byte-layout
vector, the two adversarial delimiter tuples, embedded NUL and separator bytes,
empty and overlength fields, invalid class tokens, Unicode normalization forms,
strict parsing, injected class validation, format detection, a deterministic
256-tuple sweep, a deterministic mutation sweep, registry conflicts and the
legacy vector. Five inline tests in `src/domain/reference_core.rs` cover v2
derivation, legacy text acceptance, malformed text rejection, framing errors and
assertion identity framing.

The tuple and mutation sweeps use a deterministic pseudo-random generator with
no new dependency. Distinct digests over finite inputs are evidence about those
inputs; they do not prove the absence of SHA-256 collisions.

## 7. Gates

The deterministic sweep runs rustfmt, then `python3 scripts/check_style.py`,
`python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'`,
`python3 scripts/check_prose_unified.py --all`, and
`RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps`.
The gate set then runs `cargo xtask fmt`, `lint`, `docs`, `style`, `test`,
`verify` and `python3 scripts/check_architecture.py --check`. One source
responsibility mapping was added; no anchor requirement was weakened.

## 8. Non-claims

- No rights decision, source authorization, provider contact or egress path changed.
- No market data, India-specific feed, adapter, experiment or market-shaped test was added.
- No journal, replay, catalog, shared crate or historical dated record was rewritten.
- No commit was made.
