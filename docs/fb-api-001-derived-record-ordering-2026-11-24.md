# FB-API-001 — derived record ordering at the producer API, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**, 2026-11-24. Branch
`fix/fb-api-derived-ordering`, base commit `e87a043`. No commit was created by
this work package. This is a dated scope and gate record, not a release, a
rights grant or a verification promotion.

Authority: the canonical NDC v2 Profile 1 schema package under
`WS-NDC-2026-11-24-003` remains the wire authority. This record amends the
public producer surface described in FB-NDC-001, FB-NDC-009 and FB-NDC-013
without rewriting those dated records. Frozen boundaries stay unchanged:
rights `UNKNOWN`, dataset acceptance `BLOCKED`, budget INR 0, collection
`DISABLED`, experiments `BLOCKED`, live execution `DISABLED`, no India feed and
D11 strict.

## Defect

`CanonicalRecord` carried `bytes` and a caller-supplied `order_key`.
`validate_record_order` compared supplied keys with one another and checked
declared domain, epoch, monotonicity and duplicates, but did not bind those
keys to the JSON record bytes. The conformance mapping derived keys from
bytes, while the public `BuildRequest` accepted `ArtifactInput` and
`CanonicalRecord` directly. A caller could therefore supply a key that
disagreed with the record. This was `issue/I-07`.

## Change

- `CanonicalRecord` holds `bytes` alone. A `compile_fail` doctest records that
  an external `order_key` member is a compile error.
- `RecordOrderKey` is crate-internal. The public producer input exposes one
  representation of a record and no ordering-key type.
- `ClaimedKey::to_untrusted_internal` was removed. The abstract spec keeps its
  adversarial claim as fixture input; the producer mapping drops it.
- `prepare_artifact` and `spec_to_build_inputs` construct bytes-only records.
- `validate_record_order` maps the declared profile with
  `ndc_wire::map_artifact_profile`, parses each record with
  `ndc_wire::parse_canonical_record`, derives the key with
  `ndc_wire::derive_order_key`, converts it with
  `ndc_wire::wire_order_key_to_internal`, then checks domain, epoch,
  monotonicity and duplicates against the derived keys. Malformed and
  non-canonical records fail with `ProducerError::InvalidRecord`; unknown
  ordering kinds, profile mismatches and repeated or backwards positions fail
  with `ProducerError::InvalidRecordOrder`.
- Ratified gap semantics are retained: gaps stay visible and no contiguous
  sequence numbering was introduced.

This closes `issue/I-07` at the public producer API.

## Tests

Twelve abstract tests cover both profiles with valid byte-derived order,
duplicate and decreasing positions for each profile, wrong domain, wrong
epoch, profile-mode mismatch, invalid revision and knowledge-time
representations, malformed and non-canonical bytes, an unknown ordering kind,
an unregistered profile identity, an unknown spec profile kind, and byte
replacement after a valid check. The compile-fail doctest checks that an
external key cannot be supplied on `CanonicalRecord`. All values are abstract;
no market data, provider contact, right or live route is involved.

## Gate evidence

Commands ran in the worktree with no commit. Each gate exited zero.

| Command | Outcome |
|---|---|
| `cargo fmt --all` and `cargo fmt --all -- --check` | applied; check passed |
| `python3 scripts/check_style.py` | clean: json 14, makefile 1, markdown 67, python 36, shell 7 |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | exit 0; inherited review candidates only |
| `python3 scripts/check_prose_unified.py --all` | PASS; advisory review candidates only |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps` | passed |
| `python3 scripts/check_rust_style.py` | PASS on changed lines versus main |
| `cargo xtask fmt` | passed |
| `cargo xtask lint` | passed |
| `cargo xtask docs` | passed |
| `cargo xtask style` | passed all 15 subcommands |
| `cargo xtask test` | passed all-target and doc tests |
| `cargo xtask verify` | passed five subcommands |
| `python3 scripts/check_architecture.py --check` | passed |
| `python3 scripts/check_naming_conventions.py` | passed |

`cargo test --workspace --all-targets --locked` reported 909 passed, 0 failed
and 12 ignored across registered targets. The doc-test run reported 2 passed
and 0 failed.

## Non-claims

- `Implemented` only. No verification promotion, rights grant, dataset
  acceptance or cross-execution certificate is claimed.
- The canonical wire mapping stays normative; this change edits its producer
  entry path, not the ratified schema package.
- No production key, release, dataset, provider contact, adapter, market
  observation, India implementation, experiment or live route was created.
- Rights remain `UNKNOWN`, dataset acceptance stays `BLOCKED`, collection stays
  `DISABLED`, experiments stay `BLOCKED`, live execution stays `DISABLED`,
  budget stays INR 0 and D11 stays strict.
