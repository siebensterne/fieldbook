# FB-LIMIT-001 — producer expansion ratio against stored bytes, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**. Branch `fix/fb-limit-001`, base
commit `5f3321d`. No commit was created by this work package. This record states
the defect, the corrected invariant, the zero-stored-byte rule and the gate
record. It is not a resource-profile ratification, a codec registration, a
durability certificate, a release, a rights grant, a dataset acceptance or a
verification promotion.

## Defect and scope

`src/distribution/ndc_stream.rs` computed
`allowed = expanded_bytes * max_expansion_ratio` and then compared
`expanded_bytes <= allowed`. For a ratio of one or more, that comparison holds
for each finite byte count, so the producer admitted a compressed artifact
that expanded past the profile ratio. The stored-to-expanded relationship used
by the verifier was absent from the producer path.

The change is confined to `src/distribution/ndc_stream.rs`, this record and the
README entry. Codec identifiers, the wire mapping, the manifest field set, the
receipt shape, approved digests and the `ProfileLimits` field set are unchanged.
No provider contact, collection, experiment, live routing, rights decision or
data action occurred. Rights stay `UNKNOWN`, dataset acceptance stays `BLOCKED`,
budget stays INR 0, and D11 stays strict.

## Corrected invariant

After the codec finishes and before any replay proof, manifest or seal is
built, `enforce_expansion_ratio` checks:

```text
expanded_bytes <= stored_bytes * max_expansion_ratio
```

Both operands are widened to `u128` before multiplication, so the product of
two `u64` profile values cannot wrap. A refusal is a typed
`StreamError::PolicyExceeded` naming `max_expansion_ratio`. The preparation
intent is durable at that point; the sealed intent, compatibility publication
intent, receipt, marker and final rename are not written.

Zero-stored-byte rule: `stored_bytes == 0` admits `expanded_bytes == 0` only.
An uncompressed empty artifact has zero bytes on both sides and passes; an
expanded stream with no stored bytes is refused. A gzip empty artifact stores
framing bytes and expands to zero, so it passes through the general relation.

## Compatibility and tests

Plan/source pairing, canonical artifact order, one-record-at-a-time bounded
reads, the fixed handoff queue, the two-intent lifecycle, cancellation
boundaries, other profile limits and the shared publication core are unchanged.
No codec profile was registered or changed; codec registration stays deferred.

Fifteen tests cover the boundary at the limit, one expanded byte above the
limit, the zero-stored-byte rule for pass and refusal, the regression case
admitted by the tautological calculation, `u64::MAX` operands, a wide product
above the bound, the one-stored-byte boundary, a plain artifact at ratio one,
high-entropy gzip content within a ratio of two, highly compressible gzip
content above the ratio, absence of a seal and receipt after refusal, empty
plain and gzip artifacts, and a refusal in the second canonical artifact of a
two-artifact operation.

## Gate record

Style sweeps ran after formatting: `cargo fmt`, `scripts/check_style.py`,
`scripts/assurance/english_audit.py --strict --exclude 'references/*'`,
`scripts/check_prose_unified.py --all`, strict rustdoc with warnings and broken
intra-doc links denied, and `scripts/check_rust_style.py`. Each
returned exit 0; no finding was attributed to the changed lines. The task gates
then ran in order and returned exit 0: `cargo xtask fmt`, `cargo xtask lint`,
`cargo xtask docs`, `cargo xtask style`, `cargo xtask test`,
`cargo xtask verify`, `python3 scripts/check_architecture.py --check` and
`python3 scripts/check_naming_conventions.py`. No gate is unresolved.
