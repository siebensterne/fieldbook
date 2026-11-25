# FB-SOURCE-001 — core-owned bounded record port, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**. Branch `fix/fb-source-001`,
rebased onto `c8ac3f0` after `fix/fb-stream-002` and `fix/fb-spool-001` merged.
No commit was created by this work package. This record states the defect, the
corrected port contract, the API change and the gate record. It is not a
resource-profile ratification, a codec registration, a durability certificate,
a release, a rights grant, a dataset acceptance or a verification promotion.

## Defect and scope

`ArtifactRecordSource::next_record` returned a `CanonicalRecord` that owned a
`Vec<u8>`. The built-in `BoundedRecordFramer` checked its own length before
growth, but an arbitrary adapter could allocate a byte vector of any size
before the core observed it. The public port therefore could not apply a hard
record bound to every adapter, and canonical JSON validation depended on bytes
that the adapter supplied.

The change is confined to `src/distribution/ndc_stream.rs`, this record and the
README entry. The resource-profile field set and digest, the wire mapping, the
manifest field set, the receipt shape, the two-intent lifecycle, paired-source
sorting, spooling and the shared publication core are unchanged. No provider
contact, collection, experiment, live routing, rights decision or data action
occurred. Rights stay `UNKNOWN`, dataset acceptance stays `BLOCKED`, the budget
stays INR 0, collection stays `DISABLED`, experiments stay `BLOCKED`, live
execution stays `DISABLED` and D11 stays strict.

## Corrected port contract

The core allocates and reuses one record buffer for each artifact pass. Before
each adapter call the core clears that buffer and constructs a `RecordSink`
carrying the profile `max_record_bytes` and the record index. An adapter writes
bytes only into that sink. The sink performs checked length accounting on every
write: a chunk that would cross the bound is refused whole and no part of it
is appended. The sink also records an `exceeded` marker that the core inspects
before it propagates any adapter error, so an adapter that discards a sink
error follows the same refusal as one that returns it.

One oversized write and a sequence of smaller writes that cross the bound both
produce `StreamError::PolicyExceeded` with the message
`record {index} exceeds max_record_bytes {bound}`. Canonical JSON validation,
byte-derived ordering, digest accumulation and framing read only the bytes held
in the core buffer. The core adds the LF terminator itself and emits the record
bytes in bounded writes, with no intermediate framed-vector copy.

## API change

- `ArtifactRecordSource::next_record() -> Result<Option<CanonicalRecord>, StreamError>`
  is replaced by
  `write_next_record(&mut RecordSink<'_>) -> Result<bool, StreamError>`.
  `true` reports one framed record; `false` reports end of stream; a further
  call is a typed state error.
- `RecordSink` is a new public core-owned bounded sink. It exposes checked
  `push`, length and bound-marker queries and implements `std::io::Write` for
  adapters that stream bytes.
- `RecordSliceSource` is a compatibility adapter for callers that already hold
  canonical records. It moves that slice into its own storage and pushes each
  record into the core sink in one bounded write without an extra copy. It does
  not bound allocation performed by the caller before the write, and no claim
  of memory independence is made for it. The batch `build_release` interface
  keeps its caller-owned `Vec<CanonicalRecord>` input on the same basis.
- The adapter-owned `RecordHandoff` queue and the built-in framer's private
  record buffer are removed. One-record-at-a-time semantics, paired sources,
  two intents, bounded readers and the profile memory-budget check remain.
- FB-STREAM-002 quarantine handling is preserved. A bound refusal from the
  sink, an invalid canonical record or an out-of-order derived key is a
  pre-seal failure, so the caller receives a `PreparationQuarantined` report
  carrying its typed code and first-failure text alongside durable quarantine
  evidence. The fault-injection stages remain bound to the core-owned sink
  path.
- FB-SPOOL-001 multi-source spooling is preserved. The spool path reads through
  the same core sink and keeps per-artifact spool plans, sealed spool evidence,
  ordered file and directory barriers, shared temp-disk accounting and the
  bounded verified reader.

## Tests

Sixteen tests were added to the streaming module. They cover a write exactly at
the bound, one write past the bound, incremental writes past the bound with an
identical typed refusal and message, an adapter that discards sink errors, a
malicious one-write adapter and a malicious incremental adapter before the
seal, the compatibility adapter through the sink, deeply nested JSON, malformed
and empty JSON, a canonical record at the exact limit, a canonical record one
byte past the limit, both ordering profiles in successful passes, a decreasing
reference position, an unchanged profile digest, an oversized write on the
spool path and a structural assertion that the production path has no
pre-materialized record handoff. Refusal cases assert that preparation exists
while the sealed intent and availability evidence do not.

## Gate record

Style sweeps ran after formatting: `cargo fmt`, `scripts/check_style.py`,
`scripts/assurance/english_audit.py --strict --exclude 'references/*'`,
`scripts/check_prose_unified.py --all`, strict rustdoc with warnings and broken
intra-doc links denied, and `scripts/check_rust_style.py`. Each returned exit 0;
no finding was attributed to the changed lines. The task gates then ran in
order and returned exit 0: `cargo xtask fmt`, `cargo xtask lint`,
`cargo xtask docs`, `cargo xtask style`, `cargo xtask test`,
`cargo xtask verify`, `python3 scripts/check_architecture.py --check` and
`python3 scripts/check_naming_conventions.py`. No gate is unresolved.
