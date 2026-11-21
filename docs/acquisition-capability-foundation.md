# M3.0 acquisition and data capability foundation

This record separates engineering evidence from operational claims. It is a
local design and evidence note, not a production certification.

## Baseline

The verified baseline is commit `903d1e1`. V1 capture evidence stays intact and
is labelled `legacy_incomplete`. V2 foundations are additive. No repository
migration was restarted, and no new Rust dependency was introduced.

A claim is admitted only with proof of the matching kind:

- Connector implemented: source path and deterministic tests.
- Protocol supported: golden fixture and parser tests.
- Live data received: run artifacts from a permitted run.
- History preserved: replay and archive verification.
- Source licensed: a rights record with an effective date.
- Coverage complete: a defined universe and reconciliation.
- Low latency: a reproducible benchmark with a stated workload.
- Recovery works: fault-injection evidence.

Only the first two kinds are present in this milestone. Live receipt, complete
coverage, licensed redistribution, and latency targets remain unclaimed.

## Deliverables

M3.0.1 hardened the acquisition foundation. Feed arbitration applies finite
bounds to the duplicate window, the out-of-order buffer, the declared gap and
the rejected-evidence ledger. Pruning, rejection, delay and exhaustion are
counted. Rejected packets retain their original bytes and disposition. Packet
evidence travels in a versioned envelope bound to the unchanged v1 journal
observation, so channel, sequence, protocol, capture location and decoder
version survive. Codec registration rejects a conflicting source and schema
version. Typed domain output is produced at the normalization boundary while
raw bytes remain independent evidence.

M3.0.2 separated acquisition by modality. Streaming, snapshot, batch, document
and on-chain ports are typed traits. The shared lifecycle stays small. A
manifest must declare a modality, supply its capability structure, and show a
protocol and transport that can realize it. No connector receives credit for
an undeclared capability.

M3.0.3 strengthened the product models. Certification is computed from
independent dimensions for discovery, implementation, technical validation,
rights, operations, history, quality and certification. An ordinal status
cannot override an unmet condition. A coverage record carries the full
identity tuple and either a measured universe or an explicit statement that no
denominator exists. Institutional payloads use domain-specific structures with
valid and transaction time. Timestamps record resolution, accuracy,
uncertainty and synchronization, and an accuracy claim without synchronization
is rejected.

M3.0.4 added an independent conformance harness. A source declaration is
tested against a deterministic fixture, registered codec output, typed
normalization, rights evidence and universe disclosure. Connection success is
not a check. A failed check is reported with its reason and blocks
certification.

## Evidence and limits

The offline tests are listed in `docs/requirement-test-matrix.md`. They use
deterministic fixtures and loopback transport only. No live collection, venue
rights, hardware timestamping, exchange colocation or 90-country coverage is
established by this work. Certification remains a computed local verdict, not
an independent audit of a deployed system.
