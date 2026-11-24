# FB-PUB-020 — restart-independent publication recovery, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**, 2026-11-24. Branch
`fix/pub-020-restart-recovery`, base commit `eecfe8c`. No commit was created by
this work package. This record is a scope and gate statement. It is not a
durability certificate, a release, a rights grant or a verification promotion.

Authority: this record amends the recovery contract of
[FB-PUB-014](fb-pub-014-recovery-correctness-2026-11-24.md) and the journal
contract of [FB-PUB-019](fb-pub-019-directory-durability-2026-11-24.md) without
rewriting either dated record. `src/distribution/ndc_release.rs` remains the
single producer authority. The release layout stays `manifest.json`,
`signature.json` and declared paths under `artifacts/`.

## Defect corrected

`recover_interrupted` took caller-retained `PublicationEvidence`. Journal
records did not persist the complete artifact inventory, the sidecar digest or
all receipt fields. Tests recovered only because the caller still held heap
state from the dead process. A fresh process could not reconcile a publication
from durable ledger records and the release tree.

## Durable intent

`PublicationIntentV2` is written as `<operation-id>.intent.json` in the ledger
before the first journal stage. The file is created new, synced, and its ledger
directory is synced before any release-root change. The intent binds the intent
schema version, operation id, release id, manifest digest, signature sidecar
digest, dataset digest, commit position, staging directory, final directory,
predecessor release, every expected receipt field, the expected receipt digest,
the full artifact inventory with stored and uncompressed digests, the wire
profile and a resource profile derived from the caller policy. It carries no
private key or secret. The canonical bytes exclude the intent self-digest.

Every schema-v2 journal record adds `intent_sha256`, so the chain binds the
verified intent. Schema-v1 records omit the member and keep their published
canonical bytes, digest inputs and ranks. Mixed-version chains still fail
closed.

## Public API change

```rust
pub fn recover_interrupted(
    root: &Path,
    ledger: &Path,
    operation_id: &str,
    policy: &ResourcePolicy,
) -> Result<RecoveryOutcome, ProducerError>
```

No `BuildOutcome`, `PublicationEvidence`, `BuildRequest` or dead-process heap
reaches the public path. An evidence-based internal helper remains for schema-v1
compatibility fixtures. `RecoveryOutcome` adds
`UncertainPublicationQuarantined`.

## Recovery order

1. Load the intent by operation id and verify its canonical bytes and digest.
2. Verify the wire and resource profiles, the staging and final paths, and the
   chain identity, self-digests, ordinals and stage order.
3. Validate the exact tree without following symlinks: manifest digest, sidecar
   digest, artifact set, stored digests, uncompressed digests and byte counts.
4. Rebuild the exact receipt bytes and verify the expected receipt digest. No
   receipt is derived from an incomplete journal state.
5. Follow the FB-PUB-019 ordering: release-parent sync, receipt, ledger sync,
   marker, ledger sync and `AVAILABLE`. A final name alone never grants
   ownership; the durable rename claim and operation identity still apply.

A rename without durable ownership evidence, a staging tree with an incomplete
intent, a missing or corrupt journal, an unproven final directory, an
unreconstructible receipt or a manifest disagreement returns
`UncertainPublicationQuarantined`. Quarantine preserves all durable evidence,
writes no receipt or marker, deletes nothing and permits no automatic retry
under a new operation id. Operator reconciliation is required.

## Fresh-process evidence

A test harness runs the library test binary as separate child processes. The
publisher child writes durable state and ends with `process::exit` at a chosen
boundary. The recovery child receives only the root, ledger, operation id and a
resource profile id, and prints one of `NO_EVIDENCE`, `RECOVERED_STAGED`,
`RECOVERED_PUBLISHED`, `ALREADY_AVAILABLE` or
`UNCERTAIN_PUBLICATION_QUARANTINED`. No in-memory state crosses the process
boundary. The harness covers a rename syscall before its journal commit, a
durable staging-tree stage, a durable rename stage, and two successive
recoveries whose receipt bytes and operation chain stay byte-identical.

The FB-PUB-019 bottom-up syncs, atomic no-replace rename, receipt fidelity,
operation ownership, artifact layout, journal chaining and v1 semantics are
unchanged. No gate was weakened.

## Gate evidence

Commands ran in the worktree with no commit. Each gate exited zero.

| Command | Outcome |
|---|---|
| `cargo fmt --all` and `cargo fmt --all -- --check` | applied; check passed |
| `python3 scripts/check_style.py` | clean: json 14, makefile 1, markdown 65, python 36, shell 7 |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | exit 0; inherited review candidates only |
| `python3 scripts/check_prose_unified.py --all` | PASS; inherited advisory candidates only |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps` | passed |
| `python3 scripts/check_rust_style.py` | passed on changed lines |
| `cargo xtask fmt`, `lint`, `docs`, `style` | passed |
| `cargo xtask test` | passed: 746 lib tests and all integration targets; 1 doc test |
| `cargo xtask verify` | passed all five subcommands |
| `python3 scripts/check_architecture.py --check` | passed: 90 Rust source files, 90 reachable, 3 diagrams |
| `python3 scripts/check_naming_conventions.py` | passed |

The `ndc_release` module contributes 105 tests. Seven new tests cover intent
durability, v2 intent binding, caller-free receipt reconstruction, quarantine
conditions and the fresh-process harness.

## Non-claims

- `Implemented` only. No `Verified` promotion or independent evidence package
  is claimed by this record.
- D0 process recovery is demonstrated from durable evidence. D1 power-loss
  durability remains unqualified pending filesystem qualification.
- Cross-host replication, backup and restore remain a separate durability tier.
- A receipt is a local acknowledgement. It grants no source authenticity,
  coverage, right, dataset entitlement or observation truth.
- Rights stay `UNKNOWN`, dataset acceptance stays `BLOCKED`, collection stays
  `DISABLED`, experiments stay `BLOCKED`, live execution stays `DISABLED`,
  budget stays INR 0, the India feed stays absent, the immutable journal is not
  rewritten, no shared crate is added and D11 stays strict.
