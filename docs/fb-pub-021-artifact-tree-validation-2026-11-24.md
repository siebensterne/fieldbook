# FB-PUB-021 — descriptor-relative artifact tree validation, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**, 2026-11-24. Branch
`fix/pub-021-artifact-tree-validation`, base commit `2ca329c`. No commit was
created by this work package. This record states scope and gates. It is not a
durability certificate, a release, a rights grant or a verification promotion.

Authority: this record tightens the release-tree checks of
[FB-PUB-019](fb-pub-019-directory-durability-2026-11-24.md) and
[FB-PUB-020](fb-pub-020-restart-independent-recovery-2026-11-24.md) without
rewriting either dated record. `src/distribution/ndc_release.rs` stays the
single producer authority. The release layout stays `manifest.json`,
`signature.json` and declared paths under `artifacts/`.

## Defect corrected

`validate_artifact_set` read directory entries by path and then reread each
file by path. Names and digests were checked, object types were not, and
`fs::read` follows a symlink. A replaced `artifacts/` directory, a symlinked
manifest, sidecar or artifact, a FIFO or a change between enumeration and read
could therefore escape the check. Recovery used the same pattern through
`read_no_follow_directory` and `read_no_follow_regular`.

## Correction

One descriptor-relative validator now serves the normal build path, the
v2 staging and final recovery checks, and the immutable-intent recovery path:

1. Open the release root with `open(O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
   O_CLOEXEC)`, which rejects a symlink at the root boundary.
2. Enumerate the root stream through `fdopendir` and `readdir`. Require exactly
   `manifest.json`, `signature.json` and `artifacts/`, and classify every entry
   with `fstatat(AT_SYMLINK_NOFOLLOW)` before opening it.
3. Open the manifest, sidecar and `artifacts/` with `openat` and `O_NOFOLLOW`;
   require a directory for `artifacts/` and a regular file for the two roots.
4. Enumerate the artifact stream through the held descriptor. Require exactly
   the declared relative names and classify each entry without following
   symlinks. A declared path still passes `validate_artifact_path`.
5. Open each declared artifact with `openat` and `O_NOFOLLOW`; require a
   regular file with `fstat`, then read bytes from that opened descriptor for
   the stored digest and, in intent recovery, the uncompressed digest.
6. Bind the manifest digest, the signature sidecar digest and every stored
   digest. The normal build passes the digest of its prepared sidecar bytes.
   V2 recovery passes `PublicationIntentV2.sidecar_sha256`; a changed sidecar
   withholds the receipt and every acknowledgement. Legacy evidence-based v1
   recovery has no prepared sidecar digest in its caller contract and binds the
   regular-file type and manifest and artifact digests under the same no-follow
   tree access.
7. Re-enumerate both held directory streams at the end. A changed entry set
   during validation fails the check.

The root and artifact descriptors stay open during all reads. A path moved or
replaced after the boundary open cannot redirect those reads. Every unsafe
libc call is isolated in private helpers with `SAFETY` comments; the crate-level
`unsafe_code = "deny"` stays in force outside the documented blocks.

## Hard-link policy

Hard links are refused. Every regular file must have `st_nlink == 1` at
enumeration and at the opened descriptor. A release tree owns its bytes: the
producer creates each file new under a fresh staging directory, and an alias
outside that tree could replace the hashed bytes after validation. Accepting
hard links would trade that storage ownership for no measured benefit in this
producer. The policy applies to the manifest, the sidecar and every artifact.
Directory link counts are not constrained.

## Platform primitives and limits

- Linux and macOS use `open`, `openat`, `fstat`, `fstatat`, `fdopendir`,
  `readdir`, `rewinddir` and `closedir` through the libc crate. Directory
  opens add `O_DIRECTORY`; every child open adds `O_NOFOLLOW`. Other targets
  fail closed with `UncertainPublication`.
- `readdir` returns a null pointer at end of stream and does not distinguish an
  enumeration I/O error from a completed walk. A failed walk therefore appears
  as a changed or incomplete entry set rather than a typed I/O error.
- Only the final component of the release root path is protected by
  `O_NOFOLLOW`; an ancestor symlink in the caller-supplied root is outside this
  boundary. Children are opened relative to descriptors, so ancestor changes
  cannot redirect them.
- Artifact paths remain one ASCII component below `artifacts/` under the
  existing resource policy. The validator does not accept nested paths.
- Descriptor-relative access stops path substitution. It does not stop a
  writer that mutates the bytes of the same opened inode after the digest
  read; release ownership and the FB-PUB-019 sync barriers bound that case.
- File bytes are buffered in memory for digest verification as in the prior
  validator. Resource-policy byte limits at prepare time remain the bound.

## Tests and preserved contracts

Offline fixtures cover a symlinked `artifacts/`, symlinked manifest, sidecar
and artifact, an artifact FIFO, an artifact directory, altered artifact bytes,
altered sidecar bytes, extra and missing artifacts, a name swapped and a
directory replaced after enumeration, a release root path replaced while its
descriptor stays pinned, and hard links present before and after enumeration.
Each failure asserts that validation rejects the tree and that v2 recovery
quarantines the operation with no receipt, availability marker or successful
recovery outcome.

PUB-019 bottom-up syncs, PUB-020 intent and recovery semantics, quarantine,
atomic no-replace rename, artifacts layout and journal v2 are unchanged. No
gate was weakened.

## Gate evidence

Commands ran in the worktree with no commit. Each gate exited zero.

| Command | Outcome |
|---|---|
| `cargo fmt --all` and `cargo fmt --all -- --check` | applied; check passed |
| `python3 scripts/check_style.py` | clean: json 14, makefile 1, markdown 66, python 36, shell 7 |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | exit 0; inherited review candidates only |
| `python3 scripts/check_prose_unified.py --all` | PASS; inherited advisory candidates only |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps` | passed |
| `CHALLENGE_STYLE_BASE=2ca329c python3 scripts/check_rust_style.py` | passed on changed lines |
| `cargo xtask fmt`, `lint`, `docs`, `style`, `test`, `verify` | all passed |
| `cargo xtask test` | 762 library tests and all integration targets; 1 doc test |
| `python3 scripts/check_architecture.py --check` | passed: 90 Rust source files, 90 reachable, 3 diagrams |
| `python3 scripts/check_naming_conventions.py` | passed |

The `ndc_release` module contributes 121 tests. Sixteen new tests cover object
types, digest binding, enumeration races, descriptor pinning, hard links and
the absence of receipts or availability markers after each failure.

## Non-claims

- `Implemented` only. No `Verified` promotion or independent evidence package
  is claimed by this record.
- D0 process recovery is exercised from durable evidence. D1 power-loss
  durability remains unqualified pending filesystem qualification.
- A signature proves publisher-key control over signed bytes. It grants no
  source authenticity, coverage, right, dataset entitlement or observation
  truth.
- Rights stay `UNKNOWN`, dataset acceptance stays `BLOCKED`, collection stays
  `DISABLED`, experiments stay `BLOCKED`, live execution stays `DISABLED`,
  budget stays INR 0, the India feed stays absent, the immutable journal is not
  rewritten, no shared crate is added and D11 stays strict.
