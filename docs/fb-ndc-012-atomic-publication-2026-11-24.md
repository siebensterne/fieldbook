# FB-NDC-012 — atomic no-replace directory publication, 2026-11-24

<!-- SPDX-License-Identifier: Apache-2.0 -->

Status: **Implemented in the working tree**, 2026-11-24. Branch
`fix/ndc-atomic-publication` at base commit `dd90899`. No commit was created by
this work package. This record names the primitive, the transition model and
the platform bounds. It is not a durability certificate, a release, a rights
grant or a verification promotion.

Authority: this record amends the publication mechanism of
[FB-NDC-001](fb-ndc-001-release-producer-2026-11-24.md) without rewriting that
dated record. `src/distribution/ndc_release.rs` remains the single authority
for the producer surface. The earlier exclusive-create plus hard-link path was
a visible intermediate directory; this work package replaces it.

## Defect corrected

The prior `finalize_publication` created the final release directory, linked
files into it one at a time and then wrote a stage labelled
`ATOMIC_NO_REPLACE_RENAME`. A consumer could observe a partial release, and
the stage label did not describe a directory rename. The replacement writes
every file into an exclusive sibling staging directory, fsyncs each file and
the staging directory, then calls one no-replace directory rename. The stage
`ATOMIC_NO_REPLACE_RENAME` is recorded only after that call returns success.
`create_dir` is confined to staging; the final release name is produced by the
rename alone.

## Primitive and platform qualification

| Target | Primitive | Qualification |
|---|---|---|
| Linux | `renameat2(AT_FDCWD, from, AT_FDCWD, to, RENAME_NOREPLACE)` through `libc::syscall` | Kernel and filesystem support for `RENAME_NOREPLACE` is required. The flag rejects an existing destination with `EEXIST`; absence of support surfaces as an I/O error. The Linux branch is source-qualified here and was not executed on this host. |
| macOS | `renamex_np(from, to, RENAME_EXCL)` through `libc` | Darwin and the backing filesystem must support `RENAME_EXCL`; otherwise the call returns an I/O error. The success and collision cases were exercised on the local temporary filesystem used by the tests. |
| Other targets | None | `atomic_no_replace_rename` returns `io::ErrorKind::Unsupported`. There is no fallback to `create_dir`, `hard_link` or a replacement-capable `rename`. |

`#![deny(unsafe_code)]` remains in force for the crate. The two `unsafe`
blocks sit inside the platform helper and carry `#[expect(unsafe_code, ...)]`.
Each documents pointer validity, non-null buffers and non-aliasing paths in a
`// SAFETY:` comment. Path bytes are converted to `CString` through
`std::os::unix::ffi::OsStrExt`; an embedded NUL fails with a typed I/O error.
`PublicationTopology` rejects staging and final paths that are not siblings
or that differ in Unix device id. No existence check precedes the rename.

## Transition and recovery model

| Transition | Durable evidence | Recovery meaning |
|---|---|---|
| Before staging | No stage evidence | `NoEvidence`. No release name and no acknowledgement exist. |
| During write or file sync | Staging directory with a partial file set and a stage at `STAGING_CREATED`, `FILES_WRITTEN` or `FILES_SYNCED` | `UncertainPublication`. Recovery promotes no partial release and writes no receipt. |
| After staging sync | Complete staging, stage `STAGING_DIR_FSYNCED`, no final name | `RecoveredStaged`. Recovery verifies the file set, renames, syncs the parent, commits the receipt and marker. |
| After rename, before parent sync | Final directory, stage `ATOMIC_NO_REPLACE_RENAME`, no receipt | Uncertain publication. Recovery verifies the final file set, reconciles the receipt and writes the acknowledgement. |
| After parent sync, before receipt | Final directory, stage `PARENT_DIR_FSYNCED`, no receipt | Publication exists with an unresolved receipt. Recovery commits the receipt and marker from verified evidence. |
| After receipt | Receipt on disk, stage `DURABLE_PUBLICATION_RECEIPT` | Recovery writes the missing marker and reports `RecoveredPublished`. |
| After marker | Receipt, marker and stage `AVAILABLE` | `AlreadyAvailable`. Recovery rewrites nothing. |

A receipt is the acknowledgement. Recovery writes one only from a verified
staging or final directory, or completes a receipt that the interrupted run
had already committed. `AlreadyAvailable` requires both the matching receipt
and the marker; recovery does not report that outcome for an interrupted run.
A receipt with mismatched digests, a receipt without a final directory, or an
absence of both staging and final evidence fails closed.

## Offline test coverage

Tests use abstract identifiers, injected test keys and arbitrary temporary
bytes. They cover the real primitive on the host platform, invisible final
names before the rename, collision refusal, four concurrent attempts with one
winner, injected failures at the pre-rename, parent-sync, receipt and marker
boundaries, recovery from each resulting state, and rejection of incomplete
staging. Platform-gated tests assert the Darwin primitive and the unsupported
target fallback. Stage-order and link-count assertions detect a return to
per-file linking.

## Gate evidence

Commands ran in the worktree with no commit. Each gate exited zero.

| Command | Outcome |
|---|---|
| `cargo fmt --all` | applied; `cargo fmt --all -- --check` passed |
| `python3 scripts/check_style.py` | clean: json 14, makefile 1, markdown 60, python 36, shell 7 |
| `python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'` | exit 0; 599 inherited review candidates, none in changed paths |
| `python3 scripts/check_prose_unified.py --all` | PASS; 550 inherited advisory candidates |
| `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps` | passed |
| `python3 scripts/check_rust_style.py` | PASS on changed lines versus main |
| `cargo xtask fmt` | passed |
| `cargo xtask lint` | passed |
| `cargo xtask docs` | passed |
| `cargo xtask style` | passed all 15 subcommands |
| `cargo xtask test` | passed all-target and doc tests |
| `cargo xtask verify` | passed all five subcommands |
| `python3 scripts/check_architecture.py --check` | passed: 90 Rust source files, 90 reachable, 3 diagrams |
| `python3 scripts/check_naming_conventions.py` | passed |

`cargo test --workspace --all-targets --locked` reported 822 passed, 0 failed
and 12 ignored across registered targets; the doc-test run reported 1 passed
and 0 failed. The inline `ndc_release` module contributes 50 tests, covering
the host no-replace primitive, collision and topology refusals, stage order,
final-directory invisibility before rename, four concurrent attempts, four
injected fault boundaries, recovery from each resulting state, and rejection
of incomplete staging.

## Non-claims

- `Implemented` only. No `Verified` promotion and no independently reviewed
  evidence package is claimed by this record.
- Linux `renameat2` was not executed on this macOS host. No cross-platform
  runtime qualification is asserted from source compilation alone.
- macOS `renamex_np(RENAME_EXCL)` was exercised on the local temporary
  filesystem used by the tests; other filesystem drivers were not measured.
- A no-replace rename constrains name resolution. It proves no source
  authenticity, coverage, right, dataset entitlement or observation truth.
- Rights remain `UNKNOWN`, dataset acceptance stays `BLOCKED`, collection stays
  `DISABLED`, experiments stay `BLOCKED`, live execution stays `DISABLED`,
  budget stays INR 0 and D11 stays strict.
- No production signing key, release, dataset, provider contact, adapter,
  market observation, India implementation or experiment was created.
- No production durability claim is made. Cross-host replication, backup and
  restore remain a separate durability tier that needs its own evidence.
