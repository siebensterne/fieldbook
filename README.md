# Fieldbook — securities market-data platform

Fieldbook is the authoritative source-acquisition and release platform for the
siebensterne workspace. Its domain is Indian securities reference data,
instruments, observations, corporate actions and issuer facts, acquired only
under written rights and released as immutable, rights-bound datasets to
Nirnay. It does not place orders, hold positions, run strategies or perform
pre-trade risk. The repositories remain independent; there is no shared crate.

No venue adapter is registered. Until a source, its rights and its NDC
projection are qualified, the composition root denies `collect`, `discover`
and `latency` before any client or socket is created. No venue capability,
readiness, capacity or performance claim is made.

## Status and verification

Workspace `CURRENT-STATE.json` owns current state, freezes and authorizations;
this README does not duplicate them. `Implemented` means code and deterministic
offline tests exist. `Verified` requires a named commit and an independently
reviewed evidence package with commands, output, digests and limits. Generic
journal, replay, storage and acquisition infrastructure is implemented; no
venue path is verified. A green gate is not data rights or a complete universe.

## Document authority

| Topic | Owner |
|---|---|
| Style | `STYLES.md` and `docs/style-standards.md` |
| Implementation | `docs/architecture.md` |
| Purpose | `docs/platform-charter.md` |
| Target architecture | `docs/global-data-architecture.md` |
| Decisions | `docs/adr/` |
| Data contract | workspace `NDC-REGISTRY.md` and the approved NDC v2 producer requirements |
| Requirement evidence | `docs/requirement-test-matrix.md` |
| Operating envelope | `docs/operating-envelope.md` |
| Rights and egress | `docs/rights-enforcement-2026-11-23.md`, `docs/egress-intent-2026-11-23.md` |

A status correction is a documentation edit; a contract change needs an
approved digest; a retirement is a new dated record, not a rewritten history.
Other documents under `docs/` are dated or supporting records, not parallel
authorities.

## Build and gates

`Makefile` is a facade over `cargo xtask`, which owns the gate definitions and
writes `target/xtask/last-run.json`. Rust is pinned in `rust-toolchain.toml`;
Python and shell tools are pinned in `requirements-dev.txt`.

```bash
cargo xtask fmt       # rustfmt check
cargo xtask lint      # clippy with warnings denied
cargo xtask docs      # rustdoc with broken links denied
cargo xtask style     # language and policy gates
cargo xtask test      # permitted all-target and doc tests
cargo xtask verify    # matrix, architecture and generated-path gates
cargo xtask check     # full gate
```

`make check-static` runs the non-test surface. No provider-contacting command
is runnable and live execution stays disabled. `config.example.toml` carries
no endpoint, credential, account identifier or venue default.

## Scope and provenance

`sbe_schemas/` is the supplied schema; `src/util/build.rs` generates the SBE
bridge. Dependency licenses and the pinned graph are in `Cargo.lock`. D11
retired synthetic market-shaped fixtures; abstract protocol and pure
mathematical tests remain under the test policy. The operating envelope is
not a production certification for order entry or execution.
