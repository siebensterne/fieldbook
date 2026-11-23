# Repository style guide

This document is the normative style contract for every language in the
repository. Each rule is enforced by a formatter or a fail-closed check in
`cargo xtask style` and in CI; a rule without an automated check is not part
of this contract. The existing Rust rules remain in `docs/coding-standard.md`.

## Sources

[Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)
[Google Shell Style Guide](https://google.github.io/styleguide/shellguide.html)
[Google Markdown Style Guide](https://google.github.io/styleguide/docguide/style.html)
[Google JSON Style Guide](https://google.github.io/styleguide/jsoncguide.html)
[Google Rust Style Guide](https://google.github.io/styleguide/rustguide.html)
[Linux kernel Rust coding guidelines](https://docs.kernel.org/rust/coding-guidelines.html)
[Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)

No top HFT or quant firm publishes a complete public style guide. Public
material instead exposes consistent engineering values: Jane Street's
[tech talks](https://www.janestreet.com/tech-talks/) and
[blog](https://github.com/janestreet/blog) emphasise strong types, small
reviewable changes and operating software that handles real money;
[Hudson River Trading](https://www.hrt.com/technology/) and
[Citadel](https://www.citadel.com/careers/technology/) describe low-latency
C++ and Python control planes; and practical Rust-for-HFT write-ups such as
[Luca Sbardella's](https://lucasbardella.com/coding/2025/rust-for-hft/)
collect the transferable rules below. These practices are adopted where they
apply to a read-only collector; no claim is made that they are a firm's internal
standard.

## Tool matrix

| Language | Formatter | Linter | Gate |
|---|---|---|---|
| Rust | `cargo fmt` | `cargo clippy -D warnings`, rustdoc | `cargo xtask fmt lint docs` |
| Python | Pyink 26.5.1 | Ruff 0.17.5, unittest | `cargo xtask style` |
| Shell | `scripts/check_style.py` | ShellCheck 0.11.0 | `cargo xtask style` |
| Makefile | `scripts/check_style.py` | same checker | `cargo xtask style` |
| JSON | `scripts/check_style.py` | same checker | `cargo xtask style` |
| Markdown | `scripts/check_style.py --fix` | same checker | `cargo xtask style` |
| q / kdb+ | none (scripts are short) | `scripts/check_q_style.py` (added lines) | `cargo xtask style` |

Versions are pinned in `requirements-dev.txt`. `make tools` installs them;
CI installs the same file before running any gate.

## Rust

`rustfmt` is the only formatter and `.rustfmt.toml` pins Unix newlines and
the edition-2024 style. Clippy levels live in `Cargo.toml` and are all denies:
no `unwrap`, `expect`, `panic`, `todo`, `unimplemented`, `dbg!` or
`println!`; safety comments, documentation, assertion form, panic docs,
wildcard imports and item placement are enforced. Generated SBE code is the
single module-scoped exception and is isolated from hand-written code.
Rustdoc rejects broken intra-doc links. Do not add an `allow` where an
`expect` with a reason compiles.

## Python

Pyink is Google's Black fork and implements the guide's 4-space indentation,
100-column lines and majority-quote rule. Its settings are in `pyproject.toml`.
Ruff enforces pycodestyle, pyflakes, isort ordering, naming, Google-convention
docstrings, pyupgrade, bugbear, simplification, blind-except, PIE, return,
Ruff-specific rules and annotations. Its settings are in `ruff.toml`. Every
selected rule is a failure; there are no warning-level suppressions.

Every module has a docstring and `from __future__ import annotations`.
Public functions, methods and classes have docstrings and return annotations.
Imports use full module paths; exceptions carry context; mutable global state
is avoided; `assert` never carries production logic. Test functions may use
`assert` to state expectations.

## Shell

Executables start with `#!/bin/bash`. Error messages go to stderr. Two-space
indentation, 80-column lines, quoted expansions, `[[ ... ]]` for tests,
`(( ... ))` for arithmetic, arrays for argument lists and `$(...)` for
command substitution are required. `eval`, backticks, bare `[` and unquoted
list expansions are rejected. Every script has a file header comment;
non-obvious functions have `Globals`, `Arguments`, `Outputs` and `Returns`
comments. ShellCheck with `-x` follows sourced libraries and is fail-closed.

Here-documents marked `PY` contain Python, are formatted as Python and are
not shell-wrapped. Generated evidence under `measurements/` and `captures/`
is immutable and hash-pinned, so it is validated for syntax but never
reformatted.

## Makefile

Recipes use tabs; directives and targets do not. Every target is listed in
`.PHONY`, targets are unique, and lines stay within 80 columns except URLs.
`Makefile` is a thin façade over `cargo xtask`; the task runner owns the gate
definitions so local and CI behavior cannot diverge.

## JSON

JSON files use double quotes, no comments, no trailing commas, no duplicate
keys, two-space structural indentation, a final newline and no trailing
whitespace. Property names follow the versioned report and fixture schemas:
these files are persisted artifacts, not new public APIs, so the guide's
camelCase API naming rule is not applied to them. The guide's
formatting and value rules are enforced. Byte-exact raw observations retained
as evidence are hash-pinned in their manifest and must not be reformatted;
synthetic fixture files were retired under RRP-002.

## Markdown

One H1 on line 1, ATX headings with unique names, a space after each `#`,
labelled fenced code blocks, blank lines around blocks, no trailing
whitespace and a final newline. Prose wraps at 80 columns. Links, tables,
headings, code blocks and inline code spans are the guide's explicit
exceptions and are never rewritten by the fixer. Use explicit in-repo paths
rather than parent-directory links, prefer reference links for long URLs, and
use tables only for genuinely tabular data. Do not use raw HTML where Markdown
suffices.

## HFT-derived engineering rules

These are operational rules, not style preferences:

1. **Determinism over convenience.** Identical inputs produce identical outputs;
   seeds, clocks and order are explicit inputs, never implicit state. This is
   why every stress cell records its seed and workload model.
2. **Fail closed.** Unknown versions, missing provenance, ambiguous decode and
   uncertain acknowledgements are rejected or reported as uncertain, never
   guessed. A zero exit code is not success.
3. **Account for every record.** Each inbound observation receives an explicit
   disposition. The ledger reconciles only when input and output counts agree
   exactly; no silent drops.
4. **Separate state domains.** Connection health, instrument activity and book
   continuity are independent, so a quiet market cannot trigger a reconnect and
   a reconnect cannot fabricate an anchor.
5. **Bounded work.** Queues, buffers, retries and decompression are bounded; a
   host cannot be made to allocate without limit by a remote frame.
6. **No hidden work in the hot path.** Avoid unnecessary allocation and IO on
   the ingress path; use stack values and explicit moves. Measure before
   claiming latency, and state the measurement method with the result.
7. **Evidence is immutable.** Raw journals, captures and failed runs are
   retained with source commit and SHA-256 hashes. A failed run that exposed a
   defect is stronger evidence than a clean demo.
8. **No fabricated data.** Synthetic loopback is labelled as such and never
   becomes a live claim. Live runs use direct, read-only public data with no
   proxy, VPN, hosted runner or private credentials.

## File naming

Active paths under `src/`, `tests/`, `xtask/`, `docs/`, `scripts/` and `tools/`
use domain names without phase labels such as `p6_` or `m5-`. Historical
labels stay in `measurements/` and `captures/`, which hold byte-exact evidence.
`scripts/check_naming_conventions.py` enforces this boundary in `cargo xtask verify`.

## Commands

```bash
make tools           # install pinned Python tool versions
cargo xtask style    # all non-Rust gates
cargo xtask style-fix # apply safe Pyink and Markdown fixes
cargo xtask check    # style, Rust gates, checks and e2e
cargo xtask ci       # the full gate, including release build
scripts/assurance/polish.sh --loop 2
```

## Explicit exceptions

Three Python files hold long vocabulary, regex and responsibility-map
  string constants. They are exempt from E501 in `ruff.toml` and from
  the 100-column line check by name in `scripts/check_style.py`; both lists
  must stay in lockstep.
- Immutable evidence and the raw wire fixture are excluded from formatting.
- The Google JSON API naming rule does not apply to persisted schema fields.
- Vendored third-party documents under `references/` are byte-exact and
  hash-pinned by `scripts/check_style_references.py`; the English prose audit
  excludes them because their wording is not authored project prose. That hash
  check is the fail-closed guard for this exception.

Every other rule has no exemption mechanism. Do not add one without a documented
reason in this file and a matching fail-closed check.
