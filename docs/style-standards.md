# Style standards and their enforcement

`STYLES.md` names the mandatory published style references. Local copies are
retained under `references/` with a SHA-256 index; their integrity is verified
by `scripts/check_style_references.py`, which runs in local polish and in the
`added-line-style` CI job. A published guide is evidence, not a gate: the
binding rules are the repository's own checkers and lint configuration.

## Adopted documentation standard

Fieldbook adopts the siebensterne documentation standard recorded in the workspace
file `engineering/style/DOCUMENTATION-STANDARD.md` (adopted 2026-11-24). Markdown is
the source for human-maintained documentation; rustdoc `///` carries public API
contracts, `//!` carries crate and module contracts, and `//` carries implementation
reasoning. Unsafe blocks use `// SAFETY:`, tracked annotations use `// TODO(owner):`
and `// FIXME(owner):`, and permanent architecture decisions are Markdown ADRs.
A rendered handbook uses mdBook, a Unix manual uses generated ROFF and a publication
PDF uses Typst; these three formats are optional and applied where needed.

This standard introduces no competing source of documentation. Rustdoc documents what
code exposes; Markdown documents how the system works.

### Canonical language documentation

The language references below are canonical external links. They are not mirrored in
`references/` because that index records local files verified by SHA-256 under
`scripts/check_style_references.py`; adding local copies would break its mandated set.
The binding repository rules remain the checkers and lint configuration.

- Rust rustdoc: https://doc.rust-lang.org/rustdoc/how-to-write-documentation.html
- Rust reference: https://doc.rust-lang.org/reference/
- C++: https://isocpp.org/ and https://en.cppreference.com/w/
- Python 3: https://docs.python.org/3/
- Bash: https://www.gnu.org/software/bash/manual/

## Reference-to-gate mapping

| Mandated reference | Repository enforcement |
|---|---|
| Google Rust guide and Linux kernel Rust guidelines | `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `scripts/check_rust_style.py` on added lines |
| Google Python guide | `ruff`, `pyink`, `python3 -m unittest discover` under `scripts/` |
| Google shell guide | `scripts/check_shellcheck.py`, `bash -n` over `scripts/` |
| Google JSON/C++ guide | `scripts/check_style.py` for JSON, Makefile and structured text |
| Google documentation guide | `scripts/check_style.py` for Markdown, `scripts/assurance/english_audit.py --strict` |
| Rustdoc and doc tests | `cargo doc --no-deps --workspace --locked` with `RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links"`, `cargo test --workspace --doc --locked` |

## Change rule

When a style decision changes code or a gate, it must be made through a normal
PR: update `docs/coding-standard.md` where the rule is binding, add or adjust a
checker and its unit tests, and keep `STYLES.md` and `references/` intact. The
reference-integrity gate fails closed on a missing, empty or altered copy.
