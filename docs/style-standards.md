# Style standards and their enforcement

`STYLES.md` names the mandatory published style references. Local copies are
retained under `references/` with a SHA-256 index; their integrity is verified
by `scripts/check_style_references.py`, which runs in local polish and in the
`added-line-style` CI job. A published guide is evidence, not a gate: the
binding rules are the repository's own checkers and lint configuration.

## Reference-to-gate mapping

| Mandated reference | Repository enforcement |
|---|---|
| Google Rust guide and Linux kernel Rust guidelines | `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `scripts/check_rust_style.py` on added lines |
| Google Python guide | `ruff`, `pyink`, `python3 -m unittest discover` under `scripts/` |
| Google shell guide | `scripts/check_shellcheck.py`, `bash -n` over `scripts/` |
| Google JSON/C++ guide | `scripts/check_style.py` for JSON, Makefile and structured text |
| Google documentation guide | `scripts/check_style.py` for Markdown, `scripts/assurance/english_audit.py --strict` |

## Change rule

When a style decision changes code or a gate, it must be made through a normal
PR: update `docs/coding-standard.md` where the rule is binding, add or adjust a
checker and its unit tests, and keep `STYLES.md` and `references/` intact. The
reference-integrity gate fails closed on a missing, empty or altered copy.
