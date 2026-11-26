# Retrieved style references

Local copies of externally published style material, retrieved 2026-11-19.
These are third-party documents under their publishers' terms; they are not
Fieldbook source and are not imported by build, test or runtime paths.
`STYLES.md` and `docs/coding-standard.md` remain the binding repository policy.
Two orphan copies were retired on 2026-11-23 under RRP-005; their bytes stay in
Git history and the change is recorded in
`docs/documentation-consolidation-2026-11-23.md`.

| File | Source | SHA-256 |
|---|---|---|
| `rustguide.html` | <https://google.github.io/styleguide/rustguide.html> | `89facc927c27c2667effc8e84fafa20c1a5161cf4fea86ea8622a90d6a6422a6` |
| `rust-coding-guidelines.html` | <https://docs.kernel.org/rust/coding-guidelines.html> | `e6baf3bb0332610f7513f6e827abbe2a4b134262b1082c587dd650f49780b8ef` |
| `cppguide.html` | <https://google.github.io/styleguide/cppguide.html> | `bdac9c1d0b5ddbc7622b696a8f049a6ca172a1dd2190d55b970afd1c15060c63` |
| `jsoncguide.html` | <https://google.github.io/styleguide/jsoncguide.html> | `be7fdbbf2cca0d00e947ba6efbaef977a84c6b7d1cd371d5e2fceb2abcb23386` |
| `pyguide.html` | <https://google.github.io/styleguide/pyguide.html> | `c81fe3405693a6b4f6e14d625b7176eab45754eef1ee76baae270abf15fec147` |
| `shellguide.html` | <https://google.github.io/styleguide/shellguide.html> | `7a5fe550de49a336fd7a4f8a5fbd78614054925443aa1c3df2bff1a98e593e30` |
| `docguide-style.html` | <https://google.github.io/styleguide/docguide/style.html> | `c7657bd8a5bdb13e5172c4136af9003c4d28a56e1f78a4f56f0217cb9cdd8d95` |

## Scope notes

- The mandated set is mirrored in `scripts/check_style_references.py`; this
  index must cover it with no extra or missing row.
- A published guide is evidence, not a gate. The binding rules are the
  added-line checkers in `scripts/` and the workspace lint configuration.
