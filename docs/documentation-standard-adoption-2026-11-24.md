# Documentation standard adoption — sweep and gate evidence

Date: 2026-11-24
Branch: `docs/style-standard`
Base commit: `e0472f7` (`e0472f7610ee062fe1a9b8aea8d7a6234a6e3b77`)

## Scope

This record covers adoption of the siebensterne documentation standard in the
Fieldbook worktree. It records full-tree prose and style sweeps run before the gate
suite, then the gate results. No domain code, provider contact, rights, data or
experiment action is part of this change.

## Part 1 — adoption changes

- `STYLES.md` — added the canonical external language-documentation links; the
  published style-guide links are retained.
- `docs/style-standards.md` — adopted the standard, added the workspace pointer and
  canonical language links, recorded why the local SHA-256 reference index is
  unchanged, and added the rustdoc and doc-test row to the reference-to-gate map.
- `docs/coding-standard.md` — added rules D9 to D13 for API, module and
  implementation comments, `SAFETY:`, tracked annotations and documented contracts.
  Existing rules D1 to D8 and every other rule are unchanged.
- `README.md` — doc-map row for this record.
- `references/index.md` — unchanged. Its format records local files with SHA-256 and
  `scripts/check_style_references.py` fixes the mandated set; URL rows were not
  invented.

## Part 2 — full-tree sweeps

All commands ran from the worktree root with Python 3 and the pinned Rust toolchain.
`scripts/check_style.py` has no `--all` switch; its default mode visits every file in
scope outside the skip directories, which is the full-tree mode used here. The
English audit used `--repo . --strict` with `references/*` excluded. The prose checker
used `--all`. Rustdoc used the denied warning and broken-link flags.

```text
$ python3 scripts/check_style.py
style: json=13, makefile=1, markdown=52, python=36, shell=7 clean
exit 0

$ python3 scripts/assurance/english_audit.py --repo . --strict --exclude 'references/*'
summary: total_findings=590, by_severity={"review": 590}, tautology=0
stats: tracked_paths=278, scanned_text_files=270, excluded_files=8
(the new record is untracked and was swept directly; see below)
exit 0

$ RUSTDOCFLAGS="-D warnings -D rustdoc::broken_intra_doc_links" cargo doc --workspace --no-deps
Finished `dev` profile [unoptimized + debuginfo] target(s)
Generated target/doc/fieldbook/index.html and 1 other file
exit 0

$ python3 scripts/check_prose_unified.py --all
PASS: unified prose audit clean (541 advisory review candidates)
exit 0

$ python3 scripts/check_style_references.py
PASS: 7 mandated style references verified
exit 0
```

### Sweep counts

| Sweep | Scope | Binding violations | Result |
|---|---|---:|---|
| `scripts/check_style.py` | json=13, makefile=1, markdown=52, python=36, shell=7 | 0 | clean |
| English audit, strict | 278 tracked paths, 270 scanned text files, 8 excluded | 0 tautologies | exit 0 |
| Rustdoc, warnings and broken links denied | workspace, no dependencies | 0 warnings, 0 broken links | exit 0 |
| Unified prose audit, `--all` | every tracked authored prose line | 0 binding, 541 advisory | exit 0 |
| Style reference integrity | 7 mandated local copies | 0 findings | exit 0 |

The banned-term categories enforced by the unified prose gate are tautologies,
U002 promotional or opaque-system terms, first-person pronouns and intent or
filler adverbs.
No confirmed finding in those categories was present in prose or in the files changed
by this adoption; the sweeps were repeated after every edit and stayed clean.

### Direct sweep of the new record

The English audit and the unified prose checker enumerate Git-index paths, so an
untracked record stays outside their whole-tree counts until it is staged. The new
file was scanned directly through the same checker entry points:

```text
$ python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, 'scripts/assurance')
import english_audit as ea
p = 'docs/documentation-standard-adoption-2026-11-24.md'
findings = ea.scan_text(Path(p).read_text(encoding='utf-8'), p)
print(f'english_audit on new record: {len(findings)} finding(s)')
PY
english_audit on new record: 0 finding(s)

$ python3 - <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, 'scripts')
import check_prose_unified as cpu
p = 'docs/documentation-standard-adoption-2026-11-24.md'
text = Path(p).read_text(encoding='utf-8')
fenced = cpu.read_fenced(text)
errs = []
for n, line in enumerate(text.splitlines(), 1):
    errs += cpu.check_line(p, n, line, n in fenced)
print(f'prose_unified on new record: {len(errs)} finding(s)')
PY
prose_unified on new record: 0 finding(s)
```

The direct sweep found one confirmed U002 finding at line 72 of the first draft: a
literal term from the opaque-system category. The wording was changed to name the
rule, the direct sweep was rerun and returned zero findings.

## Review candidates left unchanged

The following review-level candidates existed at the base commit and are outside the
documentation-and-style edit scope. They are recorded with file and line rather than
rewritten.

- `src/generated/orderbook.rs`:384, :398, :1745, :2206, :3476, :6163, :7034 — intent
  adverbs and filler terms in a build-generated codec. The prose checker excludes
  `src/generated/` by path, and a manual edit would be overwritten by regeneration.
- `config.example.toml`:49 — `good` in the established term `Last-known-good`.
- `src/storage/application/network_source.rs`:3 — `tiny` in a pre-existing source
  comment; this change does not edit domain source.

## Gate results

The gate suite ran after the sweeps reported clean. Each invocation passes when all
of its commands pass; the counts below are the `[passed]` lines in each run. The
final report is in `target/xtask/last-run.json`.

| Command | Passed commands | Exit |
|---|---:|---:|
| `cargo xtask fmt` | 1 | 0 |
| `cargo xtask lint` | 1 | 0 |
| `cargo xtask docs` | 1 | 0 |
| `cargo xtask style` | 15 | 0 |
| `cargo xtask test` | 2 | 0 |
| `cargo xtask verify` | 5 | 0 |

No gate was weakened, no suppression was added and no reference digest was changed.
