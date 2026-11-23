# Documentation consolidation record — 2026-11-23 (RRP-005)

Status: documentation-only consolidation under RRP-005. This record adds no
capability, contacts no provider, changes no right or dataset and rewrites no
Git history. No commits are made by this change.

## Scope

RRP-005 puts one authority on each documentation topic. Historical claims stay
in Git history and in dated evidence rather than in a second status record.
Approved document bytes keep their digests. The implementation-versus-verification
distinction is retained: implemented code with offline tests is not a verified
venue capability.

## Changes

| Path | Change |
|---|---|
| `README.md` | Rewritten for the securities platform. Retired venue language, stale capability claims and runnable provider commands removed. Authority map and implementation-versus-verification section added. |
| `docs/programme-status.md` | Replaced with a concise pointer to workspace `CURRENT-STATE.json` and the dated records. Integration tables, counts and capability inventories retired to Git history. |
| `docs/requirement-test-matrix.md` | Replaced with a concise matrix. Requirement IDs and all mandatory file-qualified test references retained; stale venue status prose removed. |
| `docs/design-decisions.md` | Replaced with a dated pointer to the ADRs. Former content duplicated the ADRs. |
| `docs/compile-time-optimisation.md` | Replaced with a dated pointer. Its content was a one-time local build measurement. |
| `measurements/README.md` | Replaced with a dated pointer to the retirement records and the retained durability evidence. |
| `docs/analytics-data-contract.md` | Marked deprecated with a migration reference to approved NDC v2. Kept until NDC v2 release publication replaces it. |
| `references/verilogguide.html` | Deleted as an orphan: no Verilog source or gate exists. |
| `references/awesome-style-guide-master.md` | Deleted as an orphan discovery index with no adopted rule. |
| `references/index.md` | Orphan rows and their scope notes removed. |
| `STYLES.md` | Verilog mandate removed. |
| `scripts/check_style_references.py` | `MANDATED` set reduced to the remaining copies, in step with `STYLES.md` and `references/index.md`. |
| `docs/style-standards.md` | Reference-to-gate rows for the two orphans removed. |
| `docs/operating-envelope.md` | Evidence pointer updated from the retired index to `measurements/live/`. |
| `docs/documentation-consolidation-2026-11-23.md` | This record added. |

## Authority map

| Topic | Single authority |
|---|---|
| Style | `STYLES.md` |
| Actual implementation | `docs/architecture.md` |
| Purpose | `docs/platform-charter.md` |
| Target architecture | `docs/global-data-architecture.md` |
| Decisions | `docs/adr/` (ADRs) |
| Data contract | approved NDC v2 producer requirements, `engineering/ndc-producer-requirements-v2-proposed.md`, and workspace `NDC-REGISTRY.md` |
| Current state | workspace `CURRENT-STATE.json` |
| Requirement-to-test evidence | `docs/requirement-test-matrix.md` |

## Retained documents

Normative documents are kept without byte changes: `docs/architecture.md`,
`docs/platform-charter.md`, `docs/global-data-architecture.md`,
`docs/durability-contract.md`, `docs/raw-frame-journal.md`,
`docs/event-accounting-contract.md`, `docs/replay-format.md`,
`docs/segmented-durability-design.md`, `docs/canonical-event-model.md`,
`docs/specifications/`, `docs/india-reference-foundation-design.md`, the ADRs
and the approved NDC v2 requirements. `docs/analytics-data-contract.md` is
retained as deprecated until NDC v2 release publication replaces it.

Dated retirement records are retained unchanged:
`docs/synthetic-asset-retirement-2026-11-23.md` (RRP-002) and
`docs/product-scope-retirement-2026-11-23.md` (RRP-003). The W1.1/W1.2 policy
record `docs/synthetic-test-policy-2026-11-23.md` stays immutable.

## Verification

Gates run for this change are `cargo xtask fmt`, `cargo xtask lint`,
`cargo xtask docs`, `cargo xtask style` and `cargo xtask test`. The
requirement-matrix and style-reference gates are included in `style` and
`verify`. No dangling local reference was left by the retirements, and the
SHA-256 of every approved document named above was compared before and after
this change. Exact commands, exit statuses and counts are reported with the
change; a green gate is not data rights or a venue claim.
