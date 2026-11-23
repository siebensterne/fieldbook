# Programme status record

This path is a concise current-state pointer. It is not a second status
authority. The authority for current state is the workspace `CURRENT-STATE.json`
(commit heads, CI runs, static gates and test counts). Historical integration
tables, measured numbers and capability inventories were retired under RRP-005;
their bytes remain in Git history and in the dated records named below. Nothing
here promotes an implemented component to a verified venue capability.

## Current-state pointer

| Topic | Record |
|---|---|
| Heads, CI, gates, test counts | workspace `CURRENT-STATE.json` |
| Actual implementation and failure model | `docs/architecture.md` |
| Scope and ownership | `docs/platform-charter.md` |
| Target architecture | `docs/global-data-architecture.md` |
| Decisions | `docs/adr/` |
| Data contract | approved NDC v2, `engineering/ndc-producer-requirements-v2-proposed.md`, and workspace `NDC-REGISTRY.md` |
| Requirement evidence | `docs/requirement-test-matrix.md` |
| Rights, freeze, live routing | `docs/rights-enforcement-2026-11-23.md` and workspace `CURRENT-STATE.json` |

## Implementation versus verification

`Implemented` is code with deterministic offline tests. `Verified` is a named
commit with a retained, independently reviewed evidence package. Static gates
and the permitted test suite are recorded as results at named commits; they do
not certify a venue, a dataset or a right. No venue adapter is registered, so no
live venue verification claim exists.

## Dated records

- `docs/synthetic-asset-retirement-2026-11-23.md` (RRP-002, directive D11).
- `docs/product-scope-retirement-2026-11-23.md` (RRP-003).
- `docs/documentation-consolidation-2026-11-23.md` (RRP-005).
- `docs/synthetic-test-policy-2026-11-23.md` — historical W1.1/W1.2 policy,
  preserved unchanged.

Approved document bytes and historical counts are not edited by status
corrections. A substantive contract change needs a new approved digest.
