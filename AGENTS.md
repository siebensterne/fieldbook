# Agent instructions

Fieldbook owns source qualification, rights enforcement, acquisition, raw-data lifecycle,
normalization, reference data, replay, quality and immutable NDC publication. Nirnay consumes
releases; Workspace owns cross-repository policy.

- Use `README.md` to locate the owning document. Read only the relevant contract, ADR, source and
  tests.
- Read `ORIGIN.md` before copying or promoting material. Read `docs/git-workflow.md` and
  `git-policy.json` before Git operations.
- Check Workspace `CURRENT-STATE.json` before any action involving provider access, data, rights,
  experiments, publication or execution. Do not infer permission from public availability, tokens
  or successful connections.
- Keep domain meaning independent of provider protocols. Adapters translate protocols; application
  code owns use cases; infrastructure owns I/O, storage, scheduling and transport.
- Preserve source identity, raw provenance, event ordering, sequence scope, clock semantics,
  bitemporal history, corrections and deterministic replay.
- Account for every input and disposition. Do not silently drop, reorder, invent or relabel records.
  Follow D11: do not restore retired generators or add synthetic market-shaped fixtures; use
  abstract protocol and pure mathematical tests only under the test policy.
- Bound every record, buffer, queue, parser, decompressor, spool, retry and worker. Resource
  profiles are selected by trusted local policy; caller or producer declarations cannot raise
  local limits.
- Keep publication, durability, rights and admission as separate states. A successful publication
  does not grant data rights or admit a dataset.
- Inspect the base commit and all affected call sites. Reproduce the defect, implement the fix and
  add positive, negative, boundary and recovery tests.
- Run targeted tests and the required `make check` gates. Report static checks separately from tests
  and deployment qualification.
- Do not add speculative ports, crates, services or transports. Require a measured need, owner,
  stable contract, acceptance tests and decision.
- Preserve dated evidence and approved bytes. Update current documentation with the code; never
  rewrite historical results as current.
- Proceed autonomously within the task and current authority. Report exact commits, commands, exits,
  CI, evidence and unresolved work.
