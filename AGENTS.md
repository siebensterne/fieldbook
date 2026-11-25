# Agent instructions

Fieldbook owns source qualification, rights enforcement, acquisition,
raw-data lifecycle, normalization, reference data, replay, quality and
immutable NDC publication. Nirnay consumes releases; Workspace owns policy.

- Use `README.md` to locate owning documents. Read only the relevant contract,
  ADR, source and tests.
- Read `ORIGIN.md` before copying or promoting material. Read
  `docs/git-workflow.md` and `git-policy.json` before Git operations.
- Check workspace `CURRENT-STATE.json` before provider, data, rights,
  experiment, publication or execution actions. A URL, token or successful
  connection grants no permission.
- Keep domain meaning independent of provider protocols. Adapters translate;
  application code owns use cases; infrastructure owns I/O and transport.
- Preserve source identity, raw provenance, event ordering, sequence scope,
  clock semantics, bitemporal history, corrections and deterministic replay.
- Account for every input and disposition. Follow D11: no retired generators
  or synthetic market-shaped fixtures; abstract protocol tests only under the
  test policy.
- Bound records, buffers, queues, parsers, decompressors, spools, retries and
  workers. Immutable profiles come from trusted local policy; callers cannot
  raise local limits.
- Keep publication, durability, rights and admission separate. A successful
  publication grants no data rights and admits no dataset.
- Inspect base commit and call sites. Reproduce defects, implement fixes and
  add positive, negative, boundary and recovery tests.
- Run targeted tests and `make check`. Report static checks separately from
  tests and deployment qualification.
- Add no speculative ports, crates, services or transports without measured
  need, owner, stable contract and decision.
- Preserve dated evidence and approved bytes. Proceed within current
  authority; report commits, gates, CI and unresolved work.
