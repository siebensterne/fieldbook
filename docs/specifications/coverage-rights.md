# Specification 06 — Global Coverage and Rights

## Purpose

This specification defines the country, venue, source and rights model for a
global financial information platform. It makes coverage and limitations
visible to consumers. A free endpoint is not a redistribution licence, and a
single instrument price is not proof of country coverage.

The Rust implementation is `src/governance/coverage_certification.rs` and
`src/governance/rights.rs`. The 2026-11-23 enforcement fix is recorded in
[`docs/rights-enforcement-2026-11-23.md`](../rights-enforcement-2026-11-23.md).

## Coverage matrix

Every source is described along these dimensions:

```text
country x venue x asset class x instrument x data category
        x depth x frequency x history x source x rights
```

Country coverage is evaluated per asset class and information category. A
country marked as covered for equities is not thereby covered for fixed
income, derivatives, macro releases or corporate filings. Each country
dossier records official exchange registries, venues, regulators, economic
sources, market calendars and data-residency restrictions.

## Coverage status ladder

| Status | Meaning |
|---|---|
| Discovered | Source identified |
| Connector implemented | Integration exists |
| Technically validated | Protocol and parsing tested |
| Licensed | Rights verified for the intended use |
| Live | Production ingestion active |
| Historically populated | Historical records available |
| Reconciled | Independent data checks completed |
| Certified | All applicable requirements passed |

Statuses are ordered. A record cannot reach `certified` without technical
validation, an explicit license, quality reconciliation, a non-empty evidence
set, recorded history bounds and no known gaps.

## Rights model

A licensing record binds a licensee, provider, source product, venue, segment,
instrument/field/modality/time-window scope, territory, delivery method,
purpose, recipient, retention rule, typed lifecycle operation, validity bound
and reference. Rights include real-time access, historical storage, internal
processing, derived data and redistribution. Display mode is a separate
concept from the right. Decisions are `permitted`, `prohibited`,
`contract_required`, `unknown` or `revoked`.

The registry is fail-closed. A missing record, a missing right, a conditional
right, an expired record or a mismatched identity denies the operation. No
venue name or API availability implies permission. A writable audit directory
is mandatory, and a permitted decision is committed before any provider
egress.

## Source acquisition categories

1. Direct exchange and market-infrastructure integrations.
2. Licensed data vendors.
3. Official government, central-bank and institutional sources.
4. Specialized information providers.

Each source has a contractual and technical onboarding record. Coverage
claims are measured per source and dataset, not as one aggregate platform
percentage.

## Evidence requirements

Certification consumes a coverage record, a licensing registry and a quality
report. The operation returns a promoted record or a named failure. Historic
evidence revisions remain append-only. Consumers can inspect available data
categories, depth, history range, real-time or delayed status, venues,
providers, last successful collection, known gaps, quality status, correction
history and applicable restrictions.

## Non-claims

This specification does not claim access to private, bilateral, unpublished,
restricted or commercially unavailable information. It does not claim 90-country
coverage today, and it does not authorize new live collection. Polymarket
access remains subject to the existing rights review; the retained captures
are controlled offline fixtures with legacy provenance.

## Sources

- Open Symbology data, MIT license: https://www.openfigi.com/
- GLEIF Global LEI Index:
  https://www.gleif.org/en/lei-data/global-lei-index
- GLEIF LEI mapping files:
  https://www.gleif.org/en/lei-data/lei-mapping
- ISO 4217 currency codes: https://www.iso.org/standard/64758.html
- ISO 10383 MIC: https://www.iso.org/standard/61067.html
- LSEG market-data licensing:
  https://marketdata.londonstockexchange.com/
