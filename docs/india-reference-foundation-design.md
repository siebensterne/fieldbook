# Fieldbook India reference-data foundation — design

- **Status:** Proposed design. This document settles semantics before
  implementation. It is not an accepted contract, a data licence, rights
  evidence, a release, a schema or authorisation to collect.
- **Task / branch / base:** W2-B..H · branch `docs/w2-reference-model` · base
  `9e60324`. Documentation only; no Rust, collector, adapter, schema or data
  change is part of this work.
- **Ownership:** consistent with the owner ratification of 2026-11-23.
  Fieldbook owns canonical identity, effective-dated reference assertions,
  corporate-action revisions, calendars, raw bytes and release publication.
  Nirnay consumes stable IDs and builds derived projections.
- **Method:** read-only inspection of the ratified ownership record, the India
  crosswalk, the C0 semantic model, Fieldbook source under `src/domain/` and
  existing specifications. No type or behaviour is inferred from a document
  where source was available.
- **Scope discipline:** no provider contact, collection, download, dataset
  acceptance, schema publication, shared crate, transport or storage choice.

## Sources consulted

| Source | Role | State |
|---|---|---|
| Owner ratification, 2026-11-23 | ownership and NDC semantics | Ratified |
| India domain ownership crosswalk, W1.2-D1 | findings F1-F12, phases I1-I6 | Proposed |
| C0 NDC v2 semantic model | six concepts, coverage, lineage, verification | semantics ratified |
| Fieldbook NDC v2 producer requirements | release sections and rejection codes | Proposed |
| `src/domain/identity.rs`, `src/domain/reference_data.rs` | identity and reference source | Implemented types |
| `src/domain/taxonomy.rs`, `src/domain/event_model.rs`, `src/domain/model.rs` | taxonomy, time roles, `NumericSpec` | Implemented types |
| `docs/specifications/*`, `docs/adr/0001-*.md` | in-repository contract | Accepted |

## 1. Canonical entity design

### 1.1 Hierarchy

The order below is a presentation order for identity assertions, not an
ownership tree. A listing references exactly one instrument, and one instrument
may be referenced by multiple listings across venues and time.

```text
VenueOperatorId
  └── VenueId
        └── MarketSegmentId (0..n; optional for a listing)
              └── ListingId (admission of one InstrumentId)
                    └── InstrumentId
                          ├── EntityId (issuer, via an issued_by edge)
                          ├── ExternalIdentifiers (0..n, effective dated)
                          └── ProductSpecification (effective dated)
```

### 1.2 Entity rules

| Entity | Identity type | Authority and stable input | Rule |
|---|---|---|---|
| Venue operator | `VenueOperatorId` | legal entity operating venues | distinct from a venue; corporate structure is separate reference |
| Venue | `VenueId` | facility, MIC with declared role | venue id is not provider id; listing, trading and reporting MIC roles stay distinct |
| Market segment | `MarketSegmentId` | segment MIC or venue segment id | optional; a segment that the venue does not publish is not invented |
| Listing | `ListingId` | admission of one instrument to one venue | listing is not instrument; effective dates and optional segment are part of the assertion |
| Instrument | `InstrumentId` | namespace, authority, immutable stable key | instrument is not symbol; opaque and platform-assigned |
| Issuer | `EntityId` | legal or natural entity, LEI evidence | issuer is not inferred from a name or an ISIN text |
| External identifiers | `InstrumentIdentifier`, `StandardIdentifier` | scheme, authority, value, scope | namespaced, scoped and effective-dated assertions, not keys |
| Product specification | `InstrumentSpecification` | instrument plus declared contract family | effective dated; not an identity input |

Hard rules:

1. An instrument is not a symbol. A ticker, native symbol, ISIN, CFI, MIC,
   FISN, output symbol or display title is an attribute or an external
   assertion, not the internal identity. `SerializationSymbol` is a wire
   projection, not an identity.
2. A listing is not an instrument. It is the admission of an instrument to a
   venue with an effective interval and optional segment. Same text on two
   venues yields two mappings and two listings, not one merged identity.
3. A venue id is not a provider id. `VenueId`, `DataProviderId`, `FeedId` and
   `FeedSessionId` are separate identities. A provider that redistributes venue
   data does not become the venue, and a feed symbol is not a venue symbol.
4. One instrument may have multiple listings and multiple effective-dated
   identifiers. Identifier reuse or change over time produces separate
   intervals; a single interval does not overwrite its predecessor.
5. Indices, derivatives and commodities have own identity rules (section 1.4).
6. `venue_mappings_from_markets()` is not an India identity authority
   (section 1.3).

Opaque derivation stays the mechanism for canonical IDs: `OpaqueId::derive`
hashes namespace, authority and stable key with a unit separator and takes the
first 12 bytes of a SHA-256 digest. For India the stable key must come from a
sourced, immutable assertion, not from mutable display text or a wire key.

### 1.3 Non-authority: adapter venue mappings

`venue_mappings_from_markets()` in `src/domain/identity.rs` derives instrument,
venue and listing IDs from `market.native_symbol`, and stamps both `valid_from`
and `observed_at` with `ADAPTER_ASSERTION_TIME = 0`. Its own documentation calls
the symbol a wire key and the time a deterministic adapter placeholder. It is
the default identity helper for non-India adapters and its tests use Kalshi,
Polymarket and Coinbase markets. Crosswalk finding F1 records the same result.

This helper must not be reused as India identity policy and must not be read as
evidence of a timestamped venue assertion. Zero is not source time, knowledge
time or receive time. For India, a venue identifier mapping must be a sourced,
venue- or feed-scoped, effective-dated assertion carrying provenance, a source
reference and a digest, with the effective interval resolved from the source.

### 1.4 Own identity rules for other product families

- **Indices.** An index family has an identity distinct from any instrument it
  tracks. Constituent membership is an effective-dated `constituent_of` edge
  (crosswalk phase I2). A continuous or tracked series derived from an index is
  a projection, not an identity merge.
- **Derivatives.** Each expiry is a distinct instrument; an option is distinct
  by underlying, expiry, strike, right and contract specification. `underlying_of`,
  `option_of` and `deliverable_of` edges carry the relationships. A product
  family is a grouping, not one instrument with a mutable expiry.
- **Commodities.** MCX enters first as a Fieldbook venue-operator and venue
  assertion. A commodity product identity, contract specification, unit and
  grade enter through a versioned release (crosswalk phase I4). Commodity
  assessment data uses its own typed payload and is not equity listing terms.
- Declared `InstrumentKind` variants do not grant support. A variant, an
  official specification and version, and parser evidence are separate claims
  (crosswalk findings F8 and F9).

## 2. Temporal semantics

Every identity assertion is a record about a named entity, asserted by a
source. When it applies in the market and when the platform learned it are
both explicit. Arrival order selects no revision.

| Field | Meaning | Source mapping |
|---|---|---|
| identity id | entity the assertion is about | `OpaqueId` prefixes `inst`, `venue`, `segment`, `listing`, `operator`, `ent`, `provider`, `feed` |
| external identifier | source text being asserted | `identifier_value` or `value` |
| namespace | scheme and assigning authority | `scheme`, `assigning_authority`, `standard`, `source` |
| venue / feed scope | where the identifier applies | venue, segment, provider, feed on the mapping |
| valid from / to | market applicability, half-open | `valid_from`, `valid_to`, `valid_from_us`, `valid_to_us` |
| knowledge time | when the platform learned the assertion | `observed_at`, `recorded_at` |
| source time | source event or publication instant | `exchange_event`, `exchange_publication` |
| receive time | network and application arrival | `network_receive`, `application_receive` |
| source reference | exact source record and archive | `source_provenance`, `raw_record_id`, `source_id` |
| revision | monotonic version of the assertion | new record with a revision field |
| digest | hash of exact source bytes and canonical assertion | release `digests`, per-record digest |
| supersession | predecessor link and invalidation | `supersedes`, `wasRevisionOf`, `invalidatedAtTime` |

Normative rules:

1. Validity is half-open `[from, to)`: the lower bound is inclusive and the
   upper bound is exclusive. `None` denotes an open upper bound. A source that
   supplies an inclusive end date is normalised by a declared rule recorded
   with the assertion; no silent coercion is permitted. Current helpers such
   as `InstrumentIdentifier::is_valid_at` and `StandardIdentifier::is_valid_at`
   compare with `<=`; the India design records explicit normalisation rather
   than inheriting that comparison for new assertions.
2. Date-domain normalisation uses a declared timezone and day boundary.
   India venue dates normalise in `Asia/Kolkata`; UTC is used only when the
   source declares UTC. The normalisation rule identifier, source domain and
   resulting instant are stored with the assertion. A host wall clock is not
   substituted for a source time. Microsecond values record storage
   granularity; precision is not an accuracy claim.
3. Source records are preserved and not rewritten. A correction appends a
   new revision with `supersedes` and its own knowledge time; the earlier
   revision stays addressable with the interval and knowledge time it had
   (ADR-0001 section 6, C0 section 8, NDC lineage section 5.6).
4. Resolution is bitemporal, on `(valid_on, known_at)`. Outcomes are
   `Resolved`, `Ambiguous`, `Unresolved` and `Conflict`; ambiguity is a first
   class outcome and candidates are retained. The bitemporal shape of
   `ProviderListingHistory` is a query shape, not an authority (crosswalk F3).
5. Timestamps carry role, clock source, resolution, accuracy, uncertainty and
   synchronisation. An accuracy claim without a declared synchronisation is
   rejected, and a receive timestamp is mandatory (`event_model.rs` validate).
6. Revision selection uses the release `as_of_ns` and knowledge time, not
   arrival order.

## 3. Corporate actions

Corporate actions are typed events in `DataCategory::CorporateActions`. The
existing `DomainPayload::CorporateAction { action_type, effective_us }` carries
an action type and an effective instant only; the fields below belong in a
versioned contract. No source, payload or schema change is made here.

| Kind | Distinguishing data |
|---|---|
| Dividend | amount per unit, currency, tax basis |
| Split | ratio of old to new units |
| Bonus | ratio of existing to additional units |
| Rights | ratio, subscription price, entitlement date |
| Buyback | ratio or price, tender window |
| Merger | successor entity or instrument, exchange ratio |
| Demerger | successor entities, allocation ratio |
| Consolidation | surviving entity or instrument, ratio |
| Symbol change | old and new venue identifiers with scopes |
| Delisting | venue, last trading session, effective date |
| Cancellation or correction | target action id, reason, revision |

Time roles stay separate:

| Time | Role |
|---|---|
| announcement | source announcement instant |
| ex-date | market date from which the entitlement is excluded |
| record date | market date defining the entitlement holder set |
| effective date | market date from which terms apply |
| payment date | market date of settlement |
| knowledge time | when the platform learned the action or its revision |
| publication time | source publication instant |
| receive time | network and application arrival |

Market dates are normalised under section 2. Publication, receive and knowledge
times are observed timestamps under the event envelope. No single time stands
in for another.

A revision chain uses `action_id`, `revision`, `supersedes` and
`invalidated_at`. A correction appends a new record; it does not overwrite the
prior record. A `known_as_of` query can express that an earlier revision was
invalidated. The slot rejection in `CorporateActionLedger::append`, which
refuses a second record for the same `(instrument, effective_date, kind)`, must
not be replicated (crosswalk F4). The embedded corporate-action array is a
snapshot and is not a point-in-time ledger (crosswalk F10).

Raw prices are immutable. Derived adjusted views are versioned and carry the
action ids applied, the transformation version, the declared ratios or amounts
with units, the rounding rule, the as-of basis and the release identity. There
is no universal adjustment formula: different research questions may select
different action sets, and adjustment is a derived consumer projection rather
than a rewrite of source observations. Corporate-action coverage is its own
dimension with a denominator per instrument and period (C0 section 6).

## 4. Trading calendars as sessions and events

A calendar is a set of scoped, effective-dated session and event assertions,
not a boolean per date.

```text
CalendarAssertion
  scope:       venue_id, segment_id?, product_id?
  timezone:    IANA name plus rule version
  sessions:    [ {kind, start, end} ]        # half-open intervals
  auctions:    [ {kind, start, end} ]
  breaks:      [ {start, end} ]
  closures:    [ {date, kind: holiday|exceptional, reason} ]
  overrides:   [ {date, kind: early_close|special_session, end?} ]
  effective:   [from, to)
  source:      reference + digest + revision
```

Normative rules:

1. Session, auction and break intervals are half-open `[start, end)` in the
   declared timezone. The current India rule declares no daylight-saving
   transition; a venue that declares one records it with the rule version.
2. Auctions and breaks are intervals with kinds, not day flags. An exceptional
   closure is distinct from a scheduled holiday and carries a reason. An early
   close or special session is an effective-dated override with its own source.
3. Every assertion carries an effective range, source reference, digest and
   revision. Corrections append new revisions; a sparse holiday file or a
   declared calendar reference such as `CountryDossier.market_calendar` does
   not supply session times by inference (crosswalk F7).
4. Calendar completeness is a separate coverage claim. The session and time
   dimension has its own denominator of declared venue calendar and session
   intervals (C0 section 6). A populated list of dates shows only that date
   entries exist; it proves no session coverage.

## 5. Contract and numeric specifications

`NumericSpec` in `src/domain/model.rs` is the numeric base. Its fields are
declared per product, not per venue or currency.

| `NumericSpec` field | Meaning |
|---|---|
| `price_scale`, `quantity_scale` | declared decimal scales |
| `price_unit`, `quantity_unit` | named units of price and quantity |
| `tick_schedule` | ordered, non-overlapping price bands |
| `quantity_step` | quantity increment |
| `lot_size` | lot size when the product declares lots |
| `contract_multiplier` | `Ratio` of numerator to denominator |

Validation requires scales within the declared maximum, ordered
non-overlapping bands, non-zero step and lot, a lot that is a multiple of the
step, and a non-zero multiplier numerator.

Derivative contract fields map onto this base:

| Derivative field | Representation |
|---|---|
| underlying | canonical `InstrumentId` plus `underlying_of` |
| expiry | `expiry_us` |
| strike | `strike_mantissa` with declared scale, or an exact decimal string |
| call / put | option kind plus `option_of` |
| lot | `lot_size` |
| quantity increment | `quantity_step` |
| tick | `tick_schedule` |
| multiplier | `contract_multiplier` |
| settlement | declared cash or physical mode |
| deliverable | `deliverable_of` edge to a canonical instrument |
| validity | `valid_from_us`, `valid_to_us` |

Commodity contract fields use the same base with commodity-specific
declarations:

| Commodity field | Representation |
|---|---|
| commodity | product identity or family in a versioned contract |
| grade | declared grade attribute |
| unit | `price_unit`, `quantity_unit` |
| contract quantity | `lot_size`, `quantity_step` |
| delivery location | declared location, `CommodityAssessment.location` |
| expiry | `expiry_us` |
| settlement | declared settlement mode |
| quality and delivery | declared attributes with units |
| price | `price_mantissa` with declared scale |

These fields do not belong in equity `ListingTerms`. Paise and lots are not
platform-wide units (crosswalk F6): each release states the original field
name, unit and domain. Exact financial decimals and arbitrary-precision
integers are JSON strings, not IEEE 754 numbers (C0 section 5.1). A derivative or commodity
family enters through a new versioned Fieldbook contract with an official
specification and version; enum variants alone do not grant support, and the
existing India cash contract is not widened in place (crosswalk F8, F9, F11).

## 6. Market-event capability taxonomy

| Capability | Taxonomy mapping | Minimum evidence |
|---|---|---|
| Trades | `Trades` | typed trade events with declared fields |
| BBO | `Level1Quotes`, `Level1` | best bid and offer with sizes |
| MBP | `Level2Book`, `Level2` or `Level3` | price levels with sizes |
| MBO | `OrderEvents`, `ParticipantEntitled` | per-order add, modify, cancel and execute events |
| Status | `MarketStatus` | declared market state transitions |
| Auction | `AuctionInformation` | auction phases and uncrossing events |
| Corporate action | `CorporateActions` | action events with revision lineage |

Rules:

1. ITCH is a protocol, not MBO. A protocol name or wire variant does not
   establish order-by-order capability. MBO requires order lifecycle events
   with order identity and a declared entitlement.
2. A native protocol is supported only with its official specification and
   version, a decoder version and golden fixture evidence. Connection success
   is not support (acquisition capability foundation, M3.0.4).
3. Five-level depth is not order-by-order. MBP with five levels is aggregated
   price levels; a level count does not imply MBO. `Level3` or
   `ParticipantEntitled` requires per-order events and a declared entitlement.
4. Capability is not permission (C0 section 1). A declared capability grants
   no retention, replay or collection right. This design claims no MBO
   capability and no high-frequency trading readiness.

## 7. NDC reference release

The release manifest and the event envelope are distinct. Dataset-wide facts
appear once in the manifest, not per event.

### 7.1 Manifest sections

| Section | Content |
|---|---|
| `release_identity` | immutable release id, contract and release versions, `as_of_ns`, publication state |
| `source_scope` | named provider, source product, venue, segment and dataset; an absent venue is a denial |
| `producer_activity` | only performed operations, each with its object class and operation evidence |
| `rights` | permission grants, document references and reviewed attestations |
| `coverage` | one named universe, denominator, count basis, as-of instant and verdict per dimension |
| `lineage` | raw archive reference, digests, transformation record and PROV relations |
| `schema_versions` | contract, normalizer, payload schema and envelope versions |
| `digests` | JCS manifest digest, deterministic data digest, algorithm and artifact digests |
| `publication_identity` | publisher identity, signing key id, detached signature reference and archive reference |

`producer_activity` has exactly two members: `performed_operations` and
`operation_evidence`. It contains no permission, grant, purpose, licensee,
recipient, coverage verdict or signature. An operation that did not occur is
not listed. Permission grants live in `rights`.

Consumer uses are declared by Nirnay and evaluated against grants. They are
not mapped into the producer operation enum (owner ratification, Decision B).
The purpose is `proprietary_own_account_trading_research`, preserved verbatim.

### 7.2 Independent rights evidence

| Proof | Establishes | Does not establish |
|---|---|---|
| Publisher integrity | publisher key control and unchanged signed manifest bytes | source authenticity, coverage, rights |
| Source lineage | raw archive reference, digests and transformation record | truth of observations |
| Rights attestation | reviewed written agreement, exact scope and document digest | permission for an unlisted action |

Rights evidence is independent of the release signature and of any admission
receipt. A signature is not a licence.

### 7.3 Per-dimension coverage

| Dimension | Denominator |
|---|---|
| Instrument | declared point-in-time instrument universe |
| Listing and identity | declared listing and identifier assertions |
| Contract | declared derivative or commodity contract set |
| Corporate action | declared action universe per instrument and period |
| Session and time | declared venue calendar and session intervals |
| Trade event | declared trades in scope |
| Quote and depth | declared BBO or MBP levels and snapshots |
| MBO | declared order lifecycle events |
| Sequence continuity | declared sequence ranges and gap policy |

A passing verdict in one dimension implies nothing about another. A gap is
measured against the denominator of its own dimension at its own as-of instant.

### 7.4 Immutability and signature

A release is immutable. A correction receives a new release identity and a new
revision; the prior revision and its knowledge time stay in lineage. Manifest
signing uses RFC 8785 JSON Canonicalization Scheme over the manifest object,
with a detached Ed25519 signature sidecar outside the canonical bytes. The
signature covers a domain-separated digest of those bytes. The `I-JSON` subset
applies, financial decimals and arbitrary-precision integers are strings,
arrays have a declared deterministic order, and NaN, Infinity or lone surrogates
terminate the operation. Key validity and revocation belong to the trusted
registry. The
signature proves publisher-key control and manifest integrity, not source
authenticity, completeness or data rights.

### 7.5 Consumer rejection rules

Verification is ordered: parse and validate the contract version, verify
canonical bytes, verify the detached signature and key, verify data digests,
verify rights evidence, verify coverage and denominators, verify producer
activity, verify event envelopes, verify temporal and correction lineage,
evaluate the requested consumer use, then issue an immutable admission receipt
or a typed rejection. Validation stops at the first refusal, a release is
admitted or rejected as a whole, and no partial publication or synthetic
fallback is admitted. Representative codes include `REJECT_INCOMPLETE`,
`REJECT_AMBIGUOUS_RELEASE`, `REJECT_CONCEPT_CONFLATION`,
`REJECT_PRODUCER_ACTIVITY`, `REJECT_RIGHTS_EVIDENCE`,
`REJECT_COVERAGE_DENOMINATOR`, `REJECT_DIGEST` and `REJECT_SIGNATURE`.
Nirnay's research-dataset manifest is a separate object referencing the exact
Fieldbook release identity and digest. Transport, storage and shared-crate
choices are deferred; none is selected by this design.

## 8. Explicit non-claims

- No provider is contacted, no collection or download is run, and no market
  data is created by this design.
- No real-data validation, live receipt or coverage measurement is claimed.
  Source, API success, a token and a checksum each establish nothing about
  rights or truth.
- No MBO capability, order-by-order depth, high-frequency trading readiness or
  latency target is claimed.
- No alpha, profitability, backtest result or strategy return is claimed.
- All source rights remain `UNKNOWN`. Budget is INR 0. Dataset acceptance is
  `BLOCKED`. Experiment registration and live execution stay disabled.
- Synthetic market-shaped tests are disabled under the retained strict test
  data policy. No synthetic observation, price bar, order book, universe,
  reference history or adjusted series is created here.
- No final NDC JSON schema, transport, storage engine, shared crate, release or
  data object is created. No contract is accepted, no right is changed and no
  implementation is authorised.
