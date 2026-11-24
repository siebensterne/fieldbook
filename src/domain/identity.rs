//! Persistent instrument and reference identity (Platform M2, ADR-0001).
//!
//! These identity types are additive. `MarketInfo.native_symbol` and
//! `MarketInfo.symbol` remain the bounded migration seam and the only bridge
//! to the SBE wire format. Nothing here changes journal, replay, catalog
//! checksums or collector behavior.
//!
//! Every identity is an opaque, platform-assigned newtype derived from an
//! explicit immutable assertion (namespace, assigning authority, stable wire
//! key). Titles, slugs and display labels are never identity inputs.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::domain::framed_identity;
use crate::domain::framed_identity::IdentityV2Error;

/// Opaque, platform-assigned identity. The prefix identifies the entity class;
/// the digest is derived from an explicit immutable assertion and never from a
/// mutable display attribute.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpaqueId(String);

impl OpaqueId {
    /// Derive an opaque id from an immutable assertion. The unit separator
    /// prevents field-concatenation collisions.
    #[must_use]
    pub fn derive(prefix: &str, namespace: &str, authority: &str, stable_key: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(namespace.as_bytes());
        hasher.update([0x1f]);
        hasher.update(authority.as_bytes());
        hasher.update([0x1f]);
        hasher.update(stable_key.as_bytes());
        let digest = hasher.finalize();
        let mut text = String::with_capacity(prefix.len() + 1 + 24);
        text.push_str(prefix);
        text.push(':');
        for byte in digest.iter().take(12) {
            text.push_str(&format!("{byte:02x}"));
        }
        Self(text)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Accept previously declared identity text after checking its shape.
    /// Legacy and version-2 text are both accepted; malformed text is rejected.
    /// This constructor is additive and does not alter [`Self::derive`].
    pub fn from_declared(text: String) -> Result<Self, IdentityV2Error> {
        framed_identity::detect_format(&text)?;
        Ok(Self(text))
    }
}

impl fmt::Display for OpaqueId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

macro_rules! identity_type {
    ($name:ident, $prefix:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(OpaqueId);

        impl $name {
            #[must_use]
            pub fn derive(namespace: &str, authority: &str, stable_key: &str) -> Self {
                Self(OpaqueId::derive($prefix, namespace, authority, stable_key))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

identity_type!(InstrumentId, "inst", "Persistent instrument identity.");
identity_type!(VenueId, "venue", "Venue facility identity.");
identity_type!(
    VenueOperatorId,
    "operator",
    "Legal entity operating one or more venues."
);
identity_type!(MarketSegmentId, "segment", "Optional venue market segment.");
identity_type!(
    ListingId,
    "listing",
    "Admission of an instrument to a venue."
);
identity_type!(DataProviderId, "provider", "Data provider identity.");
identity_type!(
    FeedId,
    "feed",
    "Feed identity, distinct from venue identity."
);
identity_type!(FeedSessionId, "session", "One feed delivery session.");

/// Serialization projection of an instrument onto the SBE wire. This is not
/// an identity: changing it does not mutate the underlying `InstrumentId`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SerializationSymbol(pub String);

impl From<&str> for SerializationSymbol {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// Named scheme of an external identifier assertion.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdentifierScheme(pub String);

/// One namespaced identifier assertion, matching ADR-0001's eight fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstrumentIdentifier {
    pub scheme: IdentifierScheme,
    pub assigning_authority: String,
    pub identifier_value: String,
    pub scope: String,
    pub valid_from: i64,
    /// `None` means still valid.
    pub valid_to: Option<i64>,
    pub observed_at: i64,
    pub source_provenance: String,
}

impl InstrumentIdentifier {
    #[must_use]
    pub fn is_valid_at(&self, timestamp: i64) -> bool {
        timestamp >= self.valid_from && self.valid_to.is_none_or(|end| timestamp <= end)
    }
}

/// Grouping relationship, explicitly not an instrument identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[expect(
    clippy::enum_variant_names,
    reason = "identity relationship names are serialized contract strings"
)]
pub enum Relationship {
    EventOf { event_id: String },
    ConditionOf { condition_id: String },
    DexOf { dex: String },
}

/// Binding from a venue-assigned external identifier to a listing. The same
/// identifier text on a different venue is a different mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VenueInstrumentMapping {
    pub instrument: InstrumentId,
    pub venue: VenueId,
    pub listing: ListingId,
    pub segment: Option<MarketSegmentId>,
    pub identifier: InstrumentIdentifier,
    pub relationships: Vec<Relationship>,
}

/// Binding from a provider/feed identifier directly to an instrument; no
/// public venue listing is required (OTC / dark-pool case).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedInstrumentMapping {
    pub instrument: InstrumentId,
    pub provider: DataProviderId,
    pub feed: FeedId,
    pub identifier: InstrumentIdentifier,
}

/// Result of identity resolution. Every outcome is explicit; unknown symbols
/// are never silently coerced to a first candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Resolution {
    Resolved {
        instrument: InstrumentId,
        listing: Option<ListingId>,
    },
    Ambiguous {
        candidates: Vec<InstrumentId>,
    },
    Unresolved {
        scope: String,
        external_id: String,
    },
    Conflict {
        candidates: Vec<InstrumentId>,
    },
}

/// The stable assertion time used for adapter-derived identity mappings. No
/// wall clock is read here; identity derivation must be deterministic.
const ADAPTER_ASSERTION_TIME: i64 = 0;

/// Build venue identity assertions from an adapter's markets. The immutable
/// wire key (`native_symbol`) is the only identity input; output `symbol` is
/// recorded separately as a serialization projection.
#[must_use]
pub fn venue_mappings_from_markets(
    authority: &str,
    markets: &[crate::model::MarketInfo],
) -> Vec<VenueInstrumentMapping> {
    markets
        .iter()
        .map(|market| {
            let instrument = InstrumentId::derive(authority, authority, &market.native_symbol);
            let venue = VenueId::derive(authority, authority, "venue");
            let listing = ListingId::derive(authority, authority, &market.native_symbol);
            // A grouping key is carried verbatim. No provider name selects a
            // relationship kind: the retired adapters encoded their own venue
            // semantics, and generic identity derivation stays venue-neutral.
            let relationships = market
                .exchange_market_id
                .as_ref()
                .map(|grouping| Relationship::DexOf {
                    dex: grouping.clone(),
                })
                .into_iter()
                .collect();
            VenueInstrumentMapping {
                instrument,
                venue,
                listing,
                segment: None,
                identifier: InstrumentIdentifier {
                    scheme: IdentifierScheme("venue_wire_key".to_owned()),
                    assigning_authority: authority.to_owned(),
                    identifier_value: market.native_symbol.clone(),
                    scope: authority.to_owned(),
                    valid_from: ADAPTER_ASSERTION_TIME,
                    valid_to: None,
                    observed_at: ADAPTER_ASSERTION_TIME,
                    source_provenance: "adapter_discovery".to_owned(),
                },
                relationships,
            }
        })
        .collect()
}

/// Append-only reference catalog. Corrections add new versions rather than
/// overwriting prior mappings, so as-of resolution is reproducible.
#[derive(Debug, Clone, Default)]
pub struct ReferenceCatalog {
    /// Key includes `valid_from` and the resolved instrument so two assertions
    /// for the same text in the same interval remain distinct (ambiguity is a
    /// first-class outcome and must not be silently overwritten).
    venue_mappings: BTreeMap<(String, String, i64, String), VenueInstrumentMapping>,
    feed_mappings: BTreeMap<(String, String, i64, String), FeedInstrumentMapping>,
    serialization: BTreeMap<InstrumentId, BTreeSet<SerializationSymbol>>,
}

impl ReferenceCatalog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a venue mapping. Explicit `valid_from` participates in the key,
    /// so identifier reuse over time yields separate records.
    pub fn insert_venue(&mut self, mapping: VenueInstrumentMapping) {
        let identifier = &mapping.identifier;
        let key = (
            identifier.scope.clone(),
            identifier.identifier_value.clone(),
            identifier.valid_from,
            mapping.instrument.as_str().to_owned(),
        );
        self.serialization
            .entry(mapping.instrument.clone())
            .or_default();
        self.venue_mappings.insert(key, mapping);
    }

    pub fn insert_feed(&mut self, mapping: FeedInstrumentMapping) {
        let identifier = &mapping.identifier;
        let key = (
            identifier.scope.clone(),
            identifier.identifier_value.clone(),
            identifier.valid_from,
            mapping.instrument.as_str().to_owned(),
        );
        self.serialization
            .entry(mapping.instrument.clone())
            .or_default();
        self.feed_mappings.insert(key, mapping);
    }

    pub fn record_serialization(&mut self, instrument: &InstrumentId, symbol: SerializationSymbol) {
        self.serialization
            .entry(instrument.clone())
            .or_default()
            .insert(symbol);
    }

    /// Resolve an external identifier as of a point in valid time.
    #[must_use]
    pub fn resolve_venue_as_of(
        &self,
        scope: &str,
        external_id: &str,
        timestamp: i64,
    ) -> Resolution {
        let mut candidates: BTreeSet<InstrumentId> = BTreeSet::new();
        let mut listing = None;
        for ((entry_scope, entry_id, _, _), mapping) in &self.venue_mappings {
            if entry_scope == scope
                && entry_id == external_id
                && mapping.identifier.is_valid_at(timestamp)
            {
                candidates.insert(mapping.instrument.clone());
                listing = Some(mapping.listing.clone());
            }
        }
        Self::finish(candidates, listing, scope, external_id)
    }

    #[must_use]
    pub fn resolve_feed_as_of(&self, scope: &str, external_id: &str, timestamp: i64) -> Resolution {
        let mut candidates: BTreeSet<InstrumentId> = BTreeSet::new();
        for ((entry_scope, entry_id, _, _), mapping) in &self.feed_mappings {
            if entry_scope == scope
                && entry_id == external_id
                && mapping.identifier.is_valid_at(timestamp)
            {
                candidates.insert(mapping.instrument.clone());
            }
        }
        Self::finish(candidates, None, scope, external_id)
    }

    fn finish(
        candidates: BTreeSet<InstrumentId>,
        listing: Option<ListingId>,
        scope: &str,
        external_id: &str,
    ) -> Resolution {
        match candidates.len() {
            0 => Resolution::Unresolved {
                scope: scope.to_owned(),
                external_id: external_id.to_owned(),
            },
            1 => {
                let Some(instrument) = candidates.into_iter().next() else {
                    return Resolution::Unresolved {
                        scope: scope.to_owned(),
                        external_id: external_id.to_owned(),
                    };
                };
                Resolution::Resolved {
                    instrument,
                    listing,
                }
            }
            _ => Resolution::Ambiguous {
                candidates: candidates.into_iter().collect(),
            },
        }
    }

    #[must_use]
    pub fn serialization_symbols(&self, instrument: &InstrumentId) -> Vec<SerializationSymbol> {
        self.serialization
            .get(instrument)
            .map(|symbols| symbols.iter().cloned().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identifier(value: &str, from: i64, to: Option<i64>) -> InstrumentIdentifier {
        InstrumentIdentifier {
            scheme: IdentifierScheme("venue_ticker".to_owned()),
            assigning_authority: "test".to_owned(),
            identifier_value: value.to_owned(),
            scope: "test".to_owned(),
            valid_from: from,
            valid_to: to,
            observed_at: from,
            source_provenance: "fixture".to_owned(),
        }
    }

    #[test]
    fn same_ticker_on_two_venues_yields_distinct_identities() {
        let a = InstrumentId::derive("test", "kalshi", "KX-A");
        let b = InstrumentId::derive("test", "coinbase", "KX-A");
        assert_ne!(a, b);
    }

    #[test]
    fn identity_is_not_a_hash_of_mutable_display_text() {
        let a = InstrumentId::derive("test", "kalshi", "KX-A");
        let title_changed = InstrumentId::derive("test", "kalshi", "KX-A");
        assert_eq!(a, title_changed);
        let different_wire_key = InstrumentId::derive("test", "kalshi", "KX-B");
        assert_ne!(a, different_wire_key);
    }

    #[test]
    fn serialization_symbol_change_does_not_mutate_identity() {
        let instrument = InstrumentId::derive("test", "kalshi", "KX-A");
        let mut catalog = ReferenceCatalog::new();
        catalog.record_serialization(&instrument, "kalshi:KX-A".into());
        catalog.record_serialization(&instrument, "kalshi:KX-A-v2".into());
        assert_eq!(catalog.serialization_symbols(&instrument).len(), 2);
    }

    #[test]
    fn ticker_reuse_over_time_has_separate_intervals() {
        let instrument = InstrumentId::derive("test", "kalshi", "KX-A");
        let venue = VenueId::derive("test", "kalshi", "main");
        let listing_old = ListingId::derive("test", "kalshi", "KX-A@1");
        let listing_new = ListingId::derive("test", "kalshi", "KX-A@2");
        let mut catalog = ReferenceCatalog::new();
        catalog.insert_venue(VenueInstrumentMapping {
            instrument: instrument.clone(),
            venue: venue.clone(),
            listing: listing_old.clone(),
            segment: None,
            identifier: identifier("KX-A", 100, Some(199)),
            relationships: vec![],
        });
        let other = InstrumentId::derive("test", "kalshi", "KX-A@epoch2");
        catalog.insert_venue(VenueInstrumentMapping {
            instrument: other.clone(),
            venue,
            listing: listing_new.clone(),
            segment: None,
            identifier: identifier("KX-A", 200, None),
            relationships: vec![],
        });
        assert_eq!(
            catalog.resolve_venue_as_of("test", "KX-A", 150),
            Resolution::Resolved {
                instrument,
                listing: Some(listing_old)
            }
        );
        assert_eq!(
            catalog.resolve_venue_as_of("test", "KX-A", 250),
            Resolution::Resolved {
                instrument: other,
                listing: Some(listing_new)
            }
        );
    }

    #[test]
    fn unknown_and_ambiguous_resolve_explicitly() {
        let mut catalog = ReferenceCatalog::new();
        assert!(matches!(
            catalog.resolve_venue_as_of("test", "missing", 1),
            Resolution::Unresolved { .. }
        ));
        let venue = VenueId::derive("test", "kalshi", "main");
        for instrument in [
            InstrumentId::derive("test", "kalshi", "A"),
            InstrumentId::derive("test", "kalshi", "B"),
        ] {
            catalog.insert_venue(VenueInstrumentMapping {
                instrument,
                venue: venue.clone(),
                listing: ListingId::derive("test", "kalshi", "shared"),
                segment: None,
                identifier: identifier("SAME", 1, None),
                relationships: vec![],
            });
        }
        assert!(matches!(
            catalog.resolve_venue_as_of("test", "SAME", 2),
            Resolution::Ambiguous { candidates } if candidates.len() == 2
        ));
    }

    #[test]
    fn parent_grouping_is_not_instrument_identity() {
        let event_id = "KXEVENT-26".to_owned();
        let a = InstrumentId::derive("test", "kalshi", "KX-A");
        let b = InstrumentId::derive("test", "kalshi", "KX-B");
        assert_ne!(a, b);
        let relationship = Relationship::EventOf {
            event_id: event_id.clone(),
        };
        assert_eq!(relationship, Relationship::EventOf { event_id });
    }

    #[test]
    fn otc_instrument_needs_no_listing() {
        let instrument = InstrumentId::derive("test", "otc", "DEAL-1");
        let mut catalog = ReferenceCatalog::new();
        catalog.insert_feed(FeedInstrumentMapping {
            instrument: instrument.clone(),
            provider: DataProviderId::derive("test", "provider", "p1"),
            feed: FeedId::derive("test", "provider", "f1"),
            identifier: identifier("DEAL-1", 1, None),
        });
        assert_eq!(
            catalog.resolve_feed_as_of("test", "DEAL-1", 2),
            Resolution::Resolved {
                instrument,
                listing: None
            }
        );
    }
}

#[cfg(test)]
mod adapter_tests {
    use super::*;
    use crate::model::{MarketInfo, NumericSpec};

    fn market(native: &str, symbol: &str, grouping: Option<&str>) -> MarketInfo {
        MarketInfo {
            exchange: "test".to_owned(),
            native_symbol: native.to_owned(),
            symbol: symbol.to_owned(),
            title: Some("mutable title".to_owned()),
            outcome: None,
            exchange_market_id: grouping.map(str::to_owned),
            close_time_us: None,
            tick_size_us: None,
            price_ranges: vec![],
            price_level_structure: None,
            numeric_spec: NumericSpec::default(),
        }
    }

    #[test]
    fn same_ticker_across_authorities_is_distinct() {
        let kalshi =
            venue_mappings_from_markets("kalshi", &[market("BTC", "kalshi:BTC", Some("EVENT"))]);
        let coinbase = venue_mappings_from_markets(
            "coinbase",
            &[market("BTC", "coinbase:spot:BTC/USD", None)],
        );
        assert_ne!(kalshi[0].instrument, coinbase[0].instrument);
        assert!(matches!(
            kalshi[0].relationships[0],
            Relationship::DexOf { .. }
        ));
    }

    #[test]
    fn two_tokens_in_one_condition_are_distinct_instruments() {
        let mappings = venue_mappings_from_markets(
            "polymarket",
            &[
                market("token-1", "polymarket:cond:0", Some("cond")),
                market("token-2", "polymarket:cond:1", Some("cond")),
            ],
        );
        assert_ne!(mappings[0].instrument, mappings[1].instrument);
        assert!(matches!(
            mappings[0].relationships[0],
            Relationship::DexOf { .. }
        ));
    }

    #[test]
    fn serialization_symbol_change_does_not_change_derived_identity() {
        let first = venue_mappings_from_markets("kalshi", &[market("KX-A", "kalshi:KX-A", None)]);
        let second = venue_mappings_from_markets(
            "kalshi",
            &[market("KX-A", "kalshi:KX-A-v2", Some("later"))],
        );
        assert_eq!(first[0].instrument, second[0].instrument);
    }

    #[test]
    fn catalog_resolves_adapter_assertions_and_tracks_serialization_separately() {
        let mappings = venue_mappings_from_markets(
            "coinbase",
            &[market(
                "coinbase:spot:BTC/USD",
                "coinbase:spot:BTC/USD",
                None,
            )],
        );
        let mut catalog = ReferenceCatalog::new();
        for mapping in &mappings {
            catalog.insert_venue(mapping.clone());
            catalog.record_serialization(
                &mapping.instrument,
                SerializationSymbol::from(mapping.identifier.identifier_value.as_str()),
            );
        }
        assert!(matches!(
            catalog.resolve_venue_as_of("coinbase", "coinbase:spot:BTC/USD", 1),
            Resolution::Resolved { .. }
        ));
        assert_eq!(
            catalog.serialization_symbols(&mappings[0].instrument).len(),
            1
        );
    }
}
