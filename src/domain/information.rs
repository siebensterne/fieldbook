// SPDX-License-Identifier: Apache-2.0
//! Domain-specific structures for institutional financial information.
//!
//! A release is not a trade and a filing is not an instrument. These payloads
//! carry domain meaning in their own structures behind the shared
//! [`UniversalEnvelope`](crate::event_model::UniversalEnvelope). They are
//! versioned independently of market-data payloads, and every record keeps
//! both valid time and transaction time so corrections and revisions remain
//! queryable.

use serde::Deserialize;
use serde::Serialize;

use crate::taxonomy::Frequency;

/// Schema version of the institutional information payload family.
pub const INFORMATION_SCHEMA_VERSION: u32 = 1;

/// Bitemporal interval for one stored fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bitemporal {
    /// Start of the interval in which the fact was true in the source world.
    pub valid_from_us: i64,
    /// End of the valid-time interval, open when absent.
    pub valid_to_us: Option<i64>,
    /// When Fieldbook first learned and stored the fact.
    pub transaction_from_us: i64,
    /// When this version stopped being the currently known version.
    pub transaction_to_us: Option<i64>,
}

impl Bitemporal {
    /// Start a bitemporal interval with both end times open.
    #[must_use]
    pub const fn new(valid_from_us: i64, transaction_from_us: i64) -> Self {
        Self {
            valid_from_us,
            valid_to_us: None,
            transaction_from_us,
            transaction_to_us: None,
        }
    }

    /// Whether the fact was true in the source world at `at_us`.
    #[must_use]
    pub fn valid_at(&self, at_us: i64) -> bool {
        self.valid_from_us <= at_us && self.valid_to_us.is_none_or(|end| at_us <= end)
    }

    /// Whether this version was the currently known version at `at_us`.
    #[must_use]
    pub fn known_at(&self, at_us: i64) -> bool {
        self.transaction_from_us <= at_us && self.transaction_to_us.is_none_or(|end| at_us <= end)
    }

    /// Answer a historical query in both time dimensions.
    #[must_use]
    pub fn as_of(&self, valid_us: i64, transaction_us: i64) -> bool {
        self.valid_at(valid_us) && self.known_at(transaction_us)
    }
}

/// Seasonal adjustment declared by a statistical source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeasonalAdjustment {
    None,
    Adjusted,
    NotApplicable,
}

impl SeasonalAdjustment {
    /// Return the stable contract string for this adjustment.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Adjusted => "adjusted",
            Self::NotApplicable => "not_applicable",
        }
    }
}

/// Source-declared status of an observation relative to later correction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceObservationStatus {
    Unknown,
    Preliminary,
    Revised,
    Final,
}

impl SourceObservationStatus {
    /// Return the stable contract string for this status.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Preliminary => "preliminary",
            Self::Revised => "revised",
            Self::Final => "final",
        }
    }
}

/// One official economic series observation with full vintage metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicObservationDetail {
    /// Stable internal series identity.
    pub series_id: String,
    /// Start of the period the observation describes.
    pub observation_period_start_us: i64,
    /// End of the period the observation describes.
    pub observation_period_end_us: i64,
    /// When the source published this observation.
    pub publication_us: i64,
    /// Release vintage assigned by the source.
    pub release_vintage: u32,
    /// Exact value coefficient.
    pub value_mantissa: i64,
    /// Decimal scale of `value_mantissa`.
    pub value_scale: u8,
    /// Unit declared by the source.
    pub unit: String,
    /// Frequency of the series.
    pub frequency: Frequency,
    /// Seasonal adjustment applied by the source.
    pub seasonal_adjustment: SeasonalAdjustment,
    /// Source status of the value.
    pub source_status: SourceObservationStatus,
    /// Identifiers of prior releases superseded by this one.
    pub revision_lineage: Vec<String>,
    /// Valid-time and transaction-time interval.
    pub bitemporal: Bitemporal,
}

/// Optional Greek associations supplied for an option or derivative quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Greeks {
    /// Delta coefficient.
    pub delta_mantissa: i64,
    /// Gamma coefficient.
    pub gamma_mantissa: i64,
    /// Theta coefficient.
    pub theta_mantissa: i64,
    /// Vega coefficient.
    pub vega_mantissa: i64,
    /// Decimal scale for all Greeks above.
    pub scale: u8,
}

/// An evaluated bond price from a contributor, not an order-book event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondEvaluatedPriceDetail {
    /// Internal instrument identity.
    pub instrument_id: String,
    /// Contributor or source identity.
    pub contributor: String,
    /// Evaluation time declared by the source.
    pub valuation_us: i64,
    /// Evaluated clean price coefficient.
    pub price_mantissa: i64,
    /// Decimal scale of `price_mantissa`.
    pub price_scale: u8,
    /// Yield in basis points, when supplied.
    pub yield_basis_points: Option<i64>,
    /// Valid-time and transaction-time interval.
    pub bitemporal: Bitemporal,
}

/// A derivative quote with optional risk sensitivities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivativeQuoteDetail {
    /// Internal instrument identity.
    pub instrument_id: String,
    /// Quoting time declared by the source.
    pub valuation_us: i64,
    /// Bid coefficient.
    pub bid_mantissa: i64,
    /// Ask coefficient.
    pub ask_mantissa: i64,
    /// Decimal scale for bid and ask.
    pub price_scale: u8,
    /// Implied volatility in basis points, when supplied.
    pub implied_volatility_basis_points: Option<i64>,
    /// Greeks supplied by the source.
    pub greeks: Option<Greeks>,
    /// Valid-time and transaction-time interval.
    pub bitemporal: Bitemporal,
}

/// One regulatory filing with its original document retained separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilingDetail {
    /// Source accession identifier.
    pub accession_id: String,
    /// Internal filer entity identity.
    pub filer_entity_id: String,
    /// Form or document type declared by the authority.
    pub form_type: String,
    /// Digest of the original document bytes.
    pub document_sha256: String,
    /// Source publication time.
    pub published_us: i64,
    /// Source status of the filing.
    pub source_status: SourceObservationStatus,
    /// Valid-time and transaction-time interval.
    pub bitemporal: Bitemporal,
}

/// A physical commodity assessment, distinct from a futures contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommodityAssessmentDetail {
    /// Source assessment identifier.
    pub assessment_id: String,
    /// Location or delivery point.
    pub location: String,
    /// Grade or quality specification.
    pub grade: String,
    /// Assessment period start.
    pub period_start_us: i64,
    /// Assessment period end.
    pub period_end_us: i64,
    /// Assessed price coefficient.
    pub price_mantissa: i64,
    /// Decimal scale of `price_mantissa`.
    pub price_scale: u8,
    /// Source status of the assessment.
    pub source_status: SourceObservationStatus,
    /// Valid-time and transaction-time interval.
    pub bitemporal: Bitemporal,
}

/// Versioned, domain-specific information payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "information_type", rename_all = "snake_case")]
pub enum InformationPayload {
    EconomicObservation(EconomicObservationDetail),
    BondEvaluatedPrice(BondEvaluatedPriceDetail),
    DerivativeQuote(DerivativeQuoteDetail),
    Filing(FilingDetail),
    CommodityAssessment(CommodityAssessmentDetail),
}

impl InformationPayload {
    /// Return the stable contract string for this payload.
    pub fn payload_type(&self) -> &'static str {
        match self {
            Self::EconomicObservation(_) => "economic_observation",
            Self::BondEvaluatedPrice(_) => "bond_evaluated_price",
            Self::DerivativeQuote(_) => "derivative_quote",
            Self::Filing(_) => "filing",
            Self::CommodityAssessment(_) => "commodity_assessment",
        }
    }
}

/// Shared envelope carrying a domain-specific information payload.
pub type InformationEnvelope = crate::event_model::UniversalEnvelope<InformationPayload>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_model::{
        ObservedTimestamp, //
        Provenance,        //
        TimestampRole,     //
        UniversalEnvelope, //
    };
    use crate::identity::InstrumentId;
    use crate::quality::QualityState;

    fn economic() -> EconomicObservationDetail {
        EconomicObservationDetail {
            series_id: "CPI".to_owned(),
            observation_period_start_us: 1_000,
            observation_period_end_us: 2_000,
            publication_us: 2_500,
            release_vintage: 2,
            value_mantissa: 302_500,
            value_scale: 3,
            unit: "index".to_owned(),
            frequency: Frequency::EndOfDay,
            seasonal_adjustment: SeasonalAdjustment::Adjusted,
            source_status: SourceObservationStatus::Revised,
            revision_lineage: vec!["release-1".to_owned()],
            bitemporal: Bitemporal::new(1_000, 2_500),
        }
    }

    #[test]
    fn bitemporal_queries_separate_valid_and_transaction_time() {
        let mut detail = economic();
        detail.bitemporal.valid_to_us = Some(5_000);
        detail.bitemporal.transaction_to_us = Some(9_000);
        assert!(
            detail.bitemporal.as_of(1_500, 3_000),
            "fact true then and known then"
        );
        assert!(
            !detail.bitemporal.as_of(1_500, 10_000),
            "fact no longer the known version"
        );
        assert!(
            !detail.bitemporal.as_of(6_000, 3_000),
            "fact no longer true in the source world"
        );
    }

    #[test]
    fn earlier_and_corrected_versions_are_distinguishable() {
        let mut original = economic();
        original.bitemporal.transaction_to_us = Some(4_000);
        let mut corrected = economic();
        corrected.release_vintage = 3;
        corrected.bitemporal = Bitemporal {
            transaction_from_us: 4_000,
            ..corrected.bitemporal
        };
        assert_ne!(original, corrected, "two vintages remain distinct records");
        assert!(
            original.bitemporal.known_at(3_000),
            "original was known on the earlier date"
        );
        assert!(
            !corrected.bitemporal.known_at(3_000),
            "correction was not known earlier"
        );
        assert!(
            corrected.bitemporal.known_at(5_000),
            "correction is known today"
        );
    }

    #[test]
    fn information_payload_round_trips_with_domain_tag() {
        let payload = InformationPayload::EconomicObservation(economic());
        let text = serde_json::to_string(&payload).expect("serialize payload");
        assert!(
            text.contains("\"information_type\":\"economic_observation\""),
            "versioned domain tag is present"
        );
        let decoded: InformationPayload = serde_json::from_str(&text).expect("deserialize payload");
        assert_eq!(decoded, payload, "domain payload round-trips exactly");
    }

    #[test]
    fn information_envelope_uses_shared_envelope_contract() {
        let envelope: InformationEnvelope = UniversalEnvelope {
            event_id: crate::canonical::EventId::derive("info", "source", "release-2"),
            instrument_id: Option::<InstrumentId>::None,
            entity_id: None,
            event_type: "economic_observation".to_owned(),
            timestamps: vec![ObservedTimestamp::new(
                TimestampRole::ApplicationReceive,
                2_600,
                "host_clock",
            )],
            sequence: None,
            source_schema_version: INFORMATION_SCHEMA_VERSION,
            normalizer_version: "test".to_owned(),
            quality: QualityState::RawCaptured,
            provenance: Provenance {
                raw_record_id: "record-2".to_owned(),
                source_id: "source".to_owned(),
                feed_id: None,
                venue: None,
                decoder_version: "test".to_owned(),
                license_reference: None,
            },
            payload: InformationPayload::EconomicObservation(economic()),
        };
        assert!(envelope.validate().is_ok(), "shared envelope validates");
        assert_eq!(
            envelope.payload.payload_type(),
            "economic_observation",
            "domain type is stable"
        );
    }
}
