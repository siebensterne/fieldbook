//! Universal financial information taxonomy.
//!
//! These types classify data domains, instruments, information categories,
//! depth, frequency and temporal status. They are declarations for a global
//! platform; they do not claim that Fieldbook currently acquires any of the
//! represented assets or information.

use std::fmt;

use serde::Deserialize;
use serde::Serialize;

/// Broad financial information domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetClass {
    Equity,
    FixedIncome,
    Derivatives,
    ForeignExchange,
    Commodity,
    DigitalAsset,
    Index,
    CorporateInformation,
    Macroeconomic,
    NewsAndEvents,
    AlternativeInformation,
}

impl AssetClass {
    /// Return the stable contract string for this asset class.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equity => "equity",
            Self::FixedIncome => "fixed_income",
            Self::Derivatives => "derivatives",
            Self::ForeignExchange => "foreign_exchange",
            Self::Commodity => "commodity",
            Self::DigitalAsset => "digital_asset",
            Self::Index => "index",
            Self::CorporateInformation => "corporate_information",
            Self::Macroeconomic => "macroeconomic",
            Self::NewsAndEvents => "news_and_events",
            Self::AlternativeInformation => "alternative_information",
        }
    }

    /// Return every declared asset class in stable order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::Equity,
            Self::FixedIncome,
            Self::Derivatives,
            Self::ForeignExchange,
            Self::Commodity,
            Self::DigitalAsset,
            Self::Index,
            Self::CorporateInformation,
            Self::Macroeconomic,
            Self::NewsAndEvents,
            Self::AlternativeInformation,
        ]
    }
}

impl fmt::Display for AssetClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Instrument or information object kind within an asset class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstrumentKind {
    CommonShare,
    PreferredShare,
    DepositaryReceipt,
    ExchangeTradedFund,
    ExchangeTradedNote,
    RealEstateInvestmentTrust,
    Fund,
    Warrant,
    Right,
    ConvertibleSecurity,
    SpecialPurposeAcquisitionCompany,
    GovernmentBond,
    TreasuryBill,
    InflationLinkedBond,
    CorporateBond,
    MunicipalBond,
    MortgageBackedSecurity,
    AssetBackedSecurity,
    CollateralizedLoanObligation,
    CommercialPaper,
    CertificateOfDeposit,
    RepurchaseAgreement,
    Future,
    Option,
    Swap,
    FxSpot,
    FxForward,
    FxSwap,
    NonDeliverableForward,
    CommoditySpot,
    CommodityAssessment,
    DigitalToken,
    PerpetualContract,
    EventContract,
    EquityIndex,
    RateIndex,
    EconomicIndicator,
    RegulatoryFiling,
    NewsItem,
    OnChainObservation,
}

impl InstrumentKind {
    /// Return the stable contract string for this instrument kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommonShare => "common_share",
            Self::PreferredShare => "preferred_share",
            Self::DepositaryReceipt => "depositary_receipt",
            Self::ExchangeTradedFund => "exchange_traded_fund",
            Self::ExchangeTradedNote => "exchange_traded_note",
            Self::RealEstateInvestmentTrust => "real_estate_investment_trust",
            Self::Fund => "fund",
            Self::Warrant => "warrant",
            Self::Right => "right",
            Self::ConvertibleSecurity => "convertible_security",
            Self::SpecialPurposeAcquisitionCompany => "spac",
            Self::GovernmentBond => "government_bond",
            Self::TreasuryBill => "treasury_bill",
            Self::InflationLinkedBond => "inflation_linked_bond",
            Self::CorporateBond => "corporate_bond",
            Self::MunicipalBond => "municipal_bond",
            Self::MortgageBackedSecurity => "mortgage_backed_security",
            Self::AssetBackedSecurity => "asset_backed_security",
            Self::CollateralizedLoanObligation => "collateralized_loan_obligation",
            Self::CommercialPaper => "commercial_paper",
            Self::CertificateOfDeposit => "certificate_of_deposit",
            Self::RepurchaseAgreement => "repurchase_agreement",
            Self::Future => "future",
            Self::Option => "option",
            Self::Swap => "swap",
            Self::FxSpot => "fx_spot",
            Self::FxForward => "fx_forward",
            Self::FxSwap => "fx_swap",
            Self::NonDeliverableForward => "non_deliverable_forward",
            Self::CommoditySpot => "commodity_spot",
            Self::CommodityAssessment => "commodity_assessment",
            Self::DigitalToken => "digital_token",
            Self::PerpetualContract => "perpetual_contract",
            Self::EventContract => "event_contract",
            Self::EquityIndex => "equity_index",
            Self::RateIndex => "rate_index",
            Self::EconomicIndicator => "economic_indicator",
            Self::RegulatoryFiling => "regulatory_filing",
            Self::NewsItem => "news_item",
            Self::OnChainObservation => "on_chain_observation",
        }
    }
}

/// Information category exposed by a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    Level1Quotes,
    Level2Book,
    Level3Book,
    Trades,
    OrderEvents,
    AuctionInformation,
    MarketStatus,
    ReferenceData,
    CorporateActions,
    Fundamentals,
    EconomicRelease,
    News,
    RegulatoryFiling,
    EvaluatedPrice,
    Curve,
    Fixing,
    OnChain,
    Sentiment,
    AlternativeInformation,
}

impl DataCategory {
    /// Return the stable contract string for this information category.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Level1Quotes => "level1_quotes",
            Self::Level2Book => "level2_book",
            Self::Level3Book => "level3_book",
            Self::Trades => "trades",
            Self::OrderEvents => "order_events",
            Self::AuctionInformation => "auction_information",
            Self::MarketStatus => "market_status",
            Self::ReferenceData => "reference_data",
            Self::CorporateActions => "corporate_actions",
            Self::Fundamentals => "fundamentals",
            Self::EconomicRelease => "economic_release",
            Self::News => "news",
            Self::RegulatoryFiling => "regulatory_filing",
            Self::EvaluatedPrice => "evaluated_price",
            Self::Curve => "curve",
            Self::Fixing => "fixing",
            Self::OnChain => "on_chain",
            Self::Sentiment => "sentiment",
            Self::AlternativeInformation => "alternative_information",
        }
    }
}

/// Market depth or liquidity model carried by an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepthModel {
    Level1,
    Level2,
    Level3,
    Consolidated,
    Indicative,
    ParticipantEntitled,
}

impl DepthModel {
    /// Return the stable contract string for this depth model.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Level1 => "level1",
            Self::Level2 => "level2",
            Self::Level3 => "level3",
            Self::Consolidated => "consolidated",
            Self::Indicative => "indicative",
            Self::ParticipantEntitled => "participant_entitled",
        }
    }
}

/// Delivery frequency of a data product.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Frequency {
    RealTime,
    Delayed,
    EndOfDay,
    Batch,
    OnDemand,
}

impl Frequency {
    /// Return the stable contract string for this delivery frequency.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RealTime => "real_time",
            Self::Delayed => "delayed",
            Self::EndOfDay => "end_of_day",
            Self::Batch => "batch",
            Self::OnDemand => "on_demand",
        }
    }
}

/// Temporal status of a value relative to later corrections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalStatus {
    Historical,
    Current,
    RealTime,
    Delayed,
    Preliminary,
    Corrected,
    Revised,
}

impl TemporalStatus {
    /// Return the stable contract string for this temporal status.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Historical => "historical",
            Self::Current => "current",
            Self::RealTime => "real_time",
            Self::Delayed => "delayed",
            Self::Preliminary => "preliminary",
            Self::Corrected => "corrected",
            Self::Revised => "revised",
        }
    }
}

/// Uppercase ISO 3166-1 alpha-2 country code.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CountryCode(String);

impl Default for CountryCode {
    fn default() -> Self {
        // "ZZ" is a valid two-letter user-assigned code. It is never a
        // wildcard: an absent territory still fails scope comparison.
        Self("ZZ".to_owned())
    }
}

impl CountryCode {
    /// Build a country code after validating its shape.
    pub fn new(value: &str) -> Result<Self, InvalidCode> {
        let bytes = value.as_bytes();
        if bytes.len() != 2 || !bytes.iter().all(|byte| byte.is_ascii_uppercase()) {
            return Err(InvalidCode::Country(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the validated code.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Uppercase ISO 4217 alphabetic currency code.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CurrencyCode(String);

impl CurrencyCode {
    /// Build a currency code after validating its shape.
    pub fn new(value: &str) -> Result<Self, InvalidCode> {
        let bytes = value.as_bytes();
        if bytes.len() != 3 || !bytes.iter().all(|byte| byte.is_ascii_uppercase()) {
            return Err(InvalidCode::Currency(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the validated code.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Reason a code failed validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidCode {
    /// Country code is not two uppercase ASCII letters.
    #[error("invalid country code: {0}")]
    Country(String),
    /// Currency code is not three uppercase ASCII letters.
    #[error("invalid currency code: {0}")]
    Currency(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_strings_are_stable() {
        let text = serde_json::to_string(&AssetClass::FixedIncome).expect("serialize asset class");
        assert_eq!(text, "\"fixed_income\"", "asset string must be stable");
    }

    #[test]
    fn data_categories_are_distinct() {
        let categories = [
            DataCategory::Level1Quotes,
            DataCategory::Level2Book,
            DataCategory::Level3Book,
            DataCategory::Trades,
            DataCategory::OrderEvents,
            DataCategory::AuctionInformation,
            DataCategory::MarketStatus,
            DataCategory::ReferenceData,
            DataCategory::CorporateActions,
            DataCategory::Fundamentals,
            DataCategory::EconomicRelease,
            DataCategory::News,
            DataCategory::RegulatoryFiling,
            DataCategory::EvaluatedPrice,
            DataCategory::Curve,
            DataCategory::Fixing,
            DataCategory::OnChain,
            DataCategory::Sentiment,
            DataCategory::AlternativeInformation,
        ];
        let mut values: Vec<&str> = categories.iter().map(|value| value.as_str()).collect();
        values.sort_unstable();
        let count = values.len();
        values.dedup();
        assert_eq!(values.len(), count, "category strings must be unique");
    }
}
