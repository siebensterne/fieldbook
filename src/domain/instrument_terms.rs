// SPDX-License-Identifier: Apache-2.0
//! Family-typed instrument terms and unit-bearing exact measures.
//!
//! Every numeric term carries a [`Unit`] and a decimal scale. Integer
//! coefficients use `i128` intermediates and checked arithmetic; no floating
//! point type appears in this module. A bare number cannot cross this
//! contract: [`ExactMeasure`] binds coefficient, scale and unit in one value.
//!
//! The seven term families are separate payload structs behind the tagged
//! [`InstrumentTerms`] enum. [`DerivativeKind`] is a validated projection of
//! [`InstrumentKind`], not a competing
//! classification enum. Contract families and instances add dated-instance
//! structure on top of that shared vocabulary. Identity comes from [`ObjectId`]
//! values derived from immutable assertions; ticker and symbol text is not an
//! identity input.
//!
//! Revisions are append-only [`BitemporalAssertion`] records in a
//! [`BitemporalLedger`]. The registry validates each payload before storage,
//! rejects repeated subject and revision pairs, and answers historical queries
//! with explicit valid and knowledge times. No clock, venue, feed, dataset,
//! entitlement or order event is consulted.

use std::fmt;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::domain::fixed::MAX_SCALE;
use crate::domain::reference_core::BitemporalAssertion;
use crate::domain::reference_core::BitemporalLedger;
use crate::domain::reference_core::LedgerResolution;
use crate::domain::reference_core::ObjectClass;
use crate::domain::reference_core::ObjectId;
use crate::domain::reference_core::ObjectRef;
use crate::domain::reference_core::ReferenceCoreError;
use crate::taxonomy::InstrumentKind;

/// Typed failure from term validation, arithmetic or revision storage.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TermsError {
    /// A decimal scale exceeded the supported maximum from `fixed::MAX_SCALE`.
    #[error("decimal scale exceeds the supported maximum")]
    ScaleOutOfRange,
    /// A derivative lot size was zero.
    #[error("lot size must be positive")]
    ZeroLotSize,
    /// A contract multiplier coefficient was zero or negative.
    #[error("multiplier coefficient must be positive")]
    NonPositiveMultiplier,
    /// A subject or underlying class was outside the permitted set.
    #[error("object class is not permitted for this term")]
    InvalidUnderlyingClass,
    /// An instrument kind was outside the derivative projection set.
    #[error("instrument kind is not a derivative classification")]
    InvalidClassification,
    /// An instance named a family identity other than its own family.
    #[error("instance family identity does not match its family")]
    ContractFamilyMismatch,
    /// A dated instance contradicted an already dated template.
    #[error("instance expiry contradicts the template expiry")]
    InvalidExpiry,
    /// A required field was empty or omitted.
    #[error("required term field is missing")]
    MissingRequiredField,
    /// Two measures with different units entered one arithmetic operation.
    #[error("measure units do not match")]
    UnitMismatch,
    /// A subject and revision pair was already stored.
    #[error("duplicate term revision for subject")]
    DuplicateRevision,
    /// A checked integer operation overflowed.
    #[error("checked integer arithmetic overflowed")]
    ArithmeticOverflow,
}

/// Unit declared with every numeric term value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[expect(
    clippy::enum_variant_names,
    reason = "TimeUnit and PricePerUnit are required serialized variant names"
)]
pub enum Unit {
    /// An amount in a currency named by the assertion context.
    Currency,
    /// A percentage value.
    Percent,
    /// A basis-point value.
    BasisPoints,
    /// A dimensionless fraction.
    Ratio,
    /// A count of items.
    Count,
    /// A mass in grams.
    WeightGram,
    /// A mass in kilograms.
    WeightKilogram,
    /// A volume in barrels.
    VolumeBarrel,
    /// A volume in cubic meters.
    VolumeCubicMeter,
    /// A duration in the time unit named by the assertion context.
    TimeUnit,
    /// A price for one named unit of another measure.
    PricePerUnit,
}

impl Unit {
    /// Return the stable `snake_case` contract string for this unit.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Currency => "currency",
            Self::Percent => "percent",
            Self::BasisPoints => "basis_points",
            Self::Ratio => "ratio",
            Self::Count => "count",
            Self::WeightGram => "weight_gram",
            Self::WeightKilogram => "weight_kilogram",
            Self::VolumeBarrel => "volume_barrel",
            Self::VolumeCubicMeter => "volume_cubic_meter",
            Self::TimeUnit => "time_unit",
            Self::PricePerUnit => "price_per_unit",
        }
    }

    /// Return the scale semantics of this unit as a stable contract string.
    ///
    /// The numeric value of a measure is its coefficient multiplied by ten to
    /// the power of negative scale, expressed in the unit named here. The
    /// assertion context names the currency, time unit or priced unit when the
    /// unit string leaves that dimension open.
    pub const fn scale_semantics(self) -> &'static str {
        match self {
            Self::Currency => "currency amount = coefficient * 10^-scale",
            Self::Percent => "percent = coefficient * 10^-scale",
            Self::BasisPoints => "basis points = coefficient * 10^-scale",
            Self::Ratio => "ratio = coefficient * 10^-scale",
            Self::Count => "items = coefficient * 10^-scale",
            Self::WeightGram => "grams = coefficient * 10^-scale",
            Self::WeightKilogram => "kilograms = coefficient * 10^-scale",
            Self::VolumeBarrel => "barrels = coefficient * 10^-scale",
            Self::VolumeCubicMeter => "cubic meters = coefficient * 10^-scale",
            Self::TimeUnit => "duration = coefficient * 10^-scale context time units",
            Self::PricePerUnit => "price per unit = coefficient * 10^-scale",
        }
    }
}

impl fmt::Display for Unit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Exact integer coefficient with an explicit decimal scale and unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactMeasure {
    /// Signed integer coefficient; the value is `coefficient * 10^-scale`.
    pub coefficient: i128,
    /// Number of decimal places in `coefficient`.
    pub scale: u8,
    /// Unit bound to this value.
    pub unit: Unit,
}

impl ExactMeasure {
    /// Build a measure after checking the scale bound.
    pub fn new(coefficient: i128, scale: u8, unit: Unit) -> Result<Self, TermsError> {
        if scale > MAX_SCALE {
            return Err(TermsError::ScaleOutOfRange);
        }
        Ok(Self {
            coefficient,
            scale,
            unit,
        })
    }

    /// Check the declared scale of this measure.
    pub fn validate(&self) -> Result<(), TermsError> {
        if self.scale > MAX_SCALE {
            return Err(TermsError::ScaleOutOfRange);
        }
        Ok(())
    }

    /// Return the signed integer coefficient.
    pub const fn coefficient(&self) -> i128 {
        self.coefficient
    }

    /// Return the decimal scale.
    pub const fn scale(&self) -> u8 {
        self.scale
    }

    /// Return the declared unit.
    pub const fn unit(&self) -> Unit {
        self.unit
    }

    /// Render the value as a canonical string naming unit and scale.
    ///
    /// The value part is an exact decimal rendering of the integer
    /// coefficient. A measure constructed with an out-of-range scale renders
    /// its raw coefficient instead of computing a power that would overflow.
    pub fn as_canonical_string(&self) -> String {
        let unit = self.unit.as_str();
        let scale = self.scale;
        let Some(factor) = scale_factor(scale) else {
            return format!("{unit}@{scale}:raw:{}", self.coefficient);
        };
        let magnitude = self.coefficient.unsigned_abs();
        let divisor = factor;
        let whole = magnitude / divisor;
        let fraction = magnitude % divisor;
        let sign = if self.coefficient < 0 { "-" } else { "" };
        let rendered = if fraction == 0 {
            format!("{sign}{whole}")
        } else {
            let digits = format!("{fraction:0width$}", width = usize::from(scale));
            let trimmed = digits.trim_end_matches('0');
            format!("{sign}{whole}.{trimmed}")
        };
        format!("{unit}@{scale}:{rendered}")
    }

    /// Add two measures with the same unit using checked integer arithmetic.
    pub fn checked_add(&self, other: &Self) -> Result<Self, TermsError> {
        self.validate()?;
        other.validate()?;
        if self.unit != other.unit {
            return Err(TermsError::UnitMismatch);
        }
        let scale = self.scale.max(other.scale);
        let left_factor = scale_multiplier(self.scale, scale)?;
        let right_factor = scale_multiplier(other.scale, scale)?;
        let left = self
            .coefficient
            .checked_mul(left_factor)
            .ok_or(TermsError::ArithmeticOverflow)?;
        let right = other
            .coefficient
            .checked_mul(right_factor)
            .ok_or(TermsError::ArithmeticOverflow)?;
        let coefficient = left
            .checked_add(right)
            .ok_or(TermsError::ArithmeticOverflow)?;
        Self::new(coefficient, scale, self.unit)
    }

    /// Multiply two measures with the same unit using checked integer
    /// arithmetic. The result carries the summed scale.
    pub fn checked_mul(&self, other: &Self) -> Result<Self, TermsError> {
        self.validate()?;
        other.validate()?;
        if self.unit != other.unit {
            return Err(TermsError::UnitMismatch);
        }
        let scale = self
            .scale
            .checked_add(other.scale)
            .ok_or(TermsError::ScaleOutOfRange)?;
        Self::new(
            self.coefficient
                .checked_mul(other.coefficient)
                .ok_or(TermsError::ArithmeticOverflow)?,
            scale,
            self.unit,
        )
    }
}

fn scale_factor(scale: u8) -> Option<u128> {
    if scale > MAX_SCALE {
        return None;
    }
    10u128.checked_pow(u32::from(scale))
}

fn scale_multiplier(from: u8, to: u8) -> Result<i128, TermsError> {
    let delta = to.checked_sub(from).ok_or(TermsError::ScaleOutOfRange)?;
    10i128
        .checked_pow(u32::from(delta))
        .ok_or(TermsError::ArithmeticOverflow)
}

/// Seniority of a debt claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebtSeniority {
    /// Senior claim.
    Senior,
    /// Subordinated claim.
    Subordinated,
    /// Perpetual claim.
    Perpetual,
    /// Secured claim.
    Secured,
    /// Unsecured claim.
    Unsecured,
}

impl DebtSeniority {
    /// Return the stable `snake_case` contract string for this seniority.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Senior => "senior",
            Self::Subordinated => "subordinated",
            Self::Perpetual => "perpetual",
            Self::Secured => "secured",
            Self::Unsecured => "unsecured",
        }
    }
}

/// Settlement mode of a derivative contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementMode {
    /// Settlement in currency.
    Cash,
    /// Settlement by delivery of the underlying object.
    Physical,
}

impl SettlementMode {
    /// Return the stable `snake_case` contract string for this settlement mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cash => "cash",
            Self::Physical => "physical",
        }
    }
}

/// Redemption mode of a fund.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedemptionMode {
    /// Redemption on demand.
    OpenEnded,
    /// Redemption at declared windows.
    ClosedEnded,
    /// Redemption on a declared schedule.
    Scheduled,
}

impl RedemptionMode {
    /// Return the stable `snake_case` contract string for this redemption mode.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenEnded => "open_ended",
            Self::ClosedEnded => "closed_ended",
            Self::Scheduled => "scheduled",
        }
    }
}

/// Frequency at which a fund publishes a net asset value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NavFrequency {
    /// Daily publication.
    Daily,
    /// Weekly publication.
    Weekly,
    /// Monthly publication.
    Monthly,
    /// Quarterly publication.
    Quarterly,
}

impl NavFrequency {
    /// Return the stable `snake_case` contract string for this frequency.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Daily => "daily",
            Self::Weekly => "weekly",
            Self::Monthly => "monthly",
            Self::Quarterly => "quarterly",
        }
    }
}

/// Frequency at which an index rebalances its constituents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebalanceFrequency {
    /// Monthly rebalance.
    Monthly,
    /// Quarterly rebalance.
    Quarterly,
    /// Semi-annual rebalance.
    SemiAnnual,
    /// Annual rebalance.
    Annual,
}

impl RebalanceFrequency {
    /// Return the stable `snake_case` contract string for this frequency.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Monthly => "monthly",
            Self::Quarterly => "quarterly",
            Self::SemiAnnual => "semi_annual",
            Self::Annual => "annual",
        }
    }
}

/// Validated derivative projection of the shared [`InstrumentKind`] enum.
///
/// The inner value stays the taxonomy variant, so this type adds no competing
/// classification vocabulary. Construction through [`TryFrom`] admits only
/// derivative variants and rejects every other instrument kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DerivativeKind(InstrumentKind);

impl TryFrom<InstrumentKind> for DerivativeKind {
    type Error = TermsError;

    /// Project a derivative taxonomy kind, rejecting all other kinds.
    fn try_from(kind: InstrumentKind) -> Result<Self, Self::Error> {
        match kind {
            InstrumentKind::Future
            | InstrumentKind::Option
            | InstrumentKind::Swap
            | InstrumentKind::NonDeliverableForward
            | InstrumentKind::PerpetualContract
            | InstrumentKind::EventContract => Ok(Self(kind)),
            _ => Err(TermsError::InvalidClassification),
        }
    }
}

impl DerivativeKind {
    /// Return the taxonomy contract string of the projected kind.
    pub const fn as_str(self) -> &'static str {
        self.0.as_str()
    }

    /// Return the underlying taxonomy instrument kind.
    pub const fn inner(self) -> InstrumentKind {
        self.0
    }
}

/// Terms specific to an equity instrument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquityTerms {
    /// Whether the equity carries a vote.
    pub voting: bool,
    /// Whether fractional ownership is permitted.
    pub fractional: bool,
    /// Declared par value, absent when not specified.
    pub par_value: Option<ExactMeasure>,
}

impl EquityTerms {
    /// Validate declared measures.
    pub fn validate(&self) -> Result<(), TermsError> {
        self.par_value
            .as_ref()
            .map_or(Ok(()), ExactMeasure::validate)
    }
}

/// Terms specific to a debt instrument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebtTerms {
    /// Declared principal measure.
    pub principal: ExactMeasure,
    /// Declared coupon measure, absent when not specified.
    pub coupon: Option<ExactMeasure>,
    /// Maturity instant in microseconds, absent when not specified.
    pub maturity_us: Option<i64>,
    /// Declared claim seniority.
    pub seniority: DebtSeniority,
}

impl DebtTerms {
    /// Validate declared measures.
    pub fn validate(&self) -> Result<(), TermsError> {
        self.principal.validate()?;
        self.coupon.as_ref().map_or(Ok(()), ExactMeasure::validate)
    }
}

/// Terms specific to a fund.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundTerms {
    /// Declared net asset value publication frequency.
    pub nav_frequency: NavFrequency,
    /// Declared redemption mode.
    pub redemption: RedemptionMode,
}

impl FundTerms {
    /// Validate declared fields.
    pub fn validate(&self) -> Result<(), TermsError> {
        Ok(())
    }
}

/// Terms specific to a derivative contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivativeTerms {
    /// Structural kind of the contract.
    pub kind: DerivativeKind,
    /// Reference object of the contract.
    pub underlying: ObjectRef,
    /// Template expiry in microseconds; zero means unspecified at family level.
    pub expiry_us: i64,
    /// Declared minimum price increment.
    pub tick_size: ExactMeasure,
    /// Positive number of units in one lot.
    pub lot_size: u64,
    /// Positive contract multiplier.
    pub multiplier: ExactMeasure,
    /// Declared settlement mode.
    pub settlement: SettlementMode,
}

impl DerivativeTerms {
    /// Validate measures, lot size, multiplier and underlying class.
    pub fn validate(&self) -> Result<(), TermsError> {
        self.tick_size.validate()?;
        self.multiplier.validate()?;
        if self.lot_size == 0 {
            return Err(TermsError::ZeroLotSize);
        }
        if self.multiplier.coefficient <= 0 {
            return Err(TermsError::NonPositiveMultiplier);
        }
        if !is_permitted_underlying(self.underlying.class()) {
            return Err(TermsError::InvalidUnderlyingClass);
        }
        Ok(())
    }
}

/// Terms specific to a commodity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommodityTerms {
    /// Declared grade text.
    pub grade: String,
    /// Declared delivery location text.
    pub delivery_location: String,
    /// Unit in which the commodity is measured.
    pub unit: Unit,
}

impl CommodityTerms {
    /// Validate that grade and delivery location are present.
    pub fn validate(&self) -> Result<(), TermsError> {
        if self.grade.is_empty() || self.delivery_location.is_empty() {
            return Err(TermsError::MissingRequiredField);
        }
        Ok(())
    }
}

/// Terms specific to an index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexTerms {
    /// Declared constituent count, absent when not specified.
    pub constituent_count: Option<u64>,
    /// Declared rebalance frequency.
    pub rebalance_frequency: RebalanceFrequency,
}

impl IndexTerms {
    /// Validate declared fields.
    pub fn validate(&self) -> Result<(), TermsError> {
        Ok(())
    }
}

/// Terms specific to a foreign-exchange pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FxTerms {
    /// Unit of the base side.
    pub base_unit: Unit,
    /// Unit of the quote side.
    pub quote_unit: Unit,
    /// Decimal scale of one pip.
    pub pip_scale: u8,
}

impl FxTerms {
    /// Validate the declared pip scale.
    pub fn validate(&self) -> Result<(), TermsError> {
        if self.pip_scale > MAX_SCALE {
            return Err(TermsError::ScaleOutOfRange);
        }
        Ok(())
    }
}

/// Family-typed instrument terms with one payload struct per family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "terms_type", rename_all = "snake_case")]
pub enum InstrumentTerms {
    /// Equity terms.
    Equity(EquityTerms),
    /// Debt terms.
    Debt(DebtTerms),
    /// Fund terms.
    Fund(FundTerms),
    /// Derivative terms.
    Derivative(DerivativeTerms),
    /// Commodity terms.
    Commodity(CommodityTerms),
    /// Index terms.
    Index(IndexTerms),
    /// Foreign-exchange terms.
    Fx(FxTerms),
}

impl InstrumentTerms {
    /// Return the stable `snake_case` tag for this terms family.
    pub const fn terms_type(&self) -> &'static str {
        match self {
            Self::Equity(_) => "equity",
            Self::Debt(_) => "debt",
            Self::Fund(_) => "fund",
            Self::Derivative(_) => "derivative",
            Self::Commodity(_) => "commodity",
            Self::Index(_) => "index",
            Self::Fx(_) => "fx",
        }
    }

    /// Validate the payload of this terms family.
    pub fn validate(&self) -> Result<(), TermsError> {
        match self {
            Self::Equity(terms) => terms.validate(),
            Self::Debt(terms) => terms.validate(),
            Self::Fund(terms) => terms.validate(),
            Self::Derivative(terms) => terms.validate(),
            Self::Commodity(terms) => terms.validate(),
            Self::Index(terms) => terms.validate(),
            Self::Fx(terms) => terms.validate(),
        }
    }
}

fn is_permitted_underlying(class: ObjectClass) -> bool {
    matches!(
        class,
        ObjectClass::FinancialInstrument | ObjectClass::Security | ObjectClass::Index
    )
}

/// A reusable derivative contract family with a dated or undated template.
///
/// Identity is the opaque `family_id`; no ticker, symbol or display label is
/// stored as an identity input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractFamily {
    /// Opaque identity of this family.
    pub family_id: ObjectId,
    /// Reference object of the family.
    pub underlying: ObjectRef,
    /// Declared derivative kind.
    pub kind: DerivativeKind,
    /// Shared derivative terms template.
    pub terms_template: DerivativeTerms,
}

impl ContractFamily {
    /// Validate the family template and its underlying class.
    pub fn validate(&self) -> Result<(), TermsError> {
        self.terms_template.validate()
    }
}

/// One dated contract instance belonging to a contract family.
///
/// Identity is the opaque `instance_id`; no ticker, symbol or display label is
/// stored as an identity input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractInstance {
    /// Opaque identity of this instance.
    pub instance_id: ObjectId,
    /// Opaque identity of the owning family.
    pub family_id: ObjectId,
    /// Instance expiry in microseconds.
    pub expiry_us: i64,
    /// Positive multiplier applied to this instance.
    pub contract_multiplier: ExactMeasure,
}

impl ContractInstance {
    /// Validate the instance multiplier.
    pub fn validate(&self) -> Result<(), TermsError> {
        self.contract_multiplier.validate()?;
        if self.contract_multiplier.coefficient <= 0 {
            return Err(TermsError::NonPositiveMultiplier);
        }
        Ok(())
    }

    /// Validate this instance against its declared family.
    pub fn validate_against(&self, family: &ContractFamily) -> Result<(), TermsError> {
        self.validate()?;
        family.validate()?;
        if self.family_id != family.family_id {
            return Err(TermsError::ContractFamilyMismatch);
        }
        let template_expiry = family.terms_template.expiry_us;
        if self.expiry_us != template_expiry && template_expiry != 0 {
            return Err(TermsError::InvalidExpiry);
        }
        Ok(())
    }
}

/// One append-only bitemporal assertion carrying instrument terms.
pub type InstrumentTermsRevision = BitemporalAssertion<InstrumentTerms>;

const PERMITTED_REVISION_CLASSES: &[ObjectClass] = &[
    ObjectClass::Security,
    ObjectClass::FinancialInstrument,
    ObjectClass::ContractFamily,
    ObjectClass::ContractInstance,
    ObjectClass::MarketProduct,
];

/// Validate a terms revision without consulting a clock.
pub fn validate_terms_revision(revision: &InstrumentTermsRevision) -> Result<(), TermsError> {
    if revision.source.is_empty() || revision.revision == 0 {
        return Err(TermsError::MissingRequiredField);
    }
    revision
        .validate()
        .map_err(|_| TermsError::MissingRequiredField)?;
    revision.payload.validate()?;
    if !PERMITTED_REVISION_CLASSES.contains(&revision.subject.class()) {
        return Err(TermsError::InvalidUnderlyingClass);
    }
    Ok(())
}

/// Append-only registry of validated terms revisions.
///
/// Records live in the shared [`BitemporalLedger`], whose index key is a map
/// from subject and revision pair to ledger position. No record is overwritten.
#[derive(Debug, Clone, Default)]
pub struct TermsRegistry {
    ledger: BitemporalLedger<InstrumentTerms>,
}

impl TermsRegistry {
    /// Create an empty terms registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a validated revision, rejecting a repeated subject and revision.
    pub fn insert(&mut self, revision: InstrumentTermsRevision) -> Result<usize, TermsError> {
        validate_terms_revision(&revision)?;
        self.ledger.insert(revision).map_err(|error| match error {
            ReferenceCoreError::DuplicateRevision(_) => TermsError::DuplicateRevision,
            _ => TermsError::MissingRequiredField,
        })
    }

    /// Query one subject at an explicit valid time and knowledge time.
    pub fn query(&self, subject: &ObjectRef, valid_us: i64, knowledge_us: i64) -> LedgerResolution {
        self.ledger.query(subject, valid_us, knowledge_us)
    }

    /// Read one stored revision by its ledger index.
    pub fn get(&self, index: usize) -> Option<&InstrumentTermsRevision> {
        self.ledger.get(index)
    }

    /// Return the number of stored revisions.
    pub fn len(&self) -> usize {
        self.ledger.len()
    }

    /// Report whether this registry holds no revisions.
    pub fn is_empty(&self) -> bool {
        self.ledger.is_empty()
    }
}

/// List missing required fields of a terms payload using stable labels.
pub fn domain_conformance_report(terms: &InstrumentTerms) -> Vec<&'static str> {
    let mut missing = Vec::new();
    match terms {
        InstrumentTerms::Equity(payload) => {
            if payload
                .par_value
                .as_ref()
                .is_some_and(|value| value.validate().is_err())
            {
                missing.push("equity.par_value");
            }
        }
        InstrumentTerms::Debt(payload) => {
            if payload.principal.validate().is_err() {
                missing.push("debt.principal");
            }
            if payload
                .coupon
                .as_ref()
                .is_some_and(|value| value.validate().is_err())
            {
                missing.push("debt.coupon");
            }
        }
        InstrumentTerms::Fund(_) | InstrumentTerms::Index(_) => {}
        InstrumentTerms::Derivative(payload) => {
            if payload.tick_size.validate().is_err() {
                missing.push("derivative.tick_size");
            }
            if payload.multiplier.validate().is_err() {
                missing.push("derivative.multiplier.scale");
            }
            if payload.lot_size == 0 {
                missing.push("derivative.lot_size");
            }
            if payload.multiplier.coefficient <= 0 {
                missing.push("derivative.multiplier");
            }
            if !is_permitted_underlying(payload.underlying.class()) {
                missing.push("derivative.underlying");
            }
        }
        InstrumentTerms::Commodity(payload) => {
            if payload.grade.is_empty() {
                missing.push("commodity.grade");
            }
            if payload.delivery_location.is_empty() {
                missing.push("commodity.delivery_location");
            }
        }
        InstrumentTerms::Fx(payload) => {
            if payload.pip_scale > MAX_SCALE {
                missing.push("fx.pip_scale");
            }
        }
    }
    missing
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::domain::information::Bitemporal;

    fn object_ref(class: ObjectClass, key: &str) -> ObjectRef {
        ObjectRef::new(class, "namespace-a", "authority-a", key).expect("valid object ref")
    }

    fn object_id(key: &str) -> ObjectId {
        ObjectId::derive(
            ObjectClass::ContractFamily,
            "namespace-a",
            "authority-a",
            key,
        )
        .expect("valid object id")
    }

    fn measure(coefficient: i128, scale: u8, unit: Unit) -> ExactMeasure {
        ExactMeasure::new(coefficient, scale, unit).expect("valid measure")
    }

    fn derivative_terms() -> DerivativeTerms {
        DerivativeTerms {
            kind: DerivativeKind::try_from(InstrumentKind::Future).expect("derivative kind"),
            underlying: object_ref(ObjectClass::Security, "key-underlying"),
            expiry_us: 90,
            tick_size: measure(7, 2, Unit::PricePerUnit),
            lot_size: 5,
            multiplier: measure(11, 1, Unit::Count),
            settlement: SettlementMode::Cash,
        }
    }

    fn all_terms() -> Vec<InstrumentTerms> {
        vec![
            InstrumentTerms::Equity(EquityTerms {
                voting: true,
                fractional: false,
                par_value: Some(measure(3, 1, Unit::Currency)),
            }),
            InstrumentTerms::Debt(DebtTerms {
                principal: measure(13, 2, Unit::Currency),
                coupon: Some(measure(4, 3, Unit::Percent)),
                maturity_us: Some(120),
                seniority: DebtSeniority::Senior,
            }),
            InstrumentTerms::Fund(FundTerms {
                nav_frequency: NavFrequency::Weekly,
                redemption: RedemptionMode::OpenEnded,
            }),
            InstrumentTerms::Derivative(derivative_terms()),
            InstrumentTerms::Commodity(CommodityTerms {
                grade: "grade-a".to_owned(),
                delivery_location: "location-a".to_owned(),
                unit: Unit::WeightGram,
            }),
            InstrumentTerms::Index(IndexTerms {
                constituent_count: Some(20),
                rebalance_frequency: RebalanceFrequency::Quarterly,
            }),
            InstrumentTerms::Fx(FxTerms {
                base_unit: Unit::Currency,
                quote_unit: Unit::Currency,
                pip_scale: 4,
            }),
        ]
    }

    fn revision(
        subject: &ObjectRef,
        payload: InstrumentTerms,
        number: u64,
        transaction_from_us: i64,
        predecessor: Option<ObjectId>,
    ) -> InstrumentTermsRevision {
        InstrumentTermsRevision {
            subject: subject.clone(),
            payload,
            bitemporal: Bitemporal::new(10, transaction_from_us),
            source: "source-a".to_owned(),
            revision: number,
            predecessor,
        }
    }

    #[test]
    fn unit_strings_are_stable_and_distinct() {
        let units = [
            (Unit::Currency, "currency"),
            (Unit::Percent, "percent"),
            (Unit::BasisPoints, "basis_points"),
            (Unit::Ratio, "ratio"),
            (Unit::Count, "count"),
            (Unit::WeightGram, "weight_gram"),
            (Unit::WeightKilogram, "weight_kilogram"),
            (Unit::VolumeBarrel, "volume_barrel"),
            (Unit::VolumeCubicMeter, "volume_cubic_meter"),
            (Unit::TimeUnit, "time_unit"),
            (Unit::PricePerUnit, "price_per_unit"),
        ];
        let mut strings = std::collections::BTreeSet::new();
        for (unit, expected) in units {
            assert_eq!(unit.as_str(), expected, "unit string must be stable");
            assert!(
                unit.scale_semantics().contains("10^-scale"),
                "every unit declares explicit scale semantics"
            );
            assert!(strings.insert(expected), "unit strings must be distinct");
        }
    }

    #[test]
    fn canonical_string_names_unit_scale_and_exact_value() {
        let positive = measure(12_345, 3, Unit::Count);
        let negative = measure(-45, 2, Unit::Percent);
        assert_eq!(
            positive.as_canonical_string(),
            "count@3:12.345",
            "canonical string carries unit, scale and exact value"
        );
        assert_eq!(
            negative.as_canonical_string(),
            "percent@2:-0.45",
            "negative coefficients keep their sign"
        );
    }

    #[test]
    fn scale_above_eighteen_is_rejected() {
        assert!(
            matches!(
                ExactMeasure::new(1, 19, Unit::Count),
                Err(TermsError::ScaleOutOfRange)
            ),
            "scale above the fixed maximum must be rejected"
        );
        assert!(
            ExactMeasure::new(1, 18, Unit::Count).is_ok(),
            "the maximum supported scale is accepted"
        );
        let invalid = ExactMeasure {
            coefficient: 1,
            scale: 19,
            unit: Unit::Count,
        };
        assert!(
            matches!(invalid.validate(), Err(TermsError::ScaleOutOfRange)),
            "struct construction is checked again on validation"
        );
        assert!(
            invalid.as_canonical_string().contains("raw"),
            "out-of-range scale uses the non-computing rendering branch"
        );
    }

    #[test]
    fn checked_add_aligns_scales_without_float() {
        let left = measure(2, 0, Unit::Count);
        let right = measure(3, 1, Unit::Count);
        let sum = left.checked_add(&right).expect("checked addition");
        assert_eq!(
            sum.coefficient(),
            23,
            "coefficients align to the larger scale"
        );
        assert_eq!(sum.scale(), 1, "result keeps the larger scale");
        assert_eq!(sum.unit(), Unit::Count, "result keeps the declared unit");
    }

    #[test]
    fn checked_add_rejects_unit_mismatch() {
        let left = measure(2, 0, Unit::Count);
        let right = measure(3, 0, Unit::Percent);
        assert!(
            matches!(left.checked_add(&right), Err(TermsError::UnitMismatch)),
            "different units cannot enter one addition"
        );
    }

    #[test]
    fn checked_add_rejects_overflow() {
        let left = measure(i128::MAX, 0, Unit::Count);
        let right = measure(1, 0, Unit::Count);
        assert!(
            matches!(
                left.checked_add(&right),
                Err(TermsError::ArithmeticOverflow)
            ),
            "coefficient overflow must be rejected"
        );
    }

    #[test]
    fn checked_mul_combines_scales() {
        let left = measure(7, 1, Unit::Count);
        let right = measure(3, 2, Unit::Count);
        let product = left.checked_mul(&right).expect("checked multiplication");
        assert_eq!(product.coefficient(), 21, "coefficients multiply exactly");
        assert_eq!(product.scale(), 3, "scales add");
        assert_eq!(
            product.as_canonical_string(),
            "count@3:0.021",
            "product rendering retains unit and combined scale"
        );
    }

    #[test]
    fn checked_mul_rejects_scale_out_of_range() {
        let left = measure(2, 10, Unit::Count);
        let right = measure(3, 9, Unit::Count);
        assert!(
            matches!(left.checked_mul(&right), Err(TermsError::ScaleOutOfRange)),
            "summed scale beyond the maximum must be rejected"
        );
    }

    #[test]
    fn same_inputs_produce_same_canonical_string() {
        let first = measure(2_109, 4, Unit::VolumeBarrel);
        let second = measure(2_109, 4, Unit::VolumeBarrel);
        assert_eq!(
            first.as_canonical_string(),
            second.as_canonical_string(),
            "equal inputs render one canonical string"
        );
    }

    #[test]
    fn derivative_kind_projects_only_derivative_taxonomy_kinds() {
        let derivative_kinds = [
            InstrumentKind::Future,
            InstrumentKind::Option,
            InstrumentKind::Swap,
            InstrumentKind::NonDeliverableForward,
            InstrumentKind::PerpetualContract,
            InstrumentKind::EventContract,
        ];
        for kind in derivative_kinds {
            let projected = DerivativeKind::try_from(kind).expect("derivative projection");
            assert_eq!(
                projected.as_str(),
                kind.as_str(),
                "projection delegates the taxonomy contract string"
            );
            assert_eq!(
                projected.inner(),
                kind,
                "projection retains the taxonomy kind"
            );
        }
        for kind in [
            InstrumentKind::CommonShare,
            InstrumentKind::FxSpot,
            InstrumentKind::NewsItem,
        ] {
            assert!(
                matches!(
                    DerivativeKind::try_from(kind),
                    Err(TermsError::InvalidClassification)
                ),
                "non-derivative taxonomy kind must be rejected"
            );
        }
    }

    #[test]
    fn each_family_validates_with_arbitrary_values() {
        for terms in all_terms() {
            let label = terms.terms_type();
            assert!(terms.validate().is_ok(), "{label} terms must validate");
        }
        assert_eq!(all_terms().len(), 7, "seven distinct families are declared");
    }

    #[test]
    fn missing_required_field_is_reported() {
        let terms = InstrumentTerms::Commodity(CommodityTerms {
            grade: String::new(),
            delivery_location: String::new(),
            unit: Unit::VolumeCubicMeter,
        });
        let report = domain_conformance_report(&terms);
        assert!(
            report.contains(&"commodity.grade"),
            "empty grade must be reported"
        );
        assert!(
            report.contains(&"commodity.delivery_location"),
            "empty delivery location must be reported"
        );
        assert!(
            matches!(terms.validate(), Err(TermsError::MissingRequiredField)),
            "empty required fields fail validation"
        );
    }

    #[test]
    fn valid_terms_have_empty_conformance_report() {
        for terms in all_terms() {
            let label = terms.terms_type();
            assert!(
                domain_conformance_report(&terms).is_empty(),
                "{label} terms have no missing required field"
            );
        }
    }

    #[test]
    fn zero_lot_is_rejected() {
        let mut terms = derivative_terms();
        terms.lot_size = 0;
        assert!(
            matches!(
                InstrumentTerms::Derivative(terms.clone()).validate(),
                Err(TermsError::ZeroLotSize)
            ),
            "zero lot size must be rejected"
        );
        assert!(
            domain_conformance_report(&InstrumentTerms::Derivative(terms))
                .contains(&"derivative.lot_size"),
            "zero lot size appears in the conformance report"
        );
    }

    #[test]
    fn nonpositive_multiplier_is_rejected() {
        let mut terms = derivative_terms();
        terms.multiplier = measure(0, 1, Unit::Count);
        assert!(
            matches!(terms.validate(), Err(TermsError::NonPositiveMultiplier)),
            "zero multiplier must be rejected"
        );
        terms.multiplier = measure(-2, 1, Unit::Count);
        assert!(
            matches!(terms.validate(), Err(TermsError::NonPositiveMultiplier)),
            "negative multiplier must be rejected"
        );
    }

    #[test]
    fn wrong_underlying_class_is_rejected() {
        let mut terms = derivative_terms();
        terms.underlying = object_ref(ObjectClass::MarketProduct, "key-product");
        assert!(
            matches!(terms.validate(), Err(TermsError::InvalidUnderlyingClass)),
            "market product is not a permitted underlying class"
        );
        terms.underlying = object_ref(ObjectClass::Index, "key-index");
        assert!(
            terms.validate().is_ok(),
            "index is a permitted underlying class"
        );
    }

    #[test]
    fn contract_family_and_instance_agree() {
        let template = derivative_terms();
        let family = ContractFamily {
            family_id: object_id("key-family"),
            underlying: template.underlying.clone(),
            kind: template.kind,
            terms_template: template,
        };
        let instance = ContractInstance {
            instance_id: object_id("key-instance"),
            family_id: family.family_id.clone(),
            expiry_us: 90,
            contract_multiplier: measure(11, 0, Unit::Count),
        };
        assert!(family.validate().is_ok(), "family template validates");
        assert!(instance.validate().is_ok(), "instance multiplier validates");
        assert!(
            instance.validate_against(&family).is_ok(),
            "agreeing family and instance validate together"
        );
    }

    #[test]
    fn instance_family_mismatch_is_rejected() {
        let template = derivative_terms();
        let family = ContractFamily {
            family_id: object_id("key-family"),
            underlying: template.underlying.clone(),
            kind: template.kind,
            terms_template: template,
        };
        let instance = ContractInstance {
            instance_id: object_id("key-instance"),
            family_id: object_id("key-other-family"),
            expiry_us: 90,
            contract_multiplier: measure(11, 0, Unit::Count),
        };
        assert!(
            matches!(
                instance.validate_against(&family),
                Err(TermsError::ContractFamilyMismatch)
            ),
            "instance must name its own family identity"
        );
    }

    #[test]
    fn template_expiry_zero_permits_dated_instances() {
        let mut template = derivative_terms();
        template.expiry_us = 0;
        let family = ContractFamily {
            family_id: object_id("key-family"),
            underlying: template.underlying.clone(),
            kind: template.kind,
            terms_template: template.clone(),
        };
        let dated = ContractInstance {
            instance_id: object_id("key-instance"),
            family_id: family.family_id.clone(),
            expiry_us: 240,
            contract_multiplier: measure(3, 0, Unit::Count),
        };
        assert!(
            dated.validate_against(&family).is_ok(),
            "unspecified template expiry permits a dated instance"
        );
        template.expiry_us = 90;
        let dated_family = ContractFamily {
            terms_template: template,
            ..family
        };
        assert!(
            matches!(
                dated.validate_against(&dated_family),
                Err(TermsError::InvalidExpiry)
            ),
            "a dated template rejects a different instance expiry"
        );
        let aligned = ContractInstance {
            expiry_us: 90,
            ..dated
        };
        assert!(
            aligned.validate_against(&dated_family).is_ok(),
            "an instance matching the dated template is accepted"
        );
    }

    #[test]
    fn revision_subject_class_is_validated() {
        let subject = object_ref(ObjectClass::Security, "key-security");
        let payload = InstrumentTerms::Fund(FundTerms {
            nav_frequency: NavFrequency::Monthly,
            redemption: RedemptionMode::Scheduled,
        });
        let valid = revision(&subject, payload.clone(), 1, 10, None);
        assert!(
            validate_terms_revision(&valid).is_ok(),
            "security is a permitted revision subject class"
        );
        let wrong = valid.clone();
        let wrong = InstrumentTermsRevision {
            subject: object_ref(ObjectClass::Venue, "key-venue"),
            ..wrong
        };
        assert!(
            matches!(
                validate_terms_revision(&wrong),
                Err(TermsError::InvalidUnderlyingClass)
            ),
            "venue is not a permitted revision subject class"
        );
        let zero = InstrumentTermsRevision {
            revision: 0,
            ..valid.clone()
        };
        assert!(
            matches!(
                validate_terms_revision(&zero),
                Err(TermsError::MissingRequiredField)
            ),
            "zero revision must be rejected"
        );
        let empty_source = InstrumentTermsRevision {
            source: String::new(),
            ..valid.clone()
        };
        assert!(
            matches!(
                validate_terms_revision(&empty_source),
                Err(TermsError::MissingRequiredField)
            ),
            "empty source must be rejected"
        );
        let bad_payload = InstrumentTermsRevision {
            payload: InstrumentTerms::Commodity(CommodityTerms {
                grade: String::new(),
                delivery_location: "location-a".to_owned(),
                unit: Unit::Count,
            }),
            ..valid
        };
        assert!(
            matches!(
                validate_terms_revision(&bad_payload),
                Err(TermsError::MissingRequiredField)
            ),
            "invalid payload fails revision validation"
        );
    }

    #[test]
    fn duplicate_revision_is_rejected() {
        let subject = object_ref(ObjectClass::ContractInstance, "key-instance-subject");
        let payload = InstrumentTerms::Equity(EquityTerms {
            voting: false,
            fractional: true,
            par_value: None,
        });
        let first = revision(&subject, payload.clone(), 7, 10, None);
        let duplicate = revision(&subject, payload, 7, 20, None);
        let mut registry = TermsRegistry::new();
        assert!(registry.is_empty(), "new registry holds no revisions");
        registry.insert(first).expect("first revision");
        assert!(
            matches!(
                registry.insert(duplicate),
                Err(TermsError::DuplicateRevision)
            ),
            "repeated subject and revision must be rejected"
        );
        assert_eq!(
            registry.len(),
            1,
            "duplicate insertion leaves the store unchanged"
        );
    }

    #[test]
    fn bitemporal_query_uses_historical_knowledge_time() {
        let subject = object_ref(ObjectClass::FinancialInstrument, "key-financial");
        let payload = InstrumentTerms::Index(IndexTerms {
            constituent_count: Some(12),
            rebalance_frequency: RebalanceFrequency::Annual,
        });
        let first = revision(&subject, payload.clone(), 1, 10, None);
        let second = revision(&subject, payload, 2, 40, Some(first.assertion_id()));
        let mut registry = TermsRegistry::new();
        registry.insert(first).expect("first revision");
        let head = registry.insert(second).expect("second revision");
        assert_eq!(
            registry.query(&subject, 15, 30),
            LedgerResolution::Resolved(0),
            "historical knowledge time resolves the earlier revision"
        );
        assert_eq!(
            registry.query(&subject, 15, 50),
            LedgerResolution::Resolved(head),
            "later knowledge time resolves the superseding revision"
        );
        assert_eq!(
            registry.get(head).map(|item| item.revision),
            Some(2),
            "stored revision is readable by ledger index"
        );
    }

    #[test]
    fn authority_paths_use_integer_coefficients() {
        fn accepts_i128(value: i128) -> i128 {
            value
        }
        fn accepts_u8(value: u8) -> u8 {
            value
        }
        let item = measure(9, 2, Unit::Ratio);
        assert_eq!(
            accepts_i128(item.coefficient()),
            9,
            "coefficient is an integer type"
        );
        assert_eq!(
            accepts_u8(item.scale()),
            2,
            "scale is an unsigned integer type"
        );
        let aligned = item
            .checked_add(&measure(1, 3, Unit::Ratio))
            .expect("checked addition");
        assert_eq!(
            accepts_i128(aligned.coefficient()),
            91,
            "checked arithmetic returns an integer coefficient"
        );
    }
}
