// SPDX-License-Identifier: Apache-2.0
//! Jurisdiction, venue and product registry with versioned country packs.
//!
//! Registrations use opaque [`ObjectId`] values from the canonical reference
//! core and the classification types from the surrounding domain. A
//! jurisdiction code is a validated string, so arbitrary territories register
//! without a Rust enum change. Country packs carry versioned data. Each
//! reference to an authority, venue or segment is checked against the recorded
//! jurisdiction, and lookups report ambiguity or conflict rather than picking
//! a first row.
//!
//! This module declares abstract structures. It names no venue, provider,
//! dataset, rights decision or feed, and it reads no clock.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::domain::information::Bitemporal;
use crate::domain::reference_core::ObjectClass;
use crate::domain::reference_core::ObjectId;
use crate::domain::reference_core::ObjectRef;
use crate::domain::reference_data::VenueCategory;
use crate::domain::taxonomy::InstrumentKind;

/// Validated uppercase ASCII jurisdiction code of two to eight characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JurisdictionCode(String);

impl JurisdictionCode {
    /// Build a jurisdiction code after checking its characters and length.
    pub fn new(value: &str) -> Result<Self, RegistryError> {
        let bytes = value.as_bytes();
        let characters_valid = bytes
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'-');
        if bytes.len() < 2 || bytes.len() > 8 || !characters_valid {
            return Err(RegistryError::InvalidJurisdictionCode(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }

    /// Return the validated code text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JurisdictionCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Typed failure from registry validation, insertion or resolution setup.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RegistryError {
    /// A jurisdiction code failed the character or length rules.
    #[error("invalid jurisdiction code: {0}")]
    InvalidJurisdictionCode(String),
    /// An object identity with the same revision was already stored.
    #[error("duplicate object revision: {0}")]
    DuplicateObject(String),
    /// A referenced object identity was not registered.
    #[error("unknown reference: {0}")]
    UnknownReference(String),
    /// A referenced object belongs to another jurisdiction.
    #[error("jurisdiction mismatch for reference {0}")]
    JurisdictionMismatch(String),
    /// A pack version did not exceed the stored version.
    #[error("pack version did not exceed the stored version for {0}")]
    VersionMismatch(String),
    /// A revision value was zero.
    #[error("revision must be nonzero: {0}")]
    InvalidRevision(u64),
    /// A required text field was empty.
    #[error("empty field: {0}")]
    EmptyField(String),
    /// No country pack was registered for a jurisdiction.
    #[error("unknown country pack: {0}")]
    UnknownPack(String),
    /// An assertion disagreed with a referenced registration.
    #[error("conflicting assertion for {0}")]
    ConflictingAssertion(String),
}

/// Role declared for a registered authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKind {
    /// Prudential or market regulator.
    Regulator,
    /// Entity operating an exchange venue.
    ExchangeOperator,
    /// Clearing house or central counterparty.
    ClearingCorporation,
    /// Securities depository.
    Depository,
    /// Administrator of a benchmark.
    BenchmarkAdministrator,
    /// Authority role named by an asserting source.
    Other(String),
}

impl AuthorityKind {
    /// Return the stable contract string for this authority role.
    pub fn as_str(&self) -> &str {
        match self {
            Self::Regulator => "regulator",
            Self::ExchangeOperator => "exchange_operator",
            Self::ClearingCorporation => "clearing_corporation",
            Self::Depository => "depository",
            Self::BenchmarkAdministrator => "benchmark_administrator",
            Self::Other(text) => text,
        }
    }
}

impl fmt::Display for AuthorityKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

fn validate_record(source: &str, revision: u64) -> Result<(), RegistryError> {
    if source.is_empty() {
        return Err(RegistryError::EmptyField("source".to_owned()));
    }
    if revision == 0 {
        return Err(RegistryError::InvalidRevision(revision));
    }
    Ok(())
}

fn permitted_terms_class(class: ObjectClass) -> bool {
    matches!(
        class,
        ObjectClass::Security
            | ObjectClass::FinancialInstrument
            | ObjectClass::ContractFamily
            | ObjectClass::ContractInstance
    )
}

/// Bitemporally scoped assertion describing one registered authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityAssertion {
    /// Object described by this assertion.
    pub object: ObjectRef,
    /// Jurisdiction in which the authority is registered.
    pub jurisdiction: JurisdictionCode,
    /// Declared role of the authority.
    pub kind: AuthorityKind,
    /// Parent authority, when the assertion names one.
    pub parent: Option<ObjectId>,
    /// Named source of the assertion record.
    pub source: String,
    /// Valid-time and knowledge-time interval.
    pub bitemporal: Bitemporal,
    /// Nonzero declaration revision.
    pub revision: u64,
}

impl AuthorityAssertion {
    /// Validate the fields of this assertion without consulting other records.
    pub fn validate(&self) -> Result<(), RegistryError> {
        validate_record(&self.source, self.revision)
    }
}

/// Bitemporally scoped assertion describing one registered venue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VenueAssertion {
    /// Object described by this assertion.
    pub object: ObjectRef,
    /// Jurisdiction in which the venue is registered.
    pub jurisdiction: JurisdictionCode,
    /// Operator authority registered in the same jurisdiction.
    pub operator: ObjectId,
    /// Market identifier text, absent when not declared.
    pub mic: Option<String>,
    /// Regulatory or operational category of the venue.
    pub category: VenueCategory,
    /// Segments declared under this venue.
    pub segments: BTreeSet<ObjectId>,
    /// Named source of the assertion record.
    pub source: String,
    /// Valid-time and knowledge-time interval.
    pub bitemporal: Bitemporal,
    /// Nonzero declaration revision.
    pub revision: u64,
}

impl VenueAssertion {
    /// Validate the fields of this assertion without consulting other records.
    pub fn validate(&self) -> Result<(), RegistryError> {
        validate_record(&self.source, self.revision)?;
        if self.mic.as_ref().is_some_and(String::is_empty) {
            return Err(RegistryError::EmptyField("mic".to_owned()));
        }
        Ok(())
    }
}

/// Bitemporally scoped assertion describing one registered segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentAssertion {
    /// Object described by this assertion.
    pub object: ObjectRef,
    /// Jurisdiction in which the segment is registered.
    pub jurisdiction: JurisdictionCode,
    /// Venue that owns this segment.
    pub venue: ObjectId,
    /// Instrument kinds admitted by this segment.
    pub product_kinds: BTreeSet<InstrumentKind>,
    /// Named source of the assertion record.
    pub source: String,
    /// Valid-time and knowledge-time interval.
    pub bitemporal: Bitemporal,
    /// Nonzero declaration revision.
    pub revision: u64,
}

impl SegmentAssertion {
    /// Validate the fields of this assertion without consulting other records.
    pub fn validate(&self) -> Result<(), RegistryError> {
        validate_record(&self.source, self.revision)
    }
}

/// Bitemporally scoped assertion describing one registered market product.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarketProductAssertion {
    /// Object described by this assertion.
    pub object: ObjectRef,
    /// Jurisdiction in which the product is registered.
    pub jurisdiction: JurisdictionCode,
    /// Segment that carries this product.
    pub segment: ObjectId,
    /// Taxonomy kind of the product.
    pub kind: InstrumentKind,
    /// Object class whose terms describe this product, when declared.
    pub terms_class: Option<ObjectClass>,
    /// Capability labels declared for this product.
    pub capabilities: BTreeSet<String>,
    /// Named source of the assertion record.
    pub source: String,
    /// Valid-time and knowledge-time interval.
    pub bitemporal: Bitemporal,
    /// Nonzero declaration revision.
    pub revision: u64,
}

impl MarketProductAssertion {
    /// Validate fields and the permitted terms classes.
    pub fn validate(&self) -> Result<(), RegistryError> {
        validate_record(&self.source, self.revision)?;
        if self
            .terms_class
            .is_some_and(|class| !permitted_terms_class(class))
        {
            return Err(RegistryError::ConflictingAssertion(
                self.object.id().to_string(),
            ));
        }
        if self.capabilities.iter().any(String::is_empty) {
            return Err(RegistryError::EmptyField("capabilities".to_owned()));
        }
        Ok(())
    }
}

/// Versioned jurisdiction data declared as records, not as Rust variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CountryPack {
    /// Jurisdiction covered by this pack.
    pub jurisdiction: JurisdictionCode,
    /// Positive version of this pack.
    pub version: u32,
    /// Timezone label declared by the pack.
    pub timezone: String,
    /// Settlement convention entries keyed by declared rule name.
    pub settlement_conventions: BTreeMap<String, String>,
    /// Calendar rule entries keyed by declared rule name.
    pub calendar_rules: BTreeMap<String, String>,
    /// Identifier scheme labels recorded by the pack.
    pub identifier_schemes: BTreeSet<String>,
    /// Regulatory source labels recorded by the pack.
    pub regulatory_sources: BTreeSet<String>,
    /// Corporate action type labels recorded by the pack.
    pub corporate_action_types: BTreeSet<String>,
}

impl CountryPack {
    /// Build a country pack and validate its version, timezone and entries.
    #[expect(
        clippy::too_many_arguments,
        reason = "a country pack declares eight stored fields in one constructor"
    )]
    pub fn new(
        jurisdiction: JurisdictionCode,
        version: u32,
        timezone: String,
        settlement_conventions: BTreeMap<String, String>,
        calendar_rules: BTreeMap<String, String>,
        identifier_schemes: BTreeSet<String>,
        regulatory_sources: BTreeSet<String>,
        corporate_action_types: BTreeSet<String>,
    ) -> Result<Self, RegistryError> {
        let pack = Self {
            jurisdiction,
            version,
            timezone,
            settlement_conventions,
            calendar_rules,
            identifier_schemes,
            regulatory_sources,
            corporate_action_types,
        };
        pack.validate()?;
        Ok(pack)
    }

    /// Validate the version, timezone and every declared text entry.
    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.version == 0 {
            return Err(RegistryError::InvalidRevision(u64::from(self.version)));
        }
        if self.timezone.is_empty() {
            return Err(RegistryError::EmptyField("timezone".to_owned()));
        }
        if self
            .settlement_conventions
            .iter()
            .any(|(key, value)| key.is_empty() || value.is_empty())
            || self
                .calendar_rules
                .iter()
                .any(|(key, value)| key.is_empty() || value.is_empty())
            || self.identifier_schemes.iter().any(String::is_empty)
            || self.regulatory_sources.iter().any(String::is_empty)
            || self.corporate_action_types.iter().any(String::is_empty)
        {
            return Err(RegistryError::EmptyField("country pack entry".to_owned()));
        }
        Ok(())
    }
}

/// Four-outcome result of a registry lookup with no first-row fallback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryResolution<T> {
    /// No registered record matched the lookup.
    Unresolved,
    /// One applicable record matched.
    Resolved(T),
    /// Two or more applicable records declared the same claim.
    Ambiguous,
    /// Two or more applicable records declared divergent claims.
    Conflict,
}

/// Fail-closed registry of country packs and jurisdiction-scoped assertions.
#[derive(Debug, Clone, Default)]
pub struct MarketRegistry {
    packs: BTreeMap<JurisdictionCode, CountryPack>,
    authorities: BTreeMap<ObjectId, Vec<AuthorityAssertion>>,
    venues: BTreeMap<ObjectId, Vec<VenueAssertion>>,
    segments: BTreeMap<ObjectId, Vec<SegmentAssertion>>,
    products: BTreeMap<ObjectId, Vec<MarketProductAssertion>>,
}

impl MarketRegistry {
    /// Create an empty registry. An empty registry covers no jurisdiction.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a country pack, admitting only a version above the stored one.
    pub fn insert_pack(&mut self, pack: CountryPack) -> Result<(), RegistryError> {
        pack.validate()?;
        if let Some(existing) = self.packs.get(&pack.jurisdiction)
            && existing.version >= pack.version
        {
            return Err(RegistryError::VersionMismatch(
                pack.jurisdiction.to_string(),
            ));
        }
        self.packs.insert(pack.jurisdiction.clone(), pack);
        Ok(())
    }

    /// Register an authority after checking its parent reference.
    pub fn insert_authority(&mut self, assertion: AuthorityAssertion) -> Result<(), RegistryError> {
        assertion.validate()?;
        if let Some(parent) = &assertion.parent {
            let Some(records) = self.authorities.get(parent) else {
                return Err(RegistryError::UnknownReference(parent.to_string()));
            };
            if !records
                .iter()
                .any(|record| record.jurisdiction == assertion.jurisdiction)
            {
                return Err(RegistryError::JurisdictionMismatch(parent.to_string()));
            }
        }
        let id = assertion.object.id().clone();
        let revision = assertion.revision;
        if self
            .authorities
            .get(&id)
            .is_some_and(|records| records.iter().any(|record| record.revision == revision))
        {
            return Err(RegistryError::DuplicateObject(format!(
                "{id} revision {revision}"
            )));
        }
        self.authorities.entry(id).or_default().push(assertion);
        Ok(())
    }

    /// Register a venue after checking its operator reference.
    pub fn insert_venue(&mut self, assertion: VenueAssertion) -> Result<(), RegistryError> {
        assertion.validate()?;
        let Some(records) = self.authorities.get(&assertion.operator) else {
            return Err(RegistryError::UnknownReference(
                assertion.operator.to_string(),
            ));
        };
        if !records
            .iter()
            .any(|record| record.jurisdiction == assertion.jurisdiction)
        {
            return Err(RegistryError::JurisdictionMismatch(
                assertion.operator.to_string(),
            ));
        }
        let id = assertion.object.id().clone();
        let revision = assertion.revision;
        if self
            .venues
            .get(&id)
            .is_some_and(|records| records.iter().any(|record| record.revision == revision))
        {
            return Err(RegistryError::DuplicateObject(format!(
                "{id} revision {revision}"
            )));
        }
        self.venues.entry(id).or_default().push(assertion);
        Ok(())
    }

    /// Register a segment after checking its venue reference.
    pub fn insert_segment(&mut self, assertion: SegmentAssertion) -> Result<(), RegistryError> {
        assertion.validate()?;
        let Some(records) = self.venues.get(&assertion.venue) else {
            return Err(RegistryError::UnknownReference(assertion.venue.to_string()));
        };
        if !records
            .iter()
            .any(|record| record.jurisdiction == assertion.jurisdiction)
        {
            return Err(RegistryError::JurisdictionMismatch(
                assertion.venue.to_string(),
            ));
        }
        let id = assertion.object.id().clone();
        let revision = assertion.revision;
        if self
            .segments
            .get(&id)
            .is_some_and(|records| records.iter().any(|record| record.revision == revision))
        {
            return Err(RegistryError::DuplicateObject(format!(
                "{id} revision {revision}"
            )));
        }
        self.segments.entry(id).or_default().push(assertion);
        Ok(())
    }

    /// Register a product after checking its segment and admitted kinds.
    pub fn insert_product(
        &mut self,
        assertion: MarketProductAssertion,
    ) -> Result<(), RegistryError> {
        assertion.validate()?;
        let Some(records) = self.segments.get(&assertion.segment) else {
            return Err(RegistryError::UnknownReference(
                assertion.segment.to_string(),
            ));
        };
        if !records
            .iter()
            .any(|record| record.jurisdiction == assertion.jurisdiction)
        {
            return Err(RegistryError::JurisdictionMismatch(
                assertion.segment.to_string(),
            ));
        }
        if !records
            .iter()
            .any(|record| record.product_kinds.contains(&assertion.kind))
        {
            return Err(RegistryError::ConflictingAssertion(
                assertion.segment.to_string(),
            ));
        }
        let id = assertion.object.id().clone();
        let revision = assertion.revision;
        if self
            .products
            .get(&id)
            .is_some_and(|records| records.iter().any(|record| record.revision == revision))
        {
            return Err(RegistryError::DuplicateObject(format!(
                "{id} revision {revision}"
            )));
        }
        self.products.entry(id).or_default().push(assertion);
        Ok(())
    }

    /// Resolve one venue identity at explicit valid and knowledge times.
    pub fn resolve_venue(
        &self,
        id: &ObjectId,
        valid_us: i64,
        knowledge_us: i64,
    ) -> RegistryResolution<VenueAssertion> {
        let Some(records) = self.venues.get(id) else {
            return RegistryResolution::Unresolved;
        };
        let applicable: Vec<&VenueAssertion> = records
            .iter()
            .filter(|record| record.bitemporal.as_of(valid_us, knowledge_us))
            .collect();
        match applicable.as_slice() {
            [] => RegistryResolution::Unresolved,
            [only] => RegistryResolution::Resolved((*only).clone()),
            [first, remainder @ ..] => {
                let agrees = remainder
                    .iter()
                    .all(|record| Self::venue_claims_agree(first, record));
                if agrees {
                    RegistryResolution::Ambiguous
                } else {
                    RegistryResolution::Conflict
                }
            }
        }
    }

    /// Resolve one product identity at explicit valid and knowledge times.
    pub fn resolve_product(
        &self,
        id: &ObjectId,
        valid_us: i64,
        knowledge_us: i64,
    ) -> RegistryResolution<MarketProductAssertion> {
        let Some(records) = self.products.get(id) else {
            return RegistryResolution::Unresolved;
        };
        let applicable: Vec<&MarketProductAssertion> = records
            .iter()
            .filter(|record| record.bitemporal.as_of(valid_us, knowledge_us))
            .collect();
        match applicable.as_slice() {
            [] => RegistryResolution::Unresolved,
            [only] => RegistryResolution::Resolved((*only).clone()),
            [first, remainder @ ..] => {
                let agrees = remainder
                    .iter()
                    .all(|record| Self::product_claims_agree(first, record));
                if agrees {
                    RegistryResolution::Ambiguous
                } else {
                    RegistryResolution::Conflict
                }
            }
        }
    }

    /// Read the stored country pack for a jurisdiction.
    pub fn pack(&self, jurisdiction: &JurisdictionCode) -> RegistryResolution<CountryPack> {
        match self.packs.get(jurisdiction) {
            Some(pack) => RegistryResolution::Resolved(pack.clone()),
            None => RegistryResolution::Unresolved,
        }
    }

    /// Read a country pack as a typed error, failing when none is registered.
    pub fn require_pack(
        &self,
        jurisdiction: &JurisdictionCode,
    ) -> Result<&CountryPack, RegistryError> {
        self.packs
            .get(jurisdiction)
            .ok_or_else(|| RegistryError::UnknownPack(jurisdiction.to_string()))
    }

    /// Return product assertions whose segment names this venue.
    pub fn products_for(&self, venue: &ObjectId) -> Vec<MarketProductAssertion> {
        let segments: BTreeSet<&ObjectId> = self
            .segments
            .iter()
            .filter(|(_, records)| records.iter().any(|record| record.venue == *venue))
            .map(|(id, _)| id)
            .collect();
        let mut matches: Vec<MarketProductAssertion> = self
            .products
            .values()
            .flatten()
            .filter(|product| segments.contains(&product.segment))
            .cloned()
            .collect();
        matches.sort_by(|left, right| {
            left.object
                .id()
                .cmp(right.object.id())
                .then(left.revision.cmp(&right.revision))
        });
        matches
    }

    fn venue_claims_agree(left: &VenueAssertion, right: &VenueAssertion) -> bool {
        left.jurisdiction == right.jurisdiction
            && left.operator == right.operator
            && left.mic == right.mic
            && left.category == right.category
            && left.segments == right.segments
    }

    fn product_claims_agree(left: &MarketProductAssertion, right: &MarketProductAssertion) -> bool {
        left.jurisdiction == right.jurisdiction
            && left.segment == right.segment
            && left.kind == right.kind
            && left.terms_class == right.terms_class
            && left.capabilities == right.capabilities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(value: &str) -> JurisdictionCode {
        JurisdictionCode::new(value).expect("jurisdiction code")
    }

    fn oid(class: ObjectClass, key: &str) -> ObjectId {
        ObjectId::derive(class, "namespace-a", "authority-a", key).expect("object id")
    }

    fn oref(class: ObjectClass, key: &str) -> ObjectRef {
        ObjectRef {
            class,
            id: oid(class, key),
        }
    }

    fn pack(jurisdiction: &JurisdictionCode, version: u32) -> CountryPack {
        CountryPack::new(
            jurisdiction.clone(),
            version,
            "zone-a".to_owned(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .expect("country pack")
    }

    fn authority(key: &str, jurisdiction: &JurisdictionCode, revision: u64) -> AuthorityAssertion {
        AuthorityAssertion {
            object: oref(ObjectClass::Authority, key),
            jurisdiction: jurisdiction.clone(),
            kind: AuthorityKind::ExchangeOperator,
            parent: None,
            source: "source-a".to_owned(),
            bitemporal: Bitemporal::new(10, 20),
            revision,
        }
    }

    fn venue(
        key: &str,
        jurisdiction: &JurisdictionCode,
        operator: &ObjectId,
        revision: u64,
    ) -> VenueAssertion {
        VenueAssertion {
            object: oref(ObjectClass::Venue, key),
            jurisdiction: jurisdiction.clone(),
            operator: operator.clone(),
            mic: None,
            category: VenueCategory::Exchange,
            segments: BTreeSet::new(),
            source: "source-a".to_owned(),
            bitemporal: Bitemporal::new(10, 20),
            revision,
        }
    }

    fn segment(
        key: &str,
        jurisdiction: &JurisdictionCode,
        venue_id: &ObjectId,
        kinds: &[InstrumentKind],
    ) -> SegmentAssertion {
        SegmentAssertion {
            object: oref(ObjectClass::Segment, key),
            jurisdiction: jurisdiction.clone(),
            venue: venue_id.clone(),
            product_kinds: kinds.iter().copied().collect(),
            source: "source-a".to_owned(),
            bitemporal: Bitemporal::new(10, 20),
            revision: 1,
        }
    }

    fn product(
        key: &str,
        jurisdiction: &JurisdictionCode,
        segment_id: &ObjectId,
        kind: InstrumentKind,
    ) -> MarketProductAssertion {
        MarketProductAssertion {
            object: oref(ObjectClass::MarketProduct, key),
            jurisdiction: jurisdiction.clone(),
            segment: segment_id.clone(),
            kind,
            terms_class: Some(ObjectClass::Security),
            capabilities: BTreeSet::from(["capability-a".to_owned()]),
            source: "source-a".to_owned(),
            bitemporal: Bitemporal::new(10, 20),
            revision: 1,
        }
    }

    fn seeded(jurisdiction: &str, key: &str) -> (MarketRegistry, ObjectId, ObjectId, ObjectId) {
        let code = code(jurisdiction);
        let mut registry = MarketRegistry::new();
        registry.insert_pack(pack(&code, 1)).expect("country pack");
        let authority = authority(key, &code, 1);
        let authority_id = authority.object.id().clone();
        registry.insert_authority(authority).expect("authority");
        let venue = venue(key, &code, &authority_id, 1);
        let venue_id = venue.object.id().clone();
        registry.insert_venue(venue).expect("venue");
        let segment = segment(key, &code, &venue_id, &[InstrumentKind::CommonShare]);
        let segment_id = segment.object.id().clone();
        registry.insert_segment(segment).expect("segment");
        (registry, authority_id, venue_id, segment_id)
    }

    #[test]
    fn arbitrary_jurisdiction_codes_are_accepted() {
        assert_eq!(code("XX").as_str(), "XX", "two-letter code is accepted");
        assert_eq!(code("YY").as_str(), "YY", "another territory is accepted");
        assert_eq!(
            code("ABC-12").as_str(),
            "ABC-12",
            "digits and hyphen are accepted"
        );
        assert_eq!(
            code("12345678").as_str(),
            "12345678",
            "eight characters are accepted"
        );
    }

    #[test]
    fn malformed_jurisdiction_codes_are_rejected() {
        for value in ["", "X", "ABCDEFGHI", "xx", "XX Y", "XX_1", "XX/1"] {
            assert!(
                matches!(
                    JurisdictionCode::new(value),
                    Err(RegistryError::InvalidJurisdictionCode(_))
                ),
                "malformed code {value:?} must be rejected"
            );
        }
    }

    #[test]
    fn authority_kind_strings_are_stable() {
        let kinds = [
            (AuthorityKind::Regulator, "regulator"),
            (AuthorityKind::ExchangeOperator, "exchange_operator"),
            (AuthorityKind::ClearingCorporation, "clearing_corporation"),
            (AuthorityKind::Depository, "depository"),
            (
                AuthorityKind::BenchmarkAdministrator,
                "benchmark_administrator",
            ),
            (AuthorityKind::Other("role-a".to_owned()), "role-a"),
        ];
        for (kind, expected) in kinds {
            assert_eq!(kind.as_str(), expected, "authority role string is stable");
        }
    }

    #[test]
    fn duplicate_object_revision_is_rejected() {
        let jurisdiction = code("XX");
        let mut registry = MarketRegistry::new();
        registry
            .insert_authority(authority("key-a", &jurisdiction, 1))
            .expect("first authority");
        assert!(
            matches!(
                registry.insert_authority(authority("key-a", &jurisdiction, 1)),
                Err(RegistryError::DuplicateObject(_))
            ),
            "a repeated identity and revision must be rejected"
        );
    }

    #[test]
    fn unknown_parent_authority_is_rejected() {
        let jurisdiction = code("XX");
        let mut assertion = authority("key-a", &jurisdiction, 1);
        assertion.parent = Some(oid(ObjectClass::Authority, "key-missing"));
        let mut registry = MarketRegistry::new();
        assert!(
            matches!(
                registry.insert_authority(assertion),
                Err(RegistryError::UnknownReference(_))
            ),
            "an unregistered parent must fail closed"
        );
    }

    #[test]
    fn cross_jurisdiction_parent_is_rejected() {
        let first = code("XX");
        let second = code("YY");
        let mut registry = MarketRegistry::new();
        registry
            .insert_authority(authority("key-a", &first, 1))
            .expect("first authority");
        let mut child = authority("key-b", &second, 1);
        child.parent = Some(oid(ObjectClass::Authority, "key-a"));
        assert!(
            matches!(
                registry.insert_authority(child),
                Err(RegistryError::JurisdictionMismatch(_))
            ),
            "a parent in another jurisdiction must be rejected"
        );
    }

    #[test]
    fn empty_source_and_zero_revision_are_rejected() {
        let jurisdiction = code("XX");
        let mut assertion = authority("key-a", &jurisdiction, 1);
        assertion.source.clear();
        assert!(
            matches!(assertion.validate(), Err(RegistryError::EmptyField(_))),
            "an empty source must be rejected"
        );
        assertion.source = "source-a".to_owned();
        assertion.revision = 0;
        assert!(
            matches!(assertion.validate(), Err(RegistryError::InvalidRevision(0))),
            "a zero revision must be rejected"
        );
    }

    #[test]
    fn unknown_venue_operator_is_rejected() {
        let jurisdiction = code("XX");
        let mut registry = MarketRegistry::new();
        let assertion = venue(
            "key-v",
            &jurisdiction,
            &oid(ObjectClass::Authority, "key-missing"),
            1,
        );
        assert!(
            matches!(
                registry.insert_venue(assertion),
                Err(RegistryError::UnknownReference(_))
            ),
            "an unregistered operator must fail closed"
        );
    }

    #[test]
    fn cross_jurisdiction_operator_is_rejected() {
        let first = code("XX");
        let second = code("YY");
        let mut registry = MarketRegistry::new();
        registry
            .insert_authority(authority("key-a", &first, 1))
            .expect("authority");
        let assertion = venue("key-v", &second, &oid(ObjectClass::Authority, "key-a"), 1);
        assert!(
            matches!(
                registry.insert_venue(assertion),
                Err(RegistryError::JurisdictionMismatch(_))
            ),
            "an operator in another jurisdiction must be rejected"
        );
    }

    #[test]
    fn unknown_segment_venue_is_rejected() {
        let jurisdiction = code("XX");
        let mut registry = MarketRegistry::new();
        let assertion = segment(
            "key-s",
            &jurisdiction,
            &oid(ObjectClass::Venue, "key-missing"),
            &[InstrumentKind::Future],
        );
        assert!(
            matches!(
                registry.insert_segment(assertion),
                Err(RegistryError::UnknownReference(_))
            ),
            "an unregistered venue must fail closed"
        );
    }

    #[test]
    fn cross_jurisdiction_segment_venue_is_rejected() {
        let (mut registry, _, venue_id, _) = seeded("XX", "key-a");
        let other = code("YY");
        let assertion = segment("key-s", &other, &venue_id, &[InstrumentKind::Future]);
        assert!(
            matches!(
                registry.insert_segment(assertion),
                Err(RegistryError::JurisdictionMismatch(_))
            ),
            "a venue in another jurisdiction must be rejected"
        );
    }

    #[test]
    fn unknown_product_segment_is_rejected() {
        let jurisdiction = code("XX");
        let mut registry = MarketRegistry::new();
        let assertion = product(
            "key-p",
            &jurisdiction,
            &oid(ObjectClass::Segment, "key-missing"),
            InstrumentKind::CommonShare,
        );
        assert!(
            matches!(
                registry.insert_product(assertion),
                Err(RegistryError::UnknownReference(_))
            ),
            "an unregistered segment must fail closed"
        );
    }

    #[test]
    fn cross_jurisdiction_product_segment_is_rejected() {
        let (mut registry, _, _, segment_id) = seeded("XX", "key-a");
        let other = code("YY");
        let assertion = product("key-p", &other, &segment_id, InstrumentKind::CommonShare);
        assert!(
            matches!(
                registry.insert_product(assertion),
                Err(RegistryError::JurisdictionMismatch(_))
            ),
            "a segment in another jurisdiction must be rejected"
        );
    }

    #[test]
    fn segment_product_kinds_are_validated() {
        let (mut registry, _, _, segment_id) = seeded("XX", "key-a");
        let jurisdiction = code("XX");
        let admitted = product(
            "key-p-a",
            &jurisdiction,
            &segment_id,
            InstrumentKind::CommonShare,
        );
        registry
            .insert_product(admitted)
            .expect("admitted product kind");
        let rejected = product(
            "key-p-b",
            &jurisdiction,
            &segment_id,
            InstrumentKind::Future,
        );
        assert!(
            matches!(
                registry.insert_product(rejected),
                Err(RegistryError::ConflictingAssertion(_))
            ),
            "a kind outside the segment declaration must be rejected"
        );
        let empty = segment(
            "key-s-b",
            &jurisdiction,
            &oid(ObjectClass::Venue, "key-a"),
            &[],
        );
        registry
            .insert_segment(empty)
            .expect("segment with no kinds");
        let any_kind = product(
            "key-p-c",
            &jurisdiction,
            &oid(ObjectClass::Segment, "key-s-b"),
            InstrumentKind::CommonShare,
        );
        assert!(
            matches!(
                registry.insert_product(any_kind),
                Err(RegistryError::ConflictingAssertion(_))
            ),
            "a segment with no declared kinds admits no product"
        );
    }

    #[test]
    fn product_terms_class_is_restricted() {
        let jurisdiction = code("XX");
        let mut assertion = product(
            "key-p",
            &jurisdiction,
            &oid(ObjectClass::Segment, "key-s"),
            InstrumentKind::CommonShare,
        );
        assertion.terms_class = Some(ObjectClass::Security);
        assert!(
            assertion.validate().is_ok(),
            "security terms class is admitted"
        );
        for class in [
            ObjectClass::Venue,
            ObjectClass::MarketProduct,
            ObjectClass::IdentifierAssertion,
        ] {
            assertion.terms_class = Some(class);
            assert!(
                matches!(
                    assertion.validate(),
                    Err(RegistryError::ConflictingAssertion(_))
                ),
                "class {class} must be rejected as a terms class"
            );
        }
        assertion.terms_class = None;
        assert!(
            assertion.validate().is_ok(),
            "an absent terms class is admitted"
        );
    }

    #[test]
    fn version_zero_and_empty_timezone_are_rejected() {
        let jurisdiction = code("XX");
        let mut pack = pack(&jurisdiction, 1);
        pack.version = 0;
        assert!(
            matches!(pack.validate(), Err(RegistryError::InvalidRevision(0))),
            "a zero pack version must be rejected"
        );
        pack.version = 1;
        pack.timezone.clear();
        assert!(
            matches!(pack.validate(), Err(RegistryError::EmptyField(_))),
            "an empty timezone must be rejected"
        );
    }

    #[test]
    fn pack_update_with_new_version_is_accepted() {
        let jurisdiction = code("XX");
        let mut registry = MarketRegistry::new();
        registry
            .insert_pack(pack(&jurisdiction, 1))
            .expect("version one");
        registry
            .insert_pack(pack(&jurisdiction, 2))
            .expect("version two");
        assert_eq!(
            registry.pack(&jurisdiction),
            RegistryResolution::Resolved(pack(&jurisdiction, 2)),
            "the registered higher version is returned"
        );
        assert!(
            matches!(
                registry.insert_pack(pack(&jurisdiction, 2)),
                Err(RegistryError::VersionMismatch(_))
            ),
            "an equal pack version must be rejected"
        );
        assert!(
            matches!(
                registry.insert_pack(pack(&jurisdiction, 1)),
                Err(RegistryError::VersionMismatch(_))
            ),
            "a lower pack version must be rejected"
        );
    }

    #[test]
    fn unknown_pack_returns_unresolved() {
        let registry = MarketRegistry::new();
        let jurisdiction = code("ZZ");
        assert_eq!(
            registry.pack(&jurisdiction),
            RegistryResolution::Unresolved,
            "an unregistered jurisdiction has no pack"
        );
        assert!(
            matches!(
                registry.require_pack(&jurisdiction),
                Err(RegistryError::UnknownPack(_))
            ),
            "a typed pack lookup fails closed"
        );
    }

    #[test]
    fn venue_resolution_has_four_outcomes() {
        let jurisdiction = code("XX");
        let (mut registry, authority_id, venue_id, _) = seeded("XX", "key-a");
        let missing = oid(ObjectClass::Venue, "key-missing");
        assert_eq!(
            registry.resolve_venue(&missing, 15, 25),
            RegistryResolution::Unresolved,
            "an unregistered venue is unresolved"
        );
        let expected = venue("key-a", &jurisdiction, &authority_id, 1);
        assert_eq!(
            registry.resolve_venue(&venue_id, 15, 25),
            RegistryResolution::Resolved(expected),
            "one applicable assertion resolves"
        );
        let mut agreeing = venue("key-a", &jurisdiction, &authority_id, 2);
        agreeing.source = "source-b".to_owned();
        registry.insert_venue(agreeing).expect("agreeing revision");
        assert_eq!(
            registry.resolve_venue(&venue_id, 15, 25),
            RegistryResolution::Ambiguous,
            "two sources declaring one claim stay ambiguous"
        );
        let mut divergent = venue("key-a", &jurisdiction, &authority_id, 3);
        divergent.category = VenueCategory::DarkPool;
        registry
            .insert_venue(divergent)
            .expect("divergent revision");
        assert_eq!(
            registry.resolve_venue(&venue_id, 15, 25),
            RegistryResolution::Conflict,
            "divergent claims produce a conflict outcome"
        );
    }

    #[test]
    fn product_resolution_has_four_outcomes() {
        let jurisdiction = code("XX");
        let (mut registry, _, _, segment_id) = seeded("XX", "key-a");
        let expected = product(
            "key-p",
            &jurisdiction,
            &segment_id,
            InstrumentKind::CommonShare,
        );
        registry
            .insert_product(expected.clone())
            .expect("first product");
        let product_id = expected.object.id().clone();
        let missing = oid(ObjectClass::MarketProduct, "key-missing");
        assert_eq!(
            registry.resolve_product(&missing, 15, 25),
            RegistryResolution::Unresolved,
            "an unregistered product is unresolved"
        );
        assert_eq!(
            registry.resolve_product(&product_id, 15, 25),
            RegistryResolution::Resolved(expected),
            "one applicable product assertion resolves"
        );
        let mut agreeing = product(
            "key-p",
            &jurisdiction,
            &segment_id,
            InstrumentKind::CommonShare,
        );
        agreeing.revision = 2;
        agreeing.source = "source-b".to_owned();
        registry
            .insert_product(agreeing)
            .expect("agreeing revision");
        assert_eq!(
            registry.resolve_product(&product_id, 15, 25),
            RegistryResolution::Ambiguous,
            "two sources declaring one product claim stay ambiguous"
        );
        let mut divergent = product(
            "key-p",
            &jurisdiction,
            &segment_id,
            InstrumentKind::CommonShare,
        );
        divergent.revision = 3;
        divergent.terms_class = None;
        registry
            .insert_product(divergent)
            .expect("divergent revision");
        assert_eq!(
            registry.resolve_product(&product_id, 15, 25),
            RegistryResolution::Conflict,
            "divergent product claims produce a conflict outcome"
        );
    }

    #[test]
    fn products_for_matches_exact_segments() {
        let first = code("XX");
        let second = code("YY");
        let (mut registry, _, first_venue, first_segment) = seeded("XX", "key-a");
        let second_authority = authority("key-b", &second, 1);
        let second_authority_id = second_authority.object.id().clone();
        registry
            .insert_authority(second_authority)
            .expect("second authority");
        let second_venue = venue("key-b", &second, &second_authority_id, 1);
        let second_venue_id = second_venue.object.id().clone();
        registry.insert_venue(second_venue).expect("second venue");
        let second_segment = segment(
            "key-b",
            &second,
            &second_venue_id,
            &[InstrumentKind::CommonShare],
        );
        let second_segment_id = second_segment.object.id().clone();
        registry
            .insert_segment(second_segment)
            .expect("second segment");
        let first_product = product(
            "key-p-a",
            &first,
            &first_segment,
            InstrumentKind::CommonShare,
        );
        let second_product = product(
            "key-p-b",
            &second,
            &second_segment_id,
            InstrumentKind::CommonShare,
        );
        registry
            .insert_product(first_product.clone())
            .expect("first product");
        registry
            .insert_product(second_product.clone())
            .expect("second product");
        assert_eq!(
            registry.products_for(&first_venue),
            vec![first_product],
            "only products of segments under this venue are returned"
        );
        assert_eq!(
            registry.products_for(&second_venue_id),
            vec![second_product],
            "the other venue returns its own product"
        );
        assert!(
            registry
                .products_for(&oid(ObjectClass::Venue, "key-missing"))
                .is_empty(),
            "an unregistered venue returns no products"
        );
    }

    #[test]
    fn two_fictional_jurisdictions_coexist() {
        let first = code("XX");
        let second = code("YY");
        let (mut registry, _, first_venue, first_segment) = seeded("XX", "key-a");
        registry
            .insert_pack(pack(&second, 1))
            .expect("second country pack");
        let second_authority = authority("key-b", &second, 1);
        let second_authority_id = second_authority.object.id().clone();
        registry
            .insert_authority(second_authority)
            .expect("second authority");
        let second_venue = venue("key-b", &second, &second_authority_id, 1);
        let second_venue_id = second_venue.object.id().clone();
        registry.insert_venue(second_venue).expect("second venue");
        let second_segment = segment(
            "key-b",
            &second,
            &second_venue_id,
            &[InstrumentKind::CommonShare],
        );
        registry
            .insert_segment(second_segment)
            .expect("second segment");
        registry
            .insert_product(product(
                "key-p-a",
                &first,
                &first_segment,
                InstrumentKind::CommonShare,
            ))
            .expect("first product");
        registry
            .insert_product(product(
                "key-p-b",
                &second,
                &oid(ObjectClass::Segment, "key-b"),
                InstrumentKind::CommonShare,
            ))
            .expect("second product");
        assert_eq!(
            registry.pack(&first),
            RegistryResolution::Resolved(pack(&first, 1)),
            "the first jurisdiction retains its pack"
        );
        assert_eq!(
            registry.pack(&second),
            RegistryResolution::Resolved(pack(&second, 1)),
            "the second jurisdiction retains its pack"
        );
        assert!(
            matches!(
                registry.resolve_venue(&first_venue, 15, 25),
                RegistryResolution::Resolved(_)
            ),
            "the first jurisdiction venue resolves"
        );
        assert!(
            matches!(
                registry.resolve_venue(&second_venue_id, 15, 25),
                RegistryResolution::Resolved(_)
            ),
            "the second jurisdiction venue resolves"
        );
    }

    #[test]
    fn empty_registry_covers_nothing() {
        let registry = MarketRegistry::new();
        let jurisdiction = code("XX");
        let id = oid(ObjectClass::Venue, "key-a");
        assert_eq!(
            registry.resolve_venue(&id, 15, 25),
            RegistryResolution::Unresolved,
            "an empty registry has no venue"
        );
        assert_eq!(
            registry.resolve_product(&id, 15, 25),
            RegistryResolution::Unresolved,
            "an empty registry has no product"
        );
        assert_eq!(
            registry.pack(&jurisdiction),
            RegistryResolution::Unresolved,
            "an empty registry has no pack"
        );
        assert!(
            registry.products_for(&id).is_empty(),
            "an empty registry has no products for any venue"
        );
    }

    #[test]
    fn bitemporal_intervals_govern_resolution_at_recorded_times() {
        let jurisdiction = code("XX");
        let mut registry = MarketRegistry::new();
        registry
            .insert_authority(authority("key-a", &jurisdiction, 1))
            .expect("authority");
        let authority_id = oid(ObjectClass::Authority, "key-a");
        let mut assertion = venue("key-a", &jurisdiction, &authority_id, 1);
        assertion.bitemporal = Bitemporal {
            valid_from_us: 100,
            valid_to_us: Some(200),
            transaction_from_us: 50,
            transaction_to_us: Some(150),
        };
        let venue_id = assertion.object.id().clone();
        registry.insert_venue(assertion.clone()).expect("venue");
        assert_eq!(
            registry.resolve_venue(&venue_id, 150, 100),
            RegistryResolution::Resolved(assertion),
            "an interior valid and knowledge instant resolves"
        );
        assert_eq!(
            registry.resolve_venue(&venue_id, 250, 100),
            RegistryResolution::Unresolved,
            "an expired valid interval is unresolved"
        );
        assert_eq!(
            registry.resolve_venue(&venue_id, 150, 200),
            RegistryResolution::Unresolved,
            "an expired knowledge interval is unresolved"
        );
    }

    #[test]
    fn non_overlapping_revisions_resolve_at_their_own_knowledge_times() {
        let jurisdiction = code("XX");
        let mut registry = MarketRegistry::new();
        registry
            .insert_authority(authority("key-a", &jurisdiction, 1))
            .expect("authority");
        let authority_id = oid(ObjectClass::Authority, "key-a");
        let mut first = venue("key-a", &jurisdiction, &authority_id, 1);
        first.bitemporal = Bitemporal {
            valid_from_us: 10,
            valid_to_us: None,
            transaction_from_us: 20,
            transaction_to_us: Some(40),
        };
        let mut second = venue("key-a", &jurisdiction, &authority_id, 2);
        second.bitemporal = Bitemporal {
            valid_from_us: 10,
            valid_to_us: None,
            transaction_from_us: 40,
            transaction_to_us: None,
        };
        second.mic = Some("mic-b".to_owned());
        let venue_id = first.object.id().clone();
        registry
            .insert_venue(first.clone())
            .expect("first revision");
        registry
            .insert_venue(second.clone())
            .expect("second revision");
        assert_eq!(
            registry.resolve_venue(&venue_id, 15, 30),
            RegistryResolution::Resolved(first),
            "the earlier knowledge instant resolves the first revision"
        );
        assert_eq!(
            registry.resolve_venue(&venue_id, 15, 50),
            RegistryResolution::Resolved(second),
            "the newer knowledge instant resolves the second revision"
        );
    }

    #[test]
    fn venue_assertion_round_trips_through_serde() {
        let jurisdiction = code("XX");
        let mut assertion = venue(
            "key-a",
            &jurisdiction,
            &oid(ObjectClass::Authority, "key-a"),
            1,
        );
        assertion.mic = Some("mic-a".to_owned());
        assertion
            .segments
            .insert(oid(ObjectClass::Segment, "key-s"));
        let text = serde_json::to_string(&assertion).expect("serialize venue assertion");
        let decoded: VenueAssertion =
            serde_json::from_str(&text).expect("deserialize venue assertion");
        assert_eq!(decoded, assertion, "the assertion round-trips exactly");
    }
}
