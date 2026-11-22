// SPDX-License-Identifier: Apache-2.0
//! Machine-readable data rights and entitlement decisions.
//!
//! Authorization is scoped to a provider, a source product, a territory, a
//! recipient class, a purpose, a usage right and an effective interval. A
//! dataset name alone never carries permission. Access to a feed does not
//! grant storage, derived-data use or redistribution rights.
//!
//! Every decision is recorded with its licence reference, document digest,
//! contract revision and recording time. Ambiguous, conflicting or revoked
//! authorizations fail closed.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde::Serialize;

use crate::taxonomy::CountryCode;

/// Right being exercised over a dataset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageRight {
    RealTimeAccess,
    HistoricalStorage,
    InternalProcessing,
    DerivedData,
    Redistribution,
    Display,
    NonDisplay,
}

impl UsageRight {
    /// Return the stable contract string for this right.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RealTimeAccess => "real_time_access",
            Self::HistoricalStorage => "historical_storage",
            Self::InternalProcessing => "internal_processing",
            Self::DerivedData => "derived_data",
            Self::Redistribution => "redistribution",
            Self::Display => "display",
            Self::NonDisplay => "non_display",
        }
    }

    /// Whether this right is a retention or onward-use right that public
    /// access cannot imply.
    #[must_use]
    pub const fn requires_explicit_grant(self) -> bool {
        matches!(
            self,
            Self::HistoricalStorage | Self::DerivedData | Self::Redistribution
        )
    }
}

/// Class of recipient exercising a right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientClass {
    Public,
    Internal,
    Participant,
    Customer,
    Affiliate,
}

impl RecipientClass {
    /// Return the stable contract string for this recipient class.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Internal => "internal",
            Self::Participant => "participant",
            Self::Customer => "customer",
            Self::Affiliate => "affiliate",
        }
    }
}

/// Purpose for which a right is exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    InternalAnalysis,
    Display,
    Redistribution,
    DerivedProduct,
    HistoricalArchive,
    Compliance,
}

impl Purpose {
    /// Return the stable contract string for this purpose.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InternalAnalysis => "internal_analysis",
            Self::Display => "display",
            Self::Redistribution => "redistribution",
            Self::DerivedProduct => "derived_product",
            Self::HistoricalArchive => "historical_archive",
            Self::Compliance => "compliance",
        }
    }
}

/// Decision recorded for one right.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RightDecision {
    Permitted,
    Prohibited,
    ContractRequired,
    Unknown,
    Revoked,
}

impl RightDecision {
    /// Return the stable contract string for this decision.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permitted => "permitted",
            Self::Prohibited => "prohibited",
            Self::ContractRequired => "contract_required",
            Self::Unknown => "unknown",
            Self::Revoked => "revoked",
        }
    }
}

/// Dimensions that identify one authorization request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationQuery {
    pub provider_id: String,
    pub source_id: String,
    pub dataset_id: String,
    pub product_id: String,
    pub territory: CountryCode,
    pub usage_right: UsageRight,
    pub recipient_class: RecipientClass,
    pub purpose: Purpose,
}

impl AuthorizationQuery {
    /// Reject a query with an incomplete identity.
    pub fn validate(&self) -> Result<(), RightsError> {
        if self.provider_id.trim().is_empty()
            || self.source_id.trim().is_empty()
            || self.dataset_id.trim().is_empty()
            || self.product_id.trim().is_empty()
        {
            return Err(RightsError::InvalidQuery);
        }
        Ok(())
    }
}

/// Effective interval and scope of one recorded decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationIdentity {
    pub provider_id: String,
    pub source_id: String,
    pub dataset_id: String,
    pub product_id: String,
    pub territory: CountryCode,
    pub usage_right: UsageRight,
    pub recipient_class: RecipientClass,
    pub purpose: Purpose,
    /// First instant at which the decision is effective.
    pub valid_from: i64,
    /// Last effective instant; open when absent.
    pub valid_until: Option<i64>,
}

impl AuthorizationIdentity {
    /// Whether this record applies to a query at `at_us`.
    #[must_use]
    pub fn matches(&self, query: &AuthorizationQuery, at_us: i64) -> bool {
        self.provider_id == query.provider_id
            && self.source_id == query.source_id
            && self.dataset_id == query.dataset_id
            && self.product_id == query.product_id
            && self.territory == query.territory
            && self.usage_right == query.usage_right
            && self.recipient_class == query.recipient_class
            && self.purpose == query.purpose
            && self.valid_from <= at_us
            && self.valid_until.is_none_or(|end| at_us <= end)
    }

    /// Stable key for conflict detection. The interval is excluded so two
    /// revisions of the same authorization cannot coexist unnoticed.
    #[must_use]
    pub fn decision_key(&self) -> (String, String, String, String, String, u8, u8, u8) {
        (
            self.provider_id.clone(),
            self.source_id.clone(),
            self.dataset_id.clone(),
            self.product_id.clone(),
            self.territory.as_str().to_owned(),
            self.usage_right as u8,
            self.recipient_class as u8,
            self.purpose as u8,
        )
    }
}

/// Audit record attached to one decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionAudit {
    pub licence_reference: String,
    pub licence_document_hash: String,
    pub contract_revision: u32,
    pub recorded_at_us: i64,
    pub authority: String,
}

/// One contract-derived authorization record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRecord {
    pub identity: AuthorizationIdentity,
    pub audit: DecisionAudit,
    /// Decision for the identity above, recorded in `audit`.
    pub decision: RightDecision,
}

impl AuthorizationRecord {
    /// Whether this record grants the right it names at `at_us`.
    #[must_use]
    pub fn grants(&self, at_us: i64) -> bool {
        if self.identity.valid_from > at_us
            || self.identity.valid_until.is_some_and(|end| at_us > end)
        {
            return false;
        }
        if self.identity.recipient_class == RecipientClass::Public
            && self.identity.usage_right.requires_explicit_grant()
        {
            return false;
        }
        self.decision == RightDecision::Permitted
    }
}

/// Proof returned for one successful authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationProof {
    pub provider_id: String,
    pub source_id: String,
    pub dataset_id: String,
    pub product_id: String,
    pub territory: String,
    pub usage_right: UsageRight,
    pub recipient_class: RecipientClass,
    pub purpose: Purpose,
    pub at_us: i64,
    pub licence_reference: String,
    pub licence_document_hash: String,
    pub contract_revision: u32,
}

/// Failure to authorize a dataset.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RightsError {
    /// The query itself is incomplete.
    #[error("authorization query is incomplete")]
    InvalidQuery,
    /// No record covers the identity and territory.
    #[error("no licensing record for {dataset_id} in {territory}")]
    MissingRecord {
        dataset_id: String,
        territory: String,
    },
    /// The right is absent, denied, conditional, expired or revoked.
    #[error("right {right} not granted for {dataset_id}")]
    RightNotGranted {
        dataset_id: String,
        right: &'static str,
    },
    /// A revoked decision blocks the operation.
    #[error("right {right} for {dataset_id} was revoked")]
    Revoked {
        dataset_id: String,
        right: &'static str,
    },
    /// Two records disagree for the same authorization identity.
    #[error("conflicting authorization for {dataset_id}: {reason}")]
    Conflict {
        dataset_id: String,
        reason: &'static str,
    },
}

/// Fail-closed registry of effective-dated authorization records.
#[derive(Debug, Default)]
pub struct LicensingRegistry {
    records: Vec<AuthorizationRecord>,
    decisions: BTreeMap<String, DecisionAudit>,
}

impl LicensingRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an authorization record.
    ///
    /// # Errors
    /// Returns a conflict when the same authorization identity and contract
    /// revision already carry a different decision, or when an earlier
    /// revision of the same identity already carries a contradictory decision.
    pub fn register(&mut self, record: AuthorizationRecord) -> Result<(), RightsError> {
        let revision_key = format!(
            "{}|{}",
            record.identity.decision_key().0,
            record.audit.contract_revision
        );
        if let Some(existing) = self.decisions.get(&revision_key)
            && existing != &record.audit
        {
            return Err(RightsError::Conflict {
                dataset_id: record.identity.dataset_id.clone(),
                reason: "contract revision already recorded with a different decision",
            });
        }
        for existing in &self.records {
            if existing.identity.decision_key() == record.identity.decision_key()
                && existing.decision != record.decision
                && !(record.decision == RightDecision::Revoked
                    || existing.decision == RightDecision::Revoked)
            {
                return Err(RightsError::Conflict {
                    dataset_id: record.identity.dataset_id.clone(),
                    reason: "same authorization identity carries different decisions",
                });
            }
        }
        self.decisions.insert(revision_key, record.audit.clone());
        self.records.push(record);
        Ok(())
    }

    /// Authorize one fully identified right at an instant.
    pub fn authorize(
        &self,
        query: &AuthorizationQuery,
        at_us: i64,
    ) -> Result<AuthorizationProof, RightsError> {
        query.validate()?;
        let candidates: Vec<&AuthorizationRecord> = self
            .records
            .iter()
            .filter(|record| record.identity.matches(query, at_us))
            .collect();
        if candidates.is_empty() {
            return Err(RightsError::MissingRecord {
                dataset_id: query.dataset_id.clone(),
                territory: query.territory.as_str().to_owned(),
            });
        }
        if candidates
            .iter()
            .any(|record| record.decision == RightDecision::Revoked)
        {
            return Err(RightsError::Revoked {
                dataset_id: query.dataset_id.clone(),
                right: query.usage_right.as_str(),
            });
        }
        let permitted = candidates.iter().any(|record| record.grants(at_us));
        let denied = candidates.iter().any(|record| {
            matches!(
                record.decision,
                RightDecision::Prohibited
                    | RightDecision::ContractRequired
                    | RightDecision::Unknown
            )
        });
        if permitted && denied {
            return Err(RightsError::Conflict {
                dataset_id: query.dataset_id.clone(),
                reason: "permitted and prohibited decisions overlap at this instant",
            });
        }
        if !permitted {
            return Err(RightsError::RightNotGranted {
                dataset_id: query.dataset_id.clone(),
                right: query.usage_right.as_str(),
            });
        }
        let winning = candidates
            .iter()
            .filter(|record| record.grants(at_us))
            .max_by_key(|record| record.audit.contract_revision)
            .ok_or_else(|| RightsError::RightNotGranted {
                dataset_id: query.dataset_id.clone(),
                right: query.usage_right.as_str(),
            })?;
        Ok(AuthorizationProof {
            provider_id: query.provider_id.clone(),
            source_id: query.source_id.clone(),
            dataset_id: query.dataset_id.clone(),
            product_id: query.product_id.clone(),
            territory: query.territory.as_str().to_owned(),
            usage_right: query.usage_right,
            recipient_class: query.recipient_class,
            purpose: query.purpose,
            at_us,
            licence_reference: winning.audit.licence_reference.clone(),
            licence_document_hash: winning.audit.licence_document_hash.clone(),
            contract_revision: winning.audit.contract_revision,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> AuthorizationQuery {
        AuthorizationQuery {
            provider_id: "provider-a".to_owned(),
            source_id: "source-a".to_owned(),
            dataset_id: "quotes".to_owned(),
            product_id: "product-a".to_owned(),
            territory: CountryCode::new("US").expect("country code"),
            usage_right: UsageRight::HistoricalStorage,
            recipient_class: RecipientClass::Internal,
            purpose: Purpose::HistoricalArchive,
        }
    }

    fn record(
        decision: RightDecision,
        provider: &str,
        territory: &str,
        valid_from: i64,
        valid_until: Option<i64>,
        revision: u32,
    ) -> AuthorizationRecord {
        AuthorizationRecord {
            identity: AuthorizationIdentity {
                provider_id: provider.to_owned(),
                source_id: "source-a".to_owned(),
                dataset_id: "quotes".to_owned(),
                product_id: "product-a".to_owned(),
                territory: CountryCode::new(territory).expect("country code"),
                usage_right: UsageRight::HistoricalStorage,
                recipient_class: RecipientClass::Internal,
                purpose: Purpose::HistoricalArchive,
                valid_from,
                valid_until,
            },
            decision,
            audit: DecisionAudit {
                licence_reference: format!("licence-{provider}-{revision}"),
                licence_document_hash: format!("hash-{provider}-{revision}"),
                contract_revision: revision,
                recorded_at_us: valid_from,
                authority: "contract-registry".to_owned(),
            },
        }
    }

    #[test]
    fn effective_dated_grant_authorizes_only_inside_its_window() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(record(
                RightDecision::Permitted,
                "provider-a",
                "US",
                100,
                Some(200),
                1,
            ))
            .expect("grant registered");
        assert!(
            registry.authorize(&query(), 99).is_err(),
            "future-effective grant must not authorize"
        );
        assert!(
            registry.authorize(&query(), 150).is_ok(),
            "effective grant must authorize"
        );
        assert!(
            registry.authorize(&query(), 201).is_err(),
            "expired grant must not authorize"
        );
    }

    #[test]
    fn provider_specific_decision_is_not_shared() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(record(
                RightDecision::Permitted,
                "provider-b",
                "US",
                0,
                None,
                1,
            ))
            .expect("other provider grant registered");
        assert!(
            registry.authorize(&query(), 1).is_err(),
            "a different provider's grant cannot authorize provider-a"
        );
    }

    #[test]
    fn conflicting_decisions_fail_closed() {
        let mut registry = LicensingRegistry::new();
        let mut conflicting = query();
        conflicting.usage_right = UsageRight::Redistribution;
        let mut grant = record(RightDecision::Permitted, "provider-a", "US", 0, None, 1);
        grant.identity.usage_right = UsageRight::Redistribution;
        let mut ban = record(RightDecision::Prohibited, "provider-a", "US", 0, None, 2);
        ban.identity.usage_right = UsageRight::Redistribution;
        registry.register(grant).expect("grant registered");
        assert!(
            matches!(registry.register(ban), Err(RightsError::Conflict { .. })),
            "a contradictory decision for the same identity must be rejected"
        );
        assert!(
            registry.authorize(&conflicting, 1).is_ok(),
            "the original grant remains; the conflicting ban was refused"
        );
    }

    #[test]
    fn revocation_blocks_authorization() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(record(
                RightDecision::Permitted,
                "provider-a",
                "US",
                0,
                None,
                1,
            ))
            .expect("grant registered");
        let revocation = record(RightDecision::Revoked, "provider-a", "US", 50, None, 2);
        registry
            .register(revocation)
            .expect("revocation registered");
        assert!(
            registry.authorize(&query(), 49).is_ok(),
            "grant held before revocation"
        );
        assert!(
            matches!(
                registry.authorize(&query(), 50),
                Err(RightsError::Revoked { .. })
            ),
            "revocation must take effect at its timestamp"
        );
    }

    #[test]
    fn territory_is_scoped() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(record(
                RightDecision::Permitted,
                "provider-a",
                "GB",
                0,
                None,
                1,
            ))
            .expect("grant registered");
        assert!(
            registry.authorize(&query(), 1).is_err(),
            "a GB grant cannot authorize US territory"
        );
    }

    #[test]
    fn public_access_never_grants_retention() {
        let mut registry = LicensingRegistry::new();
        let mut public = record(RightDecision::Permitted, "provider-a", "US", 0, None, 1);
        public.identity.recipient_class = RecipientClass::Public;
        registry
            .register(public)
            .expect("public decision registered");
        let mut public_query = query();
        public_query.recipient_class = RecipientClass::Public;
        assert!(
            registry.authorize(&public_query, 1).is_err(),
            "public access cannot imply historical storage"
        );
    }

    #[test]
    fn conflicting_registration_is_rejected() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(record(
                RightDecision::Permitted,
                "provider-a",
                "US",
                0,
                None,
                1,
            ))
            .expect("grant registered");
        assert!(
            registry
                .register(record(
                    RightDecision::Prohibited,
                    "provider-a",
                    "US",
                    0,
                    None,
                    1
                ))
                .is_err(),
            "same identity and revision cannot change decision"
        );
    }

    #[test]
    fn authorization_proof_carries_audit_identity() {
        let mut registry = LicensingRegistry::new();
        registry
            .register(record(
                RightDecision::Permitted,
                "provider-a",
                "US",
                0,
                None,
                7,
            ))
            .expect("grant registered");
        let proof = registry.authorize(&query(), 1).expect("authorization");
        assert_eq!(
            proof.licence_reference, "licence-provider-a-7",
            "licence reference retained in proof"
        );
        assert_eq!(proof.contract_revision, 7, "revision retained");
        assert_eq!(proof.purpose, Purpose::HistoricalArchive, "purpose kept");
    }
}
