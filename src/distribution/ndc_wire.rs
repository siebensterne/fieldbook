// SPDX-License-Identifier: Apache-2.0
//! Explicit producer mapping from internal release values to the ratified
//! canonical NDC v2 Profile 1 wire representation.
//!
//! The canonical schema package under workspace authority
//! `WS-NDC-2026-11-24-003` is the wire authority. The internal
//! `ReleaseManifest` and its section types are inputs only: every wire
//! member below is named and validated by this module, never inherited from a
//! Rust field name. The internal pre-ratification sections carry opaque
//! references and omit several required canonical members; a strict abstract
//! evidence supplement supplies the typed values that the internal types do
//! not hold. A missing, unknown, duplicated or coerced value fails closed with
//! a typed [`WireError`].
//!
//! The critical correctness boundary is byte-derived record ordering.
//! [`sort_byte_derived`] parses the canonical record bytes, extracts the
//! ordering member, validates it against the artifact profile, derives the key
//! and sorts. A caller-supplied key on [`CanonicalRecord`] is never read. The
//! same validated input bytes are returned in sorted order; no record is
//! re-serialized to obtain an ordering position.
//!
//! Non-claim: this module is a producer-side mapping and conformance vector
//! support. It creates no release, no right, no dataset acceptance and no
//! cross-execution status. The signing seed used by the conformance executable
//! is a published test vector, not a production key.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write as IoWrite;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::Signer as _;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier as _;
use ed25519_dalek::VerifyingKey;
use flate2::Compression as GzipCompression;
use flate2::write::GzEncoder;
use serde::Deserialize;
use sha2::Digest as _;
use sha2::Sha256;
use thiserror::Error;

use crate::distribution::ndc_release::ArtifactCompression;
use crate::distribution::ndc_release::ArtifactDescriptor;
use crate::distribution::ndc_release::CanonicalRecord;
use crate::distribution::ndc_release::DIGEST_ALGORITHM;
use crate::distribution::ndc_release::ENCODING_NDJSON;
use crate::distribution::ndc_release::JcsValue;
use crate::distribution::ndc_release::MANIFEST_SCHEMA_VERSION;
use crate::distribution::ndc_release::RecordOrderKey;
use crate::distribution::ndc_release::RecordOrderProfile;
use crate::distribution::ndc_release::ResourcePolicy;
use crate::distribution::ndc_release::SIDECAR_FILE_NAME;
use crate::distribution::ndc_release::SIDECAR_SCHEMA_VERSION;
use crate::distribution::ndc_release::SIGNATURE_ALGORITHM;
use crate::distribution::ndc_release::SIGNING_DOMAIN;
use crate::distribution::ndc_release::canonicalize_strict;
use crate::distribution::ndc_release::parse_jcs_value;

/// Canonical wire schema version implemented by this mapping.
pub const WIRE_SCHEMA_VERSION: u32 = 1;

/// Single authoritative contract version literal at the manifest root.
pub const CONTRACT_VERSION: &str = "v2";

/// Largest JSON integer with an exact ECMAScript representation.
pub const SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;

/// Registered uncompressed compression identifier.
pub const COMPRESSION_VERSION_NONE: &str = "none/1";

/// Registered gzip compression identifier.
pub const COMPRESSION_VERSION_GZIP: &str = "gzip-deflate/flate2-1";

/// Fixed test-only conformance signing seed. This is a published vector and
/// not production key material; no release package may contain these bytes.
pub const CONFORMANCE_SIGNING_SEED: [u8; 32] = [0x11; 32];

const NINE_DIMENSIONS: [&str; 9] = [
    "instrument_coverage",
    "listing_identity_coverage",
    "contract_coverage",
    "corporate_action_coverage",
    "session_time_coverage",
    "trade_event_coverage",
    "quote_depth_coverage",
    "mbo_coverage",
    "sequence_continuity",
];

const PRODUCER_ACTIONS: [&str; 14] = [
    "source_contact",
    "reference_data_retrieval",
    "historical_data_retrieval",
    "real_time_capture",
    "raw_storage",
    "normalization",
    "replay",
    "backup",
    "internal_analytics",
    "derived_data_creation",
    "display",
    "external_redistribution",
    "retention",
    "deletion",
];

const PUBLICATION_STATES: [&str; 8] = [
    "STAGING_CREATED",
    "FILES_WRITTEN",
    "FILES_SYNCED",
    "STAGING_DIR_FSYNCED",
    "ATOMIC_NO_REPLACE_RENAME",
    "PARENT_DIR_FSYNCED",
    "DURABLE_PUBLICATION_RECEIPT",
    "AVAILABLE",
];

/// Typed failure of the wire mapping. Every refusal is closed and names its
/// location so that no partial wire document can be emitted.
#[derive(Debug, Error)]
pub enum WireError {
    /// Input was not valid canonical JSON text.
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    /// A value could not be serialized as canonical JSON.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    /// An object carried a property outside its closed member set.
    #[error("unknown field `{0}` at {1}")]
    UnknownField(String, String),
    /// A required property was absent.
    #[error("missing required field `{0}` at {1}")]
    MissingField(String, String),
    /// A property appeared more than once.
    #[error("duplicate field `{0}` at {1}")]
    DuplicateField(String, String),
    /// A value had the wrong JSON type for its field.
    #[error("wrong JSON type at {0}: {1}")]
    WrongType(String, String),
    /// A string failed the ratified identifier grammar or was a placeholder.
    #[error("invalid identifier `{0}` at {1}")]
    Identifier(String, String),
    /// A decimal-string value failed the ratified grammar or u64 range.
    #[error("invalid decimal string `{0}` at {1}")]
    Decimal(String, String),
    /// A UTC string failed the canonical nine-fraction-digit grammar.
    #[error("invalid UTC instant `{0}` at {1}")]
    UtcInstant(String, String),
    /// A digest was not lowercase hexadecimal of the required length.
    #[error("invalid digest at {0}")]
    Digest(String),
    /// An artifact path failed the release-relative alphabet rules.
    #[error("invalid artifact path `{0}`")]
    ArtifactPath(String),
    /// Record bytes were not a single canonical UTF-8 JSON line.
    #[error("non-canonical record at {0}: {1}")]
    NonCanonicalRecord(String, String),
    /// A tagged ordering union was malformed or did not match its profile.
    #[error("ordering error at {0}: {1}")]
    Ordering(String, String),
    /// Two records derived the same key with different payloads.
    #[error("duplicate derived ordering key at {0}")]
    DuplicateKey(String),
    /// Coverage arithmetic, evidence or verdict gating failed.
    #[error("coverage error: {0}")]
    Coverage(String),
    /// Source-rights evidence was absent, malformed or inconsistent.
    #[error("rights evidence error: {0}")]
    Rights(String),
    /// Performed operations and typed evidence were not bound one to one.
    #[error("operation evidence error: {0}")]
    OperationEvidence(String),
    /// PROV lineage, revision or invalidation semantics failed.
    #[error("lineage error: {0}")]
    Lineage(String),
    /// The per-event payload schema registry was incomplete or inconsistent.
    #[error("payload schema registry error: {0}")]
    PayloadRegistry(String),
    /// A compression method and version identifier were not a registered pair.
    #[error("unregistered compression identifier: {0}")]
    Compression(String),
    /// A caller-supplied resource bound was exceeded.
    #[error("resource policy exceeded: {0}")]
    Policy(String),
    /// The abstract conformance spec was malformed.
    #[error("invalid conformance spec: {0}")]
    Spec(String),
    /// Signing or verifying failed.
    #[error("signature error: {0}")]
    Signature(String),
    /// A filesystem operation failed.
    #[error("filesystem failure during {0}: {1}")]
    Io(String, #[source] std::io::Error),
}

/// Parsed and validated canonical record. The original bytes are retained so
/// that sorting never re-serializes a record.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedRecord {
    /// Exact validated input bytes, without a line terminator.
    pub bytes: Vec<u8>,
    /// Declared record envelope version.
    pub envelope_schema_version: String,
    /// Declared abstract event type.
    pub event_type: String,
    /// Key derived from the parsed ordering member.
    pub derived_key: WireOrderKey,
    /// Validated abstract payload container.
    pub payload: JcsValue,
}

/// Artifact-level ordering profile expressed in canonical wire member names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireArtifactProfile {
    /// Sequenced domain and epoch required by a sequenced artifact.
    Sequenced {
        /// Sequence domain identity.
        sequence_domain_id: String,
        /// Sequence epoch identity.
        sequence_epoch: String,
    },
    /// Reference profile, which carries neither domain nor epoch.
    Reference,
}

/// Ordering key derived exclusively from parsed canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum WireOrderKey {
    /// Sequenced position with a numerically compared sequence number.
    Sequenced {
        /// Sequence domain identity.
        sequence_domain_id: String,
        /// Sequence epoch identity.
        sequence_epoch: String,
        /// Numeric position in the domain and epoch.
        sequence_number: u64,
    },
    /// Reference position with numerically compared revision and knowledge time.
    Reference {
        /// Stable object identity.
        object_id: String,
        /// Numeric revision.
        revision: u64,
        /// Numeric knowledge time.
        knowledge_time_ns: u64,
        /// Stable assertion identity.
        assertion_id: String,
    },
}

/// One canonical artifact after byte-derived ordering and compression.
#[derive(Debug, Clone)]
pub struct PreparedArtifact {
    /// Exact stored bytes written to the release.
    pub stored_bytes: Vec<u8>,
    /// Exact uncompressed canonical record stream.
    pub uncompressed_bytes: Vec<u8>,
    /// Canonical descriptors with computed sizes and digests.
    pub descriptor: ArtifactDescriptor,
    /// Ordered record lines derived from the validated input bytes.
    pub ordered_records: Vec<Vec<u8>>,
    /// Event types observed in the validated record lines.
    pub event_types: BTreeSet<String>,
}

/// Strict abstract spec accepted by the conformance producer. Every struct
/// denies unknown members; no field has a default and no type is coerced.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceSpec {
    /// Spec layout version; must equal [`WIRE_SCHEMA_VERSION`].
    pub spec_version: u32,
    /// Abstract provenance note. It is not wire content.
    pub note: String,
    /// Internal manifest shape used only as an input to the wire mapping.
    pub manifest: crate::distribution::ndc_release::ReleaseManifest,
    /// Typed evidence supplement absent from the internal sections.
    pub evidence: EvidenceSpec,
    /// Abstract artifacts and their record lines.
    pub artifacts: Vec<SpecArtifact>,
}

/// Typed supplement for the canonical members that internal sections omit.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSpec {
    /// Structured performed operations keyed by operation reference.
    pub performed_operations: Vec<PerformedOperationSpec>,
    /// Typed operation evidence bound by operation reference.
    pub operation_evidence: Vec<OperationEvidenceSpec>,
    /// Full typed source-rights grants.
    pub permission_grants: Vec<PermissionGrantSpec>,
    /// Typed supporting document references with digests.
    pub document_references: Vec<DocumentReferenceSpec>,
    /// Typed registered attestations.
    pub reviewed_attestations: Vec<RegisteredAttestationSpec>,
    /// Supplementary fields for the nine coverage dimensions.
    pub coverage_details: Vec<CoverageDetailSpec>,
    /// Per-event payload schema registry entries.
    pub payload_schemas: Vec<PayloadSchemaSpec>,
    /// Transformation identity for the PROV lineage record.
    pub transformation_identity: String,
    /// Transformation version for the PROV lineage record.
    pub transformation_version: String,
    /// Canonical UTC generation instant.
    pub generated_at_time: String,
    /// Canonical UTC invalidation instant of the current revision.
    pub invalidated_at_time: String,
    /// Typed PROV relations.
    pub prov: ProvSpec,
}

/// Structured performed operation detail.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerformedOperationSpec {
    /// Operation reference bound to an internal reference and one evidence record.
    pub operation_ref: String,
    /// Producer action vocabulary value.
    pub action: String,
    /// Named data object.
    pub data_object: DataObjectSpec,
}

/// Named data object of a performed operation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataObjectSpec {
    /// Object kind.
    pub kind: String,
    /// Object identity.
    pub id: String,
    /// Object version.
    pub version: String,
}

/// Typed operation evidence record.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationEvidenceSpec {
    /// Operation reference this evidence resolves to.
    pub operation_ref: String,
    /// Abstract event identity.
    pub event_id: String,
    /// Abstract run identity.
    pub run_id: String,
    /// Decimal-string recording instant.
    pub recorded_at_ns: String,
    /// Abstract decision key.
    pub decision_key: String,
    /// Lowercase hex digest.
    pub digest_sha256: String,
}

/// Full typed source-rights grant.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionGrantSpec {
    /// Immutable grant identity.
    pub grant_id: String,
    /// Grant revision text.
    pub grant_revision: String,
    /// Granting authority, distinct from signer and reviewer.
    pub granting_authority: GrantingAuthoritySpec,
    /// Producer action vocabulary value.
    pub action: String,
    /// Object class identifier.
    pub object_class: String,
    /// Exact `PERMIT` or `DENY` decision.
    pub decision: String,
    /// Acting party.
    pub actor: String,
    /// Licensee party.
    pub licensee: String,
    /// Recipient class.
    pub recipient_class: String,
    /// Recipient identity.
    pub recipient_identity: String,
    /// Documented purpose.
    pub purpose: String,
    /// Exact scope declaration.
    pub scope: ScopeSpec,
    /// Named validity interval.
    pub validity: ValiditySpec,
    /// Approved delivery method and endpoints.
    pub delivery: DeliverySpec,
    /// Bounded retention and purge rule.
    pub retention: RetentionSpec,
    /// Supporting document references.
    pub supporting_document_references: Vec<DigestReferenceSpec>,
    /// Contract revision text.
    pub contract_revision: String,
    /// Review authority.
    pub review_authority: String,
    /// Canonical UTC review date.
    pub reviewed_on: String,
    /// Reviewed attestation embedded in the grant.
    pub reviewed_attestation: AttestationSpec,
}

/// Granting authority identity and evidence reference.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantingAuthoritySpec {
    /// Authority identifier.
    pub authority_id: String,
    /// Evidence reference outside the signing authority.
    pub evidence_reference: String,
}

/// Exact scope declaration inside a grant.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeSpec {
    /// Provider identifier.
    pub provider_id: String,
    /// Source product identifier.
    pub source_product_id: String,
    /// Required venue identifier.
    pub venue_id: String,
    /// Required segment identifier.
    pub segment_id: String,
    /// Dataset identifier.
    pub dataset_id: String,
    /// Subject state vocabulary value.
    pub subject_state: String,
    /// Named subjects.
    pub named_subjects: Vec<String>,
    /// Decimal-string data interval begin.
    pub data_time_begin_ns: String,
    /// Decimal-string data interval end.
    pub data_time_end_ns: String,
}

/// Named validity interval with a clock domain.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValiditySpec {
    /// Decimal-string validity begin.
    pub begin_ns: String,
    /// Decimal-string validity end.
    pub end_ns: String,
    /// Clock domain name.
    pub clock_domain: String,
}

/// Approved delivery method and endpoint identities.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliverySpec {
    /// Delivery method.
    pub method: String,
    /// Approved endpoint identities.
    pub approved_endpoint_identities: Vec<String>,
}

/// Bounded retention with a purge rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionSpec {
    /// Bounded maximum duration.
    pub max_duration_ns: u64,
    /// Purge rule text.
    pub purge_rule: String,
}

/// Digest-bearing supporting document reference.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DigestReferenceSpec {
    /// Reference identity.
    pub reference: String,
    /// Lowercase hex document digest.
    pub digest_sha256: String,
}

/// Typed supporting document reference.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentReferenceSpec {
    /// Reference identity.
    pub reference: String,
    /// Contract clause.
    pub clause: String,
    /// Lowercase hex document digest.
    pub document_sha256: String,
    /// Contract revision text.
    pub contract_revision: String,
    /// Review authority.
    pub review_authority: String,
    /// Canonical UTC review date.
    pub reviewed_on: String,
}

/// Typed reviewed attestation. It records review and is not permission.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationSpec {
    /// Verbatim purpose.
    pub purpose: String,
    /// Usage right text.
    pub usage_right: String,
    /// Usage mode text.
    pub usage_mode: String,
    /// Territory text.
    pub territory: String,
    /// Scope assertions.
    pub scope_assertions: Vec<String>,
    /// Reviewer identity.
    pub reviewer: String,
    /// Review authority.
    pub authority: String,
}

/// Registered attestation bound to a grant identity.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredAttestationSpec {
    /// Attestation identity.
    pub attestation_id: String,
    /// Grant identity this attestation registers.
    pub grant_id: String,
    /// Typed attestation body.
    pub attestation: AttestationSpec,
}

/// Supplementary fields for one coverage dimension.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDetailSpec {
    /// Dimension identity matching an internal dimension.
    pub dimension_id: String,
    /// Declared denominator identity.
    pub denominator_identity: String,
    /// Declared count basis.
    pub count_basis: String,
    /// Missing count in the exhaustive decomposition.
    pub missing_count: u64,
    /// Rejected count in the exhaustive decomposition.
    pub rejected_count: u64,
    /// Decimal-string coverage as-of instant.
    pub as_of_ns: String,
    /// Typed gaps.
    pub gaps: Vec<GapSpec>,
}

/// Typed coverage gap.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GapSpec {
    /// Gap identity.
    pub gap_id: String,
    /// Gap kind vocabulary value.
    pub gap_kind: String,
    /// Affected component.
    pub component: String,
    /// Gap count.
    pub count: u64,
    /// Abstract description.
    pub description: String,
}

/// Versioned per-event payload schema registry entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadSchemaSpec {
    /// Event type registered by this entry.
    pub event_type: String,
    /// Payload schema identity.
    pub schema_id: String,
    /// Payload schema version.
    pub schema_version: String,
    /// Registered digest of the exact payload schema bytes.
    pub digest_sha256: String,
}

/// Typed PROV relations for the release lineage structure.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvSpec {
    /// Qualified derivation relation.
    pub was_derived_from: ProvDerivedSpec,
    /// Qualified revision relation.
    pub was_revision_of: ProvRevisionSpec,
    /// Qualified primary-source relation.
    pub had_primary_source: ProvSourceSpec,
    /// Qualified attribution.
    pub qualified_attribution: QualifiedAttributionSpec,
}

/// Typed derivation relation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvDerivedSpec {
    /// Source entity identity.
    pub source_entity_id: String,
    /// Deriving activity identity.
    pub deriving_activity_id: String,
    /// Decimal-string knowledge time.
    pub knowledge_time_ns: String,
}

/// Typed revision relation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvRevisionSpec {
    /// Predecessor entity identity.
    pub predecessor_entity_id: String,
    /// Revision activity identity.
    pub revision_activity_id: String,
    /// Decimal-string knowledge time.
    pub knowledge_time_ns: String,
}

/// Typed primary-source relation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvSourceSpec {
    /// Source entity identity.
    pub source_entity_id: String,
    /// Attribution activity identity.
    pub attribution_activity_id: String,
    /// Decimal-string knowledge time.
    pub knowledge_time_ns: String,
}

/// Typed qualified attribution.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedAttributionSpec {
    /// Agent identity.
    pub agent_id: String,
    /// Activity identity.
    pub activity_id: String,
    /// Agent role.
    pub role: String,
    /// Decimal-string knowledge time.
    pub knowledge_time_ns: String,
}

/// Abstract artifact declaration and its canonical record lines.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecArtifact {
    /// Logical partition identity.
    pub logical_partition_id: String,
    /// Shard ordinal within the partition.
    pub shard_ordinal: u32,
    /// Release-relative canonical path.
    pub path: String,
    /// Canonical artifact-level ordering profile.
    pub record_order_profile: SpecProfile,
    /// Canonical artifact encoding literal.
    pub encoding: String,
    /// Registered compression method.
    pub compression: String,
    /// Canonical record lines and untrusted caller keys.
    pub records: Vec<SpecRecord>,
}

/// Tagged artifact ordering profile from the abstract spec.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpecProfile {
    /// Sequenced profile with non-empty domain and epoch.
    Sequenced {
        /// Sequence domain identity.
        sequence_domain_id: String,
        /// Sequence epoch identity.
        sequence_epoch: String,
    },
    /// Reference profile carrying neither domain nor epoch.
    Reference,
}

impl SpecProfile {
    /// Canonical wire name of the selected profile kind.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Sequenced { .. } => "sequenced",
            Self::Reference => "reference",
        }
    }

    /// Convert the abstract profile into the internal producer declaration.
    pub fn to_internal(&self) -> Result<RecordOrderProfile, WireError> {
        match self {
            Self::Sequenced {
                sequence_domain_id,
                sequence_epoch,
            } => {
                reject_placeholder(sequence_domain_id, "sequence_domain_id")?;
                reject_placeholder(sequence_epoch, "sequence_epoch")?;
                Ok(RecordOrderProfile::Sequenced {
                    sequence_domain: sequence_domain_id.clone(),
                    sequence_epoch: sequence_epoch.clone(),
                })
            }
            Self::Reference => Ok(RecordOrderProfile::Reference),
        }
    }
}

/// One canonical record line plus an untrusted caller-supplied key. The key is
/// retained only to prove that the byte-derived path ignores it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecRecord {
    /// Exact canonical JSON record line, without a line terminator.
    pub bytes: String,
    /// Caller-supplied ordering hint that must never be trusted.
    pub claimed_order_key: ClaimedKey,
}

/// Tagged caller-supplied ordering hint from the abstract spec.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClaimedKey {
    /// Claimed sequenced position.
    Sequenced {
        /// Claimed sequence domain.
        sequence_domain_id: String,
        /// Claimed sequence epoch.
        sequence_epoch: String,
        /// Claimed sequence number.
        sequence_number: String,
    },
    /// Claimed reference position.
    Reference {
        /// Claimed object identity.
        object_id: String,
        /// Claimed revision.
        revision: String,
        /// Claimed knowledge time.
        knowledge_time_ns: String,
        /// Claimed assertion identity.
        assertion_id: String,
    },
}

impl ClaimedKey {
    /// Convert the untrusted hint into the internal order-key type. The result
    /// is never used for ordering; it exists only to exercise adversarial
    /// disagreement in the byte-derived path.
    pub fn to_untrusted_internal(&self) -> Result<RecordOrderKey, WireError> {
        match self {
            Self::Sequenced {
                sequence_domain_id,
                sequence_epoch,
                sequence_number,
            } => Ok(RecordOrderKey::Sequenced {
                sequence_domain: sequence_domain_id.clone(),
                sequence_epoch: sequence_epoch.clone(),
                sequence_number: parse_decimal(sequence_number, "claimed sequence_number")?,
            }),
            Self::Reference {
                object_id,
                revision,
                knowledge_time_ns,
                assertion_id,
            } => Ok(RecordOrderKey::Reference {
                object_id: object_id.clone(),
                revision: parse_decimal(revision, "claimed revision")?,
                knowledge_time_ns: knowledge_time_ns.clone(),
                assertion_id: assertion_id.clone(),
            }),
        }
    }
}

/// Enforce a closed object member set with no defaults and no coercions.
///
/// The value must be an object; every member must appear in `allowed`, every
/// name in `required` must be present, and a repeated name is rejected even
/// though the upstream parser already rejects duplicate JSON names.
pub fn strict_object<'a>(
    value: &'a JcsValue,
    path: &str,
    allowed: &[&str],
    required: &[&str],
) -> Result<BTreeMap<&'a str, &'a JcsValue>, WireError> {
    let JcsValue::Object(entries) = value else {
        return Err(WireError::WrongType(path.to_owned(), "object".to_owned()));
    };
    let mut fields = BTreeMap::new();
    for (name, child) in entries {
        if !allowed.contains(&name.as_str()) {
            return Err(WireError::UnknownField(name.clone(), path.to_owned()));
        }
        if fields.insert(name.as_str(), child).is_some() {
            return Err(WireError::DuplicateField(name.clone(), path.to_owned()));
        }
    }
    for name in required {
        if !fields.contains_key(*name) {
            return Err(WireError::MissingField((*name).to_owned(), path.to_owned()));
        }
    }
    Ok(fields)
}

/// Read a required string member from a validated object.
pub fn field_string<'a>(
    fields: &BTreeMap<&'a str, &'a JcsValue>,
    name: &str,
    path: &str,
) -> Result<&'a str, WireError> {
    let Some(value) = fields.get(name) else {
        return Err(WireError::MissingField(name.to_owned(), path.to_owned()));
    };
    let JcsValue::String(text) = value else {
        return Err(WireError::WrongType(
            format!("{path}.{name}"),
            "string".to_owned(),
        ));
    };
    Ok(text)
}

/// Read a required decimal-string member and return its parsed u64 value.
pub fn field_decimal(
    fields: &BTreeMap<&str, &JcsValue>,
    name: &str,
    path: &str,
) -> Result<u64, WireError> {
    let text = field_string(fields, name, path)?;
    parse_decimal(text, &format!("{path}.{name}"))
}

/// Parse a decimal string matching `^(0|[1-9][0-9]*)$` within the u64 range.
pub fn parse_decimal(value: &str, field: &str) -> Result<u64, WireError> {
    if value.is_empty()
        || value.len() > 20
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(WireError::Decimal(value.to_owned(), field.to_owned()));
    }
    value
        .parse::<u64>()
        .map_err(|_| WireError::Decimal(value.to_owned(), field.to_owned()))
}

/// Validate the ratified identifier grammar and reject placeholder literals.
pub fn validate_identifier(value: &str, field: &str) -> Result<(), WireError> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(WireError::Identifier(value.to_owned(), field.to_owned()));
    };
    if !first.is_ascii_alphanumeric() || value.len() > 128 {
        return Err(WireError::Identifier(value.to_owned(), field.to_owned()));
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(WireError::Identifier(value.to_owned(), field.to_owned()));
    }
    reject_placeholder(value, field)
}

fn reject_placeholder(value: &str, field: &str) -> Result<(), WireError> {
    const PLACEHOLDERS: [&str; 10] = [
        "UNKNOWN",
        "ALL",
        "NONE",
        "NULL",
        "null",
        "N/A",
        "TBD",
        "PLACEHOLDER",
        "unknown",
        "all",
    ];
    if PLACEHOLDERS.contains(&value) {
        return Err(WireError::Identifier(value.to_owned(), field.to_owned()));
    }
    Ok(())
}

/// Validate the canonical UTC grammar with exactly nine fractional digits.
pub fn validate_utc_instant(value: &str, field: &str) -> Result<(), WireError> {
    let invalid = || WireError::UtcInstant(value.to_owned(), field.to_owned());
    let bytes = value.as_bytes();
    if bytes.len() != 30
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[29] != b'Z'
    {
        return Err(invalid());
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let slice = value.get(range)?;
        if !slice.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        slice.parse::<u32>().ok()
    };
    let year = digits(0..4).ok_or_else(invalid)?;
    let month = digits(5..7).ok_or_else(invalid)?;
    let day = digits(8..10).ok_or_else(invalid)?;
    let hour = digits(11..13).ok_or_else(invalid)?;
    let minute = digits(14..16).ok_or_else(invalid)?;
    let second = digits(17..19).ok_or_else(invalid)?;
    if digits(20..29).is_none() {
        return Err(invalid());
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(invalid()),
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return Err(invalid());
    }
    Ok(())
}

/// Validate a lowercase hexadecimal SHA-256 digest.
pub fn validate_sha256_hex(value: &str, field: &str) -> Result<(), WireError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(WireError::Digest(field.to_owned()));
    }
    Ok(())
}

fn validate_artifact_path(path: &str) -> Result<(), WireError> {
    let Some(name) = path.strip_prefix("artifacts/") else {
        return Err(WireError::ArtifactPath(path.to_owned()));
    };
    if name.is_empty() || name.len() > 128 {
        return Err(WireError::ArtifactPath(path.to_owned()));
    }
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Err(WireError::ArtifactPath(path.to_owned()));
    };
    if !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(WireError::ArtifactPath(path.to_owned()));
    }
    Ok(())
}

fn validate_action(value: &str, field: &str) -> Result<(), WireError> {
    if !PRODUCER_ACTIONS.contains(&value) {
        return Err(WireError::Spec(format!(
            "{field} is not a producer action vocabulary value"
        )));
    }
    Ok(())
}

fn require_nonempty(value: &str, field: &str) -> Result<(), WireError> {
    if value.is_empty() {
        return Err(WireError::Spec(format!("{field} must not be empty")));
    }
    Ok(())
}

/// Build a canonical wire object from explicitly named members.
fn obj(entries: Vec<(&str, JcsValue)>) -> JcsValue {
    JcsValue::Object(
        entries
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

fn text(value: impl Into<String>) -> JcsValue {
    JcsValue::String(value.into())
}

/// Emit a count or byte size as an integer below 2^53 or a decimal string.
fn count(value: u64) -> JcsValue {
    if value < SAFE_INTEGER_MAX {
        JcsValue::Integer(i64::try_from(value).unwrap_or(0))
    } else {
        text(value.to_string())
    }
}

/// Emit a validated decimal-string instant.
fn decimal_text(value: &str, field: &str) -> Result<JcsValue, WireError> {
    parse_decimal(value, field)?;
    Ok(text(value))
}

/// SHA-256 over exact bytes, rendered as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    crate::distribution::ndc_release::hex_encode(&hasher.finalize())
}

/// Map an internal artifact ordering profile into the canonical tagged object.
pub fn map_artifact_profile(
    profile: &RecordOrderProfile,
) -> Result<WireArtifactProfile, WireError> {
    match profile {
        RecordOrderProfile::Sequenced {
            sequence_domain,
            sequence_epoch,
        } => {
            reject_placeholder(sequence_domain, "sequence_domain_id")?;
            reject_placeholder(sequence_epoch, "sequence_epoch")?;
            Ok(WireArtifactProfile::Sequenced {
                sequence_domain_id: sequence_domain.clone(),
                sequence_epoch: sequence_epoch.clone(),
            })
        }
        RecordOrderProfile::Reference => Ok(WireArtifactProfile::Reference),
    }
}

/// Parse one canonical record line and derive its ordering key from the parsed
/// bytes. No caller-supplied position, index or pre-sorted hint is consulted.
pub fn parse_canonical_record(
    bytes: &[u8],
    policy: &ResourcePolicy,
) -> Result<ParsedRecord, WireError> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(WireError::NonCanonicalRecord(
            "root".to_owned(),
            "byte-order mark".to_owned(),
        ));
    }
    if u64::try_from(bytes.len()).map_err(|_| WireError::Policy("record length".to_owned()))?
        > policy.max_record_bytes
    {
        return Err(WireError::Policy(format!(
            "record length {} exceeds {}",
            bytes.len(),
            policy.max_record_bytes
        )));
    }
    let source = std::str::from_utf8(bytes)
        .map_err(|_| WireError::NonCanonicalRecord("root".to_owned(), "not UTF-8".to_owned()))?;
    if source.contains(['\n', '\r']) {
        return Err(WireError::NonCanonicalRecord(
            "root".to_owned(),
            "embedded line terminator".to_owned(),
        ));
    }
    let value =
        parse_jcs_value(source).map_err(|error| WireError::InvalidJson(error.to_string()))?;
    let canonical = canonicalize_strict(&value, policy)
        .map_err(|error| WireError::Canonicalization(error.to_string()))?;
    if canonical != bytes {
        return Err(WireError::NonCanonicalRecord(
            "root".to_owned(),
            "bytes differ from RFC 8785 canonical form".to_owned(),
        ));
    }
    let envelope = strict_object(
        &value,
        "envelope",
        &[
            "envelope_schema_version",
            "event_type",
            "ordering",
            "payload",
        ],
        &[
            "envelope_schema_version",
            "event_type",
            "ordering",
            "payload",
        ],
    )?;
    let envelope_schema_version =
        field_string(&envelope, "envelope_schema_version", "envelope")?.to_owned();
    if envelope_schema_version.is_empty() {
        return Err(WireError::WrongType(
            "envelope.envelope_schema_version".to_owned(),
            "non-empty string".to_owned(),
        ));
    }
    let event_type = field_string(&envelope, "event_type", "envelope")?.to_owned();
    validate_identifier(&event_type, "event_type")?;
    let ordering_value = envelope["ordering"];
    let ordering = parse_record_ordering(ordering_value)?;
    let derived_key = match ordering {
        RecordOrdering::Sequenced {
            sequence_domain_id,
            sequence_epoch,
            sequence_number,
        } => WireOrderKey::Sequenced {
            sequence_domain_id,
            sequence_epoch,
            sequence_number,
        },
        RecordOrdering::Reference {
            object_id,
            revision,
            knowledge_time_ns,
            assertion_id,
        } => WireOrderKey::Reference {
            object_id,
            revision,
            knowledge_time_ns,
            assertion_id,
        },
    };
    let payload = envelope["payload"].clone();
    validate_payload(&payload, policy)?;
    Ok(ParsedRecord {
        bytes: bytes.to_vec(),
        envelope_schema_version,
        event_type,
        derived_key,
        payload,
    })
}

enum RecordOrdering {
    Sequenced {
        sequence_domain_id: String,
        sequence_epoch: String,
        sequence_number: u64,
    },
    Reference {
        object_id: String,
        revision: u64,
        knowledge_time_ns: u64,
        assertion_id: String,
    },
}

fn parse_record_ordering(value: &JcsValue) -> Result<RecordOrdering, WireError> {
    let JcsValue::Object(entries) = value else {
        return Err(WireError::Ordering(
            "ordering".to_owned(),
            "tagged object required".to_owned(),
        ));
    };
    let kind = entries.iter().find(|(name, _)| name == "kind");
    let Some((_, kind_value)) = kind else {
        return Err(WireError::Ordering(
            "ordering".to_owned(),
            "missing kind".to_owned(),
        ));
    };
    let JcsValue::String(kind_text) = kind_value else {
        return Err(WireError::Ordering(
            "ordering.kind".to_owned(),
            "string required".to_owned(),
        ));
    };
    match kind_text.as_str() {
        "sequenced" => {
            let fields = strict_object(
                value,
                "ordering",
                &[
                    "kind",
                    "sequence_domain_id",
                    "sequence_epoch",
                    "sequence_number",
                ],
                &[
                    "kind",
                    "sequence_domain_id",
                    "sequence_epoch",
                    "sequence_number",
                ],
            )?;
            Ok(RecordOrdering::Sequenced {
                sequence_domain_id: field_string(&fields, "sequence_domain_id", "ordering")?
                    .to_owned(),
                sequence_epoch: field_string(&fields, "sequence_epoch", "ordering")?.to_owned(),
                sequence_number: field_decimal(&fields, "sequence_number", "ordering")?,
            })
        }
        "reference" => {
            let fields = strict_object(
                value,
                "ordering",
                &[
                    "kind",
                    "object_id",
                    "revision",
                    "knowledge_time_ns",
                    "assertion_id",
                ],
                &[
                    "kind",
                    "object_id",
                    "revision",
                    "knowledge_time_ns",
                    "assertion_id",
                ],
            )?;
            let object_id = field_string(&fields, "object_id", "ordering")?.to_owned();
            let assertion_id = field_string(&fields, "assertion_id", "ordering")?.to_owned();
            validate_identifier(&object_id, "ordering.object_id")?;
            validate_identifier(&assertion_id, "ordering.assertion_id")?;
            Ok(RecordOrdering::Reference {
                object_id,
                revision: field_decimal(&fields, "revision", "ordering")?,
                knowledge_time_ns: field_decimal(&fields, "knowledge_time_ns", "ordering")?,
                assertion_id,
            })
        }
        other => Err(WireError::Ordering(
            "ordering.kind".to_owned(),
            format!("unknown kind {other}"),
        )),
    }
}

fn validate_payload(value: &JcsValue, policy: &ResourcePolicy) -> Result<(), WireError> {
    let payload = strict_object(value, "payload", &["fields"], &["fields"])?;
    let JcsValue::Array(fields) = payload["fields"] else {
        return Err(WireError::WrongType(
            "payload.fields".to_owned(),
            "array".to_owned(),
        ));
    };
    if fields.is_empty() {
        return Err(WireError::Spec(
            "payload.fields must not be empty".to_owned(),
        ));
    }
    if u64::try_from(fields.len()).map_err(|_| WireError::Policy("payload fields".to_owned()))?
        > u64::from(policy.max_array_elements)
    {
        return Err(WireError::Policy(
            "payload.fields exceeds array bound".to_owned(),
        ));
    }
    for (index, field) in fields.iter().enumerate() {
        let location = format!("payload.fields[{index}]");
        let members = strict_object(
            field,
            &location,
            &["field_name", "kind", "value"],
            &["field_name", "kind", "value"],
        )?;
        let name = field_string(&members, "field_name", &location)?;
        require_nonempty(name, "field_name")?;
        let kind = field_string(&members, "kind", &location)?;
        let scalar = field_string(&members, "value", &location)?;
        match kind {
            "string" => {}
            "decimal_string" => {
                parse_decimal(scalar, "payload field value")?;
            }
            "boolean" => {
                if scalar != "true" && scalar != "false" {
                    return Err(WireError::WrongType(
                        format!("{location}.value"),
                        "boolean literal".to_owned(),
                    ));
                }
            }
            "bytes_hex" => {
                if scalar.len() % 2 != 0
                    || !scalar
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(WireError::Digest(format!("{location}.value")));
                }
            }
            other => {
                return Err(WireError::WrongType(
                    format!("{location}.kind"),
                    format!("unknown kind {other}"),
                ));
            }
        }
    }
    Ok(())
}

/// Validate a parsed record against its containing artifact profile and
/// return the key derived from the parsed canonical bytes.
pub fn derive_order_key(
    record: &ParsedRecord,
    profile: &WireArtifactProfile,
) -> Result<WireOrderKey, WireError> {
    match (&record.derived_key, profile) {
        (
            WireOrderKey::Sequenced {
                sequence_domain_id,
                sequence_epoch,
                sequence_number,
            },
            WireArtifactProfile::Sequenced {
                sequence_domain_id: expected_domain,
                sequence_epoch: expected_epoch,
            },
        ) => {
            if sequence_domain_id != expected_domain || sequence_epoch != expected_epoch {
                return Err(WireError::Ordering(
                    record.event_type.clone(),
                    "record domain or epoch differs from artifact profile".to_owned(),
                ));
            }
            Ok(WireOrderKey::Sequenced {
                sequence_domain_id: sequence_domain_id.clone(),
                sequence_epoch: sequence_epoch.clone(),
                sequence_number: *sequence_number,
            })
        }
        (WireOrderKey::Reference { .. }, WireArtifactProfile::Reference) => {
            Ok(record.derived_key.clone())
        }
        _ => Err(WireError::Ordering(
            record.event_type.clone(),
            "record ordering mode differs from artifact profile".to_owned(),
        )),
    }
}

/// Parse, validate and sort records by keys derived from their own bytes.
///
/// The `order_key` member of each [`CanonicalRecord`] is not read. A
/// caller-supplied key that disagrees with the record bytes cannot
/// change the emitted order, and duplicate keys with differing payloads fail
/// closed. The returned byte vectors are the validated input bytes unchanged.
pub fn sort_byte_derived(
    records: &[CanonicalRecord],
    profile: &WireArtifactProfile,
    policy: &ResourcePolicy,
) -> Result<Vec<Vec<u8>>, WireError> {
    if u64::try_from(records.len()).map_err(|_| WireError::Policy("record count".to_owned()))?
        > policy.max_records_per_artifact
    {
        return Err(WireError::Policy("record count exceeds bound".to_owned()));
    }
    let mut entries: Vec<(WireOrderKey, Vec<u8>, String)> = Vec::with_capacity(records.len());
    for (index, record) in records.iter().enumerate() {
        let parsed = parse_canonical_record(&record.bytes, policy)
            .map_err(|error| WireError::NonCanonicalRecord(index.to_string(), error.to_string()))?;
        let key = derive_order_key(&parsed, profile)?;
        let payload_bytes = canonicalize_strict(&parsed.payload, policy)
            .map_err(|error| WireError::Canonicalization(error.to_string()))?;
        let digest = sha256_hex(&payload_bytes);
        if let Some(previous) = entries.iter().find(|(old, _, _)| old == &key)
            && previous.2 != digest
        {
            return Err(WireError::DuplicateKey(format!("{key:?}")));
        }
        entries.push((key, parsed.bytes, digest));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(entries.into_iter().map(|(_, bytes, _)| bytes).collect())
}

fn map_source_scope(
    scope: &crate::distribution::ndc_release::SourceScope,
) -> Result<JcsValue, WireError> {
    let provider = scope.provider_id.as_str();
    let product = scope.source_product_id.as_str();
    let Some(venue) = scope.venue_id.as_deref() else {
        return Err(WireError::Spec(
            "venue_id is required in Profile 1".to_owned(),
        ));
    };
    let Some(segment) = scope.segment_id.as_deref() else {
        return Err(WireError::Spec(
            "segment_id is required in Profile 1".to_owned(),
        ));
    };
    let dataset = scope.dataset_id.as_str();
    validate_identifier(provider, "provider_id")?;
    validate_identifier(product, "source_product_id")?;
    validate_identifier(venue, "venue_id")?;
    validate_identifier(segment, "segment_id")?;
    validate_identifier(dataset, "dataset_id")?;
    Ok(obj(vec![
        ("provider_id", text(provider)),
        ("source_product_id", text(product)),
        ("venue_id", text(venue)),
        ("segment_id", text(segment)),
        ("dataset_id", text(dataset)),
    ]))
}

fn map_release_identity(
    identity: &crate::distribution::ndc_release::ReleaseIdentity,
) -> Result<JcsValue, WireError> {
    validate_identifier(&identity.release_id, "release_id")?;
    require_nonempty(&identity.release_version, "release_version")?;
    let state = identity.publication_state.as_str();
    if !PUBLICATION_STATES.contains(&state) {
        return Err(WireError::Spec(format!(
            "unknown publication state {state}"
        )));
    }
    Ok(obj(vec![
        ("release_id", text(identity.release_id.clone())),
        ("release_version", text(identity.release_version.clone())),
        ("as_of_ns", decimal_text(&identity.as_of_ns, "as_of_ns")?),
        (
            "created_at_utc_ns",
            decimal_text(&identity.created_at_utc_ns, "created_at_utc_ns")?,
        ),
        ("publication_state", text(state)),
    ]))
}

fn map_data_object(object: &DataObjectSpec) -> Result<JcsValue, WireError> {
    validate_identifier(&object.kind, "data_object.kind")?;
    validate_identifier(&object.id, "data_object.id")?;
    require_nonempty(&object.version, "data_object.version")?;
    Ok(obj(vec![
        ("kind", text(object.kind.clone())),
        ("id", text(object.id.clone())),
        ("version", text(object.version.clone())),
    ]))
}

fn map_producer_activity(
    activity: &crate::distribution::ndc_release::ProducerActivity,
    evidence: &EvidenceSpec,
) -> Result<JcsValue, WireError> {
    let mut operations: BTreeMap<&str, &PerformedOperationSpec> = BTreeMap::new();
    for operation in &evidence.performed_operations {
        validate_identifier(&operation.operation_ref, "operation_ref")?;
        if operations
            .insert(operation.operation_ref.as_str(), operation)
            .is_some()
        {
            return Err(WireError::OperationEvidence(format!(
                "duplicate performed operation {}",
                operation.operation_ref
            )));
        }
    }
    let mut resolved: BTreeMap<&str, &OperationEvidenceSpec> = BTreeMap::new();
    for record in &evidence.operation_evidence {
        validate_identifier(&record.operation_ref, "operation_ref")?;
        if resolved
            .insert(record.operation_ref.as_str(), record)
            .is_some()
        {
            return Err(WireError::OperationEvidence(format!(
                "duplicate evidence for {}",
                record.operation_ref
            )));
        }
    }
    let mut mapped_operations = Vec::with_capacity(activity.performed_operations.len());
    let mut seen_operations = BTreeSet::new();
    for reference in &activity.performed_operations {
        validate_identifier(reference, "performed operation reference")?;
        if !seen_operations.insert(reference.as_str()) {
            return Err(WireError::OperationEvidence(format!(
                "duplicate performed operation reference {reference}"
            )));
        }
        let detail = operations.get(reference.as_str()).ok_or_else(|| {
            WireError::OperationEvidence(format!("no structured detail for {reference}"))
        })?;
        validate_action(&detail.action, "performed operation action")?;
        mapped_operations.push(obj(vec![
            ("operation_ref", text(detail.operation_ref.clone())),
            ("action", text(detail.action.clone())),
            ("data_object", map_data_object(&detail.data_object)?),
        ]));
    }
    let mut mapped_evidence = Vec::with_capacity(activity.operation_evidence.len());
    let mut seen_evidence = BTreeSet::new();
    for reference in &activity.operation_evidence {
        validate_identifier(reference, "operation evidence reference")?;
        if !seen_evidence.insert(reference.as_str()) {
            return Err(WireError::OperationEvidence(format!(
                "duplicate operation evidence reference {reference}"
            )));
        }
        let detail = resolved.get(reference.as_str()).ok_or_else(|| {
            WireError::OperationEvidence(format!("no typed evidence for {reference}"))
        })?;
        validate_identifier(&detail.event_id, "event_id")?;
        validate_identifier(&detail.run_id, "run_id")?;
        parse_decimal(&detail.recorded_at_ns, "recorded_at_ns")?;
        require_nonempty(&detail.decision_key, "decision_key")?;
        validate_sha256_hex(&detail.digest_sha256, "operation digest_sha256")?;
        mapped_evidence.push(obj(vec![
            ("operation_ref", text(detail.operation_ref.clone())),
            ("event_id", text(detail.event_id.clone())),
            ("run_id", text(detail.run_id.clone())),
            ("recorded_at_ns", text(detail.recorded_at_ns.clone())),
            ("decision_key", text(detail.decision_key.clone())),
            ("digest_sha256", text(detail.digest_sha256.clone())),
        ]));
    }
    if seen_operations != seen_evidence {
        return Err(WireError::OperationEvidence(
            "operations and evidence are not bound one to one by operation_ref".to_owned(),
        ));
    }
    if seen_operations.len() != operations.len() || seen_evidence.len() != resolved.len() {
        return Err(WireError::OperationEvidence(
            "an operation or evidence detail has no matching declaration".to_owned(),
        ));
    }
    Ok(obj(vec![
        ("performed_operations", JcsValue::Array(mapped_operations)),
        ("operation_evidence", JcsValue::Array(mapped_evidence)),
    ]))
}

fn map_scope(scope: &ScopeSpec) -> Result<JcsValue, WireError> {
    validate_identifier(&scope.provider_id, "scope.provider_id")?;
    validate_identifier(&scope.source_product_id, "scope.source_product_id")?;
    validate_identifier(&scope.venue_id, "scope.venue_id")?;
    validate_identifier(&scope.segment_id, "scope.segment_id")?;
    validate_identifier(&scope.dataset_id, "scope.dataset_id")?;
    if !["NAMED", "ALL", "NOT_APPLICABLE"].contains(&scope.subject_state.as_str()) {
        return Err(WireError::Rights("invalid subject_state".to_owned()));
    }
    for subject in &scope.named_subjects {
        validate_identifier(subject, "named_subject")?;
    }
    Ok(obj(vec![
        ("provider_id", text(scope.provider_id.clone())),
        ("source_product_id", text(scope.source_product_id.clone())),
        ("venue_id", text(scope.venue_id.clone())),
        ("segment_id", text(scope.segment_id.clone())),
        ("dataset_id", text(scope.dataset_id.clone())),
        ("subject_state", text(scope.subject_state.clone())),
        (
            "named_subjects",
            JcsValue::Array(scope.named_subjects.iter().cloned().map(text).collect()),
        ),
        (
            "data_time_begin_ns",
            decimal_text(&scope.data_time_begin_ns, "data_time_begin_ns")?,
        ),
        (
            "data_time_end_ns",
            decimal_text(&scope.data_time_end_ns, "data_time_end_ns")?,
        ),
    ]))
}

fn map_validity(validity: &ValiditySpec) -> Result<JcsValue, WireError> {
    require_nonempty(&validity.clock_domain, "clock_domain")?;
    Ok(obj(vec![
        (
            "begin_ns",
            decimal_text(&validity.begin_ns, "validity.begin_ns")?,
        ),
        ("end_ns", decimal_text(&validity.end_ns, "validity.end_ns")?),
        ("clock_domain", text(validity.clock_domain.clone())),
    ]))
}

fn map_delivery(delivery: &DeliverySpec) -> Result<JcsValue, WireError> {
    require_nonempty(&delivery.method, "delivery.method")?;
    if delivery.approved_endpoint_identities.is_empty() {
        return Err(WireError::Rights(
            "approved endpoint identities are required".to_owned(),
        ));
    }
    for endpoint in &delivery.approved_endpoint_identities {
        validate_identifier(endpoint, "approved_endpoint_identity")?;
    }
    Ok(obj(vec![
        ("method", text(delivery.method.clone())),
        (
            "approved_endpoint_identities",
            JcsValue::Array(
                delivery
                    .approved_endpoint_identities
                    .iter()
                    .cloned()
                    .map(text)
                    .collect(),
            ),
        ),
    ]))
}

fn map_retention(retention: &RetentionSpec) -> Result<JcsValue, WireError> {
    require_nonempty(&retention.purge_rule, "purge_rule")?;
    Ok(obj(vec![
        ("max_duration_ns", count(retention.max_duration_ns)),
        ("purge_rule", text(retention.purge_rule.clone())),
    ]))
}

fn map_supporting(supporting: &[DigestReferenceSpec]) -> Result<JcsValue, WireError> {
    if supporting.is_empty() {
        return Err(WireError::Rights(
            "supporting document references are required".to_owned(),
        ));
    }
    let mut mapped = Vec::with_capacity(supporting.len());
    for item in supporting {
        require_nonempty(&item.reference, "supporting reference")?;
        validate_sha256_hex(&item.digest_sha256, "supporting digest_sha256")?;
        mapped.push(obj(vec![
            ("reference", text(item.reference.clone())),
            ("digest_sha256", text(item.digest_sha256.clone())),
        ]));
    }
    Ok(JcsValue::Array(mapped))
}

fn map_attestation(attestation: &AttestationSpec) -> Result<JcsValue, WireError> {
    require_nonempty(&attestation.purpose, "attestation.purpose")?;
    require_nonempty(&attestation.usage_right, "attestation.usage_right")?;
    require_nonempty(&attestation.usage_mode, "attestation.usage_mode")?;
    require_nonempty(&attestation.territory, "attestation.territory")?;
    if attestation.scope_assertions.is_empty() {
        return Err(WireError::Rights(
            "scope assertions are required".to_owned(),
        ));
    }
    for assertion in &attestation.scope_assertions {
        require_nonempty(assertion, "scope assertion")?;
    }
    require_nonempty(&attestation.reviewer, "attestation.reviewer")?;
    require_nonempty(&attestation.authority, "attestation.authority")?;
    Ok(obj(vec![
        ("purpose", text(attestation.purpose.clone())),
        ("usage_right", text(attestation.usage_right.clone())),
        ("usage_mode", text(attestation.usage_mode.clone())),
        ("territory", text(attestation.territory.clone())),
        (
            "scope_assertions",
            JcsValue::Array(
                attestation
                    .scope_assertions
                    .iter()
                    .cloned()
                    .map(text)
                    .collect(),
            ),
        ),
        ("reviewer", text(attestation.reviewer.clone())),
        ("authority", text(attestation.authority.clone())),
    ]))
}

fn map_grant(grant: &PermissionGrantSpec) -> Result<JcsValue, WireError> {
    validate_identifier(&grant.grant_id, "grant_id")?;
    require_nonempty(&grant.grant_revision, "grant_revision")?;
    validate_identifier(&grant.granting_authority.authority_id, "authority_id")?;
    require_nonempty(
        &grant.granting_authority.evidence_reference,
        "authority evidence_reference",
    )?;
    validate_action(&grant.action, "grant.action")?;
    validate_identifier(&grant.object_class, "object_class")?;
    if grant.decision != "PERMIT" && grant.decision != "DENY" {
        return Err(WireError::Rights(
            "decision must be PERMIT or DENY".to_owned(),
        ));
    }
    for value in [
        &grant.actor,
        &grant.licensee,
        &grant.recipient_class,
        &grant.recipient_identity,
        &grant.purpose,
        &grant.contract_revision,
        &grant.review_authority,
    ] {
        require_nonempty(value, "grant text field")?;
    }
    validate_utc_instant(&grant.reviewed_on, "grant.reviewed_on")?;
    Ok(obj(vec![
        ("grant_id", text(grant.grant_id.clone())),
        ("grant_revision", text(grant.grant_revision.clone())),
        (
            "granting_authority",
            obj(vec![
                (
                    "authority_id",
                    text(grant.granting_authority.authority_id.clone()),
                ),
                (
                    "evidence_reference",
                    text(grant.granting_authority.evidence_reference.clone()),
                ),
            ]),
        ),
        ("action", text(grant.action.clone())),
        ("object_class", text(grant.object_class.clone())),
        ("decision", text(grant.decision.clone())),
        ("actor", text(grant.actor.clone())),
        ("licensee", text(grant.licensee.clone())),
        ("recipient_class", text(grant.recipient_class.clone())),
        ("recipient_identity", text(grant.recipient_identity.clone())),
        ("purpose", text(grant.purpose.clone())),
        ("scope", map_scope(&grant.scope)?),
        ("validity", map_validity(&grant.validity)?),
        ("delivery", map_delivery(&grant.delivery)?),
        ("retention", map_retention(&grant.retention)?),
        (
            "supporting_document_references",
            map_supporting(&grant.supporting_document_references)?,
        ),
        ("contract_revision", text(grant.contract_revision.clone())),
        ("review_authority", text(grant.review_authority.clone())),
        ("reviewed_on", text(grant.reviewed_on.clone())),
        (
            "reviewed_attestation",
            map_attestation(&grant.reviewed_attestation)?,
        ),
    ]))
}

fn map_rights(
    rights: &crate::distribution::ndc_release::RightsEvidence,
    evidence: &EvidenceSpec,
) -> Result<JcsValue, WireError> {
    let mut grants: BTreeMap<&str, &PermissionGrantSpec> = BTreeMap::new();
    for grant in &evidence.permission_grants {
        validate_identifier(&grant.grant_id, "grant_id")?;
        if grants.insert(grant.grant_id.as_str(), grant).is_some() {
            return Err(WireError::Rights(format!(
                "duplicate grant {}",
                grant.grant_id
            )));
        }
    }
    let mut documents: BTreeMap<&str, &DocumentReferenceSpec> = BTreeMap::new();
    for document in &evidence.document_references {
        require_nonempty(&document.reference, "document reference")?;
        require_nonempty(&document.clause, "document clause")?;
        validate_sha256_hex(&document.document_sha256, "document_sha256")?;
        require_nonempty(&document.contract_revision, "document contract_revision")?;
        require_nonempty(&document.review_authority, "document review_authority")?;
        validate_utc_instant(&document.reviewed_on, "document.reviewed_on")?;
        if documents
            .insert(document.reference.as_str(), document)
            .is_some()
        {
            return Err(WireError::Rights(format!(
                "duplicate document reference {}",
                document.reference
            )));
        }
    }
    let mut attestations: BTreeMap<&str, &RegisteredAttestationSpec> = BTreeMap::new();
    for attestation in &evidence.reviewed_attestations {
        validate_identifier(&attestation.attestation_id, "attestation_id")?;
        validate_identifier(&attestation.grant_id, "attestation grant_id")?;
        map_attestation(&attestation.attestation)?;
        if attestations
            .insert(attestation.attestation_id.as_str(), attestation)
            .is_some()
        {
            return Err(WireError::Rights(format!(
                "duplicate attestation {}",
                attestation.attestation_id
            )));
        }
    }
    if grants.is_empty() || documents.is_empty() || attestations.is_empty() {
        return Err(WireError::Rights("rights evidence is absent".to_owned()));
    }
    let mut mapped_grants = Vec::with_capacity(rights.permission_grants.len());
    let mut used_grants = BTreeSet::new();
    for reference in &rights.permission_grants {
        let grant = grants
            .get(reference.as_str())
            .ok_or_else(|| WireError::Rights(format!("no typed grant for {reference}")))?;
        if !used_grants.insert(reference.as_str()) {
            return Err(WireError::Rights(format!(
                "duplicate grant reference {reference}"
            )));
        }
        let registered = attestations
            .values()
            .find(|item| item.grant_id == grant.grant_id)
            .ok_or_else(|| {
                WireError::Rights(format!("no registered attestation for {reference}"))
            })?;
        let embedded = map_attestation(&grant.reviewed_attestation)?;
        let registered_value = map_attestation(&registered.attestation)?;
        if embedded != registered_value {
            return Err(WireError::Rights(format!(
                "embedded and registered attestations differ for {reference}"
            )));
        }
        mapped_grants.push(map_grant(grant)?);
    }
    let mut mapped_documents = Vec::with_capacity(rights.document_references.len());
    let mut used_documents = BTreeSet::new();
    for reference in &rights.document_references {
        let document = documents.get(reference.as_str()).ok_or_else(|| {
            WireError::Rights(format!("no typed document reference for {reference}"))
        })?;
        if !used_documents.insert(reference.as_str()) {
            return Err(WireError::Rights(format!(
                "duplicate document reference {reference}"
            )));
        }
        mapped_documents.push(obj(vec![
            ("reference", text(document.reference.clone())),
            ("clause", text(document.clause.clone())),
            ("document_sha256", text(document.document_sha256.clone())),
            (
                "contract_revision",
                text(document.contract_revision.clone()),
            ),
            ("review_authority", text(document.review_authority.clone())),
            ("reviewed_on", text(document.reviewed_on.clone())),
        ]));
    }
    let mut mapped_attestations = Vec::with_capacity(rights.reviewed_attestations.len());
    let mut used_attestations = BTreeSet::new();
    for reference in &rights.reviewed_attestations {
        let attestation = attestations.get(reference.as_str()).ok_or_else(|| {
            WireError::Rights(format!("no registered attestation for {reference}"))
        })?;
        if !used_attestations.insert(reference.as_str()) {
            return Err(WireError::Rights(format!(
                "duplicate attestation reference {reference}"
            )));
        }
        mapped_attestations.push(obj(vec![
            ("attestation_id", text(attestation.attestation_id.clone())),
            ("grant_id", text(attestation.grant_id.clone())),
            ("attestation", map_attestation(&attestation.attestation)?),
        ]));
    }
    if used_grants.len() != grants.len()
        || used_documents.len() != documents.len()
        || used_attestations.len() != attestations.len()
    {
        return Err(WireError::Rights(
            "an evidence detail has no matching reference".to_owned(),
        ));
    }
    Ok(obj(vec![
        ("permission_grants", JcsValue::Array(mapped_grants)),
        ("document_references", JcsValue::Array(mapped_documents)),
        (
            "reviewed_attestations",
            JcsValue::Array(mapped_attestations),
        ),
    ]))
}

fn map_gaps(gaps: &[GapSpec]) -> Result<JcsValue, WireError> {
    let mut mapped = Vec::with_capacity(gaps.len());
    for gap in gaps {
        validate_identifier(&gap.gap_id, "gap_id")?;
        if !["MISSING", "REJECTED", "OTHER"].contains(&gap.gap_kind.as_str()) {
            return Err(WireError::Coverage("invalid gap_kind".to_owned()));
        }
        require_nonempty(&gap.component, "gap.component")?;
        require_nonempty(&gap.description, "gap.description")?;
        mapped.push(obj(vec![
            ("gap_id", text(gap.gap_id.clone())),
            ("gap_kind", text(gap.gap_kind.clone())),
            ("component", text(gap.component.clone())),
            ("count", count(gap.count)),
            ("description", text(gap.description.clone())),
        ]));
    }
    Ok(JcsValue::Array(mapped))
}

fn map_coverage(
    coverage: &crate::distribution::ndc_release::CoverageEvidence,
    evidence: &EvidenceSpec,
    release_as_of_ns: &str,
) -> Result<JcsValue, WireError> {
    if coverage.dimensions.len() != NINE_DIMENSIONS.len() {
        return Err(WireError::Coverage(
            "exactly nine dimensions are required".to_owned(),
        ));
    }
    let mut details: BTreeMap<&str, &CoverageDetailSpec> = BTreeMap::new();
    for detail in &evidence.coverage_details {
        if details
            .insert(detail.dimension_id.as_str(), detail)
            .is_some()
        {
            return Err(WireError::Coverage(format!(
                "duplicate coverage detail {}",
                detail.dimension_id
            )));
        }
    }
    let mut mapped = Vec::with_capacity(coverage.dimensions.len());
    let mut seen = BTreeSet::new();
    for dimension in &coverage.dimensions {
        if !NINE_DIMENSIONS.contains(&dimension.dimension_id.as_str()) {
            return Err(WireError::Coverage(format!(
                "unknown dimension {}",
                dimension.dimension_id
            )));
        }
        if !seen.insert(dimension.dimension_id.as_str()) {
            return Err(WireError::Coverage(format!(
                "duplicate dimension {}",
                dimension.dimension_id
            )));
        }
        let detail = details
            .get(dimension.dimension_id.as_str())
            .ok_or_else(|| {
                WireError::Coverage(format!("no detail for {}", dimension.dimension_id))
            })?;
        if dimension.denominator == 0 {
            return Err(WireError::Coverage(format!(
                "{} has no declared denominator",
                dimension.dimension_id
            )));
        }
        require_nonempty(&detail.denominator_identity, "denominator_identity")?;
        require_nonempty(&detail.count_basis, "count_basis")?;
        require_nonempty(&dimension.evidence_reference, "evidence_reference")?;
        let total = dimension
            .numerator
            .checked_add(detail.missing_count)
            .and_then(|value| value.checked_add(detail.rejected_count))
            .ok_or_else(|| WireError::Coverage("coverage count overflow".to_owned()))?;
        if total != dimension.denominator {
            return Err(WireError::Coverage(format!(
                "{} arithmetic does not decompose its denominator",
                dimension.dimension_id
            )));
        }
        if detail.as_of_ns != release_as_of_ns {
            return Err(WireError::Coverage(format!(
                "{} as-of differs from release as-of",
                dimension.dimension_id
            )));
        }
        parse_decimal(&detail.as_of_ns, "coverage as_of_ns")?;
        if !["PASS", "FAIL", "UNKNOWN"].contains(&dimension.verdict.as_str()) {
            return Err(WireError::Coverage("invalid verdict".to_owned()));
        }
        if dimension.verdict == "PASS"
            && (dimension.numerator != dimension.denominator
                || detail.missing_count != 0
                || detail.rejected_count != 0)
        {
            return Err(WireError::Coverage(format!(
                "{} producer PASS is not admitted by independent evidence",
                dimension.dimension_id
            )));
        }
        validate_identifier(&dimension.universe_id, "universe_id")?;
        mapped.push(obj(vec![
            ("dimension_id", text(dimension.dimension_id.clone())),
            ("universe_id", text(dimension.universe_id.clone())),
            (
                "denominator_identity",
                text(detail.denominator_identity.clone()),
            ),
            ("count_basis", text(detail.count_basis.clone())),
            ("numerator", count(dimension.numerator)),
            ("denominator", count(dimension.denominator)),
            ("missing_count", count(detail.missing_count)),
            ("rejected_count", count(detail.rejected_count)),
            ("as_of_ns", text(detail.as_of_ns.clone())),
            ("verdict", text(dimension.verdict.clone())),
            (
                "evidence_reference",
                text(dimension.evidence_reference.clone()),
            ),
            ("gaps", map_gaps(&detail.gaps)?),
        ]));
    }
    if seen.len() != NINE_DIMENSIONS.len() || details.len() != seen.len() {
        return Err(WireError::Coverage(
            "coverage dimension set is incomplete".to_owned(),
        ));
    }
    Ok(obj(vec![("dimensions", JcsValue::Array(mapped))]))
}

fn map_prov_derived(relation: &ProvDerivedSpec) -> Result<JcsValue, WireError> {
    validate_identifier(&relation.source_entity_id, "source_entity_id")?;
    validate_identifier(&relation.deriving_activity_id, "deriving_activity_id")?;
    Ok(obj(vec![
        ("source_entity_id", text(relation.source_entity_id.clone())),
        (
            "deriving_activity_id",
            text(relation.deriving_activity_id.clone()),
        ),
        (
            "knowledge_time_ns",
            decimal_text(&relation.knowledge_time_ns, "derived knowledge_time_ns")?,
        ),
    ]))
}

fn map_prov_revision(relation: &ProvRevisionSpec) -> Result<JcsValue, WireError> {
    validate_identifier(&relation.predecessor_entity_id, "predecessor_entity_id")?;
    validate_identifier(&relation.revision_activity_id, "revision_activity_id")?;
    Ok(obj(vec![
        (
            "predecessor_entity_id",
            text(relation.predecessor_entity_id.clone()),
        ),
        (
            "revision_activity_id",
            text(relation.revision_activity_id.clone()),
        ),
        (
            "knowledge_time_ns",
            decimal_text(&relation.knowledge_time_ns, "revision knowledge_time_ns")?,
        ),
    ]))
}

fn map_prov_source(relation: &ProvSourceSpec) -> Result<JcsValue, WireError> {
    validate_identifier(&relation.source_entity_id, "primary source_entity_id")?;
    validate_identifier(&relation.attribution_activity_id, "attribution_activity_id")?;
    Ok(obj(vec![
        ("source_entity_id", text(relation.source_entity_id.clone())),
        (
            "attribution_activity_id",
            text(relation.attribution_activity_id.clone()),
        ),
        (
            "knowledge_time_ns",
            decimal_text(&relation.knowledge_time_ns, "source knowledge_time_ns")?,
        ),
    ]))
}

fn map_attribution(relation: &QualifiedAttributionSpec) -> Result<JcsValue, WireError> {
    validate_identifier(&relation.agent_id, "agent_id")?;
    validate_identifier(&relation.activity_id, "activity_id")?;
    require_nonempty(&relation.role, "attribution role")?;
    Ok(obj(vec![
        ("agent_id", text(relation.agent_id.clone())),
        ("activity_id", text(relation.activity_id.clone())),
        ("role", text(relation.role.clone())),
        (
            "knowledge_time_ns",
            decimal_text(&relation.knowledge_time_ns, "attribution knowledge_time_ns")?,
        ),
    ]))
}

fn map_lineage(
    lineage: &crate::distribution::ndc_release::Lineage,
    evidence: &EvidenceSpec,
    release_id: &str,
    as_of_ns: &str,
) -> Result<JcsValue, WireError> {
    require_nonempty(&lineage.raw_archive_reference, "raw_archive_reference")?;
    validate_sha256_hex(&lineage.raw_archive_sha256, "raw_archive_sha256")?;
    validate_identifier(&evidence.transformation_identity, "transformation identity")?;
    require_nonempty(&evidence.transformation_version, "transformation version")?;
    let knowledge = parse_decimal(&lineage.knowledge_time_ns, "lineage.knowledge_time_ns")?;
    let as_of = parse_decimal(as_of_ns, "release as_of_ns")?;
    if knowledge > as_of {
        return Err(WireError::Lineage(
            "knowledge time is after release as-of".to_owned(),
        ));
    }
    validate_utc_instant(&evidence.generated_at_time, "generated_at_time")?;
    validate_utc_instant(&evidence.invalidated_at_time, "lineage.invalidated_at_time")?;
    let supersedes = match &lineage.supersedes {
        None => JcsValue::Null,
        Some(predecessor) => {
            validate_identifier(&predecessor.supersedes_release_id, "supersedes_release_id")?;
            if predecessor.supersedes_release_id == release_id {
                return Err(WireError::Lineage(
                    "release supplies its own predecessor".to_owned(),
                ));
            }
            validate_sha256_hex(
                &predecessor.supersedes_manifest_sha256,
                "supersedes_manifest_sha256",
            )?;
            validate_sha256_hex(
                &predecessor.supersedes_data_sha256,
                "supersedes_data_sha256",
            )?;
            require_nonempty(&predecessor.correction_reason, "correction_reason")?;
            parse_decimal(
                &predecessor.knowledge_time_ns,
                "supersedes.knowledge_time_ns",
            )?;
            validate_utc_instant(
                &predecessor.invalidated_at_time,
                "supersedes.invalidated_at_time",
            )?;
            if predecessor.revision >= lineage.revision {
                return Err(WireError::Lineage(format!(
                    "predecessor revision {} is not strictly below {}",
                    predecessor.revision, lineage.revision
                )));
            }
            if predecessor.revision != lineage.revision.saturating_sub(1) {
                return Err(WireError::Lineage(
                    "predecessor is not the immediate predecessor".to_owned(),
                ));
            }
            obj(vec![
                (
                    "supersedes_release_id",
                    text(predecessor.supersedes_release_id.clone()),
                ),
                (
                    "supersedes_manifest_sha256",
                    text(predecessor.supersedes_manifest_sha256.clone()),
                ),
                (
                    "supersedes_data_sha256",
                    text(predecessor.supersedes_data_sha256.clone()),
                ),
                (
                    "revision",
                    JcsValue::Integer(i64::try_from(predecessor.revision).map_err(|_| {
                        WireError::Lineage("predecessor revision exceeds i64".to_owned())
                    })?),
                ),
                (
                    "correction_reason",
                    text(predecessor.correction_reason.clone()),
                ),
                (
                    "knowledge_time_ns",
                    text(predecessor.knowledge_time_ns.clone()),
                ),
                (
                    "invalidated_at_time",
                    text(predecessor.invalidated_at_time.clone()),
                ),
            ])
        }
    };
    let revision = i64::try_from(lineage.revision)
        .map_err(|_| WireError::Lineage("revision exceeds i64".to_owned()))?;
    Ok(obj(vec![
        (
            "raw_archive_reference",
            text(lineage.raw_archive_reference.clone()),
        ),
        (
            "raw_archive_sha256",
            text(lineage.raw_archive_sha256.clone()),
        ),
        (
            "transformation_record",
            obj(vec![
                ("identity", text(evidence.transformation_identity.clone())),
                ("version", text(evidence.transformation_version.clone())),
            ]),
        ),
        ("knowledge_time_ns", text(lineage.knowledge_time_ns.clone())),
        ("revision", JcsValue::Integer(revision)),
        (
            "was_derived_from",
            map_prov_derived(&evidence.prov.was_derived_from)?,
        ),
        (
            "was_revision_of",
            map_prov_revision(&evidence.prov.was_revision_of)?,
        ),
        (
            "had_primary_source",
            map_prov_source(&evidence.prov.had_primary_source)?,
        ),
        (
            "generated_at_time",
            text(evidence.generated_at_time.clone()),
        ),
        (
            "invalidated_at_time",
            text(evidence.invalidated_at_time.clone()),
        ),
        (
            "qualified_attribution",
            map_attribution(&evidence.prov.qualified_attribution)?,
        ),
        ("supersedes", supersedes),
    ]))
}

fn map_schema_versions(
    versions: &crate::distribution::ndc_release::SchemaVersions,
    evidence: &EvidenceSpec,
    manifest_contract_version: &str,
    observed_event_types: &BTreeSet<String>,
) -> Result<JcsValue, WireError> {
    if versions.contract_version != manifest_contract_version {
        return Err(WireError::Spec(
            "contract_version occurs with two values".to_owned(),
        ));
    }
    require_nonempty(&versions.normalizer_version, "normalizer_version")?;
    require_nonempty(&versions.envelope_version, "envelope_version")?;
    let mut registered = BTreeSet::new();
    let mut entries = Vec::with_capacity(evidence.payload_schemas.len());
    for entry in &evidence.payload_schemas {
        validate_identifier(&entry.event_type, "payload registry event_type")?;
        validate_identifier(&entry.schema_id, "payload schema_id")?;
        require_nonempty(&entry.schema_version, "payload schema_version")?;
        validate_sha256_hex(&entry.digest_sha256, "payload schema digest_sha256")?;
        if !registered.insert(entry.event_type.as_str()) {
            return Err(WireError::PayloadRegistry(format!(
                "duplicate registry entry {}",
                entry.event_type
            )));
        }
        entries.push(obj(vec![
            ("event_type", text(entry.event_type.clone())),
            ("schema_id", text(entry.schema_id.clone())),
            ("schema_version", text(entry.schema_version.clone())),
            ("digest_sha256", text(entry.digest_sha256.clone())),
        ]));
    }
    for event_type in observed_event_types {
        if !registered.contains(event_type.as_str()) {
            return Err(WireError::PayloadRegistry(format!(
                "no registered payload schema for {event_type}"
            )));
        }
    }
    Ok(obj(vec![
        (
            "normalizer_version",
            text(versions.normalizer_version.clone()),
        ),
        ("envelope_version", text(versions.envelope_version.clone())),
        ("payload_schemas", JcsValue::Array(entries)),
    ]))
}

fn validate_compression_pair(compression: &str, version: &str) -> Result<(), WireError> {
    let valid = matches!(
        (compression, version),
        ("none", COMPRESSION_VERSION_NONE) | ("gzip", COMPRESSION_VERSION_GZIP)
    );
    if !valid {
        return Err(WireError::Compression(format!(
            "{compression} with {version} is not a registered pair"
        )));
    }
    Ok(())
}

fn map_artifact(descriptor: &ArtifactDescriptor) -> Result<JcsValue, WireError> {
    validate_identifier(&descriptor.logical_partition_id, "logical_partition_id")?;
    validate_artifact_path(&descriptor.path)?;
    if descriptor.encoding != ENCODING_NDJSON {
        return Err(WireError::Spec(
            "artifact encoding is not registered".to_owned(),
        ));
    }
    validate_compression_pair(&descriptor.compression, &descriptor.compression_version)?;
    validate_sha256_hex(&descriptor.stored_sha256, "stored_sha256")?;
    validate_sha256_hex(&descriptor.uncompressed_sha256, "uncompressed_sha256")?;
    let profile = match map_artifact_profile(&descriptor.record_order_profile)? {
        WireArtifactProfile::Sequenced {
            sequence_domain_id,
            sequence_epoch,
        } => obj(vec![
            ("kind", text("sequenced")),
            ("sequence_domain_id", text(sequence_domain_id)),
            ("sequence_epoch", text(sequence_epoch)),
        ]),
        WireArtifactProfile::Reference => obj(vec![("kind", text("reference"))]),
    };
    Ok(obj(vec![
        (
            "logical_partition_id",
            text(descriptor.logical_partition_id.clone()),
        ),
        (
            "shard_ordinal",
            JcsValue::Integer(i64::from(descriptor.shard_ordinal)),
        ),
        ("path", text(descriptor.path.clone())),
        ("record_order_profile", profile),
        ("encoding", text(descriptor.encoding.clone())),
        ("compression", text(descriptor.compression.clone())),
        (
            "compression_version",
            text(descriptor.compression_version.clone()),
        ),
        ("stored_bytes", count(descriptor.stored_bytes)),
        ("stored_sha256", text(descriptor.stored_sha256.clone())),
        ("uncompressed_bytes", count(descriptor.uncompressed_bytes)),
        (
            "uncompressed_sha256",
            text(descriptor.uncompressed_sha256.clone()),
        ),
        ("record_count", count(descriptor.record_count)),
    ]))
}

/// Map a complete internal manifest and its abstract evidence supplement to
/// the canonical wire manifest value. The dataset digest is always supplied
/// by the caller from computed artifact bytes and never read from the internal
/// placeholder.
pub fn map_manifest(
    manifest: &crate::distribution::ndc_release::ReleaseManifest,
    evidence: &EvidenceSpec,
    data_sha256: &str,
    observed_event_types: &BTreeSet<String>,
) -> Result<JcsValue, WireError> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION || WIRE_SCHEMA_VERSION != 1 {
        return Err(WireError::Spec("unregistered schema version".to_owned()));
    }
    if manifest.contract_version != CONTRACT_VERSION {
        return Err(WireError::Spec("unregistered contract version".to_owned()));
    }
    require_nonempty(&manifest.contract_revision, "contract_revision")?;
    if manifest.digests.digest_algorithm != DIGEST_ALGORITHM {
        return Err(WireError::Spec("unregistered digest algorithm".to_owned()));
    }
    validate_sha256_hex(data_sha256, "computed data_sha256")?;
    let publication = &manifest.publication_identity;
    validate_identifier(&publication.publisher_identity, "publisher_identity")?;
    validate_identifier(&publication.signing_key_id, "signing_key_id")?;
    if publication.signature_reference != SIDECAR_FILE_NAME {
        return Err(WireError::Spec(
            "signature_reference is not signature.json".to_owned(),
        ));
    }
    require_nonempty(&publication.archive_reference, "archive_reference")?;
    if manifest.artifacts.is_empty() {
        return Err(WireError::Spec("no artifacts declared".to_owned()));
    }
    let mut positions = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut mapped_artifacts = Vec::with_capacity(manifest.artifacts.len());
    for descriptor in &manifest.artifacts {
        let position = (
            descriptor.logical_partition_id.as_str(),
            descriptor.shard_ordinal,
        );
        if !positions.insert(position) {
            return Err(WireError::Spec("duplicate artifact position".to_owned()));
        }
        if !paths.insert(descriptor.path.as_str()) {
            return Err(WireError::Spec("duplicate artifact path".to_owned()));
        }
        mapped_artifacts.push(map_artifact(descriptor)?);
    }
    Ok(obj(vec![
        (
            "schema_version",
            JcsValue::Integer(i64::from(WIRE_SCHEMA_VERSION)),
        ),
        ("contract_version", text(CONTRACT_VERSION)),
        (
            "contract_revision",
            text(manifest.contract_revision.clone()),
        ),
        (
            "release_identity",
            map_release_identity(&manifest.release_identity)?,
        ),
        ("source_scope", map_source_scope(&manifest.source_scope)?),
        (
            "producer_activity",
            map_producer_activity(&manifest.producer_activity, evidence)?,
        ),
        ("rights", map_rights(&manifest.rights, evidence)?),
        (
            "coverage",
            map_coverage(
                &manifest.coverage,
                evidence,
                &manifest.release_identity.as_of_ns,
            )?,
        ),
        (
            "lineage",
            map_lineage(
                &manifest.lineage,
                evidence,
                &manifest.release_identity.release_id,
                &manifest.release_identity.as_of_ns,
            )?,
        ),
        (
            "schema_versions",
            map_schema_versions(
                &manifest.schema_versions,
                evidence,
                &manifest.contract_version,
                observed_event_types,
            )?,
        ),
        (
            "digests",
            obj(vec![
                ("digest_algorithm", text(DIGEST_ALGORITHM)),
                ("data_sha256", text(data_sha256)),
            ]),
        ),
        (
            "publication_identity",
            obj(vec![
                (
                    "publisher_identity",
                    text(publication.publisher_identity.clone()),
                ),
                ("signing_key_id", text(publication.signing_key_id.clone())),
                (
                    "signature_reference",
                    text(publication.signature_reference.clone()),
                ),
                (
                    "archive_reference",
                    text(publication.archive_reference.clone()),
                ),
            ]),
        ),
        ("artifacts", JcsValue::Array(mapped_artifacts)),
    ]))
}

fn validate_tagged_shape(
    value: &JcsValue,
    path: &str,
    sequenced: &[&str],
    reference: &[&str],
) -> Result<(), WireError> {
    let JcsValue::Object(entries) = value else {
        return Err(WireError::WrongType(
            path.to_owned(),
            "tagged object".to_owned(),
        ));
    };
    let kind = entries.iter().find(|(name, _)| name == "kind");
    let Some((_, JcsValue::String(kind))) = kind else {
        return Err(WireError::Spec(format!("{path} has no string kind")));
    };
    let allowed = match kind.as_str() {
        "sequenced" => sequenced,
        "reference" => reference,
        other => return Err(WireError::Spec(format!("{path} has unknown kind {other}"))),
    };
    strict_object(value, path, allowed, allowed)?;
    Ok(())
}

fn validate_spec_shape(text: &str) -> Result<(), WireError> {
    let value = parse_jcs_value(text).map_err(|error| WireError::InvalidJson(error.to_string()))?;
    let root = strict_object(
        &value,
        "spec",
        &["spec_version", "note", "manifest", "evidence", "artifacts"],
        &["spec_version", "note", "manifest", "evidence", "artifacts"],
    )?;
    let JcsValue::Array(artifacts) = root["artifacts"] else {
        return Err(WireError::WrongType(
            "spec.artifacts".to_owned(),
            "array".to_owned(),
        ));
    };
    for (index, artifact) in artifacts.iter().enumerate() {
        let path = format!("spec.artifacts[{index}]");
        let fields = strict_object(
            artifact,
            &path,
            &[
                "logical_partition_id",
                "shard_ordinal",
                "path",
                "record_order_profile",
                "encoding",
                "compression",
                "records",
            ],
            &[
                "logical_partition_id",
                "shard_ordinal",
                "path",
                "record_order_profile",
                "encoding",
                "compression",
                "records",
            ],
        )?;
        validate_tagged_shape(
            fields["record_order_profile"],
            &format!("{path}.record_order_profile"),
            &["kind", "sequence_domain_id", "sequence_epoch"],
            &["kind"],
        )?;
        let JcsValue::Array(records) = fields["records"] else {
            return Err(WireError::WrongType(
                format!("{path}.records"),
                "array".to_owned(),
            ));
        };
        for (record_index, record) in records.iter().enumerate() {
            let record_path = format!("{path}.records[{record_index}]");
            let members = strict_object(
                record,
                &record_path,
                &["bytes", "claimed_order_key"],
                &["bytes", "claimed_order_key"],
            )?;
            validate_tagged_shape(
                members["claimed_order_key"],
                &format!("{record_path}.claimed_order_key"),
                &[
                    "kind",
                    "sequence_domain_id",
                    "sequence_epoch",
                    "sequence_number",
                ],
                &[
                    "kind",
                    "object_id",
                    "revision",
                    "knowledge_time_ns",
                    "assertion_id",
                ],
            )?;
        }
    }
    Ok(())
}

/// Parse and shape-check an abstract conformance spec.
pub fn parse_conformance_spec(text: &str) -> Result<ConformanceSpec, WireError> {
    validate_spec_shape(text)?;
    let spec: ConformanceSpec =
        serde_json::from_str(text).map_err(|error| WireError::InvalidJson(error.to_string()))?;
    if spec.spec_version != WIRE_SCHEMA_VERSION {
        return Err(WireError::Spec("unregistered spec version".to_owned()));
    }
    require_nonempty(&spec.note, "spec note")?;
    if spec.artifacts.len() < 2 {
        return Err(WireError::Spec(
            "a conformance spec needs two artifacts".to_owned(),
        ));
    }
    let mut profiles = BTreeSet::new();
    let mut compressed = false;
    for artifact in &spec.artifacts {
        if artifact.records.len() < 2 {
            return Err(WireError::Spec(
                "each artifact needs multiple records".to_owned(),
            ));
        }
        profiles.insert(artifact.record_order_profile.kind());
        if artifact.compression == "gzip" {
            compressed = true;
        }
    }
    if profiles.len() != 2 || !compressed {
        return Err(WireError::Spec(
            "a conformance spec needs both profiles and one gzip artifact".to_owned(),
        ));
    }
    Ok(spec)
}

/// Prepare one abstract artifact: byte-derived sort, canonical stream,
/// registered compression and computed descriptor.
pub fn prepare_artifact(
    artifact: &SpecArtifact,
    policy: &ResourcePolicy,
) -> Result<PreparedArtifact, WireError> {
    validate_identifier(&artifact.logical_partition_id, "logical_partition_id")?;
    validate_artifact_path(&artifact.path)?;
    if artifact.encoding != ENCODING_NDJSON {
        return Err(WireError::Spec(
            "artifact encoding is not registered".to_owned(),
        ));
    }
    let internal_profile = artifact.record_order_profile.to_internal()?;
    let profile = map_artifact_profile(&internal_profile)?;
    let (compression, version) = match artifact.compression.as_str() {
        "none" => (ArtifactCompression::None, COMPRESSION_VERSION_NONE),
        "gzip" => (ArtifactCompression::Gzip, COMPRESSION_VERSION_GZIP),
        other => return Err(WireError::Compression(other.to_owned())),
    };
    validate_compression_pair(compression.as_str(), version)?;
    let mut records = Vec::with_capacity(artifact.records.len());
    for record in &artifact.records {
        records.push(CanonicalRecord {
            bytes: record.bytes.as_bytes().to_vec(),
            order_key: record.claimed_order_key.to_untrusted_internal()?,
        });
    }
    let ordered_records = sort_byte_derived(&records, &profile, policy)?;
    let mut event_types = BTreeSet::new();
    for bytes in &ordered_records {
        let parsed = parse_canonical_record(bytes, policy)?;
        event_types.insert(parsed.event_type);
    }
    let mut uncompressed = Vec::new();
    for bytes in &ordered_records {
        uncompressed.extend_from_slice(bytes);
        uncompressed.push(b'\n');
    }
    let uncompressed_len = u64::try_from(uncompressed.len())
        .map_err(|_| WireError::Policy("uncompressed length".to_owned()))?;
    if uncompressed_len > policy.max_uncompressed_bytes_per_artifact {
        return Err(WireError::Policy(
            "uncompressed artifact bound exceeded".to_owned(),
        ));
    }
    let stored = match compression {
        ArtifactCompression::None => uncompressed.clone(),
        ArtifactCompression::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), GzipCompression::default());
            encoder
                .write_all(&uncompressed)
                .map_err(|error| WireError::Io("gzip record stream".to_owned(), error))?;
            encoder
                .finish()
                .map_err(|error| WireError::Io("finalize gzip stream".to_owned(), error))?
        }
    };
    let stored_len =
        u64::try_from(stored.len()).map_err(|_| WireError::Policy("stored length".to_owned()))?;
    if stored_len > policy.max_stored_bytes_per_artifact {
        return Err(WireError::Policy(
            "stored artifact bound exceeded".to_owned(),
        ));
    }
    let descriptor = ArtifactDescriptor {
        logical_partition_id: artifact.logical_partition_id.clone(),
        shard_ordinal: artifact.shard_ordinal,
        path: artifact.path.clone(),
        record_order_profile: internal_profile,
        encoding: artifact.encoding.clone(),
        compression: compression.as_str().to_owned(),
        compression_version: version.to_owned(),
        stored_bytes: stored_len,
        stored_sha256: sha256_hex(&stored),
        uncompressed_bytes: uncompressed_len,
        uncompressed_sha256: sha256_hex(&uncompressed),
        record_count: u64::try_from(ordered_records.len())
            .map_err(|_| WireError::Policy("record count".to_owned()))?,
    };
    Ok(PreparedArtifact {
        stored_bytes: stored,
        uncompressed_bytes: uncompressed,
        descriptor,
        ordered_records,
        event_types,
    })
}

/// Compute the dataset digest over uncompressed streams in canonical artifact
/// order. Declared compression changes neither this digest nor its order.
pub fn dataset_digest(artifacts: &[PreparedArtifact]) -> String {
    let mut hasher = Sha256::new();
    for artifact in artifacts {
        hasher.update(&artifact.uncompressed_bytes);
    }
    crate::distribution::ndc_release::hex_encode(&hasher.finalize())
}

/// Sign the exact canonical manifest bytes with an injected key. The domain
/// prefix and digest binding are those of the ratified sidecar contract.
pub fn sign_manifest(
    manifest_bytes: &[u8],
    signing: &SigningKey,
    verifying: &VerifyingKey,
) -> Result<[u8; 64], WireError> {
    let digest = Sha256::digest(manifest_bytes);
    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + digest.len());
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(&digest);
    let signature = signing.sign(&message);
    verifying
        .verify(&message, &signature)
        .map_err(|_| WireError::Signature("injected key self-check failed".to_owned()))?;
    Ok(signature.to_bytes())
}

/// Build the exactly five-member sidecar with a single trailing line feed.
pub fn sidecar_bytes(
    key_id: &str,
    manifest_sha256: &str,
    signature: &[u8; 64],
    policy: &ResourcePolicy,
) -> Result<Vec<u8>, WireError> {
    validate_identifier(key_id, "sidecar key_id")?;
    validate_sha256_hex(manifest_sha256, "sidecar manifest_sha256")?;
    let sidecar = obj(vec![
        (
            "schema_version",
            JcsValue::Integer(i64::from(SIDECAR_SCHEMA_VERSION)),
        ),
        ("algorithm", text(SIGNATURE_ALGORITHM)),
        ("key_id", text(key_id)),
        ("manifest_sha256", text(manifest_sha256)),
        ("signature_b64", text(BASE64.encode(signature))),
    ]);
    let mut bytes = canonicalize_strict(&sidecar, policy)
        .map_err(|error| WireError::Canonicalization(error.to_string()))?;
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).map_err(|_| WireError::Policy("sidecar length".to_owned()))?
        > policy.max_sidecar_bytes
    {
        return Err(WireError::Policy("sidecar bound exceeded".to_owned()));
    }
    Ok(bytes)
}

/// Write one complete release directory from validated wire bytes. Files are
/// created exclusively; no existing release name is overwritten.
pub fn write_release(
    out: &Path,
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    artifacts: &[PreparedArtifact],
) -> Result<(), WireError> {
    fs::create_dir(out)
        .map_err(|error| WireError::Io(format!("create {}", out.display()), error))?;
    let manifest_path = out.join(crate::distribution::ndc_release::MANIFEST_FILE_NAME);
    let sidecar_path = out.join(SIDECAR_FILE_NAME);
    write_new(&manifest_path, manifest_bytes)?;
    write_new(&sidecar_path, signature_bytes)?;
    let artifact_root = out.join(crate::distribution::ndc_release::ARTIFACT_DIRECTORY);
    fs::create_dir(&artifact_root)
        .map_err(|error| WireError::Io(format!("create {}", artifact_root.display()), error))?;
    for artifact in artifacts {
        let path = artifact_root.join(
            artifact
                .descriptor
                .path
                .strip_prefix("artifacts/")
                .ok_or_else(|| WireError::ArtifactPath(artifact.descriptor.path.clone()))?,
        );
        write_new(&path, &artifact.stored_bytes)?;
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), WireError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| WireError::Io(format!("create {}", path.display()), error))?;
    file.write_all(bytes)
        .map_err(|error| WireError::Io(format!("write {}", path.display()), error))?;
    file.sync_all()
        .map_err(|error| WireError::Io(format!("sync {}", path.display()), error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;
    use std::str;

    use ed25519_dalek::SigningKey;
    use serde_json::Value as JsonValue;

    use super::*;

    type TestResult = Result<(), Box<dyn StdError>>;

    const SPEC: &str = include_str!(
        "../../docs/specifications/ndc-conformance-producer-spec-example-2026-11-24.json"
    );

    fn policy() -> ResourcePolicy {
        ResourcePolicy {
            max_manifest_bytes: 1_000_000,
            max_artifact_count: 8,
            max_stored_bytes_per_artifact: 100_000,
            max_uncompressed_bytes_per_artifact: 100_000,
            max_total_stored_bytes: 1_000_000,
            max_total_uncompressed_bytes: 1_000_000,
            max_record_bytes: 4_096,
            max_records_per_artifact: 100,
            max_path_component_bytes: 128,
            max_nesting_depth: 32,
            max_object_members: 64,
            max_array_elements: 64,
            max_sidecar_bytes: 4_096,
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&CONFORMANCE_SIGNING_SEED)
    }

    fn spec() -> ConformanceSpec {
        parse_conformance_spec(SPEC).expect("example spec parses")
    }

    fn mutated(mutate: impl FnOnce(&mut JsonValue)) -> Result<ConformanceSpec, WireError> {
        let mut value: JsonValue = serde_json::from_str(SPEC).expect("example is JSON");
        mutate(&mut value);
        parse_conformance_spec(&value.to_string())
    }

    fn build(spec: &ConformanceSpec) -> Result<(ReleaseBytes, Vec<PreparedArtifact>), WireError> {
        let signing = key();
        build_conformance_release(spec, &policy(), &signing, &signing.verifying_key())
    }

    fn manifest_value(release: &ReleaseBytes) -> JcsValue {
        let text = str::from_utf8(&release.manifest_bytes).expect("canonical manifest is UTF-8");
        parse_jcs_value(text).expect("canonical manifest parses")
    }

    fn members<'a>(value: &'a JcsValue, path: &str) -> BTreeMap<&'a str, &'a JcsValue> {
        let allowed: Vec<String> = match value {
            JcsValue::Object(entries) => entries.iter().map(|(name, _)| name.clone()).collect(),
            _ => Vec::new(),
        };
        let names: Vec<&str> = allowed.iter().map(String::as_str).collect();
        strict_object(value, path, &names, &names).expect("object has a closed member set")
    }

    fn string_member<'a>(value: &'a BTreeMap<&'a str, &'a JcsValue>, name: &str) -> &'a str {
        match value.get(name) {
            Some(JcsValue::String(text)) => text,
            _ => panic!("member {name} is a string"),
        }
    }

    fn jcs_of(value: &JsonValue) -> String {
        let parsed = parse_jcs_value(&value.to_string()).expect("JSON value parses");
        let bytes = canonicalize_strict(&parsed, &policy()).expect("value canonicalizes");
        String::from_utf8(bytes).expect("canonical bytes are UTF-8")
    }

    fn artifact_index(artifacts: &[PreparedArtifact], compression: &str) -> usize {
        artifacts
            .iter()
            .position(|item| item.descriptor.compression == compression)
            .expect("artifact with requested compression")
    }

    #[test]
    fn example_spec_maps_to_canonical_manifest() -> TestResult {
        let (release, _) = build(&spec())?;
        let manifest = manifest_value(&release);
        let root = members(&manifest, "root");
        assert_eq!(root.len(), 13, "expected root.len() to equal 13");
        assert_eq!(
            string_member(&root, "contract_version"),
            "v2",
            "expected string_member(&root, \"contract_version\") to equal \"v2\""
        );
        assert!(
            !root.contains_key("limits"),
            "asserted condition: !root.contains_key(\"limits\")"
        );
        assert!(
            !root.contains_key("manifest_sha256"),
            "asserted condition: !root.contains_key(\"manifest_sha256\")"
        );
        Ok(())
    }

    #[test]
    fn single_root_contract_version_only() -> TestResult {
        let (release, _) = build(&spec())?;
        let manifest = manifest_value(&release);
        let root = members(&manifest, "root");
        let versions = members(root["schema_versions"], "schema_versions");
        assert_eq!(versions.len(), 3, "expected versions.len() to equal 3");
        assert!(
            !versions.contains_key("contract_version"),
            "asserted condition: !versions.contains_key(\"contract_version\")"
        );
        assert!(
            !versions.contains_key("payload_schema_version"),
            "asserted condition: !versions.contains_key(\"payload_schema_version\")"
        );
        Ok(())
    }

    #[test]
    fn decimal_instants_are_strings_with_ratified_grammar() -> TestResult {
        let (release, _) = build(&spec())?;
        let manifest = manifest_value(&release);
        let root = members(&manifest, "root");
        let identity = members(root["release_identity"], "release_identity");
        for name in ["as_of_ns", "created_at_utc_ns"] {
            let value = string_member(&identity, name);
            assert!(
                value.bytes().all(|byte| byte.is_ascii_digit()),
                "asserted condition: value.bytes().all(|byte| byte.is_ascii_digit())"
            );
            assert_eq!(
                parse_decimal(value, name)?,
                value.parse::<u64>()?,
                "expected parse_decimal(value, name)? to equal value.parse::<u64>()?"
            );
        }
        Ok(())
    }

    #[test]
    fn decimal_instant_rejects_leading_zero() {
        let error = mutated(|value| {
            value["manifest"]["release_identity"]["as_of_ns"] = JsonValue::from("0200");
        })
        .and_then(|spec| build(&spec))
        .expect_err("leading zero must fail");
        assert!(
            error.to_string().contains("decimal") || error.to_string().contains("lineage"),
            "asserted condition: error.to_string().contains(\"decimal\") || error.to_string().contains(\"lineage\")"
        );
    }

    #[test]
    fn decimal_instant_rejects_integer_type() {
        let error = mutated(|value| {
            value["manifest"]["release_identity"]["as_of_ns"] = JsonValue::from(200);
        })
        .expect_err("integer instant must fail");
        assert!(
            error.to_string().contains("invalid JSON")
                || error.to_string().contains("invalid conformance spec"),
            "asserted condition: error.to_string().contains(\"invalid JSON\") || error.to_string().contains(\"invalid conformance spec\")"
        );
    }

    #[test]
    fn required_scope_rejects_absent_venue() {
        let error = mutated(|value| {
            value["manifest"]["source_scope"]
                .as_object_mut()
                .expect("scope object")
                .remove("venue_id");
        })
        .and_then(|spec| build(&spec))
        .expect_err("venue is required");
        assert!(
            error.to_string().contains("venue_id"),
            "asserted condition: error.to_string().contains(\"venue_id\")"
        );
    }

    #[test]
    fn required_scope_rejects_null_segment() {
        let error = mutated(|value| {
            value["manifest"]["source_scope"]["segment_id"] = JsonValue::Null;
        })
        .and_then(|spec| build(&spec))
        .expect_err("null segment must fail");
        assert!(
            error.to_string().contains("segment_id"),
            "asserted condition: error.to_string().contains(\"segment_id\")"
        );
    }

    #[test]
    fn required_scope_rejects_placeholder_provider() {
        let error = mutated(|value| {
            value["manifest"]["source_scope"]["provider_id"] = JsonValue::from("UNKNOWN");
        })
        .and_then(|spec| build(&spec))
        .expect_err("placeholder must fail");
        assert!(
            error.to_string().contains("identifier"),
            "asserted condition: error.to_string().contains(\"identifier\")"
        );
    }

    #[test]
    fn unknown_spec_field_rejected() {
        let error = mutated(|value| {
            value["unexpected"] = JsonValue::from("abstract");
        })
        .expect_err("unknown spec member must fail");
        assert!(
            error.to_string().contains("unknown field"),
            "asserted condition: error.to_string().contains(\"unknown field\")"
        );
    }

    #[test]
    fn unknown_record_field_rejected() -> TestResult {
        let mut value: JsonValue = serde_json::from_str(SPEC)?;
        let record: JsonValue = serde_json::from_str(
            value["artifacts"][0]["records"][0]["bytes"]
                .as_str()
                .expect("record text"),
        )?;
        let mut record = record;
        record["unexpected"] = JsonValue::from("abstract");
        value["artifacts"][0]["records"][0]["bytes"] = JsonValue::from(jcs_of(&record));
        let parsed = parse_conformance_spec(&value.to_string())?;
        let error = build(&parsed).expect_err("unknown record field must fail");
        assert!(
            error.to_string().contains("unknown field"),
            "asserted condition: error.to_string().contains(\"unknown field\")"
        );
        Ok(())
    }

    #[test]
    fn non_canonical_record_bytes_rejected() {
        let mut value: JsonValue = serde_json::from_str(SPEC).expect("spec is JSON");
        let bytes = value["artifacts"][0]["records"][0]["bytes"]
            .as_str()
            .expect("record text")
            .to_owned();
        value["artifacts"][0]["records"][0]["bytes"] = JsonValue::from(bytes.replace(',', ", "));
        let parsed = parse_conformance_spec(&value.to_string()).expect("shape remains valid");
        let error = build(&parsed).expect_err("non-canonical bytes must fail");
        assert!(
            error.to_string().contains("non-canonical"),
            "asserted condition: error.to_string().contains(\"non-canonical\")"
        );
    }

    #[test]
    fn tagged_record_union_rejects_both_modes() -> TestResult {
        let spec: JsonValue = serde_json::from_str(SPEC)?;
        let mut record: JsonValue = serde_json::from_str(
            spec["artifacts"][0]["records"][0]["bytes"]
                .as_str()
                .expect("record text"),
        )?;
        record["ordering"]["object_id"] = JsonValue::from("object-abstract");
        let canonical = jcs_of(&record);
        let error =
            parse_canonical_record(canonical.as_bytes(), &policy()).expect_err("both modes fail");
        assert!(
            error.to_string().contains("ordering"),
            "asserted condition: error.to_string().contains(\"ordering\")"
        );
        Ok(())
    }

    #[test]
    fn reference_profile_rejects_domain_member() {
        let error = mutated(|value| {
            value["artifacts"][1]["record_order_profile"]["sequence_domain_id"] =
                JsonValue::from("domain-abstract");
        })
        .expect_err("reference profile has no domain");
        assert!(
            error.to_string().contains("unknown field"),
            "asserted condition: error.to_string().contains(\"unknown field\")"
        );
    }

    #[test]
    fn byte_derived_order_ignores_caller_key() -> TestResult {
        let spec = spec();
        let (_, artifacts) = build(&spec)?;
        let sequenced = &artifacts[artifact_index(&artifacts, "none")];
        let first = str::from_utf8(&sequenced.ordered_records[0])?;
        let second = str::from_utf8(&sequenced.ordered_records[1])?;
        assert!(
            first.contains("abstract-value-3"),
            "key 3 sorts before key 7"
        );
        assert!(
            second.contains("abstract-value-7"),
            "asserted condition: second.contains(\"abstract-value-7\")"
        );
        let claimed_first = &spec.artifacts[0].records[0].claimed_order_key;
        let ClaimedKey::Sequenced {
            sequence_number, ..
        } = claimed_first
        else {
            return Err("expected a sequenced claim".into());
        };
        assert_eq!(
            sequence_number, "9",
            "expected sequence_number to equal \"9\""
        );
        Ok(())
    }

    #[test]
    fn reference_order_derives_from_parsed_bytes() -> TestResult {
        let (_, artifacts) = build(&spec())?;
        let reference = &artifacts[artifact_index(&artifacts, "gzip")];
        let first = str::from_utf8(&reference.ordered_records[0])?;
        let second = str::from_utf8(&reference.ordered_records[1])?;
        assert!(
            first.contains("object-abstract-a"),
            "asserted condition: first.contains(\"object-abstract-a\")"
        );
        assert!(
            second.contains("object-abstract-b"),
            "asserted condition: second.contains(\"object-abstract-b\")"
        );
        Ok(())
    }

    #[test]
    fn record_mode_must_match_artifact_profile() -> TestResult {
        let mut value: JsonValue = serde_json::from_str(SPEC)?;
        let sequenced_bytes = value["artifacts"][0]["records"][0]["bytes"]
            .as_str()
            .expect("record text")
            .to_owned();
        value["artifacts"][1]["records"][0]["bytes"] = JsonValue::from(sequenced_bytes);
        let parsed = parse_conformance_spec(&value.to_string())?;
        let error = build(&parsed).expect_err("sequenced record in reference artifact must fail");
        assert!(
            error.to_string().contains("ordering"),
            "asserted condition: error.to_string().contains(\"ordering\")"
        );
        Ok(())
    }

    #[test]
    fn duplicate_derived_key_with_conflicting_payload_rejected() -> TestResult {
        let value: JsonValue = serde_json::from_str(SPEC)?;
        let first = value["artifacts"][0]["records"][0]["bytes"]
            .as_str()
            .expect("first record")
            .to_owned();
        let second = value["artifacts"][0]["records"][1]["bytes"]
            .as_str()
            .expect("second record")
            .to_owned();
        let same_key = first
            .replace("\"7\"", "\"3\"")
            .replace("abstract-value-7", "abstract-value-3");
        assert_eq!(same_key, second, "expected same_key to equal second");
        let claimed = |number: u64| RecordOrderKey::Sequenced {
            sequence_domain: "domain-abstract".to_owned(),
            sequence_epoch: "epoch-abstract".to_owned(),
            sequence_number: number,
        };
        let mut records = vec![
            CanonicalRecord {
                bytes: second.into_bytes(),
                order_key: claimed(1),
            },
            CanonicalRecord {
                bytes: same_key.clone().into_bytes(),
                order_key: claimed(2),
            },
        ];
        let profile = WireArtifactProfile::Sequenced {
            sequence_domain_id: "domain-abstract".to_owned(),
            sequence_epoch: "epoch-abstract".to_owned(),
        };
        assert!(
            sort_byte_derived(&records, &profile, &policy()).is_ok(),
            "asserted condition: sort_byte_derived(&records, &profile, &policy()).is_ok()"
        );
        records[1].bytes = same_key
            .replace("abstract-value-3", "conflicting-value")
            .into_bytes();
        let error = sort_byte_derived(&records, &profile, &policy())
            .expect_err("conflicting payload at one derived key must fail");
        assert!(
            error.to_string().contains("duplicate derived ordering key"),
            "asserted condition: error.to_string().contains(\"duplicate derived ordering key\")"
        );
        Ok(())
    }

    #[test]
    fn both_profiles_are_tagged_objects_in_manifest() -> TestResult {
        let (release, _) = build(&spec())?;
        let manifest = manifest_value(&release);
        let root = members(&manifest, "root");
        let JcsValue::Array(artifacts) = &root["artifacts"] else {
            return Err("artifacts must be an array".into());
        };
        let profiles: Vec<String> = artifacts
            .iter()
            .map(|artifact| {
                let fields = members(artifact, "artifact");
                string_member(&members(fields["record_order_profile"], "profile"), "kind")
                    .to_owned()
            })
            .collect();
        assert!(
            profiles.iter().any(|kind| kind == "sequenced"),
            "asserted condition: profiles.iter().any(|kind| kind == \"sequenced\")"
        );
        assert!(
            profiles.iter().any(|kind| kind == "reference"),
            "asserted condition: profiles.iter().any(|kind| kind == \"reference\")"
        );
        Ok(())
    }

    #[test]
    fn digest_reproducibility() -> TestResult {
        let (first, _) = build(&spec())?;
        let (second, _) = build(&spec())?;
        assert_eq!(
            first.manifest_bytes, second.manifest_bytes,
            "expected first.manifest_bytes to equal second.manifest_bytes"
        );
        assert_eq!(
            first.signature_bytes, second.signature_bytes,
            "expected first.signature_bytes to equal second.signature_bytes"
        );
        assert_eq!(
            first.data_sha256, second.data_sha256,
            "expected first.data_sha256 to equal second.data_sha256"
        );
        Ok(())
    }

    #[test]
    fn two_artifact_release_dataset_digest_is_compression_independent() -> TestResult {
        let baseline = build(&spec())?;
        let compressed_index = artifact_index(&baseline.1, "gzip");
        let declared_path = baseline.1[compressed_index].descriptor.path.clone();
        let mut value: JsonValue = serde_json::from_str(SPEC)?;
        let spec_index = value["artifacts"]
            .as_array()
            .expect("artifact array")
            .iter()
            .position(|item| item["compression"] == "gzip")
            .expect("gzip spec artifact");
        value["artifacts"][spec_index]["compression"] = JsonValue::from("none");
        let parsed: ConformanceSpec = serde_json::from_value(value)?;
        let changed = build(&parsed)?;
        assert_eq!(
            baseline.0.data_sha256, changed.0.data_sha256,
            "expected baseline.0.data_sha256 to equal changed.0.data_sha256"
        );
        let changed_match = changed
            .1
            .iter()
            .find(|item| item.descriptor.path == declared_path)
            .expect("same logical artifact");
        assert_ne!(
            baseline.1[compressed_index].descriptor.stored_sha256,
            changed_match.descriptor.stored_sha256,
            "expected baseline.1[compressed_index].descriptor.stored_sha256 to differ from changed_match.descriptor.stored_sha256"
        );
        assert_eq!(
            baseline.1[compressed_index].descriptor.uncompressed_sha256,
            changed_match.descriptor.uncompressed_sha256,
            "expected baseline.1[compressed_index].descriptor.uncompressed_sha256 to equal changed_match.descriptor.uncompressed_sha256"
        );
        Ok(())
    }

    #[test]
    fn gzip_artifact_has_registered_version() -> TestResult {
        let (_, artifacts) = build(&spec())?;
        let index = artifact_index(&artifacts, "gzip");
        assert_eq!(
            artifacts[index].descriptor.compression, "gzip",
            "expected artifacts[index].descriptor.compression to equal \"gzip\""
        );
        assert_eq!(
            artifacts[index].descriptor.compression_version, COMPRESSION_VERSION_GZIP,
            "expected artifacts[index].descriptor.compression_version to equal COMPRESSION_VERSION_GZIP"
        );
        assert_ne!(
            artifacts[index].descriptor.stored_bytes,
            artifacts[index].descriptor.uncompressed_bytes,
            "expected artifacts[index].descriptor.stored_bytes to differ from artifacts[index].descriptor.uncompressed_bytes"
        );
        Ok(())
    }

    #[test]
    fn unknown_compression_version_rejected() {
        let error =
            validate_compression_pair("gzip", "unknown/9").expect_err("unregistered version");
        assert!(
            error.to_string().contains("compression"),
            "asserted condition: error.to_string().contains(\"compression\")"
        );
        let mutated_spec = mutated(|value| {
            value["artifacts"][1]["compression"] = JsonValue::from("zstd");
        })
        .expect_err("unregistered method must fail");
        assert!(
            mutated_spec.to_string().contains("gzip"),
            "asserted condition: mutated_spec.to_string().contains(\"gzip\")"
        );
    }

    #[test]
    fn no_private_key_bytes_in_wire_output() -> TestResult {
        let (release, _) = build(&spec())?;
        for bytes in [&release.manifest_bytes, &release.signature_bytes] {
            assert!(
                !bytes
                    .windows(CONFORMANCE_SIGNING_SEED.len())
                    .any(|window| window == CONFORMANCE_SIGNING_SEED),
                "asserted condition: !bytes .windows(CONFORMANCE_SIGNING_SEED.len()) .any(|window| window == CONFORMANCE_SIGNING_SEED)"
            );
        }
        Ok(())
    }

    #[test]
    fn payload_registry_requires_every_event_type() {
        let error = mutated(|value| {
            value["evidence"]["payload_schemas"]
                .as_array_mut()
                .expect("registry array")
                .pop();
        })
        .and_then(|spec| build(&spec))
        .expect_err("unregistered event type must fail");
        assert!(
            error.to_string().contains("payload schema"),
            "asserted condition: error.to_string().contains(\"payload schema\")"
        );
    }

    #[test]
    fn operation_evidence_binding_is_one_to_one() {
        let error = mutated(|value| {
            value["manifest"]["producer_activity"]["operation_evidence"][0] =
                JsonValue::from("op-unbound");
        })
        .and_then(|spec| build(&spec))
        .expect_err("unbound evidence must fail");
        assert!(
            error.to_string().contains("operation evidence"),
            "asserted condition: error.to_string().contains(\"operation evidence\")"
        );
    }

    #[test]
    fn rights_attestation_mismatch_rejected() {
        let error = mutated(|value| {
            value["evidence"]["reviewed_attestations"][0]["attestation"]["purpose"] =
                JsonValue::from("different-purpose");
        })
        .and_then(|spec| build(&spec))
        .expect_err("attestation mismatch must fail");
        assert!(
            error.to_string().contains("attestations differ"),
            "asserted condition: error.to_string().contains(\"attestations differ\")"
        );
    }

    #[test]
    fn coverage_arithmetic_rejected() {
        let error = mutated(|value| {
            value["manifest"]["coverage"]["dimensions"][0]["numerator"] = JsonValue::from(4);
        })
        .and_then(|spec| build(&spec))
        .expect_err("non-exhaustive arithmetic must fail");
        assert!(
            error.to_string().contains("arithmetic"),
            "asserted condition: error.to_string().contains(\"arithmetic\")"
        );
    }

    #[test]
    fn producer_pass_is_not_promoted() {
        let error = mutated(|value| {
            value["manifest"]["coverage"]["dimensions"][0]["verdict"] = JsonValue::from("PASS");
        })
        .and_then(|spec| build(&spec))
        .expect_err("PASS without full evidence must fail");
        assert!(
            error.to_string().contains("PASS"),
            "asserted condition: error.to_string().contains(\"PASS\")"
        );
    }

    #[test]
    fn lineage_predecessor_must_be_immediate() {
        let error = mutated(|value| {
            value["manifest"]["lineage"]["supersedes"]["revision"] = JsonValue::from(2);
        })
        .and_then(|spec| build(&spec))
        .expect_err("non-immediate predecessor must fail");
        assert!(
            error.to_string().contains("lineage"),
            "asserted condition: error.to_string().contains(\"lineage\")"
        );
    }

    #[test]
    fn utc_instant_grammar_rejects_offset_leap_and_short_fraction() -> TestResult {
        validate_utc_instant("2026-11-24T00:00:00.000000000Z", "valid")?;
        assert!(
            validate_utc_instant("2026-11-24T00:00:00+00:00", "offset").is_err(),
            "asserted condition: validate_utc_instant(\"2026-11-24T00:00:00+00:00\", \"offset\").is_err()"
        );
        assert!(
            validate_utc_instant("2026-11-24T00:00:60.000000000Z", "leap").is_err(),
            "asserted condition: validate_utc_instant(\"2026-11-24T00:00:60.000000000Z\", \"leap\").is_err()"
        );
        assert!(
            validate_utc_instant("2026-11-24T00:00:00.00000000Z", "short").is_err(),
            "asserted condition: validate_utc_instant(\"2026-11-24T00:00:00.00000000Z\", \"short\").is_err()"
        );
        assert!(
            validate_utc_instant("2026-02-30T00:00:00.000000000Z", "calendar").is_err(),
            "asserted condition: validate_utc_instant(\"2026-02-30T00:00:00.000000000Z\", \"calendar\").is_err()"
        );
        Ok(())
    }

    #[test]
    fn invalidated_at_time_is_canonical_utc_string() {
        let error = mutated(|value| {
            value["manifest"]["lineage"]["supersedes"]["invalidated_at_time"] =
                JsonValue::from("1763932800000000000");
        })
        .and_then(|spec| build(&spec))
        .expect_err("integer invalidation must fail");
        assert!(
            error.to_string().contains("UTC instant"),
            "asserted condition: error.to_string().contains(\"UTC instant\")"
        );
    }

    #[test]
    fn strict_object_rejects_unknown_and_missing_members() -> TestResult {
        let value = parse_jcs_value(r#"{"a":1,"b":2}"#)?;
        assert!(
            strict_object(&value, "root", &["a"], &["a"]).is_err(),
            "asserted condition: strict_object(&value, \"root\", &[\"a\"], &[\"a\"]).is_err()"
        );
        assert!(
            strict_object(&value, "root", &["a", "b"], &["a", "b", "c"]).is_err(),
            "asserted condition: strict_object(&value, \"root\", &[\"a\", \"b\"], &[\"a\", \"b\", \"c\"]).is_err()"
        );
        assert!(
            strict_object(&value, "root", &["a", "b"], &["a", "b"]).is_ok(),
            "asserted condition: strict_object(&value, \"root\", &[\"a\", \"b\"], &[\"a\", \"b\"]).is_ok()"
        );
        Ok(())
    }

    #[test]
    fn sha256_hex_is_lowercase_and_sixty_four_characters() -> TestResult {
        validate_sha256_hex(&"ab".repeat(32), "digest")?;
        assert!(
            validate_sha256_hex(&"AB".repeat(32), "digest").is_err(),
            "asserted condition: validate_sha256_hex(&\"AB\".repeat(32), \"digest\").is_err()"
        );
        Ok(())
    }
}

/// Exact canonical release bytes produced from one abstract spec.
#[derive(Debug, Clone)]
pub struct ReleaseBytes {
    /// RFC 8785 canonical manifest bytes, without a line terminator.
    pub manifest_bytes: Vec<u8>,
    /// Five-member sidecar with a single trailing line feed.
    pub signature_bytes: Vec<u8>,
    /// Dataset digest over ordered uncompressed artifact streams.
    pub data_sha256: String,
}

/// Map one abstract spec to complete canonical release bytes. Artifacts are
/// canonically ordered by `(logical_partition_id, shard_ordinal)` before the
/// dataset digest and manifest inventory are computed.
pub fn build_conformance_release(
    spec: &ConformanceSpec,
    policy: &ResourcePolicy,
    signing: &SigningKey,
    verifying: &VerifyingKey,
) -> Result<(ReleaseBytes, Vec<PreparedArtifact>), WireError> {
    let mut artifacts = Vec::with_capacity(spec.artifacts.len());
    for artifact in &spec.artifacts {
        artifacts.push(prepare_artifact(artifact, policy)?);
    }
    artifacts.sort_by(|left, right| {
        let a = &left.descriptor;
        let b = &right.descriptor;
        (a.logical_partition_id.as_str(), a.shard_ordinal)
            .cmp(&(b.logical_partition_id.as_str(), b.shard_ordinal))
    });
    let data_sha256 = dataset_digest(&artifacts);
    let mut manifest = spec.manifest.clone();
    manifest.artifacts = artifacts
        .iter()
        .map(|item| item.descriptor.clone())
        .collect();
    manifest.digests.data_sha256 = data_sha256.clone();
    let mut event_types = BTreeSet::new();
    for artifact in &artifacts {
        event_types.extend(artifact.event_types.iter().cloned());
    }
    let wire_manifest = map_manifest(&manifest, &spec.evidence, &data_sha256, &event_types)?;
    let manifest_bytes = canonicalize_strict(&wire_manifest, policy)
        .map_err(|error| WireError::Canonicalization(error.to_string()))?;
    if u64::try_from(manifest_bytes.len())
        .map_err(|_| WireError::Policy("manifest length".to_owned()))?
        > policy.max_manifest_bytes
    {
        return Err(WireError::Policy("manifest bound exceeded".to_owned()));
    }
    let digest = Sha256::digest(&manifest_bytes);
    let manifest_sha256 = crate::distribution::ndc_release::hex_encode(&digest);
    let signature = sign_manifest(&manifest_bytes, signing, verifying)?;
    let signature_bytes = sidecar_bytes(
        &manifest.publication_identity.signing_key_id,
        &manifest_sha256,
        &signature,
        policy,
    )?;
    Ok((
        ReleaseBytes {
            manifest_bytes,
            signature_bytes,
            data_sha256,
        },
        artifacts,
    ))
}
