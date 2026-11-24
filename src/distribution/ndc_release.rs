// SPDX-License-Identifier: Apache-2.0
//! NDC v2 release producer under `WS-NDC-2026-11-24-002` Profile 1.
//!
//! This module builds a complete canonical manifest, its RFC 8785 JCS byte
//! sequence, the detached Ed25519 sidecar and the ordered artifact inventory.
//! The manifest carries no self-digest and no `limits` member; `manifest_sha256`
//! exists only in the five-member sidecar. Signing uses an injected key, and a
//! self-check with an injected verifying key is mandatory.
//!
//! Number handling is restrictive by contract. The JCS canonicalizer emits
//! minimal ECMAScript formatting for integers and finite doubles, while the
//! manifest and record paths reject `f64` and `f32` with a typed error: a
//! floating-point value cannot be checked for exact decimal intent from a
//! typed producer input. Exact decimals and wide integers are JSON strings.
//!
//! Paths accept the ASCII subset of the contract alphabet. Every accepted
//! path is NFC without conversion, and non-ASCII input fails closed, so no
//! ambiguous normalized duplicate can arise.
//!
//! [`crate::distribution::ndc_wire`] is the single canonical wire mapping. This
//! module produces manifest bytes only through that mapping; it owns no
//! second serialization of the manifest.
//!
//! Publication moves one complete, synced staging directory into its final
//! name with a single no-replace directory rename. Linux uses
//! `renameat2(RENAME_NOREPLACE)` and macOS uses `renamex_np(RENAME_EXCL)`;
//! other targets fail closed. A durable receipt, not directory presence, is
//! the local acknowledgement. The dated record states the platform bounds.
//!
//! Non-claim: a signature proves publisher-key control over exact signed
//! bytes. It proves no source authenticity, coverage, right, dataset
//! entitlement or observation truth.

use std::collections::BTreeSet;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::CString;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Write as IoWrite;
use std::path::Path;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::Signer as _;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier as _;
use ed25519_dalek::VerifyingKey;
use flate2::Compression as GzipCompression;
use flate2::write::GzEncoder;
use serde::Deserialize;
use serde::Serialize;
use serde::de::Error as DeError;
use serde::de::MapAccess;
use serde::de::SeqAccess;
use serde::de::Visitor;
use sha2::Digest as _;
use sha2::Sha256;
use thiserror::Error;

/// Domain prefix bound to the manifest digest before signing.
pub const SIGNING_DOMAIN: &[u8] = b"NDC-V2-RELEASE-MANIFEST-SHA256-V1\x00";

/// Manifest layout version implemented here.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Sidecar layout version implemented here.
pub const SIDECAR_SCHEMA_VERSION: u32 = 1;

/// Sidecar signature algorithm literal.
pub const SIGNATURE_ALGORITHM: &str = "Ed25519";

/// Digest algorithm literal carried by the manifest.
pub const DIGEST_ALGORITHM: &str = "sha256";

/// Manifest file name inside a release directory.
pub const MANIFEST_FILE_NAME: &str = "manifest.json";

/// Sidecar file name inside a release directory.
pub const SIDECAR_FILE_NAME: &str = "signature.json";

/// Artifact directory prefix inside a release directory.
pub const ARTIFACT_DIRECTORY: &str = "artifacts";

/// Uncompressed artifact encoding literal.
pub const ENCODING_NDJSON: &str = "application/x-ndjson; charset=utf-8";

/// No-compression literal.
pub const COMPRESSION_NONE: &str = "none";

/// Gzip compression literal.
pub const COMPRESSION_GZIP: &str = "gzip";

/// Declared version for uncompressed storage.
pub const COMPRESSION_VERSION_NONE: &str = "none/1";

/// Declared version for the flate2 gzip framing and deflate settings.
pub const COMPRESSION_VERSION_GZIP: &str = "gzip-deflate/flate2-1";

/// Largest integer with an exact ECMAScript double representation.
pub const SAFE_INTEGER_MAX: i64 = 9_007_199_254_740_991;

/// Producer failures. Every rejection is typed and carries context.
#[derive(Debug, Error)]
pub enum ProducerError {
    /// The supplied JSON text is malformed or outside the supported subset.
    #[error("invalid JSON: {0}")]
    InvalidJson(String),

    /// A JSON object carried a repeated property name.
    #[error("duplicate JSON property name: {0}")]
    DuplicateProperty(String),

    /// A floating-point value reached a path that requires exact numbers.
    #[error("ambiguous number rejected: {0}")]
    AmbiguousNumber(String),

    /// A string was not valid Unicode or carried an invalid scalar.
    #[error("invalid Unicode value: {0}")]
    InvalidUnicode(String),

    /// An artifact path violated the declared alphabet or boundary rules.
    #[error("invalid artifact path `{0}`: {1}")]
    InvalidArtifactPath(String, String),

    /// Two artifacts declared the same normalized path.
    #[error("duplicate artifact path: {0}")]
    DuplicateArtifactPath(String),

    /// Two artifacts declared the same logical partition and shard ordinal.
    #[error("duplicate artifact position: {0}#{1}")]
    DuplicateArtifactPosition(String, u32),

    /// A record violated the canonical line contract.
    #[error("invalid record at index {0}: {1}")]
    InvalidRecord(usize, String),

    /// A record order key repeated or moved backwards.
    #[error("invalid record order in `{0}`: {1}")]
    InvalidRecordOrder(String, String),

    /// A caller-supplied policy bound was exceeded.
    #[error("resource policy exceeded: {0}")]
    PolicyExceeded(String),

    /// A manifest descriptor had no matching artifact input.
    #[error("missing artifact input: {0}")]
    MissingArtifact(String),

    /// Correction lineage failed strict validation.
    #[error("invalid lineage: {0}")]
    InvalidLineage(String),

    /// The canonical wire mapping refused the supplied manifest or evidence.
    #[error("canonical wire mapping failed: {0}")]
    WireMapping(String),

    /// Signing configuration failed strict validation or self-check.
    #[error("invalid signature configuration: {0}")]
    InvalidSignatureConfig(String),

    /// The expected file set did not match the published directory.
    #[error("artifact set mismatch: {0}")]
    ArtifactSetMismatch(String),

    /// A release identity was already present in the publication root.
    #[error("publication collision for release: {0}")]
    PublicationCollision(String),

    /// Staging and final release paths were not siblings on one filesystem.
    #[error("invalid publication topology: {0}")]
    PublicationTopology(String),

    /// Publication evidence was absent or inconsistent with the request.
    #[error("publication evidence error: {0}")]
    PublicationEvidence(String),

    /// The interrupted publication could not be reconciled from evidence.
    #[error("uncertain publication; operator reconciliation required: {0}")]
    UncertainPublication(String),

    /// A filesystem operation failed.
    #[error("filesystem failure during {0}: {1}")]
    Io(String, #[source] std::io::Error),
}

/// Result of reconciling an interrupted publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// No durable operation evidence exists for the supplied operation id.
    NoEvidence,
    /// Staging evidence was verified and publication was completed.
    RecoveredStaged,
    /// A final directory was verified and the receipt was completed.
    RecoveredPublished,
    /// A matching receipt and availability marker were already present.
    AlreadyAvailable,
}

/// State in the ratified publication state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicationState {
    /// Exclusive sibling staging directory exists.
    #[serde(rename = "STAGING_CREATED")]
    StagingCreated,
    /// Every release file is written.
    #[serde(rename = "FILES_WRITTEN")]
    FilesWritten,
    /// Every release file is synced.
    #[serde(rename = "FILES_SYNCED")]
    FilesSynced,
    /// The staging directory is synced.
    #[serde(rename = "STAGING_DIR_FSYNCED")]
    StagingDirFsynced,
    /// The no-replace finalization primitive has run.
    #[serde(rename = "ATOMIC_NO_REPLACE_RENAME")]
    AtomicNoReplaceRename,
    /// The parent directory is synced.
    #[serde(rename = "PARENT_DIR_FSYNCED")]
    ParentDirFsynced,
    /// The durable receipt exists.
    #[serde(rename = "DURABLE_PUBLICATION_RECEIPT")]
    DurablePublicationReceipt,
    /// The availability marker exists.
    #[serde(rename = "AVAILABLE")]
    Available,
}

impl PublicationState {
    /// Stable wire literal for this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StagingCreated => "STAGING_CREATED",
            Self::FilesWritten => "FILES_WRITTEN",
            Self::FilesSynced => "FILES_SYNCED",
            Self::StagingDirFsynced => "STAGING_DIR_FSYNCED",
            Self::AtomicNoReplaceRename => "ATOMIC_NO_REPLACE_RENAME",
            Self::ParentDirFsynced => "PARENT_DIR_FSYNCED",
            Self::DurablePublicationReceipt => "DURABLE_PUBLICATION_RECEIPT",
            Self::Available => "AVAILABLE",
        }
    }

    /// Position of this state in the ratified transition sequence.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::StagingCreated => 0,
            Self::FilesWritten => 1,
            Self::FilesSynced => 2,
            Self::StagingDirFsynced => 3,
            Self::AtomicNoReplaceRename => 4,
            Self::ParentDirFsynced => 5,
            Self::DurablePublicationReceipt => 6,
            Self::Available => 7,
        }
    }
}

const STAGE_ORDER: [PublicationState; 8] = [
    PublicationState::StagingCreated,
    PublicationState::FilesWritten,
    PublicationState::FilesSynced,
    PublicationState::StagingDirFsynced,
    PublicationState::AtomicNoReplaceRename,
    PublicationState::ParentDirFsynced,
    PublicationState::DurablePublicationReceipt,
    PublicationState::Available,
];

/// Ordered events emitted by the publication filesystem during recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "durable events are constructed by the offline recording filesystem"
    )
)]
enum PublicationRecoveryEvent {
    /// The final directory name was observed.
    FinalDirectoryFound,
    /// Final directory bytes were verified against the validated intent.
    VerifyFinalDirectory,
    /// Durable operation evidence was bound to this operation and release.
    VerifyOperationIdentity,
    /// The release parent directory was synced.
    SyncReleaseParent,
    /// The synced stage was read back and validated.
    VerifyDurabilityTransition,
    /// The receipt file was committed.
    CommitReceipt,
    /// The receipt ledger directory was synced.
    SyncReceiptLedger,
    /// The availability marker was committed.
    CommitAvailabilityMarker,
    /// The final available stage was committed.
    Available,
}

/// Durable publication receipt. The receipt, not directory presence, is the
/// local durability evidence for one publication operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationReceipt {
    /// Receipt layout version.
    pub schema_version: u32,
    /// Immutable release identity.
    pub release_id: String,
    /// Digest of the canonical manifest bytes.
    pub manifest_sha256: String,
    /// Digest of the ordered uncompressed artifact streams.
    pub data_sha256: String,
    /// Identifier of the publication operation that produced this receipt.
    pub publication_operation_id: String,
    /// Commit position bound into this receipt.
    pub commit_position: String,
    /// Final publication state and result.
    pub result: PublicationState,
    /// Immediate predecessor release, when this release is a correction.
    pub supersedes_release_id: Option<String>,
}

/// Durable record of one publication attempt and its observed stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationOperation {
    /// Operation evidence version.
    pub schema_version: u32,
    /// Unique operation identifier.
    pub operation_id: String,
    /// Release identity being published.
    pub release_id: String,
    /// Expected canonical manifest digest.
    pub manifest_sha256: String,
    /// Expected dataset digest.
    pub data_sha256: String,
    /// Commit position bound into the operation.
    pub commit_position: String,
    /// Staging directory path relative to the publication root.
    pub staging_directory: String,
    /// Final release directory path relative to the publication root.
    pub final_directory: String,
    /// Stage recorded by this evidence file.
    pub stage: PublicationState,
}

/// Caller-retained evidence used to reconcile an interrupted publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicationEvidence {
    /// Release identity expected in the receipt.
    pub release_id: String,
    /// Expected canonical manifest digest.
    pub manifest_sha256: String,
    /// Expected dataset digest.
    pub data_sha256: String,
    /// Expected publication operation identifier.
    pub publication_operation_id: String,
    /// Expected commit position.
    pub commit_position: String,
    /// Release-relative declared artifact paths.
    pub artifact_paths: Vec<String>,
    /// Stored digests aligned with `artifact_paths`.
    pub artifact_stored_sha256: Vec<String>,
    /// Receipt built by `prepare_release` from the complete validated intent,
    /// including manifest lineage. Recovery does not rebuild this value from
    /// the other, narrower fields.
    pub expected_receipt: PublicationReceipt,
    /// Digest of the exact receipt bytes committed by the builder.
    pub receipt_sha256: String,
}

/// Typed resource policy. Every numeric maximum is supplied by the caller;
/// this module invents no unmeasured production limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePolicy {
    /// Maximum canonical manifest byte count.
    pub max_manifest_bytes: u64,
    /// Maximum number of declared artifacts.
    pub max_artifact_count: u64,
    /// Maximum stored byte count for one artifact.
    pub max_stored_bytes_per_artifact: u64,
    /// Maximum uncompressed byte count for one artifact.
    pub max_uncompressed_bytes_per_artifact: u64,
    /// Maximum total stored byte count.
    pub max_total_stored_bytes: u64,
    /// Maximum total uncompressed byte count.
    pub max_total_uncompressed_bytes: u64,
    /// Maximum uncompressed byte count for one record.
    pub max_record_bytes: u64,
    /// Maximum number of records in one artifact.
    pub max_records_per_artifact: u64,
    /// Maximum byte length of one path component after alphabet validation.
    pub max_path_component_bytes: u64,
    /// Maximum JSON nesting depth.
    pub max_nesting_depth: u32,
    /// Maximum member count of one JSON object.
    pub max_object_members: u32,
    /// Maximum element count of one JSON array.
    pub max_array_elements: u32,
    /// Maximum byte length of the detached sidecar.
    pub max_sidecar_bytes: u64,
}

/// Artifact compression declaration. The declared version string identifies
/// the exact framing and settings; no format is inferred from bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactCompression {
    /// Store the canonical stream without transformation.
    None,
    /// Store the canonical stream with flate2 gzip framing.
    Gzip,
}

impl ArtifactCompression {
    /// Compression literal emitted in the artifact descriptor.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => COMPRESSION_NONE,
            Self::Gzip => COMPRESSION_GZIP,
        }
    }

    /// Version literal emitted in the artifact descriptor.
    #[must_use]
    pub const fn version_str(self) -> &'static str {
        match self {
            Self::None => COMPRESSION_VERSION_NONE,
            Self::Gzip => COMPRESSION_VERSION_GZIP,
        }
    }
}

/// Declared per-artifact record ordering profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordOrderProfile {
    /// Sequenced key `(sequence_domain, sequence_epoch, sequence_number)`.
    Sequenced {
        /// Domain whose sequence numbers are comparable.
        sequence_domain: String,
        /// Epoch or session-reset identity within the domain.
        sequence_epoch: String,
    },
    /// Reference key `(object_id, revision, knowledge_time, assertion_id)`.
    Reference,
}

/// One record order position. Gaps are preserved; no missing position is
/// synthesized and no event time is used as a fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOrderKey {
    /// Position in one sequenced domain and epoch.
    Sequenced {
        /// Sequence domain identity.
        sequence_domain: String,
        /// Epoch or session-reset identity.
        sequence_epoch: String,
        /// Monotonic position within the domain and epoch.
        sequence_number: u64,
    },
    /// Position in the unsequenced reference order.
    Reference {
        /// Stable object identity.
        object_id: String,
        /// Revision of the assertion.
        revision: u64,
        /// Knowledge time as an exact decimal string.
        knowledge_time_ns: String,
        /// Stable assertion identity.
        assertion_id: String,
    },
}

/// One canonical JSON record line supplied by the caller, with its order key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalRecord {
    /// Canonical record bytes without a line-feed terminator.
    pub bytes: Vec<u8>,
    /// Declared order position for this record.
    pub order_key: RecordOrderKey,
}

/// Caller-supplied artifact content and declaration inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactInput {
    /// Logical partition identity.
    pub logical_partition_id: String,
    /// Shard ordinal within the logical partition.
    pub shard_ordinal: u32,
    /// Release-relative POSIX artifact path.
    pub path: String,
    /// Declared record ordering profile.
    pub record_order_profile: RecordOrderProfile,
    /// Declared record encoding.
    pub encoding: String,
    /// Declared compression mode.
    pub compression: ArtifactCompression,
    /// Canonical records in declared order.
    pub records: Vec<CanonicalRecord>,
}

/// The single immediate predecessor relationship for a corrected release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LineageSupersedes {
    /// Release identity of the immediate predecessor.
    pub supersedes_release_id: String,
    /// Canonical manifest digest of the immediate predecessor.
    pub supersedes_manifest_sha256: String,
    /// Dataset digest of the immediate predecessor.
    pub supersedes_data_sha256: String,
    /// Revision of this corrected release.
    pub revision: u64,
    /// Opaque correction reason.
    pub correction_reason: String,
    /// Knowledge time as an exact decimal string.
    pub knowledge_time_ns: String,
    /// Invalidation instant of the predecessor as an opaque UTC string.
    pub invalidated_at_time: String,
}

/// Release identity section of the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    /// Immutable release identity.
    pub release_id: String,
    /// Version of this release identity.
    pub release_version: String,
    /// As-of instant as an exact decimal string.
    pub as_of_ns: String,
    /// Declared publication state. This is not durability evidence.
    pub publication_state: PublicationState,
    /// Creation instant as an exact decimal string.
    pub created_at_utc_ns: String,
}

/// Source scope section of the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceScope {
    /// Opaque provider identity.
    pub provider_id: String,
    /// Opaque source product identity.
    pub source_product_id: String,
    /// Opaque venue identity, absent when venue scope is denied.
    pub venue_id: Option<String>,
    /// Opaque segment identity, absent when segment scope is denied.
    pub segment_id: Option<String>,
    /// Opaque dataset identity.
    pub dataset_id: String,
}

/// Producer activity section of the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProducerActivity {
    /// Opaque performed-operation references.
    pub performed_operations: Vec<String>,
    /// Opaque operation-evidence references.
    pub operation_evidence: Vec<String>,
}

/// Rights evidence section of the manifest. Values are references, not grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RightsEvidence {
    /// Opaque permission-grant references.
    pub permission_grants: Vec<String>,
    /// Opaque document references.
    pub document_references: Vec<String>,
    /// Opaque reviewed-attestation references.
    pub reviewed_attestations: Vec<String>,
}

/// One abstract coverage dimension report. No market observation is embedded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageDimension {
    /// Stable dimension identity.
    pub dimension_id: String,
    /// Stable universe identity.
    pub universe_id: String,
    /// Abstract numerator.
    pub numerator: u64,
    /// Abstract denominator.
    pub denominator: u64,
    /// Verdict literal from the governing vocabulary.
    pub verdict: String,
    /// Opaque evidence reference.
    pub evidence_reference: String,
}

/// Coverage section of the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageEvidence {
    /// Abstract coverage dimensions.
    pub dimensions: Vec<CoverageDimension>,
}

/// Correction and derivation lineage section of the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lineage {
    /// Opaque raw archive reference.
    pub raw_archive_reference: String,
    /// Digest of the referenced raw archive.
    pub raw_archive_sha256: String,
    /// Opaque transformation reference.
    pub transformation_record: String,
    /// Knowledge time as an exact decimal string.
    pub knowledge_time_ns: String,
    /// Revision of this release.
    pub revision: u64,
    /// Single immediate predecessor, present for corrections only.
    pub supersedes: Option<LineageSupersedes>,
}

/// Component schema versions section of the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaVersions {
    /// Contract version literal.
    pub contract_version: String,
    /// Normalizer version literal.
    pub normalizer_version: String,
    /// Payload schema version literal.
    pub payload_schema_version: String,
    /// Envelope version literal.
    pub envelope_version: String,
}

/// Dataset-level digests. The manifest digest and artifact digest array are
/// absent by ratification; per-artifact digests live in `artifacts[]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestDigests {
    /// Dataset digest over ordered uncompressed streams.
    pub data_sha256: String,
    /// Digest algorithm literal.
    pub digest_algorithm: String,
}

/// Publisher and key binding section of the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationIdentity {
    /// Publisher identity from the out-of-band registry.
    pub publisher_identity: String,
    /// Immutable key identifier from the out-of-band registry.
    pub signing_key_id: String,
    /// Detached sidecar file name.
    pub signature_reference: String,
    /// Opaque archive reference.
    pub archive_reference: String,
}

/// Per-artifact descriptor. This array is the sole artifact inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDescriptor {
    /// Logical partition identity.
    pub logical_partition_id: String,
    /// Shard ordinal within the logical partition.
    pub shard_ordinal: u32,
    /// Release-relative POSIX artifact path.
    pub path: String,
    /// Declared record ordering profile.
    pub record_order_profile: RecordOrderProfile,
    /// Declared record encoding.
    pub encoding: String,
    /// Declared compression mode.
    pub compression: String,
    /// Declared compression version.
    pub compression_version: String,
    /// Exact stored byte count.
    pub stored_bytes: u64,
    /// Digest of the exact stored bytes.
    pub stored_sha256: String,
    /// Exact uncompressed byte count.
    pub uncompressed_bytes: u64,
    /// Digest of the exact uncompressed canonical stream.
    pub uncompressed_sha256: String,
    /// Exact record count.
    pub record_count: u64,
}

/// The complete canonical release manifest. No self-digest and no policy
/// maxima appear in this structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    /// Manifest layout version.
    pub schema_version: u32,
    /// Contract major version literal.
    pub contract_version: String,
    /// Reviewed contract revision literal.
    pub contract_revision: String,
    /// Release identity section.
    pub release_identity: ReleaseIdentity,
    /// Source scope section.
    pub source_scope: SourceScope,
    /// Producer activity section.
    pub producer_activity: ProducerActivity,
    /// Rights evidence section.
    pub rights: RightsEvidence,
    /// Coverage evidence section.
    pub coverage: CoverageEvidence,
    /// Correction and derivation lineage section.
    pub lineage: Lineage,
    /// Component schema versions section.
    pub schema_versions: SchemaVersions,
    /// Dataset-level digests.
    pub digests: ManifestDigests,
    /// Publisher and key binding section.
    pub publication_identity: PublicationIdentity,
    /// Sole artifact inventory, sorted by partition and shard ordinal.
    pub artifacts: Vec<ArtifactDescriptor>,
}

/// Detached signature sidecar with exactly the five ratified members.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureSidecar {
    /// Sidecar layout version.
    pub schema_version: u32,
    /// Signature algorithm literal.
    pub algorithm: String,
    /// Key identifier bound to the manifest publisher.
    pub key_id: String,
    /// Lowercase hex digest of the canonical manifest bytes.
    pub manifest_sha256: String,
    /// Standard padded base64 of the 64-byte Ed25519 signature.
    pub signature_b64: String,
}

/// Injected signing material. No key is generated, stored or discovered here.
#[derive(Debug, Clone, Copy)]
pub struct SignatureConfig<'a> {
    /// Injected test signing key.
    pub signing_key: &'a SigningKey,
    /// Injected verifying key used for the mandatory self-check.
    pub verifying_key: &'a VerifyingKey,
    /// Key identifier bound to the manifest publisher.
    pub key_id: &'a str,
}

/// Caller-supplied lineage context for correction validation.
#[derive(Debug, Clone, Copy)]
pub struct LineageContext<'a> {
    /// Immediate predecessor receipt, retained outside the release.
    pub predecessor: Option<&'a PublicationReceipt>,
    /// All receipts available for cycle traversal.
    pub known_receipts: &'a [PublicationReceipt],
    /// Caller-supplied current time for knowledge-time validation.
    pub now_ns: u64,
}

/// One `build_release()` validation and publication boundary request.
#[derive(Debug, Clone, Copy)]
pub struct BuildRequest<'a> {
    /// Parent directory of final release directories.
    pub release_root: &'a Path,
    /// Producer journal directory for operation and receipt evidence.
    pub ledger_dir: &'a Path,
    /// Unique publication operation identifier.
    pub operation_id: &'a str,
    /// Commit position bound into the receipt.
    pub commit_position: &'a str,
    /// Complete typed manifest without digests of itself.
    pub manifest: &'a ReleaseManifest,
    /// Typed evidence supplement required by the canonical wire mapping.
    pub evidence: &'a crate::distribution::ndc_wire::EvidenceSpec,
    /// Event types observed in the validated artifact record streams.
    pub observed_event_types: &'a BTreeSet<String>,
    /// Artifact inputs in any order; the producer sorts them canonically.
    pub artifacts: &'a [ArtifactInput],
    /// Injected signing material.
    pub signature: SignatureConfig<'a>,
    /// Caller-supplied resource maxima.
    pub policy: &'a ResourcePolicy,
    /// Correction lineage evidence.
    pub lineage: LineageContext<'a>,
}

/// Result of one completed `build_release()` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildOutcome {
    /// Canonical manifest bytes.
    pub manifest_bytes: Vec<u8>,
    /// Detached sidecar bytes including its single trailing LF.
    pub sidecar_bytes: Vec<u8>,
    /// Sorted descriptors with computed digests.
    pub descriptors: Vec<ArtifactDescriptor>,
    /// Durable receipt written for this publication.
    pub receipt: PublicationReceipt,
    /// Evidence retained for recovery.
    pub evidence: PublicationEvidence,
}

/// JSON value adapted for RFC 8785 canonicalization.
#[derive(Debug, Clone, PartialEq)]
pub enum JcsValue {
    /// JSON null literal.
    Null,
    /// JSON boolean literal.
    Bool(bool),
    /// Unicode string preserved without subtype conversion.
    String(String),
    /// Exact integer represented without a decimal point.
    Integer(i64),
    /// IEEE 754 double accepted by the general canonicalizer only.
    Float(f64),
    /// Ordered array; element order is preserved by JCS.
    Array(Vec<JcsValue>),
    /// Object with unique property names in input order.
    Object(Vec<(String, JcsValue)>),
}

impl<'de> Deserialize<'de> for JcsValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ValueVisitor;

        impl<'de> Visitor<'de> for ValueVisitor {
            type Value = JcsValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a JSON value with unique property names")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(JcsValue::Null)
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(JcsValue::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(JcsValue::Integer(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                if value > i64::MAX as u64 {
                    Err(DeError::custom(
                        "integer exceeds signed 64-bit range; encode as string",
                    ))
                } else {
                    Ok(JcsValue::Integer(value as i64))
                }
            }

            fn visit_f32<E>(self, value: f32) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(JcsValue::Float(f64::from(value)))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(JcsValue::Float(value))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(JcsValue::String(value.to_owned()))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: DeError,
            {
                Ok(JcsValue::String(value))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<JcsValue>()? {
                    values.push(value);
                }
                Ok(JcsValue::Array(values))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut entries: Vec<(String, JcsValue)> = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    if entries.iter().any(|(name, _)| name == &key) {
                        return Err(DeError::custom("duplicate JSON property name"));
                    }
                    let value = map.next_value::<JcsValue>()?;
                    entries.push((key, value));
                }
                Ok(JcsValue::Object(entries))
            }
        }

        deserializer.deserialize_any(ValueVisitor)
    }
}

trait ToJcs {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError>;
}

fn jcs_string(value: impl Into<String>) -> JcsValue {
    JcsValue::String(value.into())
}

fn jcs_integer(value: u64) -> Result<JcsValue, ProducerError> {
    let narrowed = i64::try_from(value).map_err(|_| {
        ProducerError::AmbiguousNumber("integer exceeds signed 64-bit range".to_owned())
    })?;
    Ok(JcsValue::Integer(narrowed))
}

fn jcs_object(entries: Vec<(&str, JcsValue)>) -> JcsValue {
    JcsValue::Object(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn jcs_option(value: &Option<String>) -> JcsValue {
    match value {
        Some(text) => JcsValue::String(text.clone()),
        None => JcsValue::Null,
    }
}

impl ToJcs for PublicationState {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_string(self.as_str()))
    }
}

impl ToJcs for PublicationReceipt {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            (
                "schema_version",
                jcs_integer(u64::from(self.schema_version))?,
            ),
            ("release_id", jcs_string(self.release_id.clone())),
            ("manifest_sha256", jcs_string(self.manifest_sha256.clone())),
            ("data_sha256", jcs_string(self.data_sha256.clone())),
            (
                "publication_operation_id",
                jcs_string(self.publication_operation_id.clone()),
            ),
            ("commit_position", jcs_string(self.commit_position.clone())),
            ("result", self.result.to_jcs()?),
            (
                "supersedes_release_id",
                jcs_option(&self.supersedes_release_id),
            ),
        ]))
    }
}

impl ToJcs for PublicationOperation {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            (
                "schema_version",
                jcs_integer(u64::from(self.schema_version))?,
            ),
            ("operation_id", jcs_string(self.operation_id.clone())),
            ("release_id", jcs_string(self.release_id.clone())),
            ("manifest_sha256", jcs_string(self.manifest_sha256.clone())),
            ("data_sha256", jcs_string(self.data_sha256.clone())),
            ("commit_position", jcs_string(self.commit_position.clone())),
            (
                "staging_directory",
                jcs_string(self.staging_directory.clone()),
            ),
            ("final_directory", jcs_string(self.final_directory.clone())),
            ("stage", self.stage.to_jcs()?),
        ]))
    }
}

impl ToJcs for PublicationEvidence {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            ("release_id", jcs_string(self.release_id.clone())),
            ("manifest_sha256", jcs_string(self.manifest_sha256.clone())),
            ("data_sha256", jcs_string(self.data_sha256.clone())),
            (
                "publication_operation_id",
                jcs_string(self.publication_operation_id.clone()),
            ),
            ("commit_position", jcs_string(self.commit_position.clone())),
            (
                "artifact_paths",
                JcsValue::Array(
                    self.artifact_paths
                        .iter()
                        .map(|path| jcs_string(path.clone()))
                        .collect(),
                ),
            ),
            (
                "artifact_stored_sha256",
                JcsValue::Array(
                    self.artifact_stored_sha256
                        .iter()
                        .map(|digest| jcs_string(digest.clone()))
                        .collect(),
                ),
            ),
            ("expected_receipt", self.expected_receipt.to_jcs()?),
            ("receipt_sha256", jcs_string(self.receipt_sha256.clone())),
        ]))
    }
}

impl ToJcs for RecordOrderProfile {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        match self {
            Self::Sequenced {
                sequence_domain,
                sequence_epoch,
            } => Ok(jcs_object(vec![
                ("kind", jcs_string("sequenced")),
                ("sequence_domain", jcs_string(sequence_domain.clone())),
                ("sequence_epoch", jcs_string(sequence_epoch.clone())),
            ])),
            Self::Reference => Ok(jcs_object(vec![("kind", jcs_string("reference"))])),
        }
    }
}

impl ToJcs for ArtifactDescriptor {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            (
                "logical_partition_id",
                jcs_string(self.logical_partition_id.clone()),
            ),
            ("shard_ordinal", jcs_integer(u64::from(self.shard_ordinal))?),
            ("path", jcs_string(self.path.clone())),
            ("record_order_profile", self.record_order_profile.to_jcs()?),
            ("encoding", jcs_string(self.encoding.clone())),
            ("compression", jcs_string(self.compression.clone())),
            (
                "compression_version",
                jcs_string(self.compression_version.clone()),
            ),
            ("stored_bytes", jcs_integer(self.stored_bytes)?),
            ("stored_sha256", jcs_string(self.stored_sha256.clone())),
            ("uncompressed_bytes", jcs_integer(self.uncompressed_bytes)?),
            (
                "uncompressed_sha256",
                jcs_string(self.uncompressed_sha256.clone()),
            ),
            ("record_count", jcs_integer(self.record_count)?),
        ]))
    }
}

impl ToJcs for LineageSupersedes {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            (
                "supersedes_release_id",
                jcs_string(self.supersedes_release_id.clone()),
            ),
            (
                "supersedes_manifest_sha256",
                jcs_string(self.supersedes_manifest_sha256.clone()),
            ),
            (
                "supersedes_data_sha256",
                jcs_string(self.supersedes_data_sha256.clone()),
            ),
            ("revision", jcs_integer(self.revision)?),
            (
                "correction_reason",
                jcs_string(self.correction_reason.clone()),
            ),
            (
                "knowledge_time_ns",
                jcs_string(self.knowledge_time_ns.clone()),
            ),
            (
                "invalidated_at_time",
                jcs_string(self.invalidated_at_time.clone()),
            ),
        ]))
    }
}

impl ToJcs for ReleaseIdentity {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            ("release_id", jcs_string(self.release_id.clone())),
            ("release_version", jcs_string(self.release_version.clone())),
            ("as_of_ns", jcs_string(self.as_of_ns.clone())),
            ("publication_state", self.publication_state.to_jcs()?),
            (
                "created_at_utc_ns",
                jcs_string(self.created_at_utc_ns.clone()),
            ),
        ]))
    }
}

impl ToJcs for SourceScope {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            ("provider_id", jcs_string(self.provider_id.clone())),
            (
                "source_product_id",
                jcs_string(self.source_product_id.clone()),
            ),
            ("venue_id", jcs_option(&self.venue_id)),
            ("segment_id", jcs_option(&self.segment_id)),
            ("dataset_id", jcs_string(self.dataset_id.clone())),
        ]))
    }
}

impl ToJcs for ProducerActivity {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            (
                "performed_operations",
                JcsValue::Array(
                    self.performed_operations
                        .iter()
                        .map(|item| jcs_string(item.clone()))
                        .collect(),
                ),
            ),
            (
                "operation_evidence",
                JcsValue::Array(
                    self.operation_evidence
                        .iter()
                        .map(|item| jcs_string(item.clone()))
                        .collect(),
                ),
            ),
        ]))
    }
}

impl ToJcs for RightsEvidence {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            (
                "permission_grants",
                JcsValue::Array(
                    self.permission_grants
                        .iter()
                        .map(|item| jcs_string(item.clone()))
                        .collect(),
                ),
            ),
            (
                "document_references",
                JcsValue::Array(
                    self.document_references
                        .iter()
                        .map(|item| jcs_string(item.clone()))
                        .collect(),
                ),
            ),
            (
                "reviewed_attestations",
                JcsValue::Array(
                    self.reviewed_attestations
                        .iter()
                        .map(|item| jcs_string(item.clone()))
                        .collect(),
                ),
            ),
        ]))
    }
}

impl ToJcs for CoverageDimension {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            ("dimension_id", jcs_string(self.dimension_id.clone())),
            ("universe_id", jcs_string(self.universe_id.clone())),
            ("numerator", jcs_integer(self.numerator)?),
            ("denominator", jcs_integer(self.denominator)?),
            ("verdict", jcs_string(self.verdict.clone())),
            (
                "evidence_reference",
                jcs_string(self.evidence_reference.clone()),
            ),
        ]))
    }
}

impl ToJcs for CoverageEvidence {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![(
            "dimensions",
            JcsValue::Array(
                self.dimensions
                    .iter()
                    .map(ToJcs::to_jcs)
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        )]))
    }
}

impl ToJcs for Lineage {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        let supersedes = match &self.supersedes {
            Some(value) => value.to_jcs()?,
            None => JcsValue::Null,
        };
        Ok(jcs_object(vec![
            (
                "raw_archive_reference",
                jcs_string(self.raw_archive_reference.clone()),
            ),
            (
                "raw_archive_sha256",
                jcs_string(self.raw_archive_sha256.clone()),
            ),
            (
                "transformation_record",
                jcs_string(self.transformation_record.clone()),
            ),
            (
                "knowledge_time_ns",
                jcs_string(self.knowledge_time_ns.clone()),
            ),
            ("revision", jcs_integer(self.revision)?),
            ("supersedes", supersedes),
        ]))
    }
}

impl ToJcs for SchemaVersions {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            (
                "contract_version",
                jcs_string(self.contract_version.clone()),
            ),
            (
                "normalizer_version",
                jcs_string(self.normalizer_version.clone()),
            ),
            (
                "payload_schema_version",
                jcs_string(self.payload_schema_version.clone()),
            ),
            (
                "envelope_version",
                jcs_string(self.envelope_version.clone()),
            ),
        ]))
    }
}

impl ToJcs for ManifestDigests {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            ("data_sha256", jcs_string(self.data_sha256.clone())),
            (
                "digest_algorithm",
                jcs_string(self.digest_algorithm.clone()),
            ),
        ]))
    }
}

impl ToJcs for PublicationIdentity {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            (
                "publisher_identity",
                jcs_string(self.publisher_identity.clone()),
            ),
            ("signing_key_id", jcs_string(self.signing_key_id.clone())),
            (
                "signature_reference",
                jcs_string(self.signature_reference.clone()),
            ),
            (
                "archive_reference",
                jcs_string(self.archive_reference.clone()),
            ),
        ]))
    }
}

impl ToJcs for SignatureSidecar {
    fn to_jcs(&self) -> Result<JcsValue, ProducerError> {
        Ok(jcs_object(vec![
            (
                "schema_version",
                jcs_integer(u64::from(self.schema_version))?,
            ),
            ("algorithm", jcs_string(self.algorithm.clone())),
            ("key_id", jcs_string(self.key_id.clone())),
            ("manifest_sha256", jcs_string(self.manifest_sha256.clone())),
            ("signature_b64", jcs_string(self.signature_b64.clone())),
        ]))
    }
}

fn utf16_key(value: &str) -> Vec<u16> {
    value.encode_utf16().collect()
}

fn write_canonical_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '\u{08}' => output.push_str("\\b"),
            '\u{09}' => output.push_str("\\t"),
            '\u{0a}' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\u{0d}' => output.push_str("\\r"),
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            other if (other as u32) <= 0x1f => {
                output.push_str(&format!("\\u{:04x}", other as u32));
            }
            other => output.push(other),
        }
    }
    output.push('"');
}

fn split_shortest_decimal(text: &str) -> Result<(String, i32), ProducerError> {
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(index) => (
            &text[..index],
            text[index + 1..]
                .parse::<i32>()
                .map_err(|_| ProducerError::AmbiguousNumber(text.to_owned()))?,
        ),
        None => (text, 0),
    };
    let (integer_part, fraction_part) = match mantissa.split_once('.') {
        Some((left, right)) => (left, right),
        None => (mantissa, ""),
    };
    let mut digits = format!("{integer_part}{fraction_part}");
    let mut point = i32::try_from(integer_part.len())
        .map_err(|_| ProducerError::AmbiguousNumber(text.to_owned()))?
        + exponent;
    while digits.len() > 1 && digits.starts_with('0') {
        digits.remove(0);
        point -= 1;
    }
    while digits.len() > 1 && digits.ends_with('0') {
        digits.pop();
    }
    Ok((digits, point))
}

/// Minimal ECMAScript number formatting used by the JCS canonicalizer.
fn format_es_number(value: f64) -> Result<String, ProducerError> {
    if !value.is_finite() {
        return Err(ProducerError::AmbiguousNumber(
            "non-finite double".to_owned(),
        ));
    }
    if value == 0.0 {
        return Ok("0".to_owned());
    }
    let negative = value < 0.0;
    let (digits, point) = split_shortest_decimal(&value.abs().to_string())?;
    let exponent = point - 1;
    let mut output = String::new();
    if negative {
        output.push('-');
    }
    if (-6..21).contains(&exponent) {
        if point <= 0 {
            output.push_str("0.");
            for _ in 0..-point {
                output.push('0');
            }
            output.push_str(&digits);
        } else if point >= digits.len() as i32 {
            output.push_str(&digits);
            for _ in 0..(point - digits.len() as i32) {
                output.push('0');
            }
        } else {
            let split = point as usize;
            output.push_str(&digits[..split]);
            output.push('.');
            output.push_str(&digits[split..]);
        }
    } else {
        output.push_str(&digits[..1]);
        if digits.len() > 1 {
            output.push('.');
            output.push_str(&digits[1..]);
        }
        output.push('e');
        output.push(if exponent >= 0 { '+' } else { '-' });
        let _ = write!(&mut output, "{}", exponent.abs());
    }
    Ok(output)
}

fn reject_floats(value: &JcsValue, location: &str) -> Result<(), ProducerError> {
    match value {
        JcsValue::Float(_) => Err(ProducerError::AmbiguousNumber(format!(
            "floating-point value at {location}; use a string for exact decimals"
        ))),
        JcsValue::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_floats(child, &format!("{location}[{index}]"))?;
            }
            Ok(())
        }
        JcsValue::Object(entries) => {
            for (key, child) in entries {
                reject_floats(child, &format!("{location}.{key}"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn write_jcs(
    output: &mut String,
    value: &JcsValue,
    policy: &ResourcePolicy,
    depth: u32,
) -> Result<(), ProducerError> {
    if depth > policy.max_nesting_depth {
        return Err(ProducerError::PolicyExceeded(format!(
            "nesting depth exceeds {}",
            policy.max_nesting_depth
        )));
    }
    match value {
        JcsValue::Null => output.push_str("null"),
        JcsValue::Bool(true) => output.push_str("true"),
        JcsValue::Bool(false) => output.push_str("false"),
        JcsValue::String(text) => write_canonical_string(output, text),
        JcsValue::Integer(number) => {
            if number.abs() > SAFE_INTEGER_MAX {
                return Err(ProducerError::AmbiguousNumber(
                    "integer outside exact ECMAScript range; encode as string".to_owned(),
                ));
            }
            let _ = write!(output, "{number}");
        }
        JcsValue::Float(number) => output.push_str(&format_es_number(*number)?),
        JcsValue::Array(values) => {
            if values.len() > policy.max_array_elements as usize {
                return Err(ProducerError::PolicyExceeded(format!(
                    "array length {} exceeds {}",
                    values.len(),
                    policy.max_array_elements
                )));
            }
            output.push('[');
            for (index, child) in values.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_jcs(output, child, policy, depth + 1)?;
            }
            output.push(']');
        }
        JcsValue::Object(entries) => {
            if entries.len() > policy.max_object_members as usize {
                return Err(ProducerError::PolicyExceeded(format!(
                    "object member count {} exceeds {}",
                    entries.len(),
                    policy.max_object_members
                )));
            }
            let mut sorted: Vec<&(String, JcsValue)> = entries.iter().collect();
            sorted.sort_by_key(|entry| utf16_key(&entry.0));
            for pair in sorted.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(ProducerError::DuplicateProperty(pair[0].0.clone()));
                }
            }
            output.push('{');
            for (index, (key, child)) in sorted.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_string(output, key);
                output.push(':');
                write_jcs(output, child, policy, depth + 1)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

/// Serialize one JCS value under a caller-supplied policy. Floating-point
/// values use minimal ECMAScript formatting in this general-purpose path.
pub fn canonicalize_value(
    value: &JcsValue,
    policy: &ResourcePolicy,
) -> Result<Vec<u8>, ProducerError> {
    let mut output = String::new();
    write_jcs(&mut output, value, policy, 0)?;
    Ok(output.into_bytes())
}

/// Serialize a manifest or record value. Floating-point input fails closed.
pub fn canonicalize_strict(
    value: &JcsValue,
    policy: &ResourcePolicy,
) -> Result<Vec<u8>, ProducerError> {
    reject_floats(value, "root")?;
    canonicalize_value(value, policy)
}

/// Canonicalize a JSON document with duplicate-name rejection.
pub fn parse_jcs_value(text: &str) -> Result<JcsValue, ProducerError> {
    serde_json::from_str::<JcsValue>(text)
        .map_err(|error| ProducerError::InvalidJson(error.to_string()))
}

/// Lowercase hex encoding helper for digests and signatures.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let output = hasher.finalize();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&output);
    digest
}

fn validate_hex_digest(value: &str, label: &str) -> Result<(), ProducerError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProducerError::InvalidLineage(format!(
            "{label} is not a 64-character lowercase hex digest"
        )));
    }
    Ok(())
}

fn validate_decimal_string(value: &str, label: &str) -> Result<u64, ProducerError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ProducerError::InvalidLineage(format!(
            "{label} is not an unsigned decimal string"
        )));
    }
    value
        .parse::<u64>()
        .map_err(|_| ProducerError::InvalidLineage(format!("{label} exceeds u64")))
}

fn validate_identifier(value: &str, label: &str) -> Result<(), ProducerError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ProducerError::InvalidLineage(format!(
            "{label} violates the identifier alphabet"
        )));
    }
    Ok(())
}

fn validate_artifact_path(path: &str, policy: &ResourcePolicy) -> Result<(), ProducerError> {
    let prefix = format!("{ARTIFACT_DIRECTORY}/");
    if !path.starts_with(&prefix) {
        return Err(ProducerError::InvalidArtifactPath(
            path.to_owned(),
            "path must begin with artifacts/".to_owned(),
        ));
    }
    if path.ends_with('/') || path.contains("//") || path.contains('\\') || path.contains('\0') {
        return Err(ProducerError::InvalidArtifactPath(
            path.to_owned(),
            "traversal, separator or NUL byte".to_owned(),
        ));
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() != 2 {
        return Err(ProducerError::InvalidArtifactPath(
            path.to_owned(),
            "the contract declares exactly one component below artifacts/".to_owned(),
        ));
    }
    for component in &components[1..] {
        if component.is_empty() || *component == "." || *component == ".." {
            return Err(ProducerError::InvalidArtifactPath(
                path.to_owned(),
                "dot component".to_owned(),
            ));
        }
        if component.len() > policy.max_path_component_bytes as usize {
            return Err(ProducerError::PolicyExceeded(format!(
                "path component length exceeds {}",
                policy.max_path_component_bytes
            )));
        }
        let bytes = component.as_bytes();
        if !bytes[0].is_ascii_alphanumeric()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(ProducerError::InvalidArtifactPath(
                path.to_owned(),
                "component outside the ASCII NFC alphabet".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_manifest(
    manifest: &ReleaseManifest,
    policy: &ResourcePolicy,
) -> Result<(), ProducerError> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(ProducerError::InvalidLineage(
            "unsupported schema version".to_owned(),
        ));
    }
    if manifest.contract_version != "v2" {
        return Err(ProducerError::InvalidLineage(
            "unsupported contract version".to_owned(),
        ));
    }
    validate_identifier(&manifest.release_identity.release_id, "release_id")?;
    validate_identifier(
        &manifest.publication_identity.publisher_identity,
        "publisher_identity",
    )?;
    if manifest.digests.digest_algorithm != DIGEST_ALGORITHM {
        return Err(ProducerError::InvalidLineage(
            "unsupported digest algorithm".to_owned(),
        ));
    }
    if manifest.publication_identity.signature_reference != SIDECAR_FILE_NAME {
        return Err(ProducerError::InvalidSignatureConfig(
            "signature_reference is not signature.json".to_owned(),
        ));
    }
    validate_decimal_string(
        &manifest.lineage.knowledge_time_ns,
        "lineage.knowledge_time_ns",
    )?;
    validate_decimal_string(
        &manifest.release_identity.as_of_ns,
        "release_identity.as_of_ns",
    )?;
    validate_decimal_string(
        &manifest.release_identity.created_at_utc_ns,
        "release_identity.created_at_utc_ns",
    )?;
    for field in [
        &manifest.producer_activity.performed_operations,
        &manifest.producer_activity.operation_evidence,
        &manifest.rights.permission_grants,
        &manifest.rights.document_references,
        &manifest.rights.reviewed_attestations,
    ] {
        if field.len() > policy.max_array_elements as usize {
            return Err(ProducerError::PolicyExceeded(
                "manifest array exceeds policy".to_owned(),
            ));
        }
    }
    if manifest.coverage.dimensions.len() > policy.max_array_elements as usize {
        return Err(ProducerError::PolicyExceeded(
            "coverage dimension count exceeds policy".to_owned(),
        ));
    }
    for dimension in &manifest.coverage.dimensions {
        if dimension.numerator > SAFE_INTEGER_MAX as u64
            || dimension.denominator > SAFE_INTEGER_MAX as u64
        {
            return Err(ProducerError::AmbiguousNumber(
                "coverage count outside exact integer range".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_lineage(
    manifest: &ReleaseManifest,
    context: &LineageContext<'_>,
) -> Result<(), ProducerError> {
    let Some(supersedes) = &manifest.lineage.supersedes else {
        return Ok(());
    };
    let current_id = &manifest.release_identity.release_id;
    if supersedes.supersedes_release_id == *current_id {
        return Err(ProducerError::InvalidLineage("self-reference".to_owned()));
    }
    validate_identifier(&supersedes.supersedes_release_id, "supersedes_release_id")?;
    validate_hex_digest(
        &supersedes.supersedes_manifest_sha256,
        "supersedes_manifest_sha256",
    )?;
    validate_hex_digest(&supersedes.supersedes_data_sha256, "supersedes_data_sha256")?;
    if supersedes.correction_reason.is_empty() || supersedes.invalidated_at_time.is_empty() {
        return Err(ProducerError::InvalidLineage(
            "empty correction evidence".to_owned(),
        ));
    }
    let knowledge_time = validate_decimal_string(
        &supersedes.knowledge_time_ns,
        "supersedes.knowledge_time_ns",
    )?;
    let as_of = validate_decimal_string(&manifest.release_identity.as_of_ns, "as_of_ns")?;
    if knowledge_time > context.now_ns || knowledge_time > as_of {
        return Err(ProducerError::InvalidLineage(
            "future knowledge time".to_owned(),
        ));
    }
    if supersedes.revision >= manifest.lineage.revision {
        return Err(ProducerError::InvalidLineage(
            "revision regression".to_owned(),
        ));
    }
    let predecessor = context
        .predecessor
        .ok_or_else(|| ProducerError::InvalidLineage("missing predecessor receipt".to_owned()))?;
    if predecessor.release_id != supersedes.supersedes_release_id
        || predecessor.manifest_sha256 != supersedes.supersedes_manifest_sha256
        || predecessor.data_sha256 != supersedes.supersedes_data_sha256
    {
        return Err(ProducerError::InvalidLineage(
            "predecessor receipt does not bind to the descriptor".to_owned(),
        ));
    }
    let mut visited = BTreeSet::new();
    visited.insert(current_id.clone());
    let mut cursor = supersedes.supersedes_release_id.clone();
    loop {
        if !visited.insert(cursor.clone()) {
            return Err(ProducerError::InvalidLineage("correction cycle".to_owned()));
        }
        let receipt = context
            .known_receipts
            .iter()
            .find(|receipt| receipt.release_id == cursor)
            .ok_or_else(|| ProducerError::InvalidLineage("missing chain receipt".to_owned()))?;
        let Some(parent) = &receipt.supersedes_release_id else {
            break;
        };
        cursor = parent.clone();
    }
    Ok(())
}

fn validate_record(
    bytes: &[u8],
    index: usize,
    policy: &ResourcePolicy,
) -> Result<(), ProducerError> {
    if bytes.is_empty() {
        return Err(ProducerError::InvalidRecord(
            index,
            "empty record".to_owned(),
        ));
    }
    if bytes.len() > policy.max_record_bytes as usize {
        return Err(ProducerError::PolicyExceeded(format!(
            "record {index} exceeds {}",
            policy.max_record_bytes
        )));
    }
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(ProducerError::InvalidRecord(index, "UTF-8 BOM".to_owned()));
    }
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') || bytes.contains(&0) {
        return Err(ProducerError::InvalidRecord(
            index,
            "line boundary or NUL byte".to_owned(),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|error| ProducerError::InvalidRecord(index, format!("invalid UTF-8: {error}")))?;
    let value = parse_jcs_value(text)
        .map_err(|error| ProducerError::InvalidRecord(index, error.to_string()))?;
    let canonical = canonicalize_strict(&value, policy)
        .map_err(|error| ProducerError::InvalidRecord(index, error.to_string()))?;
    if canonical != bytes {
        return Err(ProducerError::InvalidRecord(
            index,
            "record bytes are not RFC 8785 canonical".to_owned(),
        ));
    }
    Ok(())
}

fn reference_key_tuple(key: &RecordOrderKey) -> Option<(&str, u64, u64, &str)> {
    match key {
        RecordOrderKey::Reference {
            object_id,
            revision,
            knowledge_time_ns,
            assertion_id,
        } => {
            let time = knowledge_time_ns.parse::<u64>().ok()?;
            Some((object_id, *revision, time, assertion_id))
        }
        RecordOrderKey::Sequenced { .. } => None,
    }
}

fn validate_record_order(
    path: &str,
    profile: &RecordOrderProfile,
    records: &[CanonicalRecord],
    policy: &ResourcePolicy,
) -> Result<(), ProducerError> {
    if records.len() > policy.max_records_per_artifact as usize {
        return Err(ProducerError::PolicyExceeded(format!(
            "record count for {path} exceeds {}",
            policy.max_records_per_artifact
        )));
    }
    let mut previous_sequence: Option<u64> = None;
    let mut previous_reference: Option<(String, u64, u64, String)> = None;
    for record in records {
        match (profile, &record.order_key) {
            (
                RecordOrderProfile::Sequenced {
                    sequence_domain,
                    sequence_epoch,
                },
                RecordOrderKey::Sequenced {
                    sequence_domain: domain,
                    sequence_epoch: epoch,
                    sequence_number,
                },
            ) => {
                if domain != sequence_domain || epoch != sequence_epoch {
                    return Err(ProducerError::InvalidRecordOrder(
                        path.to_owned(),
                        "sequence domain or epoch mismatch".to_owned(),
                    ));
                }
                if previous_sequence == Some(*sequence_number) {
                    return Err(ProducerError::InvalidRecordOrder(
                        path.to_owned(),
                        "duplicate sequence position".to_owned(),
                    ));
                }
                if previous_sequence.is_some_and(|value| *sequence_number < value) {
                    return Err(ProducerError::InvalidRecordOrder(
                        path.to_owned(),
                        "sequence position moved backwards".to_owned(),
                    ));
                }
                previous_sequence = Some(*sequence_number);
            }
            (RecordOrderProfile::Reference, RecordOrderKey::Reference { .. }) => {
                let (object_id, revision, time, assertion_id) =
                    reference_key_tuple(&record.order_key).ok_or_else(|| {
                        ProducerError::InvalidRecordOrder(
                            path.to_owned(),
                            "invalid reference key".to_owned(),
                        )
                    })?;
                let current = (
                    object_id.to_owned(),
                    revision,
                    time,
                    assertion_id.to_owned(),
                );
                if previous_reference.as_ref() == Some(&current) {
                    return Err(ProducerError::InvalidRecordOrder(
                        path.to_owned(),
                        "duplicate reference position".to_owned(),
                    ));
                }
                if previous_reference
                    .as_ref()
                    .is_some_and(|previous| current < *previous)
                {
                    return Err(ProducerError::InvalidRecordOrder(
                        path.to_owned(),
                        "reference position moved backwards".to_owned(),
                    ));
                }
                previous_reference = Some(current);
            }
            _ => {
                return Err(ProducerError::InvalidRecordOrder(
                    path.to_owned(),
                    "order key does not match declared profile".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn compress_stream(
    uncompressed: &[u8],
    compression: ArtifactCompression,
) -> Result<Vec<u8>, ProducerError> {
    match compression {
        ArtifactCompression::None => Ok(uncompressed.to_vec()),
        ArtifactCompression::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), GzipCompression::default());
            encoder
                .write_all(uncompressed)
                .map_err(|error| ProducerError::Io("gzip record stream".to_owned(), error))?;
            encoder
                .finish()
                .map_err(|error| ProducerError::Io("finalize gzip stream".to_owned(), error))
        }
    }
}

struct PreparedArtifact {
    descriptor: ArtifactDescriptor,
    stored: Vec<u8>,
}

struct PreparedRelease {
    manifest_bytes: Vec<u8>,
    sidecar_bytes: Vec<u8>,
    descriptors: Vec<ArtifactDescriptor>,
    artifacts: Vec<(String, Vec<u8>)>,
    evidence: PublicationEvidence,
    receipt: PublicationReceipt,
}

fn prepare_release(request: &BuildRequest<'_>) -> Result<PreparedRelease, ProducerError> {
    validate_manifest(request.manifest, request.policy)?;
    validate_lineage(request.manifest, &request.lineage)?;
    if request.artifacts.is_empty() {
        return Err(ProducerError::PolicyExceeded(
            "no artifacts declared".to_owned(),
        ));
    }
    if request.artifacts.len() > request.policy.max_artifact_count as usize {
        return Err(ProducerError::PolicyExceeded(
            "artifact count exceeds policy".to_owned(),
        ));
    }
    if request.signature.key_id != request.manifest.publication_identity.signing_key_id {
        return Err(ProducerError::InvalidSignatureConfig(
            "sidecar key id does not match the manifest publisher".to_owned(),
        ));
    }
    let expected_verifying_key = request.signature.signing_key.verifying_key();
    if request.signature.verifying_key != &expected_verifying_key {
        return Err(ProducerError::InvalidSignatureConfig(
            "injected verifying key does not match the signing key".to_owned(),
        ));
    }

    let mut inputs: Vec<ArtifactInput> = request.artifacts.to_vec();
    inputs.sort_by(|left, right| {
        left.logical_partition_id
            .cmp(&right.logical_partition_id)
            .then(left.shard_ordinal.cmp(&right.shard_ordinal))
    });
    let mut positions = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for input in &inputs {
        if !positions.insert((input.logical_partition_id.clone(), input.shard_ordinal)) {
            return Err(ProducerError::DuplicateArtifactPosition(
                input.logical_partition_id.clone(),
                input.shard_ordinal,
            ));
        }
        validate_artifact_path(&input.path, request.policy)?;
        if !paths.insert(input.path.clone()) {
            return Err(ProducerError::DuplicateArtifactPath(input.path.clone()));
        }
        if input.encoding != ENCODING_NDJSON {
            return Err(ProducerError::PolicyExceeded(
                "unsupported artifact encoding".to_owned(),
            ));
        }
    }

    let mut dataset_hasher = Sha256::new();
    let mut prepared = Vec::with_capacity(inputs.len());
    let mut descriptors = Vec::with_capacity(inputs.len());
    let mut total_stored = 0_u64;
    let mut total_uncompressed = 0_u64;
    for (index, input) in inputs.iter().enumerate() {
        for (record_index, record) in input.records.iter().enumerate() {
            validate_record(&record.bytes, record_index, request.policy)?;
        }
        validate_record_order(
            &input.path,
            &input.record_order_profile,
            &input.records,
            request.policy,
        )?;
        let mut uncompressed = Vec::new();
        for record in &input.records {
            uncompressed.extend_from_slice(&record.bytes);
            uncompressed.push(b'\n');
        }
        let uncompressed_bytes = u64::try_from(uncompressed.len()).map_err(|_| {
            ProducerError::PolicyExceeded("artifact stream exceeds addressable length".to_owned())
        })?;
        if uncompressed_bytes > request.policy.max_uncompressed_bytes_per_artifact {
            return Err(ProducerError::PolicyExceeded(format!(
                "artifact {index} exceeds uncompressed policy"
            )));
        }
        total_uncompressed = total_uncompressed.saturating_add(uncompressed_bytes);
        if total_uncompressed > request.policy.max_total_uncompressed_bytes {
            return Err(ProducerError::PolicyExceeded(
                "total uncompressed bytes exceed policy".to_owned(),
            ));
        }
        let stored = compress_stream(&uncompressed, input.compression)?;
        let stored_bytes = u64::try_from(stored.len()).map_err(|_| {
            ProducerError::PolicyExceeded("stored stream exceeds addressable length".to_owned())
        })?;
        if stored_bytes > request.policy.max_stored_bytes_per_artifact {
            return Err(ProducerError::PolicyExceeded(format!(
                "artifact {index} exceeds stored policy"
            )));
        }
        total_stored = total_stored.saturating_add(stored_bytes);
        if total_stored > request.policy.max_total_stored_bytes {
            return Err(ProducerError::PolicyExceeded(
                "total stored bytes exceed policy".to_owned(),
            ));
        }
        dataset_hasher.update(&uncompressed);
        let descriptor = ArtifactDescriptor {
            logical_partition_id: input.logical_partition_id.clone(),
            shard_ordinal: input.shard_ordinal,
            path: input.path.clone(),
            record_order_profile: input.record_order_profile.clone(),
            encoding: input.encoding.clone(),
            compression: input.compression.as_str().to_owned(),
            compression_version: input.compression.version_str().to_owned(),
            stored_bytes,
            stored_sha256: hex_encode(&sha256(&stored)),
            uncompressed_bytes,
            uncompressed_sha256: hex_encode(&sha256(&uncompressed)),
            record_count: u64::try_from(input.records.len()).map_err(|_| {
                ProducerError::PolicyExceeded("record count exceeds addressable length".to_owned())
            })?,
        };
        descriptors.push(descriptor.clone());
        prepared.push(PreparedArtifact { descriptor, stored });
    }
    let dataset_digest = dataset_hasher.finalize();
    let data_sha256 = hex_encode(&dataset_digest);

    let mut manifest = request.manifest.clone();
    manifest.artifacts = descriptors.clone();
    manifest.digests.data_sha256 = data_sha256.clone();
    let wire_manifest = crate::distribution::ndc_wire::map_manifest(
        &manifest,
        request.evidence,
        &data_sha256,
        request.observed_event_types,
    )
    .map_err(|error| ProducerError::WireMapping(error.to_string()))?;
    let manifest_bytes = canonicalize_strict(&wire_manifest, request.policy)?;
    if manifest_bytes.len() > request.policy.max_manifest_bytes as usize {
        return Err(ProducerError::PolicyExceeded(
            "canonical manifest exceeds policy".to_owned(),
        ));
    }
    let manifest_digest = sha256(&manifest_bytes);
    let manifest_sha256 = hex_encode(&manifest_digest);

    let mut message = Vec::with_capacity(SIGNING_DOMAIN.len() + manifest_digest.len());
    message.extend_from_slice(SIGNING_DOMAIN);
    message.extend_from_slice(&manifest_digest);
    let signature = request.signature.signing_key.sign(&message);
    request
        .signature
        .verifying_key
        .verify(&message, &signature)
        .map_err(|_| ProducerError::InvalidSignatureConfig("self-check failed".to_owned()))?;
    let sidecar = SignatureSidecar {
        schema_version: SIDECAR_SCHEMA_VERSION,
        algorithm: SIGNATURE_ALGORITHM.to_owned(),
        key_id: request.signature.key_id.to_owned(),
        manifest_sha256: manifest_sha256.clone(),
        signature_b64: BASE64.encode(signature.to_bytes()),
    };
    let mut sidecar_bytes = canonicalize_strict(&sidecar.to_jcs()?, request.policy)?;
    sidecar_bytes.push(b'\n');
    if sidecar_bytes.len() > request.policy.max_sidecar_bytes as usize {
        return Err(ProducerError::PolicyExceeded(
            "sidecar exceeds policy".to_owned(),
        ));
    }

    let mut stored_paths = Vec::new();
    let mut stored_digests = Vec::new();
    let mut artifacts = Vec::new();
    for item in prepared {
        stored_paths.push(item.descriptor.path.clone());
        stored_digests.push(item.descriptor.stored_sha256.clone());
        artifacts.push((item.descriptor.path, item.stored));
    }
    let receipt = PublicationReceipt {
        schema_version: MANIFEST_SCHEMA_VERSION,
        release_id: manifest.release_identity.release_id.clone(),
        manifest_sha256: manifest_sha256.clone(),
        data_sha256: data_sha256.clone(),
        publication_operation_id: request.operation_id.to_owned(),
        commit_position: request.commit_position.to_owned(),
        result: PublicationState::Available,
        supersedes_release_id: manifest
            .lineage
            .supersedes
            .as_ref()
            .map(|value| value.supersedes_release_id.clone()),
    };
    let receipt_bytes = receipt_file_bytes(&receipt, request.policy)?;
    let evidence = PublicationEvidence {
        release_id: receipt.release_id.clone(),
        manifest_sha256: manifest_sha256.clone(),
        data_sha256: data_sha256.clone(),
        publication_operation_id: request.operation_id.to_owned(),
        commit_position: request.commit_position.to_owned(),
        artifact_paths: stored_paths,
        artifact_stored_sha256: stored_digests,
        expected_receipt: receipt.clone(),
        receipt_sha256: hex_encode(&sha256(&receipt_bytes)),
    };
    Ok(PreparedRelease {
        manifest_bytes,
        sidecar_bytes,
        descriptors,
        artifacts,
        evidence,
        receipt,
    })
}

fn io_error(operation: &str, error: std::io::Error) -> ProducerError {
    ProducerError::Io(operation.to_owned(), error)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), ProducerError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| io_error(&format!("create {}", path.display()), error))?;
    file.write_all(bytes)
        .map_err(|error| io_error(&format!("write {}", path.display()), error))?;
    file.sync_all()
        .map_err(|error| io_error(&format!("sync {}", path.display()), error))
}

fn sync_directory(path: &Path) -> Result<(), ProducerError> {
    let directory = File::open(path)
        .map_err(|error| io_error(&format!("open directory {}", path.display()), error))?;
    directory
        .sync_all()
        .map_err(|error| io_error(&format!("sync directory {}", path.display()), error))
}

fn staging_name(operation_id: &str) -> String {
    format!(".staging-{operation_id}")
}

fn stage_path(ledger: &Path, operation_id: &str, ordinal: u32) -> PathBuf {
    ledger.join(format!("{operation_id}.stage.{ordinal:04}.json"))
}

fn write_stage(
    ledger: &Path,
    operation: &PublicationOperation,
    ordinal: u32,
    policy: &ResourcePolicy,
) -> Result<(), ProducerError> {
    let bytes = canonicalize_strict(&operation.to_jcs()?, policy)?;
    let mut bytes = bytes;
    bytes.push(b'\n');
    write_new_file(
        &stage_path(ledger, &operation.operation_id, ordinal),
        &bytes,
    )
}

fn next_stage_ordinal(ledger: &Path, operation_id: &str) -> Result<u32, ProducerError> {
    let stages = read_stage_operations(ledger, operation_id)?;
    Ok(stages
        .last()
        .map_or(0, |(ordinal, _)| ordinal.saturating_add(1)))
}

fn receipt_file_bytes(
    receipt: &PublicationReceipt,
    policy: &ResourcePolicy,
) -> Result<Vec<u8>, ProducerError> {
    let mut bytes = canonicalize_strict(&receipt.to_jcs()?, policy)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn stage_for_state(
    operation: &PublicationOperation,
    state: PublicationState,
) -> PublicationOperation {
    let mut staged = operation.clone();
    staged.stage = state;
    staged
}

fn stage_file_parts(name: &str) -> Option<(String, u32)> {
    let stem = name.strip_suffix(".json")?;
    let (operation_id, ordinal_text) = stem.rsplit_once(".stage.")?;
    if operation_id.is_empty() {
        return None;
    }
    let ordinal = ordinal_text.parse::<u32>().ok()?;
    Some((operation_id.to_owned(), ordinal))
}

fn read_all_stage_operations(
    ledger: &Path,
) -> Result<Vec<(String, u32, PublicationOperation)>, ProducerError> {
    let entries = fs::read_dir(ledger)
        .map_err(|error| io_error(&format!("read ledger {}", ledger.display()), error))?;
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error("read ledger entry", error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some((operation_id, ordinal)) = stage_file_parts(&name) else {
            continue;
        };
        let bytes = fs::read(entry.path())
            .map_err(|error| io_error(&format!("read stage {name}"), error))?;
        let operation: PublicationOperation = serde_json::from_slice(&bytes).map_err(|error| {
            ProducerError::PublicationEvidence(format!("invalid stage evidence: {error}"))
        })?;
        found.push((operation_id, ordinal, operation));
    }
    found.sort_by_key(|(operation_id, ordinal, _)| (operation_id.clone(), *ordinal));
    Ok(found)
}

fn validate_stage_sequence(stages: &[(u32, PublicationOperation)]) -> Result<(), ProducerError> {
    let Some((first_ordinal, first)) = stages.first() else {
        return Ok(());
    };
    if *first_ordinal != 0 {
        return Err(ProducerError::PublicationEvidence(format!(
            "stage history starts at ordinal {first_ordinal} instead of 0"
        )));
    }
    let mut previous: Option<&PublicationOperation> = None;
    for (index, (ordinal, operation)) in stages.iter().enumerate() {
        let expected_ordinal = u32::try_from(index).map_err(|_| {
            ProducerError::PublicationEvidence("stage ordinal exceeds addressable range".to_owned())
        })?;
        if *ordinal != expected_ordinal {
            return Err(ProducerError::PublicationEvidence(format!(
                "stage ordinal {ordinal} repeats or skips position {expected_ordinal}"
            )));
        }
        let expected_state = STAGE_ORDER.get(index).ok_or_else(|| {
            ProducerError::PublicationEvidence("stage history exceeds the state machine".to_owned())
        })?;
        if operation.stage != *expected_state {
            return Err(ProducerError::PublicationEvidence(format!(
                "stage {ordinal} records {} instead of {}",
                operation.stage.as_str(),
                expected_state.as_str()
            )));
        }
        if operation.schema_version != MANIFEST_SCHEMA_VERSION {
            return Err(ProducerError::PublicationEvidence(format!(
                "stage {ordinal} carries schema version {}",
                operation.schema_version
            )));
        }
        if operation.operation_id != first.operation_id
            || operation.release_id != first.release_id
            || operation.manifest_sha256 != first.manifest_sha256
            || operation.data_sha256 != first.data_sha256
            || operation.commit_position != first.commit_position
            || operation.staging_directory != first.staging_directory
            || operation.final_directory != first.final_directory
        {
            return Err(ProducerError::PublicationEvidence(format!(
                "stage {ordinal} conflicts with the operation identity at ordinal 0"
            )));
        }
        if let Some(prior) = previous
            && operation.stage.rank() < prior.stage.rank()
        {
            return Err(ProducerError::PublicationEvidence(format!(
                "stage {ordinal} regresses from {} to {}",
                prior.stage.as_str(),
                operation.stage.as_str()
            )));
        }
        previous = Some(operation);
    }
    Ok(())
}

fn validate_stage_history(
    stages: &[(u32, PublicationOperation)],
    evidence: &PublicationEvidence,
) -> Result<(), ProducerError> {
    validate_stage_sequence(stages)?;
    for (ordinal, operation) in stages {
        if operation.operation_id != evidence.publication_operation_id
            || operation.release_id != evidence.release_id
            || operation.manifest_sha256 != evidence.manifest_sha256
            || operation.data_sha256 != evidence.data_sha256
            || operation.commit_position != evidence.commit_position
        {
            return Err(ProducerError::UncertainPublication(format!(
                "stage {ordinal} does not bind to the supplied publication intent"
            )));
        }
        if operation.staging_directory != staging_name(&operation.operation_id)
            || operation.final_directory != evidence.release_id
        {
            return Err(ProducerError::UncertainPublication(format!(
                "stage {ordinal} does not bind to the declared staging and final paths"
            )));
        }
    }
    Ok(())
}

fn read_stage_operations(
    ledger: &Path,
    operation_id: &str,
) -> Result<Vec<(u32, PublicationOperation)>, ProducerError> {
    let all = read_all_stage_operations(ledger)?;
    let mut found: Vec<(u32, PublicationOperation)> = all
        .into_iter()
        .filter(|(name, _ordinal, operation)| {
            name == operation_id && operation.operation_id == *name
        })
        .map(|(_, ordinal, operation)| (ordinal, operation))
        .collect();
    found.sort_by_key(|(ordinal, _)| *ordinal);
    validate_stage_sequence(&found)?;
    Ok(found)
}

fn verify_durable_stage(
    ledger: &Path,
    evidence: &PublicationEvidence,
    minimum: PublicationState,
) -> Result<(), ProducerError> {
    let stages = read_stage_operations(ledger, &evidence.publication_operation_id)?;
    validate_stage_history(&stages, evidence)?;
    let (_, operation) = stages.last().ok_or_else(|| {
        ProducerError::UncertainPublication("no durable stage evidence to verify".to_owned())
    })?;
    if operation.stage.rank() < minimum.rank() {
        return Err(ProducerError::UncertainPublication(format!(
            "durable stage {} precedes required {}",
            operation.stage.as_str(),
            minimum.as_str()
        )));
    }
    Ok(())
}

fn find_foreign_rename_evidence(
    ledger: &Path,
    evidence: &PublicationEvidence,
) -> Result<(), ProducerError> {
    let all = read_all_stage_operations(ledger)?;
    for (operation_id, ordinal, operation) in all {
        if operation_id == evidence.publication_operation_id
            || operation.release_id != evidence.release_id
            || operation.stage.rank() < PublicationState::AtomicNoReplaceRename.rank()
        {
            continue;
        }
        return Err(ProducerError::UncertainPublication(format!(
            "release {} was renamed by operation {} at stage {ordinal}",
            evidence.release_id, operation_id
        )));
    }
    Ok(())
}

fn verify_operation_identity(
    final_dir: &Path,
    evidence: &PublicationEvidence,
    operation: &PublicationOperation,
    ledger: &Path,
) -> Result<(), ProducerError> {
    if operation.stage.rank() < PublicationState::AtomicNoReplaceRename.rank() {
        return Err(ProducerError::UncertainPublication(format!(
            "operation {} has no durable rename evidence",
            operation.operation_id
        )));
    }
    if operation.final_directory != evidence.release_id
        || operation.staging_directory != staging_name(&operation.operation_id)
        || final_dir
            .file_name()
            .is_none_or(|name| name != evidence.release_id.as_str())
    {
        return Err(ProducerError::UncertainPublication(format!(
            "operation {} does not own the final release directory",
            operation.operation_id
        )));
    }
    find_foreign_rename_evidence(ledger, evidence)
}

fn validate_artifact_set(
    directory: &Path,
    evidence: &PublicationEvidence,
    policy: &ResourcePolicy,
) -> Result<(), ProducerError> {
    let entries = fs::read_dir(directory)
        .map_err(|error| io_error(&format!("read release {}", directory.display()), error))?;
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|error| io_error("read release entry", error))?;
        names.insert(entry.file_name().to_string_lossy().into_owned());
    }
    let expected_top: BTreeSet<String> = [
        MANIFEST_FILE_NAME.to_owned(),
        SIDECAR_FILE_NAME.to_owned(),
        ARTIFACT_DIRECTORY.to_owned(),
    ]
    .into_iter()
    .collect();
    if names != expected_top {
        return Err(ProducerError::ArtifactSetMismatch(format!(
            "release {} top-level file set differs from manifest, sidecar and artifacts",
            evidence.release_id
        )));
    }
    let artifact_root = directory.join(ARTIFACT_DIRECTORY);
    let artifact_entries = fs::read_dir(&artifact_root)
        .map_err(|error| io_error("read staged artifact directory", error))?;
    let mut artifact_names = BTreeSet::new();
    for entry in artifact_entries {
        let entry = entry.map_err(|error| io_error("read staged artifact entry", error))?;
        artifact_names.insert(entry.file_name().to_string_lossy().into_owned());
    }
    let mut expected_artifacts = BTreeSet::new();
    for path in &evidence.artifact_paths {
        validate_artifact_path(path, policy)?;
        let relative = path
            .strip_prefix(&format!("{ARTIFACT_DIRECTORY}/"))
            .ok_or_else(|| {
                ProducerError::InvalidArtifactPath(
                    path.clone(),
                    "declared artifact path is not release-relative under artifacts/".to_owned(),
                )
            })?;
        expected_artifacts.insert(relative.to_owned());
    }
    if artifact_names != expected_artifacts {
        return Err(ProducerError::ArtifactSetMismatch(format!(
            "release {} artifact set differs from the declared inventory",
            evidence.release_id
        )));
    }
    let manifest_digest = hex_encode(&sha256(
        &fs::read(directory.join(MANIFEST_FILE_NAME))
            .map_err(|error| io_error("read staged manifest", error))?,
    ));
    if manifest_digest != evidence.manifest_sha256 {
        return Err(ProducerError::PublicationEvidence(
            "manifest digest differs from operation evidence".to_owned(),
        ));
    }
    for (path, digest) in evidence
        .artifact_paths
        .iter()
        .zip(&evidence.artifact_stored_sha256)
    {
        let relative = path
            .strip_prefix(&format!("{ARTIFACT_DIRECTORY}/"))
            .ok_or_else(|| {
                ProducerError::InvalidArtifactPath(
                    path.clone(),
                    "declared artifact path is not release-relative under artifacts/".to_owned(),
                )
            })?;
        let bytes = fs::read(artifact_root.join(relative))
            .map_err(|error| io_error(&format!("read staged artifact {relative}"), error))?;
        if hex_encode(&sha256(&bytes)) != *digest {
            return Err(ProducerError::PublicationEvidence(format!(
                "artifact digest differs for {relative}"
            )));
        }
    }
    Ok(())
}

/// Injection points used by the offline crash-state tests. Production passes
/// the default value, which enables every transition in sequence.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "boundary faults are configured by the offline crash tests"
    )
)]
struct PublicationFaults {
    /// Return an error after staging sync and before the directory rename.
    fail_before_rename: bool,
    /// Return an error after the rename syscall and before its stage record.
    fail_after_rename_before_stage: bool,
    /// Return an error after the rename stage and before the parent sync.
    fail_after_rename: bool,
    /// Return an error before the parent directory sync runs.
    fail_parent_dir_sync: bool,
    /// Return an error after the parent sync and before the receipt commit.
    fail_after_parent_sync: bool,
    /// Return an error after creating an empty receipt and before writing it.
    fail_receipt_commit: bool,
    /// Return an error after the receipt file sync and before the ledger sync.
    fail_receipt_ledger_sync: bool,
    /// Return an error after creating an empty marker and before writing it.
    fail_marker_commit: bool,
    /// Return an error after the marker file sync and before the ledger sync.
    fail_marker_ledger_sync: bool,
}

/// Filesystem boundary used by publication and recovery. The production
/// implementation performs host calls; the offline implementation records
/// every boundary so crash tests can assert durable operation order.
trait PublicationFs {
    /// Record one logical publication event.
    fn record(&self, event: PublicationRecoveryEvent);

    /// Sync the parent directory that holds the final release name.
    fn sync_release_parent(&self, root: &Path) -> Result<(), ProducerError>;

    /// Create, write and sync one durable receipt file.
    fn commit_receipt(&self, path: &Path, bytes: &[u8]) -> Result<(), ProducerError>;

    /// Sync the receipt ledger directory entry after a durable commit.
    fn sync_receipt_ledger(&self, ledger: &Path) -> Result<(), ProducerError>;

    /// Create, write and sync one availability marker file.
    fn commit_availability_marker(&self, path: &Path, bytes: &[u8]) -> Result<(), ProducerError>;
}

struct RealPublicationFs;

impl PublicationFs for RealPublicationFs {
    fn record(&self, _event: PublicationRecoveryEvent) {}

    fn sync_release_parent(&self, root: &Path) -> Result<(), ProducerError> {
        sync_directory(root)
    }

    fn commit_receipt(&self, path: &Path, bytes: &[u8]) -> Result<(), ProducerError> {
        write_new_file(path, bytes)
    }

    fn sync_receipt_ledger(&self, ledger: &Path) -> Result<(), ProducerError> {
        sync_directory(ledger)
    }

    fn commit_availability_marker(&self, path: &Path, bytes: &[u8]) -> Result<(), ProducerError> {
        write_new_file(path, bytes)
    }
}

#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "the kernel exposes renameat2 only through an unsafe libc syscall"
)]
fn atomic_no_replace_rename(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let from = CString::new(from.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let to = CString::new(to.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // SAFETY: `from` and `to` own their byte buffers, so both pointers are
    // non-null and live for this call. The two allocations cannot alias.
    // `AT_FDCWD` is the libc current-directory sentinel; the kernel reads the
    // two path pointers and the `RENAME_NOREPLACE` flag as the syscall ABI
    // declares, so no destination is replaced.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2 as libc::c_long,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    reason = "the Darwin no-replace primitive is an unsafe libc function"
)]
fn atomic_no_replace_rename(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    let from = CString::new(from.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let to = CString::new(to.as_os_str().as_bytes())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    // SAFETY: `from` and `to` own their byte buffers, so both pointers are
    // non-null and live for this call. The two allocations cannot alias.
    // `RENAME_EXCL` asks Darwin to reject an existing destination rather than
    // replacing it; the returned status is checked before success is reported.
    let result = unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn atomic_no_replace_rename(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "atomic no-replace directory rename requires Linux renameat2 or macOS renamex_np",
    ))
}

fn ensure_sibling_release_paths(staging: &Path, final_dir: &Path) -> Result<(), ProducerError> {
    let staging_parent = staging.parent().ok_or_else(|| {
        ProducerError::PublicationTopology("staging path has no parent directory".to_owned())
    })?;
    let final_parent = final_dir.parent().ok_or_else(|| {
        ProducerError::PublicationTopology("final path has no parent directory".to_owned())
    })?;
    let staging_canonical = fs::canonicalize(staging_parent)
        .map_err(|error| io_error("canonicalize staging parent", error))?;
    let final_canonical = fs::canonicalize(final_parent)
        .map_err(|error| io_error("canonicalize final parent", error))?;
    if staging_canonical != final_canonical {
        return Err(ProducerError::PublicationTopology(
            "staging and final release directories are not siblings".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let staging_device = fs::metadata(staging)
            .map_err(|error| {
                io_error(
                    &format!("read staging metadata {}", staging.display()),
                    error,
                )
            })?
            .dev();
        let parent_device = fs::metadata(&final_canonical)
            .map_err(|error| io_error("read final parent metadata", error))?
            .dev();
        if staging_device != parent_device {
            return Err(ProducerError::PublicationTopology(
                "staging and final release directories are on different filesystems".to_owned(),
            ));
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "the publication boundary carries two paths, operation evidence, a policy, injected faults and a filesystem boundary"
)]
fn finalize_publication(
    root: &Path,
    ledger: &Path,
    operation: &PublicationOperation,
    staging: &Path,
    final_dir: &Path,
    receipt: &PublicationReceipt,
    policy: &ResourcePolicy,
    faults: PublicationFaults,
    fs: &dyn PublicationFs,
) -> Result<(), ProducerError> {
    ensure_sibling_release_paths(staging, final_dir)?;
    let start = next_stage_ordinal(ledger, &operation.operation_id)?;

    if faults.fail_before_rename {
        return Err(io_error(
            "injected failure before the directory rename",
            io::Error::other("injected failure before the directory rename"),
        ));
    }
    atomic_no_replace_rename(staging, final_dir).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            ProducerError::PublicationCollision(operation.release_id.clone())
        } else {
            io_error("atomic no-replace directory rename", error)
        }
    })?;
    if faults.fail_after_rename_before_stage {
        return Err(io_error(
            "injected failure after the rename syscall",
            io::Error::other("injected failure after the rename syscall"),
        ));
    }
    // The rename has committed before this label is written. No stage record
    // claims a rename that did not run.
    write_stage(
        ledger,
        &stage_for_state(operation, PublicationState::AtomicNoReplaceRename),
        start,
        policy,
    )?;

    if faults.fail_after_rename {
        return Err(io_error(
            "injected failure after the directory rename",
            io::Error::other("injected failure after the directory rename"),
        ));
    }
    fs.sync_release_parent(root)?;
    write_stage(
        ledger,
        &stage_for_state(operation, PublicationState::ParentDirFsynced),
        start + 1,
        policy,
    )?;

    let receipt_path = ledger.join(format!("{}.receipt.json", receipt.release_id));
    fs.commit_receipt(&receipt_path, &receipt_file_bytes(receipt, policy)?)?;
    fs.sync_receipt_ledger(ledger)?;
    write_stage(
        ledger,
        &stage_for_state(operation, PublicationState::DurablePublicationReceipt),
        start + 2,
        policy,
    )?;

    let marker = ledger.join(format!("{}.available", receipt.release_id));
    fs.commit_availability_marker(&marker, operation.operation_id.as_bytes())?;
    fs.sync_receipt_ledger(ledger)?;
    write_stage(
        ledger,
        &stage_for_state(operation, PublicationState::Available),
        start + 3,
        policy,
    )?;
    Ok(())
}

fn load_receipt(
    ledger: &Path,
    release_id: &str,
) -> Result<Option<(Vec<u8>, PublicationReceipt)>, ProducerError> {
    let path = ledger.join(format!("{release_id}.receipt.json"));
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path)
        .map_err(|error| io_error(&format!("read receipt {}", path.display()), error))?;
    let receipt: PublicationReceipt = serde_json::from_slice(&bytes).map_err(|error| {
        ProducerError::UncertainPublication(format!("durable receipt is unreadable: {error}"))
    })?;
    Ok(Some((bytes, receipt)))
}

fn receipt_matches(
    receipt: &PublicationReceipt,
    bytes: &[u8],
    evidence: &PublicationEvidence,
) -> bool {
    receipt.schema_version == evidence.expected_receipt.schema_version
        && receipt.release_id == evidence.release_id
        && receipt.manifest_sha256 == evidence.manifest_sha256
        && receipt.data_sha256 == evidence.data_sha256
        && receipt.publication_operation_id == evidence.publication_operation_id
        && receipt.commit_position == evidence.commit_position
        && receipt.result == PublicationState::Available
        && receipt.supersedes_release_id == evidence.expected_receipt.supersedes_release_id
        && hex_encode(&sha256(bytes)) == evidence.receipt_sha256
}

fn recovery_receipt(evidence: &PublicationEvidence) -> PublicationReceipt {
    evidence.expected_receipt.clone()
}

fn advance_recovery_stage(
    ledger: &Path,
    evidence: &PublicationEvidence,
    operation: &PublicationOperation,
    state: PublicationState,
    policy: &ResourcePolicy,
) -> Result<(), ProducerError> {
    let ordinal = next_stage_ordinal(ledger, &operation.operation_id)?;
    write_stage(ledger, &stage_for_state(operation, state), ordinal, policy)?;
    verify_durable_stage(ledger, evidence, state)
}

fn recover_final_directory(
    root: &Path,
    ledger: &Path,
    evidence: &PublicationEvidence,
    policy: &ResourcePolicy,
    operation: &PublicationOperation,
    stages: &[(u32, PublicationOperation)],
    fs: &dyn PublicationFs,
) -> Result<RecoveryOutcome, ProducerError> {
    let final_dir = root.join(&operation.final_directory);
    fs.record(PublicationRecoveryEvent::FinalDirectoryFound);
    fs.record(PublicationRecoveryEvent::VerifyFinalDirectory);
    validate_artifact_set(&final_dir, evidence, policy)?;
    fs.record(PublicationRecoveryEvent::VerifyOperationIdentity);
    verify_operation_identity(&final_dir, evidence, operation, ledger)?;

    let mut last = stages
        .last()
        .map(|(_, staged)| staged.stage)
        .ok_or_else(|| {
            ProducerError::UncertainPublication(
                "no durable operation stage to reconcile".to_owned(),
            )
        })?;
    let receipt_path = ledger.join(format!("{}.receipt.json", evidence.release_id));
    let marker_path = ledger.join(format!("{}.available", evidence.release_id));
    let receipt_present = receipt_path.exists();
    if receipt_present {
        let Some((bytes, receipt)) = load_receipt(ledger, &evidence.release_id)? else {
            return Err(ProducerError::UncertainPublication(
                "durable receipt disappeared during recovery".to_owned(),
            ));
        };
        if !receipt_matches(&receipt, &bytes, evidence) {
            return Err(ProducerError::UncertainPublication(
                "durable receipt does not bind to the supplied evidence".to_owned(),
            ));
        }
    }
    let marker_present = marker_path.exists();
    if marker_present {
        if !receipt_present {
            return Err(ProducerError::UncertainPublication(
                "availability marker without a durable receipt".to_owned(),
            ));
        }
        let bytes = fs::read(&marker_path)
            .map_err(|error| io_error(&format!("read marker {}", marker_path.display()), error))?;
        if bytes != operation.operation_id.as_bytes() {
            return Err(ProducerError::UncertainPublication(
                "availability marker binds to a different operation".to_owned(),
            ));
        }
        if last == PublicationState::Available {
            fs.record(PublicationRecoveryEvent::Available);
            return Ok(RecoveryOutcome::AlreadyAvailable);
        }
    }

    if last.rank() < PublicationState::ParentDirFsynced.rank() {
        fs.sync_release_parent(root)?;
        advance_recovery_stage(
            ledger,
            evidence,
            operation,
            PublicationState::ParentDirFsynced,
            policy,
        )?;
        last = PublicationState::ParentDirFsynced;
    }
    fs.record(PublicationRecoveryEvent::VerifyDurabilityTransition);
    verify_durable_stage(ledger, evidence, PublicationState::ParentDirFsynced)?;

    if !receipt_present {
        fs.commit_receipt(
            &receipt_path,
            &receipt_file_bytes(&recovery_receipt(evidence), policy)?,
        )?;
    }
    fs.sync_receipt_ledger(ledger)?;
    if last.rank() < PublicationState::DurablePublicationReceipt.rank() {
        advance_recovery_stage(
            ledger,
            evidence,
            operation,
            PublicationState::DurablePublicationReceipt,
            policy,
        )?;
        last = PublicationState::DurablePublicationReceipt;
    }

    if !marker_present {
        fs.commit_availability_marker(&marker_path, operation.operation_id.as_bytes())?;
    }
    fs.sync_receipt_ledger(ledger)?;
    if last.rank() < PublicationState::Available.rank() {
        advance_recovery_stage(
            ledger,
            evidence,
            operation,
            PublicationState::Available,
            policy,
        )?;
    }
    fs.record(PublicationRecoveryEvent::Available);
    Ok(RecoveryOutcome::RecoveredPublished)
}

/// Reconcile an interrupted publication from durable operation evidence.
pub fn recover_interrupted(
    root: &Path,
    ledger: &Path,
    evidence: &PublicationEvidence,
    policy: &ResourcePolicy,
) -> Result<RecoveryOutcome, ProducerError> {
    let fs = RealPublicationFs;
    recover_interrupted_inner(root, ledger, evidence, policy, &fs)
}

fn recover_interrupted_inner(
    root: &Path,
    ledger: &Path,
    evidence: &PublicationEvidence,
    policy: &ResourcePolicy,
    fs: &dyn PublicationFs,
) -> Result<RecoveryOutcome, ProducerError> {
    let stages = read_stage_operations(ledger, &evidence.publication_operation_id)?;
    if stages.is_empty() {
        return Ok(RecoveryOutcome::NoEvidence);
    }
    validate_stage_history(&stages, evidence)?;
    let operation = stages
        .last()
        .map(|(_, staged)| staged.clone())
        .ok_or_else(|| {
            ProducerError::UncertainPublication(
                "no durable operation stage to reconcile".to_owned(),
            )
        })?;
    let staging = root.join(&operation.staging_directory);
    let final_dir = root.join(&operation.final_directory);
    if final_dir.exists() {
        return recover_final_directory(root, ledger, evidence, policy, &operation, &stages, fs);
    }
    if staging.exists() {
        if operation.stage.rank() < PublicationState::StagingDirFsynced.rank() {
            return Err(ProducerError::UncertainPublication(
                "incomplete staging evidence; publication is not acknowledged".to_owned(),
            ));
        }
        validate_artifact_set(&staging, evidence, policy)?;
        sync_directory(&staging)?;
        let receipt = recovery_receipt(evidence);
        finalize_publication(
            root,
            ledger,
            &operation,
            &staging,
            &final_dir,
            &receipt,
            policy,
            PublicationFaults::default(),
            fs,
        )?;
        return Ok(RecoveryOutcome::RecoveredStaged);
    }
    if ledger
        .join(format!("{}.receipt.json", evidence.release_id))
        .exists()
    {
        return Err(ProducerError::UncertainPublication(
            "durable receipt without staging or a final release directory".to_owned(),
        ));
    }
    Err(ProducerError::UncertainPublication(
        "neither staging nor final release evidence is present".to_owned(),
    ))
}

/// Validate, sign and publish one NDC v2 release as a single boundary.
pub fn build_release(request: &BuildRequest<'_>) -> Result<BuildOutcome, ProducerError> {
    let fs = RealPublicationFs;
    build_release_inner(request, PublicationFaults::default(), &fs)
}

fn build_release_inner(
    request: &BuildRequest<'_>,
    faults: PublicationFaults,
    fs: &dyn PublicationFs,
) -> Result<BuildOutcome, ProducerError> {
    let prepared = prepare_release(request)?;
    fs::create_dir_all(request.ledger_dir)
        .map_err(|error| io_error("create ledger directory", error))?;
    let operation = PublicationOperation {
        schema_version: MANIFEST_SCHEMA_VERSION,
        operation_id: request.operation_id.to_owned(),
        release_id: prepared.evidence.release_id.clone(),
        manifest_sha256: prepared.evidence.manifest_sha256.clone(),
        data_sha256: prepared.evidence.data_sha256.clone(),
        commit_position: request.commit_position.to_owned(),
        staging_directory: staging_name(request.operation_id),
        final_directory: prepared.evidence.release_id.clone(),
        stage: PublicationState::StagingCreated,
    };
    fs::create_dir_all(request.release_root)
        .map_err(|error| io_error("create release root", error))?;
    let staging = request.release_root.join(&operation.staging_directory);
    fs::create_dir(&staging).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            ProducerError::PublicationEvidence("staging directory already exists".to_owned())
        } else {
            io_error("create staging directory", error)
        }
    })?;
    write_stage(request.ledger_dir, &operation, 0, request.policy)?;

    write_new_file(&staging.join(MANIFEST_FILE_NAME), &prepared.manifest_bytes)?;
    write_new_file(&staging.join(SIDECAR_FILE_NAME), &prepared.sidecar_bytes)?;
    let artifact_root = staging.join(ARTIFACT_DIRECTORY);
    fs::create_dir(&artifact_root)
        .map_err(|error| io_error("create staging artifact directory", error))?;
    for (path, bytes) in &prepared.artifacts {
        validate_artifact_path(path, request.policy)?;
        write_new_file(&staging.join(path), bytes)?;
    }
    let mut written = operation.clone();
    written.stage = PublicationState::FilesWritten;
    write_stage(request.ledger_dir, &written, 1, request.policy)?;
    let mut synced_files = operation.clone();
    synced_files.stage = PublicationState::FilesSynced;
    write_stage(request.ledger_dir, &synced_files, 2, request.policy)?;
    sync_directory(&staging)?;
    let mut synced_staging = operation.clone();
    synced_staging.stage = PublicationState::StagingDirFsynced;
    write_stage(request.ledger_dir, &synced_staging, 3, request.policy)?;
    validate_artifact_set(&staging, &prepared.evidence, request.policy)?;
    let final_dir = request.release_root.join(&prepared.evidence.release_id);
    finalize_publication(
        request.release_root,
        request.ledger_dir,
        &operation,
        &staging,
        &final_dir,
        &prepared.receipt,
        request.policy,
        faults,
        fs,
    )?;
    Ok(BuildOutcome {
        manifest_bytes: prepared.manifest_bytes,
        sidecar_bytes: prepared.sidecar_bytes,
        descriptors: prepared.descriptors,
        receipt: prepared.receipt,
        evidence: prepared.evidence,
    })
}

#[cfg(test)]
impl CanonicalRecord {
    fn order_key_profile(&self) -> RecordOrderProfile {
        match &self.order_key {
            RecordOrderKey::Sequenced {
                sequence_domain,
                sequence_epoch,
                ..
            } => RecordOrderProfile::Sequenced {
                sequence_domain: sequence_domain.clone(),
                sequence_epoch: sequence_epoch.clone(),
            },
            RecordOrderKey::Reference { .. } => RecordOrderProfile::Reference,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::error::Error as StdError;
    use std::fs;

    use super::*;
    use crate::distribution::ndc_wire;
    use tempfile::TempDir;

    type TestResult = Result<(), Box<dyn StdError>>;

    const SPEC: &str = include_str!(
        "../../docs/specifications/ndc-conformance-producer-spec-example-2026-11-24.json"
    );

    fn test_policy() -> ResourcePolicy {
        ResourcePolicy {
            max_manifest_bytes: 1_000_000,
            max_artifact_count: 8,
            max_stored_bytes_per_artifact: 100_000,
            max_uncompressed_bytes_per_artifact: 100_000,
            max_total_stored_bytes: 1_000_000,
            max_total_uncompressed_bytes: 1_000_000,
            max_record_bytes: 1_000,
            max_records_per_artifact: 100,
            max_path_component_bytes: 128,
            max_nesting_depth: 32,
            max_object_members: 64,
            max_array_elements: 64,
            max_sidecar_bytes: 4_096,
        }
    }

    fn test_keys() -> (SigningKey, VerifyingKey) {
        let signing = SigningKey::from_bytes(&[0x31; 32]);
        let verifying = signing.verifying_key();
        (signing, verifying)
    }

    fn test_spec() -> ndc_wire::ConformanceSpec {
        ndc_wire::parse_conformance_spec(SPEC).expect("embedded conformance spec parses")
    }

    fn test_manifest(release_id: &str) -> ReleaseManifest {
        let mut manifest = test_spec().manifest;
        manifest.release_identity.release_id = release_id.to_owned();
        manifest.lineage.supersedes = None;
        manifest
    }

    fn test_evidence() -> ndc_wire::EvidenceSpec {
        test_spec().evidence
    }

    fn record(text: &str, policy: &ResourcePolicy) -> Result<CanonicalRecord, ProducerError> {
        let value = parse_jcs_value(text)?;
        let bytes = canonicalize_strict(&value, policy)?;
        Ok(CanonicalRecord {
            bytes,
            order_key: RecordOrderKey::Sequenced {
                sequence_domain: "domain-a".to_owned(),
                sequence_epoch: "epoch-1".to_owned(),
                sequence_number: 0,
            },
        })
    }

    fn sequenced(
        text: &str,
        number: u64,
        policy: &ResourcePolicy,
    ) -> Result<CanonicalRecord, ProducerError> {
        let mut item = record(text, policy)?;
        item.order_key = RecordOrderKey::Sequenced {
            sequence_domain: "domain-a".to_owned(),
            sequence_epoch: "epoch-1".to_owned(),
            sequence_number: number,
        };
        Ok(item)
    }

    fn referenced(
        text: &str,
        object_id: &str,
        revision: u64,
        knowledge_time_ns: &str,
        assertion_id: &str,
        policy: &ResourcePolicy,
    ) -> Result<CanonicalRecord, ProducerError> {
        let mut item = record(text, policy)?;
        item.order_key = RecordOrderKey::Reference {
            object_id: object_id.to_owned(),
            revision,
            knowledge_time_ns: knowledge_time_ns.to_owned(),
            assertion_id: assertion_id.to_owned(),
        };
        Ok(item)
    }

    fn sequenced_artifact(
        path: &str,
        partition: &str,
        ordinal: u32,
        records: Vec<CanonicalRecord>,
    ) -> ArtifactInput {
        ArtifactInput {
            logical_partition_id: partition.to_owned(),
            shard_ordinal: ordinal,
            path: path.to_owned(),
            record_order_profile: RecordOrderProfile::Sequenced {
                sequence_domain: "domain-a".to_owned(),
                sequence_epoch: "epoch-1".to_owned(),
            },
            encoding: ENCODING_NDJSON.to_owned(),
            compression: ArtifactCompression::None,
            records,
        }
    }

    fn injected(label: &str) -> ProducerError {
        io_error(label, io::Error::other(label))
    }

    /// Filesystem boundary used by crash tests. It delegates every durable
    /// operation to the host filesystem and records its ordered event log.
    struct RecordingPublicationFs {
        faults: PublicationFaults,
        ledger_syncs: Cell<u32>,
        events: RefCell<Vec<PublicationRecoveryEvent>>,
    }

    impl RecordingPublicationFs {
        fn new(faults: PublicationFaults) -> Self {
            Self {
                faults,
                ledger_syncs: Cell::new(0),
                events: RefCell::new(Vec::new()),
            }
        }

        fn events(&self) -> Vec<PublicationRecoveryEvent> {
            self.events.borrow().clone()
        }
    }

    impl PublicationFs for RecordingPublicationFs {
        fn record(&self, event: PublicationRecoveryEvent) {
            self.events.borrow_mut().push(event);
        }

        fn sync_release_parent(&self, root: &Path) -> Result<(), ProducerError> {
            self.record(PublicationRecoveryEvent::SyncReleaseParent);
            if self.faults.fail_parent_dir_sync {
                return Err(injected("injected failure during parent directory sync"));
            }
            sync_directory(root)?;
            if self.faults.fail_after_parent_sync {
                return Err(injected("injected failure after parent directory sync"));
            }
            Ok(())
        }

        fn commit_receipt(&self, path: &Path, bytes: &[u8]) -> Result<(), ProducerError> {
            self.record(PublicationRecoveryEvent::CommitReceipt);
            if self.faults.fail_receipt_commit {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|error| io_error("create partial receipt", error))?;
                file.flush()
                    .map_err(|error| io_error("flush partial receipt", error))?;
                return Err(injected("injected failure during receipt creation"));
            }
            write_new_file(path, bytes)
        }

        fn sync_receipt_ledger(&self, ledger: &Path) -> Result<(), ProducerError> {
            self.record(PublicationRecoveryEvent::SyncReceiptLedger);
            let ordinal = self.ledger_syncs.get().saturating_add(1);
            self.ledger_syncs.set(ordinal);
            if ordinal == 1 && self.faults.fail_receipt_ledger_sync {
                return Err(injected("injected failure during receipt ledger sync"));
            }
            if ordinal == 2 && self.faults.fail_marker_ledger_sync {
                return Err(injected("injected failure during marker ledger sync"));
            }
            sync_directory(ledger)
        }

        fn commit_availability_marker(
            &self,
            path: &Path,
            bytes: &[u8],
        ) -> Result<(), ProducerError> {
            self.record(PublicationRecoveryEvent::CommitAvailabilityMarker);
            if self.faults.fail_marker_commit {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|error| io_error("create partial marker", error))?;
                file.flush()
                    .map_err(|error| io_error("flush partial marker", error))?;
                return Err(injected("injected failure during marker creation"));
            }
            write_new_file(path, bytes)
        }
    }

    fn recover_with_fs(
        root: &Path,
        ledger: &Path,
        evidence: &PublicationEvidence,
        policy: &ResourcePolicy,
        fs: &RecordingPublicationFs,
    ) -> Result<RecoveryOutcome, ProducerError> {
        recover_interrupted_inner(root, ledger, evidence, policy, fs)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the fixture passes the full build boundary plus one injected fault setting"
    )]
    fn build_with_faults(
        manifest: &ReleaseManifest,
        artifacts: &[ArtifactInput],
        signing: &SigningKey,
        verifying: &VerifyingKey,
        policy: &ResourcePolicy,
        root: &Path,
        ledger: &Path,
        operation_id: &str,
        faults: PublicationFaults,
    ) -> Result<BuildOutcome, ProducerError> {
        let fs = RecordingPublicationFs::new(faults);
        build_with_faults_and_fs(
            manifest,
            artifacts,
            signing,
            verifying,
            policy,
            root,
            ledger,
            operation_id,
            faults,
            &fs,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the fixture passes the full build boundary, injected faults and a filesystem boundary"
    )]
    fn build_with_faults_and_fs(
        manifest: &ReleaseManifest,
        artifacts: &[ArtifactInput],
        signing: &SigningKey,
        verifying: &VerifyingKey,
        policy: &ResourcePolicy,
        root: &Path,
        ledger: &Path,
        operation_id: &str,
        faults: PublicationFaults,
        fs: &RecordingPublicationFs,
    ) -> Result<BuildOutcome, ProducerError> {
        let receipts: Vec<PublicationReceipt> = Vec::new();
        let lineage = LineageContext {
            predecessor: None,
            known_receipts: &receipts,
            now_ns: 10_000,
        };
        let signature = SignatureConfig {
            signing_key: signing,
            verifying_key: verifying,
            key_id: &manifest.publication_identity.signing_key_id,
        };
        let evidence = test_evidence();
        let observed_event_types = BTreeSet::new();
        let request = BuildRequest {
            release_root: root,
            ledger_dir: ledger,
            operation_id,
            commit_position: "position-1",
            manifest,
            evidence: &evidence,
            observed_event_types: &observed_event_types,
            artifacts,
            signature,
            policy,
            lineage,
        };
        build_release_inner(&request, faults, fs)
    }

    fn build_fixture(
        manifest: &ReleaseManifest,
        artifacts: &[ArtifactInput],
        signing: &SigningKey,
        verifying: &VerifyingKey,
        policy: &ResourcePolicy,
        root: &Path,
        ledger: &Path,
    ) -> Result<BuildOutcome, ProducerError> {
        build_with_faults(
            manifest,
            artifacts,
            signing,
            verifying,
            policy,
            root,
            ledger,
            "operation-1",
            PublicationFaults::default(),
        )
    }

    fn build_from_spec(
        spec: &ndc_wire::ConformanceSpec,
        policy: &ResourcePolicy,
        root: &Path,
        ledger: &Path,
    ) -> Result<BuildOutcome, ProducerError> {
        let (signing, verifying) = test_keys();
        let (artifacts, observed) = ndc_wire::spec_to_build_inputs(spec, policy)
            .map_err(|error| ProducerError::WireMapping(error.to_string()))?;
        let receipts: Vec<PublicationReceipt> = Vec::new();
        let lineage = LineageContext {
            predecessor: None,
            known_receipts: &receipts,
            now_ns: 10_000,
        };
        let signature = SignatureConfig {
            signing_key: &signing,
            verifying_key: &verifying,
            key_id: &spec.manifest.publication_identity.signing_key_id,
        };
        let request = BuildRequest {
            release_root: root,
            ledger_dir: ledger,
            operation_id: "operation-spec",
            commit_position: "position-spec",
            manifest: &spec.manifest,
            evidence: &spec.evidence,
            observed_event_types: &observed,
            artifacts: &artifacts,
            signature,
            policy,
            lineage,
        };
        build_release(&request)
    }

    fn empty_evidence(release_id: &str, operation_id: &str) -> PublicationEvidence {
        PublicationEvidence {
            release_id: release_id.to_owned(),
            manifest_sha256: "00".repeat(32),
            data_sha256: "11".repeat(32),
            publication_operation_id: operation_id.to_owned(),
            commit_position: "position-1".to_owned(),
            artifact_paths: Vec::new(),
            artifact_stored_sha256: Vec::new(),
            expected_receipt: PublicationReceipt {
                schema_version: MANIFEST_SCHEMA_VERSION,
                release_id: release_id.to_owned(),
                manifest_sha256: "00".repeat(32),
                data_sha256: "11".repeat(32),
                publication_operation_id: operation_id.to_owned(),
                commit_position: "position-1".to_owned(),
                result: PublicationState::Available,
                supersedes_release_id: None,
            },
            receipt_sha256: "22".repeat(32),
        }
    }

    fn operation_from_evidence(
        evidence: &PublicationEvidence,
        operation_id: &str,
    ) -> PublicationOperation {
        PublicationOperation {
            schema_version: MANIFEST_SCHEMA_VERSION,
            operation_id: operation_id.to_owned(),
            release_id: evidence.release_id.clone(),
            manifest_sha256: evidence.manifest_sha256.clone(),
            data_sha256: evidence.data_sha256.clone(),
            commit_position: evidence.commit_position.clone(),
            staging_directory: staging_name(operation_id),
            final_directory: evidence.release_id.clone(),
            stage: PublicationState::StagingCreated,
        }
    }

    fn write_stage_sequence(
        ledger: &Path,
        operation: &PublicationOperation,
        states: &[PublicationState],
        policy: &ResourcePolicy,
    ) -> Result<(), Box<dyn StdError>> {
        for (ordinal, state) in states.iter().enumerate() {
            let mut staged = operation.clone();
            staged.stage = *state;
            write_stage(ledger, &staged, u32::try_from(ordinal)?, policy)?;
        }
        Ok(())
    }

    fn clear_stages(ledger: &Path, operation_id: &str) -> Result<(), Box<dyn StdError>> {
        let prefix = format!("{operation_id}.stage.");
        for entry in fs::read_dir(ledger)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&prefix) {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    fn last_stage(
        ledger: &Path,
        operation_id: &str,
    ) -> Result<PublicationState, Box<dyn StdError>> {
        let stages = read_stage_operations(ledger, operation_id)?;
        let (_, operation) = stages
            .last()
            .ok_or_else(|| io::Error::other("no stage evidence"))?;
        Ok(operation.stage)
    }

    #[test]
    fn jcs_rfc8785_property_sorting_vector() -> TestResult {
        let policy = test_policy();
        let entries = [
            ("€", "Euro Sign"),
            ("\r", "Carriage Return"),
            ("\u{fb33}", "Hebrew Letter Dalet With Dagesh"),
            ("1", "One"),
            ("\u{1f600}", "Emoji: Grinning Face"),
            ("\u{0080}", "Control"),
            ("ö", "Latin Small Letter O With Diaeresis"),
        ];
        let value = JcsValue::Object(
            entries
                .iter()
                .map(|(key, text)| (key.to_string(), jcs_string(*text)))
                .collect(),
        );
        let bytes = canonicalize_strict(&value, &policy)?;
        let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{0080}\":\"Control\",\
            \"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\
            \"😀\":\"Emoji: Grinning Face\",\
            \"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
        assert_eq!(
            String::from_utf8(bytes)?,
            expected,
            "RFC 8785 section 3.2.3 ordering vector"
        );
        Ok(())
    }

    #[test]
    fn jcs_rfc8785_string_escaping_vector() -> TestResult {
        let policy = test_policy();
        let text: String = [
            '\u{20ac}', '$', '\u{000f}', '\n', 'A', '\'', 'B', '"', '\\', '\\', '"', '/',
        ]
        .iter()
        .collect();
        let bytes = canonicalize_strict(&JcsValue::String(text), &policy)?;
        let expected = r#""€$\u000f\nA'B\"\\\\\"/""#;
        assert_eq!(
            String::from_utf8(bytes)?,
            expected,
            "RFC 8785 section 3.2.2 string escaping vector"
        );
        Ok(())
    }

    #[test]
    fn jcs_rfc8785_number_samples() -> TestResult {
        let policy = test_policy();
        let samples = [
            (0.0_f64, "0"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (9_007_199_254_740_992.0, "9007199254740992"),
            (2_f64.powi(68), "295147905179352830000"),
            (1e23, "1e+23"),
            (1e21, "1e+21"),
            (1e-7, "1e-7"),
            (0.000001, "0.000001"),
            (333_333_333.333_333_3, "333333333.3333333"),
            (4.5, "4.5"),
            (2e-3, "0.002"),
            (1e-27, "1e-27"),
        ];
        for (number, expected) in samples {
            let bytes = canonicalize_value(&JcsValue::Float(number), &policy)?;
            assert_eq!(
                String::from_utf8(bytes)?,
                expected,
                "RFC 8785 double formatting sample"
            );
        }
        Ok(())
    }

    #[test]
    fn jcs_rejects_non_finite_numbers() -> TestResult {
        let policy = test_policy();
        let result = canonicalize_value(&JcsValue::Float(f64::NAN), &policy);
        assert!(
            matches!(result, Err(ProducerError::AmbiguousNumber(_))),
            "NaN fails closed"
        );
        let result = canonicalize_value(&JcsValue::Float(f64::INFINITY), &policy);
        assert!(
            matches!(result, Err(ProducerError::AmbiguousNumber(_))),
            "infinity fails closed"
        );
        Ok(())
    }

    #[test]
    fn jcs_rejects_floats_on_strict_manifest_path() -> TestResult {
        let policy = test_policy();
        let value = JcsValue::Object(vec![("amount".to_owned(), JcsValue::Float(1.25))]);
        let result = canonicalize_strict(&value, &policy);
        assert!(
            matches!(result, Err(ProducerError::AmbiguousNumber(_))),
            "floating-point manifest input rejected with a typed error"
        );
        Ok(())
    }

    #[test]
    fn jcs_rejects_duplicate_property_names() -> TestResult {
        let result = parse_jcs_value("{\"alpha\":1,\"alpha\":2}");
        assert!(
            matches!(result, Err(ProducerError::InvalidJson(_))),
            "duplicate property names fail closed"
        );
        Ok(())
    }

    #[test]
    fn jcs_nested_unicode_and_escaping_are_preserved() -> TestResult {
        let policy = test_policy();
        let inner = JcsValue::Object(vec![
            ("z-last".to_owned(), jcs_string("tab\tand quote\"")),
            ("a-first".to_owned(), jcs_string("snowman \u{2603}")),
        ]);
        let value = JcsValue::Object(vec![
            (
                "outer".to_owned(),
                JcsValue::Array(vec![inner, JcsValue::Bool(false)]),
            ),
            ("nul".to_owned(), jcs_string("control \u{0000}")),
        ]);
        let bytes = canonicalize_strict(&value, &policy)?;
        let text = String::from_utf8(bytes)?;
        assert!(
            text.starts_with("{\"nul\":\"control \\u0000\",\"outer\":["),
            "UTF-16 key order and control escaping"
        );
        assert!(
            text.contains("\"a-first\":\"snowman \u{2603}\",\"z-last\":\"tab\\tand quote\\\"\""),
            "nested canonical key order and escaping"
        );
        Ok(())
    }

    #[test]
    fn jcs_policy_bounds_are_enforced() -> TestResult {
        let mut policy = test_policy();
        policy.max_nesting_depth = 1;
        let value = JcsValue::Object(vec![(
            "outer".to_owned(),
            JcsValue::Object(vec![("inner".to_owned(), JcsValue::Bool(true))]),
        )]);
        let result = canonicalize_strict(&value, &policy);
        assert!(
            matches!(result, Err(ProducerError::PolicyExceeded(_))),
            "caller-supplied nesting bound enforced"
        );
        Ok(())
    }

    #[test]
    fn manifest_bytes_are_deterministic_and_self_digest_free() -> TestResult {
        let policy = test_policy();
        let (signing, verifying) = test_keys();
        let manifest = test_manifest("release-det");
        let record = sequenced(r#"{"kind":"abstract"}"#, 1, &policy)?;
        let artifacts = vec![sequenced_artifact(
            "artifacts/a.jsonl",
            "partition-a",
            0,
            vec![record],
        )];
        let temp = TempDir::new()?;
        let first = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &temp.path().join("root-one"),
            &temp.path().join("ledger-one"),
        )?;
        let second = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &temp.path().join("root-two"),
            &temp.path().join("ledger-two"),
        )?;
        assert_eq!(
            first.manifest_bytes, second.manifest_bytes,
            "identical typed input yields identical canonical manifest bytes"
        );
        let text = String::from_utf8(first.manifest_bytes)?;
        assert!(
            !text.contains("manifest_sha256"),
            "no self-digest in manifest"
        );
        assert!(!text.contains("\"limits\""), "no limits member in manifest");
        assert!(
            !text.contains("artifact_digests"),
            "no redundant artifact array"
        );
        Ok(())
    }

    #[test]
    fn manifest_digest_tampering_is_detected() -> TestResult {
        let policy = test_policy();
        let (signing, verifying) = test_keys();
        let manifest = test_manifest("release-tamper");
        let record = sequenced(r#"{"kind":"abstract"}"#, 1, &policy)?;
        let artifacts = vec![sequenced_artifact(
            "artifacts/a.jsonl",
            "partition-a",
            0,
            vec![record],
        )];
        let temp = TempDir::new()?;
        let outcome = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &temp.path().join("root"),
            &temp.path().join("ledger"),
        )?;
        let mut tampered = outcome.manifest_bytes.clone();
        if let Some(byte) = tampered.last_mut() {
            *byte = b' ';
        }
        assert_ne!(
            sha256(&outcome.manifest_bytes),
            sha256(&tampered),
            "a changed canonical byte changes the digest"
        );
        Ok(())
    }

    #[test]
    fn manifest_with_limits_member_fails_strict_parsing() -> TestResult {
        let mut value = serde_json::to_value(test_manifest("release-strict"))?;
        value
            .as_object_mut()
            .ok_or("manifest object")?
            .insert("limits".to_owned(), serde_json::json!({}));
        let text = serde_json::to_string(&value)?;
        let result = serde_json::from_str::<ReleaseManifest>(&text);
        assert!(result.is_err(), "unknown limits member fails closed");
        Ok(())
    }

    #[test]
    fn descriptor_has_the_exact_field_set() -> TestResult {
        let policy = test_policy();
        let descriptor = ArtifactDescriptor {
            logical_partition_id: "part".to_owned(),
            shard_ordinal: 0,
            path: "artifacts/a.jsonl".to_owned(),
            record_order_profile: RecordOrderProfile::Reference,
            encoding: ENCODING_NDJSON.to_owned(),
            compression: COMPRESSION_NONE.to_owned(),
            compression_version: COMPRESSION_VERSION_NONE.to_owned(),
            stored_bytes: 1,
            stored_sha256: "00".repeat(32),
            uncompressed_bytes: 1,
            uncompressed_sha256: "00".repeat(32),
            record_count: 1,
        };
        let bytes = canonicalize_strict(&descriptor.to_jcs()?, &policy)?;
        let text = String::from_utf8(bytes)?;
        for field in [
            "logical_partition_id",
            "shard_ordinal",
            "path",
            "record_order_profile",
            "encoding",
            "compression",
            "compression_version",
            "stored_bytes",
            "stored_sha256",
            "uncompressed_bytes",
            "uncompressed_sha256",
            "record_count",
        ] {
            assert!(
                text.contains(&format!("\"{field}\"")),
                "descriptor field {field}"
            );
        }
        Ok(())
    }

    #[test]
    fn injected_key_signature_verifies() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-sign");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let outcome = build_fixture(
            &manifest, &artifacts, &signing, &verifying, &policy, &root, &ledger,
        )?;
        let sidecar: SignatureSidecar = serde_json::from_slice(&outcome.sidecar_bytes)?;
        let signature_bytes = BASE64.decode(sidecar.signature_b64.as_bytes())?;
        let signature = ed25519_dalek::Signature::from_slice(&signature_bytes)?;
        let mut message = Vec::new();
        message.extend_from_slice(SIGNING_DOMAIN);
        let digest = sha256(&outcome.manifest_bytes);
        message.extend_from_slice(&digest);
        verifying.verify(&message, &signature)?;
        assert_eq!(
            sidecar.manifest_sha256,
            hex_encode(&digest),
            "sidecar digest binds to the manifest bytes"
        );
        Ok(())
    }

    #[test]
    fn wrong_verifying_key_is_rejected() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-wrong-key");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, _) = test_keys();
        let other = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        let result = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &other,
            &policy,
            &temp.path().join("releases"),
            &temp.path().join("ledger"),
        );
        assert!(
            matches!(result, Err(ProducerError::InvalidSignatureConfig(_))),
            "mismatched injected verifying key fails the self-check"
        );
        Ok(())
    }

    #[test]
    fn sidecar_has_exactly_five_fields() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-sidecar");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let outcome = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &temp.path().join("releases"),
            &temp.path().join("ledger"),
        )?;
        let value = parse_jcs_value(String::from_utf8(outcome.sidecar_bytes.clone())?.trim())?;
        let JcsValue::Object(entries) = value else {
            return Err("sidecar is an object".into());
        };
        let mut names: Vec<String> = entries.into_iter().map(|(key, _)| key).collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "algorithm".to_owned(),
                "key_id".to_owned(),
                "manifest_sha256".to_owned(),
                "schema_version".to_owned(),
                "signature_b64".to_owned(),
            ],
            "sidecar field set is exact"
        );
        assert!(
            outcome.sidecar_bytes.ends_with(b"\n"),
            "sidecar has one trailing LF"
        );
        Ok(())
    }

    #[test]
    fn duplicate_artifact_path_is_rejected() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-duplicate-path");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![
            sequenced_artifact("artifacts/a.jsonl", "part-a", 0, records.clone()),
            sequenced_artifact("artifacts/a.jsonl", "part-b", 0, records),
        ];
        let (signing, verifying) = test_keys();
        let result = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &temp.path().join("releases"),
            &temp.path().join("ledger"),
        );
        assert!(
            matches!(result, Err(ProducerError::DuplicateArtifactPath(_))),
            "duplicate normalized path fails closed"
        );
        Ok(())
    }

    #[test]
    fn traversal_path_is_rejected() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-traversal");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact(
            "artifacts/../escape.jsonl",
            "part",
            0,
            records,
        )];
        let (signing, verifying) = test_keys();
        let result = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &temp.path().join("releases"),
            &temp.path().join("ledger"),
        );
        assert!(
            matches!(result, Err(ProducerError::InvalidArtifactPath(_, _))),
            "traversal path fails closed"
        );
        Ok(())
    }

    #[test]
    fn non_ascii_path_is_rejected() -> TestResult {
        let policy = test_policy();
        let result = validate_artifact_path("artifacts/ünïcode.jsonl", &policy);
        assert!(
            matches!(result, Err(ProducerError::InvalidArtifactPath(_, _))),
            "non-ASCII component fails closed without normalization"
        );
        Ok(())
    }

    #[test]
    fn overlength_record_is_rejected() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-overlength");
        let long_value = "x".repeat(2_000);
        let text = format!("{{\"alpha\":\"{long_value}\"}}");
        let records = vec![sequenced(&text, 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let result = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &temp.path().join("releases"),
            &temp.path().join("ledger"),
        );
        assert!(
            matches!(result, Err(ProducerError::PolicyExceeded(_))),
            "record length bound enforced"
        );
        Ok(())
    }

    #[test]
    fn non_canonical_record_is_rejected() -> TestResult {
        let policy = test_policy();
        let result = validate_record(b"{\"beta\":1,\"alpha\":2}", 0, &policy);
        assert!(
            matches!(result, Err(ProducerError::InvalidRecord(_, _))),
            "unsorted record keys fail closed"
        );
        let result = validate_record(b"{\"alpha\":1}\n", 0, &policy);
        assert!(
            matches!(result, Err(ProducerError::InvalidRecord(_, _))),
            "embedded line boundary fails closed"
        );
        Ok(())
    }

    #[test]
    fn missing_artifact_is_detected() -> TestResult {
        let mut evidence = empty_evidence("release-missing", "operation-1");
        evidence.artifact_paths = vec!["artifacts/a.jsonl".to_owned()];
        evidence.artifact_stored_sha256 = vec!["22".repeat(32)];
        let temp = TempDir::new()?;
        let result = validate_artifact_set(temp.path(), &evidence, &test_policy());
        assert!(
            matches!(result, Err(ProducerError::ArtifactSetMismatch(_))),
            "missing declared artifact fails closed"
        );
        Ok(())
    }

    #[test]
    fn sequenced_ordering_is_deterministic() -> TestResult {
        let policy = test_policy();
        let first = sequenced("{\"alpha\":\"aa\"}", 4, &policy)?;
        let second = sequenced("{\"alpha\":\"bb\"}", 9, &policy)?;
        let profile = first.order_key_profile();
        validate_record_order(
            "artifacts/a.jsonl",
            &profile,
            &[first.clone(), second.clone()],
            &policy,
        )?;
        let result =
            validate_record_order("artifacts/a.jsonl", &profile, &[second, first], &policy);
        assert!(
            matches!(result, Err(ProducerError::InvalidRecordOrder(_, _))),
            "backwards sequence position fails closed"
        );
        Ok(())
    }

    #[test]
    fn reference_ordering_is_deterministic() -> TestResult {
        let policy = test_policy();
        let first = referenced("{\"alpha\":\"aa\"}", "obj-1", 1, "100", "assert-1", &policy)?;
        let second = referenced("{\"alpha\":\"bb\"}", "obj-1", 2, "100", "assert-2", &policy)?;
        let records = vec![second.clone(), first.clone()];
        let result = validate_record_order(
            "artifacts/r.jsonl",
            &RecordOrderProfile::Reference,
            &records,
            &policy,
        );
        assert!(
            matches!(result, Err(ProducerError::InvalidRecordOrder(_, _))),
            "backwards reference position fails closed"
        );
        let ordered = vec![first, second];
        validate_record_order(
            "artifacts/r.jsonl",
            &RecordOrderProfile::Reference,
            &ordered,
            &policy,
        )?;
        Ok(())
    }

    #[test]
    fn duplicate_sequence_position_is_rejected() -> TestResult {
        let policy = test_policy();
        let first = sequenced("{\"alpha\":\"aa\"}", 7, &policy)?;
        let duplicate = sequenced("{\"alpha\":\"bb\"}", 7, &policy)?;
        let result = validate_record_order(
            "artifacts/a.jsonl",
            &first.order_key_profile(),
            &[first, duplicate],
            &policy,
        );
        assert!(
            matches!(result, Err(ProducerError::InvalidRecordOrder(_, _))),
            "duplicate sequence position fails closed"
        );
        Ok(())
    }

    #[test]
    fn sequence_gaps_remain_visible() -> TestResult {
        let policy = test_policy();
        let gap = vec![
            sequenced("{\"alpha\":\"aa\"}", 1, &policy)?,
            sequenced("{\"alpha\":\"bb\"}", 3, &policy)?,
        ];
        validate_record_order(
            "artifacts/a.jsonl",
            &RecordOrderProfile::Sequenced {
                sequence_domain: "domain-a".to_owned(),
                sequence_epoch: "epoch-1".to_owned(),
            },
            &gap,
            &policy,
        )?;
        assert_eq!(
            gap[1].bytes.as_slice(),
            b"{\"alpha\":\"bb\"}".as_slice(),
            "no fabricated record"
        );
        Ok(())
    }

    #[test]
    fn dataset_digest_is_reproducible() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-dataset");
        let records = vec![
            sequenced("{\"alpha\":\"aa\"}", 1, &policy)?,
            sequenced("{\"alpha\":\"bb\"}", 2, &policy)?,
        ];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let first = build_fixture(
            &manifest, &artifacts, &signing, &verifying, &policy, &root, &ledger,
        )?;
        let expected = first.evidence.data_sha256.clone();
        let concatenator = {
            let mut bytes = Vec::new();
            for record in &artifacts[0].records {
                bytes.extend_from_slice(&record.bytes);
                bytes.push(b'\n');
            }
            hex_encode(&sha256(&bytes))
        };
        assert_eq!(
            expected, concatenator,
            "dataset digest covers ordered LF streams"
        );
        Ok(())
    }

    #[test]
    fn compression_does_not_change_dataset_digest() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-compression");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let mut plain = sequenced_artifact("artifacts/a.jsonl", "part", 0, records.clone());
        let mut gzipped = plain.clone();
        gzipped.path = "artifacts/a.jsonl.gz".to_owned();
        gzipped.compression = ArtifactCompression::Gzip;
        let (signing, verifying) = test_keys();
        let first = build_fixture(
            &manifest,
            std::slice::from_ref(&plain),
            &signing,
            &verifying,
            &policy,
            &temp.path().join("releases-a"),
            &temp.path().join("ledger-a"),
        )?;
        let second = build_fixture(
            &manifest,
            std::slice::from_ref(&gzipped),
            &signing,
            &verifying,
            &policy,
            &temp.path().join("releases-b"),
            &temp.path().join("ledger-b"),
        )?;
        plain.compression = ArtifactCompression::Gzip;
        assert_eq!(
            first.evidence.data_sha256, second.evidence.data_sha256,
            "dataset digest is independent of compression"
        );
        assert_ne!(
            first.descriptors[0].stored_sha256, second.descriptors[0].stored_sha256,
            "stored digest reflects compression"
        );
        Ok(())
    }

    #[test]
    fn gzip_stored_bytes_are_deterministic() -> TestResult {
        let stream = b"{\"alpha\":\"aa\"}\n{\"alpha\":\"bb\"}\n";
        let first = compress_stream(stream, ArtifactCompression::Gzip)?;
        let second = compress_stream(stream, ArtifactCompression::Gzip)?;
        assert_eq!(
            first, second,
            "gzip framing carries no changing header field"
        );
        assert_ne!(
            first,
            compress_stream(stream, ArtifactCompression::None)?,
            "gzip framing differs from the stored canonical stream"
        );
        Ok(())
    }

    #[test]
    fn publication_collision_is_rejected() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-collision");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        fs::create_dir_all(&root)?;
        fs::create_dir(root.join("release-collision"))?;
        let result = build_fixture(
            &manifest, &artifacts, &signing, &verifying, &policy, &root, &ledger,
        );
        assert!(
            matches!(result, Err(ProducerError::PublicationCollision(_))),
            "existing release id fails closed"
        );
        Ok(())
    }

    fn evidence_for_operation(
        manifest: &ReleaseManifest,
        artifacts: &[ArtifactInput],
        signing: &SigningKey,
        verifying: &VerifyingKey,
        policy: &ResourcePolicy,
        operation_id: &str,
    ) -> Result<PublicationEvidence, Box<dyn StdError>> {
        let temp = TempDir::new()?;
        let outcome = build_with_faults(
            manifest,
            artifacts,
            signing,
            verifying,
            policy,
            &temp.path().join("releases"),
            &temp.path().join("ledger"),
            operation_id,
            PublicationFaults::default(),
        )?;
        Ok(outcome.evidence)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn no_replace_rename_moves_one_directory_without_replacing() -> TestResult {
        let temp = TempDir::new()?;
        let source = temp.path().join("source");
        let target = temp.path().join("target");
        fs::create_dir(&source)?;
        fs::write(source.join("abstract"), b"payload")?;
        atomic_no_replace_rename(&source, &target)?;
        assert!(!source.exists(), "the rename consumes the source name");
        assert_eq!(
            fs::read(target.join("abstract"))?,
            b"payload",
            "the byte stream follows the renamed directory"
        );

        let second = temp.path().join("second");
        fs::create_dir(&second)?;
        let result = atomic_no_replace_rename(&second, &target);
        assert!(
            matches!(result, Err(error) if error.kind() == io::ErrorKind::AlreadyExists),
            "the platform primitive rejects an existing target"
        );
        assert!(second.exists(), "the rejected source directory is retained");
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn no_replace_rename_fails_closed_on_other_platforms() -> TestResult {
        let result = atomic_no_replace_rename(Path::new("from"), Path::new("to"));
        assert!(
            matches!(result, Err(error) if error.kind() == io::ErrorKind::Unsupported),
            "unsupported targets report a typed error"
        );
        Ok(())
    }

    #[test]
    fn publication_topology_rejects_non_siblings() -> TestResult {
        let temp = TempDir::new()?;
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        fs::create_dir(&first)?;
        fs::create_dir(&second)?;
        let staging = first.join("staging");
        fs::create_dir(&staging)?;
        let result = ensure_sibling_release_paths(&staging, &second.join("release"));
        assert!(
            matches!(result, Err(ProducerError::PublicationTopology(_))),
            "staging and final paths under different parents fail closed"
        );
        assert!(
            ensure_sibling_release_paths(&staging, &first.join("release")).is_ok(),
            "sibling paths on one filesystem are accepted"
        );
        Ok(())
    }

    #[test]
    fn publication_stage_order_follows_the_committed_rename() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-stage-order");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        build_fixture(
            &manifest, &artifacts, &signing, &verifying, &policy, &root, &ledger,
        )?;
        let stages = read_stage_operations(&ledger, "operation-1")?;
        let observed: Vec<PublicationState> = stages.iter().map(|(_, item)| item.stage).collect();
        assert_eq!(
            observed,
            vec![
                PublicationState::StagingCreated,
                PublicationState::FilesWritten,
                PublicationState::FilesSynced,
                PublicationState::StagingDirFsynced,
                PublicationState::AtomicNoReplaceRename,
                PublicationState::ParentDirFsynced,
                PublicationState::DurablePublicationReceipt,
                PublicationState::Available,
            ],
            "stage evidence follows the committed transition order"
        );
        assert!(
            !root.join(".staging-operation-1").exists(),
            "the staging name is consumed by the final directory rename"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let link_count =
                fs::metadata(root.join("release-stage-order").join(MANIFEST_FILE_NAME))?.nlink();
            assert_eq!(
                link_count, 1,
                "publication uses a directory rename rather than file hard links"
            );
        }
        Ok(())
    }

    #[test]
    fn final_directory_is_absent_before_the_rename() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-before-rename");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_before_rename: true,
            ..PublicationFaults::default()
        };
        let result = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-before-rename",
            faults,
        );
        assert!(
            matches!(result, Err(ProducerError::Io(..))),
            "the injected pre-rename failure is typed"
        );
        assert!(
            !root.join("release-before-rename").exists(),
            "the final release stays invisible before the rename"
        );
        assert!(
            root.join(".staging-operation-before-rename").exists(),
            "the complete staging directory is retained"
        );
        assert_eq!(
            last_stage(&ledger, "operation-before-rename")?,
            PublicationState::StagingDirFsynced,
            "no rename stage is claimed before the rename"
        );
        let evidence = evidence_for_operation(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            "operation-before-rename",
        )?;
        validate_artifact_set(
            &root.join(".staging-operation-before-rename"),
            &evidence,
            &policy,
        )?;
        assert!(
            !ledger.join("release-before-rename.receipt.json").exists(),
            "no acknowledgement exists before the rename"
        );
        let recovered = recover_interrupted(&root, &ledger, &evidence, &policy)?;
        assert_eq!(
            recovered,
            RecoveryOutcome::RecoveredStaged,
            "complete unpublished staging is reconciled by a later recovery"
        );
        Ok(())
    }

    #[test]
    fn rename_collision_does_not_expose_a_partial_release() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-rename-collision");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        fs::create_dir_all(&root)?;
        let occupied = root.join("release-rename-collision");
        fs::create_dir(&occupied)?;
        fs::write(occupied.join("holder"), b"unchanged")?;
        let result = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-rename-collision",
            PublicationFaults::default(),
        );
        assert!(
            matches!(result, Err(ProducerError::PublicationCollision(_))),
            "an occupied release identity is rejected by the rename"
        );
        assert_eq!(
            fs::read(occupied.join("holder"))?,
            b"unchanged",
            "the existing release identity keeps its content"
        );
        assert_eq!(
            fs::read_dir(&occupied)?.count(),
            1,
            "no staged file is linked into the occupied directory"
        );
        assert_ne!(
            last_stage(&ledger, "operation-rename-collision")?,
            PublicationState::AtomicNoReplaceRename,
            "a failed rename is not labelled as committed"
        );
        assert!(
            !ledger
                .join("release-rename-collision.receipt.json")
                .exists(),
            "a failed rename writes no receipt"
        );
        Ok(())
    }

    #[test]
    fn concurrent_publications_have_exactly_one_winner() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-concurrent");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let shared = (
            &manifest, &artifacts, &signing, &verifying, &policy, &root, &ledger,
        );
        let results = std::thread::scope(
            |scope| -> Result<Vec<Result<BuildOutcome, ProducerError>>, Box<dyn StdError>> {
                let mut handles = Vec::new();
                for index in 0..4 {
                    let operation_id = format!("operation-concurrent-{index}");
                    handles.push(scope.spawn(move || {
                        build_with_faults(
                            shared.0,
                            shared.1,
                            shared.2,
                            shared.3,
                            shared.4,
                            shared.5,
                            shared.6,
                            &operation_id,
                            PublicationFaults::default(),
                        )
                    }));
                }
                let mut results = Vec::new();
                for handle in handles {
                    results.push(
                        handle
                            .join()
                            .map_err(|_| io::Error::other("publication thread panicked"))?,
                    );
                }
                Ok(results)
            },
        )?;
        let winners: Vec<&BuildOutcome> = results
            .iter()
            .filter_map(|result| result.as_ref().ok())
            .collect();
        assert_eq!(winners.len(), 1, "exactly one no-replace rename wins");
        for result in &results {
            if let Err(error) = result {
                assert!(
                    matches!(error, ProducerError::PublicationCollision(_)),
                    "every losing attempt reports a collision"
                );
            }
        }
        validate_artifact_set(
            &root.join("release-concurrent"),
            &winners[0].evidence,
            &policy,
        )?;
        let receipts = fs::read_dir(&ledger)?
            .filter(|entry| {
                entry.as_ref().is_ok_and(|item| {
                    item.file_name()
                        .to_string_lossy()
                        .ends_with(".receipt.json")
                })
            })
            .count();
        assert_eq!(receipts, 1, "one durable receipt is committed");
        Ok(())
    }

    #[test]
    fn parent_sync_failure_leaves_an_uncertain_publication() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-parent-fault");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_parent_dir_sync: true,
            ..PublicationFaults::default()
        };
        let result = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-parent-fault",
            faults,
        );
        assert!(
            matches!(result, Err(ProducerError::Io(..))),
            "the injected parent sync failure is typed"
        );
        let mut evidence = evidence_for_operation(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            "operation-parent-fault",
        )?;
        evidence.publication_operation_id = "operation-parent-fault".to_owned();
        let final_dir = root.join("release-parent-fault");
        validate_artifact_set(&final_dir, &evidence, &policy)?;
        assert_eq!(
            last_stage(&ledger, "operation-parent-fault")?,
            PublicationState::AtomicNoReplaceRename,
            "the rename is recorded before the parent directory sync"
        );
        assert!(
            !ledger.join("release-parent-fault.receipt.json").exists(),
            "an uncertain publication carries no committed acknowledgement"
        );
        assert!(
            !ledger.join("release-parent-fault.available").exists(),
            "an uncertain publication carries no availability marker"
        );
        let recovered = recover_interrupted(&root, &ledger, &evidence, &policy)?;
        assert_eq!(
            recovered,
            RecoveryOutcome::RecoveredPublished,
            "reconciliation commits the receipt for the verified final directory"
        );
        let (_, receipt) = load_receipt(&ledger, "release-parent-fault")?
            .ok_or_else(|| io::Error::other("missing reconciled receipt"))?;
        assert_eq!(
            receipt.result,
            PublicationState::Available,
            "recovery commits an acknowledgement that the failed run did not write"
        );
        assert!(
            ledger.join("release-parent-fault.available").exists(),
            "recovery writes the availability marker after the receipt"
        );
        Ok(())
    }

    #[test]
    fn receipt_commit_failure_does_not_mark_available() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-receipt-fault");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_receipt_commit: true,
            ..PublicationFaults::default()
        };
        let result = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-receipt-fault",
            faults,
        );
        assert!(
            matches!(result, Err(ProducerError::Io(..))),
            "the injected receipt failure is typed"
        );
        assert_eq!(
            last_stage(&ledger, "operation-receipt-fault")?,
            PublicationState::ParentDirFsynced,
            "the publication exists with the parent directory synced"
        );
        let receipt_bytes = fs::read(ledger.join("release-receipt-fault.receipt.json"))?;
        assert!(receipt_bytes.is_empty(), "receipt is empty after crash");
        assert!(
            !ledger.join("release-receipt-fault.available").exists(),
            "no availability marker is committed on the receipt failure path"
        );
        let mut evidence = evidence_for_operation(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            "operation-receipt-fault",
        )?;
        evidence.publication_operation_id = "operation-receipt-fault".to_owned();
        let recovered = recover_interrupted(&root, &ledger, &evidence, &policy);
        let is_uncertain = matches!(recovered, Err(ProducerError::UncertainPublication(_)));
        assert!(is_uncertain, "a partial receipt is not acknowledged");
        Ok(())
    }

    #[test]
    fn marker_commit_failure_keeps_the_receipt_without_an_acknowledgement() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-marker-fault");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_marker_commit: true,
            ..PublicationFaults::default()
        };
        let result = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-marker-fault",
            faults,
        );
        assert!(
            matches!(result, Err(ProducerError::Io(..))),
            "the injected marker failure is typed"
        );
        assert_eq!(
            last_stage(&ledger, "operation-marker-fault")?,
            PublicationState::DurablePublicationReceipt,
            "the receipt is committed before the availability marker"
        );
        assert!(
            load_receipt(&ledger, "release-marker-fault")?.is_some(),
            "the receipt survives the marker failure"
        );
        let marker_bytes = fs::read(ledger.join("release-marker-fault.available"))?;
        assert!(marker_bytes.is_empty(), "marker is empty after crash");
        let mut evidence = evidence_for_operation(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            "operation-marker-fault",
        )?;
        evidence.publication_operation_id = "operation-marker-fault".to_owned();
        let recovered = recover_interrupted(&root, &ledger, &evidence, &policy);
        assert!(
            matches!(recovered, Err(ProducerError::UncertainPublication(_))),
            "an empty marker is never accepted as an acknowledgement"
        );
        Ok(())
    }

    #[test]
    fn incomplete_staging_is_not_promoted_by_recovery() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-incomplete");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_before_rename: true,
            ..PublicationFaults::default()
        };
        let interrupted = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-incomplete",
            faults,
        );
        assert!(
            matches!(interrupted, Err(ProducerError::Io(..))),
            "the injected pre-rename failure is typed"
        );
        let evidence = evidence_for_operation(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            "operation-incomplete",
        )?;
        fs::remove_file(
            root.join(".staging-operation-incomplete")
                .join("artifacts")
                .join("a.jsonl"),
        )?;
        clear_stages(&ledger, "operation-incomplete")?;
        write_stage_sequence(
            &ledger,
            &operation_from_evidence(&evidence, "operation-incomplete"),
            &[
                PublicationState::StagingCreated,
                PublicationState::FilesWritten,
            ],
            &policy,
        )?;
        let result = recover_interrupted(&root, &ledger, &evidence, &policy);
        assert!(
            matches!(result, Err(ProducerError::UncertainPublication(_))),
            "an interrupted write is not acknowledged by recovery"
        );
        assert!(
            !root.join("release-incomplete").exists(),
            "no partial final release is promoted"
        );
        assert!(
            !ledger.join("release-incomplete.receipt.json").exists(),
            "recovery writes no receipt for incomplete staging"
        );
        Ok(())
    }

    #[test]
    fn receipt_is_bound_to_release_and_digests() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-receipt");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let ledger = temp.path().join("ledger");
        let outcome = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &temp.path().join("releases"),
            &ledger,
        )?;
        let bytes = fs::read(ledger.join("release-receipt.receipt.json"))?;
        let receipt: PublicationReceipt = serde_json::from_slice(&bytes)?;
        assert_eq!(
            receipt, outcome.receipt,
            "on-disk receipt matches the outcome"
        );
        assert_eq!(
            receipt.manifest_sha256, outcome.evidence.manifest_sha256,
            "receipt binds to the manifest digest"
        );
        assert_eq!(
            receipt.publication_operation_id, "operation-1",
            "receipt binds to the operation id"
        );
        assert_eq!(
            receipt.commit_position, "position-1",
            "receipt binds to the commit position"
        );
        Ok(())
    }

    #[test]
    fn recovery_without_evidence_is_empty() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let ledger = temp.path().join("ledger");
        fs::create_dir_all(&ledger)?;
        let evidence = empty_evidence("release-none", "operation-none");
        let outcome = recover_interrupted(temp.path(), &ledger, &evidence, &policy)?;
        assert_eq!(
            outcome,
            RecoveryOutcome::NoEvidence,
            "absent operation evidence is reported"
        );
        Ok(())
    }

    #[test]
    fn recovery_after_completed_publication_is_already_available() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-recovered");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let outcome = build_fixture(
            &manifest, &artifacts, &signing, &verifying, &policy, &root, &ledger,
        )?;
        let recovered = recover_interrupted(&root, &ledger, &outcome.evidence, &policy)?;
        assert_eq!(
            recovered,
            RecoveryOutcome::AlreadyAvailable,
            "completed receipt and marker reconcile without rewriting"
        );
        Ok(())
    }

    #[test]
    fn recovery_from_final_directory_writes_receipt() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-final-recovery");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let outcome = build_fixture(
            &manifest, &artifacts, &signing, &verifying, &policy, &root, &ledger,
        )?;
        fs::remove_file(ledger.join("release-final-recovery.receipt.json"))?;
        fs::remove_file(ledger.join("release-final-recovery.available"))?;
        let recovered = recover_interrupted(&root, &ledger, &outcome.evidence, &policy)?;
        assert_eq!(
            recovered,
            RecoveryOutcome::RecoveredPublished,
            "verified final directory yields a durable receipt"
        );
        assert!(
            ledger.join("release-final-recovery.receipt.json").exists(),
            "receipt was written during recovery"
        );
        Ok(())
    }

    #[test]
    fn recovery_from_staging_completes_publication() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-stage-recovery");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_before_rename: true,
            ..PublicationFaults::default()
        };
        let interrupted = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-stage-recovery",
            faults,
        );
        assert!(
            matches!(interrupted, Err(ProducerError::Io(..))),
            "the injected pre-rename failure is typed"
        );
        assert!(
            !root.join("release-stage-recovery").exists(),
            "staging is unpublished before recovery"
        );
        let evidence = evidence_for_operation(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            "operation-stage-recovery",
        )?;
        let recovered = recover_interrupted(&root, &ledger, &evidence, &policy)?;
        assert_eq!(
            recovered,
            RecoveryOutcome::RecoveredStaged,
            "verified staging completes the publication"
        );
        assert!(
            root.join("release-stage-recovery").exists(),
            "final directory exists after staged recovery"
        );
        validate_artifact_set(&root.join("release-stage-recovery"), &evidence, &policy)?;
        Ok(())
    }

    #[test]
    fn receipt_binding_mismatch_fails_closed() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-binding");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let mut outcome = build_fixture(
            &manifest, &artifacts, &signing, &verifying, &policy, &root, &ledger,
        )?;
        outcome.evidence.manifest_sha256 = "ff".repeat(32);
        let result = recover_interrupted(&root, &ledger, &outcome.evidence, &policy);
        assert!(
            matches!(result, Err(ProducerError::UncertainPublication(_))),
            "receipt with mismatched digest fails closed"
        );
        Ok(())
    }

    #[test]
    fn lineage_self_reference_is_rejected() -> TestResult {
        let mut manifest = test_manifest("release-self-lineage");
        manifest.lineage.supersedes = Some(LineageSupersedes {
            supersedes_release_id: "release-self-lineage".to_owned(),
            supersedes_manifest_sha256: "00".repeat(32),
            supersedes_data_sha256: "11".repeat(32),
            revision: 1,
            correction_reason: "abstract correction".to_owned(),
            knowledge_time_ns: "500".to_owned(),
            invalidated_at_time: "epoch-500".to_owned(),
        });
        let receipts: Vec<PublicationReceipt> = Vec::new();
        let result = validate_lineage(
            &manifest,
            &LineageContext {
                predecessor: None,
                known_receipts: &receipts,
                now_ns: 10_000,
            },
        );
        assert!(
            matches!(result, Err(ProducerError::InvalidLineage(_))),
            "self-reference fails closed"
        );
        Ok(())
    }

    #[test]
    fn lineage_missing_predecessor_is_rejected() -> TestResult {
        let mut manifest = test_manifest("release-correction");
        manifest.lineage.supersedes = Some(LineageSupersedes {
            supersedes_release_id: "release-predecessor".to_owned(),
            supersedes_manifest_sha256: "00".repeat(32),
            supersedes_data_sha256: "11".repeat(32),
            revision: 1,
            correction_reason: "abstract correction".to_owned(),
            knowledge_time_ns: "500".to_owned(),
            invalidated_at_time: "epoch-500".to_owned(),
        });
        let receipts: Vec<PublicationReceipt> = Vec::new();
        let result = validate_lineage(
            &manifest,
            &LineageContext {
                predecessor: None,
                known_receipts: &receipts,
                now_ns: 10_000,
            },
        );
        assert!(
            matches!(result, Err(ProducerError::InvalidLineage(_))),
            "missing predecessor fails closed"
        );
        Ok(())
    }

    #[test]
    fn lineage_cycle_is_rejected() -> TestResult {
        let mut manifest = test_manifest("release-cycle");
        manifest.lineage.supersedes = Some(LineageSupersedes {
            supersedes_release_id: "release-predecessor".to_owned(),
            supersedes_manifest_sha256: "00".repeat(32),
            supersedes_data_sha256: "11".repeat(32),
            revision: 1,
            correction_reason: "abstract correction".to_owned(),
            knowledge_time_ns: "500".to_owned(),
            invalidated_at_time: "epoch-500".to_owned(),
        });
        let predecessor = PublicationReceipt {
            schema_version: 1,
            release_id: "release-predecessor".to_owned(),
            manifest_sha256: "00".repeat(32),
            data_sha256: "11".repeat(32),
            publication_operation_id: "op-predecessor".to_owned(),
            commit_position: "position-predecessor".to_owned(),
            result: PublicationState::Available,
            supersedes_release_id: Some("release-cycle".to_owned()),
        };
        let receipts = vec![predecessor.clone()];
        let result = validate_lineage(
            &manifest,
            &LineageContext {
                predecessor: Some(&predecessor),
                known_receipts: &receipts,
                now_ns: 10_000,
            },
        );
        assert!(
            matches!(result, Err(ProducerError::InvalidLineage(_))),
            "correction cycle fails closed"
        );
        Ok(())
    }

    #[test]
    fn lineage_revision_regression_is_rejected() -> TestResult {
        let mut manifest = test_manifest("release-regression");
        manifest.lineage.revision = 2;
        manifest.lineage.supersedes = Some(LineageSupersedes {
            supersedes_release_id: "release-predecessor".to_owned(),
            supersedes_manifest_sha256: "00".repeat(32),
            supersedes_data_sha256: "11".repeat(32),
            revision: 2,
            correction_reason: "abstract correction".to_owned(),
            knowledge_time_ns: "500".to_owned(),
            invalidated_at_time: "epoch-500".to_owned(),
        });
        let predecessor = PublicationReceipt {
            schema_version: 1,
            release_id: "release-predecessor".to_owned(),
            manifest_sha256: "00".repeat(32),
            data_sha256: "11".repeat(32),
            publication_operation_id: "op-predecessor".to_owned(),
            commit_position: "position-predecessor".to_owned(),
            result: PublicationState::Available,
            supersedes_release_id: None,
        };
        let receipts = vec![predecessor.clone()];
        let result = validate_lineage(
            &manifest,
            &LineageContext {
                predecessor: Some(&predecessor),
                known_receipts: &receipts,
                now_ns: 10_000,
            },
        );
        assert!(
            matches!(result, Err(ProducerError::InvalidLineage(_))),
            "revision regression fails closed"
        );
        Ok(())
    }

    #[test]
    fn no_private_key_bytes_are_written_to_the_release() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-no-key");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &temp.path().join("ledger"),
        )?;
        let secret = signing.to_bytes();
        let mut files = vec![root.join("release-no-key").join(MANIFEST_FILE_NAME)];
        files.push(root.join("release-no-key").join(SIDECAR_FILE_NAME));
        files.push(
            root.join("release-no-key")
                .join("artifacts")
                .join("a.jsonl"),
        );
        for path in files {
            let bytes = fs::read(path)?;
            assert!(
                !bytes.windows(secret.len()).any(|window| window == secret),
                "injected private key bytes are absent from the release package"
            );
        }
        Ok(())
    }

    #[test]
    fn build_release_publishes_artifacts_directory_layout() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-layout");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("root");
        build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &temp.path().join("ledger"),
        )?;
        let release = root.join("release-layout");
        let mut top = Vec::new();
        for entry in fs::read_dir(&release)? {
            top.push(entry?.file_name().to_string_lossy().into_owned());
        }
        top.sort();
        assert_eq!(
            top,
            vec!["artifacts", "manifest.json", "signature.json"],
            "published release has exactly the manifest, sidecar and artifacts directory"
        );
        assert!(
            release.join("artifacts").join("a.jsonl").is_file(),
            "artifact is stored at its declared relative path"
        );
        Ok(())
    }

    #[test]
    fn declared_relative_paths_are_not_flattened_to_root() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-no-flatten");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact(
            "artifacts/named-artifact.jsonl",
            "part",
            0,
            records,
        )];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("root");
        let outcome = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &temp.path().join("ledger"),
        )?;
        let release = root.join("release-no-flatten");
        assert!(
            !release.join("named-artifact.jsonl").exists(),
            "no artifact is written to the release root"
        );
        assert!(
            release
                .join("artifacts")
                .join("named-artifact.jsonl")
                .is_file(),
            "the declared artifacts path is preserved verbatim"
        );
        assert_eq!(
            outcome.evidence.artifact_paths,
            vec!["artifacts/named-artifact.jsonl".to_owned()],
            "evidence retains the declared relative path"
        );
        Ok(())
    }

    #[test]
    fn exact_file_set_rejects_an_extra_artifact() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-extra");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("root");
        let outcome = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &temp.path().join("ledger"),
        )?;
        let extra = root
            .join("release-extra")
            .join("artifacts")
            .join("extra.jsonl");
        fs::write(&extra, b"unexpected")?;
        let result = validate_artifact_set(&root.join("release-extra"), &outcome.evidence, &policy);
        assert!(
            matches!(result, Err(ProducerError::ArtifactSetMismatch(_))),
            "an extra file under artifacts/ fails the exact-set check"
        );
        Ok(())
    }

    #[test]
    fn exact_file_set_rejects_a_missing_artifact() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-missing-file");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("root");
        let outcome = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &temp.path().join("ledger"),
        )?;
        fs::remove_file(
            root.join("release-missing-file")
                .join("artifacts")
                .join("a.jsonl"),
        )?;
        let result = validate_artifact_set(
            &root.join("release-missing-file"),
            &outcome.evidence,
            &policy,
        );
        assert!(
            matches!(result, Err(ProducerError::ArtifactSetMismatch(_))),
            "a missing declared artifact fails the exact-set check"
        );
        Ok(())
    }

    #[test]
    fn declared_path_outside_artifacts_is_rejected() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-outside");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("outside.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let result = build_fixture(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &temp.path().join("root"),
            &temp.path().join("ledger"),
        );
        assert!(
            matches!(result, Err(ProducerError::InvalidArtifactPath(..))),
            "a declared path outside artifacts/ fails closed"
        );
        Ok(())
    }

    #[test]
    fn canonical_manifest_bytes_match_the_wire_mapping() -> TestResult {
        let policy = test_policy();
        let mut spec = test_spec();
        spec.manifest.lineage.supersedes = None;
        let wire_key = SigningKey::from_bytes(&ndc_wire::CONFORMANCE_SIGNING_SEED);
        let wire_verifying = wire_key.verifying_key();
        let (wire, _) =
            ndc_wire::build_conformance_release(&spec, &policy, &wire_key, &wire_verifying)?;
        let temp = TempDir::new()?;
        let produced = build_from_spec(
            &spec,
            &policy,
            &temp.path().join("root"),
            &temp.path().join("ledger"),
        )?;
        assert_eq!(
            produced.manifest_bytes, wire.manifest_bytes,
            "production builder and wire mapping emit identical manifest bytes"
        );
        Ok(())
    }

    #[test]
    fn sidecar_digest_and_signature_agree_with_canonical_bytes() -> TestResult {
        let policy = test_policy();
        let mut spec = test_spec();
        spec.manifest.lineage.supersedes = None;
        let temp = TempDir::new()?;
        let produced = build_from_spec(
            &spec,
            &policy,
            &temp.path().join("root"),
            &temp.path().join("ledger"),
        )?;
        let digest = hex_encode(&sha256(&produced.manifest_bytes));
        let text = String::from_utf8(produced.sidecar_bytes.clone())?;
        let value = parse_jcs_value(text.trim_end_matches('\n'))?;
        let JcsValue::Object(fields) = value else {
            return Err("sidecar is not an object".into());
        };
        let mut claimed = "";
        let mut signature_b64 = "";
        for (name, member) in &fields {
            let JcsValue::String(text) = member else {
                continue;
            };
            match name.as_str() {
                "manifest_sha256" => claimed = text,
                "signature_b64" => signature_b64 = text,
                _ => {}
            }
        }
        assert_eq!(
            claimed, digest,
            "sidecar digest binds the production canonical bytes"
        );
        let mut message = SIGNING_DOMAIN.to_vec();
        message.extend_from_slice(&sha256(&produced.manifest_bytes));
        let bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature_b64)?;
        let fixed: [u8; 64] = bytes.try_into().map_err(|_| "signature is not 64 bytes")?;
        let signature = ed25519_dalek::Signature::from_bytes(&fixed);
        let (_, verifying) = test_keys();
        verifying
            .verify(&message, &signature)
            .map_err(|error| format!("injected key rejected the sidecar signature: {error}"))?;
        Ok(())
    }

    #[test]
    fn manifest_carries_wire_only_members() -> TestResult {
        let policy = test_policy();
        let mut spec = test_spec();
        spec.manifest.lineage.supersedes = None;
        let temp = TempDir::new()?;
        let produced = build_from_spec(
            &spec,
            &policy,
            &temp.path().join("root"),
            &temp.path().join("ledger"),
        )?;
        let value = parse_jcs_value(&String::from_utf8(produced.manifest_bytes.clone())?)?;
        let JcsValue::Object(entries) = value else {
            return Err("manifest is not an object".into());
        };
        assert!(
            entries.iter().any(|(name, _)| name == "schema_versions"),
            "wire-only schema versions section is present"
        );
        assert!(
            text_contains(&produced.manifest_bytes, "payload_schemas"),
            "wire-only payload schema registry is present"
        );
        assert_eq!(
            entries.len(),
            13,
            "manifest has exactly thirteen wire members"
        );
        Ok(())
    }

    #[test]
    fn builder_does_not_invent_rights_grants() -> TestResult {
        let policy = test_policy();
        let mut spec = test_spec();
        spec.manifest.lineage.supersedes = None;
        let declared = spec.manifest.rights.permission_grants.len();
        let temp = TempDir::new()?;
        let produced = build_from_spec(
            &spec,
            &policy,
            &temp.path().join("root"),
            &temp.path().join("ledger"),
        )?;
        let value = parse_grant_count(&produced.manifest_bytes)?;
        assert_eq!(
            value, declared,
            "the builder emits exactly the declared rights grants"
        );
        Ok(())
    }

    #[test]
    fn staging_writes_artifacts_directory_before_rename() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-staged-layout");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("root");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_before_rename: true,
            ..PublicationFaults::default()
        };
        let result = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-staged-layout",
            faults,
        );
        assert!(
            matches!(result, Err(ProducerError::Io(..))),
            "the injected pre-rename failure is typed"
        );
        let staged = root.join(".staging-operation-staged-layout");
        assert!(
            staged.join("artifacts").join("a.jsonl").is_file(),
            "staging holds the artifact under artifacts/ before publication"
        );
        assert!(
            !staged.join("a.jsonl").exists(),
            "staging never flattens the artifact into its root"
        );
        Ok(())
    }

    #[test]
    fn recovery_with_artifacts_layout_succeeds() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-recovery-layout");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("root");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_before_rename: true,
            ..PublicationFaults::default()
        };
        let interrupted = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-recovery-layout",
            faults,
        );
        assert!(
            matches!(interrupted, Err(ProducerError::Io(..))),
            "the injected pre-rename failure is typed"
        );
        let evidence = evidence_for_operation(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            "operation-recovery-layout",
        )?;
        let outcome = recover_interrupted(&root, &ledger, &evidence, &policy)?;
        assert_eq!(
            outcome,
            RecoveryOutcome::RecoveredStaged,
            "complete staging is promoted after verification"
        );
        let release = root.join("release-recovery-layout");
        assert!(
            release.join("artifacts").join("a.jsonl").is_file(),
            "recovered release retains the artifacts directory layout"
        );
        Ok(())
    }

    #[test]
    fn recovery_detects_an_artifact_in_the_wrong_directory() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = test_manifest("release-wrong-dir");
        let records = vec![sequenced("{\"alpha\":\"aa\"}", 1, &policy)?];
        let artifacts = vec![sequenced_artifact("artifacts/a.jsonl", "part", 0, records)];
        let (signing, verifying) = test_keys();
        let root = temp.path().join("root");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_before_rename: true,
            ..PublicationFaults::default()
        };
        let interrupted = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-wrong-dir",
            faults,
        );
        assert!(
            matches!(interrupted, Err(ProducerError::Io(..))),
            "the injected pre-rename failure is typed"
        );
        let staged = root.join(".staging-operation-wrong-dir");
        fs::rename(
            staged.join("artifacts").join("a.jsonl"),
            staged.join("a.jsonl"),
        )?;
        let evidence = evidence_for_operation(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            "operation-wrong-dir",
        )?;
        let result = recover_interrupted(&root, &ledger, &evidence, &policy);
        assert!(
            matches!(result, Err(ProducerError::ArtifactSetMismatch(_))),
            "an artifact outside artifacts/ is refused by recovery"
        );
        Ok(())
    }

    fn boundary_manifest(release_id: &str) -> ReleaseManifest {
        test_manifest(release_id)
    }

    fn boundary_artifacts(policy: &ResourcePolicy) -> Vec<ArtifactInput> {
        let record =
            sequenced(r#"{"kind":"boundary"}"#, 1, policy).expect("boundary record is canonical");
        vec![sequenced_artifact(
            "artifacts/a.jsonl",
            "partition-a",
            0,
            vec![record],
        )]
    }

    fn boundary_evidence(
        manifest: &ReleaseManifest,
        artifacts: &[ArtifactInput],
        operation_id: &str,
    ) -> Result<PublicationEvidence, Box<dyn StdError>> {
        let policy = test_policy();
        let (signing, verifying) = test_keys();
        evidence_for_operation(
            manifest,
            artifacts,
            &signing,
            &verifying,
            &policy,
            operation_id,
        )
    }

    fn interrupt_boundary(
        faults: PublicationFaults,
        operation_id: &str,
        release_id: &str,
        root: &Path,
        ledger: &Path,
    ) -> Result<(PublicationEvidence, PublicationState), Box<dyn StdError>> {
        let policy = test_policy();
        let manifest = boundary_manifest(release_id);
        let artifacts = boundary_artifacts(&policy);
        let (signing, verifying) = test_keys();
        let result = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            root,
            ledger,
            operation_id,
            faults,
        );
        assert!(
            matches!(result, Err(ProducerError::Io(..))),
            "injected boundary failure is typed: {result:?}"
        );
        let evidence = boundary_evidence(&manifest, &artifacts, operation_id)?;
        let stage = last_stage(ledger, operation_id)?;
        Ok((evidence, stage))
    }

    const FULL_RECOVERY_ORDER: [PublicationRecoveryEvent; 10] = [
        PublicationRecoveryEvent::FinalDirectoryFound,
        PublicationRecoveryEvent::VerifyFinalDirectory,
        PublicationRecoveryEvent::VerifyOperationIdentity,
        PublicationRecoveryEvent::SyncReleaseParent,
        PublicationRecoveryEvent::VerifyDurabilityTransition,
        PublicationRecoveryEvent::CommitReceipt,
        PublicationRecoveryEvent::SyncReceiptLedger,
        PublicationRecoveryEvent::CommitAvailabilityMarker,
        PublicationRecoveryEvent::SyncReceiptLedger,
        PublicationRecoveryEvent::Available,
    ];

    fn assert_recovered_receipt(
        ledger: &Path,
        release_id: &str,
        evidence: &PublicationEvidence,
        outcome: RecoveryOutcome,
    ) -> Result<(), Box<dyn StdError>> {
        assert_eq!(
            outcome,
            RecoveryOutcome::RecoveredPublished,
            "recovery completes the interrupted publication"
        );
        let Some((bytes, receipt)) = load_receipt(ledger, release_id)? else {
            return Err("recovery committed no receipt".into());
        };
        assert_eq!(
            receipt, evidence.expected_receipt,
            "recovery preserves the builder receipt field for field"
        );
        assert!(
            receipt_matches(&receipt, &bytes, evidence),
            "the committed receipt matches every normative field and its digest"
        );
        assert_eq!(
            last_stage(ledger, &evidence.publication_operation_id)?,
            PublicationState::Available,
            "the final durable stage is available"
        );
        Ok(())
    }

    #[test]
    fn recovery_after_rename_syncs_parent_before_the_receipt() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_after_rename: true,
            ..PublicationFaults::default()
        };
        let (evidence, stage) = interrupt_boundary(
            faults,
            "operation-after-rename",
            "release-after-rename",
            &root,
            &ledger,
        )?;
        assert_eq!(
            stage,
            PublicationState::AtomicNoReplaceRename,
            "the rename stage is durable before the crash"
        );
        let fs = RecordingPublicationFs::new(PublicationFaults::default());
        let outcome = recover_with_fs(&root, &ledger, &evidence, &policy, &fs)?;
        assert_recovered_receipt(&ledger, &evidence.release_id, &evidence, outcome)?;
        assert_eq!(
            fs.events(),
            FULL_RECOVERY_ORDER.to_vec(),
            "recovery syncs the release parent before committing the receipt"
        );
        Ok(())
    }

    #[test]
    fn final_directory_without_rename_evidence_is_not_adopted() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_after_rename_before_stage: true,
            ..PublicationFaults::default()
        };
        let (evidence, stage) = interrupt_boundary(
            faults,
            "operation-unstaged-rename",
            "release-unstaged-rename",
            &root,
            &ledger,
        )?;
        assert_eq!(
            stage,
            PublicationState::StagingDirFsynced,
            "no stage claims a rename that has no durable record"
        );
        assert!(
            root.join("release-unstaged-rename").exists(),
            "the rename produced a final directory before the crash"
        );
        let fs = RecordingPublicationFs::new(PublicationFaults::default());
        let outcome = recover_with_fs(&root, &ledger, &evidence, &policy, &fs);
        assert!(
            matches!(outcome, Err(ProducerError::UncertainPublication(_))),
            "mere final-directory existence never grants ownership or an acknowledgement"
        );
        assert_eq!(
            fs.events(),
            vec![
                PublicationRecoveryEvent::FinalDirectoryFound,
                PublicationRecoveryEvent::VerifyFinalDirectory,
                PublicationRecoveryEvent::VerifyOperationIdentity,
            ],
            "ownership verification stops recovery before any sync or receipt"
        );
        assert!(
            !ledger.join("release-unstaged-rename.receipt.json").exists(),
            "no receipt is written for an unowned final directory"
        );
        Ok(())
    }

    #[test]
    fn recovery_during_parent_sync_never_commits_an_unsynced_receipt() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_parent_dir_sync: true,
            ..PublicationFaults::default()
        };
        let (evidence, stage) = interrupt_boundary(
            faults,
            "operation-parent-sync",
            "release-parent-sync",
            &root,
            &ledger,
        )?;
        assert_eq!(
            stage,
            PublicationState::AtomicNoReplaceRename,
            "a failed parent sync leaves the rename as the last stage"
        );
        let fs = RecordingPublicationFs::new(PublicationFaults::default());
        let outcome = recover_with_fs(&root, &ledger, &evidence, &policy, &fs)?;
        assert_recovered_receipt(&ledger, &evidence.release_id, &evidence, outcome)?;
        assert_eq!(
            fs.events(),
            FULL_RECOVERY_ORDER.to_vec(),
            "recovery supplies the missing parent sync before any receipt"
        );
        Ok(())
    }

    #[test]
    fn recovery_after_parent_sync_preserves_the_receipt_order() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_after_parent_sync: true,
            ..PublicationFaults::default()
        };
        let (evidence, stage) = interrupt_boundary(
            faults,
            "operation-after-parent",
            "release-after-parent",
            &root,
            &ledger,
        )?;
        assert_eq!(
            stage,
            PublicationState::AtomicNoReplaceRename,
            "the crash precedes the parent-synced stage record"
        );
        let fs = RecordingPublicationFs::new(PublicationFaults::default());
        let outcome = recover_with_fs(&root, &ledger, &evidence, &policy, &fs)?;
        assert_recovered_receipt(&ledger, &evidence.release_id, &evidence, outcome)?;
        assert_eq!(
            fs.events(),
            FULL_RECOVERY_ORDER.to_vec(),
            "recovery repeats the parent sync before committing the receipt"
        );
        Ok(())
    }

    #[test]
    fn recovery_during_receipt_ledger_sync_completes_both_ledger_syncs() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_receipt_ledger_sync: true,
            ..PublicationFaults::default()
        };
        let (evidence, stage) = interrupt_boundary(
            faults,
            "operation-receipt-sync",
            "release-receipt-sync",
            &root,
            &ledger,
        )?;
        assert_eq!(
            stage,
            PublicationState::ParentDirFsynced,
            "the receipt ledger sync failure precedes the receipt stage"
        );
        let fs = RecordingPublicationFs::new(PublicationFaults::default());
        let outcome = recover_with_fs(&root, &ledger, &evidence, &policy, &fs)?;
        assert_recovered_receipt(&ledger, &evidence.release_id, &evidence, outcome)?;
        assert_eq!(
            fs.events(),
            vec![
                PublicationRecoveryEvent::FinalDirectoryFound,
                PublicationRecoveryEvent::VerifyFinalDirectory,
                PublicationRecoveryEvent::VerifyOperationIdentity,
                PublicationRecoveryEvent::VerifyDurabilityTransition,
                PublicationRecoveryEvent::SyncReceiptLedger,
                PublicationRecoveryEvent::CommitAvailabilityMarker,
                PublicationRecoveryEvent::SyncReceiptLedger,
                PublicationRecoveryEvent::Available,
            ],
            "an existing receipt is verified before the marker and both ledger syncs"
        );
        Ok(())
    }

    #[test]
    fn recovery_during_marker_ledger_sync_makes_the_marker_durable() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let faults = PublicationFaults {
            fail_marker_ledger_sync: true,
            ..PublicationFaults::default()
        };
        let (evidence, stage) = interrupt_boundary(
            faults,
            "operation-marker-sync",
            "release-marker-sync",
            &root,
            &ledger,
        )?;
        assert_eq!(
            stage,
            PublicationState::DurablePublicationReceipt,
            "the marker ledger sync failure precedes the available stage"
        );
        let fs = RecordingPublicationFs::new(PublicationFaults::default());
        let outcome = recover_with_fs(&root, &ledger, &evidence, &policy, &fs)?;
        assert_recovered_receipt(&ledger, &evidence.release_id, &evidence, outcome)?;
        assert_eq!(
            fs.events(),
            vec![
                PublicationRecoveryEvent::FinalDirectoryFound,
                PublicationRecoveryEvent::VerifyFinalDirectory,
                PublicationRecoveryEvent::VerifyOperationIdentity,
                PublicationRecoveryEvent::VerifyDurabilityTransition,
                PublicationRecoveryEvent::SyncReceiptLedger,
                PublicationRecoveryEvent::SyncReceiptLedger,
                PublicationRecoveryEvent::Available,
            ],
            "the marker is already committed and only its ledger entry is completed"
        );
        Ok(())
    }

    #[test]
    fn partial_receipt_or_marker_is_never_acknowledged() -> TestResult {
        for (faults, operation_id, release_id) in [
            (
                PublicationFaults {
                    fail_receipt_commit: true,
                    ..PublicationFaults::default()
                },
                "operation-partial-receipt",
                "release-partial-receipt",
            ),
            (
                PublicationFaults {
                    fail_marker_commit: true,
                    ..PublicationFaults::default()
                },
                "operation-partial-marker",
                "release-partial-marker",
            ),
        ] {
            let temp = TempDir::new()?;
            let policy = test_policy();
            let root = temp.path().join("releases");
            let ledger = temp.path().join("ledger");
            let (evidence, _) =
                interrupt_boundary(faults, operation_id, release_id, &root, &ledger)?;
            let fs = RecordingPublicationFs::new(PublicationFaults::default());
            let outcome = recover_with_fs(&root, &ledger, &evidence, &policy, &fs);
            assert!(
                matches!(outcome, Err(ProducerError::UncertainPublication(_))),
                "a partial durable file is never converted into an acknowledgement"
            );
            assert_eq!(
                fs.events(),
                vec![
                    PublicationRecoveryEvent::FinalDirectoryFound,
                    PublicationRecoveryEvent::VerifyFinalDirectory,
                    PublicationRecoveryEvent::VerifyOperationIdentity,
                ],
                "recovery stops at verification when a partial file is present"
            );
        }
        Ok(())
    }

    #[test]
    fn recovery_does_not_adopt_a_release_from_another_operation() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = boundary_manifest("release-ownership");
        let artifacts = boundary_artifacts(&policy);
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let winner = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-winner",
            PublicationFaults::default(),
        )?;
        let loser = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-loser",
            PublicationFaults::default(),
        );
        assert!(
            matches!(loser, Err(ProducerError::PublicationCollision(_))),
            "the second operation loses the no-replace rename"
        );
        let evidence = boundary_evidence(&manifest, &artifacts, "operation-loser")?;
        let fs = RecordingPublicationFs::new(PublicationFaults::default());
        let outcome = recover_with_fs(&root, &ledger, &evidence, &policy, &fs);
        assert!(
            matches!(outcome, Err(ProducerError::UncertainPublication(_))),
            "a losing operation never receives an acknowledgement"
        );
        assert_eq!(
            fs.events(),
            vec![
                PublicationRecoveryEvent::FinalDirectoryFound,
                PublicationRecoveryEvent::VerifyFinalDirectory,
                PublicationRecoveryEvent::VerifyOperationIdentity,
            ],
            "ownership verification precedes any receipt or marker event"
        );
        assert!(
            ledger.join("release-ownership.available").exists(),
            "the winner retains its own availability marker"
        );
        assert_eq!(
            load_receipt(&ledger, "release-ownership")?
                .map(|(_, receipt)| receipt.publication_operation_id),
            Some(winner.receipt.publication_operation_id),
            "the durable receipt still belongs to the winning operation"
        );
        Ok(())
    }

    #[test]
    fn forged_rename_stage_does_not_transfer_ownership() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = boundary_manifest("release-forged");
        let artifacts = boundary_artifacts(&policy);
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-owner",
            PublicationFaults::default(),
        )?;
        let loser = build_with_faults(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-forger",
            PublicationFaults::default(),
        );
        assert!(
            matches!(loser, Err(ProducerError::PublicationCollision(_))),
            "the forger loses the release identity"
        );
        let evidence = boundary_evidence(&manifest, &artifacts, "operation-forger")?;
        let forged = stage_for_state(
            &operation_from_evidence(&evidence, "operation-forger"),
            PublicationState::AtomicNoReplaceRename,
        );
        write_stage(&ledger, &forged, 4, &policy)?;
        let outcome = recover_interrupted(&root, &ledger, &evidence, &policy);
        assert!(
            matches!(outcome, Err(ProducerError::UncertainPublication(_))),
            "a foreign operation's rename evidence prevents adoption"
        );
        assert_eq!(
            load_receipt(&ledger, "release-forged")?
                .map(|(_, receipt)| receipt.publication_operation_id),
            Some("operation-owner".to_owned()),
            "the receipt identity is unchanged by the forged stage"
        );
        Ok(())
    }

    #[test]
    fn stage_journal_conflicts_and_regressions_fail_closed() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let (evidence, _) = interrupt_boundary(
            PublicationFaults {
                fail_after_rename: true,
                ..PublicationFaults::default()
            },
            "operation-journal",
            "release-journal",
            &root,
            &ledger,
        )?;
        let original = stage_path(&ledger, "operation-journal", 4);
        fs::remove_file(&original)?;
        let mut regressed = operation_from_evidence(&evidence, "operation-journal");
        regressed.stage = PublicationState::FilesWritten;
        write_stage(&ledger, &regressed, 4, &policy)?;
        let result = recover_interrupted(&root, &ledger, &evidence, &policy);
        assert!(
            matches!(result, Err(ProducerError::PublicationEvidence(_))),
            "a stage regression is rejected before any acknowledgement"
        );
        fs::remove_file(stage_path(&ledger, "operation-journal", 4))?;
        let mut conflicting = operation_from_evidence(&evidence, "operation-journal");
        conflicting.stage = PublicationState::AtomicNoReplaceRename;
        conflicting.release_id = "release-other".to_owned();
        write_stage(&ledger, &conflicting, 4, &policy)?;
        let result = recover_interrupted(&root, &ledger, &evidence, &policy);
        assert!(
            matches!(result, Err(ProducerError::PublicationEvidence(_))),
            "a conflicting release identity in the journal is rejected"
        );
        fs::remove_file(stage_path(&ledger, "operation-journal", 4))?;
        let mut wrong_digest = operation_from_evidence(&evidence, "operation-journal");
        wrong_digest.stage = PublicationState::AtomicNoReplaceRename;
        wrong_digest.manifest_sha256 = "ff".repeat(32);
        write_stage(&ledger, &wrong_digest, 4, &policy)?;
        let result = recover_interrupted(&root, &ledger, &evidence, &policy);
        assert!(
            result.is_err(),
            "a digest mismatch in journal evidence is rejected"
        );
        Ok(())
    }

    #[test]
    fn duplicate_and_out_of_range_stage_ordinals_fail_closed() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let (evidence, _) = interrupt_boundary(
            PublicationFaults {
                fail_after_rename: true,
                ..PublicationFaults::default()
            },
            "operation-ordinals",
            "release-ordinals",
            &root,
            &ledger,
        )?;
        let extra = stage_for_state(
            &operation_from_evidence(&evidence, "operation-ordinals"),
            PublicationState::Available,
        );
        write_stage(&ledger, &extra, 8, &policy)?;
        let result = recover_interrupted(&root, &ledger, &evidence, &policy);
        assert!(
            matches!(result, Err(ProducerError::PublicationEvidence(_))),
            "a stage beyond the ratified state machine is rejected"
        );
        fs::remove_file(stage_path(&ledger, "operation-ordinals", 8))?;
        write_stage(&ledger, &extra, 9, &policy)?;
        fs::rename(
            stage_path(&ledger, "operation-ordinals", 9),
            ledger.join("operation-ordinals.stage.4.json"),
        )?;
        let result = recover_interrupted(&root, &ledger, &evidence, &policy);
        assert!(
            matches!(result, Err(ProducerError::PublicationEvidence(_))),
            "a duplicate stage ordinal is rejected"
        );
        Ok(())
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the correction fixture carries the full build boundary plus its injected fault"
    )]
    fn build_correction_inner(
        manifest: &ReleaseManifest,
        artifacts: &[ArtifactInput],
        signing: &SigningKey,
        verifying: &VerifyingKey,
        policy: &ResourcePolicy,
        root: &Path,
        ledger: &Path,
        operation_id: &str,
        commit_position: &str,
        faults: PublicationFaults,
        fs: &dyn PublicationFs,
    ) -> Result<BuildOutcome, ProducerError> {
        let descriptor = manifest.lineage.supersedes.as_ref().ok_or_else(|| {
            ProducerError::InvalidLineage("correction fixture lacks lineage".to_owned())
        })?;
        let predecessor = PublicationReceipt {
            schema_version: MANIFEST_SCHEMA_VERSION,
            release_id: descriptor.supersedes_release_id.clone(),
            manifest_sha256: descriptor.supersedes_manifest_sha256.clone(),
            data_sha256: descriptor.supersedes_data_sha256.clone(),
            publication_operation_id: "operation-predecessor".to_owned(),
            commit_position: "position-predecessor".to_owned(),
            result: PublicationState::Available,
            supersedes_release_id: None,
        };
        let receipts = vec![predecessor.clone()];
        let lineage = LineageContext {
            predecessor: Some(&predecessor),
            known_receipts: &receipts,
            now_ns: 10_000,
        };
        let evidence = test_evidence();
        let observed = BTreeSet::new();
        let signature = SignatureConfig {
            signing_key: signing,
            verifying_key: verifying,
            key_id: &manifest.publication_identity.signing_key_id,
        };
        let request = BuildRequest {
            release_root: root,
            ledger_dir: ledger,
            operation_id,
            commit_position,
            manifest,
            evidence: &evidence,
            observed_event_types: &observed,
            artifacts,
            signature,
            policy,
            lineage,
        };
        build_release_inner(&request, faults, fs)
    }

    fn correction_manifest() -> ReleaseManifest {
        let mut manifest = boundary_manifest("release-correction");
        manifest.lineage.revision = 2;
        manifest.lineage.supersedes = Some(LineageSupersedes {
            supersedes_release_id: "release-predecessor".to_owned(),
            supersedes_manifest_sha256: "a7".repeat(32),
            supersedes_data_sha256: "b9".repeat(32),
            revision: 1,
            correction_reason: "abstract correction".to_owned(),
            knowledge_time_ns: "2500".to_owned(),
            invalidated_at_time: "2026-11-23T00:00:00.000000000Z".to_owned(),
        });
        manifest
    }

    fn correction_evidence(
        manifest: &ReleaseManifest,
        artifacts: &[ArtifactInput],
    ) -> Result<PublicationEvidence, Box<dyn StdError>> {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let (signing, verifying) = test_keys();
        let fs = RealPublicationFs;
        let outcome = build_correction_inner(
            manifest,
            artifacts,
            &signing,
            &verifying,
            &policy,
            &temp.path().join("releases"),
            &temp.path().join("ledger"),
            "operation-correction",
            "position-correction",
            PublicationFaults::default(),
            &fs,
        )?;
        Ok(outcome.evidence)
    }

    #[test]
    fn correction_recovery_preserves_predecessor_lineage() -> TestResult {
        let temp = TempDir::new()?;
        let policy = test_policy();
        let manifest = correction_manifest();
        let artifacts = boundary_artifacts(&policy);
        let (signing, verifying) = test_keys();
        let root = temp.path().join("releases");
        let ledger = temp.path().join("ledger");
        let evidence = correction_evidence(&manifest, &artifacts)?;
        assert_eq!(
            evidence.expected_receipt.supersedes_release_id.as_deref(),
            Some("release-predecessor"),
            "the builder receipt retains the predecessor identity"
        );
        let faults = PublicationFaults {
            fail_after_parent_sync: true,
            ..PublicationFaults::default()
        };
        let fs = RecordingPublicationFs::new(faults);
        let result = build_correction_inner(
            &manifest,
            &artifacts,
            &signing,
            &verifying,
            &policy,
            &root,
            &ledger,
            "operation-correction",
            "position-correction",
            faults,
            &fs,
        );
        assert!(
            matches!(result, Err(ProducerError::Io(..))),
            "the correction crash is typed"
        );
        let recovery_fs = RecordingPublicationFs::new(PublicationFaults::default());
        let outcome = recover_with_fs(&root, &ledger, &evidence, &policy, &recovery_fs)?;
        assert_recovered_receipt(&ledger, &evidence.release_id, &evidence, outcome)?;
        assert_eq!(
            recovery_fs.events(),
            FULL_RECOVERY_ORDER.to_vec(),
            "correction recovery follows the ratified transition order"
        );
        let Some((bytes, receipt)) = load_receipt(&ledger, "release-correction")? else {
            return Err("correction receipt is absent".into());
        };
        assert_eq!(
            receipt.schema_version, MANIFEST_SCHEMA_VERSION,
            "recovery preserves the receipt schema version"
        );
        assert_eq!(
            receipt.supersedes_release_id.as_deref(),
            Some("release-predecessor"),
            "recovery preserves the correction lineage"
        );
        assert!(
            receipt_matches(&receipt, &bytes, &evidence),
            "the recovered correction receipt matches the complete intent"
        );
        Ok(())
    }

    fn text_contains(bytes: &[u8], needle: &str) -> bool {
        std::str::from_utf8(bytes).is_ok_and(|text| text.contains(needle))
    }

    fn parse_grant_count(bytes: &[u8]) -> Result<usize, Box<dyn StdError>> {
        let text = std::str::from_utf8(bytes)?;
        let value: serde_json::Value = serde_json::from_str(text)?;
        let grants = value
            .get("rights")
            .and_then(|rights| rights.get("permission_grants"))
            .and_then(serde_json::Value::as_array)
            .ok_or("rights.permission_grants is absent")?;
        Ok(grants.len())
    }
}
