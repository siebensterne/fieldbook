// SPDX-License-Identifier: Apache-2.0
//! Immutable, versioned resource-profile contract for the streaming producer.
//!
//! The ratified contract in `WS-STREAM-001` fixes the form of the profile and
//! leaves every numeric maximum DEFERRED. This module therefore registers no
//! production profile and no approved digest. Only finite profiles whose name
//! carries the `TEST_ONLY` marker exist here, and they are reachable from a
//! test harness alone.
//!
//! All fields are private and are populated by one validating constructor.
//! There is no setter, no caller-supplied raw limit on a production path and
//! no fallback when trusted local policy cannot select an approved profile.

use serde::Serialize;
use sha2::Digest as _;
use sha2::Sha256;
use thiserror::Error;

use crate::distribution::ndc_release::ResourcePolicy;

/// Domain separation for the canonical resource-profile digest.
const PROFILE_DIGEST_DOMAIN: &[u8] = b"FIELDBOOK-STREAM-RESOURCE-PROFILE-V1\x00";

/// Minimum parallel descriptor set: artifact, staging writer, verify and one
/// owned directory descriptor. The number is structural, not a ratified
/// maximum; a profile below it fails validation.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the constructor that uses the structural minimum is test-only"
    )
)]
const MIN_OPEN_FILE_DESCRIPTORS: u32 = 4;

/// Fail-closed profile and selection failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProfileError {
    /// The profile identifier was empty or outside the accepted alphabet.
    #[error("invalid resource profile identifier: {0}")]
    InvalidId(String),

    /// A required limit was zero where a positive value is required.
    #[error("resource profile limit `{0}` must be positive")]
    ZeroLimit(String),

    /// Two limits stood in an inconsistent relation.
    #[error("inconsistent resource profile limits: {0}")]
    Inconsistent(String),

    /// The profile declared a role that does not match the request.
    #[error("resource profile role {0} does not match {1}")]
    RoleMismatch(&'static str, &'static str),

    /// The stored digest did not match the canonical profile bytes.
    #[error("resource profile digest mismatch for {0}")]
    DigestMismatch(String),

    /// No approved profile exists for the requested role.
    #[error("no approved resource profile is registered for role {0}")]
    NoApprovedProfile(&'static str),

    /// A test-only profile was presented where an approved profile is needed.
    #[error("test-only resource profile {0} is not admissible in production")]
    TestOnlyRefused(String),
}

impl ProfileError {
    /// Stable refusal code for typed evidence.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidId(_) => "PROFILE_INVALID_ID",
            Self::ZeroLimit(_) => "PROFILE_ZERO_LIMIT",
            Self::Inconsistent(_) => "PROFILE_INCONSISTENT",
            Self::RoleMismatch(..) => "PROFILE_ROLE_MISMATCH",
            Self::DigestMismatch(_) => "PROFILE_DIGEST_MISMATCH",
            Self::NoApprovedProfile(_) => "PROFILE_NOT_APPROVED",
            Self::TestOnlyRefused(_) => "PROFILE_TEST_ONLY_REFUSED",
        }
    }
}

/// Processing role bound to one profile and one resident-memory budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ProcessingRole {
    /// Bounded release producer.
    Producer,
    /// Independent release verifier.
    Verifier,
    /// Bounded recovery task.
    Recovery,
    /// Bounded snapshot task.
    Snapshot,
}

impl ProcessingRole {
    /// Stable wire literal for the role.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Producer => "PRODUCER",
            Self::Verifier => "VERIFIER",
            Self::Recovery => "RECOVERY",
            Self::Snapshot => "SNAPSHOT",
        }
    }
}

/// Versioned identity of one immutable resource profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceProfileId {
    name: String,
    version: u32,
}

impl ResourceProfileId {
    /// Validate and construct one profile identifier.
    pub fn new(name: impl Into<String>, version: u32) -> Result<Self, ProfileError> {
        let name = name.into();
        let valid = !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            && name
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_uppercase());
        if !valid {
            return Err(ProfileError::InvalidId(name));
        }
        if version == 0 {
            return Err(ProfileError::InvalidId(
                "profile version must be positive".to_owned(),
            ));
        }
        Ok(Self { name, version })
    }

    /// Profile name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Profile version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Render the identifier as one stable literal.
    #[must_use]
    pub fn as_literal(&self) -> String {
        format!("{}@{}", self.name, self.version)
    }
}

/// Canonical codec settings for the registered compression method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StorageCodec {
    window_bytes: u64,
}

impl StorageCodec {
    /// Construct codec settings from a validated window size.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "profiles are populated by the validating test constructor"
        )
    )]
    pub(crate) const fn new(window_bytes: u64) -> Self {
        Self { window_bytes }
    }

    /// Codec window size in bytes.
    #[must_use]
    pub const fn window_bytes(self) -> u64 {
        self.window_bytes
    }
}

/// Parser bounds applied inside the one-line strict record parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ParserProfile {
    max_nesting_depth: u32,
    max_string_bytes: u32,
    max_token_bytes: u32,
    max_object_members: u32,
    max_array_elements: u32,
}

impl ParserProfile {
    /// Construct parser bounds through the validating parent constructor.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "profiles are populated by the validating test constructor"
        )
    )]
    const fn new(
        max_nesting_depth: u32,
        max_string_bytes: u32,
        max_token_bytes: u32,
        max_object_members: u32,
        max_array_elements: u32,
    ) -> Self {
        Self {
            max_nesting_depth,
            max_string_bytes,
            max_token_bytes,
            max_object_members,
            max_array_elements,
        }
    }

    /// Maximum nesting depth of one parsed record.
    #[must_use]
    pub const fn max_nesting_depth(self) -> u32 {
        self.max_nesting_depth
    }

    /// Maximum byte length of one parsed string.
    #[must_use]
    pub const fn max_string_bytes(self) -> u32 {
        self.max_string_bytes
    }

    /// Maximum byte length of one parsed token.
    #[must_use]
    pub const fn max_token_bytes(self) -> u32 {
        self.max_token_bytes
    }

    /// Maximum member count of one parsed object.
    #[must_use]
    pub const fn max_object_members(self) -> u32 {
        self.max_object_members
    }

    /// Maximum element count of one parsed array.
    #[must_use]
    pub const fn max_array_elements(self) -> u32 {
        self.max_array_elements
    }
}

/// Complete set of enforceable limits. Every value is DEFERRED by the
/// ratification; this type carries no approved number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ProfileLimits {
    max_record_bytes: u64,
    max_records_per_artifact: u64,
    max_records_per_release: u64,
    max_artifacts_per_release: u64,
    max_stored_bytes_per_artifact: u64,
    max_stored_bytes_per_release: u64,
    max_expanded_bytes_per_artifact: u64,
    max_expanded_bytes_per_release: u64,
    max_decompression_budget_bytes: u64,
    max_expansion_ratio: u64,
    storage_codec: StorageCodec,
    io_chunk_bytes: u64,
    parser: ParserProfile,
    max_concurrent_artifacts: u64,
    worker_count: u64,
    queue_capacity_records: u64,
    temp_disk_bytes: u64,
    max_processing_duration_secs: u64,
    max_journal_record_bytes: u64,
    max_preparation_intent_bytes: u64,
    max_sealed_intent_bytes: u64,
    max_open_file_descriptors: u32,
    memory_budget_bytes: u64,
}

/// Input to the single validating constructor.
///
/// The structure exists only to name the deferred values. It is crate-visible
/// so a test harness can build a finite profile without exposing a raw-limit
/// constructor on a production path.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct LimitInputs {
    pub(crate) max_record_bytes: u64,
    pub(crate) max_records_per_artifact: u64,
    pub(crate) max_records_per_release: u64,
    pub(crate) max_artifacts_per_release: u64,
    pub(crate) max_stored_bytes_per_artifact: u64,
    pub(crate) max_stored_bytes_per_release: u64,
    pub(crate) max_expanded_bytes_per_artifact: u64,
    pub(crate) max_expanded_bytes_per_release: u64,
    pub(crate) max_decompression_budget_bytes: u64,
    pub(crate) max_expansion_ratio: u64,
    pub(crate) storage_codec_window_bytes: u64,
    pub(crate) io_chunk_bytes: u64,
    pub(crate) max_nesting_depth: u32,
    pub(crate) max_string_bytes: u32,
    pub(crate) max_token_bytes: u32,
    pub(crate) max_object_members: u32,
    pub(crate) max_array_elements: u32,
    pub(crate) max_concurrent_artifacts: u64,
    pub(crate) worker_count: u64,
    pub(crate) queue_capacity_records: u64,
    pub(crate) temp_disk_bytes: u64,
    pub(crate) max_processing_duration_secs: u64,
    pub(crate) max_journal_record_bytes: u64,
    pub(crate) max_preparation_intent_bytes: u64,
    pub(crate) max_sealed_intent_bytes: u64,
    pub(crate) max_open_file_descriptors: u32,
    pub(crate) memory_budget_bytes: u64,
}

impl ProfileLimits {
    /// Validate every finite value and every required relation.
    #[cfg(test)]
    pub(crate) fn new(input: LimitInputs) -> Result<Self, ProfileError> {
        let positive = [
            ("max_record_bytes", input.max_record_bytes),
            ("max_records_per_artifact", input.max_records_per_artifact),
            ("max_records_per_release", input.max_records_per_release),
            ("max_artifacts_per_release", input.max_artifacts_per_release),
            (
                "max_stored_bytes_per_artifact",
                input.max_stored_bytes_per_artifact,
            ),
            (
                "max_stored_bytes_per_release",
                input.max_stored_bytes_per_release,
            ),
            (
                "max_expanded_bytes_per_artifact",
                input.max_expanded_bytes_per_artifact,
            ),
            (
                "max_expanded_bytes_per_release",
                input.max_expanded_bytes_per_release,
            ),
            (
                "max_decompression_budget_bytes",
                input.max_decompression_budget_bytes,
            ),
            ("max_expansion_ratio", input.max_expansion_ratio),
            (
                "storage_codec.window_bytes",
                input.storage_codec_window_bytes,
            ),
            ("io_chunk_bytes", input.io_chunk_bytes),
            ("max_concurrent_artifacts", input.max_concurrent_artifacts),
            ("worker_count", input.worker_count),
            ("queue_capacity_records", input.queue_capacity_records),
            ("temp_disk_bytes", input.temp_disk_bytes),
            (
                "max_processing_duration_secs",
                input.max_processing_duration_secs,
            ),
            ("max_journal_record_bytes", input.max_journal_record_bytes),
            (
                "max_preparation_intent_bytes",
                input.max_preparation_intent_bytes,
            ),
            ("max_sealed_intent_bytes", input.max_sealed_intent_bytes),
            ("memory_budget_bytes", input.memory_budget_bytes),
        ];
        for (name, value) in positive {
            if value == 0 {
                return Err(ProfileError::ZeroLimit(name.to_owned()));
            }
        }
        let parser_positive = [
            ("parser.max_nesting_depth", input.max_nesting_depth),
            ("parser.max_string_bytes", input.max_string_bytes),
            ("parser.max_token_bytes", input.max_token_bytes),
            ("parser.max_object_members", input.max_object_members),
            ("parser.max_array_elements", input.max_array_elements),
        ];
        for (name, value) in parser_positive {
            if value == 0 {
                return Err(ProfileError::ZeroLimit(name.to_owned()));
            }
        }
        if input.max_open_file_descriptors < MIN_OPEN_FILE_DESCRIPTORS {
            return Err(ProfileError::Inconsistent(
                "max_open_file_descriptors is below the required parallel set".to_owned(),
            ));
        }
        if input.max_records_per_artifact > input.max_records_per_release
            || input.max_artifacts_per_release > input.max_records_per_release
            || input.max_stored_bytes_per_artifact > input.max_stored_bytes_per_release
            || input.max_expanded_bytes_per_artifact > input.max_expanded_bytes_per_release
        {
            return Err(ProfileError::Inconsistent(
                "a per-artifact limit exceeds its per-release limit".to_owned(),
            ));
        }
        if input.io_chunk_bytes > input.max_record_bytes
            || u64::from(input.max_string_bytes) > input.max_record_bytes
            || u64::from(input.max_token_bytes) > input.max_record_bytes
            || u64::from(input.max_object_members) > input.max_record_bytes
            || u64::from(input.max_array_elements) > input.max_record_bytes
            || input.queue_capacity_records > input.max_records_per_artifact
            || input.storage_codec_window_bytes > input.max_expanded_bytes_per_artifact
        {
            return Err(ProfileError::Inconsistent(
                "a chunk, parser, queue or window bound exceeds its parent bound".to_owned(),
            ));
        }
        Ok(Self {
            max_record_bytes: input.max_record_bytes,
            max_records_per_artifact: input.max_records_per_artifact,
            max_records_per_release: input.max_records_per_release,
            max_artifacts_per_release: input.max_artifacts_per_release,
            max_stored_bytes_per_artifact: input.max_stored_bytes_per_artifact,
            max_stored_bytes_per_release: input.max_stored_bytes_per_release,
            max_expanded_bytes_per_artifact: input.max_expanded_bytes_per_artifact,
            max_expanded_bytes_per_release: input.max_expanded_bytes_per_release,
            max_decompression_budget_bytes: input.max_decompression_budget_bytes,
            max_expansion_ratio: input.max_expansion_ratio,
            storage_codec: StorageCodec::new(input.storage_codec_window_bytes),
            io_chunk_bytes: input.io_chunk_bytes,
            parser: ParserProfile::new(
                input.max_nesting_depth,
                input.max_string_bytes,
                input.max_token_bytes,
                input.max_object_members,
                input.max_array_elements,
            ),
            max_concurrent_artifacts: input.max_concurrent_artifacts,
            worker_count: input.worker_count,
            queue_capacity_records: input.queue_capacity_records,
            temp_disk_bytes: input.temp_disk_bytes,
            max_processing_duration_secs: input.max_processing_duration_secs,
            max_journal_record_bytes: input.max_journal_record_bytes,
            max_preparation_intent_bytes: input.max_preparation_intent_bytes,
            max_sealed_intent_bytes: input.max_sealed_intent_bytes,
            max_open_file_descriptors: input.max_open_file_descriptors,
            memory_budget_bytes: input.memory_budget_bytes,
        })
    }

    /// Maximum framed record bytes excluding the appended LF.
    #[must_use]
    pub const fn max_record_bytes(&self) -> u64 {
        self.max_record_bytes
    }

    /// Maximum observed records in one artifact.
    #[must_use]
    pub const fn max_records_per_artifact(&self) -> u64 {
        self.max_records_per_artifact
    }

    /// Maximum observed records in one release.
    #[must_use]
    pub const fn max_records_per_release(&self) -> u64 {
        self.max_records_per_release
    }

    /// Maximum artifact count in one release.
    #[must_use]
    pub const fn max_artifacts_per_release(&self) -> u64 {
        self.max_artifacts_per_release
    }

    /// Maximum stored bytes in one artifact.
    #[must_use]
    pub const fn max_stored_bytes_per_artifact(&self) -> u64 {
        self.max_stored_bytes_per_artifact
    }

    /// Maximum stored bytes in one release.
    #[must_use]
    pub const fn max_stored_bytes_per_release(&self) -> u64 {
        self.max_stored_bytes_per_release
    }

    /// Maximum expanded bytes in one artifact.
    #[must_use]
    pub const fn max_expanded_bytes_per_artifact(&self) -> u64 {
        self.max_expanded_bytes_per_artifact
    }

    /// Maximum expanded bytes in one release.
    #[must_use]
    pub const fn max_expanded_bytes_per_release(&self) -> u64 {
        self.max_expanded_bytes_per_release
    }

    /// Consumer-side emission cap applied before buffer growth.
    #[must_use]
    pub const fn max_decompression_budget_bytes(&self) -> u64 {
        self.max_decompression_budget_bytes
    }

    /// Expanded-to-stored ratio ceiling for one artifact.
    #[must_use]
    pub const fn max_expansion_ratio(&self) -> u64 {
        self.max_expansion_ratio
    }

    /// Registered codec settings.
    #[must_use]
    pub const fn storage_codec(&self) -> StorageCodec {
        self.storage_codec
    }

    /// Fixed stored and decoder chunk size.
    #[must_use]
    pub const fn io_chunk_bytes(&self) -> u64 {
        self.io_chunk_bytes
    }

    /// Parser bounds for the one-line strict parse.
    #[must_use]
    pub const fn parser(&self) -> ParserProfile {
        self.parser
    }

    /// Maximum concurrently active artifacts.
    #[must_use]
    pub const fn max_concurrent_artifacts(&self) -> u64 {
        self.max_concurrent_artifacts
    }

    /// Fixed worker count.
    #[must_use]
    pub const fn worker_count(&self) -> u64 {
        self.worker_count
    }

    /// Fixed queue capacity in records.
    #[must_use]
    pub const fn queue_capacity_records(&self) -> u64 {
        self.queue_capacity_records
    }

    /// Spool and staging disk bound for one operation.
    #[must_use]
    pub const fn temp_disk_bytes(&self) -> u64 {
        self.temp_disk_bytes
    }

    /// Wall-clock processing budget in seconds.
    #[must_use]
    pub const fn max_processing_duration_secs(&self) -> u64 {
        self.max_processing_duration_secs
    }

    /// Maximum durable journal record size.
    #[must_use]
    pub const fn max_journal_record_bytes(&self) -> u64 {
        self.max_journal_record_bytes
    }

    /// Maximum preparation-intent size.
    #[must_use]
    pub const fn max_preparation_intent_bytes(&self) -> u64 {
        self.max_preparation_intent_bytes
    }

    /// Maximum sealed-intent size.
    #[must_use]
    pub const fn max_sealed_intent_bytes(&self) -> u64 {
        self.max_sealed_intent_bytes
    }

    /// Parallel descriptor bound.
    #[must_use]
    pub const fn max_open_file_descriptors(&self) -> u32 {
        self.max_open_file_descriptors
    }

    /// Role-specific resident-memory budget.
    #[must_use]
    pub const fn memory_budget_bytes(&self) -> u64 {
        self.memory_budget_bytes
    }

    /// Adapt the profile into the existing caller-policy shape so the canon-
    /// ical wire parser enforces the same record and parser bounds.
    pub(crate) fn to_resource_policy(self) -> ResourcePolicy {
        ResourcePolicy {
            max_manifest_bytes: self.max_sealed_intent_bytes,
            max_artifact_count: self.max_artifacts_per_release,
            max_stored_bytes_per_artifact: self.max_stored_bytes_per_artifact,
            max_uncompressed_bytes_per_artifact: self.max_expanded_bytes_per_artifact,
            max_total_stored_bytes: self.max_stored_bytes_per_release,
            max_total_uncompressed_bytes: self.max_expanded_bytes_per_release,
            max_record_bytes: self.max_record_bytes,
            max_records_per_artifact: self.max_records_per_artifact,
            max_path_component_bytes: u64::from(self.parser.max_token_bytes).min(255),
            max_nesting_depth: self.parser.max_nesting_depth,
            max_object_members: self.parser.max_object_members,
            max_array_elements: self.parser.max_array_elements,
            max_sidecar_bytes: self.max_journal_record_bytes,
            max_intent_bytes: self
                .max_preparation_intent_bytes
                .max(self.max_sealed_intent_bytes),
        }
    }
}

/// Immutable, self-digested resource profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceProfile {
    id: ResourceProfileId,
    digest: [u8; 32],
    role: ProcessingRole,
    limits: ProfileLimits,
}

#[derive(Serialize)]
struct CanonicalProfileMaterial<'a> {
    name: &'a str,
    version: u32,
    role: &'a str,
    limits: &'a ProfileLimits,
}

impl ResourceProfile {
    /// Construct a finite test-only profile. The marker is mandatory and the
    /// constructor is reachable only from a test harness.
    #[cfg(test)]
    pub(crate) fn new_test_only(
        id: ResourceProfileId,
        role: ProcessingRole,
        limits: ProfileLimits,
    ) -> Result<Self, ProfileError> {
        if !id.name().contains("TEST_ONLY") {
            return Err(ProfileError::TestOnlyRefused(id.as_literal()));
        }
        let digest = Self::canonical_digest(&id, role, &limits)?;
        Ok(Self {
            id,
            digest,
            role,
            limits,
        })
    }

    fn canonical_digest(
        id: &ResourceProfileId,
        role: ProcessingRole,
        limits: &ProfileLimits,
    ) -> Result<[u8; 32], ProfileError> {
        let material = CanonicalProfileMaterial {
            name: id.name(),
            version: id.version(),
            role: role.as_str(),
            limits,
        };
        let bytes = serde_json::to_vec(&material).map_err(|error| {
            ProfileError::Inconsistent(format!("profile serialization: {error}"))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(PROFILE_DIGEST_DOMAIN);
        hasher.update([0_u8]);
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }

    /// Profile identifier and version.
    #[must_use]
    pub fn id(&self) -> &ResourceProfileId {
        &self.id
    }

    /// Canonical domain-separated digest of every profile field.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Bound processing role.
    #[must_use]
    pub const fn role(&self) -> ProcessingRole {
        self.role
    }

    /// Enforced limits.
    #[must_use]
    pub const fn limits(&self) -> &ProfileLimits {
        &self.limits
    }

    /// Recompute the digest and fail closed on any drift.
    pub fn verify_digest(&self) -> Result<(), ProfileError> {
        let recomputed = Self::canonical_digest(&self.id, self.role, &self.limits)?;
        if recomputed != self.digest {
            return Err(ProfileError::DigestMismatch(self.id.as_literal()));
        }
        Ok(())
    }
}

/// Approval state kept beside a profile in trusted local policy. No approved
/// variant exists while the numeric maxima remain deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileApproval {
    /// Finite evidence profile admitted by a test harness only.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only a test harness registers local profile entries"
        )
    )]
    TestOnly,
}

/// Trusted local policy for profile selection inside each process.
///
/// The registry is populated locally. A manifest field, a caller hint or a
/// declaration carried in a preparation intent cannot add an entry.
#[derive(Debug, Default)]
pub struct ProfileSelection {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "only a test harness registers local profile entries"
        )
    )]
    entries: Vec<(ResourceProfile, ProfileApproval)>,
}

impl ProfileSelection {
    /// Construct an empty local policy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a finite test-only profile. Production code cannot call this
    /// constructor, so a test profile does not become a local approval.
    #[cfg(test)]
    pub(crate) fn insert_test_only(
        &mut self,
        profile: ResourceProfile,
    ) -> Result<(), ProfileError> {
        profile.verify_digest()?;
        if !profile.id().name().contains("TEST_ONLY") {
            return Err(ProfileError::TestOnlyRefused(profile.id().as_literal()));
        }
        self.entries.push((profile, ProfileApproval::TestOnly));
        Ok(())
    }

    /// Select an approved profile for production. No profile is approved while
    /// the numeric maxima and the per-role digests remain deferred.
    pub fn select_for_production(
        &self,
        role: ProcessingRole,
        _id: &ResourceProfileId,
    ) -> Result<&ResourceProfile, ProfileError> {
        Err(ProfileError::NoApprovedProfile(role.as_str()))
    }

    /// Select a finite test-only profile for a test harness.
    #[cfg(test)]
    pub(crate) fn select_for_test(
        &self,
        role: ProcessingRole,
        id: &ResourceProfileId,
    ) -> Result<&ResourceProfile, ProfileError> {
        let found = self
            .entries
            .iter()
            .find(|(profile, _)| profile.id() == id)
            .map(|(profile, approval)| (profile, approval));
        let Some((profile, approval)) = found else {
            return Err(ProfileError::NoApprovedProfile(role.as_str()));
        };
        if profile.role() != role {
            return Err(ProfileError::RoleMismatch(
                profile.role().as_str(),
                role.as_str(),
            ));
        }
        if *approval != ProfileApproval::TestOnly {
            return Err(ProfileError::TestOnlyRefused(id.as_literal()));
        }
        profile.verify_digest()?;
        Ok(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn test_limits() -> LimitInputs {
        LimitInputs {
            max_record_bytes: 4_096,
            max_records_per_artifact: 1_024,
            max_records_per_release: 4_096,
            max_artifacts_per_release: 4,
            max_stored_bytes_per_artifact: 1_048_576,
            max_stored_bytes_per_release: 4_194_304,
            max_expanded_bytes_per_artifact: 4_194_304,
            max_expanded_bytes_per_release: 16_777_216,
            max_decompression_budget_bytes: 16_777_216,
            max_expansion_ratio: 16,
            storage_codec_window_bytes: 32_768,
            io_chunk_bytes: 4_096,
            max_nesting_depth: 16,
            max_string_bytes: 1_024,
            max_token_bytes: 128,
            max_object_members: 64,
            max_array_elements: 256,
            max_concurrent_artifacts: 1,
            worker_count: 1,
            queue_capacity_records: 64,
            temp_disk_bytes: 16_777_216,
            max_processing_duration_secs: 120,
            max_journal_record_bytes: 65_536,
            max_preparation_intent_bytes: 262_144,
            max_sealed_intent_bytes: 262_144,
            max_open_file_descriptors: 8,
            memory_budget_bytes: 64 * 1024 * 1024,
        }
    }

    fn test_profile(role: ProcessingRole) -> Result<ResourceProfile, Box<dyn std::error::Error>> {
        Ok(ResourceProfile::new_test_only(
            ResourceProfileId::new("STREAM_TEST_ONLY_PRODUCER_V1", 1)?,
            role,
            ProfileLimits::new(test_limits())?,
        )?)
    }

    #[test]
    fn profile_id_rejects_empty_and_lowercase_names() {
        assert!(
            matches!(
                ResourceProfileId::new("", 1),
                Err(ProfileError::InvalidId(_))
            ),
            "an empty profile name must be refused"
        );
        assert!(
            matches!(
                ResourceProfileId::new("lower", 1),
                Err(ProfileError::InvalidId(_))
            ),
            "a lowercase profile name must be refused"
        );
        assert!(
            matches!(
                ResourceProfileId::new("VALID", 0),
                Err(ProfileError::InvalidId(_))
            ),
            "version zero must be refused"
        );
    }

    #[test]
    fn role_literals_are_the_ratified_four() {
        let roles = [
            ProcessingRole::Producer,
            ProcessingRole::Verifier,
            ProcessingRole::Recovery,
            ProcessingRole::Snapshot,
        ];
        let rendered: Vec<&str> = roles.iter().map(|role| role.as_str()).collect();
        assert_eq!(
            rendered,
            vec!["PRODUCER", "VERIFIER", "RECOVERY", "SNAPSHOT"],
            "role literals must match the ratified contract"
        );
    }

    #[test]
    fn zero_limit_is_refused() {
        let mut input = test_limits();
        input.max_record_bytes = 0;
        assert!(
            matches!(ProfileLimits::new(input), Err(ProfileError::ZeroLimit(_))),
            "a zero record bound must be refused"
        );
    }

    #[test]
    fn inconsistent_relations_are_refused() {
        let mut input = test_limits();
        input.max_records_per_artifact = input.max_records_per_release + 1;
        assert!(
            matches!(
                ProfileLimits::new(input),
                Err(ProfileError::Inconsistent(_))
            ),
            "a per-artifact count above the release count must be refused"
        );
        let mut input = test_limits();
        input.io_chunk_bytes = input.max_record_bytes + 1;
        assert!(
            matches!(
                ProfileLimits::new(input),
                Err(ProfileError::Inconsistent(_))
            ),
            "a chunk above the record bound must be refused"
        );
        let mut input = test_limits();
        input.max_string_bytes = u32::try_from(input.max_record_bytes + 1).unwrap_or(u32::MAX);
        assert!(
            matches!(
                ProfileLimits::new(input),
                Err(ProfileError::Inconsistent(_))
            ),
            "a string bound above the record bound must be refused"
        );
        let mut input = test_limits();
        input.max_open_file_descriptors = 3;
        assert!(
            matches!(
                ProfileLimits::new(input),
                Err(ProfileError::Inconsistent(_))
            ),
            "a descriptor count below the parallel set must be refused"
        );
        let mut input = test_limits();
        input.queue_capacity_records = input.max_records_per_artifact + 1;
        assert!(
            matches!(
                ProfileLimits::new(input),
                Err(ProfileError::Inconsistent(_))
            ),
            "a queue above the record bound must be refused"
        );
    }

    #[test]
    fn profile_digest_is_domain_separated_and_field_sensitive() -> TestResult {
        let profile = test_profile(ProcessingRole::Producer)?;
        profile.verify_digest()?;
        let mut changed = profile.clone();
        changed.limits.max_record_bytes += 1;
        assert!(
            matches!(
                changed.verify_digest(),
                Err(ProfileError::DigestMismatch(_))
            ),
            "changing one limit must invalidate the digest"
        );
        assert_ne!(
            profile.digest(),
            &[0_u8; 32],
            "the domain-separated digest is not the zero value"
        );
        Ok(())
    }

    #[test]
    fn test_only_marker_is_mandatory() -> TestResult {
        let id = ResourceProfileId::new("STREAM_UNMARKED_PRODUCER_V1", 1)?;
        let result = ResourceProfile::new_test_only(
            id,
            ProcessingRole::Producer,
            ProfileLimits::new(test_limits())?,
        );
        assert!(
            matches!(result, Err(ProfileError::TestOnlyRefused(_))),
            "an unmarked profile must not be constructed by the test-only constructor"
        );
        Ok(())
    }

    #[test]
    fn production_selection_refuses_every_profile() -> TestResult {
        let mut policy = ProfileSelection::new();
        let profile = test_profile(ProcessingRole::Producer)?;
        let id = profile.id().clone();
        policy.insert_test_only(profile)?;
        let result = policy.select_for_production(ProcessingRole::Producer, &id);
        assert!(
            matches!(result, Err(ProfileError::NoApprovedProfile(_))),
            "no approved profile exists while numeric maxima are deferred"
        );
        assert_eq!(
            ProfileError::NoApprovedProfile("PRODUCER").code(),
            "PROFILE_NOT_APPROVED",
            "the refusal code is stable"
        );
        Ok(())
    }

    #[test]
    fn test_selection_enforces_role_and_digest() -> TestResult {
        let mut policy = ProfileSelection::new();
        let profile = test_profile(ProcessingRole::Producer)?;
        let id = profile.id().clone();
        policy.insert_test_only(profile)?;
        let selected = policy.select_for_test(ProcessingRole::Producer, &id)?;
        assert_eq!(
            selected.role(),
            ProcessingRole::Producer,
            "the selected role matches the request"
        );
        assert!(
            matches!(
                policy.select_for_test(ProcessingRole::Verifier, &id),
                Err(ProfileError::RoleMismatch(..))
            ),
            "a verifier must not execute under a producer profile"
        );
        Ok(())
    }
}
