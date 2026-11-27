// SPDX-License-Identifier: Apache-2.0
//! Versioned source-event envelope: provenance metadata, never market observations.
//!
//! An event records *that* a frame was captured, decoded, validated or
//! quarantined, together with the identities and receipts that make the record
//! auditable. No price, quantity, book or trade payload is represented here.
//! Nothing in this module contacts a provider, reads a clock, admits a dataset
//! or grants rights: every value is supplied by the caller and checked as
//! data.
//!
//! The envelope digest is SHA-256 over canonical JSON of every other field:
//! keys sorted lexicographically, no whitespace, `null` for an absent optional
//! value. A digest is never synthesized by a reader; a producer may call
//! [`SourceEventEnvelope::seal`] to set it before publishing the metadata.
//!
//! Rejections expose the normative v1 reason codes from the source-event
//! contract. Internal Rust variants may be finer grained, but
//! [`SourceEventReason::as_str`] is the stable external vocabulary.

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde::Serialize;

use crate::util::sha256_hex;

/// The only source-event schema version accepted by this contract.
pub const SOURCE_EVENT_SCHEMA_VERSION: u32 = 1;

/// Stable reason codes for source-event rejection.
///
/// The strings returned by [`Self::as_str`] are the normative v1 codes and are
/// part of the audit contract; they do not change with display wording.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceEventReason {
    UnsupportedSchemaVersion,
    UnknownOrMissingMember,
    MalformedJson,
    EmptyString,
    InvalidConnectionEpoch,
    InvalidReceiveTime,
    InvalidProviderSequence,
    InvalidDigestFormat,
    EnvelopeDigestMismatch,
    InvalidQualityState,
    InvalidContinuityState,
    ValidatedRequiresDecoderVersion,
    ValidatedRequiresReferenceDataRevision,
    ValidatedContinuityRequired,
    QuarantinedNotAdmittable,
    NonMonotonicCaptureSequence,
    NonMonotonicCanonicalSequence,
    CanonicalizationFailed,
}

impl SourceEventReason {
    /// Stable machine-readable normative v1 reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedSchemaVersion => "SCHEMA_VERSION_MISMATCH",
            Self::UnknownOrMissingMember | Self::MalformedJson | Self::CanonicalizationFailed => {
                "UNKNOWN_OR_MISSING_MEMBER"
            }
            Self::EmptyString => "EMPTY_REQUIRED_STRING",
            Self::InvalidConnectionEpoch => "INVALID_CONNECTION_EPOCH",
            Self::InvalidReceiveTime => "INVALID_RECEIVE_TIME",
            Self::InvalidProviderSequence => "INVALID_PROVIDER_SEQUENCE",
            Self::InvalidDigestFormat => "INVALID_DIGEST_FORMAT",
            Self::EnvelopeDigestMismatch => "ENVELOPE_DIGEST_MISMATCH",
            Self::InvalidQualityState => "INVALID_QUALITY_STATE",
            Self::InvalidContinuityState => "INVALID_CONTINUITY_STATE",
            Self::ValidatedRequiresDecoderVersion
            | Self::ValidatedRequiresReferenceDataRevision => "VALIDATED_MISSING_REVISIONS",
            Self::ValidatedContinuityRequired => "VALIDATED_CONTINUITY_UNRESOLVED",
            Self::QuarantinedNotAdmittable => "QUARANTINED_NOT_ADMISSIBLE",
            Self::NonMonotonicCaptureSequence => "NON_MONOTONIC_CAPTURE_SEQUENCE",
            Self::NonMonotonicCanonicalSequence => "NON_MONOTONIC_CANONICAL_SEQUENCE",
        }
    }
}

impl fmt::Display for SourceEventReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Typed, whole-value rejection. No event is partly accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("source event rejected: reason={reason} field={field}")]
pub struct SourceEventError {
    pub reason: SourceEventReason,
    pub field: String,
}

impl SourceEventError {
    fn new(reason: SourceEventReason, field: impl Into<String>) -> Self {
        Self {
            reason,
            field: field.into(),
        }
    }

    /// Stable normative reason code of this rejection.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        self.reason.as_str()
    }
}

/// Quality state of a source event. Values are the exact wire spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum QualityState {
    Captured,
    Decoded,
    Validated,
    Quarantined,
}

impl QualityState {
    /// Exact JSON spelling of this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Captured => "CAPTURED",
            Self::Decoded => "DECODED",
            Self::Validated => "VALIDATED",
            Self::Quarantined => "QUARANTINED",
        }
    }
}

/// Continuity state of a source event. Values are the exact wire spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContinuityState {
    Continuous,
    GapSuspected,
    Recovered,
    Unknown,
}

impl ContinuityState {
    /// Exact JSON spelling of this state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Continuous => "CONTINUOUS",
            Self::GapSuspected => "GAP_SUSPECTED",
            Self::Recovered => "RECOVERED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Versioned source-event metadata envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceEventEnvelope {
    pub schema_version: u32,
    pub source_id: String,
    pub source_product_ref: String,
    pub session_ref: String,
    pub decoder_version: String,
    pub reference_data_revision: String,
    pub rights_evidence_ref: String,
    pub connection_epoch: u64,
    pub capture_sequence: u64,
    pub canonical_sequence: u64,
    /// `null` means the provider did not supply a sequence; it is never
    /// synthesized by this library.
    pub provider_sequence: Option<u64>,
    pub source_timestamp_ns: Option<u64>,
    pub receive_utc_ns: u64,
    pub receive_monotonic_ns: u64,
    pub raw_frame_digest: String,
    pub envelope_digest: String,
    pub quality_state: QualityState,
    pub continuity_state: ContinuityState,
}

fn is_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Name of the field a serde error refers to, if it names one.
fn serde_error_field(message: &str) -> String {
    message.split('`').nth(1).unwrap_or("json").to_owned()
}

/// Classify a typed-deserialization failure without ever collapsing the input
/// into a `serde_json::Value` (which would silently discard duplicate members).
fn from_serde_error(error: serde_json::Error) -> SourceEventError {
    let message = error.to_string();
    let reason = if message.contains("duplicate field")
        || message.contains("missing field")
        || message.contains("unknown field")
    {
        SourceEventReason::UnknownOrMissingMember
    } else if message.contains("unknown variant") && message.contains("`CAPTURED`") {
        SourceEventReason::InvalidQualityState
    } else if message.contains("unknown variant") && message.contains("`CONTINUOUS`") {
        SourceEventReason::InvalidContinuityState
    } else {
        SourceEventReason::MalformedJson
    };
    let field = match reason {
        SourceEventReason::InvalidQualityState => "quality_state".to_owned(),
        SourceEventReason::InvalidContinuityState => "continuity_state".to_owned(),
        _ => serde_error_field(&message),
    };
    SourceEventError::new(reason, field)
}

impl SourceEventEnvelope {
    /// Canonical JSON of all fields except `envelope_digest`.
    ///
    /// A `BTreeMap` is used instead of relying on the serializer's map
    /// ordering, so sorted keys hold even when `serde_json` is built with the
    /// `preserve_order` feature. This is the unchanged v1 digest input.
    ///
    /// # Errors
    /// Returns [`SourceEventReason::CanonicalizationFailed`] if the value
    /// cannot be rendered as JSON.
    pub fn canonical_payload(&self) -> Result<String, SourceEventError> {
        let value = serde_json::to_value(self).map_err(|_| {
            SourceEventError::new(SourceEventReason::CanonicalizationFailed, "json")
        })?;
        let object = value.as_object().ok_or_else(|| {
            SourceEventError::new(SourceEventReason::CanonicalizationFailed, "json")
        })?;
        let mut fields = BTreeMap::new();
        for (key, item) in object {
            if key != "envelope_digest" {
                fields.insert(key.clone(), item.clone());
            }
        }
        serde_json::to_string(&fields)
            .map_err(|_| SourceEventError::new(SourceEventReason::CanonicalizationFailed, "json"))
    }

    /// SHA-256 lowercase hex of [`Self::canonical_payload`].
    ///
    /// # Errors
    /// Returns [`SourceEventReason::CanonicalizationFailed`] if canonical JSON
    /// cannot be produced.
    pub fn compute_digest(&self) -> Result<String, SourceEventError> {
        Ok(sha256_hex(self.canonical_payload()?.as_bytes()))
    }

    /// Set `envelope_digest` to the digest of the remaining fields and check
    /// the complete value. This is a producer-side operation on local data.
    ///
    /// # Errors
    /// Returns the typed rejection for any invalid field.
    pub fn seal(mut self) -> Result<Self, SourceEventError> {
        self.envelope_digest = self.compute_digest()?;
        self.validate()?;
        Ok(self)
    }

    /// Decode a complete v1 envelope into the typed struct and validate it.
    ///
    /// Parsing goes straight into [`SourceEventEnvelope`]: `deny_unknown_fields`
    /// rejects extra members and serde rejects duplicate members instead of
    /// letting a later `Value` parse overwrite them. The digest is then built
    /// from the serialized typed fields, preserving the v1 wire shape.
    ///
    /// # Errors
    /// Returns the typed rejection for any invalid field. There is no partial
    /// envelope on failure.
    pub fn from_json(input: &str) -> Result<Self, SourceEventError> {
        let event: Self = serde_json::from_str(input).map_err(from_serde_error)?;
        event.validate()?;
        Ok(event)
    }

    /// Validate the complete value, including the digest and quality rules.
    ///
    /// A `QUARANTINED` event is a valid record but is not admissible
    /// downstream; use [`Self::admission`] for that decision.
    ///
    /// # Errors
    /// Returns the typed rejection for the first failing rule.
    pub fn validate(&self) -> Result<(), SourceEventError> {
        self.validate_structure()?;
        self.validate_quality()?;
        let expected = self.compute_digest()?;
        if expected != self.envelope_digest {
            return Err(SourceEventError::new(
                SourceEventReason::EnvelopeDigestMismatch,
                "envelope_digest",
            ));
        }
        Ok(())
    }

    /// Per-event downstream admission check. This is not dataset admission:
    /// no dataset, release or recipient is involved here.
    ///
    /// # Errors
    /// Returns the typed rejection if the value is invalid or quarantined.
    pub fn admission(&self) -> Result<(), SourceEventError> {
        self.validate()?;
        if self.quality_state == QualityState::Quarantined {
            return Err(SourceEventError::new(
                SourceEventReason::QuarantinedNotAdmittable,
                "quality_state",
            ));
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), SourceEventError> {
        if self.schema_version != SOURCE_EVENT_SCHEMA_VERSION {
            return Err(SourceEventError::new(
                SourceEventReason::UnsupportedSchemaVersion,
                "schema_version",
            ));
        }
        if self.connection_epoch == 0 {
            return Err(SourceEventError::new(
                SourceEventReason::InvalidConnectionEpoch,
                "connection_epoch",
            ));
        }
        // A zero sequence is never a valid starting watermark: reject it
        // before any ledger can record a high-water mark.
        if self.capture_sequence == 0 {
            return Err(SourceEventError::new(
                SourceEventReason::NonMonotonicCaptureSequence,
                "capture_sequence",
            ));
        }
        if self.canonical_sequence == 0 {
            return Err(SourceEventError::new(
                SourceEventReason::NonMonotonicCanonicalSequence,
                "canonical_sequence",
            ));
        }
        if self.receive_utc_ns == 0 || self.receive_monotonic_ns == 0 {
            return Err(SourceEventError::new(
                SourceEventReason::InvalidReceiveTime,
                "receive_utc_ns",
            ));
        }
        if self.provider_sequence == Some(0) {
            return Err(SourceEventError::new(
                SourceEventReason::InvalidProviderSequence,
                "provider_sequence",
            ));
        }
        if !is_digest(&self.raw_frame_digest) {
            return Err(SourceEventError::new(
                SourceEventReason::InvalidDigestFormat,
                "raw_frame_digest",
            ));
        }
        if !is_digest(&self.envelope_digest) {
            return Err(SourceEventError::new(
                SourceEventReason::InvalidDigestFormat,
                "envelope_digest",
            ));
        }
        Self::text("source_id", &self.source_id)?;
        Self::text("source_product_ref", &self.source_product_ref)?;
        Self::text("session_ref", &self.session_ref)?;
        Self::text("rights_evidence_ref", &self.rights_evidence_ref)?;
        Ok(())
    }

    fn text(field: &str, value: &str) -> Result<(), SourceEventError> {
        if value.trim().is_empty() {
            Err(SourceEventError::new(SourceEventReason::EmptyString, field))
        } else {
            Ok(())
        }
    }

    fn validate_quality(&self) -> Result<(), SourceEventError> {
        if self.quality_state == QualityState::Validated {
            if self.decoder_version.trim().is_empty() {
                return Err(SourceEventError::new(
                    SourceEventReason::ValidatedRequiresDecoderVersion,
                    "decoder_version",
                ));
            }
            if self.reference_data_revision.trim().is_empty() {
                return Err(SourceEventError::new(
                    SourceEventReason::ValidatedRequiresReferenceDataRevision,
                    "reference_data_revision",
                ));
            }
            if matches!(
                self.continuity_state,
                ContinuityState::GapSuspected | ContinuityState::Unknown
            ) {
                return Err(SourceEventError::new(
                    SourceEventReason::ValidatedContinuityRequired,
                    "continuity_state",
                ));
            }
        }
        Self::text("decoder_version", &self.decoder_version)?;
        Self::text("reference_data_revision", &self.reference_data_revision)?;
        Ok(())
    }
}

/// Monotonicity of `capture_sequence` and `canonical_sequence` per
/// `(source_id, session_ref)` scope.
///
/// State changes only after the whole event passes admission; a rejection
/// leaves the recorded high-water marks untouched. Two sources that share one
/// session therefore keep independent histories.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionSequences {
    last: BTreeMap<(String, String), (u64, u64)>,
}

impl SessionSequences {
    /// Empty sequence tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit one event into its `(source_id, session_ref)` scope and advance
    /// that scope's high-water marks.
    ///
    /// # Errors
    /// Returns [`SourceEventReason::NonMonotonicCaptureSequence`] or
    /// [`SourceEventReason::NonMonotonicCanonicalSequence`] when the relevant
    /// sequence repeats or decreases, or the event-level rejection when the
    /// event itself is not admissible. Rejections never touch a watermark.
    pub fn admit(&mut self, event: &SourceEventEnvelope) -> Result<(), SourceEventError> {
        event.admission()?;
        let key = (event.source_id.clone(), event.session_ref.clone());
        if let Some((capture, canonical)) = self.last.get(&key).copied() {
            if event.capture_sequence <= capture {
                return Err(SourceEventError::new(
                    SourceEventReason::NonMonotonicCaptureSequence,
                    "capture_sequence",
                ));
            }
            if event.canonical_sequence <= canonical {
                return Err(SourceEventError::new(
                    SourceEventReason::NonMonotonicCanonicalSequence,
                    "canonical_sequence",
                ));
            }
        }
        self.last
            .insert(key, (event.capture_sequence, event.canonical_sequence));
        Ok(())
    }

    /// Highest admitted pair for one `(source_id, session_ref)` scope, if any.
    #[must_use]
    pub fn last(&self, source_id: &str, session_ref: &str) -> Option<(u64, u64)> {
        self.last
            .get(&(source_id.to_owned(), session_ref.to_owned()))
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_event() -> SourceEventEnvelope {
        SourceEventEnvelope {
            schema_version: SOURCE_EVENT_SCHEMA_VERSION,
            source_id: "source-a".to_owned(),
            source_product_ref: "product-a".to_owned(),
            session_ref: "session-a".to_owned(),
            decoder_version: "decoder-1".to_owned(),
            reference_data_revision: "refdata-1".to_owned(),
            rights_evidence_ref: "rights-evidence-a".to_owned(),
            connection_epoch: 7,
            capture_sequence: 10,
            canonical_sequence: 20,
            provider_sequence: None,
            source_timestamp_ns: Some(1_700_000_000_000_000_000),
            receive_utc_ns: 1_700_000_000_000_000_001,
            receive_monotonic_ns: 4_200,
            raw_frame_digest: "a".repeat(64),
            envelope_digest: "0".repeat(64),
            quality_state: QualityState::Validated,
            continuity_state: ContinuityState::Continuous,
        }
    }

    fn sample() -> SourceEventEnvelope {
        base_event().seal().expect("sample event seals")
    }

    #[test]
    fn digest_is_over_sorted_whitespace_free_canonical_json() {
        let event = sample();
        let payload = event.canonical_payload().expect("canonical payload exists");
        assert!(!payload.contains(' '), "canonical JSON has no spaces");
        assert!(
            payload.find("\"capture_sequence\"").expect("capture key")
                < payload.find("\"schema_version\"").expect("schema key"),
            "keys are sorted lexicographically"
        );
        assert!(
            !payload.contains("envelope_digest"),
            "the digest field is excluded from its own payload"
        );
        assert!(
            payload.contains("\"provider_sequence\":null"),
            "null is preserved"
        );
        assert_eq!(
            event.envelope_digest,
            sha256_hex(payload.as_bytes()),
            "envelope digest matches SHA-256 of canonical payload"
        );
    }

    #[test]
    fn valid_envelope_round_trips_through_json() {
        let event = sample();
        let json = serde_json::to_string(&event).expect("serializable event");
        let decoded = SourceEventEnvelope::from_json(&json).expect("valid event decodes");
        assert_eq!(decoded, event, "round trip preserves every field");
        assert_eq!(
            decoded.provider_sequence, None,
            "an absent provider sequence is not synthesized"
        );
    }

    #[test]
    fn missing_field_is_rejected_with_the_normative_code() {
        let mut value: serde_json::Value =
            serde_json::to_value(sample()).expect("serializable sample");
        value
            .as_object_mut()
            .expect("object value")
            .remove("source_id");
        let json = serde_json::to_string(&value).expect("serializable value");
        let error = SourceEventEnvelope::from_json(&json).expect_err("missing field is rejected");
        assert_eq!(
            error.reason_code(),
            "UNKNOWN_OR_MISSING_MEMBER",
            "missing member maps to the normative code"
        );
        assert_eq!(error.field, "source_id", "the absent field is named");
    }

    #[test]
    fn duplicate_member_is_rejected_before_digest_recomputation() {
        let json = format!(
            "{{\"schema_version\":1,\"source_id\":\"a\",\"source_id\":\"a\",\
             \"source_product_ref\":\"p\",\"session_ref\":\"s\",\
             \"decoder_version\":\"d\",\"reference_data_revision\":\"r\",\
             \"rights_evidence_ref\":\"e\",\"connection_epoch\":1,\
             \"capture_sequence\":1,\"canonical_sequence\":1,\
             \"provider_sequence\":null,\"source_timestamp_ns\":null,\
             \"receive_utc_ns\":1,\"receive_monotonic_ns\":1,\
             \"raw_frame_digest\":\"{}\",\"envelope_digest\":\"{}\",\
             \"quality_state\":\"CAPTURED\",\"continuity_state\":\"CONTINUOUS\"}}",
            "a".repeat(64),
            "0".repeat(64)
        );
        let error = SourceEventEnvelope::from_json(&json)
            .expect_err("a duplicate member is never silently overwritten");
        assert_eq!(
            error.reason_code(),
            "UNKNOWN_OR_MISSING_MEMBER",
            "duplicate member maps to the normative code"
        );
    }

    #[test]
    fn unknown_member_is_rejected_with_the_normative_code() {
        let mut value: serde_json::Value =
            serde_json::to_value(sample()).expect("serializable sample");
        value
            .as_object_mut()
            .expect("object value")
            .insert("extra".to_owned(), serde_json::json!(1));
        let json = serde_json::to_string(&value).expect("serializable value");
        let error = SourceEventEnvelope::from_json(&json).expect_err("unknown member is rejected");
        assert_eq!(
            error.reason_code(),
            "UNKNOWN_OR_MISSING_MEMBER",
            "unknown member maps to the normative code"
        );
    }

    #[test]
    fn altered_envelope_digest_is_rejected() {
        let mut event = sample();
        event.envelope_digest = format!("{}1", "0".repeat(63));
        let error = event.validate().expect_err("altered digest is rejected");
        assert_eq!(
            error.reason_code(),
            "ENVELOPE_DIGEST_MISMATCH",
            "digest mismatch has a stable code"
        );
    }

    #[test]
    fn uppercase_and_short_hex_digests_are_rejected() {
        let mut uppercase = sample();
        uppercase.raw_frame_digest = "A".repeat(64);
        let error = uppercase
            .validate()
            .expect_err("uppercase hex is not a valid digest");
        assert_eq!(
            error.reason_code(),
            "INVALID_DIGEST_FORMAT",
            "uppercase digest has the format code"
        );
        let mut short = sample();
        short.envelope_digest = "a".repeat(63);
        let error = short
            .validate()
            .expect_err("short hex is not a valid digest");
        assert_eq!(
            error.field, "envelope_digest",
            "short digest field is named"
        );
    }

    #[test]
    fn zero_epoch_and_receive_times_are_rejected() {
        let mut event = base_event();
        event.connection_epoch = 0;
        event.receive_utc_ns = 0;
        event.receive_monotonic_ns = 0;
        let error = event.validate().expect_err("zero epoch is rejected");
        assert_eq!(
            error.reason_code(),
            "INVALID_CONNECTION_EPOCH",
            "zero epoch has a stable code"
        );
        let mut event = base_event();
        event.receive_monotonic_ns = 0;
        let error = event
            .validate()
            .expect_err("zero monotonic receive time is rejected");
        assert_eq!(
            error.reason_code(),
            "INVALID_RECEIVE_TIME",
            "zero monotonic receive time has a stable code"
        );
    }

    #[test]
    fn zero_sequences_are_rejected_with_distinct_normative_codes() {
        let mut capture_zero = base_event();
        capture_zero.capture_sequence = 0;
        let error = capture_zero
            .validate()
            .expect_err("a zero capture sequence is rejected");
        assert_eq!(
            error.reason_code(),
            "NON_MONOTONIC_CAPTURE_SEQUENCE",
            "zero capture sequence has its own code"
        );
        let mut canonical_zero = base_event();
        canonical_zero.canonical_sequence = 0;
        let error = canonical_zero
            .validate()
            .expect_err("a zero canonical sequence is rejected");
        assert_eq!(
            error.reason_code(),
            "NON_MONOTONIC_CANONICAL_SEQUENCE",
            "zero canonical sequence has its own code"
        );
    }

    #[test]
    fn duplicate_and_decreasing_sequences_are_rejected() {
        let mut tracker = SessionSequences::new();
        let first = sample();
        tracker.admit(&first).expect("first event is admitted");
        assert_eq!(
            tracker.last("source-a", "session-a"),
            Some((10, 20)),
            "high-water marks are recorded"
        );
        let error = tracker.admit(&first).expect_err("duplicate is rejected");
        assert_eq!(
            error.reason_code(),
            "NON_MONOTONIC_CAPTURE_SEQUENCE",
            "a repeated capture sequence has its own code"
        );
        assert_eq!(
            tracker.last("source-a", "session-a"),
            Some((10, 20)),
            "a rejected event does not advance state"
        );
        let mut decreasing_canonical = base_event();
        decreasing_canonical.capture_sequence = 11;
        decreasing_canonical.canonical_sequence = 19;
        let decreasing_canonical = decreasing_canonical
            .seal()
            .expect("decreasing canonical event seals");
        let error = tracker
            .admit(&decreasing_canonical)
            .expect_err("a decrease is rejected");
        assert_eq!(
            error.reason_code(),
            "NON_MONOTONIC_CANONICAL_SEQUENCE",
            "a repeated canonical sequence has its own code"
        );
        let mut other_session = base_event();
        other_session.session_ref = "session-b".to_owned();
        let other_session = other_session.seal().expect("other session event seals");
        tracker
            .admit(&other_session)
            .expect("another session has its own order");
        assert_eq!(
            tracker.last("source-a", "session-b"),
            Some((10, 20)),
            "sessions are tracked independently"
        );
    }

    #[test]
    fn rejected_event_does_not_advance_the_watermark() {
        let mut tracker = SessionSequences::new();
        let first = sample();
        tracker.admit(&first).expect("first event is admitted");

        let mut quarantined = base_event();
        quarantined.capture_sequence = 11;
        quarantined.canonical_sequence = 21;
        quarantined.quality_state = QualityState::Quarantined;
        let quarantined = quarantined.seal().expect("quarantined record seals");
        let error = tracker
            .admit(&quarantined)
            .expect_err("a quarantined record is not admitted");
        assert_eq!(
            error.reason_code(),
            "QUARANTINED_NOT_ADMISSIBLE",
            "quarantine blocks admission"
        );
        assert_eq!(
            tracker.last("source-a", "session-a"),
            Some((10, 20)),
            "a rejected record leaves the watermark untouched"
        );

        let mut next = base_event();
        next.capture_sequence = 11;
        next.canonical_sequence = 21;
        let next = next.seal().expect("the next event seals");
        tracker
            .admit(&next)
            .expect("the rejected record did not consume sequence 11/21");
        assert_eq!(
            tracker.last("source-a", "session-a"),
            Some((11, 21)),
            "the same sequences advance after a clean admission"
        );
    }

    #[test]
    fn two_sources_sharing_a_session_have_independent_histories() {
        let mut tracker = SessionSequences::new();
        let mut source_a = base_event();
        source_a.source_id = "source-a".to_owned();
        let source_a = source_a.seal().expect("source a seals");
        let mut source_b = base_event();
        source_b.source_id = "source-b".to_owned();
        let source_b = source_b.seal().expect("source b seals");
        tracker
            .admit(&source_a)
            .expect("source a starts its history");
        tracker
            .admit(&source_b)
            .expect("source b starts the same history independently");
        assert_eq!(
            tracker.last("source-a", "session-a"),
            Some((10, 20)),
            "source a has its own watermark"
        );
        assert_eq!(
            tracker.last("source-b", "session-a"),
            Some((10, 20)),
            "source b has the same watermark in the same session"
        );
        let mut source_b_next = base_event();
        source_b_next.source_id = "source-b".to_owned();
        source_b_next.capture_sequence = 11;
        source_b_next.canonical_sequence = 21;
        let source_b_next = source_b_next.seal().expect("source b next seals");
        tracker
            .admit(&source_b_next)
            .expect("source b advances without affecting source a");
        assert_eq!(
            tracker.last("source-a", "session-a"),
            Some((10, 20)),
            "source a is unchanged"
        );
    }

    #[test]
    fn provider_sequence_zero_is_rejected_and_null_is_preserved() {
        let mut event = base_event();
        event.provider_sequence = Some(0);
        let error = event
            .validate()
            .expect_err("provider sequence zero is rejected");
        assert_eq!(
            error.reason_code(),
            "INVALID_PROVIDER_SEQUENCE",
            "zero provider sequence has a stable code"
        );
        assert_eq!(
            error.field, "provider_sequence",
            "the offending field is named"
        );
        let event = sample();
        let json = serde_json::to_string(&event).expect("serializable event");
        assert!(
            json.contains("\"provider_sequence\":null"),
            "absence is encoded as null, never as a number"
        );
    }

    #[test]
    fn whitespace_only_required_strings_are_empty() {
        let mut source_id = base_event();
        source_id.source_id = "   ".to_owned();
        let mut product_ref = base_event();
        product_ref.source_product_ref = " \t ".to_owned();
        let mut session_ref = base_event();
        session_ref.session_ref = "\n".to_owned();
        let mut rights_ref = base_event();
        rights_ref.rights_evidence_ref = "   ".to_owned();
        let mut decoder = base_event();
        decoder.quality_state = QualityState::Captured;
        decoder.decoder_version = "   ".to_owned();
        let mut revision = base_event();
        revision.quality_state = QualityState::Captured;
        revision.reference_data_revision = "   ".to_owned();
        let cases = [
            (source_id, "source_id"),
            (product_ref, "source_product_ref"),
            (session_ref, "session_ref"),
            (rights_ref, "rights_evidence_ref"),
            (decoder, "decoder_version"),
            (revision, "reference_data_revision"),
        ];
        for (event, field) in cases {
            let error = event
                .validate()
                .expect_err("a whitespace-only required string is rejected");
            assert_eq!(
                error.reason_code(),
                "EMPTY_REQUIRED_STRING",
                "{field} treats whitespace as empty"
            );
        }
    }

    #[test]
    fn empty_rights_evidence_ref_is_rejected() {
        let mut event = base_event();
        event.rights_evidence_ref = String::new();
        let error = event
            .validate()
            .expect_err("empty rights reference is rejected");
        assert_eq!(
            error.reason_code(),
            "EMPTY_REQUIRED_STRING",
            "empty rights reference has the normative code"
        );
        assert_eq!(
            error.field, "rights_evidence_ref",
            "the empty field is named"
        );
    }

    #[test]
    fn validated_without_reference_revision_is_rejected() {
        let mut event = base_event();
        event.reference_data_revision = String::new();
        let error = event
            .validate()
            .expect_err("VALIDATED needs a reference data revision");
        assert_eq!(
            error.reason_code(),
            "VALIDATED_MISSING_REVISIONS",
            "the VALIDATED-specific code wins"
        );
        let mut event = base_event();
        event.decoder_version = String::new();
        let error = event
            .validate()
            .expect_err("VALIDATED needs a decoder version");
        assert_eq!(
            error.reason_code(),
            "VALIDATED_MISSING_REVISIONS",
            "decoder version is required for VALIDATED"
        );
    }

    #[test]
    fn validated_with_gap_or_unknown_continuity_is_rejected() {
        for continuity in [ContinuityState::GapSuspected, ContinuityState::Unknown] {
            let mut event = base_event();
            event.continuity_state = continuity;
            let error = event
                .validate()
                .expect_err("unresolved continuity is never admitted as VALIDATED");
            assert_eq!(
                error.reason_code(),
                "VALIDATED_CONTINUITY_UNRESOLVED",
                "unresolved continuity has the normative code"
            );
        }
    }

    #[test]
    fn quarantined_event_cannot_be_admitted_downstream() {
        let mut event = base_event();
        event.quality_state = QualityState::Quarantined;
        let event = event.seal().expect("quarantined event is a valid record");
        assert!(
            event.validate().is_ok(),
            "QUARANTINED is a valid quality state"
        );
        let error = event.admission().expect_err("quarantine blocks admission");
        assert_eq!(
            error.reason_code(),
            "QUARANTINED_NOT_ADMISSIBLE",
            "quarantine denial has a stable code"
        );
        let mut tracker = SessionSequences::new();
        let error = tracker
            .admit(&event)
            .expect_err("tracker also blocks quarantine");
        assert_eq!(
            error.reason_code(),
            "QUARANTINED_NOT_ADMISSIBLE",
            "the tracker uses the same admission rule"
        );
        assert_eq!(
            tracker.last("source-a", "session-a"),
            None,
            "no state was changed"
        );
    }
}
