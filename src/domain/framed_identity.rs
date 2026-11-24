// SPDX-License-Identifier: Apache-2.0
//! Versioned, unambiguous derivation of reference-object identities.
//!
//! This module is additive. Legacy identity derivation in
//! [`crate::domain::identity`] stays byte-identical for persisted identifiers.
//! Version 2 hashes a length-framed preimage and binds the object class into
//! that preimage, so no delimiter can move between fields without changing the
//! digest input. No normalization, trimming or case folding is applied to any
//! field.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use sha2::Digest;
use sha2::Sha256;
use thiserror::Error;

/// Domain separator bound into every version-2 preimage.
pub const IDENTITY_V2_DOMAIN: &[u8] = b"FIELDBOOK-REFERENCE-OBJECT-ID-V2";

/// Serialized identity format version carried in every version-2 preimage.
pub const FORMAT_VERSION: u16 = 2;

/// Policy maximum for each UTF-8 field, in bytes.
pub const MAX_FIELD_BYTES: usize = 4096;

/// Maximum length of a legacy prefix accepted by format detection.
const MAX_LEGACY_PREFIX_BYTES: usize = 64;

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Typed failure from version-2 framing, parsing or registration.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdentityV2Error {
    /// A required identity field was empty.
    #[error("empty identity field `{field}`")]
    EmptyField {
        /// Name of the rejected field.
        field: &'static str,
    },
    /// A field exceeded the encoding limit or the policy maximum.
    #[error("identity field `{field}` has {actual} bytes, limit is {limit}")]
    FieldTooLong {
        /// Name of the rejected field.
        field: &'static str,
        /// Declared UTF-8 byte length.
        actual: usize,
        /// Applied limit in bytes.
        limit: usize,
    },
    /// The object-class token did not match the declared token grammar.
    #[error("invalid object-class token `{0}`")]
    InvalidClass(String),
    /// Declared identity text did not match either accepted format.
    #[error("invalid identity text `{0}`")]
    InvalidText(String),
    /// Text resembling a version-2 identity failed structural validation.
    #[error("malformed version-2 identity text `{0}`")]
    MalformedIdentityText(String),
    /// One identity was presented with two different subjects.
    #[error("identity `{id}` already registered for subject `{subject}`")]
    ConflictingRegistration {
        /// Conflicting identity text.
        id: String,
        /// Newly presented subject.
        subject: String,
    },
    /// One subject was presented with two different identities.
    #[error("subject `{subject}` already registered with identity `{id}`")]
    AmbiguousMigration {
        /// Conflicting subject text.
        subject: String,
        /// Newly presented identity text.
        id: String,
    },
}

/// Answer whether a token matches the object-class grammar.
///
/// A class token starts with an ASCII lowercase letter and continues with ASCII
/// lowercase letters, digits or underscores. The declared `ObjectClass` strings
/// satisfy this grammar. No case folding or other normalization is performed.
#[must_use]
pub fn is_valid_class_token(class: &str) -> bool {
    let mut bytes = class.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_field(field: &'static str, value: &str) -> Result<(), IdentityV2Error> {
    if value.is_empty() {
        return Err(IdentityV2Error::EmptyField { field });
    }
    let length = value.len();
    if length > u32::MAX as usize {
        return Err(IdentityV2Error::FieldTooLong {
            field,
            actual: length,
            limit: u32::MAX as usize,
        });
    }
    if length > MAX_FIELD_BYTES {
        return Err(IdentityV2Error::FieldTooLong {
            field,
            actual: length,
            limit: MAX_FIELD_BYTES,
        });
    }
    Ok(())
}

/// Length-framed byte sequence hashed by version-2 identity derivation.
///
/// The encoding is the domain separator, the big-endian `u16` format version,
/// then four fields. Each field contributes a big-endian `u32` UTF-8 byte length
/// followed by its exact UTF-8 bytes. Embedded NUL and unit-separator bytes are
/// ordinary field content because lengths, not delimiters, bound each field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedPreimage {
    bytes: Vec<u8>,
}

impl FramedPreimage {
    /// Validate four fields and frame them with the active format version.
    pub fn new(
        class: &str,
        namespace: &str,
        authority: &str,
        stable_key: &str,
    ) -> Result<Self, IdentityV2Error> {
        Self::with_version(class, namespace, authority, stable_key, FORMAT_VERSION)
    }

    /// Validate four fields and frame them with an explicit format version.
    ///
    /// Explicit versions support framing tests and future version dispatch.
    /// Derivation through [`derive_v2`] uses [`FORMAT_VERSION`].
    pub fn with_version(
        class: &str,
        namespace: &str,
        authority: &str,
        stable_key: &str,
        version: u16,
    ) -> Result<Self, IdentityV2Error> {
        for (name, value) in [
            ("class", class),
            ("namespace", namespace),
            ("authority", authority),
            ("stable_key", stable_key),
        ] {
            validate_field(name, value)?;
        }
        if !is_valid_class_token(class) {
            return Err(IdentityV2Error::InvalidClass(class.to_owned()));
        }
        let mut bytes = Vec::with_capacity(
            IDENTITY_V2_DOMAIN.len()
                + 2
                + 16
                + class.len()
                + namespace.len()
                + authority.len()
                + stable_key.len(),
        );
        bytes.extend_from_slice(IDENTITY_V2_DOMAIN);
        bytes.extend_from_slice(&version.to_be_bytes());
        for value in [class, namespace, authority, stable_key] {
            let length = u32::try_from(value.len()).map_err(|_| IdentityV2Error::FieldTooLong {
                field: "framed_field",
                actual: value.len(),
                limit: u32::MAX as usize,
            })?;
            bytes.extend_from_slice(&length.to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
        Ok(Self { bytes })
    }

    /// Return the exact framed preimage bytes.
    #[must_use]
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A parsed or derived version-2 identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct V2Identity(String);

impl V2Identity {
    /// Return the serialized identity text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return the object-class token embedded in the identity text.
    #[must_use]
    pub fn class_token(&self) -> &str {
        self.0.split_once(':').map_or("", |(token, _)| token)
    }

    /// Consume this identity and return its serialized text.
    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }

    /// Parse identity text with a caller-supplied object-class validator.
    ///
    /// The validator enables strict binding to a declared class set, such as
    /// the strings returned by `ObjectClass::as_str`.
    pub fn parse_with_class_validator(
        text: &str,
        validator: fn(&str) -> bool,
    ) -> Result<Self, IdentityV2Error> {
        let (class, _) = parse_shape(text)?;
        if !validator(class) {
            return Err(IdentityV2Error::InvalidClass(class.to_owned()));
        }
        Ok(Self(text.to_owned()))
    }

    /// Accept already-declared identity text after validating its shape.
    pub fn from_declared(text: String) -> Result<Self, IdentityV2Error> {
        let _ = Self::from_str(&text)?;
        Ok(Self(text))
    }

    fn from_digest(class: &str, digest: &[u8]) -> Self {
        let mut text = String::with_capacity(class.len() + 4 + 64);
        text.push_str(class);
        text.push_str(":v2:");
        for byte in digest {
            text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
        Self(text)
    }
}

impl fmt::Display for V2Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for V2Identity {
    type Err = IdentityV2Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse_with_class_validator(text, is_valid_class_token)
    }
}

fn parse_shape(text: &str) -> Result<(&str, &str), IdentityV2Error> {
    let malformed = || IdentityV2Error::MalformedIdentityText(text.to_owned());
    let (class, rest) = text.split_once(':').ok_or_else(malformed)?;
    let (version, digest) = rest.split_once(':').ok_or_else(malformed)?;
    if version != "v2" || !is_valid_class_token(class) {
        return Err(malformed());
    }
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(malformed());
    }
    Ok((class, digest))
}

/// Derive a version-2 identity from a class and an immutable assertion.
///
/// The full 32-byte SHA-256 digest of the framed preimage is encoded as 64
/// lowercase hexadecimal characters. No field is normalized before hashing.
pub fn derive_v2(
    class: &str,
    namespace: &str,
    authority: &str,
    stable_key: &str,
) -> Result<V2Identity, IdentityV2Error> {
    let preimage = FramedPreimage::new(class, namespace, authority, stable_key)?;
    let digest = Sha256::digest(preimage.to_bytes());
    Ok(V2Identity::from_digest(class, &digest))
}

/// Format family detected in declared identity text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityFormat {
    /// Legacy `<prefix>:<24 lowercase hex>` text.
    Legacy,
    /// Version-2 `<class>:v2:<64 lowercase hex>` text.
    V2,
}

fn has_lowercase_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_legacy_text(text: &str) -> bool {
    let Some((prefix, digest)) = text.split_once(':') else {
        return false;
    };
    !prefix.is_empty()
        && prefix.len() <= MAX_LEGACY_PREFIX_BYTES
        && prefix.chars().all(|character| !character.is_control())
        && has_lowercase_hex(digest, 24)
}

/// Detect whether declared text has legacy or version-2 identity shape.
///
/// V2 requires the exact `<class>:v2:<64 lowercase hex>` shape. Legacy requires
/// the exact `<prefix>:<24 lowercase hex>` shape. Every other text is rejected
/// as `InvalidText`; no format is inferred from a partial match and no silent
/// conversion between formats is performed.
pub fn detect_format(text: &str) -> Result<IdentityFormat, IdentityV2Error> {
    if V2Identity::from_str(text).is_ok() {
        return Ok(IdentityFormat::V2);
    }
    if is_legacy_text(text) {
        return Ok(IdentityFormat::Legacy);
    }
    Err(IdentityV2Error::InvalidText(text.to_owned()))
}

/// Parse declared text as either a legacy or a version-2 identity.
///
/// This is the dual-format ingress entry point. It delegates to
/// [`detect_format`] and shares its fail-closed behavior.
pub fn parse_legacy_or_v2(text: &str) -> Result<IdentityFormat, IdentityV2Error> {
    detect_format(text)
}

/// Fail-closed binding between version-2 identities and subject strings.
///
/// Both directions are indexed. Rebinding an identity to another subject or a
/// subject to another identity is rejected. No implicit migration map is kept.
#[derive(Debug, Clone, Default)]
pub struct IdentityRegistry {
    by_id: BTreeMap<V2Identity, String>,
    by_subject: BTreeMap<String, V2Identity>,
}

impl IdentityRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register one identity for one subject.
    ///
    /// Repeating the same pair is accepted. A different subject for the same
    /// identity yields `ConflictingRegistration`; a different identity for the
    /// same subject yields `AmbiguousMigration`.
    pub fn register(&mut self, id: V2Identity, subject: &str) -> Result<(), IdentityV2Error> {
        let _ = V2Identity::from_str(id.as_str())?;
        if let Some(existing) = self.by_id.get(&id) {
            if existing != subject {
                return Err(IdentityV2Error::ConflictingRegistration {
                    id: id.into_string(),
                    subject: subject.to_owned(),
                });
            }
            return Ok(());
        }
        if self.by_subject.contains_key(subject) {
            return Err(IdentityV2Error::AmbiguousMigration {
                subject: subject.to_owned(),
                id: id.into_string(),
            });
        }
        self.by_subject.insert(subject.to_owned(), id.clone());
        self.by_id.insert(id, subject.to_owned());
        Ok(())
    }

    /// Return the subject registered for an identity.
    #[must_use]
    pub fn subject_for(&self, id: &V2Identity) -> Option<&str> {
        self.by_id.get(id).map(String::as_str)
    }

    /// Return the identity registered for a subject.
    #[must_use]
    pub fn id_for(&self, subject: &str) -> Option<&V2Identity> {
        self.by_subject.get(subject)
    }

    /// Return the number of registered identity and subject pairs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Report whether the registry holds no pairs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

#[cfg(test)]
mod tests {
    //! Deterministic sweeps check framing and parsing on finite input sets.
    //! Distinct digests in a sweep are evidence about those inputs, not a proof
    //! about the collision resistance of SHA-256.

    use super::*;
    use std::collections::BTreeSet;

    fn identity(key: &str) -> V2Identity {
        derive_v2("security", "namespace-a", "authority-a", key).expect("valid v2 identity fixture")
    }

    fn legacy_identity(namespace: &str, authority: &str, key: &str) -> String {
        crate::domain::identity::OpaqueId::derive("inst", namespace, authority, key).to_string()
    }

    #[test]
    fn equal_inputs_derive_equal_identity_and_preimage() {
        let first =
            derive_v2("security", "ns-a", "authority-a", "key-7").expect("first derived identity");
        let second =
            derive_v2("security", "ns-a", "authority-a", "key-7").expect("second derived identity");
        assert_eq!(first, second, "equal tuples derive equal identities");
        let first_preimage = FramedPreimage::new("security", "ns-a", "authority-a", "key-7")
            .expect("first framed preimage");
        let second_preimage = FramedPreimage::new("security", "ns-a", "authority-a", "key-7")
            .expect("second framed preimage");
        assert_eq!(
            first_preimage.to_bytes(),
            second_preimage.to_bytes(),
            "equal tuples derive equal framed bytes"
        );
    }

    #[test]
    fn every_field_and_version_changes_the_preimage() {
        let base =
            FramedPreimage::new("security", "ns-a", "authority-a", "key-7").expect("base preimage");
        let variants = [
            FramedPreimage::new("venue", "ns-a", "authority-a", "key-7").expect("class variant"),
            FramedPreimage::new("security", "ns-b", "authority-a", "key-7")
                .expect("namespace variant"),
            FramedPreimage::new("security", "ns-a", "authority-b", "key-7")
                .expect("authority variant"),
            FramedPreimage::new("security", "ns-a", "authority-a", "key-8")
                .expect("stable-key variant"),
            FramedPreimage::with_version("security", "ns-a", "authority-a", "key-7", 3)
                .expect("version variant"),
        ];
        for (index, variant) in variants.iter().enumerate() {
            assert_ne!(
                base.to_bytes(),
                variant.to_bytes(),
                "field or version variant {index} must change framed bytes"
            );
        }
        let base_id = derive_v2("security", "ns-a", "authority-a", "key-7").expect("base identity");
        let identity_variants = [
            derive_v2("venue", "ns-a", "authority-a", "key-7").expect("class identity variant"),
            derive_v2("security", "ns-b", "authority-a", "key-7")
                .expect("namespace identity variant"),
            derive_v2("security", "ns-a", "authority-b", "key-7")
                .expect("authority identity variant"),
            derive_v2("security", "ns-a", "authority-a", "key-8")
                .expect("stable-key identity variant"),
        ];
        for (index, variant) in identity_variants.iter().enumerate() {
            assert_ne!(
                base_id, *variant,
                "field variant {index} must change the derived identity"
            );
        }
        let version_preimage = FramedPreimage::with_version(
            "security",
            "ns-a",
            "authority-a",
            "key-7",
            FORMAT_VERSION + 1,
        )
        .expect("version identity preimage");
        let version_digest = Sha256::digest(version_preimage.to_bytes());
        let version_text = format!("security:v2:{}", hex_encode(&version_digest));
        assert_eq!(
            detect_format(&version_text),
            Ok(IdentityFormat::V2),
            "alternate-version digest retains the v2 serialization"
        );
        assert_ne!(
            base_id.as_str(),
            version_text,
            "format version must participate in hashing"
        );
    }

    #[test]
    fn framed_preimage_matches_declared_byte_layout() {
        let preimage = FramedPreimage::new("security", "ns-a", "authority-a", "key-7")
            .expect("declared preimage");
        let expected = "4649454c44424f4f4b2d5245464552454e43452d4f424a4543542d49442d56320002\
                        000000087365637572697479000000046e732d610000000b617574686f726974792d\
                        61000000056b65792d37";
        assert_eq!(
            preimage.to_bytes(),
            &hex_decode(expected),
            "framed bytes must match the declared layout"
        );
        assert_eq!(
            derive_v2("security", "ns-a", "authority-a", "key-7")
                .expect("declared identity")
                .as_str(),
            "security:v2:2424fb648667feb277dcec44d93e75c6556def849b1bf2a5c3ee550dd5776cc7",
            "digest and serialization must match the declared vector"
        );
    }

    #[test]
    fn adversarial_delimiter_tuples_do_not_collide() {
        let first = derive_v2("security", "a\u{1f}b", "c", "d").expect("first delimiter tuple");
        let second = derive_v2("security", "a", "b", "c\u{1f}d").expect("second delimiter tuple");
        assert_ne!(
            first, second,
            "delimiter tuples must derive distinct identities"
        );
        assert_eq!(
            legacy_identity("a\u{1f}b", "c", "d"),
            legacy_identity("a", "b", "c\u{1f}d"),
            "legacy concatenation collides on the adversarial tuples"
        );
    }

    #[test]
    fn embedded_control_bytes_remain_ordinary_field_content() {
        let base = derive_v2("security", "ab", "c", "d").expect("plain tuple");
        let nul = derive_v2("security", "a\0b", "c", "d").expect("NUL tuple");
        let separator = derive_v2("security", "a\u{1f}b", "c", "d").expect("separator tuple");
        assert_ne!(base, nul, "embedded NUL must change the identity");
        assert_ne!(
            base, separator,
            "embedded unit separator must change the identity"
        );
        assert_ne!(
            nul, separator,
            "distinct control bytes must remain distinct"
        );
    }

    #[test]
    fn empty_fields_are_rejected() {
        let cases = [
            ("", "namespace-a", "authority-a", "key-a", "class"),
            ("security", "", "authority-a", "key-a", "namespace"),
            ("security", "namespace-a", "", "key-a", "authority"),
            ("security", "namespace-a", "authority-a", "", "stable_key"),
        ];
        for (class, namespace, authority, key, field) in cases {
            assert_eq!(
                derive_v2(class, namespace, authority, key),
                Err(IdentityV2Error::EmptyField { field }),
                "empty {field} must be rejected"
            );
        }
    }

    #[test]
    fn overlength_fields_are_rejected_and_policy_boundary_is_accepted() {
        let overlength = "x".repeat(MAX_FIELD_BYTES + 1);
        assert_eq!(
            derive_v2("security", &overlength, "authority-a", "key-a"),
            Err(IdentityV2Error::FieldTooLong {
                field: "namespace",
                actual: MAX_FIELD_BYTES + 1,
                limit: MAX_FIELD_BYTES,
            }),
            "an overlength namespace must be rejected"
        );
        let boundary = "x".repeat(MAX_FIELD_BYTES);
        assert!(
            derive_v2("security", &boundary, "authority-a", "key-a").is_ok(),
            "the declared policy boundary must be accepted"
        );
    }

    #[test]
    fn invalid_class_tokens_are_rejected() {
        for class in ["Security", "1security", "sec-urity", "sec urity"] {
            assert_eq!(
                derive_v2(class, "namespace-a", "authority-a", "key-a"),
                Err(IdentityV2Error::InvalidClass(class.to_owned())),
                "class token `{class}` must be rejected"
            );
        }
    }

    #[test]
    fn unicode_normalization_forms_derive_distinct_identities() {
        let nfc = derive_v2("security", "namespace-\u{e9}", "authority-a", "key-a")
            .expect("NFC namespace");
        let nfd = derive_v2("security", "namespace-e\u{301}", "authority-a", "key-a")
            .expect("NFD namespace");
        assert_ne!(
            nfc, nfd,
            "distinct UTF-8 byte sequences must remain distinct"
        );
    }

    #[test]
    fn serialized_identity_parsing_is_strict() {
        let valid = identity("key-a");
        let parsed = valid
            .as_str()
            .parse::<V2Identity>()
            .expect("valid identity");
        assert_eq!(parsed, valid, "valid text must round-trip");
        assert_eq!(
            parsed.class_token(),
            "security",
            "class token must be exposed"
        );
        for invalid in [
            "security:v3:2424fb648667feb277dcec44d93e75c6556def849b1bf2a5c3ee550dd5776cc7",
            "security:v2:2424FB648667FEB277DCEC44D93E75C6556DEF849B1BF2A5C3EE550DD5776CC7",
            "security:v2:2424fb648667feb277dcec44d93e75c6556def849b1bf2a5c3ee550dd5776cc",
            "security:v2:2424fb648667feb277dcec44d93e75c6556def849b1bf2a5c3ee550dd5776cc7f",
            "security:2424fb648667feb277dcec44d93e75c6556def849b1bf2a5c3ee550dd5776cc7",
            "security:v2:2424fb648667feb277dcec44d93e75c6556def849b1bf2a5c3ee550dd5776cg7",
            "",
        ] {
            assert!(
                invalid.parse::<V2Identity>().is_err(),
                "malformed text `{invalid}` must be rejected"
            );
        }
        assert!(
            V2Identity::from_declared("not-an-identity".to_owned()).is_err(),
            "declared text must be validated"
        );
    }

    #[test]
    fn class_validator_can_be_injected() {
        let valid = identity("key-a");
        let accepted =
            V2Identity::parse_with_class_validator(valid.as_str(), |token| token == "security")
                .expect("declared class validator accepts the token");
        assert_eq!(accepted, valid, "accepted identity must round-trip");
        assert!(
            V2Identity::parse_with_class_validator(valid.as_str(), |token| token == "venue")
                .is_err(),
            "unknown declared class must be rejected"
        );
    }

    #[test]
    fn legacy_and_v2_text_are_detected_distinctly() {
        let v2 = identity("key-a").into_string();
        let legacy = legacy_identity("namespace-a", "authority-a", "key-a");
        assert_eq!(
            detect_format(&v2),
            Ok(IdentityFormat::V2),
            "v2 text must be detected as v2"
        );
        assert_eq!(
            detect_format(&legacy),
            Ok(IdentityFormat::Legacy),
            "legacy text must be detected as legacy"
        );
        assert_eq!(
            parse_legacy_or_v2(&v2),
            detect_format(&v2),
            "dual-format parser must agree with detection for v2"
        );
        assert_eq!(
            parse_legacy_or_v2(&legacy),
            detect_format(&legacy),
            "dual-format parser must agree with detection for legacy"
        );
        for invalid in ["", "inst:xyz", "security:v2:abc", "a:b:c:d"] {
            assert_eq!(
                detect_format(invalid),
                Err(IdentityV2Error::InvalidText(invalid.to_owned())),
                "unrecognized text `{invalid}` must be rejected"
            );
        }
    }

    #[test]
    fn deterministic_tuple_sweep_has_distinct_preimages_and_identities() {
        let classes = ["security", "venue", "feed", "listing"];
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut preimages = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for index in 0..256_usize {
            let namespace = swept_text(&mut state, index, 1);
            let authority = swept_text(&mut state, index, 2);
            let key = format!("key-{index}-{}", swept_text(&mut state, index, 3));
            let class = classes[index % classes.len()];
            let preimage =
                FramedPreimage::new(class, &namespace, &authority, &key).expect("sweep preimage");
            let derived = derive_v2(class, &namespace, &authority, &key).expect("sweep identity");
            assert!(
                preimages.insert(preimage.to_bytes().to_vec()),
                "tuple {index} must have a distinct framed preimage"
            );
            assert!(
                identities.insert(derived),
                "tuple {index} must have a distinct identity"
            );
        }
        assert_eq!(preimages.len(), 256, "sweep must frame 256 tuples");
        assert_eq!(identities.len(), 256, "sweep must derive 256 identities");
    }

    #[test]
    fn deterministic_mutation_sweep_rejects_or_distinguishes_text() {
        let original = identity("key-a").into_string();
        let bytes = original.as_bytes();
        let mut examined = 0_usize;
        let mut accepted = BTreeSet::new();
        for position in 0..bytes.len() {
            for mask in [1_u8, 0x7f] {
                let mut mutated = bytes.to_vec();
                mutated[position] ^= mask;
                let Ok(text) = std::str::from_utf8(&mutated) else {
                    continue;
                };
                examined += 1;
                if let Ok(parsed) = text.parse::<V2Identity>() {
                    assert_ne!(
                        parsed.as_str(),
                        original,
                        "mutation must not reproduce text"
                    );
                    assert!(
                        accepted.insert(parsed.as_str().to_owned()),
                        "accepted mutation must be distinct"
                    );
                }
            }
        }
        let mut variants = vec![
            original.replacen(":v2:", ":v3:", 1),
            original.replacen(":v2:", ":V2:", 1),
            original.replacen('a', "A", 1),
            original[..original.len() - 1].to_owned(),
            format!("{original}0"),
        ];
        variants.push(format!("{original}:extra"));
        for variant in variants.drain(..) {
            examined += 1;
            assert!(
                variant.parse::<V2Identity>().is_err(),
                "structural mutation `{variant}` must be rejected"
            );
        }
        assert!(examined > 100, "sweep must exercise multiple mutations");
    }

    #[test]
    fn registry_rejects_both_conflict_directions() {
        let first = identity("key-a");
        let second = identity("key-b");
        let mut registry = IdentityRegistry::new();
        assert!(registry.is_empty(), "new registry has no pairs");
        registry
            .register(first.clone(), "subject-a")
            .expect("first registration");
        registry
            .register(first.clone(), "subject-a")
            .expect("idempotent registration");
        assert_eq!(registry.len(), 1, "idempotent registration adds no pair");
        assert_eq!(
            registry.subject_for(&first),
            Some("subject-a"),
            "subject lookup must return the declared subject"
        );
        assert_eq!(
            registry.id_for("subject-a"),
            Some(&first),
            "identity lookup must return the declared identity"
        );
        assert_eq!(
            registry.register(first.clone(), "subject-b"),
            Err(IdentityV2Error::ConflictingRegistration {
                id: first.to_string(),
                subject: "subject-b".to_owned(),
            }),
            "one identity with two subjects must be rejected"
        );
        assert_eq!(
            registry.register(second.clone(), "subject-a"),
            Err(IdentityV2Error::AmbiguousMigration {
                subject: "subject-a".to_owned(),
                id: second.to_string(),
            }),
            "one subject with two identities must be rejected"
        );
    }

    #[test]
    fn legacy_derive_vector_is_unchanged() {
        assert_eq!(
            legacy_identity("ns", "authority", "key"),
            "inst:8864c214ac0e8fd283cc8c99",
            "legacy concatenation and truncation must stay byte-identical"
        );
    }

    fn swept_text(state: &mut u64, index: usize, salt: u64) -> String {
        const CHARS: &[char] = &['a', 'b', 'z', '_', '-', '\0', '\u{1f}', '\u{e9}', '\u{301}'];
        let mut value = *state ^ (index as u64).wrapping_mul(salt);
        let mut text = String::from("f");
        for _ in 0..(1 + index % 4) {
            value = value
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let chosen = (value >> 33) as usize % CHARS.len();
            text.push(CHARS[chosen]);
        }
        *state = value;
        text
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut text = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
        text
    }

    fn hex_decode(text: &str) -> Vec<u8> {
        let bytes = text.as_bytes();
        let mut output = Vec::with_capacity(bytes.len() / 2);
        for pair in bytes.as_chunks::<2>().0 {
            let high = hex_value(pair[0]).expect("high hex digit");
            let low = hex_value(pair[1]).expect("low hex digit");
            output.push((high << 4) | low);
        }
        output
    }

    fn hex_value(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
}
