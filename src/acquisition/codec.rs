// SPDX-License-Identifier: Apache-2.0
//! Acquisition feed decoding primitives.
//!
//! A [`CodecRegistry`] maps a `(source, schema_version)` pair to a boxed
//! [`FeedCodec`] and partitions decoded observations by outcome. Decoding is
//! fail-closed: a packet without a registered codec produces an error rather
//! than a partial batch.

use std::collections::BTreeMap;

use anyhow::Context as _;
use serde::{
    Deserialize, //
    Serialize,   //
};
use sha2::{
    Digest, //
    Sha256, //
};

use crate::{
    event_model::{DomainPayload, OrderAction},
    util::sha256_hex,
};

/// Decode outcome attached to one observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecodeStatus {
    /// Payload produced a structured observation.
    Decoded,
    /// Payload was recognized and produced no observation.
    Ignored,
    /// Payload failed validation and was refused.
    Rejected,
    /// Payload uses a schema version outside the codec support range.
    Unsupported,
}

impl DecodeStatus {
    /// Stable lowercase label for the status.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Decoded => "decoded",
            Self::Ignored => "ignored",
            Self::Rejected => "rejected",
            Self::Unsupported => "unsupported",
        }
    }
}

/// One structured observation emitted by a feed codec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecodedObservation {
    /// Identifier of the packet that carried the observation.
    pub packet_id: String,
    /// Source feed that produced the packet.
    pub source: String,
    /// Schema version of the codec that decoded the packet.
    pub schema_version: u32,
    /// Observation kind, such as `trade` or `book`.
    pub kind: String,
    /// Observation body encoded as JSON text.
    pub payload_json: String,
    /// Decode outcome attached to the observation.
    pub status: DecodeStatus,
    /// Reason text for a status other than [`DecodeStatus::Decoded`].
    pub reason: Option<String>,
}

impl DecodedObservation {
    /// Compute a `Sha256` digest over the stable fields of the observation.
    ///
    /// Field boundaries carry a unit separator so distinct field splits
    /// cannot produce the same digest.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.packet_id.as_bytes());
        hasher.update([0x1f]);
        hasher.update(self.source.as_bytes());
        hasher.update([0x1f]);
        hasher.update(self.schema_version.to_le_bytes());
        hasher.update([0x1f]);
        hasher.update(self.kind.as_bytes());
        hasher.update([0x1f]);
        hasher.update(self.payload_json.as_bytes());
        hasher.update([0x1f]);
        hasher.update(self.status.as_str().as_bytes());
        hasher.update([0x1f]);
        match &self.reason {
            Some(reason) => hasher.update(reason.as_bytes()),
            None => hasher.update([0x00]),
        }
        let digest = hasher.finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        bytes
    }
}

/// Original bytes retained independently of the typed domain record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEvidence {
    /// Exact original payload bytes.
    pub bytes: Vec<u8>,
    /// SHA-256 of `bytes`, for independent verification.
    pub sha256: String,
}

/// Typed domain output produced at the normalization boundary.
///
/// `payload_json` remains an interchange representation. Internal consumers
/// should use this typed form; raw evidence is never replaced by it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedPayload {
    /// Stable payload type, matching [`DomainPayload::payload_type`].
    pub payload_type: String,
    /// Typed domain meaning.
    pub payload: DomainPayload,
}

/// One normalized event with independently retained raw evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedEvent {
    /// Identifier of the packet that carried the event.
    pub packet_id: String,
    /// Source that produced the packet.
    pub source: String,
    /// Schema version of the codec that decoded the packet.
    pub schema_version: u32,
    /// Observation kind reported by the codec.
    pub kind: String,
    /// Typed domain payload, absent for rejected or unsupported observations.
    pub payload: Option<TypedPayload>,
    /// Original payload bytes and their digest.
    pub raw: RawEvidence,
    /// Decode outcome attached to the event.
    pub status: DecodeStatus,
    /// Reason text for a status other than [`DecodeStatus::Decoded`].
    pub reason: Option<String>,
}

/// Failure to produce a typed domain payload from a decoded observation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NormalizationError {
    /// The observation kind has no typed normalizer.
    #[error("observation kind `{kind}` has no typed normalizer")]
    UnknownKind {
        /// Kind that could not be normalized.
        kind: String,
    },
    /// A required field was absent from the payload object.
    #[error("payload field `{field}` is missing")]
    MissingField {
        /// Field that was absent.
        field: String,
    },
    /// The payload body was not a valid object for its declared kind.
    #[error("invalid `{kind}` payload: {reason}")]
    InvalidPayload {
        /// Kind whose payload was invalid.
        kind: String,
        /// Description of the validation failure.
        reason: String,
    },
}

fn payload_object(
    observation: &DecodedObservation,
) -> Result<serde_json::Map<String, serde_json::Value>, NormalizationError> {
    let value: serde_json::Value =
        serde_json::from_str(&observation.payload_json).map_err(|error| {
            NormalizationError::InvalidPayload {
                kind: observation.kind.clone(),
                reason: error.to_string(),
            }
        })?;
    match value {
        serde_json::Value::Object(map) => Ok(map),
        _ => Err(NormalizationError::InvalidPayload {
            kind: observation.kind.clone(),
            reason: "payload is not a JSON object".to_owned(),
        }),
    }
}

fn text_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, NormalizationError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| NormalizationError::MissingField {
            field: key.to_owned(),
        })
}

fn i64_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<i64, NormalizationError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| NormalizationError::MissingField {
            field: key.to_owned(),
        })
}

fn u64_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, NormalizationError> {
    object
        .get(key)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| NormalizationError::MissingField {
            field: key.to_owned(),
        })
}

fn u32_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u32, NormalizationError> {
    u32::try_from(u64_field(object, key)?).map_err(|_| NormalizationError::InvalidPayload {
        kind: key.to_owned(),
        reason: "value exceeds u32".to_owned(),
    })
}

fn u8_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u8, NormalizationError> {
    u8::try_from(u64_field(object, key)?).map_err(|_| NormalizationError::InvalidPayload {
        kind: key.to_owned(),
        reason: "value exceeds u8".to_owned(),
    })
}

fn optional_text_field(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn typed_payload(observation: &DecodedObservation) -> Result<TypedPayload, NormalizationError> {
    let object = payload_object(observation)?;
    let payload = match observation.kind.as_str() {
        "trade" => DomainPayload::Trade {
            trade_id: text_field(&object, "trade_id")?,
            price_mantissa: i64_field(&object, "price_mantissa")?,
            quantity_mantissa: i64_field(&object, "quantity_mantissa")?,
        },
        "book" | "equity_quote" => DomainPayload::EquityQuote {
            bid_mantissa: i64_field(&object, "bid_mantissa")?,
            ask_mantissa: i64_field(&object, "ask_mantissa")?,
            bid_quantity: i64_field(&object, "bid_quantity")?,
            ask_quantity: i64_field(&object, "ask_quantity")?,
            price_scale: u8_field(&object, "price_scale")?,
            quantity_scale: u8_field(&object, "quantity_scale")?,
        },
        "economic_observation" => DomainPayload::EconomicObservation {
            release_id: text_field(&object, "release_id")?,
            value_mantissa: i64_field(&object, "value_mantissa")?,
            revision: u32_field(&object, "revision")?,
        },
        "order_event" => {
            let action = match text_field(&object, "action")?.as_str() {
                "add" => OrderAction::Add,
                "modify" => OrderAction::Modify,
                "cancel" => OrderAction::Cancel,
                "execute" => OrderAction::Execute,
                other => {
                    return Err(NormalizationError::InvalidPayload {
                        kind: observation.kind.clone(),
                        reason: format!("unknown order action `{other}`"),
                    });
                }
            };
            DomainPayload::OrderEvent {
                order_id: text_field(&object, "order_id")?,
                action,
                side: text_field(&object, "side")?,
                price_mantissa: i64_field(&object, "price_mantissa")?,
                quantity_mantissa: i64_field(&object, "quantity_mantissa")?,
            }
        }
        "document" | "news_event" => DomainPayload::NewsEvent {
            document_sha256: text_field(&object, "document_sha256")?,
            published_us: i64_field(&object, "published_us")?,
        },
        "blockchain_event" => DomainPayload::BlockchainEvent {
            chain: text_field(&object, "chain")?,
            block_number: u64_field(&object, "block_number")?,
            transaction_hash: optional_text_field(&object, "transaction_hash"),
        },
        other => {
            return Err(NormalizationError::UnknownKind {
                kind: other.to_owned(),
            });
        }
    };
    Ok(TypedPayload {
        payload_type: payload.payload_type().to_owned(),
        payload,
    })
}

impl DecodedObservation {
    /// Convert one decoded observation into a typed domain record, retaining
    /// the original payload bytes as independent evidence.
    ///
    /// # Errors
    /// Returns an error when the kind has no normalizer or the JSON body does
    /// not carry the required typed fields. Unknown kinds fail closed.
    pub fn try_normalize(&self, raw: &[u8]) -> Result<NormalizedEvent, NormalizationError> {
        Ok(NormalizedEvent {
            packet_id: self.packet_id.clone(),
            source: self.source.clone(),
            schema_version: self.schema_version,
            kind: self.kind.clone(),
            payload: Some(typed_payload(self)?),
            raw: RawEvidence {
                bytes: raw.to_vec(),
                sha256: sha256_hex(raw),
            },
            status: self.status,
            reason: self.reason.clone(),
        })
    }
}

/// Schema-versioned decoder for one feed source.
pub trait FeedCodec: Send + Sync {
    /// Decode a raw payload into observations.
    ///
    /// # Errors
    /// Returns an error when the payload is malformed beyond per-observation
    /// rejection.
    fn decode(&self, payload: &[u8]) -> anyhow::Result<Vec<DecodedObservation>>;

    /// Schema version understood by the codec.
    fn schema_version(&self) -> u32;
}

/// Observations partitioned by decode outcome.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DecodeBatch {
    /// Observations carrying [`DecodeStatus::Decoded`] or [`DecodeStatus::Ignored`].
    pub accepted: Vec<DecodedObservation>,
    /// Observations carrying [`DecodeStatus::Rejected`].
    pub rejected: Vec<DecodedObservation>,
    /// Observations carrying [`DecodeStatus::Unsupported`].
    pub unsupported: Vec<DecodedObservation>,
}

/// Failure to install a codec into the registry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecRegistrationError {
    /// A codec is already registered for the same source and schema version.
    #[error("codec already registered for source `{source_id}` schema version {version}")]
    Conflict {
        /// Source that was already registered.
        source_id: String,
        /// Schema version that was already registered.
        version: u32,
    },
}

/// Registry of boxed codecs keyed by source and schema version.
#[derive(Default)]
pub struct CodecRegistry {
    codecs: BTreeMap<(String, u32), Box<dyn FeedCodec>>,
}

impl CodecRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a codec under its source and reported schema version.
    ///
    /// A conflicting registration is refused instead of silently replacing a
    /// previously installed decoder. Identical re-registration is idempotent
    /// in effect but is still reported so callers can audit duplicate setup.
    ///
    /// # Errors
    /// Returns an error when the same source and schema version is already
    /// registered. The original codec remains installed.
    pub fn register(
        &mut self,
        source: &str,
        codec: Box<dyn FeedCodec>,
    ) -> Result<(), CodecRegistrationError> {
        let key = (source.to_owned(), codec.schema_version());
        if self.codecs.contains_key(&key) {
            return Err(CodecRegistrationError::Conflict {
                source_id: source.to_owned(),
                version: key.1,
            });
        }
        self.codecs.insert(key, codec);
        Ok(())
    }

    /// Resolve the codec registered for a source and schema version.
    #[must_use]
    pub fn resolve(&self, source: &str, schema_version: u32) -> Option<&dyn FeedCodec> {
        self.codecs
            .get(&(source.to_owned(), schema_version))
            .map(Box::as_ref)
    }

    /// Decode one packet with the codec registered for its envelope.
    ///
    /// Packet id, source and schema version are stamped onto every
    /// observation returned by the codec. A missing codec fails closed.
    ///
    /// # Errors
    /// Returns an error when no codec is registered or the codec fails.
    pub fn decode(
        &self,
        packet_id: &str,
        source: &str,
        schema_version: u32,
        payload: &[u8],
    ) -> anyhow::Result<DecodeBatch> {
        let codec = self.resolve(source, schema_version).with_context(|| {
            format!("no codec registered for source `{source}` schema version {schema_version}")
        })?;
        let mut observations = codec.decode(payload).with_context(|| {
            format!("decoding packet `{packet_id}` from source `{source}` schema {schema_version}")
        })?;
        for observation in &mut observations {
            observation.packet_id = packet_id.to_owned();
            observation.source = source.to_owned();
            observation.schema_version = schema_version;
        }
        let mut batch = DecodeBatch::default();
        for observation in observations {
            match observation.status {
                DecodeStatus::Decoded | DecodeStatus::Ignored => batch.accepted.push(observation),
                DecodeStatus::Rejected => batch.rejected.push(observation),
                DecodeStatus::Unsupported => batch.unsupported.push(observation),
            }
        }
        Ok(batch)
    }

    /// Decode and normalize one packet into typed domain events.
    ///
    /// Raw bytes are retained on every returned event, including rejected and
    /// unsupported observations. A decoded observation whose kind has no typed
    /// normalizer fails the whole batch rather than being silently downgraded.
    ///
    /// # Errors
    /// Returns an error when no codec is registered, decoding fails, or typed
    /// normalization fails for a decoded observation.
    pub fn decode_normalized(
        &self,
        packet_id: &str,
        source: &str,
        schema_version: u32,
        raw_payload: &[u8],
    ) -> anyhow::Result<Vec<NormalizedEvent>> {
        let batch = self.decode(packet_id, source, schema_version, raw_payload)?;
        let mut events = Vec::with_capacity(
            batch.accepted.len() + batch.rejected.len() + batch.unsupported.len(),
        );
        for observation in batch
            .accepted
            .into_iter()
            .chain(batch.rejected)
            .chain(batch.unsupported)
        {
            let decoded = observation.status == DecodeStatus::Decoded;
            let payload = if decoded {
                Some(
                    typed_payload(&observation)
                        .with_context(|| format!("normalizing packet `{packet_id}`"))?,
                )
            } else {
                None
            };
            events.push(NormalizedEvent {
                packet_id: observation.packet_id,
                source: observation.source,
                schema_version: observation.schema_version,
                kind: observation.kind,
                payload,
                raw: RawEvidence {
                    bytes: raw_payload.to_vec(),
                    sha256: sha256_hex(raw_payload),
                },
                status: observation.status,
                reason: observation.reason,
            });
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::CodecRegistry;
    use super::DecodeBatch;
    use super::DecodeStatus;
    use super::DecodedObservation;
    use super::DomainPayload;
    use super::FeedCodec;
    use super::sha256_hex;

    struct LengthPrefixedCodec {
        version: u32,
    }

    impl FeedCodec for LengthPrefixedCodec {
        fn decode(&self, payload: &[u8]) -> anyhow::Result<Vec<DecodedObservation>> {
            let (kind_len, rest) = payload
                .split_first()
                .ok_or_else(|| anyhow::anyhow!("empty payload"))?;
            let kind_len = usize::from(*kind_len);
            if rest.len() < kind_len {
                anyhow::bail!("truncated kind field");
            }
            let (kind, body) = rest.split_at(kind_len);
            Ok(vec![DecodedObservation {
                packet_id: String::new(),
                source: String::new(),
                schema_version: 0,
                kind: String::from_utf8(kind.to_vec())?,
                payload_json: String::from_utf8(body.to_vec())?,
                status: DecodeStatus::Decoded,
                reason: None,
            }])
        }

        fn schema_version(&self) -> u32 {
            self.version
        }
    }

    struct FixedStatusCodec {
        version: u32,
        status: DecodeStatus,
    }

    impl FeedCodec for FixedStatusCodec {
        fn decode(&self, _payload: &[u8]) -> anyhow::Result<Vec<DecodedObservation>> {
            Ok(vec![DecodedObservation {
                packet_id: String::new(),
                source: String::new(),
                schema_version: 0,
                kind: "status".to_owned(),
                payload_json: "{}".to_owned(),
                status: self.status,
                reason: None,
            }])
        }

        fn schema_version(&self) -> u32 {
            self.version
        }
    }

    fn encoded(kind: &str, body: &str) -> Vec<u8> {
        let mut payload = vec![u8::try_from(kind.len()).unwrap_or(u8::MAX)];
        payload.extend_from_slice(kind.as_bytes());
        payload.extend_from_slice(body.as_bytes());
        payload
    }

    #[test]
    fn length_prefixed_decode_stamps_envelope() {
        let mut registry = CodecRegistry::new();
        registry
            .register("venue-a", Box::new(LengthPrefixedCodec { version: 3 }))
            .expect("register codec");
        let payload = encoded("trade", "{\"price\":10}");
        let batch: DecodeBatch = registry
            .decode("packet-7", "venue-a", 3, &payload)
            .expect("registered codec decodes payload");
        assert_eq!(batch.accepted.len(), 1, "one accepted observation");
        let observation = &batch.accepted[0];
        assert_eq!(observation.packet_id, "packet-7", "packet id stamped");
        assert_eq!(observation.source, "venue-a", "source stamped");
        assert_eq!(observation.schema_version, 3, "schema version stamped");
        assert_eq!(observation.kind, "trade", "kind from length prefix");
        assert_eq!(
            observation.payload_json, "{\"price\":10}",
            "body from remainder"
        );
        assert_eq!(
            observation.status,
            DecodeStatus::Decoded,
            "decoded status kept"
        );
        assert!(batch.rejected.is_empty(), "no rejected observations");
        assert!(batch.unsupported.is_empty(), "no unsupported observations");
    }

    #[test]
    fn missing_codec_fails_closed() {
        let registry = CodecRegistry::new();
        let result = registry.decode("packet-1", "venue-x", 1, b"payload");
        assert!(result.is_err(), "unregistered source returns an error");
        let message = format!("{:#}", result.expect_err("error present"));
        assert!(
            message.contains("no codec registered"),
            "error names missing codec: {message}"
        );
    }

    #[test]
    fn decode_partitions_by_status() {
        let mut registry = CodecRegistry::new();
        registry
            .register(
                "reject-venue",
                Box::new(FixedStatusCodec {
                    version: 1,
                    status: DecodeStatus::Rejected,
                }),
            )
            .expect("register reject codec");
        registry
            .register(
                "unsupported-venue",
                Box::new(FixedStatusCodec {
                    version: 2,
                    status: DecodeStatus::Unsupported,
                }),
            )
            .expect("register unsupported codec");
        registry
            .register(
                "ignored-venue",
                Box::new(FixedStatusCodec {
                    version: 3,
                    status: DecodeStatus::Ignored,
                }),
            )
            .expect("register ignored codec");
        let rejected = registry
            .decode("p1", "reject-venue", 1, b"x")
            .expect("reject codec registered");
        assert_eq!(rejected.rejected.len(), 1, "rejected observation bucketed");
        assert!(rejected.accepted.is_empty(), "no accepted observations");
        let unsupported = registry
            .decode("p2", "unsupported-venue", 2, b"x")
            .expect("unsupported codec registered");
        assert_eq!(
            unsupported.unsupported.len(),
            1,
            "unsupported observation bucketed"
        );
        let ignored = registry
            .decode("p3", "ignored-venue", 3, b"x")
            .expect("ignored codec registered");
        assert_eq!(ignored.accepted.len(), 1, "ignored observation accepted");
    }

    #[test]
    fn digest_is_stable_and_field_sensitive() {
        let observation = DecodedObservation {
            packet_id: "packet-9".to_owned(),
            source: "venue-a".to_owned(),
            schema_version: 2,
            kind: "trade".to_owned(),
            payload_json: "{\"qty\":3}".to_owned(),
            status: DecodeStatus::Decoded,
            reason: None,
        };
        let copy = observation.clone();
        assert_eq!(
            observation.digest(),
            copy.digest(),
            "identical observations share a digest"
        );
        let mut changed_body = observation.clone();
        changed_body.payload_json.push(' ');
        assert_ne!(
            observation.digest(),
            changed_body.digest(),
            "digest changes with payload body"
        );
        let mut changed_source = observation.clone();
        changed_source.source = "venue-b".to_owned();
        assert_ne!(
            observation.digest(),
            changed_source.digest(),
            "digest changes with source"
        );
    }

    #[test]
    fn status_labels_are_stable() {
        assert_eq!(DecodeStatus::Decoded.as_str(), "decoded", "decoded label");
        assert_eq!(DecodeStatus::Ignored.as_str(), "ignored", "ignored label");
        assert_eq!(
            DecodeStatus::Rejected.as_str(),
            "rejected",
            "rejected label"
        );
        assert_eq!(
            DecodeStatus::Unsupported.as_str(),
            "unsupported",
            "unsupported label"
        );
    }

    #[test]
    fn conflicting_codec_registration_is_refused() {
        let mut registry = CodecRegistry::new();
        registry
            .register("venue-a", Box::new(LengthPrefixedCodec { version: 3 }))
            .expect("first registration");
        let result = registry.register("venue-a", Box::new(LengthPrefixedCodec { version: 3 }));
        assert!(
            result.is_err(),
            "second registration for the same key must fail"
        );
        let batch = registry
            .decode("p1", "venue-a", 3, &encoded("trade", "{}"))
            .expect("original codec remains installed");
        assert_eq!(batch.accepted.len(), 1, "original codec still decodes");
    }

    #[test]
    fn typed_normalization_keeps_raw_evidence() {
        let mut registry = CodecRegistry::new();
        registry
            .register("venue-a", Box::new(LengthPrefixedCodec { version: 3 }))
            .expect("register codec");
        let payload = encoded(
            "trade",
            "{\"trade_id\":\"t-1\",\"price_mantissa\":10,\"quantity_mantissa\":2}",
        );
        let events = registry
            .decode_normalized("packet-7", "venue-a", 3, &payload)
            .expect("typed decode succeeds");
        assert_eq!(events.len(), 1, "one normalized event");
        let event = &events[0];
        assert_eq!(event.raw.bytes, payload, "original bytes retained");
        assert_eq!(event.raw.sha256, sha256_hex(&payload), "digest retained");
        let typed = event.payload.as_ref().expect("typed payload present");
        assert_eq!(typed.payload_type, "trade", "payload type is stable");
        assert_eq!(
            typed.payload,
            DomainPayload::Trade {
                trade_id: "t-1".to_owned(),
                price_mantissa: 10,
                quantity_mantissa: 2,
            },
            "typed domain payload is produced"
        );
    }

    #[test]
    fn unknown_kind_fails_closed() {
        let observation = DecodedObservation {
            packet_id: "p".to_owned(),
            source: "venue".to_owned(),
            schema_version: 1,
            kind: "mystery".to_owned(),
            payload_json: "{}".to_owned(),
            status: DecodeStatus::Decoded,
            reason: None,
        };
        assert!(
            observation.try_normalize(b"raw").is_err(),
            "unknown kind must not be downgraded"
        );
    }

    #[test]
    fn rejected_observations_keep_raw_evidence_without_typed_payload() {
        let mut registry = CodecRegistry::new();
        registry
            .register(
                "reject-venue",
                Box::new(FixedStatusCodec {
                    version: 1,
                    status: DecodeStatus::Rejected,
                }),
            )
            .expect("register codec");
        let events = registry
            .decode_normalized("p1", "reject-venue", 1, b"raw-bytes")
            .expect("rejected observation still yields evidence");
        assert_eq!(events.len(), 1, "rejected event retained");
        assert_eq!(events[0].status, DecodeStatus::Rejected, "status preserved");
        assert!(
            events[0].payload.is_none(),
            "no typed payload for rejection"
        );
        assert_eq!(events[0].raw.bytes, b"raw-bytes", "raw bytes preserved");
    }
}
