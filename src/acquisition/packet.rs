// SPDX-License-Identifier: Apache-2.0
//! Raw packet evidence and its mapping into the existing journal contract.
//!
//! Original payload bytes and packet boundaries are preserved before decode.
//! Journal integration uses an explicit source identity supplied by the
//! source manifest; no identity is inferred from packet content.
//!
//! The v1 journal observation cannot carry channel, packet sequence, protocol,
//! capture location or decoder version. Those fields used to be dropped by the
//! conversion. They now travel in a versioned [`EvidenceEnvelope`] alongside
//! the unchanged v1 observation, bound to it by a payload digest and the
//! source/epoch/receive-time tuple. V1 and V2 readers therefore share the same
//! retained bytes, and no field is silently discarded.

use anyhow::ensure;
use serde::Deserialize;
use serde::Serialize;

use crate::{
    acquisition::arbiter::FeedChannel,
    journal::ObservationRecord,
    model::SourceId,
    protocol::{FrameClassification, FrameDirection, FrameKind, HeartbeatMechanism, SessionSignal},
    util::sha256_hex,
};

/// Schema version of the legacy v1 journal observation.
pub const V1_OBSERVATION_SCHEMA_VERSION: u32 = 1;
/// Schema version of the extended evidence envelope.
pub const V2_EVIDENCE_SCHEMA_VERSION: u32 = 2;

/// Immutable evidence for one received packet or application payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketEvidence {
    pub source: String,
    pub channel: FeedChannel,
    pub connection_epoch: u64,
    pub sequence: Option<u64>,
    pub protocol: String,
    pub payload: Vec<u8>,
    pub received_at_us: i64,
    pub capture_location: String,
    pub decoder_version: String,
}

/// Packet fields that the v1 journal observation has no slot for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketEvidenceExtension {
    pub channel: FeedChannel,
    pub sequence: Option<u64>,
    pub protocol: String,
    pub capture_location: String,
    pub decoder_version: String,
    pub source_text: String,
}

/// Minimal binding from an extended envelope back to its v1 observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationBinding {
    pub source_shard: u16,
    pub source_replica: u16,
    pub connection_epoch: u64,
    pub received_at_us: i64,
    pub payload_sha256: String,
}

/// Versioned evidence extension persisted next to the v1 journal observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEnvelope {
    pub schema_version: u32,
    pub binding: ObservationBinding,
    pub extension: PacketEvidenceExtension,
}

impl EvidenceEnvelope {
    /// Encode the envelope as JSON for a versioned side channel.
    pub fn to_json(&self) -> anyhow::Result<String> {
        serde_json::to_string(self).map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    /// Decode an envelope, failing closed on an unknown schema version.
    pub fn from_json(text: &str) -> anyhow::Result<Self> {
        let envelope: Self =
            serde_json::from_str(text).map_err(|error| anyhow::anyhow!(error.to_string()))?;
        ensure!(
            envelope.schema_version == V2_EVIDENCE_SCHEMA_VERSION,
            "unsupported evidence schema version {}",
            envelope.schema_version
        );
        Ok(envelope)
    }
}

/// The unchanged v1 journal observation paired with its v2 evidence extension.
#[derive(Debug, Clone)]
pub struct VersionedEvidence {
    /// Legacy observation, byte-compatible with the v1 journal contract.
    pub observation: ObservationRecord,
    /// Extended evidence, written to the versioned side channel.
    pub envelope: EvidenceEnvelope,
}

impl PacketEvidence {
    /// Create evidence from a received payload.
    #[expect(
        clippy::too_many_arguments,
        reason = "packet evidence fields are explicit and caller-supplied"
    )]
    pub fn new(
        source: &str,
        channel: FeedChannel,
        connection_epoch: u64,
        sequence: Option<u64>,
        protocol: &str,
        payload: Vec<u8>,
        received_at_us: i64,
        capture_location: &str,
        decoder_version: &str,
    ) -> Self {
        Self {
            source: source.to_owned(),
            channel,
            connection_epoch,
            sequence,
            protocol: protocol.to_owned(),
            payload,
            received_at_us,
            capture_location: capture_location.to_owned(),
            decoder_version: decoder_version.to_owned(),
        }
    }

    /// Return the SHA-256 digest of the original payload bytes.
    pub fn payload_sha256(&self) -> String {
        sha256_hex(&self.payload)
    }

    /// Map to the existing journal observation record with an explicit source.
    ///
    /// This is the legacy v1 path. Callers that need full evidence must use
    /// [`Self::to_versioned_evidence`] instead; this method cannot carry the
    /// packet fields that the v1 record has no slot for.
    pub fn to_observation(&self, source: SourceId) -> ObservationRecord {
        ObservationRecord {
            source,
            connection_epoch: self.connection_epoch,
            received_at_us: self.received_at_us,
            direction: FrameDirection::Inbound,
            classification: FrameClassification::Data {
                frame_kind: FrameKind::Binary,
            },
            signal: SessionSignal::MarketData,
            mechanism: HeartbeatMechanism::Disabled,
            payload: self.payload.clone(),
            send_result: None,
        }
    }

    /// Build the v1 observation and its bound v2 evidence extension together.
    pub fn to_versioned_evidence(&self, source: SourceId) -> VersionedEvidence {
        VersionedEvidence {
            observation: self.to_observation(source),
            envelope: EvidenceEnvelope {
                schema_version: V2_EVIDENCE_SCHEMA_VERSION,
                binding: ObservationBinding {
                    source_shard: source.shard,
                    source_replica: source.replica,
                    connection_epoch: self.connection_epoch,
                    received_at_us: self.received_at_us,
                    payload_sha256: self.payload_sha256(),
                },
                extension: PacketEvidenceExtension {
                    channel: self.channel,
                    sequence: self.sequence,
                    protocol: self.protocol.clone(),
                    capture_location: self.capture_location.clone(),
                    decoder_version: self.decoder_version.clone(),
                    source_text: self.source.clone(),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> PacketEvidence {
        PacketEvidence::new(
            "source-a",
            FeedChannel::Primary,
            1,
            Some(7),
            "itch",
            vec![1, 2, 3, 4],
            1_700_000_000_000_000,
            "lab",
            "decoder-1",
        )
    }

    #[test]
    fn payload_digest_is_stable() {
        let packet = evidence();
        assert_eq!(
            packet.payload_sha256(),
            sha256_hex(&[1, 2, 3, 4]),
            "digest must cover original bytes"
        );
    }

    #[test]
    fn journal_mapping_preserves_identity_and_payload() {
        let packet = evidence();
        let observation = packet.to_observation(SourceId::new(2, 3));
        assert_eq!(
            observation.source,
            SourceId::new(2, 3),
            "source is explicit"
        );
        assert_eq!(observation.connection_epoch, 1, "epoch must be retained");
        assert_eq!(
            observation.payload,
            vec![1, 2, 3, 4],
            "original bytes must survive"
        );
    }

    #[test]
    fn v1_observation_is_unchanged_by_extension() {
        let packet = evidence();
        let versioned = packet.to_versioned_evidence(SourceId::new(2, 3));
        let legacy = packet.to_observation(SourceId::new(2, 3));
        assert_eq!(
            versioned.observation.source, legacy.source,
            "v1 reader sees the identical source"
        );
        assert_eq!(
            versioned.observation.payload, legacy.payload,
            "v1 reader sees the identical bytes"
        );
    }

    #[test]
    fn all_packet_fields_survive_versioned_round_trip() {
        let packet = evidence();
        let versioned = packet.to_versioned_evidence(SourceId::new(2, 3));
        let json = versioned.envelope.to_json().expect("encode envelope");
        let decoded = EvidenceEnvelope::from_json(&json).expect("decode envelope");
        assert_eq!(decoded, versioned.envelope, "envelope round-trips exactly");
        let extension = decoded.extension;
        assert_eq!(extension.channel, FeedChannel::Primary, "channel survives");
        assert_eq!(extension.sequence, Some(7), "packet sequence survives");
        assert_eq!(extension.protocol, "itch", "protocol survives");
        assert_eq!(extension.capture_location, "lab", "location survives");
        assert_eq!(extension.decoder_version, "decoder-1", "decoder survives");
        assert_eq!(extension.source_text, "source-a", "source text survives");
    }

    #[test]
    fn envelope_is_bound_to_its_v1_observation() {
        let packet = evidence();
        let versioned = packet.to_versioned_evidence(SourceId::new(2, 3));
        assert_eq!(versioned.envelope.binding.source_shard, 2, "shard bound");
        assert_eq!(
            versioned.envelope.binding.source_replica, 3,
            "replica bound"
        );
        assert_eq!(
            versioned.envelope.binding.payload_sha256,
            packet.payload_sha256(),
            "digest binds the same original bytes"
        );
    }

    #[test]
    fn unknown_schema_version_fails_closed() {
        let packet = evidence();
        let mut versioned = packet.to_versioned_evidence(SourceId::new(2, 3));
        versioned.envelope.schema_version = 99;
        let json = versioned.envelope.to_json().expect("encode envelope");
        assert!(
            EvidenceEnvelope::from_json(&json).is_err(),
            "unknown evidence version must be rejected"
        );
    }
}
