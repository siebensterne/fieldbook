// SPDX-License-Identifier: Apache-2.0
//! Dual-feed packet arbitration by sequence number.
//!
//! [`FeedArbiter`] tracks the next expected sequence, records sequences seen
//! on either channel, buffers packets that arrive ahead of the expected
//! sequence and drains them once the gap is filled.
//!
//! Every retained collection is bounded by entry counts and payload bytes.
//! State is private and exposed through read-only snapshots and metrics. Two
//! redundant feeds reporting the same sequence with different bytes produce a
//! conflict, not an ordinary duplicate. Every submitted packet is offered to
//! a raw-evidence sink before arbitration can reject or deduplicate it.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    mem::size_of,
};

use serde::{
    Deserialize, //
    Serialize,   //
};

use crate::{
    governance::adapter::SourceCapabilityManifest, governance::modality::AcquisitionModality,
    util::sha256_hex,
};

/// Whether a source declaration supports sequence arbitration.
#[must_use]
pub fn arbiter_applicable(manifest: &SourceCapabilityManifest) -> bool {
    manifest
        .modalities
        .contains(&AcquisitionModality::Streaming)
        && manifest.streaming.is_some_and(|capability| {
            capability.continuous
                && capability.sequence_numbers
                && (capability.recovery.packet_sequence || capability.recovery.exchange_sequence)
        })
}

/// Feed channel that delivered a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeedChannel {
    /// Primary feed channel.
    Primary,
    /// Secondary feed channel.
    Secondary,
}

impl FeedChannel {
    /// Stable lowercase label for the channel.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
        }
    }
}

/// Packet carrying sequence metadata through arbitration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequencedPacket {
    /// Channel that delivered the packet.
    pub channel: FeedChannel,
    /// Feed sequence number.
    pub sequence: u64,
    /// Raw packet body.
    pub payload: Vec<u8>,
    /// Arrival timestamp in microseconds.
    pub received_at_us: i64,
}

/// Sequence space shared by the feeds under arbitration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceDomain {
    /// Stable identifier of the sequence space.
    pub domain_id: String,
    /// Connection epoch that owns the sequence counter.
    pub connection_epoch: u64,
}

impl SequenceDomain {
    /// Construct a sequence domain.
    #[must_use]
    pub fn new(domain_id: &str, connection_epoch: u64) -> Self {
        Self {
            domain_id: domain_id.to_owned(),
            connection_epoch,
        }
    }
}

impl fmt::Display for SequenceDomain {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.domain_id, self.connection_epoch)
    }
}

/// Byte and entry budgets for every retained collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArbiterLimits {
    pub max_packet_bytes: usize,
    pub max_seen_entries: usize,
    pub max_buffered_entries: usize,
    pub max_buffered_bytes: u64,
    pub max_rejected_entries: usize,
    pub max_rejected_bytes: u64,
    pub max_total_payload_bytes: u64,
    pub max_sequence_gap: u64,
}

impl Default for ArbiterLimits {
    fn default() -> Self {
        Self {
            max_packet_bytes: 1_048_576,
            max_seen_entries: 1_000_000,
            max_buffered_entries: 65_536,
            max_buffered_bytes: 256 * 1_024 * 1_024,
            max_rejected_entries: 1_024,
            max_rejected_bytes: 64 * 1_024 * 1_024,
            max_total_payload_bytes: 320 * 1_024 * 1_024,
            max_sequence_gap: 100_000,
        }
    }
}

impl ArbiterLimits {
    /// Validate that every bound is positive and coherent.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.max_packet_bytes > 0,
            "max_packet_bytes must be positive"
        );
        anyhow::ensure!(
            self.max_seen_entries > 0,
            "max_seen_entries must be positive"
        );
        anyhow::ensure!(
            self.max_buffered_entries > 0,
            "max_buffered_entries must be positive"
        );
        anyhow::ensure!(
            self.max_rejected_entries > 0,
            "max_rejected_entries must be positive"
        );
        anyhow::ensure!(
            self.max_sequence_gap > 0,
            "max_sequence_gap must be positive"
        );
        anyhow::ensure!(
            self.max_buffered_bytes <= self.max_total_payload_bytes,
            "buffered byte budget exceeds the total payload budget"
        );
        anyhow::ensure!(
            self.max_rejected_bytes <= self.max_total_payload_bytes,
            "rejected byte budget exceeds the total payload budget"
        );
        Ok(())
    }
}

/// Verdict for one submitted packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArbiterVerdict {
    /// Packet advanced the expected sequence.
    Accepted,
    /// The same sequence and bytes arrived on another channel.
    DuplicateIdentical,
    /// The same sequence arrived with different bytes.
    DuplicateConflict {
        sequence: u64,
        expected_sha256: String,
        observed_sha256: String,
    },
    /// Packet arrived beyond a gap carrying the still-expected sequence.
    Gap(u64),
    /// Packet sequence is older than expected and unseen.
    Stale,
    /// Packet arrived ahead of expected and was buffered.
    OutOfOrder,
    /// Declared maximum sequence gap was exceeded.
    GapExceeded { expected: u64, observed: u64 },
    /// Out-of-order buffer is full by entries or bytes.
    BufferFull { sequence: u64 },
    /// A configured byte budget refused the packet.
    BudgetRejected { reason: String },
    /// Sequence space is exhausted.
    SequenceExhausted { sequence: u64 },
}

/// One packet that was rejected, with its disposition and original evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedPacket {
    /// Original packet, including its payload bytes.
    pub packet: SequencedPacket,
    /// Why the packet was not admitted to the in-order stream.
    pub verdict: ArbiterVerdict,
}

/// Counters for every disposition and resource budget.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArbiterMetrics {
    pub accepted: u64,
    pub duplicate_identical: u64,
    pub duplicate_conflict: u64,
    pub stale: u64,
    pub delayed: u64,
    pub rejected: u64,
    pub pruned_seen: u64,
    pub gaps: u64,
    pub gap_exceeded: u64,
    pub sequence_exhausted: u64,
    pub budget_rejections: u64,
    pub evidence_overflow: u64,
    pub buffered_bytes: u64,
    pub rejected_bytes: u64,
    pub total_payload_bytes: u64,
    pub high_water_buffered_bytes: u64,
    pub high_water_total_bytes: u64,
}

/// Current occupancy of the arbiter's bounded collections.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArbiterMemory {
    pub seen_entries: usize,
    pub buffered_entries: usize,
    pub rejected_entries: usize,
    pub buffered_bytes: u64,
    pub rejected_bytes: u64,
    pub total_payload_bytes: u64,
    /// Fixed-size estimate of map bookkeeping, not allocator occupancy.
    pub overhead_estimate_bytes: u64,
    pub high_water_buffered_bytes: u64,
    pub high_water_total_bytes: u64,
}

/// Read-only view of one seen sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeenEntry {
    pub sequence: u64,
    pub channel: FeedChannel,
    pub received_at_us: i64,
}

/// Serializable arbiter state for restart recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArbiterSnapshot {
    pub domain: SequenceDomain,
    pub expected: u64,
    pub seen: Vec<SeenEntry>,
    pub seen_digest: BTreeMap<u64, String>,
    pub buffered: Vec<SequencedPacket>,
    pub rejected: Vec<RejectedPacket>,
    pub gap_count: u64,
    pub metrics: ArbiterMetrics,
    pub exhausted: bool,
}

/// Sink that retains raw evidence before arbitration decides.
pub trait RawEvidenceSink: Send + Sync + fmt::Debug {
    /// Retain one submitted packet as raw evidence.
    fn retain(&self, packet: &SequencedPacket);
}

/// Deterministic fault point for failure injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArbiterFault {
    /// Interrupt before raw-evidence retention.
    Retain,
    /// Interrupt before out-of-order buffering.
    Buffer,
    /// Interrupt before advancing the expected sequence.
    Advance,
}

/// Arbiter reconciling primary and secondary feed sequences.
#[derive(Debug)]
pub struct FeedArbiter {
    domain: SequenceDomain,
    expected: u64,
    seen: BTreeMap<u64, (FeedChannel, i64)>,
    seen_digest: BTreeMap<u64, String>,
    gap_count: u64,
    limits: ArbiterLimits,
    metrics: ArbiterMetrics,
    buffered: BTreeMap<u64, SequencedPacket>,
    rejected: VecDeque<RejectedPacket>,
    exhausted: bool,
    evidence_sink: Option<Box<dyn RawEvidenceSink>>,
    injected_fault: Option<ArbiterFault>,
}

impl FeedArbiter {
    /// Construct an arbiter for a sequence domain with explicit bounds.
    pub fn new(
        domain: SequenceDomain,
        expected: u64,
        limits: ArbiterLimits,
    ) -> anyhow::Result<Self> {
        limits.validate()?;
        Ok(Self {
            domain,
            expected,
            seen: BTreeMap::new(),
            seen_digest: BTreeMap::new(),
            gap_count: 0,
            limits,
            metrics: ArbiterMetrics::default(),
            buffered: BTreeMap::new(),
            rejected: VecDeque::new(),
            exhausted: false,
            evidence_sink: None,
            injected_fault: None,
        })
    }

    /// Construct an arbiter with default bounds.
    pub fn with_defaults(domain: SequenceDomain, expected: u64) -> anyhow::Result<Self> {
        Self::new(domain, expected, ArbiterLimits::default())
    }

    /// Install a raw-evidence sink called for every submitted packet.
    #[must_use]
    pub fn with_evidence_sink(mut self, sink: Box<dyn RawEvidenceSink>) -> Self {
        self.evidence_sink = Some(sink);
        self
    }

    /// Install a deterministic fault point for tests.
    #[must_use]
    pub fn with_injected_fault(mut self, fault: ArbiterFault) -> Self {
        self.injected_fault = Some(fault);
        self
    }

    /// Return the sequence domain governed by this arbiter.
    #[must_use]
    pub fn domain(&self) -> &SequenceDomain {
        &self.domain
    }

    /// Return the next required sequence.
    #[must_use]
    pub const fn expected(&self) -> u64 {
        self.expected
    }

    /// Return the gap counter.
    #[must_use]
    pub const fn gap_count(&self) -> u64 {
        self.gap_count
    }

    /// Return the configured bounds.
    #[must_use]
    pub const fn limits(&self) -> &ArbiterLimits {
        &self.limits
    }

    /// Return the disposition counters.
    #[must_use]
    pub const fn metrics(&self) -> &ArbiterMetrics {
        &self.metrics
    }

    /// Return a read-only snapshot of the duplicate window.
    #[must_use]
    pub fn seen_snapshot(&self) -> Vec<SeenEntry> {
        self.seen
            .iter()
            .map(|(sequence, (channel, received_at_us))| SeenEntry {
                sequence: *sequence,
                channel: *channel,
                received_at_us: *received_at_us,
            })
            .collect()
    }

    /// Return rejected packet dispositions under the evidence bound.
    pub fn rejected(&self) -> impl Iterator<Item = &RejectedPacket> {
        self.rejected.iter()
    }

    /// Whether the sequence space has been exhausted.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Current memory occupancy of the bounded collections.
    #[must_use]
    pub fn memory(&self) -> ArbiterMemory {
        let overhead_estimate_bytes = (self.seen.len()
            * (size_of::<u64>() + size_of::<FeedChannel>() + size_of::<i64>()))
            as u64;
        ArbiterMemory {
            seen_entries: self.seen.len(),
            buffered_entries: self.buffered.len(),
            rejected_entries: self.rejected.len(),
            buffered_bytes: self.metrics.buffered_bytes,
            rejected_bytes: self.metrics.rejected_bytes,
            total_payload_bytes: self.metrics.total_payload_bytes,
            overhead_estimate_bytes,
            high_water_buffered_bytes: self.metrics.high_water_buffered_bytes,
            high_water_total_bytes: self.metrics.high_water_total_bytes,
        }
    }

    /// Capture restart-safe state.
    #[must_use]
    pub fn snapshot(&self) -> ArbiterSnapshot {
        ArbiterSnapshot {
            domain: self.domain.clone(),
            expected: self.expected,
            seen: self.seen_snapshot(),
            seen_digest: self.seen_digest.clone(),
            buffered: self.buffered.values().cloned().collect(),
            rejected: self.rejected.iter().cloned().collect(),
            gap_count: self.gap_count,
            metrics: self.metrics,
            exhausted: self.exhausted,
        }
    }

    /// Restore arbiter state captured by [`Self::snapshot`].
    pub fn restore(snapshot: ArbiterSnapshot, limits: ArbiterLimits) -> anyhow::Result<Self> {
        limits.validate()?;
        let mut restored = Self::new(snapshot.domain, snapshot.expected, limits)?;
        for entry in snapshot.seen {
            restored
                .seen
                .insert(entry.sequence, (entry.channel, entry.received_at_us));
        }
        restored.seen_digest = snapshot.seen_digest;
        for packet in snapshot.buffered {
            let sequence = packet.sequence;
            restored.buffered.insert(sequence, packet);
        }
        restored.rejected.extend(snapshot.rejected);
        restored.gap_count = snapshot.gap_count;
        restored.metrics = snapshot.metrics;
        restored.exhausted = snapshot.exhausted;
        Ok(restored)
    }

    fn record(&mut self, packet: &SequencedPacket) {
        if self.seen.len() >= self.limits.max_seen_entries && self.seen.pop_first().is_some() {
            self.metrics.pruned_seen = self.metrics.pruned_seen.saturating_add(1);
        }
        self.seen
            .insert(packet.sequence, (packet.channel, packet.received_at_us));
    }

    fn advance(&mut self) -> bool {
        match self.expected.checked_add(1) {
            Some(next) => {
                self.expected = next;
                true
            }
            None => {
                self.exhausted = true;
                self.metrics.sequence_exhausted = self.metrics.sequence_exhausted.saturating_add(1);
                false
            }
        }
    }

    fn add_rejected_bytes(&mut self, bytes: u64) {
        self.metrics.rejected_bytes = self.metrics.rejected_bytes.saturating_add(bytes);
        self.metrics.total_payload_bytes = self.metrics.total_payload_bytes.saturating_add(bytes);
        self.update_high_water();
    }

    fn update_high_water(&mut self) {
        self.metrics.high_water_buffered_bytes = self
            .metrics
            .high_water_buffered_bytes
            .max(self.metrics.buffered_bytes);
        self.metrics.high_water_total_bytes = self
            .metrics
            .high_water_total_bytes
            .max(self.metrics.total_payload_bytes);
    }

    fn reject(&mut self, packet: SequencedPacket, verdict: ArbiterVerdict) {
        let bytes = packet.payload.len() as u64;
        self.metrics.rejected = self.metrics.rejected.saturating_add(1);
        self.add_rejected_bytes(bytes);
        while (self.rejected.len() >= self.limits.max_rejected_entries
            || self.metrics.rejected_bytes > self.limits.max_rejected_bytes)
            && !self.rejected.is_empty()
        {
            if let Some(dropped) = self.rejected.pop_front() {
                let dropped_bytes = dropped.packet.payload.len() as u64;
                self.metrics.rejected_bytes =
                    self.metrics.rejected_bytes.saturating_sub(dropped_bytes);
                self.metrics.total_payload_bytes = self
                    .metrics
                    .total_payload_bytes
                    .saturating_sub(dropped_bytes);
                self.metrics.evidence_overflow = self.metrics.evidence_overflow.saturating_add(1);
            }
        }
        if bytes <= self.limits.max_rejected_bytes {
            self.rejected.push_back(RejectedPacket { packet, verdict });
        } else {
            self.metrics.evidence_overflow = self.metrics.evidence_overflow.saturating_add(1);
        }
    }

    fn budget_rejection(&mut self, reason: &'static str) -> ArbiterVerdict {
        self.metrics.budget_rejections = self.metrics.budget_rejections.saturating_add(1);
        ArbiterVerdict::BudgetRejected {
            reason: reason.to_owned(),
        }
    }

    /// Submit one packet for arbitration.
    pub fn submit(&mut self, packet: SequencedPacket) -> ArbiterVerdict {
        if let Some(sink) = &self.evidence_sink {
            sink.retain(&packet);
        }
        if self.injected_fault == Some(ArbiterFault::Retain) {
            return self.budget_rejection("injected_before_retain");
        }
        let bytes = packet.payload.len() as u64;
        if packet.payload.len() > self.limits.max_packet_bytes {
            return self.budget_rejection("packet_bytes");
        }
        let total_after = self.metrics.total_payload_bytes.saturating_add(bytes);
        if total_after > self.limits.max_total_payload_bytes {
            return self.budget_rejection("total_payload_bytes");
        }
        if self.exhausted {
            let sequence = packet.sequence;
            self.reject(packet, ArbiterVerdict::SequenceExhausted { sequence });
            return ArbiterVerdict::SequenceExhausted {
                sequence: self.expected,
            };
        }
        let sequence = packet.sequence;
        let observed_sha256 = sha256_hex(&packet.payload);
        if self.seen.contains_key(&sequence) {
            let expected_sha256 = self
                .seen_digest
                .get(&sequence)
                .cloned()
                .unwrap_or(observed_sha256.clone());
            if expected_sha256 == observed_sha256 {
                self.metrics.duplicate_identical =
                    self.metrics.duplicate_identical.saturating_add(1);
                return ArbiterVerdict::DuplicateIdentical;
            }
            self.metrics.duplicate_conflict = self.metrics.duplicate_conflict.saturating_add(1);
            return ArbiterVerdict::DuplicateConflict {
                sequence,
                expected_sha256,
                observed_sha256,
            };
        }
        if let Some(buffered) = self.buffered.get(&sequence) {
            let expected_sha256 = sha256_hex(&buffered.payload);
            if expected_sha256 == observed_sha256 {
                self.metrics.duplicate_identical =
                    self.metrics.duplicate_identical.saturating_add(1);
                return ArbiterVerdict::DuplicateIdentical;
            }
            self.metrics.duplicate_conflict = self.metrics.duplicate_conflict.saturating_add(1);
            return ArbiterVerdict::DuplicateConflict {
                sequence,
                expected_sha256,
                observed_sha256,
            };
        }
        if sequence < self.expected {
            self.metrics.stale = self.metrics.stale.saturating_add(1);
            return ArbiterVerdict::Stale;
        }
        if sequence == self.expected {
            if self.injected_fault == Some(ArbiterFault::Advance) {
                return self.budget_rejection("injected_before_advance");
            }
            self.record(&packet);
            self.seen_digest.insert(sequence, observed_sha256);
            self.metrics.accepted = self.metrics.accepted.saturating_add(1);
            if self.advance() {
                return ArbiterVerdict::Accepted;
            }
            return ArbiterVerdict::SequenceExhausted { sequence };
        }
        let gap = sequence - self.expected;
        if gap > self.limits.max_sequence_gap {
            self.metrics.gap_exceeded = self.metrics.gap_exceeded.saturating_add(1);
            let verdict = ArbiterVerdict::GapExceeded {
                expected: self.expected,
                observed: sequence,
            };
            self.reject(packet, verdict.clone());
            return verdict;
        }
        if self.buffered.len() >= self.limits.max_buffered_entries
            || self.metrics.buffered_bytes.saturating_add(bytes) > self.limits.max_buffered_bytes
        {
            let verdict = ArbiterVerdict::BufferFull { sequence };
            self.reject(packet, verdict.clone());
            return verdict;
        }
        if self.injected_fault == Some(ArbiterFault::Buffer) {
            return self.budget_rejection("injected_before_buffer");
        }
        let gap_opened = self.buffered.is_empty();
        self.metrics.buffered_bytes = self.metrics.buffered_bytes.saturating_add(bytes);
        self.metrics.total_payload_bytes = self.metrics.total_payload_bytes.saturating_add(bytes);
        self.update_high_water();
        self.buffered.insert(sequence, packet);
        if gap_opened {
            self.gap_count = self.gap_count.saturating_add(1);
            self.metrics.gaps = self.metrics.gaps.saturating_add(1);
            return ArbiterVerdict::Gap(self.expected);
        }
        ArbiterVerdict::OutOfOrder
    }

    /// Return buffered packets whose sequences are now in order.
    pub fn drain_available(&mut self) -> Vec<SequencedPacket> {
        let mut drained = Vec::new();
        while let Some(packet) = self.buffered.remove(&self.expected) {
            let bytes = packet.payload.len() as u64;
            self.metrics.buffered_bytes = self.metrics.buffered_bytes.saturating_sub(bytes);
            self.metrics.total_payload_bytes =
                self.metrics.total_payload_bytes.saturating_sub(bytes);
            self.record(&packet);
            self.seen_digest
                .insert(packet.sequence, sha256_hex(&packet.payload));
            self.metrics.delayed = self.metrics.delayed.saturating_add(1);
            if !self.advance() {
                break;
            }
            drained.push(packet);
        }
        drained
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{
        AtomicUsize, //
        Ordering,    //
    };

    #[derive(Debug)]
    struct CountingSink {
        count: std::sync::Arc<AtomicUsize>,
    }

    impl RawEvidenceSink for CountingSink {
        fn retain(&self, _packet: &SequencedPacket) {
            self.count.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn domain() -> SequenceDomain {
        SequenceDomain::new("fixture-feed", 1)
    }

    fn packet(sequence: u64, body: &str) -> SequencedPacket {
        SequencedPacket {
            channel: FeedChannel::Primary,
            sequence,
            payload: body.as_bytes().to_vec(),
            received_at_us: 100 + sequence as i64,
        }
    }

    fn arbiter(expected: u64) -> FeedArbiter {
        FeedArbiter::with_defaults(domain(), expected).expect("arbiter created")
    }

    #[test]
    fn arbiter_is_not_forced_onto_sources_without_sequence_semantics() {
        use crate::{
            adapter::{
                AccessStatus, HistoricalCapability, Protocol, RecoveryCapability,
                SourceCapabilityManifest, TimestampCapability, Transport,
            },
            modality::{AcquisitionModality, StreamingCapability},
            reference_data::VenueCategory,
            taxonomy::{AssetClass, CountryCode, DataCategory, DepthModel, Frequency},
        };

        let mut manifest = SourceCapabilityManifest {
            source_id: "fixture".to_owned(),
            provider: "fixture".to_owned(),
            venue_mic: None,
            country: CountryCode::new("US").expect("country code"),
            venue_category: VenueCategory::Exchange,
            asset_classes: vec![AssetClass::Equity],
            data_categories: vec![DataCategory::Trades],
            protocols: vec![Protocol::WebSocket],
            transports: vec![Transport::WebSocket],
            book_model: DepthModel::Level2,
            timestamps: TimestampCapability {
                exchange_event_time: false,
                exchange_publication_time: false,
                packet_capture_time: true,
                sequence_numbers: true,
                clock_source: "host".to_owned(),
            },
            recovery: RecoveryCapability {
                snapshot: false,
                incremental_recovery: false,
                packet_sequence: true,
                exchange_sequence: false,
                gap_request: false,
            },
            historical: HistoricalCapability {
                available: false,
                earliest_us: None,
                frequency: Frequency::RealTime,
            },
            access: AccessStatus::Public,
            schema_version: 1,
            modalities: vec![AcquisitionModality::Streaming],
            streaming: Some(StreamingCapability {
                continuous: true,
                sequence_numbers: true,
                recovery: RecoveryCapability {
                    snapshot: false,
                    incremental_recovery: false,
                    packet_sequence: true,
                    exchange_sequence: false,
                    gap_request: false,
                },
            }),
            snapshot: None,
            batch: None,
            document: None,
            on_chain: None,
        };
        assert!(
            arbiter_applicable(&manifest),
            "streaming sequence source applies"
        );
        manifest.modalities = vec![AcquisitionModality::Snapshot];
        assert!(
            !arbiter_applicable(&manifest),
            "snapshot sources must not be forced through arbitration"
        );
    }

    #[test]
    fn in_order_packet_is_accepted() {
        let mut arbiter = arbiter(1);
        assert_eq!(
            arbiter.submit(packet(1, "one")),
            ArbiterVerdict::Accepted,
            "expected packet accepted"
        );
        assert_eq!(arbiter.expected(), 2, "expected sequence advanced");
        assert_eq!(arbiter.metrics().accepted, 1, "acceptance counted");
    }

    #[test]
    fn identical_and_conflicting_duplicates_are_distinct() {
        let mut arbiter = arbiter(9);
        arbiter.submit(packet(9, "a"));
        assert_eq!(
            arbiter.submit(packet(9, "a")),
            ArbiterVerdict::DuplicateIdentical,
            "matching bytes are an ordinary duplicate"
        );
        let conflict = arbiter.submit(packet(9, "different"));
        let is_conflict = matches!(conflict, ArbiterVerdict::DuplicateConflict { .. });
        assert!(is_conflict, "different bytes must conflict");
        assert_eq!(arbiter.metrics().duplicate_conflict, 1, "conflict counted");
    }

    #[test]
    fn gap_then_recovery_drains_buffered() {
        let mut arbiter = arbiter(1);
        arbiter.submit(packet(1, "1"));
        assert_eq!(
            arbiter.submit(packet(4, "4")),
            ArbiterVerdict::Gap(2),
            "gap reports the expected sequence"
        );
        arbiter.submit(packet(3, "3"));
        arbiter.submit(packet(2, "2"));
        let drained = arbiter.drain_available();
        let sequences: Vec<u64> = drained.iter().map(|item| item.sequence).collect();
        assert_eq!(sequences, vec![3, 4], "buffered packets drain in order");
        assert_eq!(arbiter.metrics().delayed, 2, "delayed packets counted");
    }

    #[test]
    fn stale_packet_is_rejected() {
        let mut arbiter = arbiter(5);
        assert_eq!(
            arbiter.submit(packet(3, "old")),
            ArbiterVerdict::Stale,
            "older unseen packet is stale"
        );
        assert_eq!(arbiter.expected(), 5, "stale leaves expected unchanged");
    }

    #[test]
    fn every_submitted_packet_reaches_raw_evidence() {
        let count = std::sync::Arc::new(AtomicUsize::new(0));
        let mut arbiter = arbiter(1).with_evidence_sink(Box::new(CountingSink {
            count: count.clone(),
        }));
        arbiter.submit(packet(1, "ok"));
        arbiter.submit(packet(1, "duplicate"));
        arbiter.submit(packet(9, "gap"));
        arbiter.submit(packet(0, "stale"));
        assert_eq!(
            count.load(Ordering::Relaxed),
            4,
            "raw evidence retains every received packet"
        );
    }

    #[test]
    fn byte_budgets_are_enforced() {
        let limits = ArbiterLimits {
            max_packet_bytes: 4,
            ..ArbiterLimits::default()
        };
        let mut arbiter = FeedArbiter::new(domain(), 1, limits).expect("arbiter created");
        assert_eq!(
            arbiter.submit(packet(1, "toolong")),
            ArbiterVerdict::BudgetRejected {
                reason: "packet_bytes".to_owned()
            },
            "oversized frame is refused"
        );
        assert_eq!(
            arbiter.metrics().budget_rejections,
            1,
            "budget rejection counted"
        );
    }

    #[test]
    fn buffered_byte_budget_is_enforced() {
        let limits = ArbiterLimits {
            max_buffered_bytes: 4,
            max_rejected_bytes: 32,
            max_total_payload_bytes: 64,
            ..ArbiterLimits::default()
        };
        let mut arbiter = FeedArbiter::new(domain(), 1, limits).expect("arbiter created");
        assert_eq!(
            arbiter.submit(packet(2, "abcd")),
            ArbiterVerdict::Gap(1),
            "first buffered packet fills the byte budget"
        );
        assert_eq!(
            arbiter.submit(packet(3, "xyz")),
            ArbiterVerdict::BufferFull { sequence: 3 },
            "second packet exceeds the buffer byte budget"
        );
    }

    #[test]
    fn conflicting_duplicate_is_not_counted_as_identical() {
        let mut arbiter = arbiter(1);
        arbiter.submit(packet(1, "one"));
        let verdict = arbiter.submit(packet(1, "two"));
        assert!(
            matches!(verdict, ArbiterVerdict::DuplicateConflict { .. }),
            "same sequence with different bytes conflicts"
        );
        assert_eq!(
            arbiter.metrics().duplicate_identical,
            0,
            "conflict is not an identical duplicate"
        );
    }

    #[test]
    fn sequence_exhaustion_is_explicit() {
        let mut arbiter = arbiter(u64::MAX);
        assert_eq!(
            arbiter.submit(packet(u64::MAX, "last")),
            ArbiterVerdict::SequenceExhausted { sequence: u64::MAX },
            "exhaustion is reported"
        );
        assert!(arbiter.is_exhausted(), "arbiter is exhausted");
    }

    #[test]
    fn snapshot_restores_arbiter_state() {
        let mut arbiter = arbiter(1);
        arbiter.submit(packet(1, "one"));
        arbiter.submit(packet(3, "three"));
        let snapshot = arbiter.snapshot();
        let restored =
            FeedArbiter::restore(snapshot, ArbiterLimits::default()).expect("state restored");
        assert_eq!(restored.expected(), 2, "expected sequence restored");
        assert_eq!(
            restored.domain(),
            arbiter.domain(),
            "sequence domain restored"
        );
        assert!(
            restored.seen_snapshot()[0].sequence == 1,
            "duplicate window restored"
        );
    }

    #[test]
    fn injected_fault_produces_explicit_verdict() {
        let arbiter = arbiter(1).with_injected_fault(ArbiterFault::Advance);
        let mut arbiter = arbiter;
        assert_eq!(
            arbiter.submit(packet(1, "one")),
            ArbiterVerdict::BudgetRejected {
                reason: "injected_before_advance".to_owned()
            },
            "injected fault is explicit"
        );
        assert_eq!(arbiter.expected(), 1, "fault does not advance the sequence");
    }

    #[test]
    fn deterministic_reordered_stream_keeps_bounds_and_accounting() {
        let mut state = 0x9E37_79B9_u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut arbiter = arbiter(1);
        let mut submitted = 0_u64;
        for _ in 0..256 {
            let sequence = (next() % 40) + 1;
            arbiter.submit(packet(sequence, &format!("body-{sequence}")));
            submitted += 1;
            let memory = arbiter.memory();
            assert!(
                memory.total_payload_bytes <= arbiter.limits().max_total_payload_bytes,
                "total payload stays within budget"
            );
            assert!(
                memory.buffered_entries <= arbiter.limits().max_buffered_entries,
                "buffer stays within entry bound"
            );
        }
        arbiter.drain_available();
        assert_eq!(submitted, 256, "all packets submitted");
        assert!(
            arbiter.expected() >= 1,
            "expected sequence advances monotonically"
        );
    }
}
