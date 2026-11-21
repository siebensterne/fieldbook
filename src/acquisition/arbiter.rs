// SPDX-License-Identifier: Apache-2.0
//! Dual-feed packet arbitration by sequence number.
//!
//! [`FeedArbiter`] tracks the next expected sequence, records sequences seen
//! on either channel, buffers packets that arrive ahead of the expected
//! sequence and drains them once the gap is filled.
//!
//! Every collection in the arbiter is bounded by [`ArbiterLimits`]. The
//! duplicate-detection window is pruned with accounting; out-of-order and
//! gap-exceeded packets are rejected with a recorded disposition and retained
//! in a bounded evidence ledger. Nothing is silently discarded to satisfy a
//! bound. Sequence arithmetic is checked so exhaustion is an explicit
//! decision rather than a wraparound.

use std::{
    collections::{
        BTreeMap, //
        VecDeque, //
    },
    mem::size_of,
};

use serde::{
    Deserialize, //
    Serialize,   //
};

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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Differences between the required sequence and the observed sequence are
/// measured, declared and enforced. These are the production bounds; the
/// defaults are finite by construction but generous so offline helpers can
/// use [`FeedArbiter::new`] without choosing a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArbiterLimits {
    /// Maximum number of retained sequence numbers in the duplicate window.
    pub max_seen: usize,
    /// Maximum number of out-of-order packets held for gap recovery.
    pub max_buffered: usize,
    /// Largest declared gap that may be buffered while awaiting recovery.
    pub max_sequence_gap: u64,
    /// Maximum number of rejected packet dispositions retained as evidence.
    pub max_rejected: usize,
}

impl Default for ArbiterLimits {
    fn default() -> Self {
        Self {
            max_seen: 1_000_000,
            max_buffered: 65_536,
            max_sequence_gap: 100_000,
            max_rejected: 1_024,
        }
    }
}

impl ArbiterLimits {
    /// Validate that every bound is positive and coherent.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.max_seen > 0, "max_seen must be positive");
        anyhow::ensure!(self.max_buffered > 0, "max_buffered must be positive");
        anyhow::ensure!(self.max_rejected > 0, "max_rejected must be positive");
        anyhow::ensure!(
            self.max_sequence_gap > 0,
            "max_sequence_gap must be positive"
        );
        Ok(())
    }
}

/// Verdict for one submitted packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArbiterVerdict {
    /// Packet advanced the expected sequence.
    Accepted,
    /// Packet sequence was seen on either channel.
    Duplicate,
    /// Packet arrived beyond a gap carrying the still-expected sequence.
    Gap(u64),
    /// Packet sequence is older than expected and unseen.
    Stale,
    /// Packet arrived ahead of expected and was buffered.
    OutOfOrder,
    /// Declared maximum sequence gap was exceeded; recovery is required.
    GapExceeded {
        /// Sequence the arbiter still requires.
        expected: u64,
        /// Sequence that could not be buffered.
        observed: u64,
    },
    /// Out-of-order buffer is full; the packet was rejected with evidence.
    BufferFull {
        /// Sequence that could not be buffered.
        sequence: u64,
    },
    /// Sequence space is exhausted; a new connection epoch is required.
    SequenceExhausted {
        /// Sequence that cannot be advanced past.
        sequence: u64,
    },
}

/// One packet that was rejected, with its disposition and original evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedPacket {
    /// Original packet, including its payload bytes.
    pub packet: SequencedPacket,
    /// Why the packet was not admitted to the in-order stream.
    pub verdict: ArbiterVerdict,
}

/// Counters for every disposition produced by the arbiter.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArbiterMetrics {
    /// Packets that advanced the expected sequence.
    pub accepted: u64,
    /// Duplicate packets seen on either channel.
    pub duplicates: u64,
    /// Older unseen packets.
    pub stale: u64,
    /// Packets released from the out-of-order buffer.
    pub delayed: u64,
    /// Packets rejected by a bound or an explicit recovery decision.
    pub rejected: u64,
    /// Duplicate-window entries pruned under the configured bound.
    pub pruned_seen: u64,
    /// Gaps opened by an ahead-of-sequence packet.
    pub gaps: u64,
    /// Gaps that exceeded the declared maximum.
    pub gap_exceeded: u64,
    /// Sequence-exhaustion events.
    pub sequence_exhausted: u64,
    /// Rejected evidence records dropped because the evidence ledger is full.
    pub rejected_evidence_overflow: u64,
}

/// Current memory occupancy of the arbiter's bounded collections.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArbiterMemory {
    /// Retained duplicate-window entries.
    pub seen_entries: usize,
    /// Retained out-of-order packets.
    pub buffered_entries: usize,
    /// Sum of buffered payload lengths in bytes.
    pub buffered_bytes: u64,
    /// Fixed-size estimate of duplicate-window bookkeeping in bytes.
    pub seen_bytes: u64,
}

/// Arbiter reconciling primary and secondary feed sequences.
#[derive(Debug, Clone)]
pub struct FeedArbiter {
    /// Next sequence number required for in-order progress.
    pub expected: u64,
    /// Seen sequences mapped to channel and arrival timestamp.
    pub seen: BTreeMap<u64, (FeedChannel, i64)>,
    /// Count of gaps detected.
    pub gap_count: u64,
    /// Bounds applied to every collection.
    pub limits: ArbiterLimits,
    /// Disposition counters.
    pub metrics: ArbiterMetrics,
    buffered: BTreeMap<u64, SequencedPacket>,
    rejected: VecDeque<RejectedPacket>,
    exhausted: bool,
}

impl FeedArbiter {
    /// Construct an arbiter starting at `expected` with default bounds.
    #[must_use]
    pub fn new(expected: u64) -> Self {
        let limits = ArbiterLimits::default();
        Self {
            expected,
            seen: BTreeMap::new(),
            gap_count: 0,
            limits,
            metrics: ArbiterMetrics::default(),
            buffered: BTreeMap::new(),
            rejected: VecDeque::new(),
            exhausted: false,
        }
    }

    /// Construct an arbiter with explicit bounds.
    ///
    /// # Errors
    /// Returns an error when the supplied limits are not coherent.
    pub fn with_limits(expected: u64, limits: ArbiterLimits) -> anyhow::Result<Self> {
        limits.validate()?;
        Ok(Self {
            expected,
            seen: BTreeMap::new(),
            gap_count: 0,
            limits,
            metrics: ArbiterMetrics::default(),
            buffered: BTreeMap::new(),
            rejected: VecDeque::new(),
            exhausted: false,
        })
    }

    /// Whether the sequence space has been exhausted.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// Current memory occupancy of the bounded collections.
    #[must_use]
    pub fn memory(&self) -> ArbiterMemory {
        let buffered_bytes = self
            .buffered
            .values()
            .map(|packet| packet.payload.len() as u64)
            .sum();
        let entry_bytes = (size_of::<u64>() + size_of::<FeedChannel>() + size_of::<i64>()) as u64;
        ArbiterMemory {
            seen_entries: self.seen.len(),
            buffered_entries: self.buffered.len(),
            buffered_bytes,
            seen_bytes: self.seen.len() as u64 * entry_bytes,
        }
    }

    /// Rejected packet dispositions retained under the evidence bound.
    pub fn rejected(&self) -> impl Iterator<Item = &RejectedPacket> {
        self.rejected.iter()
    }

    fn record(&mut self, packet: &SequencedPacket) {
        if self.seen.len() >= self.limits.max_seen && self.seen.pop_first().is_some() {
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

    fn reject(&mut self, packet: SequencedPacket, verdict: ArbiterVerdict) {
        self.metrics.rejected = self.metrics.rejected.saturating_add(1);
        if self.rejected.len() >= self.limits.max_rejected && self.rejected.pop_front().is_some() {
            self.metrics.rejected_evidence_overflow =
                self.metrics.rejected_evidence_overflow.saturating_add(1);
        }
        self.rejected.push_back(RejectedPacket { packet, verdict });
    }

    /// Submit one packet for arbitration.
    ///
    /// A gap opens on the first packet beyond the expected sequence; that
    /// packet and later ones are buffered and released by [`Self::drain_available`].
    /// Bounds are enforced before buffering: a rejected packet is recorded with
    /// its disposition and original bytes rather than dropped.
    pub fn submit(&mut self, packet: SequencedPacket) -> ArbiterVerdict {
        if self.exhausted {
            let sequence = packet.sequence;
            self.reject(packet, ArbiterVerdict::SequenceExhausted { sequence });
            return ArbiterVerdict::SequenceExhausted {
                sequence: self.expected,
            };
        }
        let sequence = packet.sequence;
        if self.seen.contains_key(&sequence) || self.buffered.contains_key(&sequence) {
            self.metrics.duplicates = self.metrics.duplicates.saturating_add(1);
            return ArbiterVerdict::Duplicate;
        }
        if sequence < self.expected {
            self.metrics.stale = self.metrics.stale.saturating_add(1);
            return ArbiterVerdict::Stale;
        }
        if sequence == self.expected {
            self.record(&packet);
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
        if self.buffered.len() >= self.limits.max_buffered {
            let verdict = ArbiterVerdict::BufferFull { sequence };
            self.reject(packet, verdict.clone());
            return verdict;
        }
        let gap_opened = self.buffered.is_empty();
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
            self.record(&packet);
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
    use super::ArbiterLimits;
    use super::ArbiterVerdict;
    use super::FeedArbiter;
    use super::FeedChannel;
    use super::SequencedPacket;

    fn packet(channel: FeedChannel, sequence: u64, body: &str, at: i64) -> SequencedPacket {
        SequencedPacket {
            channel,
            sequence,
            payload: body.as_bytes().to_vec(),
            received_at_us: at,
        }
    }

    #[test]
    fn in_order_packet_is_accepted() {
        let mut arbiter = FeedArbiter::new(1);
        let verdict = arbiter.submit(packet(FeedChannel::Primary, 1, "one", 100));
        assert_eq!(
            verdict,
            ArbiterVerdict::Accepted,
            "expected packet accepted"
        );
        assert_eq!(arbiter.expected, 2, "expected sequence advanced");
        assert_eq!(
            arbiter.seen.get(&1).copied(),
            Some((FeedChannel::Primary, 100)),
            "seen entry records channel and arrival time"
        );
        assert_eq!(arbiter.gap_count, 0, "no gaps detected");
        assert_eq!(arbiter.metrics.accepted, 1, "accepted counter advances");
    }

    #[test]
    fn duplicate_across_channels_is_detected() {
        let mut arbiter = FeedArbiter::new(9);
        let first = arbiter.submit(packet(FeedChannel::Primary, 9, "a", 10));
        assert_eq!(first, ArbiterVerdict::Accepted, "sequence accepted");
        let second = arbiter.submit(packet(FeedChannel::Secondary, 9, "a", 20));
        assert_eq!(
            second,
            ArbiterVerdict::Duplicate,
            "other channel reports duplicate"
        );
        assert_eq!(arbiter.seen.len(), 1, "single seen entry retained");
        assert_eq!(arbiter.expected, 10, "duplicate leaves expected unchanged");
        assert_eq!(arbiter.metrics.duplicates, 1, "duplicate accounted");
    }

    #[test]
    fn gap_then_recovery_drains_buffered() {
        let mut arbiter = FeedArbiter::new(1);
        let first = arbiter.submit(packet(FeedChannel::Primary, 1, "1", 1));
        assert_eq!(first, ArbiterVerdict::Accepted, "first packet accepted");

        let gap = arbiter.submit(packet(FeedChannel::Primary, 4, "4", 4));
        assert_eq!(gap, ArbiterVerdict::Gap(2), "gap reports expected sequence");
        assert_eq!(arbiter.expected, 2, "gap leaves expected unchanged");
        assert_eq!(arbiter.gap_count, 1, "gap counter incremented");

        let ahead = arbiter.submit(packet(FeedChannel::Secondary, 3, "3", 3));
        assert_eq!(ahead, ArbiterVerdict::OutOfOrder, "ahead packet buffered");

        let recovered = arbiter.submit(packet(FeedChannel::Primary, 2, "2", 2));
        assert_eq!(
            recovered,
            ArbiterVerdict::Accepted,
            "missing packet accepted"
        );

        let drained = arbiter.drain_available();
        let sequences: Vec<u64> = drained.iter().map(|item| item.sequence).collect();
        assert_eq!(sequences, vec![3, 4], "buffered packets drain in order");
        assert_eq!(
            arbiter.expected, 5,
            "expected advanced past drained packets"
        );
        assert_eq!(arbiter.metrics.delayed, 2, "delayed packets accounted");
    }

    #[test]
    fn stale_packet_is_rejected() {
        let mut arbiter = FeedArbiter::new(5);
        let verdict = arbiter.submit(packet(FeedChannel::Secondary, 3, "old", 7));
        assert_eq!(
            verdict,
            ArbiterVerdict::Stale,
            "older unseen packet is stale"
        );
        assert_eq!(
            arbiter.expected, 5,
            "stale packet leaves expected unchanged"
        );
        assert!(arbiter.seen.is_empty(), "stale packet is not recorded");
        assert_eq!(arbiter.metrics.stale, 1, "stale packet accounted");
    }

    #[test]
    fn out_of_order_packets_drain_after_gap_fill() {
        let mut arbiter = FeedArbiter::new(1);
        let first = arbiter.submit(packet(FeedChannel::Primary, 3, "c", 3));
        assert_eq!(
            first,
            ArbiterVerdict::Gap(1),
            "first ahead packet opens gap"
        );
        let second = arbiter.submit(packet(FeedChannel::Primary, 2, "b", 2));
        assert_eq!(
            second,
            ArbiterVerdict::OutOfOrder,
            "second ahead packet buffered"
        );
        let fill = arbiter.submit(packet(FeedChannel::Secondary, 1, "a", 1));
        assert_eq!(fill, ArbiterVerdict::Accepted, "missing packet accepted");

        let drained = arbiter.drain_available();
        assert_eq!(drained.len(), 2, "two buffered packets drained");
        assert_eq!(drained[0].sequence, 2, "lower sequence drains first");
        assert_eq!(drained[1].sequence, 3, "higher sequence drains second");
        assert!(arbiter.drain_available().is_empty(), "drain is repeatable");
    }

    #[test]
    fn channel_labels_are_stable() {
        assert_eq!(FeedChannel::Primary.as_str(), "primary", "primary label");
        assert_eq!(
            FeedChannel::Secondary.as_str(),
            "secondary",
            "secondary label"
        );
    }

    #[test]
    fn duplicate_window_is_bounded_with_pruning_accounting() {
        let limits = ArbiterLimits {
            max_seen: 2,
            ..ArbiterLimits::default()
        };
        let mut arbiter = FeedArbiter::with_limits(1, limits).expect("valid limits");
        for sequence in 1..=4 {
            assert_eq!(
                arbiter.submit(packet(FeedChannel::Primary, sequence, "x", 0)),
                ArbiterVerdict::Accepted,
                "sequence {sequence} accepted"
            );
        }
        assert_eq!(arbiter.seen.len(), 2, "seen window respects bound");
        assert_eq!(arbiter.metrics.pruned_seen, 2, "prunes are accounted");
        assert!(!arbiter.seen.contains_key(&1), "oldest entry pruned");
    }

    #[test]
    fn buffer_full_rejects_with_preserved_evidence() {
        let limits = ArbiterLimits {
            max_buffered: 1,
            ..ArbiterLimits::default()
        };
        let mut arbiter = FeedArbiter::with_limits(1, limits).expect("valid limits");
        assert_eq!(
            arbiter.submit(packet(FeedChannel::Primary, 5, "five", 5)),
            ArbiterVerdict::Gap(1),
            "first ahead packet opens gap and fills buffer"
        );
        let verdict = arbiter.submit(packet(FeedChannel::Secondary, 6, "six", 6));
        assert_eq!(
            verdict,
            ArbiterVerdict::BufferFull { sequence: 6 },
            "full buffer rejects packet"
        );
        assert_eq!(arbiter.metrics.rejected, 1, "rejection accounted");
        let rejected = arbiter.rejected().next().expect("rejected evidence");
        assert_eq!(rejected.packet.sequence, 6, "original packet retained");
        assert_eq!(
            rejected.packet.payload,
            b"six".to_vec(),
            "original payload bytes retained"
        );
    }

    #[test]
    fn declared_maximum_gap_is_enforced() {
        let limits = ArbiterLimits {
            max_sequence_gap: 3,
            ..ArbiterLimits::default()
        };
        let mut arbiter = FeedArbiter::with_limits(10, limits).expect("valid limits");
        let verdict = arbiter.submit(packet(FeedChannel::Primary, 20, "far", 20));
        assert_eq!(
            verdict,
            ArbiterVerdict::GapExceeded {
                expected: 10,
                observed: 20,
            },
            "gap beyond declared maximum is rejected"
        );
        assert_eq!(arbiter.metrics.gap_exceeded, 1, "gap excess accounted");
        assert!(arbiter.buffered.is_empty(), "no packet buffered");
    }

    #[test]
    fn sequence_exhaustion_is_explicit() {
        let mut arbiter = FeedArbiter::new(u64::MAX);
        let verdict = arbiter.submit(packet(FeedChannel::Primary, u64::MAX, "last", 1));
        assert_eq!(
            verdict,
            ArbiterVerdict::SequenceExhausted { sequence: u64::MAX },
            "sequence exhaustion is reported"
        );
        assert!(arbiter.is_exhausted(), "arbiter is exhausted");
        assert_eq!(
            arbiter.metrics.sequence_exhausted, 1,
            "exhaustion accounted"
        );
    }

    #[test]
    fn rejected_evidence_ledger_is_bounded() {
        let limits = ArbiterLimits {
            max_sequence_gap: 1,
            max_rejected: 1,
            ..ArbiterLimits::default()
        };
        let mut arbiter = FeedArbiter::with_limits(1, limits).expect("valid limits");
        let first = arbiter.submit(packet(FeedChannel::Primary, 9, "a", 1));
        let second = arbiter.submit(packet(FeedChannel::Primary, 8, "b", 2));
        assert!(
            matches!(first, ArbiterVerdict::GapExceeded { .. }),
            "first far packet rejected"
        );
        assert!(
            matches!(second, ArbiterVerdict::GapExceeded { .. }),
            "second far packet rejected"
        );
        assert_eq!(
            arbiter.rejected().count(),
            1,
            "evidence ledger respects bound"
        );
        assert_eq!(
            arbiter.metrics.rejected_evidence_overflow, 1,
            "dropped evidence is accounted"
        );
    }

    #[test]
    fn memory_accounting_tracks_buffered_payload_bytes() {
        let mut arbiter = FeedArbiter::new(1);
        arbiter.submit(packet(FeedChannel::Primary, 4, "abcd", 4));
        let memory = arbiter.memory();
        assert_eq!(memory.seen_entries, 0, "ahead packet is not in seen window");
        assert_eq!(memory.buffered_entries, 1, "one packet buffered");
        assert_eq!(memory.buffered_bytes, 4, "payload bytes counted");
        assert!(memory.seen_bytes < 1_000, "fixed-size estimate stays small");
    }
}
