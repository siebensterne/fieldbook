//! Fixed-bucket latency histograms for stage-specific performance evidence.
//!
//! Each boundary owns one [`Histogram`] of atomic bucket counters. Sampling is
//! allocation-free: [`Histogram::record`] reads a monotonic `Instant` elapsed
//! value, maps it to a fixed boundary with a bit-length calculation, and bumps
//! one counter. The histogram is shared by every worker that crosses the same
//! boundary, so there is exactly one set of raw counts to report.
//!
//! Percentiles are **nearest-rank estimates derived from the merged bucket
//! counts**, never averages of per-worker percentiles. A bucket represents the
//! half-open interval `(previous_bound, bound]`, so a reported percentile is
//! the inclusive upper bound of the bucket containing that rank. This is a
//! deliberate accuracy trade: compact, deterministic, mergeable counts instead
//! of a claim of exact ordering or nanosecond precision. The final bucket is
//! open-ended (overflow) and is represented by the observed maximum.
//!
//! Nanoseconds are the storage unit, not a precision claim. The clock's step
//! (measured per host in the stress manifest as `clock_resolution_ns`) can be
//! far coarser than a nanosecond, and scheduling or instrumentation overhead
//! can be far larger than the step. Timing claims must state the measured
//! clock resolution and the overhead model instead of assuming nanoseconds.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};

/// Largest power-of-two bucket boundary, in nanoseconds (2^33 ≈ 8.6 seconds).
pub const MAX_BUCKET_EXPONENT: u32 = 33;
/// Index of the open-ended overflow bucket.
pub const OVERFLOW_BUCKET_INDEX: usize = MAX_BUCKET_EXPONENT as usize + 1;
/// Total number of buckets: exponents 0..=33 plus one overflow bucket.
pub const BUCKET_COUNT: usize = OVERFLOW_BUCKET_INDEX + 1;
/// Minimum sample count before p99.99 is reported at all.
///
/// Four nines needs at least 10,000 samples for one observation in the top
/// 0.01%; reporting it from a smaller sample would imply resolution the data
/// does not have.
pub const P9999_MIN_SAMPLES: u64 = 10_000;

const fn bucket_bounds() -> [u64; BUCKET_COUNT] {
    let mut bounds = [0u64; BUCKET_COUNT];
    let mut index = 0usize;
    while index <= MAX_BUCKET_EXPONENT as usize {
        bounds[index] = 1u64 << index;
        index += 1;
    }
    bounds[OVERFLOW_BUCKET_INDEX] = u64::MAX;
    bounds
}

/// Inclusive upper bound of each bucket, in nanoseconds. The last entry is an
/// open-ended overflow bucket (`u64::MAX`).
pub const BUCKET_UPPER_BOUNDS_NS: [u64; BUCKET_COUNT] = bucket_bounds();

/// Map a duration in nanoseconds to a fixed bucket in constant time without
/// allocation. Buckets 1 through 33 cover values above the preceding power of
/// two and at or below the corresponding power. Bucket 0 covers `[0, 1]`; the
/// final bucket records overflow.
#[must_use]
pub fn bucket_index(ns: u64) -> usize {
    if ns <= 1 {
        return 0;
    }
    // ceil(log2(ns)) for ns > 1. `ns - 1` keeps exact powers of two in their
    // own bucket instead of rolling them into the next one.
    let index = (u64::BITS - (ns - 1).leading_zeros()) as usize;
    if index >= BUCKET_COUNT {
        OVERFLOW_BUCKET_INDEX
    } else {
        index
    }
}

/// Allocation-free, lock-free fixed-bucket histogram. Safe to share across
/// threads via [`Arc`]; all counters use relaxed atomics because timing samples
/// are evidence, not synchronization.
#[derive(Debug)]
pub struct Histogram {
    counts: [AtomicU64; BUCKET_COUNT],
    total: AtomicU64,
    min_ns: AtomicU64,
    max_ns: AtomicU64,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            total: AtomicU64::new(0),
            min_ns: AtomicU64::new(u64::MAX),
            max_ns: AtomicU64::new(0),
        }
    }
}

impl Histogram {
    /// Record one measured duration. Returns without allocating or blocking.
    pub fn record(&self, duration: Duration) {
        self.record_ns(u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX));
    }

    /// Record one duration already expressed in nanoseconds. Exposed for
    /// deterministic tests; production callers use [`Self::record`].
    pub fn record_ns(&self, ns: u64) {
        if let Some(counter) = self.counts.get(bucket_index(ns)) {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        self.total.fetch_add(1, Ordering::Relaxed);
        self.min_ns.fetch_min(ns, Ordering::Relaxed);
        self.max_ns.fetch_max(ns, Ordering::Relaxed);
    }

    /// Take a consistent-at-read-time snapshot of raw counts and derived
    /// percentiles. Intended for shutdown, manifest publication, or a metrics
    /// scrape — never for the hot path.
    #[must_use]
    pub fn report(&self) -> HistogramReport {
        let sample_count = self.total.load(Ordering::Relaxed);
        let min_ns = if sample_count == 0 {
            0
        } else {
            self.min_ns.load(Ordering::Relaxed)
        };
        let max_ns = self.max_ns.load(Ordering::Relaxed);
        let counts: Vec<u64> = self
            .counts
            .iter()
            .map(|count| count.load(Ordering::Relaxed))
            .collect();
        HistogramReport::from_counts(sample_count, min_ns, max_ns, counts)
    }
}

/// One raw bucket in a reported histogram.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketCount {
    /// Inclusive upper bound in nanoseconds; `u64::MAX` marks the overflow bucket.
    pub upper_bound_ns: u64,
    pub count: u64,
}

/// Serializable histogram evidence: explicit sample count, observed extremes,
/// nearest-rank percentiles from raw counts, and every bucket count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistogramReport {
    pub sample_count: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    /// Present only at [`P9999_MIN_SAMPLES`] samples or more.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p9999_ns: Option<u64>,
    /// Raw counts for all fixed buckets, including empty ones.
    pub buckets: Vec<BucketCount>,
}

impl HistogramReport {
    fn from_counts(sample_count: u64, min_ns: u64, max_ns: u64, counts: Vec<u64>) -> Self {
        let percentile = |numerator: u64, denominator: u64| {
            percentile_from_counts(&counts, sample_count, max_ns, numerator, denominator)
        };
        let buckets = BUCKET_UPPER_BOUNDS_NS
            .iter()
            .copied()
            .zip(counts.iter().copied())
            .map(|(upper_bound_ns, count)| BucketCount {
                upper_bound_ns,
                count,
            })
            .collect();
        Self {
            sample_count,
            min_ns,
            max_ns,
            p50_ns: percentile(50, 100),
            p90_ns: percentile(90, 100),
            p95_ns: percentile(95, 100),
            p99_ns: percentile(99, 100),
            p999_ns: percentile(999, 1_000),
            p9999_ns: (sample_count >= P9999_MIN_SAMPLES).then(|| percentile(9_999, 10_000)),
            buckets,
        }
    }

    /// Merge raw bucket counts from independent recorders and recompute every
    /// percentile from the merged distribution. This is the *only* valid way
    /// to combine workers: averaging worker percentiles is never performed.
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        let counts: Vec<u64> = self
            .buckets
            .iter()
            .zip(other.buckets.iter())
            .map(|(left, right)| left.count.saturating_add(right.count))
            .collect();
        let sample_count = self.sample_count.saturating_add(other.sample_count);
        let min_ns = match (self.sample_count, other.sample_count) {
            (0, 0) => 0,
            (0, _) => other.min_ns,
            (_, 0) => self.min_ns,
            _ => self.min_ns.min(other.min_ns),
        };
        let max_ns = self.max_ns.max(other.max_ns);
        Self::from_counts(sample_count, min_ns, max_ns, counts)
    }
}

/// Nearest-rank percentile from bucket counts. Rank is `ceil(p * n)`, clamped
/// to at least one. The reported value is the containing bucket's upper bound
/// (the observed maximum for the open overflow bucket).
fn percentile_from_counts(
    counts: &[u64],
    sample_count: u64,
    max_ns: u64,
    numerator: u64,
    denominator: u64,
) -> u64 {
    if sample_count == 0 {
        return 0;
    }
    let rank = numerator
        .saturating_mul(sample_count)
        .div_ceil(denominator)
        .max(1);
    let mut cumulative = 0u64;
    for (index, count) in counts.iter().enumerate() {
        cumulative = cumulative.saturating_add(*count);
        if cumulative >= rank {
            if index == OVERFLOW_BUCKET_INDEX {
                return max_ns;
            }
            return BUCKET_UPPER_BOUNDS_NS.get(index).copied().unwrap_or(max_ns);
        }
    }
    max_ns
}

/// Histograms owned by the serialized writer thread. The coordinator creates
/// these once and shares the same counters with the writer and the report.
#[derive(Debug, Clone, Default)]
pub struct WriterTimings {
    /// Message admission (queue enqueue) to writer dequeue.
    pub queue_wait: Arc<Histogram>,
    /// Time inside `MessageSink::write`.
    pub sbe_write: Arc<Histogram>,
    /// Time inside `MessageSink::flush`.
    pub flush: Arc<Histogram>,
}

/// All measured stage boundaries for one run. Shared by the core, writer,
/// journal, and report so a single set of raw counts is published.
#[derive(Debug, Clone, Default)]
pub struct StageTimings {
    /// Core admission to state transition (`CollectorCore::handle_event`).
    pub core_processing: Arc<Histogram>,
    pub writer: WriterTimings,
    /// Journal segment append. `None` when the journal is not enabled.
    pub journal_append: Option<Arc<Histogram>>,
}

/// A boundary is either measured with an explicit sample count, or explicitly
/// unavailable with a reason. An unexercised boundary is never reported as 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StageHistogram {
    Measured { report: HistogramReport },
    Unavailable { reason: String },
}

/// Serializable view of all five boundaries for a run report or manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageTimingReport {
    pub core_processing: StageHistogram,
    pub writer_queue_wait: StageHistogram,
    pub sbe_write: StageHistogram,
    pub flush: StageHistogram,
    pub journal_append: StageHistogram,
}

fn stage(histogram: &Arc<Histogram>, unmeasured_reason: &str) -> StageHistogram {
    let report = histogram.report();
    if report.sample_count == 0 {
        StageHistogram::Unavailable {
            reason: unmeasured_reason.to_owned(),
        }
    } else {
        StageHistogram::Measured { report }
    }
}

impl StageTimings {
    #[must_use]
    pub fn report(&self) -> StageTimingReport {
        let journal_append = match &self.journal_append {
            None => StageHistogram::Unavailable {
                reason: "journal append boundary not enabled for this run".to_owned(),
            },
            Some(histogram) => stage(
                histogram,
                "journal enabled but no records were appended in this run",
            ),
        };
        StageTimingReport {
            core_processing: stage(
                &self.core_processing,
                "no core-processing samples recorded in this run",
            ),
            writer_queue_wait: stage(
                &self.writer.queue_wait,
                "no writer queue-wait samples recorded in this run",
            ),
            sbe_write: stage(
                &self.writer.sbe_write,
                "no SBE write samples recorded in this run",
            ),
            flush: stage(&self.writer.flush, "no flush samples recorded in this run"),
            journal_append,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recorded(values: &[u64]) -> Histogram {
        let histogram = Histogram::default();
        for value in values {
            histogram.record_ns(*value);
        }
        histogram
    }

    #[test]
    fn bucket_boundaries_are_closed_and_disjoint() {
        assert_eq!(bucket_index(0), 0);
        assert_eq!(bucket_index(1), 0);
        for exponent in 0..=MAX_BUCKET_EXPONENT {
            let bound = 1u64 << exponent;
            assert_eq!(bucket_index(bound), exponent as usize);
            if exponent < MAX_BUCKET_EXPONENT {
                assert_eq!(bucket_index(bound + 1), exponent as usize + 1);
            }
        }
        assert_eq!(
            bucket_index(1u64 << MAX_BUCKET_EXPONENT),
            MAX_BUCKET_EXPONENT as usize
        );
        assert_eq!(
            bucket_index((1u64 << MAX_BUCKET_EXPONENT) + 1),
            OVERFLOW_BUCKET_INDEX
        );
        assert_eq!(bucket_index(u64::MAX), OVERFLOW_BUCKET_INDEX);
        assert_eq!(BUCKET_UPPER_BOUNDS_NS[OVERFLOW_BUCKET_INDEX], u64::MAX);
    }

    #[test]
    fn percentiles_are_nearest_rank_from_bucket_counts() {
        let values: Vec<u64> = (1..=100).collect();
        let report = recorded(&values).report();
        assert_eq!(report.sample_count, 100);
        assert_eq!(report.min_ns, 1);
        assert_eq!(report.max_ns, 100);
        // 100 samples: rank 50 is in the (32, 64] bucket; rank 90+ in (64, 128].
        assert_eq!(report.p50_ns, 64);
        assert_eq!(report.p90_ns, 128);
        assert_eq!(report.p95_ns, 128);
        assert_eq!(report.p99_ns, 128);
        assert_eq!(report.p999_ns, 128);
        assert_eq!(report.p9999_ns, None);
        let counted: u64 = report.buckets.iter().map(|bucket| bucket.count).sum();
        assert_eq!(counted, 100);
        assert_eq!(report.buckets.len(), BUCKET_COUNT);
        assert_eq!(report.buckets[0].upper_bound_ns, 1);
        assert_eq!(
            report.buckets[OVERFLOW_BUCKET_INDEX].upper_bound_ns,
            u64::MAX
        );
    }

    #[test]
    fn empty_histogram_has_no_samples_and_no_percentiles() {
        let report = Histogram::default().report();
        assert_eq!(report.sample_count, 0);
        assert_eq!(report.min_ns, 0);
        assert_eq!(report.max_ns, 0);
        assert_eq!(report.p50_ns, 0);
        assert_eq!(report.p9999_ns, None);
        assert!(report.buckets.iter().all(|bucket| bucket.count == 0));
    }

    #[test]
    fn overflow_bucket_uses_the_observed_maximum() {
        let report = recorded(&[u64::MAX]).report();
        assert_eq!(report.sample_count, 1);
        assert_eq!(report.buckets[OVERFLOW_BUCKET_INDEX].count, 1);
        assert_eq!(report.p50_ns, u64::MAX);
        assert_eq!(report.p999_ns, u64::MAX);
    }

    #[test]
    fn p9999_requires_ten_thousand_samples() {
        let few = (0..P9999_MIN_SAMPLES - 1).map(|_| 8u64).collect::<Vec<_>>();
        assert_eq!(recorded(&few).report().p9999_ns, None);
        let enough = (0..P9999_MIN_SAMPLES).map(|_| 8u64).collect::<Vec<_>>();
        let report = recorded(&enough).report();
        assert_eq!(report.sample_count, P9999_MIN_SAMPLES);
        assert_eq!(report.p9999_ns, Some(8));
    }

    #[test]
    fn merge_recomputes_percentiles_from_raw_counts() {
        let first: Vec<u64> = (1..=50).collect();
        let second: Vec<u64> = (51..=100).collect();
        let merged = recorded(&first).report().merge(&recorded(&second).report());
        let single = recorded(&(1..=100).collect::<Vec<_>>()).report();
        assert_eq!(merged, single);
        assert_eq!(merged.sample_count, 100);
        // Never the mean of the workers' percentiles (32 and 96 here).
        assert_eq!(merged.p50_ns, 64);
    }

    #[test]
    fn unmeasured_boundaries_carry_a_reason_not_a_zero() {
        let report = StageTimings::default().report();
        for boundary in [
            &report.core_processing,
            &report.writer_queue_wait,
            &report.sbe_write,
            &report.flush,
            &report.journal_append,
        ] {
            match boundary {
                StageHistogram::Unavailable { reason } => assert!(!reason.is_empty()),
                StageHistogram::Measured { .. } => {
                    panic!("unexercised boundary must be unavailable")
                }
            }
        }
        assert!(
            serde_json::to_value(&report)
                .expect("serialize")
                .to_string()
                .contains("unavailable")
        );
    }

    #[test]
    fn measured_boundaries_report_explicit_sample_counts() {
        let mut timings = StageTimings::default();
        timings.core_processing.record(Duration::from_nanos(4));
        timings.writer.queue_wait.record(Duration::from_nanos(16));
        timings.writer.sbe_write.record(Duration::from_nanos(2));
        timings.writer.flush.record(Duration::from_nanos(32));
        timings.journal_append = Some(Arc::new(Histogram::default()));
        let report = timings.report();
        for boundary in [
            &report.core_processing,
            &report.writer_queue_wait,
            &report.sbe_write,
            &report.flush,
        ] {
            match boundary {
                StageHistogram::Measured { report } => assert_eq!(report.sample_count, 1),
                StageHistogram::Unavailable { .. } => panic!("recorded boundary must be measured"),
            }
        }
        assert!(matches!(
            report.journal_append,
            StageHistogram::Unavailable { .. }
        ));
    }
}
