// SPDX-License-Identifier: Apache-2.0
//! Decode-interchange versus typed-normalization benchmark.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    reason = "benchmarks print measured timings and use deterministic fixtures"
)]
#![allow(
    clippy::allow_attributes,
    reason = "benchmark crates relax the production lint set wholesale"
)]

//! Run with `cargo bench --bench codec_normalization`. The harness is
//! `std`-only (`harness = false`). Both workloads decode the same deterministic
//! payload; one stops at the JSON interchange representation and the other
//! produces typed domain records with a raw-record reference. Timings are
//! measured, not targets.

use std::time::Instant;

use fieldbook::{
    acquisition::codec::{CodecRegistry, DecodeStatus, DecodedObservation, FeedCodec},
    util::sha256_hex,
};

struct TradeCodec;

impl FeedCodec for TradeCodec {
    fn decode(&self, payload: &[u8]) -> anyhow::Result<Vec<DecodedObservation>> {
        Ok(vec![DecodedObservation {
            packet_id: String::new(),
            source: String::new(),
            schema_version: 0,
            kind: "trade".to_owned(),
            payload_json: String::from_utf8(payload.to_vec())?,
            status: DecodeStatus::Decoded,
            reason: None,
        }])
    }

    fn schema_version(&self) -> u32 {
        1
    }
}

fn main() {
    let iterations: usize = std::env::var("CODEC_BENCH_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(50_000);
    let payload =
        b"{\"trade_id\":\"bench-1\",\"price_mantissa\":123456,\"quantity_mantissa\":789}".to_vec();
    let digest = sha256_hex(&payload);
    let mut registry = CodecRegistry::new();
    registry
        .register("bench", Box::new(TradeCodec))
        .expect("register");

    let started = Instant::now();
    for index in 0..iterations {
        let batch = registry
            .decode(&format!("bench-{index}"), "bench", 1, &payload)
            .expect("decode");
        assert_eq!(
            batch.accepted.len(),
            1,
            "interchange decode produces one record"
        );
    }
    let interchange = started.elapsed();

    let started = Instant::now();
    for index in 0..iterations {
        let events = registry
            .decode_normalized(&format!("bench-{index}"), "bench", 1, &payload)
            .expect("normalized decode");
        assert_eq!(events.len(), 1, "typed decode produces one record");
        assert_eq!(
            events[0].raw.sha256, digest,
            "raw reference digest is retained"
        );
    }
    let typed = started.elapsed();

    println!("iterations: {iterations}");
    println!("json_interchange_total: {:?}", interchange);
    println!("typed_normalized_total: {:?}", typed);
    println!(
        "json_interchange_per_op_ns: {}",
        interchange.as_nanos() / iterations as u128
    );
    println!(
        "typed_normalized_per_op_ns: {}",
        typed.as_nanos() / iterations as u128
    );
}
