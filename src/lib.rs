//! Fieldbook library root organised by domain.
//!
//! Domain modules own their implementations. Crate-root re-exports preserve
//! the existing public paths for collectors, tests and offline tools.

pub mod acquisition;
pub mod distribution;
pub mod domain;
pub mod governance;
pub mod integrity;
pub mod market_state;
pub mod storage;
pub mod util;

pub use acquisition::egress;
pub use acquisition::exchange;
pub use acquisition::session;
pub use acquisition::ws;
pub use distribution::cli;
pub use distribution::coordinator;
pub use distribution::inspect;
pub use distribution::metrics;
pub use distribution::probe;
pub use domain::canonical;
pub use domain::event_model;
pub use domain::fixed;
pub use domain::identity;
pub use domain::information;
pub use domain::model;
pub use domain::products;
pub use domain::reference_data;
pub use domain::side;
pub use domain::taxonomy;
pub use governance::adapter;
pub use governance::config;
pub use governance::coverage_certification;
pub use governance::modality;
pub use governance::rights;
pub use integrity::completeness;
pub use integrity::conformance;
pub use integrity::coverage;
pub use integrity::journal;
pub use integrity::latency;
pub use integrity::quality;
pub use integrity::replay;
pub use integrity::time;
pub use integrity::verify;
pub use market_state::collector;
pub use market_state::histogram;
pub use market_state::orderbook;
pub use market_state::protocol;
pub use market_state::recovery;
pub use storage::analytics;
pub use storage::application;
pub use storage::capacity;
pub use storage::catalog;
pub use storage::persistence;
pub use storage::report;
pub use storage::writer;

pub use side::{InvalidSide, Side};
