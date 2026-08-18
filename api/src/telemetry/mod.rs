//! Telemetry: failure classification, metrics, and request correlation.

pub mod failure;
pub mod http;
pub mod metrics;

pub use failure::FailureClass;
pub use metrics::Metrics;
