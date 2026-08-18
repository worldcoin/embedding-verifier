//! Metrics facade over `DogStatsD`.
//!
//! Publishing is best-effort: a metric never blocks or fails a request, and is discarded
//! entirely when no agent is configured.

use std::{net::UdpSocket, time::Duration};

use cadence::{
    Counted, Gauged, Metric, MetricBuilder, NopMetricSink, StatsdClient, Timed, UdpMetricSink,
};

use crate::config::Config;

const PREFIX: &str = "embedding_verifier.api";

/// Enclave readiness probe outcome. Tags: `result`, `class`.
pub const ENCLAVE_PROBE: &str = "enclave.probe";
/// Enclave readiness probe round-trip time.
pub const ENCLAVE_PROBE_LATENCY: &str = "enclave.probe.latency";
/// Whether a readiness condition holds, `1` or `0`. Tag: `condition`.
pub const READINESS_CONDITION: &str = "readiness.condition";
/// Whether the process is serving traffic, `1` or `0`.
pub const READINESS_READY: &str = "readiness.ready";
/// Completed HTTP request. Tags: `route`, `status`, `class`.
pub const HTTP_REQUEST: &str = "http.request";
/// Server-side HTTP request latency. Tag: `route`.
pub const HTTP_REQUEST_LATENCY: &str = "http.request.latency";
/// Transit-key fetch outcome. Tags: `result`, `class`.
pub const TRANSIT_KEY: &str = "transit_key";

/// Publishes metrics to a `DogStatsD` agent, or nowhere when unconfigured.
#[derive(Debug)]
pub struct Metrics {
    client: StatsdClient,
}

impl Metrics {
    /// Builds a publisher from configuration, tagging every metric with `env` and `service`.
    ///
    /// # Errors
    ///
    /// Returns an error when an endpoint is configured but its socket cannot be opened —
    /// better to fail the boot than to start up silently blind.
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let builder = if let Some(endpoint) = &config.dogstatsd {
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            // Dropping a datagram beats stalling a request path.
            socket.set_nonblocking(true)?;
            let sink = UdpMetricSink::from((endpoint.host.as_str(), endpoint.port), socket)?;
            StatsdClient::builder(PREFIX, sink)
        } else {
            tracing::warn!("DD_AGENT_HOST is unset — metrics are not being published");
            StatsdClient::builder(PREFIX, NopMetricSink)
        };

        Ok(Self {
            client: builder
                .with_tag("env", config.environment.metric_tag())
                .with_tag("service", "embedding-verifier-api")
                .with_error_handler(|error| tracing::warn!(%error, "failed to publish a metric"))
                .build(),
        })
    }

    /// Builds a publisher that discards everything.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            client: StatsdClient::from_sink(PREFIX, NopMetricSink),
        }
    }

    /// Builds a publisher that records what it emits, alongside the recording.
    #[cfg(test)]
    #[must_use]
    pub fn recording() -> (Self, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        let emitted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = RecordingSink {
            emitted: std::sync::Arc::clone(&emitted),
        };

        (
            Self {
                client: StatsdClient::from_sink(PREFIX, sink),
            },
            emitted,
        )
    }

    /// Increments a counter.
    pub fn count(&self, name: &str, tags: &[(&str, &str)]) {
        send(self.client.count_with_tags(name, 1), tags);
    }

    /// Records a duration.
    pub fn timing(&self, name: &str, elapsed: Duration, tags: &[(&str, &str)]) {
        send(self.client.time_with_tags(name, elapsed), tags);
    }

    /// Records a point-in-time value.
    pub fn gauge(&self, name: &str, value: u64, tags: &[(&str, &str)]) {
        send(self.client.gauge_with_tags(name, value), tags);
    }
}

/// Applies tags and dispatches. Errors reach the client's error handler, never the caller.
fn send<'a, T>(mut builder: MetricBuilder<'a, '_, T>, tags: &'a [(&'a str, &'a str)])
where
    T: Metric + From<String>,
{
    for (key, value) in tags {
        builder = builder.with_tag(key, value);
    }
    builder.send();
}

#[cfg(test)]
struct RecordingSink {
    emitted: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

#[cfg(test)]
impl cadence::MetricSink for RecordingSink {
    fn emit(&self, metric: &str) -> std::io::Result<usize> {
        self.emitted
            .lock()
            .expect("metrics mutex should not be poisoned")
            .push(metric.to_owned());

        Ok(metric.len())
    }
}
