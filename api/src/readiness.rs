//! Readiness state: what must hold before this instance accepts traffic.
//!
//! Deliberately separate from liveness. An unreachable enclave means "stop routing to me",
//! not "restart me" — conflating the two turns a dependency blip into a crash loop.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde::Serialize;
use tokio::task::JoinHandle;

use crate::enclave::EnclaveClient;
use crate::telemetry::{FailureClass, Metrics, metrics};

/// Probing on a timer rather than per request keeps kubelet probe traffic off the vsock
/// path and bounds `/readyz` latency independently of enclave latency.
const ENCLAVE_PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// A condition that must hold for this instance to serve traffic.
///
/// Later work adds `KeysRegistered` and `BundleActive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// The local enclave answered its last health probe.
    EnclaveReachable,
}

impl Condition {
    /// Every condition, in reporting order.
    pub const ALL: [Self; 1] = [Self::EnclaveReachable];

    /// Stable name, used in the `/readyz` body and as a metric tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EnclaveReachable => "enclave_reachable",
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::EnclaveReachable => 0,
        }
    }
}

/// Shared readiness state. Conditions start unmet, so a booting process is never ready.
#[derive(Debug)]
pub struct Readiness {
    conditions: [AtomicBool; Condition::ALL.len()],
    draining: AtomicBool,
}

impl Default for Readiness {
    fn default() -> Self {
        Self::new()
    }
}

impl Readiness {
    /// Creates state with every condition unmet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            conditions: [AtomicBool::new(false)],
            draining: AtomicBool::new(false),
        }
    }

    /// Records whether a condition holds, returning `true` if this changed it.
    pub fn set(&self, condition: Condition, met: bool) -> bool {
        self.conditions[condition.index()].swap(met, Ordering::Relaxed) != met
    }

    /// Whether a condition currently holds.
    #[must_use]
    pub fn is_met(&self, condition: Condition) -> bool {
        self.conditions[condition.index()].load(Ordering::Relaxed)
    }

    /// Marks the process as draining, which makes it permanently unready.
    pub fn begin_draining(&self) {
        self.draining.store(true, Ordering::Relaxed);
    }

    /// Whether the process is shutting down.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Relaxed)
    }

    /// Whether this instance should receive traffic.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        !self.is_draining()
            && Condition::ALL
                .iter()
                .all(|condition| self.is_met(*condition))
    }

    /// Point-in-time view for the `/readyz` body.
    #[must_use]
    pub fn report(&self) -> ReadinessReport {
        ReadinessReport {
            ready: self.is_ready(),
            draining: self.is_draining(),
            unmet: Condition::ALL
                .iter()
                .filter(|condition| !self.is_met(**condition))
                .map(|condition| condition.as_str())
                .collect(),
        }
    }
}

/// Why an instance is or is not ready, so a failing probe is self-explaining.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReadinessReport {
    /// Whether traffic should be routed here.
    pub ready: bool,
    /// Whether the process is shutting down.
    pub draining: bool,
    /// Conditions that do not currently hold.
    pub unmet: Vec<&'static str>,
}

/// Probes the enclave on a timer and publishes the result into [`Readiness`].
///
/// Failures are logged on transition only; the per-probe signal lives in metrics.
pub fn spawn_enclave_prober(
    client: Arc<dyn EnclaveClient>,
    readiness: Arc<Readiness>,
    metrics: Arc<Metrics>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ENCLAVE_PROBE_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            probe_once(client.as_ref(), readiness.as_ref(), metrics.as_ref()).await;
        }
    })
}

async fn probe_once(client: &dyn EnclaveClient, readiness: &Readiness, metrics: &Metrics) {
    let started = Instant::now();
    let result = client.health().await;
    metrics.timing(metrics::ENCLAVE_PROBE_LATENCY, started.elapsed(), &[]);

    match result {
        Ok(()) => {
            metrics.count(
                metrics::ENCLAVE_PROBE,
                &[("result", "ok"), ("class", "none")],
            );
            if readiness.set(Condition::EnclaveReachable, true) {
                tracing::warn!("enclave became reachable — instance is ready");
            }
        }
        Err(error) => {
            let class = FailureClass::from(&error);
            metrics.count(
                metrics::ENCLAVE_PROBE,
                &[("result", "error"), ("class", class.as_str())],
            );
            if readiness.set(Condition::EnclaveReachable, false) {
                tracing::error!(
                    ?error,
                    class = class.as_str(),
                    "enclave became unreachable — instance is unready"
                );
            }
        }
    }

    metrics.gauge(
        metrics::READINESS_READY,
        u64::from(readiness.is_ready()),
        &[],
    );
    for condition in Condition::ALL {
        metrics.gauge(
            metrics::READINESS_CONDITION,
            u64::from(readiness.is_met(condition)),
            &[("condition", condition.as_str())],
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;
    use enclave_types::{GetTransitKeyResponse, MatchRequest, MatchResponse};

    use super::{Condition, Readiness, probe_once};
    use crate::enclave::{EnclaveClient, EnclaveClientError};
    use crate::telemetry::Metrics;

    #[derive(Default)]
    struct StubEnclave {
        healthy: AtomicBool,
    }

    #[async_trait]
    impl EnclaveClient for StubEnclave {
        async fn health(&self) -> Result<(), EnclaveClientError> {
            if self.healthy.load(Ordering::Relaxed) {
                Ok(())
            } else {
                Err(EnclaveClientError::Transport("unreachable".to_owned()))
            }
        }

        async fn get_transit_key(&self) -> Result<GetTransitKeyResponse, EnclaveClientError> {
            unimplemented!()
        }

        async fn run_match(&self, _: MatchRequest) -> Result<MatchResponse, EnclaveClientError> {
            unimplemented!()
        }
    }

    #[test]
    fn a_fresh_instance_is_not_ready() {
        let readiness = Readiness::new();

        assert!(!readiness.is_ready());
        assert_eq!(readiness.report().unmet, vec!["enclave_reachable"]);
    }

    #[test]
    fn draining_overrides_met_conditions() {
        let readiness = Readiness::new();
        readiness.set(Condition::EnclaveReachable, true);

        readiness.begin_draining();

        assert!(!readiness.is_ready());
        // The enclave is still fine; we are the ones going away.
        assert!(readiness.report().unmet.is_empty());
    }

    #[tokio::test]
    async fn probes_move_readiness_in_both_directions() {
        let readiness = Readiness::new();
        let metrics = Metrics::disabled();
        let enclave = StubEnclave::default();

        enclave.healthy.store(true, Ordering::Relaxed);
        probe_once(&enclave, &readiness, &metrics).await;
        assert!(readiness.is_ready());

        enclave.healthy.store(false, Ordering::Relaxed);
        probe_once(&enclave, &readiness, &metrics).await;
        assert!(!readiness.is_ready());
    }
}
