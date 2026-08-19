//! Configuration for the verifier client.
//!
//! Follows the shape `world-id-protocol` uses for authenticator configuration. Configuration
//! is explicit — nothing is read from the environment.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::nitro::{EnclaveAttestationVerifier, PcrMeasurement};

/// Default freshness bound, matching the few-hour lifetime of a Nitro certificate.
const fn default_max_attestation_age_millis() -> u64 {
    60 * 60 * 1000
}

const fn default_connect_timeout_millis() -> u64 {
    5_000
}

const fn default_request_timeout_millis() -> u64 {
    10_000
}

/// An attestation document is a few kB.
const fn default_max_response_bytes() -> u64 {
    64 * 1024
}

/// Failures while building a [`Config`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A field was not usable.
    #[error("invalid {attribute}: {reason}")]
    InvalidInput {
        /// Which field.
        attribute: String,
        /// Why it was rejected.
        reason: String,
    },

    /// The JSON could not be parsed.
    #[error("failed to parse config: {0}")]
    Serialization(String),
}

/// Configuration to interact with an embedding verifier host.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Base URL of the host, e.g. `https://verifier.example.com`.
    host_url: Url,
    /// Measurements to trust. A document is accepted if it matches any one configuration in
    /// full, which lets several enclave versions be trusted at once during a rollout.
    allowed_pcr_configs: Vec<Vec<PcrMeasurement>>,
    /// How old an attestation document's own timestamp may be.
    #[serde(default = "default_max_attestation_age_millis")]
    max_attestation_age_millis: u64,
    /// Whether to accept `--debug-mode` enclaves, whose measurements are all zero and whose
    /// memory the parent instance can read. Development only.
    #[serde(default)]
    allow_debug_measurements: bool,
    /// Bound on establishing a connection.
    #[serde(default = "default_connect_timeout_millis")]
    connect_timeout_millis: u64,
    /// Bound on a whole request.
    #[serde(default = "default_request_timeout_millis")]
    request_timeout_millis: u64,
    /// Largest response body accepted.
    #[serde(default = "default_max_response_bytes")]
    max_response_bytes: u64,
}

impl Config {
    /// Instantiates a configuration with the default bounds.
    ///
    /// # Errors
    ///
    /// Returns an error if `host_url` is not a valid URL, or if no measurements are given —
    /// an empty policy would accept any genuine Nitro enclave, including somebody else's.
    pub fn new(
        host_url: &str,
        allowed_pcr_configs: Vec<Vec<PcrMeasurement>>,
    ) -> Result<Self, ConfigError> {
        let host_url = Url::parse(host_url).map_err(|error| ConfigError::InvalidInput {
            attribute: "host_url".to_string(),
            reason: error.to_string(),
        })?;

        let config = Self {
            host_url,
            allowed_pcr_configs,
            max_attestation_age_millis: default_max_attestation_age_millis(),
            allow_debug_measurements: false,
            connect_timeout_millis: default_connect_timeout_millis(),
            request_timeout_millis: default_request_timeout_millis(),
            max_response_bytes: default_max_response_bytes(),
        };
        config.validate()?;

        Ok(config)
    }

    /// Bounds how old an attestation document's own timestamp may be.
    #[must_use]
    pub fn with_max_attestation_age(mut self, max_age: Duration) -> Self {
        self.max_attestation_age_millis = u64::try_from(max_age.as_millis()).unwrap_or(u64::MAX);
        self
    }

    /// Accepts `--debug-mode` enclaves, whose memory the parent instance can read.
    ///
    /// Development only.
    #[must_use]
    pub const fn allowing_debug_measurements(mut self) -> Self {
        self.allow_debug_measurements = true;
        self
    }

    /// Loads a configuration from JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the JSON is invalid or the resulting configuration is not usable.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let config: Self = serde_json::from_str(json)
            .map_err(|error| ConfigError::Serialization(error.to_string()))?;
        config.validate()?;

        Ok(config)
    }

    /// Rejects configurations that would verify nothing.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.allowed_pcr_configs.iter().all(Vec::is_empty) {
            return Err(ConfigError::InvalidInput {
                attribute: "allowed_pcr_configs".to_string(),
                reason: "no measurements pinned, which would accept any Nitro enclave".to_string(),
            });
        }

        Ok(())
    }

    /// Builds a verifier applying this configuration's measurement policy.
    #[must_use]
    pub fn verifier(&self) -> EnclaveAttestationVerifier {
        let verifier = EnclaveAttestationVerifier::new(
            self.allowed_pcr_configs.clone(),
            self.max_attestation_age_millis,
        );

        if self.allow_debug_measurements {
            return verifier.allowing_debug_measurements();
        }

        verifier
    }

    /// The host to call.
    #[must_use]
    pub const fn host_url(&self) -> &Url {
        &self.host_url
    }

    /// Bound on establishing a connection.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_millis)
    }

    /// Bound on a whole request.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_millis)
    }

    /// Largest response body accepted.
    #[must_use]
    pub const fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Config, ConfigError, default_max_response_bytes};
    use crate::nitro::PcrMeasurement;

    fn pcrs() -> Vec<Vec<PcrMeasurement>> {
        vec![vec![PcrMeasurement::new(0, [0xabu8; 48])]]
    }

    #[test]
    fn rejects_a_configuration_that_pins_nothing() {
        let error = Config::new("http://localhost:8000", Vec::new())
            .expect_err("an empty policy must fail closed");

        assert!(matches!(error, ConfigError::InvalidInput { .. }));
    }

    #[test]
    fn rejects_an_invalid_host_url() {
        let error =
            Config::new("not a url", pcrs()).expect_err("an unparseable URL must be rejected");

        assert!(matches!(error, ConfigError::InvalidInput { .. }));
    }

    #[test]
    fn round_trips_through_json_with_defaults_applied() {
        let json = r#"{
            "host_url": "http://localhost:8000",
            "allowed_pcr_configs": [[{ "index": 0, "value": "abcd" }]]
        }"#;

        let config = Config::from_json(json).expect("config should parse");

        assert_eq!(config.max_response_bytes(), default_max_response_bytes());
        assert_eq!(config.request_timeout(), Duration::from_secs(10));
    }
}
