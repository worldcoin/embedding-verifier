//! Service configuration, resolved and validated once at startup.

use std::{env, fmt, num::ParseIntError, time::Duration};

const DEFAULT_PORT: u16 = 8000;
const DEFAULT_DOGSTATSD_PORT: u16 = 8125;
const DEFAULT_SHUTDOWN_DRAIN_SECONDS: u64 = 5;

/// Runtime environment for the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    /// Production environment.
    Production,
    /// Staging environment.
    Staging,
    /// Local development environment.
    Development,
}

impl Environment {
    /// Value used for the `env` tag on emitted metrics.
    ///
    /// Not the variant name: the org's Datadog convention is `stage`, and querying
    /// `env:staging` silently returns no data.
    #[must_use]
    pub const fn metric_tag(self) -> &'static str {
        match self {
            Self::Production => "prod",
            Self::Staging => "stage",
            Self::Development => "dev",
        }
    }
}

/// `DogStatsD` endpoint to publish metrics to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DogstatsdEndpoint {
    /// Agent host.
    pub host: String,
    /// Agent UDP port.
    pub port: u16,
}

/// Everything the API needs from its environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Runtime environment.
    pub environment: Environment,
    /// Port the HTTP listener binds.
    pub port: u16,
    /// vsock CID of the local enclave.
    pub enclave_cid: u32,
    /// Pontifex port the enclave serves on.
    pub enclave_port: u32,
    /// How long to keep serving after going unready, before graceful shutdown starts.
    pub shutdown_drain: Duration,
    /// Where to publish metrics. `None` disables publishing.
    pub dogstatsd: Option<DogstatsdEndpoint>,
}

impl Default for Config {
    /// Local-development defaults. Production values always come from the environment.
    fn default() -> Self {
        Self {
            environment: Environment::Development,
            port: DEFAULT_PORT,
            enclave_cid: 0,
            enclave_port: 0,
            shutdown_drain: Duration::from_secs(DEFAULT_SHUTDOWN_DRAIN_SECONDS),
            dogstatsd: None,
        }
    }
}

impl Config {
    /// Resolves configuration from the process environment.
    ///
    /// # Errors
    ///
    /// Returns every problem found, not just the first, so one restart surfaces the whole
    /// misconfiguration.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::resolve(&|name| env::var(name).ok())
    }

    fn resolve(source: &dyn Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut reader = Reader {
            source,
            problems: Vec::new(),
        };

        let environment = reader.environment();
        let port = reader.optional("PORT", DEFAULT_PORT);
        let cid = reader.required("ENCLAVE_CID");
        let enclave_port = reader.required("ENCLAVE_PORT");
        let drain = reader.optional("SHUTDOWN_DRAIN_SECONDS", DEFAULT_SHUTDOWN_DRAIN_SECONDS);
        let dogstatsd_port = reader.optional("DD_DOGSTATSD_PORT", DEFAULT_DOGSTATSD_PORT);
        let agent_host = reader.read("DD_AGENT_HOST");

        match (environment, port, cid, enclave_port, drain, dogstatsd_port) {
            (
                Some(environment),
                Some(port),
                Some(cid),
                Some(enclave_port),
                Some(drain),
                Some(dd),
            ) if reader.problems.is_empty() => Ok(Self {
                environment,
                port,
                enclave_cid: cid,
                enclave_port,
                shutdown_drain: Duration::from_secs(drain),
                dogstatsd: agent_host.map(|host| DogstatsdEndpoint { host, port: dd }),
            }),
            _ => Err(ConfigError {
                problems: reader.problems,
            }),
        }
    }
}

/// Problems that prevented configuration from resolving.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    problems: Vec<String>,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid configuration: {}",
            self.problems.join("; ")
        )
    }
}

impl std::error::Error for ConfigError {}

struct Reader<'a> {
    source: &'a dyn Fn(&str) -> Option<String>,
    problems: Vec<String>,
}

impl Reader<'_> {
    /// Reads a variable, treating blank values as absent.
    fn read(&self, name: &str) -> Option<String> {
        (self.source)(name)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }

    fn environment(&mut self) -> Option<Environment> {
        let Some(raw) = self.read("APP_ENV") else {
            return Some(Environment::Development);
        };

        match raw.to_lowercase().as_str() {
            "production" => Some(Environment::Production),
            "staging" => Some(Environment::Staging),
            "development" => Some(Environment::Development),
            other => {
                self.problems.push(format!(
                    "APP_ENV is '{other}', expected production, staging, or development"
                ));
                None
            }
        }
    }

    fn optional<T: std::str::FromStr<Err = ParseIntError>>(
        &mut self,
        name: &str,
        default: T,
    ) -> Option<T> {
        self.read(name)
            .map_or(Some(default), |raw| self.parse(name, &raw))
    }

    fn required<T: std::str::FromStr<Err = ParseIntError>>(&mut self, name: &str) -> Option<T> {
        if let Some(raw) = self.read(name) {
            return self.parse(name, &raw);
        }

        self.problems.push(format!("{name} is not set"));
        None
    }

    fn parse<T: std::str::FromStr<Err = ParseIntError>>(
        &mut self,
        name: &str,
        raw: &str,
    ) -> Option<T> {
        raw.parse()
            .map_err(|error| {
                self.problems
                    .push(format!("{name} is '{raw}', which is not a number: {error}"));
            })
            .ok()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{Config, ConfigError, Environment};

    fn resolve(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();

        Config::resolve(&move |name| map.get(name).cloned())
    }

    #[test]
    fn staging_tags_metrics_as_stage() {
        assert_eq!(Environment::Staging.metric_tag(), "stage");
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let error = resolve(&[("APP_ENV", "prod"), ("ENCLAVE_CID", "sixteen")])
            .expect_err("bad config should fail");

        let message = error.to_string();
        assert!(message.contains("APP_ENV is 'prod'"), "{message}");
        assert!(message.contains("ENCLAVE_CID is 'sixteen'"), "{message}");
        assert!(message.contains("ENCLAVE_PORT is not set"), "{message}");
    }

    #[test]
    fn optional_variables_fall_back_to_defaults() {
        let config = resolve(&[
            ("ENCLAVE_CID", "16"),
            ("ENCLAVE_PORT", "1000"),
            ("DD_AGENT_HOST", "  "),
        ])
        .expect("defaults should resolve");

        assert_eq!(config.environment, Environment::Development);
        assert_eq!(config.port, 8000);
        assert_eq!(config.shutdown_drain.as_secs(), 5);
        // Blank is treated as unset.
        assert!(config.dogstatsd.is_none());
    }
}
