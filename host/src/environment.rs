//! Runtime environment configuration.

use std::env;

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
    /// Resolves the runtime environment from `APP_ENV`.
    ///
    /// Defaults to development when `APP_ENV` is unset.
    ///
    /// # Panics
    ///
    /// Panics when `APP_ENV` is not `development`, `staging`, or `production`.
    #[must_use]
    pub fn from_env() -> Self {
        let environment = env::var("APP_ENV")
            .unwrap_or_else(|_| "development".to_owned())
            .trim()
            .to_lowercase();

        match environment.as_str() {
            "production" => Self::Production,
            "staging" => Self::Staging,
            "development" => Self::Development,
            _ => panic!("invalid APP_ENV: {environment}"),
        }
    }

    /// Returns the configured Nitro enclave CID.
    ///
    /// # Panics
    ///
    /// Panics when `ENCLAVE_CID` is unset or is not a valid `u32`.
    #[must_use]
    pub fn enclave_cid(&self) -> u32 {
        Self::required_u32("ENCLAVE_CID")
    }

    /// Returns the configured enclave Pontifex port.
    ///
    /// # Panics
    ///
    /// Panics when `ENCLAVE_PORT` is unset or is not a valid `u32`.
    #[must_use]
    pub fn enclave_port(&self) -> u32 {
        Self::required_u32("ENCLAVE_PORT")
    }

    /// Returns the allowlisted challenge-image locations, as `host/key-prefix` entries.
    ///
    /// # Panics
    ///
    /// Panics when `CHALLENGE_IMAGE_ALLOWLIST` is unset or holds no entry. There is no safe
    /// default: a fetcher that pins nothing would fetch from anywhere a caller names.
    #[must_use]
    pub fn challenge_image_allowlist(&self) -> Vec<String> {
        let raw = env::var("CHALLENGE_IMAGE_ALLOWLIST").unwrap_or_else(|_| {
            panic!("CHALLENGE_IMAGE_ALLOWLIST environment variable is not set")
        });
        let entries: Vec<String> = raw
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        assert!(
            !entries.is_empty(),
            "CHALLENGE_IMAGE_ALLOWLIST is empty; refusing to fetch challenge images from anywhere"
        );

        entries
    }

    fn required_u32(name: &str) -> u32 {
        env::var(name)
            .unwrap_or_else(|_| panic!("{name} environment variable is not set"))
            .parse()
            .unwrap_or_else(|_| panic!("{name} environment variable is not a valid u32"))
    }
}
