//! Runtime environment configuration.

use std::env;

/// Length of a Nitro PCR0, which is a SHA-384 digest.
const PCR0_LEN: usize = 48;

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

/// Store backing the `Signing Key` registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRegistryStore {
    /// `DynamoDB` table named by `KEY_REGISTRY_TABLE`.
    DynamoDb,
    /// Process-local map that dies with the host.
    InMemory,
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

    /// Returns the store backing the `Signing Key` registry.
    ///
    /// Defaults to `DynamoDB`, so a host that names no store fails on the missing table instead
    /// of serving from a registry that dies with the process.
    ///
    /// # Panics
    ///
    /// Panics when `KEY_REGISTRY` is not `dynamodb` or `in-memory`, and when `in-memory` is
    /// selected outside development.
    #[must_use]
    pub fn key_registry(&self) -> KeyRegistryStore {
        let store = env::var("KEY_REGISTRY")
            .unwrap_or_else(|_| "dynamodb".to_owned())
            .trim()
            .to_lowercase();

        let store = match store.as_str() {
            "dynamodb" => KeyRegistryStore::DynamoDb,
            "in-memory" => KeyRegistryStore::InMemory,
            _ => panic!("invalid KEY_REGISTRY: {store}"),
        };

        assert!(
            store == KeyRegistryStore::DynamoDb || *self == Self::Development,
            "KEY_REGISTRY=in-memory is development-only"
        );

        store
    }

    /// Returns the `DynamoDB` table holding the `Signing Key` registry.
    ///
    /// # Panics
    ///
    /// Panics when `KEY_REGISTRY_TABLE` is unset or empty.
    #[must_use]
    pub fn key_registry_table(&self) -> String {
        let table = Self::required("KEY_REGISTRY_TABLE");

        assert!(
            !table.trim().is_empty(),
            "KEY_REGISTRY_TABLE environment variable is empty"
        );

        table
    }

    /// Returns the PCR0 this host's enclave must attest.
    ///
    /// The measurement of the image the host was deployed with, so an enclave running anything
    /// else never reaches the registry.
    ///
    /// # Panics
    ///
    /// Panics when `ENCLAVE_PCR0` is unset, is not hex, or is not 48 bytes.
    #[must_use]
    pub fn enclave_pcr0(&self) -> Vec<u8> {
        let value = Self::required("ENCLAVE_PCR0");
        let value = value.trim();
        let digits = value.strip_prefix("0x").unwrap_or(value);

        let pcr0 = hex::decode(digits)
            .unwrap_or_else(|_| panic!("ENCLAVE_PCR0 environment variable is not hex"));

        // A shorter value is hex that decodes fine and then matches no enclave, which would show
        // up as registration retrying a misconfiguration forever with readiness red.
        assert!(
            pcr0.len() == PCR0_LEN,
            "ENCLAVE_PCR0 is {} bytes, not {PCR0_LEN}",
            pcr0.len()
        );

        pcr0
    }

    /// Whether to accept a `--debug-mode` enclave, whose measurements are all zero.
    ///
    /// # Panics
    ///
    /// Panics outside development. A debug-mode enclave's memory is readable from the parent
    /// instance, so its attestation says nothing about what ran.
    #[must_use]
    pub fn allow_debug_measurements(&self) -> bool {
        let allowed = env::var("ALLOW_DEBUG_MEASUREMENTS")
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case("true"));

        assert!(
            !allowed || *self == Self::Development,
            "ALLOW_DEBUG_MEASUREMENTS is development-only"
        );

        allowed
    }

    fn required(name: &str) -> String {
        env::var(name).unwrap_or_else(|_| panic!("{name} environment variable is not set"))
    }

    fn required_u32(name: &str) -> u32 {
        Self::required(name)
            .parse()
            .unwrap_or_else(|_| panic!("{name} environment variable is not a valid u32"))
    }
}
