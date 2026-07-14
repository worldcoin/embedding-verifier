//! Runtime environment configuration.

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
        let environment = std::env::var("APP_ENV")
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
}
