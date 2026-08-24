//! Fetching the RP's challenge image.
//!
//! The caller names an object, not a destination: the bucket comes from configuration, so no
//! request can move the fetch somewhere else. That is what closes the SSRF surface spec §6 flags —
//! the host part of the URL is not an input.
//!
//! The id is a locator, not a capability. A caller presenting someone else's id gets a blob that
//! will not decrypt under the key in its own sealed payload, so nothing downstream treats the id
//! as authorization.

use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use futures_util::StreamExt as _;
use reqwest::redirect::Policy;
use url::Url;
use uuid::Uuid;

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CHALLENGE_BYTES: usize = 4 * 1024 * 1024;

/// Why a challenge image could not be fetched. Never the enclave's fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// The id was not a UUID.
    InvalidId,
    /// The request failed, timed out, or the bucket answered with an error status.
    Unreachable,
    /// The response exceeded [`MAX_CHALLENGE_BYTES`].
    TooLarge,
}

/// Where the host gets a challenge image.
#[async_trait]
pub trait ChallengeSource: Send + Sync {
    /// Fetches the challenge ciphertext stored under `id`.
    async fn fetch(&self, id: &str) -> Result<Vec<u8>, FetchError>;
}

/// Fetches challenge images from one configured bucket location.
#[derive(Debug, Clone)]
pub struct ChallengeFetcher {
    http: reqwest::Client,
    base_url: Url,
}

impl ChallengeFetcher {
    /// Builds a fetcher over `base_url`, which every fetch is resolved against.
    ///
    /// # Errors
    ///
    /// Returns an error when `base_url` is not HTTPS, does not end in `/`, or when the HTTP client
    /// cannot be built. The trailing slash matters: `Url::join` replaces the last path segment
    /// without it, so `…/challenges` would resolve ids as siblings of the prefix rather than
    /// inside it.
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        let base_url = Url::parse(base_url)
            .with_context(|| format!("challenge image base URL {base_url} does not parse"))?;

        anyhow::ensure!(
            base_url.scheme() == "https",
            "challenge image base URL must be https"
        );
        anyhow::ensure!(
            base_url.path().ends_with('/'),
            "challenge image base URL must end in /"
        );

        let http = reqwest::Client::builder()
            // A redirect off our own bucket is not something to follow.
            .redirect(Policy::none())
            .timeout(FETCH_TIMEOUT)
            .build()?;

        Ok(Self { http, base_url })
    }

    /// Resolves `id` against the configured base.
    ///
    /// Parsing as a UUID is what keeps an id an id: anything carrying a slash, an escape, or a
    /// scheme is refused before `join` sees it.
    fn object_url(&self, id: &str) -> Result<Url, FetchError> {
        let id = Uuid::try_parse(id).map_err(|_| FetchError::InvalidId)?;

        self.base_url
            .join(&id.as_hyphenated().to_string())
            .map_err(|_| FetchError::InvalidId)
    }
}

#[async_trait]
impl ChallengeSource for ChallengeFetcher {
    async fn fetch(&self, id: &str) -> Result<Vec<u8>, FetchError> {
        let url = self.object_url(id)?;

        let response = self.http.get(url).send().await.map_err(|error| {
            tracing::warn!(%error, dependency = "challenge_bucket", "challenge image fetch failed");
            FetchError::Unreachable
        })?;

        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                dependency = "challenge_bucket",
                "challenge image fetch returned an error status"
            );
            return Err(FetchError::Unreachable);
        }

        // Streamed against a running budget: `Content-Length` is the bucket's own claim, so a
        // lying or chunked response would otherwise allocate without limit.
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                tracing::warn!(
                    %error,
                    dependency = "challenge_bucket",
                    "challenge image stream failed"
                );
                FetchError::Unreachable
            })?;

            if body.len() + chunk.len() > MAX_CHALLENGE_BYTES {
                tracing::warn!(
                    limit = MAX_CHALLENGE_BYTES,
                    dependency = "challenge_bucket",
                    "challenge image exceeded the size limit"
                );
                return Err(FetchError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }

        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::{ChallengeFetcher, FetchError};

    const BASE: &str = "https://bucket.example.com/challenges/";
    const ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

    fn fetcher() -> ChallengeFetcher {
        ChallengeFetcher::new(BASE).expect("the base URL should build")
    }

    #[test]
    fn rejects_a_base_url_that_is_not_usable() {
        for base in [
            "not-a-url",
            "http://bucket.example.com/challenges/",
            // Without the trailing slash `join` would resolve ids alongside the prefix.
            "https://bucket.example.com/challenges",
        ] {
            assert!(ChallengeFetcher::new(base).is_err(), "{base}");
        }
    }

    #[test]
    fn resolves_an_id_inside_the_base() {
        assert_eq!(
            fetcher().object_url(ID).expect("a UUID should resolve"),
            format!("{BASE}{ID}").parse().expect("the URL should parse")
        );
    }

    #[test]
    fn accepts_an_uppercase_id() {
        assert_eq!(
            fetcher()
                .object_url(&ID.to_uppercase())
                .expect("a UUID should resolve"),
            format!("{BASE}{ID}").parse().expect("the URL should parse")
        );
    }

    #[test]
    fn rejects_anything_that_is_not_a_uuid() {
        // The traversal and absolute-URL cases cannot escape the base once the id parses as a
        // UUID; they are here so that stays true if the validation is ever loosened.
        for id in [
            "",
            "../secrets",
            "%2e%2e/secrets",
            "/etc/passwd",
            "https://attacker.example.com/x",
            &format!("{ID}/../../secrets"),
            &format!("{ID}extra"),
        ] {
            assert_eq!(
                fetcher().object_url(id).err(),
                Some(FetchError::InvalidId),
                "{id}"
            );
        }
    }
}
