//! Fetching the RP's challenge image.
//!
//! The one place the host fetches a caller-supplied URL (SSRF surface). A substituted URL fails
//! closed in the enclave, which holds the challenge key.
//!
//! TODO(SSRF): no destination allowlist — any HTTPS domain in `challenge_image_url` is fetched.
//! Bounds below (HTTPS, no IP literals/userinfo/redirects, 5s/4 MiB caps) limit blast radius but
//! do not pin where a fetch may go. Before untrusted callers: re-add `CHALLENGE_IMAGE_ALLOWLIST`,
//! force uploads to a bucket we own, or verify presigned URLs.

use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt as _;
use reqwest::redirect::Policy;
use url::{Host, Url};

/// How long the whole fetch may take, connection included.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on the challenge image, enforced while streaming rather than after.
const MAX_CHALLENGE_BYTES: usize = 4 * 1024 * 1024;

/// Why a challenge image could not be fetched. Never the enclave's fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// The URL did not parse, was not HTTPS, carried credentials, or named a literal IP.
    Malformed,
    /// The request failed, timed out, or the bucket answered with an error status.
    Unreachable,
    /// The response exceeded [`MAX_CHALLENGE_BYTES`].
    TooLarge,
}

/// Where the host gets a challenge image.
///
/// A trait because the constraints below make a local test server unfetchable by construction.
#[async_trait]
pub trait ChallengeSource: Send + Sync {
    /// Fetches the challenge ciphertext at `url`.
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, FetchError>;
}

/// Fetches challenge images. See the module-level `TODO(SSRF)`: destinations are not pinned.
#[derive(Debug, Clone)]
pub struct ChallengeFetcher {
    http: reqwest::Client,
}

impl ChallengeFetcher {
    /// Builds a fetcher.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP client cannot be built.
    pub fn new() -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            // Following a redirect would move the fetch somewhere the caller did not name.
            .redirect(Policy::none())
            .timeout(FETCH_TIMEOUT)
            .build()?;

        Ok(Self { http })
    }

    /// Applies every URL-shaped constraint before a request is made.
    fn validate(url: &str) -> Result<Url, FetchError> {
        let url = Url::parse(url).map_err(|_| FetchError::Malformed)?;

        if url.scheme() != "https" {
            return Err(FetchError::Malformed);
        }
        // This host has no business holding credentials for the RP's bucket.
        if !url.username().is_empty() || url.password().is_some() {
            return Err(FetchError::Malformed);
        }

        // A literal IP is the classic route to link-local metadata endpoints.
        match url.host() {
            Some(Host::Domain(_)) => Ok(url),
            _ => Err(FetchError::Malformed),
        }
    }
}

#[async_trait]
impl ChallengeSource for ChallengeFetcher {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        let url = Self::validate(url)?;

        let response = self.http.get(url).send().await.map_err(|error| {
            tracing::warn!(%error, dependency = "rp_bucket", "challenge image fetch failed");
            FetchError::Unreachable
        })?;

        if !response.status().is_success() {
            tracing::warn!(
                status = %response.status(),
                dependency = "rp_bucket",
                "challenge image fetch returned an error status"
            );
            return Err(FetchError::Unreachable);
        }

        // Streamed against a running budget: `Content-Length` is the RP's own claim, so a lying
        // or chunked response would otherwise allocate without limit.
        let mut stream = response.bytes_stream();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| {
                tracing::warn!(%error, dependency = "rp_bucket", "challenge image stream failed");
                FetchError::Unreachable
            })?;

            if body.len() + chunk.len() > MAX_CHALLENGE_BYTES {
                tracing::warn!(
                    limit = MAX_CHALLENGE_BYTES,
                    dependency = "rp_bucket",
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

    #[test]
    fn builds_without_configuration() {
        assert!(ChallengeFetcher::new().is_ok());
    }

    #[test]
    fn accepts_an_https_url_naming_a_domain() {
        assert!(
            ChallengeFetcher::validate("https://bucket.example.com/challenge-images/abc").is_ok()
        );
    }

    #[test]
    fn rejects_plaintext_http() {
        assert_eq!(
            ChallengeFetcher::validate("http://bucket.example.com/challenge-images/abc").err(),
            Some(FetchError::Malformed)
        );
    }

    #[test]
    fn rejects_embedded_credentials() {
        let host_and_path = "bucket.example.com/challenge-images/abc";
        for url in [
            format!("https://user@{host_and_path}"),
            format!("https://user:secret@{host_and_path}"),
        ] {
            assert_eq!(
                ChallengeFetcher::validate(&url).err(),
                Some(FetchError::Malformed),
                "{url}"
            );
        }
    }

    #[test]
    fn rejects_ip_literals() {
        // The link-local address is the one that matters: it is the instance metadata endpoint.
        for url in [
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1/challenge-images/abc",
            "https://[::1]/challenge-images/abc",
        ] {
            assert_eq!(
                ChallengeFetcher::validate(url).err(),
                Some(FetchError::Malformed),
                "{url}"
            );
        }
    }

    #[test]
    fn rejects_a_url_that_does_not_parse() {
        assert_eq!(
            ChallengeFetcher::validate("not-a-url").err(),
            Some(FetchError::Malformed)
        );
    }

    // TODO(SSRF): nothing pins *where* a fetch may go, so no test covers it. Restoring a
    // destination control means restoring coverage for an off-allowlist host and for a suffix
    // match, e.g. `evil-bucket.example.com` against `bucket.example.com`.
}
