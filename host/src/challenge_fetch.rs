//! Fetching the RP's challenge image.
//!
//! The one place the host fetches a caller-supplied URL, which makes it an SSRF surface: instance
//! metadata, private addresses, endpoints chosen to exhaust the host. The allowlist is the
//! load-bearing bound; the rest limit blast radius.
//!
//! The bytes are ciphertext the host cannot read, so a substituted URL fails closed in the enclave,
//! where the challenge key lives.

use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt as _;
use reqwest::redirect::Policy;
use url::{Host, Url};

/// How long the whole fetch may take, connection included.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on the challenge image, enforced while streaming rather than after.
const MAX_CHALLENGE_BYTES: usize = 4 * 1024 * 1024;

/// Why a challenge image could not be fetched.
///
/// Never the enclave's fault, so the route maps all of them outward. Kept distinct because a
/// rejected URL and an unreachable bucket need different people.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// The URL did not parse, was not HTTPS, carried credentials, or named a literal IP.
    Malformed,
    /// The URL's host and path did not match any allowlisted prefix.
    NotAllowlisted,
    /// The request failed, timed out, or the bucket answered with an error status.
    Unreachable,
    /// The response exceeded [`MAX_CHALLENGE_BYTES`].
    TooLarge,
}

/// Where the host gets a challenge image.
///
/// A trait because the constraints below reject plain HTTP and IP literals, which makes a local
/// test server unfetchable by construction — routes need some seam to be testable.
#[async_trait]
pub trait ChallengeSource: Send + Sync {
    /// Fetches the challenge ciphertext at `url`.
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, FetchError>;
}

/// One allowlisted location: an exact host plus a required key prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AllowedPrefix {
    host: String,
    path_prefix: String,
}

/// Fetches challenge images, constrained to a configured allowlist.
#[derive(Debug, Clone)]
pub struct ChallengeFetcher {
    http: reqwest::Client,
    allowed: Vec<AllowedPrefix>,
}

impl ChallengeFetcher {
    /// Builds a fetcher from `host/prefix` entries.
    ///
    /// # Errors
    ///
    /// Returns an error when the allowlist is empty, when an entry is malformed, or when the HTTP
    /// client cannot be built. An empty allowlist would be an open proxy, so it fails startup.
    pub fn new(entries: &[String]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !entries.is_empty(),
            "the challenge-image allowlist is empty; refusing to start rather than \
             fetch from anywhere"
        );

        let allowed = entries
            .iter()
            .map(|entry| {
                let (host, path_prefix) = entry.split_once('/').ok_or_else(|| {
                    anyhow::anyhow!("allowlist entry {entry} must be host/path-prefix")
                })?;
                anyhow::ensure!(
                    !host.is_empty(),
                    "allowlist entry {entry} has an empty host"
                );

                Ok(AllowedPrefix {
                    host: host.to_ascii_lowercase(),
                    path_prefix: format!("/{path_prefix}"),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let http = reqwest::Client::builder()
            // A permitted URL that redirects would otherwise walk past the allowlist.
            .redirect(Policy::none())
            .timeout(FETCH_TIMEOUT)
            .build()?;

        Ok(Self { http, allowed })
    }

    /// Applies every URL-shaped constraint before a request is made.
    fn validate(&self, url: &str) -> Result<Url, FetchError> {
        let url = Url::parse(url).map_err(|_| FetchError::Malformed)?;

        if url.scheme() != "https" {
            return Err(FetchError::Malformed);
        }
        // This host has no business holding credentials for the RP's bucket.
        if !url.username().is_empty() || url.password().is_some() {
            return Err(FetchError::Malformed);
        }

        // A literal IP cannot be allowlisted by name, and is the classic route to link-local
        // metadata endpoints.
        let host = match url.host() {
            Some(Host::Domain(host)) => host.to_ascii_lowercase(),
            _ => return Err(FetchError::Malformed),
        };

        let allowed = self.allowed.iter().any(|prefix| {
            prefix.host == host && url.path().starts_with(prefix.path_prefix.as_str())
        });
        if allowed {
            Ok(url)
        } else {
            tracing::warn!(%host, "challenge image URL is not allowlisted");
            Err(FetchError::NotAllowlisted)
        }
    }
}

#[async_trait]
impl ChallengeSource for ChallengeFetcher {
    async fn fetch(&self, url: &str) -> Result<Vec<u8>, FetchError> {
        let url = self.validate(url)?;

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

    fn fetcher() -> ChallengeFetcher {
        ChallengeFetcher::new(&["bucket.example.com/challenge-images/".to_owned()])
            .expect("allowlist should build")
    }

    #[test]
    fn refuses_to_build_without_an_allowlist() {
        // Fail closed: an empty allowlist would make this an open proxy.
        assert!(ChallengeFetcher::new(&[]).is_err());
    }

    #[test]
    fn rejects_a_malformed_allowlist_entry() {
        assert!(ChallengeFetcher::new(&["no-slash-here".to_owned()]).is_err());
        assert!(ChallengeFetcher::new(&["/empty-host".to_owned()]).is_err());
    }

    #[test]
    fn accepts_an_allowlisted_url() {
        assert!(
            fetcher()
                .validate("https://bucket.example.com/challenge-images/abc")
                .is_ok()
        );
    }

    #[test]
    fn rejects_plaintext_http() {
        assert_eq!(
            fetcher()
                .validate("http://bucket.example.com/challenge-images/abc")
                .err(),
            Some(FetchError::Malformed)
        );
    }

    #[test]
    fn rejects_embedded_credentials() {
        for url in [
            "https://user@bucket.example.com/challenge-images/abc",
            "https://user:pass@bucket.example.com/challenge-images/abc",
        ] {
            assert_eq!(
                fetcher().validate(url).err(),
                Some(FetchError::Malformed),
                "{url}"
            );
        }
    }

    #[test]
    fn rejects_ip_literals() {
        // The link-local address is the one that matters: it is the instance metadata endpoint.
        for url in [
            "https://169.254.169.254/challenge-images/abc",
            "https://127.0.0.1/challenge-images/abc",
            "https://[::1]/challenge-images/abc",
        ] {
            assert_eq!(
                fetcher().validate(url).err(),
                Some(FetchError::Malformed),
                "{url}"
            );
        }
    }

    #[test]
    fn rejects_another_host() {
        assert_eq!(
            fetcher()
                .validate("https://attacker.example.com/challenge-images/abc")
                .err(),
            Some(FetchError::NotAllowlisted)
        );
    }

    #[test]
    fn rejects_a_host_that_merely_ends_with_an_allowlisted_one() {
        // Suffix matching would accept this; the allowlist compares the whole host.
        assert_eq!(
            fetcher()
                .validate("https://evil-bucket.example.com/challenge-images/abc")
                .err(),
            Some(FetchError::NotAllowlisted)
        );
    }

    #[test]
    fn rejects_a_path_outside_the_prefix() {
        assert_eq!(
            fetcher()
                .validate("https://bucket.example.com/private/abc")
                .err(),
            Some(FetchError::NotAllowlisted)
        );
    }

    #[test]
    fn host_matching_is_case_insensitive() {
        assert!(
            fetcher()
                .validate("https://BUCKET.Example.COM/challenge-images/abc")
                .is_ok()
        );
    }
}
