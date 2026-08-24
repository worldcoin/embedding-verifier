//! Fetching the RP's challenge image.
//!
//! The one place the host follows a caller-supplied URL, so every bound here is for SSRF
//! (spec §6). The allowlist is the load-bearing one; the rest limit blast radius.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt as _;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;
use url::{Host, Url};

const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CHALLENGE_BYTES: usize = 4 * 1024 * 1024;

/// Why a challenge image could not be fetched. Never the enclave's fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// Unparseable, not HTTPS, a non-default port, credentials, or a literal IP.
    Malformed,
    /// No allowlist entry matched the host and path.
    NotAllowlisted,
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
    /// Builds a fetcher from `host/key-prefix` entries.
    ///
    /// # Errors
    ///
    /// Returns an error when the allowlist is empty, when an entry is malformed, or when the HTTP
    /// client cannot be built. An empty allowlist is refused rather than defaulted: a fetcher that
    /// pins nothing is an open proxy.
    pub fn new(entries: &[String]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !entries.is_empty(),
            "the challenge-image allowlist is empty"
        );

        let allowed = entries
            .iter()
            .map(|entry| {
                let (host, path_prefix) = entry.split_once('/').ok_or_else(|| {
                    anyhow::anyhow!("allowlist entry {entry} must be host/key-prefix")
                })?;
                anyhow::ensure!(!host.is_empty(), "allowlist entry {entry} has no host");

                Ok(AllowedPrefix {
                    host: host.to_ascii_lowercase(),
                    path_prefix: format!("/{path_prefix}"),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let http = reqwest::Client::builder()
            // A redirect would walk straight past the allowlist.
            .redirect(Policy::none())
            .dns_resolver(Arc::new(PublicAddrsOnly))
            .timeout(FETCH_TIMEOUT)
            .build()?;

        Ok(Self { http, allowed })
    }

    fn validate(&self, url: &str) -> Result<Url, FetchError> {
        let url = Url::parse(url).map_err(|_| FetchError::Malformed)?;

        // `Url` drops the scheme's default port, so any port here is a non-443 one: the name is
        // allowlisted as a bucket, not as everything else listening on it.
        if url.scheme() != "https" || url.port().is_some() {
            return Err(FetchError::Malformed);
        }
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

/// Keeps only publicly routable addresses.
///
/// The allowlist pins names, and DNS is what turns a name into an address, so an entry answering
/// `169.254.169.254` would otherwise reach instance metadata. reqwest connects to exactly what
/// this returns. A refusal reaches the route as a connect failure, so the warning below is what
/// separates it from an outage in triage.
struct PublicAddrsOnly;

impl Resolve for PublicAddrsOnly {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            // Port 0: reqwest replaces it with the port the URL implies.
            let addresses: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|address| is_public(address.ip()))
                .collect();

            if addresses.is_empty() {
                tracing::warn!(
                    host = name.as_str(),
                    dependency = "rp_bucket",
                    "challenge image host has no publicly routable address"
                );
                return Err("no publicly routable address".into());
            }

            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

const fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        // `::ffff:169.254.169.254` is the metadata endpoint too.
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(mapped) => is_public_v4(mapped),
            None => is_public_v6(ip),
        },
    }
}

/// `IpAddr::is_global` is unstable, so the reserved ranges are spelled out.
const fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();

    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || a == 0 // 0.0.0.0/8
        || (a == 100 && b & 0b1100_0000 == 0b0100_0000) // 100.64.0.0/10, CGNAT
        || (a == 192 && b == 0 && c == 0) // 192.0.0.0/24
        || (a == 198 && b & 0b1111_1110 == 18) // 198.18.0.0/15
        || a & 0b1111_0000 == 240) // 240.0.0.0/4
}

const fn is_public_v6(ip: Ipv6Addr) -> bool {
    let [first, second, ..] = ip.segments();

    !(ip.is_multicast()
        // ::/96 — loopback, unspecified, and the deprecated IPv4-compatible form.
        || matches!(ip.segments(), [0, 0, 0, 0, 0, 0, ..])
        || first & 0xfe00 == 0xfc00 // fc00::/7, unique local
        || first & 0xffc0 == 0xfe80 // fe80::/10, link-local
        || (first == 0x2001 && second == 0x0db8)) // 2001:db8::/32
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{ChallengeFetcher, FetchError, is_public};

    fn fetcher() -> ChallengeFetcher {
        ChallengeFetcher::new(&["bucket.example.com/challenge-images/".to_owned()])
            .expect("the allowlist should build")
    }

    #[test]
    fn refuses_to_build_without_an_allowlist() {
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
    fn host_matching_is_case_insensitive() {
        assert!(
            fetcher()
                .validate("https://BUCKET.Example.COM/challenge-images/abc")
                .is_ok()
        );
    }

    #[test]
    fn rejects_urls_that_are_not_plain_https() {
        for url in [
            "not-a-url",
            "http://bucket.example.com/challenge-images/abc",
            "https://bucket.example.com:8443/challenge-images/abc",
            "https://user@bucket.example.com/challenge-images/abc",
            "https://user:secret@bucket.example.com/challenge-images/abc",
            // A literal IP, the classic route to the metadata endpoint.
            "https://169.254.169.254/latest/meta-data/",
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
    fn rejects_destinations_off_the_allowlist() {
        for url in [
            "https://attacker.example.com/challenge-images/abc",
            // Suffix matching would accept this; the allowlist compares the whole host.
            "https://evil-bucket.example.com/challenge-images/abc",
            "https://bucket.example.com/private/abc",
        ] {
            assert_eq!(
                fetcher().validate(url).err(),
                Some(FetchError::NotAllowlisted),
                "{url}"
            );
        }
    }

    /// What the resolver refuses to hand back, so an allowlisted name cannot be pointed inward.
    #[test]
    fn private_address_space_is_not_public() {
        for address in [
            "169.254.169.254", // EC2 instance metadata
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "192.0.0.1",
            "198.18.0.1",
            "240.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fd00::1",
            "fe80::1",
            // The metadata endpoint, spelled IPv4-mapped and IPv4-compatible.
            "::ffff:169.254.169.254",
            "::169.254.169.254",
        ] {
            let ip: IpAddr = address.parse().expect("test address should parse");
            assert!(!is_public(ip), "{address} should not be treated as public");
        }
    }

    #[test]
    fn public_address_space_is_public() {
        for address in ["93.184.216.34", "8.8.8.8", "2606:2800:220:1::1"] {
            let ip: IpAddr = address.parse().expect("test address should parse");
            assert!(is_public(ip), "{address} should be treated as public");
        }
    }
}
