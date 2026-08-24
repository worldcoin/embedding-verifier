//! Fetching the RP's challenge image.
//!
//! The one place the host follows a caller-supplied URL, which makes it this service's SSRF
//! surface (spec §6). The bytes fetched are ciphertext the host cannot read, so a *substituted*
//! URL fails closed inside the enclave — but a fetch aimed somewhere it should not go is a
//! host-side problem no enclave check can catch, and that is what the bounds here are for:
//!
//! - an allowlist of `host/key-prefix` entries, matched exactly — the load-bearing control;
//! - a resolver that keeps only publicly routable addresses, so an allowlisted name whose DNS
//!   answers into the VPC still cannot be reached;
//! - HTTPS, the default port, no credentials, no IP literals, no redirects;
//! - a 5s deadline and a 4 MiB ceiling enforced while streaming.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt as _;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;
use url::{Host, Url};

/// How long the whole fetch may take, connection included.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on the challenge image, enforced while streaming rather than after.
const MAX_CHALLENGE_BYTES: usize = 4 * 1024 * 1024;

/// Why a challenge image could not be fetched. Never the enclave's fault.
///
/// Keeping a rejected URL distinct from an unreachable bucket is what lets a dashboard tell a
/// caller error from an RP outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// The URL did not parse, was not HTTPS, named a non-default port, carried credentials, or
    /// named a literal IP.
    Malformed,
    /// The URL's host and path matched no allowlisted entry.
    NotAllowlisted,
    /// The request failed, timed out, resolved to no public address, or the bucket answered with
    /// an error status.
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
    /// permits everything is an open proxy, and failing to start is the only safe reading of a
    /// missing configuration.
    pub fn new(entries: &[String]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !entries.is_empty(),
            "the challenge-image allowlist is empty; refusing to start rather than fetch from \
             anywhere"
        );

        let allowed = entries
            .iter()
            .map(|entry| {
                let (host, path_prefix) = entry.split_once('/').ok_or_else(|| {
                    anyhow::anyhow!("allowlist entry {entry} must be host/key-prefix")
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
            // Following a redirect would walk straight past the allowlist.
            .redirect(Policy::none())
            .dns_resolver(Arc::new(PublicAddrsOnly))
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
        // `Url` drops the scheme's default port, so a port here is a non-443 one. An allowlisted
        // name is allowlisted as a bucket, not as everything else listening on that name.
        if url.port().is_some() {
            return Err(FetchError::Malformed);
        }
        // This host has no business holding credentials for the RP's bucket.
        if !url.username().is_empty() || url.password().is_some() {
            return Err(FetchError::Malformed);
        }

        // A literal IP cannot be allowlisted by name, and accepting one is the classic route to
        // link-local metadata endpoints.
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

/// A resolver that keeps only publicly routable addresses.
///
/// The allowlist pins names, and a name only becomes an address at connect time. Without this, an
/// entry whose DNS answers `169.254.169.254` — repointed after it was registered, or registered
/// that way — would reach instance metadata with the allowlist none the wiser. reqwest connects to
/// exactly the addresses returned here, so there is no second resolution to race.
///
/// A refusal reaches the route as a connect failure, so it is indistinguishable from an outage
/// there and surfaces as a retryable `502`. The warning below is what separates the two in triage.
struct PublicAddrsOnly;

impl Resolve for PublicAddrsOnly {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            // Port 0: reqwest replaces it with the port the URL implies.
            let resolved = tokio::net::lookup_host((name.as_str(), 0)).await?;
            let public: Vec<SocketAddr> =
                resolved.filter(|address| is_public(address.ip())).collect();

            if public.is_empty() {
                tracing::warn!(
                    host = name.as_str(),
                    dependency = "rp_bucket",
                    "challenge image host resolved to no publicly routable address"
                );
                return Err("no publicly routable address".into());
            }

            Ok(Box::new(public.into_iter()) as Addrs)
        })
    }
}

/// Whether `ip` is on the public internet.
const fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => match embedded_v4(address) {
            Some(embedded) => is_public_v4(embedded),
            None => is_public_v6(address),
        },
    }
}

/// The IPv4 address an IPv6 address carries, if it carries one.
///
/// Judged as the destination rather than the spelling: `169.254.169.254` is the metadata endpoint
/// whether it arrives as `::ffff:169.254.169.254`, as the deprecated `::169.254.169.254`, or
/// translated through NAT64.
const fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let [prefix @ .., high, low] = ip.segments();

    let carries_v4 = matches!(
        prefix,
        // ::/96, IPv4-compatible and deprecated, and ::ffff:0:0/96, IPv4-mapped.
        [0, 0, 0, 0, 0, 0 | 0xffff]
        // 64:ff9b::/96, the well-known NAT64 prefix.
        | [0x0064, 0xff9b, 0, 0, 0, 0]
    );
    if !carries_v4 {
        return None;
    }

    let [first, second] = high.to_be_bytes();
    let [third, fourth] = low.to_be_bytes();

    Some(Ipv4Addr::new(first, second, third, fourth))
}

/// `IpAddr::is_global` is still unstable, so the reserved IPv4 ranges are spelled out.
const fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();

    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        // 0.0.0.0/8, "this network". Wider than `is_unspecified`, which is the /32 alone, and the
        // range an `::a.b.c.d` unwrapped from `::` or `::1` lands in.
        || a == 0
        // 100.64.0.0/10, carrier-grade NAT.
        || (a == 100 && b & 0b1100_0000 == 0b0100_0000)
        // 192.0.0.0/24, IETF protocol assignments.
        || (a == 192 && b == 0 && c == 0)
        // 198.18.0.0/15, benchmarking.
        || (a == 198 && b & 0b1111_1110 == 18)
        // 240.0.0.0/4, reserved.
        || a & 0b1111_0000 == 240)
}

/// The IPv6 counterpart of [`is_public_v4`]; `is_unique_local` is unstable too.
const fn is_public_v6(ip: Ipv6Addr) -> bool {
    let [first, second, ..] = ip.segments();

    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        // fc00::/7, unique local.
        || first & 0xfe00 == 0xfc00
        // fe80::/10, link-local.
        || first & 0xffc0 == 0xfe80
        // 2001:db8::/32, documentation.
        || (first == 0x2001 && second == 0x0db8))
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
    fn host_matching_is_case_insensitive() {
        assert!(
            fetcher()
                .validate("https://BUCKET.Example.COM/challenge-images/abc")
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
    fn rejects_a_non_default_port() {
        // The name is allowlisted as a bucket, not as whatever else answers on it.
        assert_eq!(
            fetcher()
                .validate("https://bucket.example.com:8443/challenge-images/abc")
                .err(),
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
                fetcher().validate(&url).err(),
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
                fetcher().validate(url).err(),
                Some(FetchError::Malformed),
                "{url}"
            );
        }
    }

    #[test]
    fn rejects_a_url_that_does_not_parse() {
        assert_eq!(
            fetcher().validate("not-a-url").err(),
            Some(FetchError::Malformed)
        );
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

    /// What the resolver refuses to hand back, so an allowlisted name cannot be pointed inward.
    #[test]
    fn private_address_space_is_not_public() {
        for address in [
            "169.254.169.254", // EC2 instance metadata
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1", // carrier-grade NAT
            "192.0.0.1",  // IETF protocol assignments
            "198.18.0.1", // benchmarking
            "240.0.0.1",  // reserved
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "fd00::1", // unique local
            "fe80::1", // link-local
            // The metadata endpoint, spelled three other ways.
            "::ffff:169.254.169.254",   // IPv4-mapped
            "::169.254.169.254",        // IPv4-compatible, deprecated
            "64:ff9b::169.254.169.254", // NAT64
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
