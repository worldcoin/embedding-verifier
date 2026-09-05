//! Validation shared by the two places a caller can set headers: [`Config`](crate::Config) for
//! the constant ones, and the client for the ones bound to a single request.

use std::fmt;

use reqwest::header::{COOKIE, HeaderMap, HeaderName, HeaderValue};

use crate::error::Error;

/// A validated set of headers. A value is likely a credential, so `Debug` lists the names only.
#[derive(Clone, Default)]
pub struct ExtraHeaders(HeaderMap);

impl ExtraHeaders {
    /// Validates `headers` for use on the wire, rejecting `Cookie`.
    pub fn new<K, V>(headers: impl IntoIterator<Item = (K, V)>) -> Result<Self, Error>
    where
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut map = HeaderMap::new();

        for (name, value) in headers {
            let (name, value) = (name.as_ref(), value.as_ref());

            let key = HeaderName::try_from(name).map_err(|error| Error::InvalidConfig {
                attribute: "headers".to_string(),
                reason: format!("{name:?} is not a header name: {error}"),
            })?;

            if key == COOKIE {
                return Err(Error::InvalidConfig {
                    attribute: "headers".to_string(),
                    reason: "the client's cookie store owns Cookie, so that the match reaches the \
                             enclave the assignment attested"
                        .to_string(),
                });
            }

            // Names the header but never the value, which may be a credential.
            let value = HeaderValue::try_from(value).map_err(|error| Error::InvalidConfig {
                attribute: "headers".to_string(),
                reason: format!("value of {name:?} is not a header value: {error}"),
            })?;

            map.insert(key, value);
        }

        Ok(Self(map))
    }

    pub const fn as_map(&self) -> &HeaderMap {
        &self.0
    }
}

impl fmt::Debug for ExtraHeaders {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_list()
            .entries(self.0.keys().map(HeaderName::as_str))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::ExtraHeaders;
    use crate::error::Error;

    #[test]
    fn rejects_headers_that_are_not_valid_on_the_wire() {
        let error = ExtraHeaders::new([("not a name", "value")])
            .expect_err("an invalid header name must be rejected");
        assert!(matches!(error, Error::InvalidConfig { .. }));

        let error = ExtraHeaders::new([("authorization", "new\nline")])
            .expect_err("an invalid header value must be rejected");
        assert!(matches!(error, Error::InvalidConfig { .. }));
    }

    #[test]
    fn rejects_a_cookie_header() {
        let error = ExtraHeaders::new([("Cookie", "AWSALB=pod-a")])
            .expect_err("Cookie must be rejected whatever its spelling");

        assert!(matches!(error, Error::InvalidConfig { .. }));
    }

    #[test]
    fn keeps_values_out_of_debug() {
        let headers = ExtraHeaders::new([("integrity-token", "super-secret")])
            .expect("headers should be valid");

        let debug = format!("{headers:?}");
        assert!(debug.contains("integrity-token"), "{debug}");
        assert!(!debug.contains("super-secret"), "{debug}");
    }
}
