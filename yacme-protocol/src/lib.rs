use std::ops::Deref;
use std::str::FromStr;

mod base64;
pub mod client;
pub mod errors;
pub mod fmt;
pub mod jose;
pub mod request;
pub mod response;

pub use base64::Base64Data;
pub use base64::Base64JSON;
pub use client::Client;
pub use errors::AcmeError;
pub use request::Request;
pub use response::Response;
use serde::{Deserialize, Serialize};

pub type Result<T> = ::std::result::Result<T, AcmeError>;

/// Universal Resource Locator which provides
/// a [`std::fmt::Debug`] implementation which prints the
/// full URL (rather than the parsed parts) for compactness.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Url(url::Url);

impl Url {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn path(&self) -> &str {
        self.0.path()
    }

    pub fn host(&self) -> Option<&str> {
        self.0.host_str()
    }
}

impl Deref for Url {
    type Target = url::Url;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<url::Url> for Url {
    fn from(value: url::Url) -> Self {
        Url(value)
    }
}

impl From<Url> for url::Url {
    fn from(value: Url) -> Self {
        value.0
    }
}

impl AsRef<str> for Url {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Url").field(&self.0.as_str()).finish()
    }
}

impl FromStr for Url {
    type Err = url::ParseError;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        s.parse().map(Url)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::sync::Arc;

    #[macro_export]
    macro_rules! example {
        ($name:tt) => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-examples/",
                $name
            ))
        };
    }

    #[macro_export]
    macro_rules! key {
        ($name:tt) => {
            $crate::test::key(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-examples/",
                $name,
                ".pem"
            )))
        };
    }

    #[macro_export]
    macro_rules! response {
        ($name:tt) => {
            $crate::test::parse($crate::example!($name))
        };
    }

    #[allow(dead_code)]
    pub(crate) fn key(private: &str) -> Arc<yacme_key::SigningKey> {
        let key = yacme_key::SigningKey::from_pkcs8_pem(
            private,
            yacme_key::SignatureKind::Ecdsa(yacme_key::EcdsaAlgorithm::P256),
        )
        .unwrap();

        Arc::new(key)
    }

    pub(crate) fn parse(data: &str) -> http::Response<String> {
        let mut lines = data.lines();

        let status = {
            let status_line = lines.next().unwrap().trim();
            let (version, status) = status_line.split_once(' ').unwrap();

            if !matches!(version, "HTTP/1.1") {
                panic!("Expected HTTP/1.1, got {version}");
            }

            let (code, _reason) = status.split_once(' ').unwrap();
            http::StatusCode::from_u16(code.parse().unwrap()).unwrap()
        };

        let mut headers = http::HeaderMap::new();

        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            } else {
                let (name, value) = line.trim().split_once(": ").unwrap();
                headers.append(
                    http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
            }
        }

        let body: String = lines.collect();
        let mut response = http::Response::new(body);
        *response.headers_mut() = headers;
        *response.status_mut() = status;
        *response.version_mut() = http::Version::HTTP_11;
        response
    }
}
