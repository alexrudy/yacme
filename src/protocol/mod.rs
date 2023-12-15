//! # ACME JWT implementation and ACME request types.
//!
//! Most ACME requests are authenticated as a JWT, signed by the
//! account key. This module provides the implementation of that
//! protocol, and the deserialization of the corresponding responses,
//! as well as providing a [`AcmeClient`] type which can be used to
//! track the correct Nonce through a series of requests.
#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::ops::Deref;
use std::str::FromStr;

pub mod client;
pub mod errors;
pub mod fmt;
pub mod jose;
pub mod request;
pub mod response;

pub use client::AcmeClient;
pub use errors::AcmeError;
pub use jaws::base64data::Base64Data;
pub use jaws::base64data::Base64JSON;
pub use jaws::base64data::Base64Signature;

#[doc(no_inline)]
pub use request::Request;
#[doc(no_inline)]
pub use response::Response;
use serde::{Deserialize, Serialize};

/// A result type which uses [`AcmeError`] as the error type.
pub type Result<T> = ::std::result::Result<T, AcmeError>;

/// Universal Resource Locator which provides
/// a [`std::fmt::Debug`] implementation which prints the
/// full URL (rather than the parsed parts) for compactness.
///
/// This tries to be a drop-in replacement for [`reqwest::Url`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct Url(reqwest::Url);

impl Url {
    /// Underlying string representation of the URL.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Just the path component of the URL.
    pub fn path(&self) -> &str {
        self.0.path()
    }

    /// Just the host component of the URL.
    pub fn host(&self) -> Option<&str> {
        self.0.host_str()
    }
}

impl Deref for Url {
    type Target = reqwest::Url;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<reqwest::Url> for Url {
    fn from(value: reqwest::Url) -> Self {
        Url(value)
    }
}

impl From<Url> for reqwest::Url {
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
    type Err = <reqwest::Url as FromStr>::Err;

    fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
        s.parse().map(Url)
    }
}

#[cfg(test)]
pub(crate) mod test {

    #[macro_export]
    macro_rules! example {
        ($name:expr) => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/",
                $name
            ))
        };
    }

    #[macro_export]
    macro_rules! response {
        ($name:expr) => {
            $crate::protocol::test::parse($crate::example!($name))
        };
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
            reqwest::StatusCode::from_u16(code.parse().unwrap()).unwrap()
        };

        let mut headers = reqwest::header::HeaderMap::new();

        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            } else {
                let (name, value) = line.trim().split_once(": ").unwrap();
                headers.append(
                    reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
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
