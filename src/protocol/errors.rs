//! Errors which occur when working with an ACME Protocol

use http::HeaderValue;
use thiserror::Error;

pub use self::acme::{AcmeErrorCode, AcmeErrorDocument};

/// Unified error type for errors arising from the ACME protocol.
#[derive(Debug, Error)]
pub enum AcmeError {
    /// The ACME provider returned an error, see [`AcmeErrorDocument`].
    #[error("An error occured with the ACME service: {0}")]
    Acme(#[source] self::acme::AcmeErrorDocument),

    /// The `reqwest` library encountered an error while fulfilling the HTTP
    /// request, and the ACME provider did not provide a corresponding error document.
    #[error("An error occured during the network request: {0}")]
    HttpRequest(#[from] reqwest::Error),

    /// An error was encountered while trying to deserialize the JSON payload of the response.
    #[error("An error occured deserializing JSON: {0}")]
    JsonDeserialize(#[source] serde_json::Error),

    /// An error was encountered while trying to serialize the JSON payload of the request.
    #[error("An error occured serializing JSON: {0}")]
    JsonSerialize(#[source] serde_json::Error),

    /// An error occured while trying decode a PEM binary in a response.
    #[error("An error occured while deserializing a PEM document: {0}")]
    PemDecodeError(#[from] pem_rfc7468::Error),

    /// An error occured while trying decode a DER binary in a response.
    #[error("An error occured while deserializing a DER binary: {0}")]
    DerDecodeError(#[from] der::Error),

    /// The ACME Client encountered non utf-8 data in a response.
    #[error("The ACME Client encountered non utf-8 data: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    /// The ACME provider indicated that an invalid nonce was used.
    #[error("The nonce header returned was not valid: {0:?}")]
    InvalidNonce(Option<HeaderValue>),

    /// The ACME provider did not provide a nonce. This is a bug in the provider's
    /// adherence to [RFC 8885](https://tools.ietf.org/html/rfc8555).
    #[error("No Nonce header was returned with the request")]
    MissingNonce,

    /// The `reqwest` library encountered an error while making an additional HTTP
    /// request to get a new nonce, and the ACME provider did not provide a corresponding error document.
    #[error("An error occured during a network request to fetch a new nonce: {0}")]
    NonceRequest(#[source] reqwest::Error),

    /// The signing algorithm encountered an error.
    #[error("An error occured while signing the JWS token: {0}")]
    Signing(#[source] signature::Error),

    /// Some data was missing from an input.
    #[error("Required configuration data is missing: {0}")]
    MissingData(&'static str),

    /// A signing key was not provided (e.g. for finalizing an order, or creating an account).
    #[error("Signing Key for {0} is missing")]
    MissingKey(&'static str),

    /// The ACME provider indicated that a resource is not ready. This usually indicates
    /// that an error occured during e.g. validation, or the prerequisites for waiting
    /// on some process from the ACME provider were not fulfilled.
    #[error("{0} is not ready")]
    NotReady(&'static str),

    /// The ACME challenge is not a known challenge type for YACME.
    #[error("{0} is not a known challenge type")]
    UnknownChallenge(String),

    /// The authorization object returned a status other than Valid, indicating
    /// that an authorization encountered an error or was not fulfilled.
    #[error("Authorization status {0}, expected Valid")]
    AuthorizationError(String),
}

impl AcmeError {
    /// Constructor for a deserialization error.
    pub fn de(error: serde_json::Error) -> Self {
        AcmeError::JsonDeserialize(error)
    }

    /// Constructor for a serialization error.
    pub fn ser(error: serde_json::Error) -> Self {
        AcmeError::JsonSerialize(error)
    }

    /// Constructor for a Nonce request error.
    pub fn nonce(error: reqwest::Error) -> Self {
        AcmeError::NonceRequest(error)
    }
}

impl From<AcmeErrorDocument> for AcmeError {
    fn from(value: AcmeErrorDocument) -> Self {
        match value.kind() {
            acme::AcmeErrorCode::BadNonce => AcmeError::InvalidNonce(None),
            acme::AcmeErrorCode::Other(_) => AcmeError::Acme(value),
        }
    }
}

impl<E> From<jaws::token::TokenSigningError<E>> for AcmeError
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn from(error: jaws::token::TokenSigningError<E>) -> Self {
        match error {
            jaws::token::TokenSigningError::Signing(error) => {
                AcmeError::Signing(signature::Error::from_source(error))
            }
            jaws::token::TokenSigningError::Serialization(error) => AcmeError::JsonSerialize(error),
        }
    }
}

mod acme {
    use std::fmt;

    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    /// Error document returned by ACME servers when a request has caused an
    /// error.
    ///
    /// ACME Error documents follow RFC 7807 "Problem Details for HTTP APIs".
    #[derive(Debug, Clone, Error, Serialize, Deserialize)]
    #[serde(from = "RawErrorInfo")]
    #[error("{code}: {detail}")]
    pub struct AcmeErrorDocument {
        code: AcmeErrorCode,
        detail: String,
    }

    impl AcmeErrorDocument {
        /// The error code provided in the ACME error document.
        pub fn kind(&self) -> &AcmeErrorCode {
            &self.code
        }

        /// The error message, intended to be human readable, in the
        /// ACME error document.
        pub fn message(&self) -> &str {
            &self.detail
        }
    }

    /// Specific code indicating the kind of error that an ACME server
    /// encountered.
    ///
    /// These codes are specified in RFC 8885.
    ///
    /// Not all codes are implemented here.
    #[derive(Debug, Serialize, Clone)]
    #[non_exhaustive]
    pub enum AcmeErrorCode {
        /// A bad nonce was sent with the request. Try again with a new nonce.
        BadNonce,

        /// Some other error occured.
        Other(String),
    }

    impl fmt::Display for AcmeErrorCode {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                AcmeErrorCode::BadNonce => f.write_str("an invalid nonce was sent"),
                AcmeErrorCode::Other(message) => f.write_str(message),
            }
        }
    }

    impl From<String> for AcmeErrorCode {
        fn from(value: String) -> Self {
            let urn = value.split(':').collect::<Vec<_>>();

            const URN: &[&str; 5] = &["urn", "ietf", "params", "acme", "error"];

            if !urn
                .iter()
                .take(5)
                .zip(URN)
                .all(|(&part, &expected)| part == expected)
            {
                tracing::warn!("Unexpected URN: {value}");
            }

            if !urn.contains(&"error") {
                tracing::warn!("URN isn't an error: {value}");
            }

            let tag = urn.into_iter().nth(5);

            match tag {
                Some("badNonce") => AcmeErrorCode::BadNonce,
                _ => AcmeErrorCode::Other(value),
            }
        }
    }

    /// Deserializable format for an ACME error document.
    #[derive(Debug, Clone, Deserialize)]
    struct RawErrorInfo {
        r#type: String,
        detail: String,
    }

    impl From<RawErrorInfo> for AcmeErrorDocument {
        fn from(value: RawErrorInfo) -> Self {
            AcmeErrorDocument {
                code: value.r#type.into(),
                detail: value.detail,
            }
        }
    }
}
