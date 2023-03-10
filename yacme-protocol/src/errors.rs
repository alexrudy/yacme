//! Errors which occur when working with an ACME Protocol

use http::HeaderValue;
use thiserror::Error;

pub use self::acme::{AcmeErrorCode, AcmeErrorDocument};

/// Unified error type for errors arising from the ACME protocol.
#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("An error occured with the ACME service: {0}")]
    Acme(#[source] self::acme::AcmeErrorDocument),

    #[error("An error occured during the network request: {0}")]
    HttpRequest(#[from] reqwest::Error),

    #[error("An error occured deserializing JSON: {0}")]
    JsonDeserialize(#[source] serde_json::Error),

    #[error("An error occured serializing JSON: {0}")]
    JsonSerialize(#[source] serde_json::Error),

    #[error("An error occured while deserializing a PEM binary: {0}")]
    PemDecodeError(#[from] pem_rfc7468::Error),

    #[error("An error occured while deserializing a DER binary: {0}")]
    DerDecodeError(#[from] der::Error),

    #[error("The ACME Client encountered non utf-8 data: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("The nonce header returned was not valid: {0:?}")]
    InvalidNonce(Option<HeaderValue>),

    #[error("No Nonce header was returned with the request")]
    MissingNonce,

    #[error("An error occured during a network request to fetch a new nonce: {0}")]
    NonceRequest(#[source] reqwest::Error),

    #[error("An error occured while signing the JWS token: {0}")]
    Signing(#[source] eyre::Report),

    #[error("Required configuration data is missing: {0}")]
    MissingData(&'static str),

    #[error("Signing Key for {0} is missing")]
    MissingKey(&'static str),

    #[error("{0} is not ready")]
    NotReady(&'static str),

    #[error("{0} is not a known challenge type")]
    UnknownChallenge(String),
}

impl AcmeError {
    pub fn de(error: serde_json::Error) -> Self {
        AcmeError::JsonDeserialize(error)
    }

    pub fn ser(error: serde_json::Error) -> Self {
        AcmeError::JsonSerialize(error)
    }

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
        pub fn kind(&self) -> &AcmeErrorCode {
            &self.code
        }

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
    pub enum AcmeErrorCode {
        BadNonce,
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
