use http::HeaderValue;
use thiserror::Error;

pub use self::acme::{AcmeErrorCode, AcmeErrorDocument};

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
    #[error("The nonce header returned was not valid: {0:?}")]
    InvalidNonce(Option<HeaderValue>),
    #[error("No Nonce header was returned with the request")]
    MissingNonce,
    #[error("An error occured during a network request to fetch a new nonce: {0}")]
    NonceRequest(#[source] reqwest::Error),
    #[error("An error occured while signing the JWS token: {0}")]
    Signing(#[source] eyre::Report),
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

    use serde::Deserialize;
    use thiserror::Error;

    #[derive(Debug, Clone, Error, Deserialize)]
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

    #[derive(Debug, Clone)]
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
            eprintln!("URN: {value}");
            eprintln!("URN Tag: {tag:?}");

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
