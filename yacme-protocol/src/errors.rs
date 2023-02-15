use http::HeaderValue;
use thiserror::Error;

pub(super) use self::acme::AcmeErrorDocument;

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("An error occured with the ACME service: {0}")]
    Acme(#[from] self::acme::AcmeErrorDocument),
    #[error("An error occured during the network request: {0}")]
    HttpRequest(#[from] reqwest::Error),
    #[error("An error occured deserializing JSON: {0}")]
    JsonDeserialize(#[source] serde_json::Error),
    #[error("An error occured serializing JSON: {0}")]
    JsonSerialize(#[source] serde_json::Error),
    #[error("The nonce header returned was not valid: {0:?}")]
    InvalidNonce(HeaderValue),
    #[error("No Nonce header was returned with the request")]
    MissingNonce,
    #[error("An error occured during a network request to fetch a new nonce: {0}")]
    NonceRequest(#[source] reqwest::Error),
    #[error("An error occured while signing the JWS token: {0}")]
    Signing(#[source] eyre::Report),
}

impl AcmeError {
    pub(super) fn de(error: serde_json::Error) -> Self {
        AcmeError::JsonDeserialize(error)
    }

    pub(super) fn ser(error: serde_json::Error) -> Self {
        AcmeError::JsonSerialize(error)
    }

    pub(super) fn nonce(error: reqwest::Error) -> Self {
        AcmeError::NonceRequest(error)
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
        Other(String),
    }

    impl fmt::Display for AcmeErrorCode {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
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

            #[allow(clippy::match_single_binding)]
            match value.as_str() {
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
