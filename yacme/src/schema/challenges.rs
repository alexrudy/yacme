//! # ACME Challenges
//!
//! Challenges used to validate ownership of an identifier, as part
//! of an authorization.

use std::ops::Deref;

use crate::key::SigningKey;
use base64ct::Encoding;
use chrono::{DateTime, Utc};
use serde::ser::SerializeMap;
use serde::{ser, Deserialize, Serialize};
use sha2::Digest;

use crate::protocol::errors::AcmeErrorDocument;
use crate::protocol::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChallengeInfo {
    url: Url,
    status: ChallengeStatus,
    #[serde(default)]
    validated: Option<DateTime<Utc>>,
    #[serde(default)]
    error: Option<AcmeErrorDocument>,
}

/// ACME challenge variety.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
#[non_exhaustive]
pub enum Challenge {
    /// HTTP-01 challenge where the client must serve a file at a specific URL.
    #[serde(rename = "http-01")]
    Http01(Http01Challenge),

    /// DNS-01 challenge where the client must set a DNS TXT record for a domain.
    #[serde(rename = "dns-01")]
    Dns01(Dns01Challenge),

    /// A challenge type not currently supported by YACME.
    #[serde(other)]
    UnknownChallenge,
}

impl Challenge {
    fn info(&self) -> Option<&ChallengeInfo> {
        match self {
            Challenge::Http01(http) => Some(&http.info),
            Challenge::Dns01(dns) => Some(&dns.info),
            _ => None,
        }
    }

    /// The name of the challenge type.
    pub fn name(&self) -> Option<&'static str> {
        match self {
            Challenge::Http01(_) => Some("http-01"),
            Challenge::Dns01(_) => Some("dns-01"),
            _ => None,
        }
    }

    /// The kind of challenge - HTTP-01, DNS-01, etc.
    pub fn kind(&self) -> ChallengeKind {
        self.into()
    }

    /// The URL of the challenge, which can be used to get updates, or to indicate
    /// that the challenge is ready for validation by the ACME provider.
    pub fn url(&self) -> Option<Url> {
        self.info().map(|i| i.url.clone())
    }

    /// Status of the challenge.
    pub fn status(&self) -> Option<ChallengeStatus> {
        self.info().map(|i| i.status)
    }

    /// Has the provider validated this challenge?
    pub fn is_finished(&self) -> bool {
        matches!(
            self.info().map(|i| i.status),
            Some(ChallengeStatus::Valid) | Some(ChallengeStatus::Invalid)
        )
    }

    /// Has the provider validated this challenge and found it to be valid?
    pub fn is_valid(&self) -> bool {
        matches!(self.info().map(|i| i.status), Some(ChallengeStatus::Valid))
    }

    /// When was this challenge validated?
    pub fn validated_at(&self) -> Option<DateTime<Utc>> {
        self.info().and_then(|i| i.validated)
    }

    /// Get the error document, if this challenge has failed.
    pub fn error(&self) -> Option<&AcmeErrorDocument> {
        self.info().and_then(|i| i.error.as_ref())
    }

    /// Get the inner HTTP-01 challenge, if this is an HTTP-01 challenge.
    pub fn http01(&self) -> Option<&Http01Challenge> {
        match self {
            Challenge::Http01(http) => Some(http),
            _ => None,
        }
    }

    /// Get the inner DNS-01 challenge, if this is an DNS-01 challenge.
    pub fn dns01(&self) -> Option<&Dns01Challenge> {
        match self {
            Challenge::Dns01(dns) => Some(dns),
            _ => None,
        }
    }
}

/// State of the ACME challenge.
#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    /// This challenge has not been submitted.
    Pending,
    /// The client has indicated that this challenge is ready to be validated, but
    /// the server has not yet validated it.
    Processing,

    /// The server has validated this challenge.
    Valid,

    /// The server has validated this challenge, but the validation failed.
    Invalid,
}

/// The different kinds of ACME challenges supported by YACME
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ChallengeKind {
    /// The HTTP-01 challenge.
    #[serde(rename = "http-01")]
    Http01,

    /// The DNS-01 challenge.
    #[serde(rename = "dns-01")]
    Dns01,

    /// Another challenge not currently supported by YACME.
    #[serde(other)]
    Unknown,
}

impl From<&Challenge> for ChallengeKind {
    fn from(value: &Challenge) -> Self {
        match value {
            Challenge::Http01(_) => ChallengeKind::Http01,
            Challenge::Dns01(_) => ChallengeKind::Dns01,
            _ => ChallengeKind::Unknown,
        }
    }
}

/// The challenge authorization token, which combines the provided token
/// with the thumbprint of the account signing key.
#[derive(Debug, Serialize)]
pub struct KeyAuthorization(String);

impl KeyAuthorization {
    fn new(token: &str, key: &crate::key::SigningKey) -> KeyAuthorization {
        let thumb = key.public_key().to_jwk().thumbprint();
        KeyAuthorization(format!("{token}.{thumb}"))
    }
}

impl Deref for KeyAuthorization {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

/// A challenge that requires the client to serve a file at a specific URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http01Challenge {
    #[serde(flatten)]
    info: ChallengeInfo,
    token: String,
}

impl Http01Challenge {
    /// The token used for challenge validation.
    ///
    /// This token is used as the contents of the file, and the URL for the acme-challenge
    /// file.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// THe URL where the challenge file should be served.
    pub fn target_url(&self) -> Url {
        format!(".well-known/acme-challenge/{}", self.token)
            .parse()
            .unwrap()
    }

    /// The URL for this challenge object with the ACME provider.
    pub fn url(&self) -> Url {
        self.info.url.clone()
    }

    /// Get the key authorization, used to validate the challenge.
    pub fn authorization(&self, account_key: &SigningKey) -> KeyAuthorization {
        KeyAuthorization::new(&self.token, account_key)
    }

    fn info(&self) -> Option<&ChallengeInfo> {
        Some(&self.info)
    }

    /// Check if the challenge has been verified by the ACME provider.
    pub fn is_finished(&self) -> bool {
        matches!(
            self.info().map(|i| i.status),
            Some(ChallengeStatus::Valid) | Some(ChallengeStatus::Invalid)
        )
    }

    /// Is the challenge accepted as valid by the ACME provider?
    pub fn is_valid(&self) -> bool {
        matches!(self.info().map(|i| i.status), Some(ChallengeStatus::Valid))
    }

    /// When was the challenge validated?
    pub fn validated_at(&self) -> Option<DateTime<Utc>> {
        self.info().and_then(|i| i.validated)
    }

    /// If the challenge was found to be invalid, what error document was returned with it?
    pub fn error(&self) -> Option<&AcmeErrorDocument> {
        self.info().and_then(|i| i.error.as_ref())
    }
}

/// DNS-01 challenge.
///
/// This challenge requires the client to create a TXT record with a specific value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dns01Challenge {
    #[serde(flatten)]
    info: ChallengeInfo,
    token: String,
}

impl Dns01Challenge {
    /// The token value used for challenge validation.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The name of the DNS TXT record that should be created.
    pub fn record(&self, domain: &str) -> String {
        format!("_acme-challenge.{domain}.")
    }

    /// The value of the DNS TXT record that should be created.
    pub fn digest(&self, account_key: &SigningKey) -> String {
        let digest = sha2::Sha256::digest(self.authorization(account_key).as_bytes());
        base64ct::Base64UrlUnpadded::encode_string(&digest)
    }

    /// The key authorization object for this challenge.
    pub fn authorization(&self, account_key: &SigningKey) -> KeyAuthorization {
        KeyAuthorization::new(&self.token, account_key)
    }
}

/// An empty request to indicate that the challenge is ready to be validated.
#[derive(Debug, Default)]
pub struct ChallengeReadyRequest;

impl ser::Serialize for ChallengeReadyRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let map = serializer.serialize_map(Some(0))?;
        map.end()
    }
}
