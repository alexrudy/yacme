use std::ops::Deref;

use base64ct::Encoding;
use chrono::{DateTime, Utc};
use serde::ser::SerializeMap;
use serde::{ser, Deserialize, Serialize};
use sha2::Digest;
use yacme_key::SigningKey;

use yacme_protocol::errors::AcmeErrorDocument;
use yacme_protocol::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChallengeInfo {
    url: Url,
    status: ChallengeStatus,
    #[serde(default)]
    validated: Option<DateTime<Utc>>,
    #[serde(default)]
    error: Option<AcmeErrorDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum Challenge {
    #[serde(rename = "http-01")]
    Http01(Http01Challenge),
    #[serde(rename = "dns-01")]
    Dns01(Dns01Challenge),
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

    pub fn name(&self) -> Option<&'static str> {
        match self {
            Challenge::Http01(_) => Some("http-01"),
            Challenge::Dns01(_) => Some("dns-01"),
            _ => None,
        }
    }

    pub fn url(&self) -> Option<Url> {
        self.info().map(|i| i.url.clone())
    }

    pub fn status(&self) -> Option<ChallengeStatus> {
        self.info().map(|i| i.status)
    }

    pub fn is_finished(&self) -> bool {
        matches!(
            self.info().map(|i| i.status),
            Some(ChallengeStatus::Valid) | Some(ChallengeStatus::Invalid)
        )
    }

    pub fn is_valid(&self) -> bool {
        matches!(self.info().map(|i| i.status), Some(ChallengeStatus::Valid))
    }

    pub fn validated_at(&self) -> Option<DateTime<Utc>> {
        self.info().and_then(|i| i.validated)
    }

    pub fn error(&self) -> Option<&AcmeErrorDocument> {
        self.info().and_then(|i| i.error.as_ref())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Serialize)]
pub struct KeyAuthorization(String);

impl KeyAuthorization {
    fn new(token: &str, key: &yacme_key::SigningKey) -> KeyAuthorization {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http01Challenge {
    #[serde(flatten)]
    info: ChallengeInfo,
    token: String,
}

impl Http01Challenge {
    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn target_url(&self) -> Url {
        format!(".well-known/acme-challenge/{}", self.token)
            .parse()
            .unwrap()
    }

    pub fn url(&self) -> Url {
        self.info.url.clone()
    }

    pub fn authorization(&self, account_key: &SigningKey) -> KeyAuthorization {
        KeyAuthorization::new(&self.token, account_key)
    }

    fn info(&self) -> Option<&ChallengeInfo> {
        Some(&self.info)
    }

    pub fn is_finished(&self) -> bool {
        matches!(
            self.info().map(|i| i.status),
            Some(ChallengeStatus::Valid) | Some(ChallengeStatus::Invalid)
        )
    }

    pub fn is_valid(&self) -> bool {
        matches!(self.info().map(|i| i.status), Some(ChallengeStatus::Valid))
    }

    pub fn validated_at(&self) -> Option<DateTime<Utc>> {
        self.info().and_then(|i| i.validated)
    }

    pub fn error(&self) -> Option<&AcmeErrorDocument> {
        self.info().and_then(|i| i.error.as_ref())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dns01Challenge {
    #[serde(flatten)]
    info: ChallengeInfo,
    token: String,
}

impl Dns01Challenge {
    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn record(&self, domain: &str) -> String {
        format!("_acme-challenge.{domain}")
    }

    pub fn digest(&self, account_key: &SigningKey) -> String {
        let digest = sha2::Sha256::digest(self.authorization(account_key).as_bytes());
        base64ct::Base64UrlUnpadded::encode_string(&digest)
    }

    pub fn authorization(&self, account_key: &SigningKey) -> KeyAuthorization {
        KeyAuthorization::new(&self.token, account_key)
    }
}

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
