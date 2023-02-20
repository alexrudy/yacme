use std::ops::Deref;

use base64ct::Encoding;
use chrono::{DateTime, Utc};
use reqwest::Request;
use serde::ser::SerializeMap;
use serde::{ser, Deserialize, Serialize};
use sha2::Digest;

use crate::account::Account;
use crate::client::Client;
use yacme_protocol::Url;
use yacme_protocol::{errors::AcmeErrorDocument, AcmeError};

#[derive(Debug, Clone, Deserialize)]
struct ChallengeInfo {
    url: Url,
    status: ChallengeStatus,
    #[serde(default)]
    validated: Option<DateTime<Utc>>,
    #[serde(default)]
    error: Option<AcmeErrorDocument>,
}

impl ChallengeInfo {
    fn url(&self) -> &Url {
        &self.url
    }
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Deserialize, Clone, Copy)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct Http01Challenge {
    #[serde(flatten)]
    info: ChallengeInfo,
    token: String,
}

impl Http01Challenge {
    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn url(&self) -> String {
        format!(".well-known/acme-challenge/{}", self.token)
    }

    pub fn authorization(&self, account: &Account) -> KeyAuthorization {
        KeyAuthorization::new(&self.token, account.key())
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

#[derive(Debug, Clone, Deserialize)]
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

    pub fn digest(&self, account: &Account) -> String {
        let digest = sha2::Sha256::digest(self.authorization(account).as_bytes());
        base64ct::Base64UrlUnpadded::encode_string(&digest)
    }

    pub fn authorization(&self, account: &Account) -> KeyAuthorization {
        KeyAuthorization::new(&self.token, account.key())
    }
}

#[derive(Debug, Default)]
struct ChallengeReadyRequest;

impl ser::Serialize for ChallengeReadyRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let map = serializer.serialize_map(Some(0))?;
        map.end()
    }
}

impl Client {
    pub async fn challenge_ready(
        &mut self,
        account: &Account,
        challenge: Challenge,
    ) -> Result<Challenge, AcmeError> {
        let url = challenge.info().unwrap().url().clone();
        let request = Request::new(http::Method::POST, url.into());
        let payload = ChallengeReadyRequest::default();
        let response = self
            .account_post(account.key_identifier(), request, &payload)
            .await?;

        let body = response.bytes().await?;
        let challenge: Challenge = serde_json::from_slice(&body).map_err(AcmeError::de)?;

        Ok(challenge)
    }
}
