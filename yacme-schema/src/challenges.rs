use std::ops::Deref;

use chrono::{DateTime, Utc};
use reqwest::Request;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::account::Account;
use crate::client::Client;
use yacme_protocol::Url;
use yacme_protocol::{errors::AcmeErrorDocument, AcmeError};

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase", tag = "type")]
pub enum Challenge {
    #[serde(rename = "http-01")]
    Http01(Http01Challenge),
    #[serde(rename = "dns-01")]
    Dns01(Dns01Challenge),
}

impl Challenge {
    fn info(&self) -> &ChallengeInfo {
        match self {
            Challenge::Http01(http) => &http.info,
            Challenge::Dns01(dns) => &dns.info,
        }
    }

    pub fn is_finished(&self) -> bool {
        matches!(
            self.info().status,
            ChallengeStatus::Valid | ChallengeStatus::Invalid
        )
    }

    pub fn is_valid(&self) -> bool {
        matches!(self.info().status, ChallengeStatus::Valid)
    }

    pub fn validated_at(&self) -> Option<DateTime<Utc>> {
        self.info().validated
    }

    pub fn error(&self) -> Option<&AcmeErrorDocument> {
        self.info().error.as_ref()
    }
}

#[derive(Debug, Deserialize)]
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
        let thumb = key.as_jwk().thumbprint();
        KeyAuthorization(format!("{token}.{thumb}"))
    }
}

impl Deref for KeyAuthorization {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

#[derive(Debug, Deserialize)]
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
}

#[derive(Debug, Deserialize)]
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
        let digest = sha2::Sha256::digest(self.authorization(account).as_bytes()).to_vec();
        base64_url::encode(&digest)
    }

    pub fn authorization(&self, account: &Account) -> KeyAuthorization {
        KeyAuthorization::new(&self.token, account.key())
    }
}

#[derive(Debug, Serialize)]
struct ChallengeReadyRequest;

impl Client {
    pub async fn challenge_ready(
        &mut self,
        account: &Account,
        challenge: Challenge,
    ) -> Result<Challenge, AcmeError> {
        let url = challenge.info().url().clone();
        let request = Request::new(http::Method::POST, url.into());
        let payload = ChallengeReadyRequest;
        let response = self
            .account_post(account.key_identifier(), request, &payload)
            .await?;

        let body = response.bytes().await?;
        let challenge: Challenge = serde_json::from_slice(&body).map_err(AcmeError::de)?;

        Ok(challenge)
    }
}
