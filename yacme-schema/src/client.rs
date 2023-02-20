use std::ops::Deref;
use std::sync::Arc;

use eyre::Report;
use http::HeaderMap;
use reqwest::Request;
use serde::Serialize;

use crate::directory::Directory;
use yacme_protocol::errors::{AcmeError, AcmeErrorCode, AcmeErrorDocument};
use yacme_protocol::jose::AccountKeyIdentifier;
use yacme_protocol::jose::AcmeProtectedHeader;
use yacme_protocol::jose::Nonce;
use yacme_protocol::jose::ProtectedHeader;
use yacme_protocol::jose::UnsignedToken;
use yacme_protocol::Url;

const NONCE_HEADER: &str = "Replay-Nonce";
const CONTENT_JOSE: &str = "application/jose+json";

#[allow(clippy::large_enum_variant)]
enum InitialDirectory {
    Fetch(Url),
    Directory(Directory),
}

pub struct ClientBuilder {
    inner: reqwest::Client,
    key: Option<Arc<yacme_key::SigningKey>>,
    directory: Option<InitialDirectory>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder {
            inner: reqwest::Client::new(),
            key: None,
            directory: None,
        }
    }

    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.inner = client;
        self
    }

    pub fn with_directory_url(mut self, url: Url) -> Self {
        self.directory = Some(InitialDirectory::Fetch(url));
        self
    }

    pub fn with_directory(mut self, directory: Directory) -> Self {
        self.directory = Some(InitialDirectory::Directory(directory));
        self
    }

    pub fn with_key(mut self, key: Arc<yacme_key::SigningKey>) -> Self {
        self.key = Some(key);
        self
    }

    pub async fn build(self) -> Result<Client, Report> {
        let directory = match self
            .directory
            .ok_or_else(|| Report::msg("Missing directory"))?
        {
            InitialDirectory::Fetch(url) => {
                self.inner
                    .get(url.as_str())
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await?
            }
            InitialDirectory::Directory(directory) => directory,
        };

        Ok(Client {
            inner: self.inner,
            key: self.key.ok_or_else(|| Report::msg("Missing signing key"))?,
            nonce: None,
            directory,
        })
    }
}

#[derive(Debug)]
pub struct Client {
    pub(super) inner: reqwest::Client,
    key: Arc<yacme_key::SigningKey>,
    nonce: Option<Nonce>,
    pub(super) directory: Directory,
}

impl Client {
    /// Create a new ACME client from a directory
    pub fn new(key: Arc<yacme_key::SigningKey>, directory: Directory) -> Self {
        Self {
            inner: reqwest::Client::new(),
            key,
            nonce: None,
            directory,
        }
    }

    /// Create a new ACME client from the URL for a directory
    /// and a user account key pair.
    pub async fn new_from_directory_url(
        key: Arc<yacme_key::SigningKey>,
        url: Url,
    ) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::new();
        let response = client.get(url.as_str()).send().await?.error_for_status()?;

        let directory = response.json().await?;

        Ok(Self {
            inner: client,
            key,
            nonce: None,
            directory,
        })
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub(super) fn public_key(&self) -> yacme_key::PublicKey {
        self.key.public_key()
    }

    pub(super) fn key(&self) -> &Arc<yacme_key::SigningKey> {
        &self.key
    }
}

impl Client {
    pub(super) async fn key_post<P: Serialize>(
        &mut self,
        request: Request,
        payload: &P,
    ) -> Result<reqwest::Response, AcmeError> {
        let nonce = self.get_nonce().await?;
        let key = self.key.clone();
        let header = ProtectedHeader::new_acme_header(&key, request.url().clone().into(), nonce);

        let response = self.execute_post(request, payload, header).await?;
        if response.status().is_success() {
            Ok(response)
        } else {
            let body = response.bytes().await?;
            let error: AcmeErrorDocument = serde_json::from_slice(&body).map_err(AcmeError::de)?;
            Err(error.into())
        }
    }

    async fn execute_post<P: Serialize>(
        &mut self,
        mut request: Request,
        payload: &P,
        header: AcmeProtectedHeader<'_>,
    ) -> Result<reqwest::Response, AcmeError> {
        #[cfg(feature = "debug-messages")]
        {
            eprintln!("ProtectedHeader:");
            eprintln!("{}", serde_json::to_string_pretty(&header).unwrap());
            eprintln!("Payload:");
            eprintln!("{}", serde_json::to_string_pretty(payload).unwrap());
        }

        let token = UnsignedToken::post(header, payload)
            .sign(self.key.deref())
            .unwrap();

        #[cfg(feature = "debug-messages")]
        {
            eprintln!("Full Token:");
            eprintln!("{}", serde_json::to_string_pretty(&token).unwrap());
        }

        let body = serde_json::to_vec(&token).map_err(AcmeError::ser)?;

        request
            .headers_mut()
            .insert(http::header::CONTENT_TYPE, CONTENT_JOSE.parse().unwrap());
        *request.method_mut() = http::Method::POST;
        *request.body_mut() = Some(body.into());

        let response = self.inner.execute(request).await?;
        self.record_nonce(response.headers())?;

        Ok(response)
    }

    pub(super) async fn account_post<P: Serialize>(
        &mut self,
        account: &AccountKeyIdentifier,
        request: Request,
        payload: &P,
    ) -> Result<reqwest::Response, AcmeError> {
        let nonce = self.get_nonce().await?;
        let header =
            ProtectedHeader::new_acme_account_header(account, request.url().clone().into(), nonce);
        let response = self.execute_post(request, payload, header).await?;
        if response.status().is_success() {
            Ok(response)
        } else {
            let body = response.bytes().await?;
            let error: AcmeErrorDocument = serde_json::from_slice(&body).map_err(AcmeError::de)?;
            Err(error.into())
        }
    }

    async fn execute_get(
        &mut self,
        mut request: Request,
        header: AcmeProtectedHeader<'_>,
    ) -> Result<reqwest::Response, AcmeError> {
        let token = UnsignedToken::get(header).sign(self.key.deref()).unwrap();

        let body = serde_json::to_vec(&token).map_err(AcmeError::ser)?;

        request
            .headers_mut()
            .insert(http::header::CONTENT_TYPE, CONTENT_JOSE.parse().unwrap());
        *request.method_mut() = http::Method::POST;
        *request.body_mut() = Some(body.into());

        loop {
            let response = self.inner.execute(request.try_clone().unwrap()).await?;
            self.record_nonce(response.headers())?;

            if response.status().is_success() {
                return Ok(response);
            } else {
                let body = response.bytes().await?;
                let error: AcmeErrorDocument =
                    serde_json::from_slice(&body).map_err(AcmeError::de)?;

                if matches!(error.kind(), AcmeErrorCode::BadNonce) {
                    tracing::trace!("Retrying request with next nonce");
                } else {
                    return Err(error.into());
                }
            }
        }
    }

    pub(super) async fn account_get(
        &mut self,
        account: &AccountKeyIdentifier,
        request: Request,
    ) -> Result<reqwest::Response, AcmeError> {
        let nonce = self.get_nonce().await?;
        let header =
            ProtectedHeader::new_acme_account_header(account, request.url().clone().into(), nonce);
        let response = self.execute_get(request, header).await?;
        if response.status().is_success() {
            Ok(response)
        } else {
            let body = response.bytes().await?;
            let error: AcmeErrorDocument = serde_json::from_slice(&body).map_err(AcmeError::de)?;
            Err(error.into())
        }
    }
}

fn extract_nonce(headers: &HeaderMap) -> Result<Nonce, AcmeError> {
    let value = headers.get(NONCE_HEADER).ok_or(AcmeError::MissingNonce)?;
    Ok(Nonce::from(
        value
            .to_str()
            .map_err(|_| AcmeError::InvalidNonce(Some(value.clone())))?
            .to_owned(),
    ))
}

impl Client {
    fn record_nonce(&mut self, headers: &HeaderMap) -> Result<(), AcmeError> {
        self.nonce = Some(extract_nonce(headers)?);
        Ok(())
    }

    async fn get_nonce(&mut self) -> Result<Nonce, AcmeError> {
        if let Some(value) = self.nonce.take() {
            return Ok(value);
        }

        tracing::debug!("Requesting a new nonce");
        let response = self
            .inner
            .head(self.directory.new_nonce.clone().as_str())
            .send()
            .await
            .map_err(AcmeError::nonce)?;

        response.error_for_status_ref().map_err(AcmeError::nonce)?;

        let value = extract_nonce(response.headers())?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn extract_nonce_from_header() {
        let response = crate::response!("new-nonce.http");
        let nonce = extract_nonce(response.headers()).unwrap();
        assert_eq!(nonce.as_ref(), "oFvnlFP1wIhRlYS2jTaXbA");
    }

    #[test]
    fn new_account_request() {
        let nonce = "6S8IqOGY7eL2lsGoTZYifg";
        let key = crate::key!("ec-p255");
        let builder = crate::account::AccountBuilder::new()
            .add_contact_email("cert-admin@example.org")
            .unwrap()
            .add_contact_email("admin@example.org")
            .unwrap()
            .agree_to_terms_of_service();

        let header = ProtectedHeader::new_acme_header(
            &key,
            "https://example.com/acme/new-account".parse().unwrap(),
            Nonce::from(nonce.to_owned()),
        );
        let public = key.public_key();
        let payload = builder.build_payload(
            &public,
            "https://example.com/acme/new-account".parse().unwrap(),
        );

        let token = UnsignedToken::post(header, &payload);
        let signed_token = token.sign(key.deref()).unwrap();

        let serialized = serde_json::to_value(signed_token).unwrap();
        let expected = serde_json::from_str::<Value>(crate::example!("new-account.json")).unwrap();

        assert_eq!(
            serialized["payload"], expected["payload"],
            "payload mismatch"
        );
        assert_eq!(
            serialized["protected"], expected["protected"],
            "header mismatch"
        );
    }
}
