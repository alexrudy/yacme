use http::HeaderMap;
use reqwest::Certificate;
use serde::{de::DeserializeOwned, Serialize};

use yacme_protocol::errors::{AcmeError, AcmeErrorCode, AcmeErrorDocument};
use yacme_protocol::jose::Nonce;
use yacme_protocol::Url;

use crate::response::{Decode, Response};
use crate::Request;

#[cfg(feature = "debug-messages")]
use yacme_protocol::fmt::AcmeFormat;

#[cfg(feature = "debug-messages")]
use crate::request::Encode;

const NONCE_HEADER: &str = "Replay-Nonce";

pub struct ClientBuilder {
    inner: reqwest::ClientBuilder,
    new_nonce: Option<Url>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    pub fn new() -> Self {
        ClientBuilder {
            inner: reqwest::Client::builder(),
            new_nonce: None,
        }
    }

    pub fn with_nonce_url(mut self, url: Url) -> Self {
        self.new_nonce = Some(url);
        self
    }

    pub fn add_root_certificate(mut self, cert: Certificate) -> Self {
        self.inner = self.inner.add_root_certificate(cert);
        self
    }

    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner = self.inner.connect_timeout(timeout);
        self
    }

    pub fn build(self) -> Result<Client, reqwest::Error> {
        Ok(Client {
            inner: self.inner.build()?,
            nonce: None,
            new_nonce: self.new_nonce.unwrap(),
        })
    }
}

#[derive(Debug)]
pub struct Client {
    pub(super) inner: reqwest::Client,
    nonce: Option<Nonce>,
    new_nonce: Url,
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }
}

impl Client {
    pub async fn get<R>(&mut self, url: Url) -> Result<Response<R>, AcmeError>
    where
        R: DeserializeOwned,
    {
        let response = self.inner.get(url.as_str()).send().await?;
        Response::from_decoded_response(response).await
    }

    #[cfg(not(feature = "debug-messages"))]
    pub async fn execute<P, R>(&mut self, request: Request<P>) -> Result<Response<R>, AcmeError>
    where
        P: Serialize,
        R: Decode,
    {
        Response::from_decoded_response(self.execute_internal(request).await?).await
    }

    #[cfg(feature = "debug-messages")]
    pub async fn execute<P, R>(&mut self, request: Request<P>) -> Result<Response<R>, AcmeError>
    where
        P: Serialize,
        R: Decode + Encode,
    {
        eprintln!("{}", request.as_signed().formatted());
        Response::from_decoded_response(self.execute_internal(request).await?)
            .await
            .map(|r| {
                eprintln!("{}", r.formatted());
                r
            })
    }

    #[inline]
    async fn execute_internal<P>(
        &mut self,
        request: Request<P>,
    ) -> Result<reqwest::Response, AcmeError>
    where
        P: Serialize,
    {
        let mut nonce = self.get_nonce().await?;
        loop {
            let signed = request.sign(nonce)?;
            let response = self.inner.execute(signed.into_inner()).await?;
            self.record_nonce(response.headers())?;
            if response.status().is_success() {
                return Ok(response);
            } else {
                let body = response.bytes().await?;
                let error: AcmeErrorDocument =
                    serde_json::from_slice(&body).map_err(AcmeError::de)?;

                if matches!(error.kind(), AcmeErrorCode::BadNonce) {
                    tracing::trace!("Retrying request with next nonce");
                    nonce = self.get_nonce().await?;
                } else {
                    return Err(error.into());
                }
            }
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
            .head(self.new_nonce.as_str())
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
    use std::ops::Deref;

    use serde_json::Value;
    use yacme_protocol::jose::{ProtectedHeader, UnsignedToken};

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
