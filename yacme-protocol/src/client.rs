//! Client for sending HTTP requests to an ACME server
use http::HeaderMap;
use reqwest::Certificate;
use serde::Serialize;

use crate::errors::{AcmeError, AcmeErrorCode, AcmeErrorDocument};
use crate::jose::Nonce;
use crate::response::{Decode, Response};
use crate::Request;
use crate::Url;

#[cfg(feature = "trace-requests")]
use crate::fmt::AcmeFormat;

#[cfg(feature = "trace-requests")]
use crate::request::Encode;

const NONCE_HEADER: &str = "Replay-Nonce";

/// Builder struct for an ACME HTTP client.
#[derive(Debug)]
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
        let builder =
            reqwest::Client::builder().user_agent(concat!("YACME / ", env!("CARGO_PKG_VERSION")));

        ClientBuilder {
            inner: builder,
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
            new_nonce: self.new_nonce,
        })
    }
}

/// ACME HTTP Client
///
/// The client handles sending ACME HTTP requests, and providing ACME HTTP
/// responses using the [`crate::Request`] and [`crate::Response`] objects
/// respectively.
#[derive(Debug, Default)]
pub struct Client {
    pub(super) inner: reqwest::Client,
    nonce: Option<Nonce>,
    new_nonce: Option<Url>,
}

impl Client {
    /// Create a new client builder to configure a client.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub fn set_new_nonce_url(&mut self, url: Url) {
        self.new_nonce = Some(url);
    }
}

impl Client {
    /// Run a plain HTTP `GET` request without using the ACME HTTP JWS
    /// protocol.
    pub async fn get<R>(&mut self, url: Url) -> Result<Response<R>, AcmeError>
    where
        R: Decode,
    {
        let response = self.inner.get(url.as_str()).send().await?;
        Response::from_decoded_response(response).await
    }

    /// Execute an HTTP request using the ACME protocol.
    #[cfg(not(feature = "trace-requests"))]
    pub async fn execute<P, R>(&mut self, request: Request<P>) -> Result<Response<R>, AcmeError>
    where
        P: Serialize,
        R: Decode,
    {
        Response::from_decoded_response(self.execute_internal(request).await?).await
    }

    #[cfg(feature = "trace-requests")]
    pub async fn execute<P, R>(&mut self, request: Request<P>) -> Result<Response<R>, AcmeError>
    where
        P: Serialize,
        R: Decode + Encode,
    {
        tracing::trace!("REQ: \n{}", request.as_signed().formatted());
        Response::from_decoded_response(self.execute_internal(request).await?)
            .await
            .map(|r| {
                tracing::trace!("RES: \n{}", r.formatted());
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

pub(crate) fn extract_nonce(headers: &HeaderMap) -> Result<Nonce, AcmeError> {
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

        if let Some(url) = &self.new_nonce {
            tracing::debug!("Requesting a new nonce");
            let response = self
                .inner
                .head(url.as_str())
                .send()
                .await
                .map_err(AcmeError::nonce)?;

            response.error_for_status_ref().map_err(AcmeError::nonce)?;

            let value = extract_nonce(response.headers())?;
            Ok(value)
        } else {
            tracing::warn!("No nonce URL provided, unable to fetch new nonce");
            Err(AcmeError::MissingNonce)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn extract_nonce_from_header() {
        let response = crate::response!("new-nonce.http");
        let nonce = extract_nonce(response.headers()).unwrap();
        assert_eq!(nonce.as_ref(), "oFvnlFP1wIhRlYS2jTaXbA");
    }
}
