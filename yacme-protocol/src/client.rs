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
    pub(crate) fn new() -> Self {
        let builder =
            reqwest::Client::builder().user_agent(concat!("YACME / ", env!("CARGO_PKG_VERSION")));

        ClientBuilder {
            inner: builder,
            new_nonce: None,
        }
    }

    /// Set the URL to use to fetch a new nonce.
    ///
    /// This is used to bootstrap the nonce at the start of an interaction
    /// with an ACME provider, and to acquire a new nonce if an old one
    /// ends up invalidated. Both of these actions happen transparently
    /// when using the [`Client::execute`] method, to ensure that the JWT always
    /// contains a valid nonce.
    pub fn with_nonce_url(mut self, url: Url) -> Self {
        self.new_nonce = Some(url);
        self
    }

    /// Add a custom root certificate to the underlying [`reqwest::Client`].
    ///
    /// This is useful if you are using a self-signed certificate from your ACME
    /// provider for testing, e.g. when using [Pebble](https://github.com/letsencrypt/pebble).
    pub fn add_root_certificate(mut self, cert: Certificate) -> Self {
        self.inner = self.inner.add_root_certificate(cert);
        self
    }

    /// Set a timeout on the underlying [`reqwest::Client`].
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    /// Set a connect timeout on the underlying [`reqwest::Client`].
    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner = self.inner.connect_timeout(timeout);
        self
    }

    /// Finalize this and build this client. See [`reqwest::ClientBuilder::build`].
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
///
/// # Example
///
/// You can use a Client to send HTTP requests to an ACME provider, using either
/// [`Client::get`] to send a plain HTTP GET request, or [`Client::execute`] to
/// send a signed ACME HTTP request.
///
/// See [`crate::Request`] for more information on how to create a request.
///
/// ```no_run
/// # use yacme_protocol::Client;
/// # use yacme_protocol::Request;
/// let mut client = Client::default();
/// client.set_new_nonce_url("https://acme.example.com/new-nonce".parse().unwrap());
///
/// let request = Request::get("https://acme.example.com/account/1");
/// let response = client.execute(request).await?;
/// ```
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

    /// Set the URL used for fetching a new Nonce from the ACME provider.
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
    ///
    /// See [`crate::Request`] for more information on how to create a request.
    ///
    /// Request payloads must be serializable, and request responses must implement [`Decode`].
    /// `Decode` is implemented for all types that implement [`serde::Deserialize`].
    #[cfg(any(not(feature = "trace-requests"), docs))]
    pub async fn execute<P, R>(&mut self, request: Request<P>) -> Result<Response<R>, AcmeError>
    where
        P: Serialize,
        R: Decode,
    {
        Response::from_decoded_response(self.execute_internal(request).await?).await
    }

    /// Execute an HTTP request using the ACME protocol, and trace the request.
    ///
    /// Tracing is done using the [RFC 8885](https://tools.ietf.org/html/rfc8885) format,
    /// via the `tracing` crate, at the `trace` level.
    #[cfg(all(feature = "trace-requests", not(docs)))]
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
