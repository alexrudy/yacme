use std::ops::Deref;
use std::sync::Arc;

use eyre::Report;
use http::HeaderMap;
use reqwest::{Request, Url};
use serde::{ser, Deserialize, Serialize};
use thiserror::Error;

use super::base64::{Base64Data, Base64JSON};
use super::directory::Directory;
use super::errors::{AcmeError, AcmeErrorDocument};
use yacme_key::Signature;

const NONCE_HEADER: &str = "Replay-Nonce";
const CONTENT_JOSE: &str = "application/jose+json";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    ES256,
    HS256,
}

#[derive(Debug, Serialize)]
pub struct Nonce(String);

impl AsRef<str> for Nonce {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone)]
pub(super) struct AccountKeyIdentifier(Arc<Url>);

impl ser::Serialize for AccountKeyIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.deref().serialize(serializer)
    }
}

impl From<Url> for AccountKeyIdentifier {
    fn from(value: Url) -> Self {
        AccountKeyIdentifier(Arc::new(value))
    }
}

impl AccountKeyIdentifier {
    pub fn to_url(&self) -> Url {
        self.0.deref().clone()
    }
}

impl AsRef<[u8]> for AccountKeyIdentifier {
    fn as_ref(&self) -> &[u8] {
        self.0.as_str().as_bytes()
    }
}

#[derive(Debug, Serialize)]
#[serde(bound(serialize = "KI: Serialize"))]
pub(super) struct ProtectedHeader<KI> {
    #[serde(rename = "alg")]
    algorithm: SignatureAlgorithm,
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    key_id: Option<KI>,
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    web_key: Option<yacme_key::jwk::Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<Nonce>,
    url: Url,
}

impl<KI> ProtectedHeader<KI> {
    pub(super) fn new(
        algorithm: SignatureAlgorithm,
        key_id: Option<KI>,
        web_key: Option<yacme_key::jwk::Jwk>,
        url: Url,
        nonce: Option<Nonce>,
    ) -> Self {
        Self {
            algorithm,
            key_id,
            web_key,
            nonce,
            url,
        }
    }
}

type AcmeProtectedHeader<'k> = ProtectedHeader<&'k AccountKeyIdentifier>;

impl<'k> ProtectedHeader<&'k AccountKeyIdentifier> {
    fn new_acme_header(
        key: &'k yacme_key::SigningKey,
        url: Url,
        nonce: Nonce,
    ) -> AcmeProtectedHeader<'k> {
        Self {
            algorithm: SignatureAlgorithm::ES256,
            web_key: Some(key.as_jwk()),
            key_id: None,
            nonce: Some(nonce),
            url,
        }
    }

    fn new_acme_account_header(
        account: &'k AccountKeyIdentifier,
        url: Url,
        nonce: Nonce,
    ) -> AcmeProtectedHeader<'k> {
        Self {
            algorithm: SignatureAlgorithm::ES256,
            web_key: None,
            key_id: Some(account),
            nonce: Some(nonce),
            url,
        }
    }
}

#[derive(Debug)]
enum Payload<P> {
    Json(Base64JSON<P>),
    Empty,
}

impl<P> Payload<P>
where
    P: Serialize,
{
    fn serialized_value(&self) -> Result<String, serde_json::Error> {
        match self {
            Payload::Json(data) => data.serialized_value(),
            Payload::Empty => Ok("".to_owned()),
        }
    }
}

impl<P> From<P> for Payload<P> {
    fn from(value: P) -> Self {
        Payload::Json(value.into())
    }
}

impl<P> ser::Serialize for Payload<P>
where
    P: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Payload::Json(data) => data.serialize(serializer),
            Payload::Empty => serializer.serialize_str(""),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(bound(serialize = "P: Serialize, KI: Serialize, S: AsRef<[u8]>"))]
pub struct SignedToken<P, KI, S> {
    protected: Base64JSON<ProtectedHeader<KI>>,
    payload: Payload<P>,
    signature: Base64Data<S>,
}

#[derive(Debug, Error)]
pub(super) enum SigningError {
    #[error("signature error")]
    Signing(#[from] signature::Error),
    #[error("serialization error: {0}")]
    JsonSerialize(#[source] serde_json::Error),
}

impl From<SigningError> for AcmeError {
    fn from(value: SigningError) -> Self {
        match value {
            SigningError::Signing(error) => Self::Signing(eyre::Report::msg(error)),
            SigningError::JsonSerialize(error) => Self::ser(error),
        }
    }
}

pub(super) struct UnsignedToken<P, KI> {
    protected: Base64JSON<ProtectedHeader<KI>>,
    payload: Payload<P>,
}

impl<KI> UnsignedToken<(), KI> {
    pub(super) fn get(protected: ProtectedHeader<KI>) -> Self {
        Self {
            protected: protected.into(),
            payload: Payload::Empty,
        }
    }
}

impl<P, KI> UnsignedToken<P, KI> {
    pub(super) fn post(protected: ProtectedHeader<KI>, payload: P) -> Self {
        Self {
            protected: protected.into(),
            payload: payload.into(),
        }
    }
}

impl<P, KI> UnsignedToken<P, KI>
where
    P: Serialize,
    KI: Serialize,
{
    fn signing_input(&self) -> Result<String, SigningError> {
        let header = self
            .protected
            .serialized_value()
            .map_err(SigningError::JsonSerialize)?;
        let payload = self
            .payload
            .serialized_value()
            .map_err(SigningError::JsonSerialize)?;
        let message = format!("{header}.{payload}");
        Ok(message)
    }

    pub(super) fn sign<K>(self, key: &K) -> Result<SignedToken<P, KI, Signature>, SigningError>
    where
        K: signature::Signer<Signature>,
    {
        let message = self.signing_input()?;
        let signature = key.try_sign(message.as_bytes())?;
        Ok(SignedToken {
            protected: self.protected,
            payload: self.payload,
            signature: signature.into(),
        })
    }

    pub(super) fn digest<D: signature::digest::Mac>(
        self,
        mut digest: D,
    ) -> Result<SignedToken<P, KI, Signature>, SigningError> {
        let message = self.signing_input()?;
        digest.update(message.as_bytes());
        let result = digest.finalize();
        Ok(SignedToken {
            protected: self.protected,
            payload: self.payload,
            signature: Signature::from(result.into_bytes().to_vec()).into(),
        })
    }
}

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
                    .get(url)
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
        let response = client.get(url).send().await?.error_for_status()?;

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
        let header = ProtectedHeader::new_acme_header(&key, request.url().clone(), nonce);

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
        eprintln!("ProtectedHeader:");
        eprintln!("{}", serde_json::to_string_pretty(&header).unwrap());
        eprintln!("Payload:");
        eprintln!("{}", serde_json::to_string_pretty(payload).unwrap());

        let token = UnsignedToken::post(header, payload)
            .sign(self.key.deref())
            .unwrap();

        eprintln!("Full Token:");
        eprintln!("{}", serde_json::to_string_pretty(&token).unwrap());

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
            ProtectedHeader::new_acme_account_header(account, request.url().clone(), nonce);
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

        let response = self.inner.execute(request).await?;
        self.record_nonce(response.headers())?;

        Ok(response)
    }

    pub(super) async fn account_get(
        &mut self,
        account: &AccountKeyIdentifier,
        request: Request,
    ) -> Result<reqwest::Response, AcmeError> {
        let nonce = self.get_nonce().await?;
        let header =
            ProtectedHeader::new_acme_account_header(account, request.url().clone(), nonce);
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
    Ok(Nonce(
        value
            .to_str()
            .map_err(|_| AcmeError::InvalidNonce(value.clone()))?
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
            .head(self.directory.new_nonce.clone())
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
            Nonce(nonce.into()),
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
