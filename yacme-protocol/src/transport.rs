use std::fmt;
use std::ops::Deref;
use std::{marker::PhantomData, sync::Arc};

use eyre::Report;
use http::HeaderMap;
use reqwest::{Request, Url};
use ring::signature::{EcdsaKeyPair, KeyPair, Signature};
use serde::{de, ser, Serialize};
use thiserror::Error;

use super::directory::Directory;
use super::errors::{AcmeError, AcmeErrorDocument};
use super::key::SignatureAlgorithm;

const NONCE_HEADER: &str = "Replay-Nonce";
const CONTENT_JOSE: &str = "application/jose+json";

#[derive(Debug, Serialize)]
pub struct Nonce(String);

#[derive(Debug, Clone)]
pub(super) struct Base64JSON<T>(pub T);

impl<T> Base64JSON<T>
where
    T: Serialize,
{
    fn serialized_value(&self) -> Result<String, serde_json::Error> {
        let inner = serde_json::to_vec(&self.0)?;
        Ok(base64_url::encode(&inner))
    }
}

impl<T> From<T> for Base64JSON<T> {
    fn from(value: T) -> Self {
        Base64JSON(value)
    }
}

struct Base64JSONVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for Base64JSONVisitor<T>
where
    T: de::DeserializeOwned,
{
    type Value = Base64JSON<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a base64url encoded type")
    }

    fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let data = base64_url::decode(v)
            .map_err(|_| E::invalid_value(de::Unexpected::Str(v), &"invalid base64url encoding"))?;

        let data = serde_json::from_slice(&data)
            .map_err(|err| E::custom(format!("invalid JSON: {err}")))?;
        Ok(Base64JSON(data))
    }
}

impl<'de, T> de::Deserialize<'de> for Base64JSON<T>
where
    T: de::DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(Base64JSONVisitor(PhantomData))
    }
}

impl<T> ser::Serialize for Base64JSON<T>
where
    T: ser::Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;
        let inner = self
            .serialized_value()
            .map_err(|err| S::Error::custom(format!("Error producing inner JSON: {err}")))?;
        serializer.serialize_str(&inner)
    }
}

#[derive(Debug, Clone)]
pub(super) struct Base64DataRef<'a, T: ?Sized>(pub &'a T);

impl<'a, T: ?Sized> From<&'a T> for Base64DataRef<'a, T> {
    fn from(value: &'a T) -> Self {
        Base64DataRef(value)
    }
}

impl<'a, T> ser::Serialize for Base64DataRef<'a, T>
where
    T: AsRef<[u8]> + ?Sized,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let target = base64_url::encode(self.0);
        serializer.serialize_str(&target)
    }
}

#[derive(Debug, Clone)]
pub(super) struct Base64Data<T>(pub T);

impl<T> From<T> for Base64Data<T> {
    fn from(value: T) -> Self {
        Base64Data(value)
    }
}

impl<T> ser::Serialize for Base64Data<T>
where
    T: AsRef<[u8]>,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let target = base64_url::encode(&self.0);
        serializer.serialize_str(&target)
    }
}

#[derive(Debug, Clone)]
pub(super) struct AccountKeyIdentifier(Arc<Url>);

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
#[serde(bound(serialize = "KI: AsRef<[u8]>, KP: AsRef<[u8]>"))]
pub(super) struct ProtectedHeader<'k, KI, KP: ?Sized> {
    algorithm: SignatureAlgorithm,
    key_id: Option<Base64Data<KI>>,
    web_key: Option<Base64DataRef<'k, KP>>,
    url: Url,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<Nonce>,
}

impl<'k, KI, KP> ProtectedHeader<'k, KI, KP> {
    pub(super) fn new(
        algorithm: SignatureAlgorithm,
        key_id: Option<Base64Data<KI>>,
        web_key: Option<Base64DataRef<'k, KP>>,
        url: Url,
        nonce: Option<Nonce>,
    ) -> Self {
        Self {
            algorithm,
            key_id,
            web_key,
            url,
            nonce,
        }
    }
}

type AcmeProtectedHeader<'k> =
    ProtectedHeader<'k, &'k AccountKeyIdentifier, <EcdsaKeyPair as KeyPair>::PublicKey>;

impl<'k> ProtectedHeader<'k, &'k AccountKeyIdentifier, <EcdsaKeyPair as KeyPair>::PublicKey> {
    fn new_acme_header(key: &'k EcdsaKeyPair, url: Url, nonce: Nonce) -> AcmeProtectedHeader<'k> {
        Self {
            algorithm: SignatureAlgorithm::ES256,
            web_key: Some(key.public_key().into()),
            key_id: None,
            url,
            nonce: Some(nonce),
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
            key_id: Some(account.into()),
            url,
            nonce: Some(nonce),
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
#[serde(bound(serialize = "P: Serialize, KI: AsRef<[u8]>, KP: AsRef<[u8]>, S: AsRef<[u8]>"))]
pub struct SignedToken<'k, P, KI, KP, S> {
    protected: Base64JSON<ProtectedHeader<'k, KI, KP>>,
    payload: Payload<P>,
    signature: Base64Data<S>,
}

#[derive(Debug, Error)]
pub(super) enum SigningError<E>
where
    E: std::fmt::Display,
{
    Signing(#[source] E),
    JsonSerialize(#[source] serde_json::Error),
}

impl<E> From<SigningError<E>> for AcmeError
where
    E: std::fmt::Display + std::fmt::Debug + Sync + Send + 'static,
{
    fn from(value: SigningError<E>) -> Self {
        match value {
            SigningError::Signing(error) => Self::Signing(eyre::Report::msg(error)),
            SigningError::JsonSerialize(error) => Self::ser(error),
        }
    }
}

pub(super) struct UnsignedToken<'k, P, KI, KP> {
    protected: Base64JSON<ProtectedHeader<'k, KI, KP>>,
    payload: Payload<P>,
}

impl<'k, KI, KP> UnsignedToken<'k, (), KI, KP> {
    pub(super) fn get(protected: ProtectedHeader<'k, KI, KP>) -> Self {
        Self {
            protected: protected.into(),
            payload: Payload::Empty,
        }
    }
}

impl<'k, P, KI, KP> UnsignedToken<'k, P, KI, KP> {
    pub(super) fn post(protected: ProtectedHeader<'k, KI, KP>, payload: P) -> Self {
        Self {
            protected: protected.into(),
            payload: payload.into(),
        }
    }
}

impl<'k, P, KI, KP> UnsignedToken<'k, P, KI, KP>
where
    P: Serialize,
    KI: AsRef<[u8]>,
    KP: AsRef<[u8]>,
{
    pub(super) fn sign<'m: 'k, F, S, E>(
        self,
        f: F,
    ) -> Result<SignedToken<'k, P, KI, KP, S>, SigningError<E>>
    where
        F: FnOnce(&[u8]) -> Result<S, E>,
        E: std::fmt::Display,
        S: 'static,
    {
        let header = self
            .protected
            .serialized_value()
            .map_err(SigningError::JsonSerialize)?;
        let payload = self
            .payload
            .serialized_value()
            .map_err(SigningError::JsonSerialize)?;
        let message = base64_url::encode(&format!("{header}.{payload}"));

        let signature = f(message.as_bytes()).map_err(SigningError::Signing)?;
        Ok(SignedToken {
            protected: self.protected,
            payload: self.payload,
            signature: signature.into(),
        })
    }
}

impl<'k, P> UnsignedToken<'k, P, &'k AccountKeyIdentifier, <EcdsaKeyPair as KeyPair>::PublicKey>
where
    P: Serialize,
{
    fn sign_ecdsa<'m: 'k>(
        self,
        rng: &'m dyn ring::rand::SecureRandom,
        key: &'k EcdsaKeyPair,
    ) -> Result<
        SignedToken<
            'k,
            P,
            &'k AccountKeyIdentifier,
            <EcdsaKeyPair as KeyPair>::PublicKey,
            Signature,
        >,
        SigningError<Report>,
    > {
        self.sign(|message| {
            key.sign(rng, message)
                .map_err(|_| Report::msg("An unspecified signing error occured"))
        })
    }
}

#[derive(Debug)]
pub struct Client {
    pub(super) inner: reqwest::Client,
    key: Arc<EcdsaKeyPair>,
    nonce: Option<Nonce>,
    pub(super) directory: Directory,
    rng: Box<dyn ring::rand::SecureRandom>,
}

impl Client {
    /// Create a new ACME client from a directory
    pub fn new(key: Arc<EcdsaKeyPair>, directory: Directory) -> Self {
        Self {
            inner: reqwest::Client::new(),
            key,
            nonce: None,
            directory,
            rng: Box::new(ring::rand::SystemRandom::new()) as _,
        }
    }

    /// Create a new ACME client from the URL for a directory
    /// and a user account key pair.
    pub async fn new_from_directory_url(
        key: Arc<EcdsaKeyPair>,
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
            rng: Box::new(ring::rand::SystemRandom::new()) as _,
        })
    }

    pub(super) fn public_key(&self) -> &<EcdsaKeyPair as KeyPair>::PublicKey {
        self.key.public_key()
    }

    pub(super) fn key(&self) -> &Arc<EcdsaKeyPair> {
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
        let token =
            UnsignedToken::post(header, payload).sign_ecdsa(self.rng.as_ref(), &self.key)?;

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
        let token = UnsignedToken::get(header).sign_ecdsa(self.rng.as_ref(), &self.key)?;

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
