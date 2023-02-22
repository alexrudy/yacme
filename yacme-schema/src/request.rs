use std::{ops::Deref, sync::Arc};

use serde::Serialize;
use yacme_key::SigningKey;
use yacme_protocol::{
    jose::{AccountKeyIdentifier, Nonce, ProtectedHeader, UnsignedToken},
    AcmeError, Url,
};

const CONTENT_JOSE: &str = "application/jose+json";

#[derive(Debug, Clone, Copy)]
pub enum Method<T> {
    Get,
    Post(T),
}

#[derive(Debug, Clone)]
pub enum Key {
    Identified {
        identifier: AccountKeyIdentifier,
        key: Arc<SigningKey>,
    },
    Signed {
        key: Arc<SigningKey>,
    },
}

impl From<(Arc<SigningKey>, Option<AccountKeyIdentifier>)> for Key {
    fn from((key, id): (Arc<SigningKey>, Option<AccountKeyIdentifier>)) -> Self {
        match id {
            Some(identifier) => Key::Identified { identifier, key },
            None => Key::Signed { key },
        }
    }
}

impl From<Arc<SigningKey>> for Key {
    fn from(value: Arc<SigningKey>) -> Self {
        Key::Signed { key: value }
    }
}

impl From<(Arc<SigningKey>, AccountKeyIdentifier)> for Key {
    fn from((key, identifier): (Arc<SigningKey>, AccountKeyIdentifier)) -> Self {
        Key::Identified { identifier, key }
    }
}

#[derive(Debug, Clone)]
pub struct Request<T> {
    method: Method<T>,
    url: Url,
    key: Key,
}

impl<T> Request<T> {
    fn new(method: Method<T>, url: Url, key: Key) -> Self {
        Self { method, url, key }
    }

    pub fn post<K: Into<Key>>(payload: T, url: Url, key: K) -> Self {
        Self::new(Method::Post(payload), url, key.into())
    }

    pub fn with_url(mut self, url: Url) -> Self {
        self.url = url;
        self
    }
}
impl Request<()> {
    pub fn get<K: Into<Key>>(url: Url, key: K) -> Self {
        Self::new(Method::Get, url, key.into())
    }
}

impl<T> Request<T>
where
    T: Serialize,
{
    pub fn sign(&self, nonce: Nonce) -> Result<SignedRequest, AcmeError> {
        let (header, key) = match &self.key {
            Key::Identified { identifier, key } => (
                ProtectedHeader::new_acme_account_header(identifier, self.url.clone(), nonce),
                key,
            ),
            Key::Signed { key } => (
                ProtectedHeader::new_acme_header(key, self.url.clone(), nonce),
                key,
            ),
        };

        let token = match &self.method {
            Method::Get => UnsignedToken::get(header),
            Method::Post(payload) => UnsignedToken::post(header, payload),
        };

        let signed_token = token.sign(key.deref())?;
        let mut request = reqwest::Request::new(http::Method::POST, self.url.clone().into());
        request
            .headers_mut()
            .insert(http::header::CONTENT_TYPE, CONTENT_JOSE.parse().unwrap());
        let body = serde_json::to_vec(&signed_token).map_err(AcmeError::ser)?;
        *request.body_mut() = Some(body.into());

        Ok(SignedRequest(request))
    }
}

pub struct SignedRequest(reqwest::Request);

impl SignedRequest {
    pub(crate) fn into_inner(self) -> reqwest::Request {
        self.0
    }
}
