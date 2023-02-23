use std::fmt::Write;
use std::{ops::Deref, sync::Arc};

use serde::Serialize;
use yacme_key::{Signature, SigningKey};

use crate::fmt::{self, HttpCase};
use crate::jose::{AccountKeyIdentifier, Nonce, ProtectedHeader, SignedToken, UnsignedToken};
use crate::AcmeError;
use crate::Url;

const CONTENT_JOSE: &str = "application/jose+json";

pub trait Encode {
    fn encode(&self) -> Result<String, AcmeError>;
}

impl<T> Encode for T
where
    T: Serialize,
{
    fn encode(&self) -> Result<String, AcmeError> {
        serde_json::to_string_pretty(&self).map_err(AcmeError::ser)
    }
}

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

impl Key {
    pub fn header(&self, url: Url, nonce: Nonce) -> ProtectedHeader<&AccountKeyIdentifier> {
        match &self {
            Key::Identified { identifier, key: _ } => {
                ProtectedHeader::new_acme_account_header(identifier, url, nonce)
            }

            Key::Signed { key } => ProtectedHeader::new_acme_header(key, url, nonce),
        }
    }

    pub fn key(&self) -> &Arc<SigningKey> {
        match self {
            Key::Identified { identifier: _, key } => key,
            Key::Signed { key } => key,
        }
    }
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
    fn token<'t>(
        &'t self,
        header: ProtectedHeader<&'t AccountKeyIdentifier>,
    ) -> UnsignedToken<&'t T, &'t AccountKeyIdentifier> {
        match &self.method {
            Method::Get => UnsignedToken::get(header),
            Method::Post(payload) => UnsignedToken::post(header, payload),
        }
    }

    fn signed_token(
        &self,
        nonce: Nonce,
    ) -> Result<SignedToken<&T, &AccountKeyIdentifier, Signature>, AcmeError> {
        let header = self.key.header(self.url.clone(), nonce);
        let key = self.key.key();

        let token = self.token(header);
        Ok(token.sign(key.deref())?)
    }

    pub fn sign(&self, nonce: Nonce) -> Result<SignedRequest, AcmeError> {
        let signed_token = self.signed_token(nonce)?;
        let mut request = reqwest::Request::new(http::Method::POST, self.url.clone().into());
        request
            .headers_mut()
            .insert(http::header::CONTENT_TYPE, CONTENT_JOSE.parse().unwrap());
        let body = serde_json::to_vec(&signed_token).map_err(AcmeError::ser)?;
        *request.body_mut() = Some(body.into());

        Ok(SignedRequest(request))
    }

    pub fn as_signed(&self) -> FormatSignedRequest<'_, T> {
        FormatSignedRequest(self)
    }

    fn acme_format_preamble<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        let method = match &self.method {
            Method::Get => "POST as GET",
            Method::Post(_) => "POST",
        };
        let path = self.url.path();

        writeln!(f, "{method} {path} HTTP/1.1")?;
        if let Some(host) = self.url.host() {
            writeln!(f, "{}: {}", http::header::HOST.titlecase(), host)?;
        }

        writeln!(
            f,
            "{}: {}",
            http::header::CONTENT_TYPE.titlecase(),
            CONTENT_JOSE
        )?;

        writeln!(f)?;
        Ok(())
    }
}

pub struct FormatSignedRequest<'r, T>(&'r Request<T>);

impl<'r, T> fmt::AcmeFormat for FormatSignedRequest<'r, T>
where
    T: Serialize,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        self.0.acme_format_preamble(f)?;
        let nonce = String::from("<nonce>").into();
        let signed = self.0.signed_token(nonce).unwrap();
        <SignedToken<_, _, _> as fmt::AcmeFormat>::fmt(&signed, f)
    }
}

impl<T> fmt::AcmeFormat for Request<T>
where
    T: Serialize,
{
    fn fmt<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        self.acme_format_preamble(f)?;
        let nonce = String::from("<nonce>").into();
        let header = self.key.header(self.url.clone(), nonce);
        let token = self.token(header);

        <UnsignedToken<_, _> as fmt::AcmeFormat>::fmt(&token, f)
    }
}

pub struct SignedRequest(reqwest::Request);

impl SignedRequest {
    pub(crate) fn into_inner(self) -> reqwest::Request {
        self.0
    }
}
