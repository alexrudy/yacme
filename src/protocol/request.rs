//! HTTP requests which adhere to RFC 8885
//!
//! [RFC 8885][] requires that most ACME HTTP requests (other than to the
//! directory endpoint and the new-nonce endpoint) be authenticated with a
//! JWS token using the flattened JSON format.
//!
//! This format is particular to ACME/[RFC 8885][] and so is implemented
//! here (along with [super::jose] which implements the JWS portion).
//!
//! For example, a request to create a new account might look like:
//! ```text
//! POST /acme/new-account HTTP/1.1
//! Host: example.com
//! Content-Type: application/jose+json
//!
//! {
//!   "protected": base64url({
//!     "alg": "ES256",
//!     "jwk": {...
//!     },
//!     "nonce": "6S8IqOGY7eL2lsGoTZYifg",
//!     "url": "https://example.com/acme/new-account"
//!   }),
//!   "payload": base64url({
//!     "termsOfServiceAgreed": true,
//!     "contact": [
//!       "mailto:cert-admin@example.org",
//!       "mailto:admin@example.org"
//!     ]
//!   }),
//!   "signature": "RZPOnYoPs1PhjszF...-nh6X1qtOFPB519I"
//! }
//! ```
//!
//! [RFC 8885]: https://datatracker.ietf.org/doc/html/rfc8555

use std::fmt::Write;
use std::{ops::Deref, sync::Arc};

use http::HeaderMap;
use serde::Serialize;

use super::fmt::HttpCase;
use super::jose::{AccountKeyIdentifier, Nonce, RequestHeader, UnsignedToken};
use super::AcmeError;
use super::Url;
use jaws::fmt;

const CONTENT_JOSE: &str = "application/jose+json";

/// Trait which marks request/response bodies which can be encoded to string
/// in some fashion.
///
/// This is only useful when formatting the response in the ACME-style HTTP
/// format, as used by [`super::fmt::AcmeFormat`].
///
/// There is a blanket implementation provided for any type which implements
/// [`serde::Serialize`], as we assume that serializable values would be sent
/// over the wire as JSON (or at least, it is acceptable to display the value
/// as JSON when printing the ACME server response). Other types can
/// implement this to provide a custom representation when showing an ACME
/// response.
pub trait Encode {
    /// Encode the value to a string suitable for an ACME request payload.
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

/// The HTTP request method in use with this ACME request.
///
/// All ACME requests use POST under the hood, since they all contain
/// a JWS-via-JOSE token to validate that the request is coming from
/// the account holder. However, sometimes the ACME server wants the
/// request to have GET semantics. In those cases, the payload will
/// be the empty string.
#[derive(Debug, Clone, Copy)]
pub enum Method<T> {
    /// GET-as-POST request with an empty string payload
    Get,
    /// POST request with a specific JSON payload.
    Post(T),
}

/// The components requrired to sign an ACME request from an account which
/// is already registered with the ACME service in question.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct Identified<K> {
    identifier: AccountKeyIdentifier,
    key: Arc<K>,
}

/// The components required to sign an ACME request for a new account,
/// when the ACME service is not yet aware of the public key being used.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct Signed<K> {
    key: Arc<K>,
}

/// The signing key and method for an ACME request.
///
/// There are two ways to sign an ACME request: Identified, and unidentifeid.
/// Identified requests correspond to an account which is already registered
/// with the ACME provider. In these cases, the request is signed with the account
/// key, but the JWS will not contain the JWK object for the public key, and
/// instead will have the `kid` (Key ID) field, which will contain an account
/// identifier. In ACME, the account identifier is a URL.
#[derive(Debug, Clone)]
pub enum Key<K> {
    /// A signing key which will be identified to the ACME service as a
    /// known account.
    Identified(Identified<K>),

    /// A signing key which will have the public component provided as a
    /// JWK structure inside the signed part of the request.
    Signed(Signed<K>),
}

impl<K> Key<K>
where
    K: jaws::algorithms::SigningAlgorithm,
    K::Key: Clone,
{
    /// Create a protected header which can use this [Key] for signing.
    ///
    /// ACME Protected headers must contain the target URL for the request, along with a
    /// [Nonce], which is used for replay protection.
    pub(crate) fn sign<P>(
        &self,
        mut token: jaws::UnsignedToken<RequestHeader, P>,
    ) -> Result<jaws::SignedToken<RequestHeader, P, K>, jaws::token::TokenSigningError<K::Error>>
    where
        P: Serialize,
    {
        match &self {
            Key::Identified(Identified { identifier, key }) => {
                token.header.registered.key_id = Some(AsRef::<str>::as_ref(&identifier).to_owned());
                token.sign(key.deref())
            }

            Key::Signed(Signed { key }) => {
                token.header.registered.key = true;
                token.sign(key.deref())
            }
        }
    }

    /// A reference to the signing key.
    pub fn key(&self) -> &Arc<K> {
        match self {
            Key::Identified(Identified { identifier: _, key }) => key,
            Key::Signed(Signed { key }) => key,
        }
    }
}

impl<K> From<(Arc<K>, Option<AccountKeyIdentifier>)> for Key<K> {
    fn from((key, id): (Arc<K>, Option<AccountKeyIdentifier>)) -> Self {
        match id {
            Some(identifier) => Key::Identified(Identified { identifier, key }),
            None => Key::Signed(Signed { key }),
        }
    }
}

impl<K> From<(Arc<K>, Url)> for Key<K> {
    fn from((key, id): (Arc<K>, Url)) -> Self {
        Key::Identified(Identified {
            identifier: AccountKeyIdentifier::from(id),
            key,
        })
    }
}

impl<K> From<Arc<K>> for Key<K> {
    fn from(value: Arc<K>) -> Self {
        Key::Signed(Signed { key: value })
    }
}

impl<K> From<(Arc<K>, AccountKeyIdentifier)> for Key<K> {
    fn from((key, identifier): (Arc<K>, AccountKeyIdentifier)) -> Self {
        Key::Identified(Identified { identifier, key })
    }
}

/// A request which follows the RFC 8885 protocol for HTTP with JWS authentication
///
/// ACME prescribes that all requests are POST JWS requests in the flattened
/// JSON format. This structure contains all of the materials *except* the
/// anti-replay [nonce][Nonce] which are required to create an appropriate HTTP
/// request. The [nonce][Nonce] is left out of this object that if the [`super::Client`]
/// encounters a bad [nonce][Nonce], it can re-try the same request with a new [nonce][Nonce]
/// value without having to re-build the request object.
///
///
///
/// Create a request with either [`Request::post`] or [`Request::get`]
///
/// For example, a GET request:
///
/// ```
/// # use std::sync::Arc;
/// # use yacme::key::{SignatureKind, SigningKey, EcdsaAlgorithm};
/// # use yacme::protocol::{Url, Request};
/// # use yacme::protocol::fmt::AcmeFormat;
///
/// // ⚠️ **Do not use this key, it is an example used for testing only!**
/// let private = "-----BEGIN PRIVATE KEY-----
/// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgm1tOPOUt86+QgoiJ
/// kirpEl69+tUxLP848nPw9BbyW1ShRANCAASGWHBM2Lj7uUA4i9/jKSDp1vw4+iyu
/// hxVHBELXhxaD/LOQKtQAOhumi1uCTg8mMTrFrUM1VOtF8R0+rjrB3UXd
/// -----END PRIVATE KEY-----";
///
/// let key = Arc::new(SigningKey::from_pkcs8_pem(private,
///    SignatureKind::Ecdsa(yacme::key::EcdsaAlgorithm::P256))
/// .unwrap());
///
/// let url: Url = "https://letsencrypt.test/new-account-plz/".parse().unwrap();
///
/// let request = Request::get(url, key);
/// println!("{}", request.formatted());
/// ```
///
#[derive(Debug, Clone)]
pub struct Request<T, K> {
    method: Method<T>,
    url: Url,
    key: Key<K>,
    headers: HeaderMap,
}

impl<T, K> Request<T, K> {
    fn new<KK>(method: Method<T>, url: Url, key: KK) -> Self
    where
        KK: Into<Key<K>>,
    {
        Self {
            method,
            url,
            key: key.into(),
            headers: Default::default(),
        }
    }

    /// Create a `POST` request with a given payload.
    ///
    /// The payload must implement [`serde::Serialize`] and will be serialized to
    /// JSON and included in the JWS which is sent to the ACME server. The [`Url`]
    /// is required as it is a part of the JWS header (to prevent re-using a
    /// header and signature pair for additional requests). The signing key is
    /// also required.
    pub fn post<KK>(payload: T, url: Url, key: KK) -> Self
    where
        KK: Into<Key<K>>,
    {
        Self::new(Method::Post(payload), url, key)
    }

    /// Mutable reference to the headers to be sent by this request.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    /// Inspect the headers to be sent with this request.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Alter the URL on this request to a new value.
    pub fn with_url(mut self, url: Url) -> Self {
        self.url = url;
        self
    }

    /// Alter the [`Key`] on this request to a new value.
    pub fn with_key(mut self, key: Key<K>) -> Self {
        self.key = key;
        self
    }
}

impl<K> Request<(), K> {
    /// Create a `GET-as-POST` request with an empty payload.
    ///
    /// When making an authenticated `GET` request to an ACME server, the client
    /// sends a `POST` request, with a JWS body where the payload is the empty
    /// string. This is signed in the same way that a `POST` request is signed.
    pub fn get<KK>(url: Url, key: KK) -> Self
    where
        KK: Into<Key<K>>,
    {
        Self::new(Method::Get, url, key)
    }
}

impl<T, K> Request<T, K>
where
    T: Serialize,
    K: jaws::algorithms::SigningAlgorithm,
    K::Key: Clone,
    K::Error: std::error::Error + Send + Sync + 'static,
{
    fn token(&self, nonce: Nonce) -> UnsignedToken<&T> {
        let header = RequestHeader::new(self.url.clone(), Some(nonce));

        match &self.method {
            Method::Get => UnsignedToken::get(header),
            Method::Post(payload) => UnsignedToken::post(header, payload),
        }
    }

    fn signed_token(&self, nonce: Nonce) -> Result<jaws::Token<RequestHeader, &T>, AcmeError> {
        let token = self.token(nonce);

        Ok(self.key.sign(token.into_inner()).map(|t| t.into_token())?)
    }

    /// Sign and finalize this request so that it can be sent over HTTP.
    ///
    /// The resulting [`SignedRequest`] can be converted to a [`reqwest::Request`]
    /// for transmission. Normally, this method is not necessary - the [`crate::protocol::Client`]
    /// provides [`crate::protocol::Client::execute`] for executing [`Request`] objects natively.
    pub fn sign(&self, nonce: Nonce) -> Result<SignedRequest, AcmeError> {
        let signed_token = self.signed_token(nonce)?;
        let mut request = reqwest::Request::new(http::Method::POST, self.url.clone().into());
        *request.headers_mut() = self.headers.clone();
        request
            .headers_mut()
            .insert(http::header::CONTENT_TYPE, CONTENT_JOSE.parse().unwrap());
        let body = serde_json::to_vec(&signed_token).map_err(AcmeError::ser)?;
        *request.body_mut() = Some(body.into());

        Ok(SignedRequest(request))
    }
}

impl<T, K> Request<T, K> {
    /// Provides a formatting proxy which when formatted will include the
    /// signature (as a Base64 URL-safe string in the JWS object). The format approximates
    /// that used by [RFC 8885][].
    ///
    /// Note that this format will include a dummy [nonce][Nonce] value, so the signature is
    /// consistent and repeatable, but may not match what should have been sent to the
    /// ACME service provider.
    ///
    /// Use [`Request::as_signed_with_nonce`] if you have a real [nonce][Nonce] and want to see
    /// a representation of this request similar to those in [RFC 8885](https://datatracker.ietf.org/doc/html/rfc8555).
    pub fn as_signed(&self) -> FormatSignedRequest<'_, T, K> {
        let nonce = String::from("<nonce>").into();
        FormatSignedRequest(self, nonce)
    }

    /// Provides a formatting proxy which when formatted will include the
    /// signature (as a Base64 URL-safe string in the JWS object). The format approximates
    /// that used by [RFC 8885][].
    ///
    /// Note that this format will include the provided [nonce][Nonce] value, so the signature
    /// can match what would be sent to the ACME service provider.
    ///
    /// Use [`Request::as_signed`] if you do not have a [nonce][Nonce] and want to see
    /// a representation of this request similar to those in [RFC 8885][].
    ///
    /// [RFC 8885]: https://datatracker.ietf.org/doc/html/rfc8555
    pub fn as_signed_with_nonce(&self, nonce: Nonce) -> FormatSignedRequest<'_, T, K> {
        FormatSignedRequest(self, nonce)
    }

    /// Format the preamble of this request (the HTTP part) in the style of RFC 8885
    fn acme_format_preamble<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        let method = match &self.method {
            Method::Get => "POST as GET",
            Method::Post(_) => "POST",
        };
        let path = self.url.path();

        // Request Line
        writeln!(f, "{method} {path} HTTP/1.1")?;

        // Host: header
        if let Some(host) = self.url.host() {
            writeln!(f, "{}: {}", http::header::HOST.titlecase(), host)?;
        }

        // Content-Type: header
        writeln!(
            f,
            "{}: {}",
            http::header::CONTENT_TYPE.titlecase(),
            CONTENT_JOSE
        )?;

        // Empty line to mark the end of the HTTP headers
        writeln!(f)?;
        Ok(())
    }
}

/// Formatting proxy to show a request in the style of
/// [RFC 8885](https://datatracker.ietf.org/doc/html/rfc8555)
pub struct FormatSignedRequest<'r, T, K>(&'r Request<T, K>, Nonce);

impl<'r, T, K> fmt::JWTFormat for FormatSignedRequest<'r, T, K>
where
    T: Serialize,
    K: jaws::algorithms::SigningAlgorithm,
    K::Key: Clone,
    K::Error: std::error::Error + Send + Sync + 'static,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        self.0.acme_format_preamble(f)?;
        let signed = self.0.signed_token(self.1.clone()).unwrap();
        <jaws::Token<RequestHeader, &T> as fmt::JWTFormat>::fmt(&signed, f)
    }
}

impl<T, K> fmt::JWTFormat for Request<T, K>
where
    T: Serialize,
    K: jaws::algorithms::SigningAlgorithm,
    K::Key: Clone,
    K::Error: std::error::Error + Send + Sync + 'static,
{
    fn fmt<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        self.acme_format_preamble(f)?;
        let nonce = String::from("<nonce>").into();
        let token = self.token(nonce).into_inner();

        <jaws::UnsignedToken<RequestHeader, _> as fmt::JWTFormat>::fmt(&token, f)
    }
}

/// A request which follows the RFC 8885 protocol for HTTP with JWS authentication
/// and has been signed with a private key.
///
/// This request is ready to be transmitted over HTTP.
pub struct SignedRequest(reqwest::Request);

impl SignedRequest {
    pub(crate) fn into_inner(self) -> reqwest::Request {
        self.0
    }
}

impl From<SignedRequest> for reqwest::Request {
    fn from(value: SignedRequest) -> Self {
        value.0
    }
}

#[cfg(test)]
mod test {
    use elliptic_curve::SecretKey;
    use p256::NistP256;
    use serde_json::json;

    use jaws::jose::UnsignedHeader;
    use jaws::JWTFormat;

    use super::*;

    #[test]
    fn encode_via_serialize() {
        let data = json!({
            "foo": "bar",
            "baz": ["qux", "gorb"]
        });

        let expected = serde_json::to_string_pretty(
            &serde_json::from_str::<serde_json::Value>(crate::example!("json-object.json"))
                .unwrap(),
        )
        .unwrap();

        assert_eq!(data.encode().unwrap(), expected);
    }

    #[test]
    fn key_builds_header() {
        let key = crate::key!("ec-p255");

        let url = "https://letsencrypt.test/new-orderz"
            .parse::<Url>()
            .unwrap();
        let nonce: Nonce = String::from("<nonce>").into();
        let header = {
            let mut header = UnsignedHeader::new(RequestHeader::new(url, Some(nonce)));
            header.registered.key = true;
            header
        }
        .sign::<SecretKey<NistP256>>(&key);
        assert_eq!(
            header.formatted().to_string(),
            crate::example!("header-key.txt").trim()
        );
    }

    #[test]
    fn key_builds_header_with_id() {
        let key = crate::key!("ec-p255");
        let identifier = AccountKeyIdentifier::from(
            "https://letsencrypt.test/account/foo-bar"
                .parse::<Url>()
                .unwrap(),
        );
        let url = "https://letsencrypt.test/new-orderz"
            .parse::<Url>()
            .unwrap();
        let nonce: Nonce = String::from("<nonce>").into();

        let header = {
            let mut header = UnsignedHeader::new(RequestHeader::new(url, Some(nonce)));
            header.registered.key_id = Some(identifier.to_string());
            header
        }
        .sign::<SecretKey<NistP256>>(&key);

        eprintln!("{}", header.formatted());
        assert_eq!(
            header.formatted().to_string(),
            crate::example!("header-id.txt").trim()
        );
    }

    #[test]
    fn request_has_headers() {
        let key = crate::key!("ec-p255");
        let identifier = AccountKeyIdentifier::from(
            "https://letsencrypt.test/account/foo-bar"
                .parse::<Url>()
                .unwrap(),
        );
        let url = "https://letsencrypt.test/new-orderz"
            .parse::<Url>()
            .unwrap();

        let mut request = Request::get(url, (key, Some(identifier)));
        request
            .headers_mut()
            .insert("X-Foo", "bar".parse().unwrap());

        let signed = request.sign("foo".into()).unwrap();
        assert_eq!(signed.0.headers().get("X-Foo").unwrap(), "bar");
        assert_eq!(
            signed.0.headers().get("Content-Type").unwrap(),
            "application/jose+json"
        );
    }
}
