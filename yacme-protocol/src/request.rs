//! HTTP requests which adhere to RFC 8885
//!
//! [RFC 8885][] requires that most ACME HTTP requests (other than to the
//! directory endpoint and the new-nonce endpoint) be authenticated with a
//! JWS token using the flattened JSON format.
//!
//! This format is particular to ACME/[RFC 8885][] and so is implemented
//! here (along with [crate::jose] which implements the JWS portion).
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

use serde::Serialize;
use yacme_key::{Signature, SigningKey};

use crate::fmt::{self, HttpCase};
use crate::jose::{AccountKeyIdentifier, Nonce, ProtectedHeader, SignedToken, UnsignedToken};
use crate::AcmeError;
use crate::Url;

const CONTENT_JOSE: &str = "application/jose+json";

/// Trait which marks request/response bodies which can be encoded to string
/// in some fashion.
///
/// This is only useful when formatting the response in the ACME-style HTTP
/// format, as used by [`crate::fmt::AcmeFormat`].
///
/// There is a blanket implementation provided for any type which implements
/// [`serde::Serialize`], as we assume that serializable values would be sent
/// over the wire as JSON (or at least, it is acceptable to display the value
/// as JSON when printing the ACME server response). Other types can
/// implement this to provide a custom representation when showing an ACME
/// response.
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
pub struct Identified {
    identifier: AccountKeyIdentifier,
    key: Arc<SigningKey>,
}

/// The components required to sign an ACME request for a new account,
/// when the ACME service is not yet aware of the public key being used.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct Signed {
    key: Arc<SigningKey>,
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
pub enum Key {
    /// A signing key which will be identified to the ACME service as a
    /// known account.
    Identified(Identified),

    /// A signing key which will have the public component provided as a
    /// JWK structure inside the signed part of the request.
    Signed(Signed),
}

impl Key {
    /// Create a protected header which can use this [Key] for signing.
    ///
    /// ACME Protected headers must contain the target URL for the request, along with a
    /// [Nonce], which is used for replay protection.
    pub(crate) fn header(&self, url: Url, nonce: Nonce) -> ProtectedHeader<&AccountKeyIdentifier> {
        match &self {
            Key::Identified(Identified { identifier, key: _ }) => {
                ProtectedHeader::new_acme_account_header(identifier, url, nonce)
            }

            Key::Signed(Signed { key }) => ProtectedHeader::new_acme_header(key, url, nonce),
        }
    }

    /// A reference to the signing key.
    pub fn key(&self) -> &Arc<SigningKey> {
        match self {
            Key::Identified(Identified { identifier: _, key }) => key,
            Key::Signed(Signed { key }) => key,
        }
    }
}

impl From<(Arc<SigningKey>, Option<AccountKeyIdentifier>)> for Key {
    fn from((key, id): (Arc<SigningKey>, Option<AccountKeyIdentifier>)) -> Self {
        match id {
            Some(identifier) => Key::Identified(Identified { identifier, key }),
            None => Key::Signed(Signed { key }),
        }
    }
}

impl From<(Arc<SigningKey>, Url)> for Key {
    fn from((key, id): (Arc<SigningKey>, Url)) -> Self {
        Key::Identified(Identified {
            identifier: AccountKeyIdentifier::from(id),
            key,
        })
    }
}

impl From<Arc<SigningKey>> for Key {
    fn from(value: Arc<SigningKey>) -> Self {
        Key::Signed(Signed { key: value })
    }
}

impl From<(Arc<SigningKey>, AccountKeyIdentifier)> for Key {
    fn from((key, identifier): (Arc<SigningKey>, AccountKeyIdentifier)) -> Self {
        Key::Identified(Identified { identifier, key })
    }
}

/// A request which follows the RFC 8885 protocol for HTTP with JWS authentication
///
/// ACME prescribes that all requests are POST JWS requests in the flattened
/// JSON format. This structure contains all of the materials *except* the
/// anti-replay [nonce][Nonce] which are required to create an appropriate HTTP
/// request. The [nonce][Nonce] is left out of this object that if the [`crate::Client`]
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
/// use yacme_key::{SignatureKind, SigningKey, EcdsaAlgorithm};
/// use yacme_protocol::{Url, Request};
/// use yacme_protocol::fmt::AcmeFormat;
///
/// // ⚠️ **Do not use this key, it is an example used for testing only!**
/// let private = "-----BEGIN PRIVATE KEY-----
/// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgm1tOPOUt86+QgoiJ
/// kirpEl69+tUxLP848nPw9BbyW1ShRANCAASGWHBM2Lj7uUA4i9/jKSDp1vw4+iyu
/// hxVHBELXhxaD/LOQKtQAOhumi1uCTg8mMTrFrUM1VOtF8R0+rjrB3UXd
/// -----END PRIVATE KEY-----";
///
/// let key = Arc::new(SigningKey::from_pkcs8_pem(private,
///    SignatureKind::Ecdsa(yacme_key::EcdsaAlgorithm::P256))
/// .unwrap());
///
/// let url: Url = "https://letsencrypt.test/new-account-plz/".parse().unwrap();
///
/// let request = Request::get(url, key);
/// println!("{}", request.formatted());
/// ```
///
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

    /// Create a `POST` request with a given payload.
    ///
    /// The payload must implement [`serde::Serialize`] and will be serialized to
    /// JSON and included in the JWS which is sent to the ACME server. The [`Url`]
    /// is required as it is a part of the JWS header (to prevent re-using a
    /// header and signature pair for additional requests). The signing key is
    /// also required.
    pub fn post<K: Into<Key>>(payload: T, url: Url, key: K) -> Self {
        Self::new(Method::Post(payload), url, key.into())
    }

    /// Alter the URL on this request to a new value.
    pub fn with_url(mut self, url: Url) -> Self {
        self.url = url;
        self
    }

    /// Alter the [`Key`] on this request to a new value.
    pub fn with_key<K: Into<Key>>(mut self, key: K) -> Self {
        self.key = key.into();
        self
    }
}
impl Request<()> {
    /// Create a `GET-as-POST` request with an empty payload.
    ///
    /// When making an authenticated `GET` request to an ACME server, the client
    /// sends a `POST` request, with a JWS body where the payload is the empty
    /// string. This is signed in the same way that a `POST` request is signed.
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

    /// Sign and finalize this request so that it can be sent over HTTP.
    ///
    /// The resulting [`SignedRequest`] can be converted to a [`reqwest::Request`]
    /// for transmission. Normally, this method is not necessary - the [`crate::Client`]
    /// provides [`crate::Client::execute`] for executing [`Request`] objects natively.
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
    pub fn as_signed(&self) -> FormatSignedRequest<'_, T> {
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
    pub fn as_signed_with_nonce(&self, nonce: Nonce) -> FormatSignedRequest<'_, T> {
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
pub struct FormatSignedRequest<'r, T>(&'r Request<T>, Nonce);

impl<'r, T> fmt::AcmeFormat for FormatSignedRequest<'r, T>
where
    T: Serialize,
{
    fn fmt<W: std::fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> std::fmt::Result {
        self.0.acme_format_preamble(f)?;
        let signed = self.0.signed_token(self.1.clone()).unwrap();
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
    use serde_json::json;

    use crate::fmt::AcmeFormat;

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

        let request_key: Key = (key, None).into();
        let header = request_key.header(url, nonce);
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

        let request_key: Key = (key, Some(identifier)).into();
        let header = request_key.header(url, nonce);

        eprintln!("{}", header.formatted());
        assert_eq!(
            header.formatted().to_string(),
            crate::example!("header-id.txt").trim()
        );
    }
}
