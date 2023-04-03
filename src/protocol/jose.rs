//! JSON Object Signing and Encryption primitives used in RFC 8885
//! to implement the ACME protocol.

use std::fmt::{Debug, Write};
use std::ops::Deref;
use std::sync::Arc;

use serde::{ser, Deserialize, Serialize};
use thiserror::Error;

use super::base64::{Base64Data, Base64JSON};
use super::errors::AcmeError;
use super::fmt;
use super::Url;

use crate::key::Signature;

/// Sigature algorithms for JWS signatures.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// Elliptic curve ECDSA signature with the NIST P-256 curve.
    ES256,
    /// HMAC-SHA256 using a shared key
    HS256,
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureAlgorithm::ES256 => f.write_str("ES256"),
            SignatureAlgorithm::HS256 => f.write_str("HS256"),
        }
    }
}

/// Anti-replay nonce
///
/// This is a token provided by the ACME server. Each nonce may only be used
/// once, and each reply from the ACME server should contain a new nonce.
///
/// A new nonce is also avaiable from the ACME endpoint `new-nonce`.
///
/// The [`Nonce`] here is really just an opaque stirng token. Clients
/// may not assume anything about the structure of the nonce.
#[derive(Debug, Clone, Serialize)]
pub struct Nonce(String);

impl AsRef<str> for Nonce {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for Nonce {
    fn from(value: String) -> Self {
        Nonce(value)
    }
}

/// Identifier used by ACME servers for registered accounts
///
/// Internally, RFC 8885 specifies that this should be the `GET` resource URL
/// for the account.
#[derive(Debug, Clone)]
pub struct AccountKeyIdentifier(Arc<Url>);

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
    /// Get the underlying URL.
    ///
    /// ACME account keys are always supposed to be the GET resource URL for the account.
    pub fn to_url(&self) -> Url {
        self.0.deref().clone()
    }
}

impl AsRef<[u8]> for AccountKeyIdentifier {
    fn as_ref(&self) -> &[u8] {
        self.0.as_str().as_bytes()
    }
}

/// The signed header values for the JWS which are common to each
/// request.
///
/// RFC 8885 only supports "Protected" / "Registered" headers, and only a
/// subset of those fields.
///
/// Fields which are `None` are left out of the protected header.
///
/// The parameter `KI` is the key identifier, which must be serializable as
/// JSON, but is otherwise unconstrained.
#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = "KI: Serialize"))]
pub struct ProtectedHeader<KI> {
    #[serde(rename = "alg")]
    algorithm: SignatureAlgorithm,
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    key_id: Option<KI>,
    #[serde(rename = "jwk", skip_serializing_if = "Option::is_none")]
    web_key: Option<crate::key::jwk::Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<Nonce>,
    url: Url,
}

impl<KI> fmt::AcmeFormat for ProtectedHeader<KI>
where
    KI: Serialize,
{
    fn fmt<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        let mut structure = serde_json::Map::default();

        structure.insert("alg".to_owned(), self.algorithm.to_string().into());
        if let Some(key_id) = &self.key_id {
            structure.insert("kid".to_owned(), serde_json::to_value(key_id).unwrap());
        }
        if let Some(jwk) = &self.web_key {
            structure.insert("jwk".to_owned(), serde_json::to_value(jwk).unwrap());
        }

        if let Some(nonce) = &self.nonce {
            structure.insert("nonce".to_owned(), nonce.0.clone().into());
        }

        structure.insert("url".to_owned(), self.url.as_str().to_owned().into());

        let structure = serde_json::Value::Object(structure);

        f.write_json(&structure)
    }
}

impl<KI> ProtectedHeader<KI> {
    /// Create a new protected header from the constituent components.
    pub fn new(
        algorithm: SignatureAlgorithm,
        key_id: Option<KI>,
        web_key: Option<crate::key::jwk::Jwk>,
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

    /// Replace the [`Nonce`] in this header with a new value.
    pub fn replace_nonce(&mut self, nonce: Nonce) {
        self.nonce = Some(nonce);
    }
}

/// A protected header which uses [`AccountKeyIdentifier`] as the key identifier.
pub type AcmeProtectedHeader<'k> = ProtectedHeader<&'k AccountKeyIdentifier>;

impl<'k> ProtectedHeader<&'k AccountKeyIdentifier> {
    /// Create a new protected header based on a signing key without an account
    /// identifier.
    pub fn new_acme_header(
        key: &'k crate::key::SigningKey,
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

    /// Create a new protected header based on an account identifier.
    pub fn new_acme_account_header(
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

impl<P> fmt::AcmeFormat for Payload<P>
where
    P: Serialize,
{
    fn fmt<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        match self {
            Payload::Json(data) => <Base64JSON<P> as fmt::AcmeFormat>::fmt(data, f),
            Payload::Empty => f.write_str("\"\""),
        }
    }
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

/// A JWS token wihtout an attached signature
///
/// This token contains just the unsigned parts which are used as the
/// input to the cryptographic signature.
#[derive(Debug, Serialize)]
pub struct UnsignedToken<P, KI> {
    protected: Base64JSON<ProtectedHeader<KI>>,
    payload: Payload<P>,
}

impl<P, KI> UnsignedToken<P, KI> {
    /// Create a JWS token appropraite for an ACME `GET` request.
    ///
    /// The request will have an empty string as the payload.
    pub fn get(protected: ProtectedHeader<KI>) -> Self {
        Self {
            protected: protected.into(),
            payload: Payload::Empty,
        }
    }
}

impl<P, KI> UnsignedToken<P, KI> {
    /// Create a JWS token appropraite for an ACME `POST` request.
    pub fn post(protected: ProtectedHeader<KI>, payload: P) -> Self {
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

    /// Sign this token with the given cryptographic key.
    pub fn sign<K>(self, key: &K) -> Result<SignedToken<P, KI, Box<[u8]>>, SigningError>
    where
        K: signature::Signer<Signature>,
    {
        let message = self.signing_input()?;
        let signature = key.try_sign(message.as_bytes())?;
        Ok(SignedToken {
            target: self,
            signature: signature.to_bytes().into(),
        })
    }

    /// Sign this token using the given HMAC digest
    /// function.
    pub fn digest<D: signature::digest::Mac>(
        self,
        mut digest: D,
    ) -> Result<SignedToken<P, KI, Box<[u8]>>, SigningError> {
        let message = self.signing_input()?;
        digest.update(message.as_bytes());
        let result = digest.finalize();
        Ok(SignedToken {
            target: self,
            signature: Base64Data(Box::from(result.into_bytes().to_vec())),
        })
    }
}

impl<P, KI> fmt::AcmeFormat for UnsignedToken<P, KI>
where
    P: Serialize,
    KI: Debug + Serialize,
{
    fn fmt<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        fmt_token::<_, _, [u8; 0], _>(f, &self.protected, &self.payload, None)
    }
}

/// A JWS token with an included cryptographic signature.
#[derive(Debug, Serialize)]
#[serde(bound(serialize = "UnsignedToken<P, KI>: Serialize, S: AsRef<[u8]>"))]
pub struct SignedToken<P, KI, S> {
    #[serde(flatten)]
    target: UnsignedToken<P, KI>,
    signature: Base64Data<S>,
}

impl<P, KI, S> fmt::AcmeFormat for SignedToken<P, KI, S>
where
    P: Serialize,
    KI: Debug + Serialize,
    S: AsRef<[u8]>,
{
    fn fmt<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        fmt_token(
            f,
            &self.target.protected,
            &self.target.payload,
            Some(&self.signature),
        )
    }
}

/// Error returned for issues signing a JWS token
#[derive(Debug, Error)]
pub enum SigningError {
    /// An error occured in the cryptographic signature process.
    #[error("signature error")]
    Signing(#[from] signature::Error),

    /// An error occured while trying to serialize the token as JSON.
    #[error("serialization error: {0}")]
    JsonSerialize(#[source] serde_json::Error),
}

impl From<SigningError> for AcmeError {
    fn from(value: SigningError) -> Self {
        match value {
            SigningError::Signing(error) => Self::Signing(error),
            SigningError::JsonSerialize(error) => Self::ser(error),
        }
    }
}

fn fmt_token<P, KI, S, W>(
    f: &mut fmt::IndentWriter<'_, W>,
    header: &Base64JSON<ProtectedHeader<KI>>,
    payload: &Payload<P>,
    signature: Option<&Base64Data<S>>,
) -> fmt::Result
where
    P: Serialize,
    KI: Debug + Serialize,
    S: AsRef<[u8]>,
    W: fmt::Write,
{
    writeln!(f, "{{")?;
    {
        let mut f = f.indent();
        write!(f, "\"protected\": ")?;
        <Base64JSON<ProtectedHeader<KI>> as fmt::AcmeFormat>::fmt_indented_skip_first(
            header, &mut f,
        )?;
        writeln!(f, ",")?;
        write!(f, "\"payload\": ")?;
        <Payload<P> as fmt::AcmeFormat>::fmt_indented_skip_first(payload, &mut f)?;
        writeln!(f, ",")?;
        write!(f, "\"signature\": ")?;
        if let Some(signature) = signature {
            <Base64Data<S> as fmt::AcmeFormat>::fmt_indented_skip_first(signature, &mut f)?;
        } else {
            write!(f, "\"<signature>\"")?;
        }
    }
    writeln!(f)?;
    writeln!(f, "}}")?;
    Ok(())
}
