//! JSON Object Signing and Encryption primitives used in RFC 8885
//! to implement the ACME protocol.

use std::fmt::{Debug, Write};
use std::ops::Deref;
use std::sync::Arc;

use serde::{ser, Serialize};

use super::Url;
use jaws::b64data::{Base64Data, Base64JSON};
use jaws::fmt::{self, JWTFormat};

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

impl From<&str> for Nonce {
    fn from(value: &str) -> Self {
        Nonce(value.to_string())
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

impl AsRef<str> for AccountKeyIdentifier {
    fn as_ref(&self) -> &str {
        self.0.as_str()
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
/// RFC 8885 only supports "Protected"  headers, and only a
/// subset of those fields.
///
/// Fields which are `None` are left out of the protected header.
///
/// The parameter `KI` is the key identifier, which must be serializable as
/// JSON, but is otherwise unconstrained.
#[derive(Debug, Clone, Serialize)]
pub struct RequestHeader {
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<Nonce>,
    url: Url,
}

impl RequestHeader {
    /// Create a new protected header from the constituent components.
    pub fn new(url: Url, nonce: Option<Nonce>) -> Self {
        Self { nonce, url }
    }

    /// Replace the [`Nonce`] in this header with a new value.
    pub fn replace_nonce(&mut self, nonce: Nonce) {
        self.nonce = Some(nonce);
    }
}

/// An unsigned JWT token
pub struct UnsignedToken<P>(jaws::UnsignedToken<RequestHeader, P>);

impl<P> UnsignedToken<P> {
    /// Create a JWS token appropraite for an ACME `GET` request.
    ///
    /// The request will have an empty string as the payload.
    pub fn get(custom: RequestHeader) -> Self {
        UnsignedToken(jaws::UnsignedToken::empty(custom))
    }

    /// Create a JWS token appropraite for an ACME `POST` request.
    pub fn post(custom: RequestHeader, payload: P) -> Self {
        UnsignedToken(jaws::UnsignedToken::new(custom, payload))
    }

    /// Produce the native token type
    pub fn into_inner(self) -> jaws::UnsignedToken<RequestHeader, P> {
        self.0
    }
}

impl<P> UnsignedToken<P>
where
    P: Serialize,
{
    /// Sign a token with the given algorithm.
    pub fn sign<A>(
        self,
        algorithm: &A,
    ) -> Result<jaws::Token<RequestHeader, P>, jaws::token::TokenSigningError<A::Error>>
    where
        A: jaws::algorithms::SigningAlgorithm,
        A::Key: Clone,
    {
        self.0.sign(algorithm).map(|t| t.into_token())
    }
}

fn fmt_token<P, K, S, W>(
    f: &mut fmt::IndentWriter<'_, W>,
    header: &jaws::jose::SignedHeader<RequestHeader, K>,
    payload: &Option<P>,
    signature: Option<&Base64Data<S>>,
) -> fmt::Result
where
    P: Serialize,
    K: jaws::key::SerializeJWK,
    S: AsRef<[u8]>,
    W: fmt::Write,
{
    writeln!(f, "{{")?;
    {
        let mut f = f.indent();
        write!(f, "\"protected\": ")?;
        <jaws::jose::SignedHeader<RequestHeader, K> as jaws::JWTFormat>::fmt_indented_skip_first(
            header, &mut f,
        )?;
        writeln!(f, ",")?;
        write!(f, "\"payload\": ")?;
        if let Some(payload) = payload {
            Base64JSON(payload).fmt_indented_skip_first(&mut f)?;
        } else {
            write!(f, "\"\"")?;
        }
        writeln!(f, ",")?;
        write!(f, "\"signature\": ")?;
        if let Some(signature) = signature {
            <Base64Data<S> as fmt::JWTFormat>::fmt_indented_skip_first(signature, &mut f)?;
        } else {
            write!(f, "\"<signature>\"")?;
        }
    }
    writeln!(f)?;
    writeln!(f, "}}")?;
    Ok(())
}
