use std::fmt::{Debug, Write};
use std::ops::Deref;
use std::sync::Arc;

use serde::{ser, Deserialize, Serialize};
use thiserror::Error;

use super::base64::{Base64Data, Base64JSON};
use super::errors::AcmeError;
use crate::fmt;
use crate::Url;

use yacme_key::Signature;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    ES256,
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
    pub fn to_url(&self) -> Url {
        self.0.deref().clone()
    }
}

impl AsRef<[u8]> for AccountKeyIdentifier {
    fn as_ref(&self) -> &[u8] {
        self.0.as_str().as_bytes()
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(bound(serialize = "KI: Serialize"))]
pub struct ProtectedHeader<KI> {
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
    pub fn new(
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

    pub fn replace_nonce(&mut self, nonce: Nonce) {
        self.nonce = Some(nonce);
    }
}

pub type AcmeProtectedHeader<'k> = ProtectedHeader<&'k AccountKeyIdentifier>;

impl<'k> ProtectedHeader<&'k AccountKeyIdentifier> {
    pub fn new_acme_header(
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

#[derive(Debug, Serialize)]
#[serde(bound(serialize = "P: Serialize, KI: Serialize, S: AsRef<[u8]>"))]
pub struct SignedToken<P, KI, S> {
    protected: Base64JSON<ProtectedHeader<KI>>,
    payload: Payload<P>,
    signature: Base64Data<S>,
}

impl<P, KI, S> fmt::AcmeFormat for SignedToken<P, KI, S>
where
    P: Serialize,
    KI: Debug + Serialize,
    S: AsRef<[u8]>,
{
    fn fmt<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        fmt_token(f, &self.protected, &self.payload, Some(&self.signature))
    }
}

#[derive(Debug, Error)]
pub enum SigningError {
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

pub struct UnsignedToken<P, KI> {
    protected: Base64JSON<ProtectedHeader<KI>>,
    payload: Payload<P>,
}

impl<P, KI> UnsignedToken<P, KI> {
    pub fn get(protected: ProtectedHeader<KI>) -> Self {
        Self {
            protected: protected.into(),
            payload: Payload::Empty,
        }
    }
}

impl<P, KI> UnsignedToken<P, KI> {
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

    pub fn sign<K>(self, key: &K) -> Result<SignedToken<P, KI, Signature>, SigningError>
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

    pub fn digest<D: signature::digest::Mac>(
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

impl<P, KI> fmt::AcmeFormat for UnsignedToken<P, KI>
where
    P: Serialize,
    KI: Debug + Serialize,
{
    fn fmt<W: fmt::Write>(&self, f: &mut fmt::IndentWriter<'_, W>) -> fmt::Result {
        fmt_token::<_, _, [u8; 0], _>(f, &self.protected, &self.payload, None)
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
