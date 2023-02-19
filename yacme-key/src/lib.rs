use std::fmt;

mod ecdsa;
pub mod jwk;

use crate::ecdsa::EcdsaSigningKey;

pub use crate::ecdsa::EcdsaAlgorithm;

/// A signature
pub struct Signature(Vec<u8>);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature").field(&self.0).finish()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<Vec<u8>> for Signature {
    fn from(value: Vec<u8>) -> Self {
        Signature(value)
    }
}

/// Error returned when signatures failed
pub struct SigningError;

/// The public half of a signing key
pub struct PublicKey(Box<dyn PublicKeyAlgorithm>);

impl PublicKey {
    pub fn to_jwk(&self) -> crate::jwk::Jwk {
        self.0.as_jwk()
    }
}

impl<T> From<Box<T>> for PublicKey
where
    T: PublicKeyAlgorithm + 'static,
{
    fn from(value: Box<T>) -> Self {
        PublicKey(value as _)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").finish()
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        todo!("PublicKey to bytes")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKind {
    Ecdsa(EcdsaAlgorithm),
}

/// Signing key to authenticate an ACME account
#[derive(Debug)]
pub struct SigningKey(InnerSigningKey);

impl SigningKey {
    pub fn from_pkcs8_pem(data: &str, signature: SignatureKind) -> Result<Self, pkcs8::Error> {
        match signature {
            SignatureKind::Ecdsa(algorithm) => Ok(SigningKey(InnerSigningKey::Ecdsa(Box::new(
                EcdsaSigningKey::from_pkcs8_pem(data, algorithm)?,
            )))),
        }
    }
}

impl SigningKey {
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    pub fn as_jwk(&self) -> crate::jwk::Jwk {
        self.0.as_jwk()
    }
}

impl signature::Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, ::ecdsa::Error> {
        self.0.try_sign(msg)
    }
}

pub(crate) enum InnerSigningKey {
    Ecdsa(Box<dyn SigningKeyAlgorithm>),
    //TODO: Consider supporting other algorithms?
}

impl InnerSigningKey {
    pub(crate) fn as_jwk(&self) -> crate::jwk::Jwk {
        match self {
            InnerSigningKey::Ecdsa(ecdsa) => ecdsa.as_jwk(),
        }
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        match self {
            InnerSigningKey::Ecdsa(ecdsa) => ecdsa.public_key(),
        }
    }
}

impl signature::Signer<Signature> for InnerSigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, ::ecdsa::Error> {
        match self {
            InnerSigningKey::Ecdsa(key) => key.try_sign(msg),
        }
    }
}

impl fmt::Debug for InnerSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InnerSigningKey::Ecdsa(_) => f.write_str("ECDSA-Key"),
        }
    }
}

pub(crate) trait SigningKeyAlgorithm: signature::Signer<Signature> {
    fn as_jwk(&self) -> crate::jwk::Jwk;
    fn public_key(&self) -> PublicKey;
}

pub(crate) trait PublicKeyAlgorithm {
    fn as_jwk(&self) -> crate::jwk::Jwk;
}
