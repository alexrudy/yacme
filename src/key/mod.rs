//! # Encryption keys for ACME protocol certificate issuance.
//!
//! ACME requires that accounts be identified by an asymmetric public/private key pair
//! used for signing all requests. This crate implements the types which handle those
//! keypairs, using RustCrypto libraries under the hood. The types here are not directly
//! the RustCrypto primatives, as they abstract over the actual algorithm in use without
//! polluting the entire ACME interface with generics.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

pub mod cert;
mod ecdsa;
pub mod jwk;
mod rsa;

use self::{ecdsa::EcdsaSigningKey, rsa::RsaSigningKey};

pub use self::{ecdsa::EcdsaAlgorithm, rsa::RsaAlgorithm};

pub use p256;
pub use pkcs8;
use pkcs8::EncodePublicKey;
pub use signature;

#[derive(Debug)]
enum InnerSignature {
    Ecdsa(self::ecdsa::EcdsaSignature),
    Rsa(self::rsa::RsaSignature),
}

impl From<self::ecdsa::EcdsaSignature> for Signature {
    fn from(value: self::ecdsa::EcdsaSignature) -> Self {
        Signature(InnerSignature::Ecdsa(value))
    }
}

impl From<self::rsa::RsaSignature> for Signature {
    fn from(value: self::rsa::RsaSignature) -> Self {
        Signature(InnerSignature::Rsa(value))
    }
}

impl InnerSignature {
    fn to_der(&self) -> der::Document {
        match self {
            InnerSignature::Ecdsa(sig) => sig.to_der(),
            InnerSignature::Rsa(sig) => sig.to_der(),
        }
    }

    fn to_bytes(&self) -> Box<[u8]> {
        match self {
            InnerSignature::Ecdsa(sig) => sig.to_bytes(),
            InnerSignature::Rsa(sig) => sig.to_bytes(),
        }
    }
}

/// A signature, produced by signing a key over a message.
pub struct Signature(InnerSignature);

impl Signature {
    /// Convert this signature to the underlying raw bytes.
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.to_bytes()
    }

    /// Encode this signature in ASN.1 DER format.
    pub fn to_der(&self) -> der::Document {
        self.0.to_der()
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature").field(&self.0).finish()
    }
}

impl From<Signature> for Vec<u8> {
    fn from(value: Signature) -> Self {
        value.0.to_bytes().into()
    }
}

/// Error returned when signatures failed
pub struct SigningError;

/// The public half of a signing key
pub struct PublicKey(Box<dyn PublicKeyAlgorithm + Send + Sync>);

impl PublicKey {
    /// A JSON web key type suitable for use in a JWS header
    /// and for use when creating a key thumbprint for authentication
    /// challenges.
    pub fn to_jwk(&self) -> self::jwk::Jwk {
        self.0.as_jwk()
    }

    /// The pkcs8 algorithm identifier for this key.
    pub fn algorithm(&self) -> spki::AlgorithmIdentifierOwned {
        self.0.algorithm()
    }

    /// The key, as raw bytes.
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.as_bytes()
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_jwk() == other.to_jwk()
    }
}

impl Eq for PublicKey {}

impl<T> From<Box<T>> for PublicKey
where
    T: PublicKeyAlgorithm + Send + Sync + 'static,
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

impl EncodePublicKey for PublicKey {
    fn to_public_key_der(&self) -> pkcs8::spki::Result<der::Document> {
        self.0.to_public_key_der()
    }
}

/// Supported signing key types for YACME
///
/// Currently, only ECDSA P256 is supported.
///
/// ```
/// # use yacme::key::SignatureKind;
/// # use yacme::key::EcdsaAlgorithm;
/// let algorithm = SignatureKind::Ecdsa(EcdsaAlgorithm::P256);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureKind {
    /// ECDSA using a variety of potential curves
    Ecdsa(EcdsaAlgorithm),

    /// RSA Signing Key
    RSA(RsaAlgorithm),
}

impl SignatureKind {
    /// Create a new, secure random signing key for this signature kind.
    pub fn random(&self) -> SigningKey {
        match self {
            SignatureKind::Ecdsa(ecdsa) => SigningKey(ecdsa.random().into()),
            SignatureKind::RSA(rsa) => SigningKey(rsa.random().into()),
        }
    }
}

/// Signing key to authenticate an ACME account
///
/// Read a signing key from a PKCS#8 PEM-encoded file:
///
/// ```
/// # use yacme::key::{SignatureKind, SigningKey};
/// # use yacme::key::EcdsaAlgorithm;
/// let private = "-----BEGIN PRIVATE KEY-----
/// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgm1tOPOUt86+QgoiJ
/// kirpEl69+tUxLP848nPw9BbyW1ShRANCAASGWHBM2Lj7uUA4i9/jKSDp1vw4+iyu
/// hxVHBELXhxaD/LOQKtQAOhumi1uCTg8mMTrFrUM1VOtF8R0+rjrB3UXd
/// -----END PRIVATE KEY-----";
/// let key = SigningKey::from_pkcs8_pem(private,
///    SignatureKind::Ecdsa(EcdsaAlgorithm::P256))
/// .unwrap();
/// ```
///
/// ⚠️ *Do not use this key, it is an example used for testing only*!
#[derive(Debug, PartialEq, Eq)]
pub struct SigningKey(InnerSigningKey);

impl SigningKey {
    /// Read a private key from a PEM-encoded PKCS#8 format key (usually the kind produced by
    /// OpenSSL) into this signing key document. You must provide the signature kind, as the code
    /// does not currently infer the type of key in use.
    pub fn from_pkcs8_pem(data: &str, signature: SignatureKind) -> Result<Self, pkcs8::Error> {
        match signature {
            SignatureKind::Ecdsa(algorithm) => Ok(SigningKey(InnerSigningKey::Ecdsa(Box::new(
                EcdsaSigningKey::from_pkcs8_pem(data, algorithm)?,
            )))),
            SignatureKind::RSA(algorithm) => Ok(SigningKey(InnerSigningKey::Rsa(Box::new(
                RsaSigningKey::from_pkcs8_pem(data, algorithm)?,
            )))),
        }
    }

    /// Return the signature kind, used to recover the key type from a PEM file.
    pub fn kind(&self) -> SignatureKind {
        match &self.0 {
            InnerSigningKey::Ecdsa(key) => key.kind(),
            InnerSigningKey::Rsa(key) => key.kind(),
        }
    }
}

impl SigningKey {
    /// The public key half of this signing key.
    pub fn public_key(&self) -> PublicKey {
        self.0.public_key()
    }

    /// A JSON web key type suitable for use in a JWS header
    /// and for use when creating a key thumbprint for authentication
    /// challenges.
    pub fn as_jwk(&self) -> self::jwk::Jwk {
        self.0.as_jwk()
    }

    /// The pkcs8 algorithm identifier for this key.
    pub fn algorithm(&self) -> spki::AlgorithmIdentifierOwned {
        self.0.algorithm()
    }
}

impl pkcs8::EncodePrivateKey for SigningKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<der::SecretDocument> {
        self.0.to_pkcs8_der()
    }
}

impl signature::Signer<Signature> for SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, ::ecdsa::Error> {
        self.0.try_sign(msg)
    }
}

impl signature::DigestSigner<sha2::Sha256, Signature> for SigningKey {
    fn try_sign_digest(&self, digest: sha2::Sha256) -> Result<Signature, ::ecdsa::Error> {
        self.0.try_sign_digest(digest)
    }
}

impl signature::RandomizedDigestSigner<sha2::Sha256, Signature> for SigningKey {
    fn try_sign_digest_with_rng(
        &self,
        rng: &mut impl signature::rand_core::CryptoRngCore,
        digest: sha2::Sha256,
    ) -> Result<Signature, ::ecdsa::Error> {
        self.0.try_sign_digest_with_rng(rng, digest)
    }
}

pub(crate) enum InnerSigningKey {
    Ecdsa(Box<dyn SigningKeyAlgorithm + Send + Sync>),
    Rsa(Box<dyn SigningKeyAlgorithm + Send + Sync>),
    //TODO: Consider supporting other algorithms?
}

impl InnerSigningKey {
    pub(crate) fn as_jwk(&self) -> self::jwk::Jwk {
        match self {
            InnerSigningKey::Ecdsa(ecdsa) => ecdsa.as_jwk(),
            InnerSigningKey::Rsa(rsa) => rsa.as_jwk(),
        }
    }

    pub(crate) fn public_key(&self) -> PublicKey {
        match self {
            InnerSigningKey::Ecdsa(ecdsa) => ecdsa.public_key(),
            InnerSigningKey::Rsa(rsa) => rsa.public_key(),
        }
    }

    pub(crate) fn algorithm(&self) -> spki::AlgorithmIdentifierOwned {
        match self {
            InnerSigningKey::Ecdsa(ecdsa) => ecdsa.algorithm(),
            InnerSigningKey::Rsa(rsa) => rsa.algorithm(),
        }
    }
}

impl From<EcdsaSigningKey> for InnerSigningKey {
    fn from(value: EcdsaSigningKey) -> Self {
        InnerSigningKey::Ecdsa(Box::new(value) as _)
    }
}

impl From<RsaSigningKey> for InnerSigningKey {
    fn from(value: RsaSigningKey) -> Self {
        InnerSigningKey::Rsa(Box::new(value) as _)
    }
}

impl PartialEq for InnerSigningKey {
    fn eq(&self, other: &Self) -> bool {
        self.public_key() == other.public_key()
    }
}

impl Eq for InnerSigningKey {}

impl pkcs8::EncodePrivateKey for InnerSigningKey {
    fn to_pkcs8_der(&self) -> pkcs8::Result<der::SecretDocument> {
        match self {
            InnerSigningKey::Ecdsa(key) => key.to_pkcs8_der(),
            InnerSigningKey::Rsa(key) => key.to_pkcs8_der(),
        }
    }
}

impl signature::Signer<Signature> for InnerSigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, ::ecdsa::Error> {
        match self {
            InnerSigningKey::Ecdsa(key) => key.try_sign(msg),
            InnerSigningKey::Rsa(key) => key.try_sign(msg),
        }
    }
}

impl signature::DigestSigner<sha2::Sha256, Signature> for InnerSigningKey {
    fn try_sign_digest(&self, digest: sha2::Sha256) -> Result<Signature, ::ecdsa::Error> {
        match self {
            InnerSigningKey::Ecdsa(key) => key.try_sign_digest(digest),
            InnerSigningKey::Rsa(key) => key.try_sign_digest(digest),
        }
    }
}
impl signature::RandomizedDigestSigner<sha2::Sha256, Signature> for InnerSigningKey {
    fn try_sign_digest_with_rng(
        &self,
        _rng: &mut impl signature::rand_core::CryptoRngCore,
        digest: sha2::Sha256,
    ) -> Result<Signature, ::ecdsa::Error> {
        match self {
            InnerSigningKey::Ecdsa(key) => key.try_sign_digest_with_rng(digest),
            InnerSigningKey::Rsa(key) => key.try_sign_digest_with_rng(digest),
        }
    }
}

impl fmt::Debug for InnerSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InnerSigningKey::Ecdsa(_) => f.write_str("ECDSA-Key"),
            InnerSigningKey::Rsa(_) => f.write_str("RSA-Key"),
        }
    }
}

pub(crate) trait SigningKeyAlgorithm: signature::Signer<Signature> {
    fn as_jwk(&self) -> self::jwk::Jwk;
    fn public_key(&self) -> PublicKey;
    fn try_sign_digest(&self, digest: sha2::Sha256) -> Result<Signature, ::ecdsa::Error>;
    fn try_sign_digest_with_rng(&self, digest: sha2::Sha256) -> Result<Signature, ::ecdsa::Error>;
    fn algorithm(&self) -> spki::AlgorithmIdentifierOwned;
    fn kind(&self) -> SignatureKind;
    fn to_pkcs8_der(&self) -> pkcs8::Result<der::SecretDocument>;
}

pub(crate) trait PublicKeyAlgorithm {
    fn as_jwk(&self) -> self::jwk::Jwk;
    fn algorithm(&self) -> spki::AlgorithmIdentifierOwned;
    fn as_bytes(&self) -> Vec<u8>;
    fn to_public_key_der(&self) -> pkcs8::spki::Result<der::Document>;
}

#[cfg(test)]
pub(crate) mod test {
    use std::sync::Arc;

    use base64ct::LineEnding;
    use pkcs8::EncodePrivateKey;

    pub fn key(private: &str) -> Arc<super::SigningKey> {
        let key = super::SigningKey::from_pkcs8_pem(
            private,
            super::SignatureKind::Ecdsa(super::EcdsaAlgorithm::P256),
        )
        .unwrap();

        Arc::new(key)
    }

    #[macro_export]
    macro_rules! key {
        ($name:tt) => {
            $crate::key::test::key(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/reference-keys/",
                $name,
                ".pem"
            )))
        };
    }

    #[test]
    fn roundtrip_key_through_pkcs8() {
        let key = key!("ec-p255");
        let pkcs8 = key.to_pkcs8_pem(LineEnding::default()).unwrap();
        let key2 = super::SigningKey::from_pkcs8_pem(&pkcs8, key.kind()).unwrap();

        assert_eq!(key.as_ref(), &key2);
    }

    static_assertions::assert_impl_all!(super::Signature: Send, Sync);
    static_assertions::assert_impl_all!(super::SigningKey: Send, Sync);
    static_assertions::assert_impl_all!(super::PublicKey: Send, Sync);
}
