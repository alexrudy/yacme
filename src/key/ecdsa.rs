//! Yacme's cryptographic primatives for ECDSA signatures

use const_oid::AssociatedOid;
use elliptic_curve::sec1::ToEncodedPoint;
use pkcs8::{EncodePrivateKey, EncodePublicKey};
use signature::rand_core::OsRng;

use super::{PublicKeyAlgorithm, Signature};

#[derive(Debug)]
pub(crate) enum EcdsaSignature {
    P256(::ecdsa::Signature<p256::NistP256>),
}

impl From<::ecdsa::Signature<p256::NistP256>> for EcdsaSignature {
    fn from(signature: ::ecdsa::Signature<p256::NistP256>) -> Self {
        EcdsaSignature::P256(signature)
    }
}

impl EcdsaSignature {
    pub(crate) fn to_der(&self) -> der::Document {
        match self {
            EcdsaSignature::P256(signature) => {
                der::Document::encode_msg(&signature.to_der()).unwrap()
            }
        }
    }

    pub(crate) fn to_bytes(&self) -> Box<[u8]> {
        match self {
            EcdsaSignature::P256(signature) => signature.to_vec().into(),
        }
    }
}

/// Named elliptic curves supported by Yacme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaAlgorithm {
    /// The NIST P-256 (a.k.a. secp256r1, prime256v1) elliptic curve.
    P256,
}

impl EcdsaAlgorithm {
    pub(crate) fn random(&self) -> EcdsaSigningKey {
        match self {
            EcdsaAlgorithm::P256 => {
                EcdsaSigningKey::P256(::elliptic_curve::SecretKey::random(&mut OsRng))
            }
        }
    }
}

/// Implements the ECDSA signature scheme across
/// varying elliptic curve cryptography algorithms
pub(crate) enum EcdsaSigningKey {
    P256(::elliptic_curve::SecretKey<p256::NistP256>),
}

impl signature::Signer<Signature> for EcdsaSigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, ::ecdsa::Error> {
        match self {
            EcdsaSigningKey::P256(key) => {
                let signature = <::ecdsa::SigningKey<p256::NistP256> as signature::Signer<
                    ::ecdsa::Signature<p256::NistP256>,
                >>::sign(&key.into(), msg);
                Ok(EcdsaSignature::from(signature).into())
            }
        }
    }
}

impl super::SigningKeyAlgorithm for EcdsaSigningKey {
    fn as_jwk(&self) -> super::jwk::Jwk {
        match self {
            EcdsaSigningKey::P256(key) => key.public_key().to_jwk().into(),
        }
    }

    fn public_key(&self) -> super::PublicKey {
        match self {
            EcdsaSigningKey::P256(key) => Box::new(EcdsaPublicKey::from(key.public_key())).into(),
        }
    }

    fn try_sign_digest(&self, digest: sha2::Sha256) -> Result<Signature, ecdsa::Error> {
        match self {
            EcdsaSigningKey::P256(key) => {
                let signature = <::ecdsa::SigningKey<p256::NistP256> as signature::DigestSigner<
                    sha2::Sha256,
                    ::ecdsa::Signature<p256::NistP256>,
                >>::try_sign_digest(&key.into(), digest)?;
                Ok(EcdsaSignature::from(signature).into())
            }
        }
    }

    fn algorithm(&self) -> spki::AlgorithmIdentifierOwned {
        match self {
            EcdsaSigningKey::P256(_) => spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
                parameters: None,
            },
        }
    }

    fn kind(&self) -> super::SignatureKind {
        match self {
            EcdsaSigningKey::P256(_) => super::SignatureKind::Ecdsa(super::EcdsaAlgorithm::P256),
        }
    }

    fn to_pkcs8_der(&self) -> pkcs8::Result<der::SecretDocument> {
        match self {
            EcdsaSigningKey::P256(key) => key.to_pkcs8_der(),
        }
    }

    fn try_sign_digest_with_rng(&self, digest: sha2::Sha256) -> Result<Signature, ecdsa::Error> {
        match self {
            EcdsaSigningKey::P256(key) => {
                let signature =
                    <::ecdsa::SigningKey<p256::NistP256> as signature::RandomizedDigestSigner<
                        sha2::Sha256,
                        ::ecdsa::Signature<p256::NistP256>,
                    >>::try_sign_digest_with_rng(
                        &key.into(), &mut OsRng, digest
                    )?;
                Ok(EcdsaSignature::from(signature).into())
            }
        }
    }
}

impl EcdsaSigningKey {
    pub(crate) fn from_pkcs8_pem(
        data: &str,
        algorithm: EcdsaAlgorithm,
    ) -> Result<Self, pkcs8::Error> {
        use pkcs8::DecodePrivateKey;
        match algorithm {
            EcdsaAlgorithm::P256 => Ok(EcdsaSigningKey::P256(
                ::elliptic_curve::SecretKey::from_pkcs8_pem(data)?,
            )),
        }
    }
}

enum EcdsaPublicKey {
    P256(elliptic_curve::PublicKey<p256::NistP256>),
}

impl From<elliptic_curve::PublicKey<p256::NistP256>> for EcdsaPublicKey {
    fn from(value: elliptic_curve::PublicKey<p256::NistP256>) -> Self {
        EcdsaPublicKey::P256(value)
    }
}

impl PublicKeyAlgorithm for EcdsaPublicKey {
    fn as_jwk(&self) -> super::jwk::Jwk {
        match self {
            EcdsaPublicKey::P256(key) => key.to_jwk().into(),
        }
    }

    fn algorithm(&self) -> spki::AlgorithmIdentifierOwned {
        match self {
            EcdsaPublicKey::P256(_) => spki::AlgorithmIdentifierOwned {
                oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
                parameters: Some((&p256::NistP256::OID).into()),
            },
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        match self {
            // EcdsaPublicKey::P256(key) => key.to_sec1_bytes().to_vec(),
            EcdsaPublicKey::P256(key) => key.to_encoded_point(false).as_bytes().to_vec(),
        }
    }

    fn to_public_key_der(&self) -> pkcs8::spki::Result<der::Document> {
        match self {
            EcdsaPublicKey::P256(key) => key.to_public_key_der(),
        }
    }
}
