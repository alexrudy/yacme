//! Yacme's cryptographic primatives for ECDSA signatures

use const_oid::AssociatedOid;
use elliptic_curve::sec1::ToEncodedPoint;

use crate::{PublicKeyAlgorithm, Signature};

/// Named elliptic curves supported by Yacme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaAlgorithm {
    /// The NIST P-256 (a.k.a. secp256r1, prime256v1) elliptic curve.
    P256,
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
                let bytes = signature.to_vec();
                Ok(Signature(bytes))
            }
        }
    }
}

impl crate::SigningKeyAlgorithm for EcdsaSigningKey {
    fn as_jwk(&self) -> crate::jwk::Jwk {
        match self {
            EcdsaSigningKey::P256(key) => key.public_key().to_jwk().into(),
        }
    }

    fn public_key(&self) -> crate::PublicKey {
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
                let bytes = signature.to_vec();
                Ok(Signature(bytes))
            }
        }
    }

    fn algorithm(&self) -> pkcs8::AlgorithmIdentifier {
        match self {
            EcdsaSigningKey::P256(_) => pkcs8::AlgorithmIdentifier {
                oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
                parameters: None,
            },
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
    fn as_jwk(&self) -> crate::jwk::Jwk {
        match self {
            EcdsaPublicKey::P256(key) => key.to_jwk().into(),
        }
    }

    fn algorithm(&self) -> pkcs8::AlgorithmIdentifier {
        match self {
            EcdsaPublicKey::P256(_) => pkcs8::AlgorithmIdentifier {
                oid: const_oid::db::rfc5912::ID_EC_PUBLIC_KEY,
                parameters: Some((&p256::NistP256::OID).into()),
            },
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        match self {
            EcdsaPublicKey::P256(key) => key.to_encoded_point(false).as_ref().into(),
        }
    }
}
