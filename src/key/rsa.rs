use elliptic_curve::rand_core::OsRng;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use signature::SignatureEncoding;
use spki::{EncodePublicKey, SignatureBitStringEncoding};

use super::{PublicKeyAlgorithm, Signature};

/// Named elliptic curves supported by Yacme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RsaAlgorithm {
    /// RSA PKCS#1 v1.5 signature using SHA-256
    RS256,

    /// RSA PKCS#1 v1.5 signature using SHA-348
    RS384,

    /// RSA PKCS#1 v1.5 signature using SHA-512
    RS512,
}

impl RsaAlgorithm {
    pub(crate) fn random(&self) -> RsaSigningKey {
        let keypair = ::rsa::RsaPrivateKey::new(&mut OsRng, self.key_size()).unwrap();
        RsaSigningKey {
            algorithm: *self,
            keypair,
        }
    }

    pub(crate) fn key_size(&self) -> usize {
        2048
    }
}

#[derive(Debug)]
pub(crate) enum RsaSignature {
    PKCS1v15(::rsa::pkcs1v15::Signature),
}

impl From<::rsa::pkcs1v15::Signature> for RsaSignature {
    fn from(value: ::rsa::pkcs1v15::Signature) -> Self {
        RsaSignature::PKCS1v15(value)
    }
}

impl RsaSignature {
    pub(crate) fn to_bytes(&self) -> Box<[u8]> {
        match self {
            RsaSignature::PKCS1v15(signature) => signature.to_vec().into(),
        }
    }

    pub(crate) fn to_der(&self) -> der::Document {
        match self {
            RsaSignature::PKCS1v15(signature) => {
                der::Document::encode_msg(&signature.to_bitstring().unwrap()).unwrap()
            }
        }
    }
}

/// Implements the RSA signature scheme across algorithms
#[derive(Debug, PartialEq, Eq)]
pub struct RsaSigningKey {
    algorithm: RsaAlgorithm,
    keypair: ::rsa::RsaPrivateKey,
}

impl signature::Signer<Signature> for RsaSigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
        match self.algorithm {
            RsaAlgorithm::RS256 => {
                rsa::pkcs1v15::SigningKey::<sha2::Sha256>::from(self.keypair.clone())
                    .try_sign(msg)
                    .map(|s| RsaSignature::from(s).into())
            }
            RsaAlgorithm::RS384 => {
                rsa::pkcs1v15::SigningKey::<sha2::Sha384>::from(self.keypair.clone())
                    .try_sign(msg)
                    .map(|s| RsaSignature::from(s).into())
            }
            RsaAlgorithm::RS512 => {
                rsa::pkcs1v15::SigningKey::<sha2::Sha512>::from(self.keypair.clone())
                    .try_sign(msg)
                    .map(|s| RsaSignature::from(s).into())
            }
        }
    }
}

impl super::SigningKeyAlgorithm for RsaSigningKey {
    fn as_jwk(&self) -> super::jwk::Jwk {
        let key = self.keypair.to_public_key();
        key.into()
    }

    fn public_key(&self) -> super::PublicKey {
        Box::new(RsaPublicKey::PKCS1v15(self.keypair.to_public_key())).into()
    }

    #[allow(unused_variables)]
    fn try_sign_digest(&self, digest: sha2::Sha256) -> Result<Signature, ecdsa::Error> {
        todo!("Digest signing not implemented for RSA")
    }

    fn algorithm(&self) -> spki::AlgorithmIdentifierOwned {
        spki::AlgorithmIdentifier {
            oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
            parameters: None,
        }
    }

    fn kind(&self) -> super::SignatureKind {
        super::SignatureKind::RSA(self.algorithm)
    }

    fn to_pkcs8_der(&self) -> pkcs8::Result<der::SecretDocument> {
        self.keypair.to_pkcs8_der()
    }

    #[allow(unused_variables)]
    fn try_sign_digest_with_rng(&self, digest: sha2::Sha256) -> Result<Signature, ecdsa::Error> {
        todo!("Digest with rng signing not implemented for RSA");
    }
}

impl RsaSigningKey {
    pub fn new(algorithm: RsaAlgorithm, keypair: ::rsa::RsaPrivateKey) -> Self {
        Self { algorithm, keypair }
    }

    pub(crate) fn from_pkcs8_pem(
        data: &str,
        algorithm: RsaAlgorithm,
    ) -> Result<Self, pkcs8::Error> {
        let key = ::rsa::RsaPrivateKey::from_pkcs8_pem(data)?;
        Ok(Self::new(algorithm, key))
    }
}

enum RsaPublicKey {
    PKCS1v15(::rsa::RsaPublicKey),
}

impl From<::rsa::RsaPublicKey> for RsaPublicKey {
    fn from(value: ::rsa::RsaPublicKey) -> Self {
        RsaPublicKey::PKCS1v15(value)
    }
}

impl PublicKeyAlgorithm for RsaPublicKey {
    fn as_jwk(&self) -> super::jwk::Jwk {
        match self {
            RsaPublicKey::PKCS1v15(key) => key.clone().into(),
        }
    }

    fn algorithm(&self) -> spki::AlgorithmIdentifierOwned {
        spki::AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
            parameters: None,
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        todo!("as_bytes not implemented for RSA")
    }

    fn to_public_key_der(&self) -> pkcs8::spki::Result<der::Document> {
        match self {
            RsaPublicKey::PKCS1v15(key) => key.to_public_key_der(),
        }
    }
}
