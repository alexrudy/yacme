use crate::{PublicKeyAlgorithm, Signature};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaAlgorithm {
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
}
