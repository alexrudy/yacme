use std::fmt;

use ring::signature::{EcdsaKeyPair, KeyPair};
use serde::{Deserialize, Serialize};

use super::transport::Base64Data;

pub type PublicKey = <EcdsaKeyPair as KeyPair>::PublicKey;

#[derive(Debug, Serialize)]
enum CurveID {
    #[serde(rename = "P-256")]
    P256,
}

#[derive(Debug, Serialize)]
enum KeyType {
    #[serde(rename = "EC")]
    EllipticCurve,
}

#[derive(Debug)]
struct Coordinate(Vec<u8>);

#[derive(Debug, Serialize)]
pub(crate) struct JWK<'k> {
    #[serde(rename = "crv")]
    curve: CurveID,

    #[serde(rename = "kty")]
    key_type: KeyType,

    x: Base64Data<&'k [u8]>,

    y: Base64Data<&'k [u8]>,
}

impl<'k> JWK<'k> {
    pub(crate) fn new(key: &'k EcdsaKeyPair) -> JWK<'k> {
        let (x, y) = key.public_key().as_ref()[1..].split_at(32);
        Self {
            curve: CurveID::P256,
            key_type: KeyType::EllipticCurve,
            x: Base64Data(x),
            y: Base64Data(y),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thumbprint(String);

impl fmt::Display for Thumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

pub fn thumbprint(key: &EcdsaKeyPair) -> Thumbprint {
    let jwk = JWK::new(key);
    let raw = serde_json::to_vec(&jwk).expect("Valid jwk json");
    let digest = ring::digest::digest(&ring::digest::SHA256, &raw);

    Thumbprint(base64_url::encode(&digest))
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    ES256,
    HS256,
}
