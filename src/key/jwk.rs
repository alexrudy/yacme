//! Yacme's primatives for JSON Web Keys and thumbprints
use std::fmt;

use base64ct::Encoding;
use elliptic_curve::sec1::Coordinates;
use serde::ser::{self, SerializeStruct};
use sha2::Digest;

/// JSON Web Key structure for a private or public singing key.
///
/// JWK serializes the information required to verify or recover a key
/// in a well-known JSON format. This is used to both initially provide
/// a key for an ACME account, and to sign additional pieces of a payload
/// (i.e. external account bindings).
///
/// JWK implements [serde::Serialize] so that it can be used as an element
/// of a JSON-serializable structure. This also means that JWK can be used
/// to store information about a key in other serde-supported formats.
///
/// Along with serialization, JWK exposes a [Jwk::thumbprint] method for computing
/// the key thumbprint required for ACME authorization challenges.
#[derive(Clone, PartialEq, Eq)]
pub struct Jwk(InnerJwk);

impl fmt::Debug for Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Jwk").finish()
    }
}

impl Jwk {
    /// An RFC 7638 thumbprint, which uniquely identifies this JWS cryptographic
    /// key.
    ///
    /// The thumbprint hash value can be used for identifying or selecting the key
    /// represented by the JWK that is the subject of the thumbprint.
    pub fn thumbprint(&self) -> String {
        let thumb = serde_json::to_vec(&self).expect("Valid JSON format");
        // eprintln!("JWK: {}", std::str::from_utf8(&thumb).unwrap());

        let mut hasher = sha2::Sha256::new();
        hasher.update(&thumb);
        let digest = hasher.finalize();
        base64ct::Base64UrlUnpadded::encode_string(&digest)
    }
}

#[derive(Clone, PartialEq, Eq)]
enum InnerJwk {
    EllipticCurve(elliptic_curve::JwkEcKey),
}

impl ser::Serialize for Jwk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.0 {
            InnerJwk::EllipticCurve(ec_jwk) => {
                let mut state = serializer.serialize_struct("Jwk", 3)?;
                let point = ec_jwk.to_encoded_point::<p256::NistP256>().unwrap();
                let Coordinates::Uncompressed { x, y } = point.coordinates() else {panic!("can't extract jwk coordinates")};
                state.serialize_field("crv", ec_jwk.crv())?;
                state.serialize_field("kty", "EC")?;
                state.serialize_field("x", &base64ct::Base64UrlUnpadded::encode_string(x))?;
                state.serialize_field("y", &base64ct::Base64UrlUnpadded::encode_string(y))?;
                state.end()
            }
        }
    }
}

impl From<elliptic_curve::JwkEcKey> for Jwk {
    fn from(value: elliptic_curve::JwkEcKey) -> Self {
        Jwk(InnerJwk::EllipticCurve(value))
    }
}
