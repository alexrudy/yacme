use std::fmt;

use serde::ser;

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
pub struct Jwk(InnerJwk);

impl fmt::Debug for Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Jwk").finish()
    }
}

impl Jwk {
    pub fn thumbprint(&self) -> String {
        todo!("JWK Thumbprint")
    }
}

enum InnerJwk {
    EllipticCurve(elliptic_curve::JwkEcKey),
}

impl ser::Serialize for Jwk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.0 {
            InnerJwk::EllipticCurve(ec_jwk) => ec_jwk.serialize(serializer),
        }
    }
}

impl From<elliptic_curve::JwkEcKey> for Jwk {
    fn from(value: elliptic_curve::JwkEcKey) -> Self {
        Jwk(InnerJwk::EllipticCurve(value))
    }
}
