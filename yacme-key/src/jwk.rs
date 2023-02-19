use std::fmt;

use serde::ser;

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
