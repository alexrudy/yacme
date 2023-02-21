use std::{fmt, str::FromStr};

mod base64;
pub mod errors;
pub mod jose;

pub use base64::{Base64Data, Base64JSON};
pub use errors::AcmeError;
use serde::{Deserialize, Serialize};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Url(url::Url);

impl Url {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<url::Url> for Url {
    fn from(value: url::Url) -> Self {
        Url(value)
    }
}

impl From<Url> for url::Url {
    fn from(value: Url) -> Self {
        value.0
    }
}

impl AsRef<str> for Url {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Url").field(&self.0.as_str()).finish()
    }
}

impl FromStr for Url {
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(Url)
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::sync::Arc;

    #[macro_export]
    macro_rules! example {
        ($name:tt) => {
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-examples/",
                $name
            ))
        };
    }

    #[macro_export]
    macro_rules! key {
        ($name:tt) => {
            $crate::test::key(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/test-examples/",
                $name,
                ".pem"
            )))
        };
    }

    #[allow(dead_code)]
    pub(crate) fn key(private: &str) -> Arc<yacme_key::SigningKey> {
        let key = yacme_key::SigningKey::from_pkcs8_pem(
            private,
            yacme_key::SignatureKind::Ecdsa(yacme_key::EcdsaAlgorithm::P256),
        )
        .unwrap();

        Arc::new(key)
    }
}
