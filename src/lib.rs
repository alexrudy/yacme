#![cfg_attr(
    not(doc),
    doc = "YACME is an implementation of the [ACME protocol](https://tools.ietf.org/html/rfc8555)."
)]
#![cfg_attr(feature = "pebble", doc = include_str!("../README.md"))]
#![deny(missing_docs)]

pub mod cert;
pub mod protocol;
pub mod schema;
pub mod service;

#[cfg(feature = "pebble")]
pub mod pebble;

#[cfg(test)]
#[allow(missing_docs)]
pub(crate) mod test {
    use std::sync::Arc;

    use base64ct::LineEnding;
    use pkcs8::{DecodePrivateKey, EncodePrivateKey};

    pub fn key(private: &str) -> Arc<ecdsa::SigningKey<p256::NistP256>> {
        let key = ecdsa::SigningKey::from_pkcs8_pem(private).unwrap();

        Arc::new(key)
    }

    #[macro_export]
    macro_rules! key {
        ($name:tt) => {
            $crate::test::key(include_str!(concat!(
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
        let key2 = ecdsa::SigningKey::from_pkcs8_pem(&pkcs8).unwrap();

        assert_eq!(key.as_ref(), &key2);
    }
}
