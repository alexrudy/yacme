#![doc = include_str!("../README.md")]

pub mod cert;
pub mod protocol;
pub mod schema;
pub mod service;

#[cfg(any(test, feature = "pebble"))]
pub mod pebble;

#[cfg(test)]
pub(crate) mod test {
    use std::sync::Arc;

    use base64ct::LineEnding;
    use pkcs8::{DecodePrivateKey, EncodePrivateKey};

    pub fn key(private: &str) -> Arc<elliptic_curve::SecretKey<p256::NistP256>> {
        let key = elliptic_curve::SecretKey::from_pkcs8_pem(&private).unwrap();

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
        let key2 = elliptic_curve::SecretKey::from_pkcs8_pem(&pkcs8).unwrap();

        assert_eq!(key.as_ref(), &key2);
    }
}
