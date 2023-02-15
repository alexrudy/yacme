pub mod account;
pub mod authorizations;
pub mod challenges;
pub mod directory;
pub mod errors;
pub mod identifier;
mod key;
pub mod orders;
mod transport;

pub use account::{Account, AccountInfo};
pub use errors::AcmeError;
pub use key::PublicKey;
pub use transport::Client;

#[cfg(test)]
pub(crate) mod test {
    use std::sync::Arc;

    use ring::signature::EcdsaKeyPair;

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
    macro_rules! response {
        ($name:tt) => {
            $crate::test::parse($crate::example!($name))
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

    pub(crate) fn key(private: &str) -> Arc<EcdsaKeyPair> {
        let (label, data) = pem_rfc7468::decode_vec(private.as_bytes()).unwrap();
        assert_eq!(label, "PRIVATE KEY");

        Arc::new(
            EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &data)
                .unwrap(),
        )
    }

    pub(crate) fn parse(data: &str) -> http::Response<String> {
        let mut lines = data.lines();

        let status = {
            let status_line = lines.next().unwrap().trim();
            let (version, status) = status_line.split_once(' ').unwrap();

            if !matches!(version, "HTTP/1.1") {
                panic!("Expected HTTP/1.1, got {version}");
            }

            let (code, _reason) = status.split_once(' ').unwrap();
            http::StatusCode::from_u16(code.parse().unwrap()).unwrap()
        };

        let mut headers = http::HeaderMap::new();

        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            } else {
                let (name, value) = line.trim().split_once(": ").unwrap();
                headers.append(
                    http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
            }
        }

        let body: String = lines.collect();
        let mut response = http::Response::new(body);
        *response.headers_mut() = headers;
        *response.status_mut() = status;
        *response.version_mut() = http::Version::HTTP_11;
        response
    }
}
