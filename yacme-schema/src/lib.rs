pub mod account;
pub mod authorizations;
pub mod challenges;
pub mod client;
pub mod directory;
pub mod identifier;
pub mod orders;
mod response;

pub use crate::response::Response;
pub use account::Account;
pub use client::Client;
pub use identifier::Identifier;
pub use orders::Order;

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
                "/../reference-keys/",
                $name,
                ".pem"
            )))
        };
    }

    pub(crate) fn key(private: &str) -> Arc<yacme_key::SigningKey> {
        let key = yacme_key::SigningKey::from_pkcs8_pem(
            private,
            yacme_key::SignatureKind::Ecdsa(yacme_key::EcdsaAlgorithm::P256),
        )
        .unwrap();

        Arc::new(key)
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
