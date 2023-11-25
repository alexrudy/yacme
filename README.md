# Yet Another Certificate Management Engine

YACME is an implementation of the [ACME protocol](https://tools.ietf.org/html/rfc8555).

## Features

YACME supports custom certificates, CAs, and ACME servers. It supports HTTP-01 and DNS-01 authorization challenges.
It does not currently support TLS-ALPN-01 challenges, but may at a future time.

YACME also does not support certificate revocation or account certificate updates.

YACME supports ec256 keys only at this point, but new key implementations would be welcome
additions to `yacme::key`.

## Getting Started

Using the high level service interface, you can connect to letsencrypt (or really, and ACME provider) and issue a certificate:

(check out [`letsencrypt-pebble.rs`](https://github.com/alexrudy/yacme/blob/main/yacme-service/examples/letsencrypt-pebble.rs) for more details on this example)

```rust no_run

use std::sync::Arc;
use yacme::service::Authorization;
use yacme::schema::challenges::ChallengeKind;
use signature::rand_core::OsRng;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {


    let provider = yacme::service::Provider::build().
        directory_url(
            yacme::service::provider::LETSENCRYPT.parse().unwrap()
        )
            .build()
            .await?;

    // Create a random key to identify this account. Currently only ECDSA keys using
    // the P256 curve are supported.
    let account_key: Arc<::elliptic_curve::SecretKey<p256::NistP256>> = Arc::new(::elliptic_curve::SecretKey::random(&mut OsRng));

    // You should probably save this key somewhere:
    use pkcs8::{EncodePrivateKey, LineEnding};
    let data = account_key.to_pkcs8_pem(LineEnding::default()).unwrap();

    // Fetch an existing account
    let account = provider.account(account_key).must_exist().get().await?;

    // Create a new order
    let mut order = account
        .order()
        .dns("www.example.test")
        .dns("internal.example.test")
        .create()
        .await?;

    // Get the authorizations
    let mut authz: Vec<Authorization<_>> = order.authorizations().await?;
    let auth = &mut authz[0];
    let mut chall = auth
        .challenge(&ChallengeKind::Http01)
        .ok_or("No http01 challenge provided")?;
    let inner = chall.http01().unwrap();
    // Complete the challenges, then call
    chall.ready().await?;
    // Wait for the service to acknowleged the challenge
    auth.finalize().await?;

    // Set a certifiacte key
    let cert_key: ::ecdsa::SigningKey<p256::NistP256> = ::elliptic_curve::SecretKey::random(&mut OsRng).into();

    // Finalize and fetch the order
    let cert = order.finalize_and_download(&cert_key).await?;

    Ok(())
}

```

## Finding your way around

YACME is split into several levels of api:

- `service` is the high level API, and provides a simple interface for issuing certificates.
- `schema` provides all of the data structures to implement individual ACME endpoints.
- `protocol` provides the JWT protocol used by ACME servers.
- `key` provides support for ECDSA keys.

## Goals

This is a yak-shave project to get an ACME client in rust that I like, and to learn more about ACME, and internet protocol cryptography in general.

The design goals of this project are:

- No OpenSSL dependency. The cryptography here should be pure rust.
- Modular and re-usable. This isn't an opinionated command line tool to help you get started. Instead, this crate hopes to be easy to integrate into existing projects, like those built on hyper.
- Easy to extend: adding new signature algorithms, challenge types, and other extensions (assuming they are supported by pure rust crates) should be relatively easy.
- Runtime flexible. Signature algorithms can be swapped out without changing types in the code calling in to the ACME service.

This probably isn't good for production use, but it is based on the work of [RustCrypto](https://github.com/RustCrypto) who make good stuff. Don't blame them, blame me!
