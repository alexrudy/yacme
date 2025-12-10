# Yet Another Certificate Management Engine

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
[![Build Status][build-image]][build-link]
![MIT licensed][license-image]

YACME is an implementation of the [ACME protocol](https://tools.ietf.org/html/rfc8555).

## Features

YACME supports custom certificates, CAs, and ACME servers. It supports HTTP-01 and DNS-01 authorization challenges.
It does not currently support TLS-ALPN-01 challenges, but may at a future time.

YACME also does not support certificate revocation or account certificate updates.

YACME uses [jaws](https://crates.io/jaws) to provide JWT support, and so supports all of the signing algorithms
supported by that crate.

## Getting Started

Using the high level service interface, you can connect to letsencrypt (or really, and ACME provider) and issue a certificate:

(check out [`letsencrypt-pebble.rs`](https://github.com/alexrudy/yacme/blob/main/yacme-service/examples/letsencrypt-pebble.rs) for more details on this example, the code below is not meant to compile)

```rust no_run
//! Run a certificate issue process via the pebble local ACME server
//!
//! *Prerequisite*: Start the pebble server via docker-compose. It is defined in the
//! pebble/ directory, or available at https://github.com/letsencrypt/pebble/
//!
//! This example handles the challenge using pebble's challenge server. In the real world,
//! you would have to implement this yourself.

use std::sync::Arc;

use pkcs8::DecodePrivateKey;
use signature::rand_core::OsRng;
use yacme::schema::authorizations::AuthorizationStatus;
use yacme::schema::challenges::{ChallengeKind, Http01Challenge};

const PRIVATE_KEY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/reference-keys/ec-p255.pem");
const PEBBLE_ROOT_CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/pebble/pebble.minica.pem");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    tracing::debug!("Loading root certificate from {PEBBLE_ROOT_CA}");
    let cert = reqwest::Certificate::from_pem(&std::fs::read(PEBBLE_ROOT_CA)?)?;

    let provider = yacme::service::Provider::build()
        .directory_url(yacme::service::provider::PEBBLE.parse().unwrap())
        .add_root_certificate(cert)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .await?;

    tracing::info!("Loading private key from {PRIVATE_KEY_PATH:?}");

    let key = Arc::new(ecdsa::SigningKey::from_pkcs8_pem(
        &std::fs::read_to_string(PRIVATE_KEY_PATH)?,
    )?);

    // Step 1: Get an account
    tracing::info!("Requesting account");
    let account = provider
        .account(key)
        .add_contact_email("hello@example.test")?
        .agree_to_terms_of_service()
        .create()
        .await?;

    tracing::trace!("Account: \n{account:#?}");
    tracing::info!("Requesting order");

    let mut order = account
        .order()
        .dns("www.example.test")
        .dns("internal.example.test")
        .create()
        .await?;
    tracing::trace!("Order: \n{order:#?}");

    tracing::info!("Completing Authorizations");

    for auth in order.authorizations().await?.iter_mut() {
        tracing::info!("Authorizing {:?}", auth.identifier());
        tracing::trace!("Authorization: \n{auth:#?}");

        if !matches!(auth.data().status, AuthorizationStatus::Pending) {
            continue;
        }

        let mut chall = auth
            .challenge(&ChallengeKind::Http01)
            .ok_or("No http01 challenge provided")?;
        let inner = chall.http01().unwrap();
        http01_challenge_response(&inner, &account.key()).await?;

        chall.ready().await?;
        auth.finalize().await?;
        tracing::info!("Authorization finalized");
    }

    tracing::info!("Finalizing order");
    tracing::debug!("Generating random certificate key");
    let certificate_key = Arc::new(ecdsa::SigningKey::<p256::NistP256>::random(&mut OsRng));
    let cert = order
        .finalize_and_download::<ecdsa::SigningKey::<p256::NistP256>, ecdsa::der::Signature<p256::NistP256>>(&certificate_key)
        .await?;

    println!("{}", cert.to_pem_documents()?.join(""));

    Ok(())
}

// This method is specific to pebble - you would set up your challenge respons in an appropriate fashion
async fn http01_challenge_response(
    challenge: &Http01Challenge,
    key: &ecdsa::SigningKey<p256::NistP256>,
) -> Result<(), reqwest::Error> {
    #[derive(Debug, serde::Serialize)]
    struct Http01ChallengeSetup {
        token: String,
        content: String,
    }

    let chall_setup = Http01ChallengeSetup {
        token: challenge.token().into(),
        content: (*challenge.authorization(key)).to_owned(),
    };

    tracing::trace!(
        "Challenge Setup:\n{}",
        serde_json::to_string(&chall_setup).unwrap()
    );

    let resp = reqwest::Client::new()
        .post("http://localhost:8055/add-http01")
        .json(&chall_setup)
        .send()
        .await?;
    match resp.error_for_status_ref() {
        Ok(_) => {}
        Err(_) => {
            eprintln!("Request:");
            eprintln!("{}", serde_json::to_string(&chall_setup).unwrap());
            eprintln!("ERROR:");
            eprintln!("Status: {:?}", resp.status().canonical_reason());
            eprintln!("{}", resp.text().await?);
            panic!("Failed to update challenge server");
        }
    }

    Ok(())
}

```

## Finding your way around

YACME is split into several levels of api:

- [`service`](https://docs.rs/yacme/latest/yacme/service/index.html) is the high level API, and provides a simple interface for issuing certificates.
- [`schema`](https://docs.rs/yacme/latest/yacme/schema/index.html) provides all of the data structures to implement individual ACME endpoints.
- [`protocol`](https://docs.rs/yacme/latest/yacme/protocol/index.html) provides the JWT protocol used by ACME servers.
- [`cert`](https://docs.rs/yacme/latest/yacme/cert/index.html) provides support for X.509 certificates.

## Goals

This is a yak-shave project to get an ACME client in rust that I like, and to learn more about ACME, and internet protocol cryptography in general.

The design goals of this project are:

- No OpenSSL dependency. The cryptography here should be pure rust.
- Modular and re-usable. This isn't an opinionated command line tool to help you get started. Instead, this crate hopes to be easy to integrate into existing projects, like those built on hyper.
- Easy to extend: adding new signature algorithms, challenge types, and other extensions (assuming they are supported by pure rust crates) should be relatively easy.
- Runtime flexible. Signature algorithms can be swapped out without changing types in the code calling in to the ACME service.

This probably isn't good for production use, but it is based on the work of [RustCrypto](https://github.com/RustCrypto) who make good stuff. Don't blame them, blame me!

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/yacme
[crate-link]: https://crates.io/crates/yacme
[docs-image]: https://docs.rs/yacme/badge.svg
[docs-link]: https://docs.rs/yacme/
[build-image]: https://github.com/alexrudy/yacme/actions/workflows/ci.yml/badge.svg
[build-link]: https://github.com/alexrudy/yacme/actions/workflows/ci.yml
[license-image]: https://img.shields.io/badge/license-MIT-blue.svg
