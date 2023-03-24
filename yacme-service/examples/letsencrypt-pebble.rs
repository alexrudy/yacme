//! Run a certificate issue process via the pebble local ACME server
//!
//! *Prerequisite*: Start the pebble server via docker-compose. It is defined in the
//! pebble/ directory, or available at https://github.com/letsencrypt/pebble/
//!
//! This example does not handle the challenge for you, you have to provide that
//! yourself.

use std::io::{self, Read};
use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use yacme_key::{SignatureKind, SigningKey};
use yacme_schema::authorizations::AuthroizationStatus;
use yacme_schema::challenges::{Challenge, Http01Challenge};
use yacme_service::Provider;

fn read_bytes<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut rdr = io::BufReader::new(std::fs::File::open(path)?);
    let mut buf = Vec::new();
    rdr.read_to_end(&mut buf)?;
    Ok(buf)
}

fn read_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut rdr = io::BufReader::new(std::fs::File::open(path)?);
    let mut buf = String::new();
    rdr.read_to_string(&mut buf)?;
    Ok(buf)
}

fn read_private_key<P: AsRef<Path>>(path: P) -> io::Result<yacme_key::SigningKey> {
    let raw = read_string(path)?;

    let key = yacme_key::SigningKey::from_pkcs8_pem(
        &raw,
        yacme_key::SignatureKind::Ecdsa(yacme_key::EcdsaAlgorithm::P256),
    )
    .unwrap();

    Ok(key)
}

const PRIVATE_KEY_PATH: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../reference-keys/ec-p255.pem");

const PEBBLE_ROOT_CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../pebble/pebble.minica.pem");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    tracing::debug!("Loading root certificate from {PEBBLE_ROOT_CA}");
    let cert = reqwest::Certificate::from_pem(&read_bytes(PEBBLE_ROOT_CA)?)?;

    let provider = Provider::build()
        .directory_url(yacme_service::provider::PEBBLE.parse().unwrap())
        .add_root_certificate(cert)
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .await?;

    tracing::info!("Loading private key from {PRIVATE_KEY_PATH:?}");
    let key = Arc::new(read_private_key(PRIVATE_KEY_PATH)?);

    // Step 1: Get an account
    tracing::info!("Requesting account");
    let account = provider
        .account()
        .add_contact_email("hello@example.test")?
        .key(key)
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

    for auth in order.authorizations().await? {
        tracing::info!("Authorizing {:?}", auth.identifier());
        tracing::trace!("Authorization: \n{auth:#?}");

        if !matches!(auth.schema().status, AuthroizationStatus::Pending) {
            continue;
        }

        let chall = auth
            .challenge("http-01")
            .ok_or("Pebble did not provide an http-01 challenge")?;

        let schema = chall.schema();
        let inner = match schema.deref().deref() {
            Challenge::Http01(inner) => inner,
            _ => panic!("wat? didn't we just check the challenge type?"),
        };

        http01_challenge_response(inner, &account.key()).await?;

        chall.ready().await?;
        auth.finalize().await?;
        tracing::info!("Authorization finalized");
    }

    tracing::info!("Finalizing order");
    tracing::debug!("Generating random certificate key");
    let key = Arc::new(SignatureKind::Ecdsa(yacme_key::EcdsaAlgorithm::P256).random());

    order.certificate_key(key);
    let cert = order.finalize_and_donwload().await?;

    println!("{}", cert.to_pem_documents()?.join(""));

    Ok(())
}

// This method is specific to pebble - you would set up your challenge respons in an appropriate fashion
async fn http01_challenge_response(
    challenge: &Http01Challenge,
    key: &SigningKey,
) -> Result<(), reqwest::Error> {
    #[derive(Debug, Serialize)]
    struct Http01ChallengeSetup {
        token: String,
        content: String,
    }

    let chall_setup = Http01ChallengeSetup {
        token: challenge.token().into(),
        content: challenge.authorization(key).deref().to_owned(),
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
