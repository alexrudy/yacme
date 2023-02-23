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

use reqwest::Url;
use serde::Serialize;
use yacme_protocol::jose::AccountKeyIdentifier;
use yacme_protocol::{Client, Request, Response};
use yacme_schema::authorizations::Authorization;
use yacme_schema::challenges::{Challenge, ChallengeReadyRequest};
use yacme_schema::directory::Directory;
use yacme_schema::orders::{CertificateChain, FinalizeOrder, OrderStatus};
use yacme_schema::{Account, Order};

const DIRECTORY: &str = "https://localhost:14000/dir";

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
const CERTIFICATE_KEY_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../reference-keys/ec-p255-cert.pem"
);
const PEBBLE_ROOT_CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../pebble/pebble.minica.pem");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Loading root certificate from {PEBBLE_ROOT_CA}");
    let cert = reqwest::Certificate::from_pem(&read_bytes(PEBBLE_ROOT_CA)?)?;
    let client = reqwest::Client::builder()
        .add_root_certificate(cert.clone())
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    tracing::info!("Fetching directory");
    let directory: Directory = client
        .get::<Url>(DIRECTORY.parse().unwrap())
        .send()
        .await?
        .json()
        .await?;

    // Client maintains synchronous state, and so requires a mutable / exclusive reference.
    let mut client = Client::builder()
        .add_root_certificate(cert)
        .timeout(std::time::Duration::from_secs(30))
        .with_nonce_url(directory.new_nonce.clone())
        .build()?;

    tracing::info!("Loading private key from {PRIVATE_KEY_PATH:?}");
    let key = Arc::new(read_private_key(PRIVATE_KEY_PATH)?);

    // Step 1: Get an account
    tracing::info!("Requesting account");
    let account_request = yacme_schema::Account::builder()
        .add_contact_email("hello@example.test")
        .unwrap()
        .agree_to_terms_of_service()
        .build(&key.public_key(), directory.new_account.clone());
    let account: Response<Account> = client
        .execute(Request::post(
            account_request,
            directory.new_account.clone(),
            key.clone(),
        ))
        .await?;

    tracing::debug!("Account: {account:#?}");
    let account_id: AccountKeyIdentifier = account.location().unwrap().into();
    let account_key = (key.clone(), account_id);

    tracing::info!("Requesting order");
    let mut order_request = Order::builder();
    order_request.dns("www.example.test");
    order_request.dns("internal.example.test");

    let order: Response<Order> = client
        .execute(Request::post(
            order_request.build(),
            directory.new_order.clone(),
            account_key.clone(),
        ))
        .await?;

    let order_url = order.location().expect("New order should have a location");
    tracing::debug!("Order: {order:#?}");

    tracing::info!("Completing Authorizations");
    for authz_url in order.payload().authorizations() {
        let authz = client
            .execute::<_, Authorization>(Request::get(authz_url.clone(), account_key.clone()))
            .await?;
        tracing::debug!("Authz: {authz:#?}");

        let challenge = authz
            .payload()
            .challenges
            .iter()
            .filter_map(|c| match c {
                Challenge::Http01(challenge) => Some(challenge),
                _ => None,
            })
            .next()
            .unwrap();

        if !challenge.is_finished() {
            tracing::info!("Solving challenge");
            tracing::debug!("Challenge: {:#?}", challenge);

            #[derive(Debug, Serialize)]
            struct Http01ChallengeSetup {
                token: String,
                content: String,
            }

            let chall_setup = Http01ChallengeSetup {
                token: challenge.token().into(),
                content: challenge.authorization(&key).deref().to_owned(),
            };

            tracing::debug!(
                "Challenge Setup: {}",
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

            let challenge = client
                .execute::<_, Challenge>(Request::post(
                    ChallengeReadyRequest::default(),
                    challenge.url(),
                    account_key.clone(),
                ))
                .await?;

            tracing::debug!("Marked challenge ready: {challenge:#?}");
        }

        loop {
            tracing::debug!("Fetching authorization");

            let authz = client
                .execute::<_, Authorization>(Request::get(authz_url.clone(), account_key.clone()))
                .await?;
            tracing::debug!("Authz: {authz:#?}");

            let challenge = authz
                .payload()
                .challenges
                .iter()
                .find(|c| c.url() == Some(challenge.url()))
                .unwrap();

            tracing::debug!("Checking challenge {challenge:#?}");

            if challenge.is_finished() {
                tracing::info!("Completed authorization");
                tracing::debug!("{:#?}", authz);
                break;
            }

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
    tracing::info!("Finalizing order");
    println!("Loading certificate private key from {CERTIFICATE_KEY_PATH:?}");
    let key = Arc::new(read_private_key(CERTIFICATE_KEY_PATH)?);
    let finalize = FinalizeOrder::new(order.payload(), &key);
    let mut order = client
        .execute::<_, Order>(Request::post(
            finalize,
            order.payload().finalize().clone(),
            account_key.clone(),
        ))
        .await?;

    tracing::info!("Finalized order: {:?}", order.status());
    tracing::debug!("Order: {order:#?}");

    while matches!(order.payload().status(), OrderStatus::Processing) {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        order = client
            .execute(Request::get(order_url.clone(), account_key.clone()))
            .await?;
        tracing::debug!("Order status: {:?}", order.payload().status());
    }

    if let Some(certificate) = order.payload().certificate() {
        tracing::info!("Fetching certificate");
        let _cert = client
            .execute::<_, CertificateChain>(Request::get(certificate.clone(), account_key.clone()))
            .await?;

        tracing::info!("Save certificate chain here");
    } else {
        tracing::warn!("Certificate was never finalized");
    }

    Ok(())
}
