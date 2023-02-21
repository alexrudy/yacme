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

use reqwest::Certificate;
use serde::Serialize;
use yacme_schema::challenges::Challenge;
use yacme_schema::orders::OrderStatus;
use yacme_schema::Client;
use yacme_schema::Order;

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
    let cert = Certificate::from_pem(&read_bytes(PEBBLE_ROOT_CA)?)?;
    let rclient = reqwest::Client::builder()
        .add_root_certificate(cert)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    println!("Loading private key from {PRIVATE_KEY_PATH:?}");
    let key = Arc::new(read_private_key(PRIVATE_KEY_PATH)?);

    // Client maintains synchronous state, and so requires a mutable / exclusive reference.
    let mut client = Client::builder()
        .with_client(rclient)
        .with_directory_url(DIRECTORY.parse().unwrap())
        .with_key(key)
        .build()
        .await?;

    // Step 1: Get an account
    let account_request = yacme_schema::Account::builder()
        .add_contact_email("hello@example.test")
        .unwrap()
        .agree_to_terms_of_service();
    tracing::info!("Requesting account");
    let account = client.create_account(account_request).await?;
    println!("Account: {account:#?}");

    tracing::info!("Requesting order");
    let mut order_request = Order::builder();
    order_request.dns("www.example.test");

    let order = client.order(&account, order_request).await?;
    println!("Order: {order:#?}");

    tracing::info!("Finding challenge");

    let authz_url = order
        .authorizations()
        .first()
        .expect("at least one authorization");
    let authz = client.authorization(&account, authz_url.clone()).await?;
    println!("Authz: {authz:#?}");

    let challenge = authz
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
        eprintln!("{:#?}", challenge);

        #[derive(Debug, Serialize)]
        struct Http01ChallengeSetup {
            token: String,
            content: String,
        }

        let chall_setup = Http01ChallengeSetup {
            token: challenge.token().into(),
            content: challenge.authorization(&account).deref().to_owned(),
        };

        eprintln!(
            "Challenge: {}",
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

        let updated_chall = client
            .challenge_ready(&account, Challenge::Http01(challenge.clone()))
            .await?;
        println!("Marked challenge ready: {updated_chall:#?}");

        loop {
            eprintln!("Fetching latest authorization");
            let authz = client.authorization(&account, authz_url.clone()).await?;
            let challenge = authz
                .challenges
                .iter()
                .filter_map(|c| match c {
                    Challenge::Http01(challenge) => Some(challenge),
                    _ => None,
                })
                .next()
                .unwrap();
            eprintln!("Checking challenge {challenge:#?}");

            if challenge.is_finished() {
                eprintln!("Completed authorization");
                eprintln!("{:#?}", authz);
                break;
            }

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
    tracing::info!("Finalizing order");
    println!("Loading certificate private key from {CERTIFICATE_KEY_PATH:?}");
    let key = Arc::new(read_private_key(CERTIFICATE_KEY_PATH)?);

    let order = client.order_finalize(&account, order, &key).await?;
    eprintln!("Finalized order: {:?}", order.status());
    eprintln!("Order: {order:#?}");

    if !matches!(order.status(), OrderStatus::Ready) {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    let cert = client.download_certificate(&account, &order).await?;

    Ok(())
}
