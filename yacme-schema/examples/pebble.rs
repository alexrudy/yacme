//! Run a certificate issue process via the pebble local ACME server
//!
//! *Prerequisite*: Start the pebble server via docker-compose. It is defined in the
//! pebble/ directory, or available at https://github.com/letsencrypt/pebble/
//!
//! This example does not handle the challenge for you, you have to provide that
//! yourself.

use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

use reqwest::Certificate;
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

const PRIVATE_KEY_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-examples/ec-p255.pem");
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

    Ok(())
}
