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
use ring::signature::EcdsaKeyPair;
use yacme_protocol::identifier::Identifier;
use yacme_protocol::orders::OrderBuilder;
use yacme_protocol::Client;

const DIRECTORY: &str = "https://localhost:14000/dir";

fn read_bytes<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut rdr = io::BufReader::new(std::fs::File::open(path)?);
    let mut buf = Vec::new();
    rdr.read_to_end(&mut buf)?;
    Ok(buf)
}

fn read_private_key<P: AsRef<Path>>(path: P) -> io::Result<EcdsaKeyPair> {
    let raw = read_bytes(path)?;

    let (label, data) = pem_rfc7468::decode_vec(&raw).unwrap();
    assert_eq!(label, "PRIVATE KEY");

    Ok(EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, &data).unwrap())
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
    let account_request = yacme_protocol::account::AccountBuilder::new()
        .add_contact_email("hello@example.org")
        .unwrap()
        .agree_to_terms_of_service();
    tracing::info!("Requesting account");
    let account = client.create_account(account_request).await?;
    println!("Account: {account:#?}");

    tracing::info!("Requesting order");
    let mut order_request = OrderBuilder::new();
    order_request.push(Identifier::dns("www.example.org".into()));

    let order = client.order(&account, order_request).await?;
    println!("Order: {order:#?}");

    Ok(())
}
