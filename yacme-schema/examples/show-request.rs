use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;

use reqwest::Certificate;
use reqwest::Url;
use yacme_protocol::fmt::AcmeFormat;
use yacme_schema::directory::Directory;
use yacme_schema::{Account, Client, Request};

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
// const CERTIFICATE_KEY_PATH: &str = concat!(
//     env!("CARGO_MANIFEST_DIR"),
//     "/../reference-keys/ec-p255-cert.pem"
// );
const PEBBLE_ROOT_CA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../pebble/pebble.minica.pem");

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    println!("Loading root certificate from {PEBBLE_ROOT_CA}");
    let cert = Certificate::from_pem(&read_bytes(PEBBLE_ROOT_CA)?)?;
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
    let account_request = Request::post(
        yacme_schema::Account::builder()
            .add_contact_email("hello@example.test")
            .unwrap()
            .agree_to_terms_of_service()
            .build(&key.public_key(), directory.new_account.clone()),
        directory.new_account.clone(),
        key.clone(),
    );
    println!("{}", account_request.as_signed().formatted());

    let account = client.execute::<_, Account>(account_request).await?;
    println!("{}", account.formatted());

    Ok(())
}
