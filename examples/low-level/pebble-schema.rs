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

use pkcs8::DecodePrivateKey;
use reqwest::Url;
use serde::Serialize;
use signature::rand_core::OsRng;
use yacme::protocol::jose::AccountKeyIdentifier;
use yacme::protocol::{AcmeClient, Response};
use yacme::schema::account::{Contacts, CreateAccount};
use yacme::schema::authorizations::Authorization;
use yacme::schema::challenges::{Challenge, ChallengeReadyRequest};
use yacme::schema::directory::Directory;
use yacme::schema::orders::{CertificateChain, FinalizeOrder, NewOrderRequest, OrderStatus};
use yacme::schema::{Account, Identifier, Order};

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

fn read_private_key<P: AsRef<Path>>(path: P) -> io::Result<ecdsa::SigningKey<p256::NistP256>> {
    let raw = read_string(path)?;

    let key = ecdsa::SigningKey::<p256::NistP256>::from_pkcs8_pem(&raw).unwrap();

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
    let mut client = AcmeClient::builder()
        .add_root_certificate(cert)
        .timeout(std::time::Duration::from_secs(30))
        .with_nonce_url(directory.new_nonce.clone())
        .build()?;

    tracing::info!("Loading private key from {PRIVATE_KEY_PATH:?}");
    let key = Arc::new((read_private_key(PRIVATE_KEY_PATH)?));

    // Step 1: Get an account
    tracing::info!("Requesting account");
    let contact = {
        let mut contact = Contacts::new();
        contact.add_contact_email("hello@example.test")?;
        contact
    };

    let account_request = CreateAccount {
        contact,
        terms_of_service_agreed: Some(true),
        ..Default::default()
    };

    let account: Response<Account> = client
        .post(directory.new_account.clone(), account_request, key.clone())
        .await?;

    tracing::trace!("Account: \n{account:#?}");
    let account_id: AccountKeyIdentifier = account.location().unwrap().into();
    let account_key = (key.clone(), account_id);

    tracing::info!("Requesting order");

    let identifiers = vec![
        Identifier::dns("www.example.test".into()),
        Identifier::dns("internal.example.test".into()),
    ];

    let payload = NewOrderRequest {
        identifiers,
        ..Default::default()
    };

    let order: Response<Order> = client
        .post(directory.new_order.clone(), payload, account_key.clone())
        .await?;

    let order_url = order.location().expect("New order should have a location");
    tracing::trace!("Order: \n{order:#?}");

    tracing::info!("Completing Authorizations");
    for authz_url in order.payload().authorizations() {
        let authz: Response<Authorization> = client
            .get_as_post(authz_url.clone(), account_key.clone())
            .await?;
        tracing::trace!("Authz:\n{authz:#?}");

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
            tracing::trace!("Challenge:\n{:#?}", challenge);

            #[derive(Debug, Serialize)]
            struct Http01ChallengeSetup {
                token: String,
                content: String,
            }

            let chall_setup = Http01ChallengeSetup {
                token: challenge.token().into(),
                content: challenge.authorization(&*key).to_owned(),
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

            let challenge = client
                .post::<_, _, _, Challenge>(
                    challenge.url(),
                    ChallengeReadyRequest,
                    account_key.clone(),
                )
                .await?;

            tracing::debug!("Marked challenge ready: {challenge:#?}");
        }

        loop {
            tracing::debug!("Fetching authorization");

            let authz: Response<Authorization> = client
                .get_as_post(authz_url.clone(), account_key.clone())
                .await?;
            tracing::trace!("Authz:\n{authz:#?}");

            let challenge = authz
                .payload()
                .challenges
                .iter()
                .find(|c| c.url() == Some(challenge.url()))
                .unwrap();

            tracing::debug!("Checking challenge {challenge:#?}");

            if challenge.is_finished() {
                tracing::info!("Completed authorization");
                tracing::trace!("Authz:\n{:#?}", authz);
                break;
            }

            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    }
    tracing::info!("Finalizing order");
    tracing::debug!("Generating random certificate key");
    let certificate_key = Arc::new(ecdsa::SigningKey::<p256::NistP256>::random(&mut OsRng));
    let finalize =
        FinalizeOrder::new::<_, ecdsa::der::Signature<_>>(order.payload(), certificate_key.deref());
    let mut order: Response<Order> = client
        .post(
            order.payload().finalize().clone(),
            finalize,
            account_key.clone(),
        )
        .await?;

    tracing::info!("Finalized order: {:?}", order.status());
    tracing::trace!("Order:\n{order:#?}");

    while matches!(order.payload().status(), OrderStatus::Processing) {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        order = client
            .get_as_post(order_url.clone(), account_key.clone())
            .await?;
        tracing::debug!("Order status: {:?}", order.payload().status());
    }

    if let Some(certificate) = order.payload().certificate() {
        tracing::info!("Fetching certificate");
        let _cert: Response<CertificateChain> = client
            .get_as_post(certificate.clone(), account_key.clone())
            .await?;

        tracing::info!("Save certificate chain here");
    } else {
        tracing::warn!("Certificate was never finalized");
    }

    Ok(())
}
