//! Run a certificate issue process via the pebble local ACME server
//!
//! *Prerequisite*: Start the pebble server via docker-compose. It is defined in the
//! pebble/ directory, or available at https://github.com/letsencrypt/pebble/
//!
//! This example does not handle the challenge for you, you have to provide that
//! yourself.

use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use signature::rand_core::OsRng;
use yacme::schema::authorizations::AuthorizationStatus;
use yacme::schema::challenges::{Challenge, ChallengeKind};
use yacme::service::Provider;

fn tracing_init() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
}

#[tokio::test]
async fn http01() {
    tracing_init();
    pebble_http01().await.unwrap();
    yacme::pebble::Pebble::new().down();
}

fn random_key() -> Arc<ecdsa::SigningKey<p256::NistP256>> {
    Arc::new(ecdsa::SigningKey::from(
        ecdsa::SigningKey::<p256::NistP256>::random(&mut OsRng),
    ))
}

#[tracing::instrument("http01")]
async fn pebble_http01() -> Result<(), Box<dyn std::error::Error>> {
    let pebble = yacme::pebble::Pebble::new();
    tokio::time::timeout(Duration::from_secs(3), pebble.ready()).await??;

    let provider = Provider::build()
        .directory_url(yacme::service::provider::PEBBLE.parse().unwrap())
        .add_root_certificate(pebble.certificate())
        .timeout(Duration::from_secs(30))
        .build()
        .await?;

    let key = random_key();

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
        tracing::info!("Authorizing {:?} with HTTP01", auth.identifier());
        tracing::trace!("Authorization: \n{auth:#?}");

        if !matches!(auth.data().status, AuthorizationStatus::Pending) {
            continue;
        }

        let mut chall = auth
            .challenge(&ChallengeKind::Http01)
            .ok_or("Pebble did not provide an http-01 challenge")?;

        let schema = chall.data();
        let inner = match schema {
            Challenge::Http01(inner) => inner,
            _ => panic!("wat? didn't we just check the challenge type?"),
        };

        pebble
            .http01(
                inner.token(),
                inner.authorization(account.key().deref()).deref(),
            )
            .await;

        chall.ready().await?;
        tokio::time::timeout(Duration::from_secs(60), auth.finalize())
            .await
            .unwrap()?;
        tracing::info!("Authorization finalized");
    }

    tracing::info!("Finalizing order");
    tracing::debug!("Generating random certificate key");
    let certificate_key = Arc::new(ecdsa::SigningKey::<p256::NistP256>::random(&mut OsRng));
    let cert = tokio::time::timeout(
        Duration::from_secs(60),
        order.finalize_and_download::<ecdsa::SigningKey<p256::NistP256>, ecdsa::der::Signature<_>>(
            &certificate_key,
        ),
    )
    .await
    .unwrap()?;

    println!("{}", cert.to_pem_documents()?.join(""));

    pebble.down();

    Ok(())
}

#[tokio::test]
async fn failure_http01_challenge() {
    tracing_init();
    pebble_http01_failue().await.unwrap();
    yacme::pebble::Pebble::new().down();
}

#[tracing::instrument("http01-failure")]
async fn pebble_http01_failue() -> Result<(), Box<dyn std::error::Error>> {
    let pebble = yacme::pebble::Pebble::new();
    tokio::time::timeout(Duration::from_secs(3), pebble.ready()).await??;

    let provider = Provider::build()
        .directory_url(yacme::service::provider::PEBBLE.parse().unwrap())
        .add_root_certificate(pebble.certificate())
        .timeout(Duration::from_secs(30))
        .build()
        .await?;

    let key = random_key();

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

    let order = account
        .order()
        .dns("fail.example.test")
        .dns("also-fail.example.test")
        .create()
        .await?;
    tracing::trace!("Order: \n{order:#?}");

    tracing::info!("Completing Authorizations");

    for auth in order.authorizations().await?.iter_mut() {
        tracing::info!("Authorizing {:?} with HTTP01", auth.identifier());
        tracing::trace!("Authorization: \n{auth:#?}");

        if !matches!(auth.data().status, AuthorizationStatus::Pending) {
            continue;
        }

        let mut chall = auth
            .challenge(&ChallengeKind::Http01)
            .ok_or("Pebble did not provide an http-01 challenge")?;

        let schema = chall.data();
        let _ = match schema {
            Challenge::Http01(inner) => inner,
            _ => panic!("wat? didn't we just check the challenge type?"),
        };

        // pebble
        //     .http01(inner.token(), inner.authorization(&account.key()).deref())
        //     .await;

        chall.ready().await?;
        let error = tokio::time::timeout(Duration::from_secs(60), auth.finalize())
            .await?
            .unwrap_err();
        assert!(matches!(error, yacme::protocol::AcmeError::Acme(_)));
        tracing::info!("Authorization finalized");
    }

    pebble.down();

    Ok(())
}

#[tokio::test]
async fn dns01() {
    tracing_init();
    let r = pebble_dns01().await;
    yacme::pebble::Pebble::new().down();
    r.unwrap();
}

#[tracing::instrument("dns01")]
async fn pebble_dns01() -> Result<(), Box<dyn std::error::Error>> {
    let pebble = yacme::pebble::Pebble::new();
    tokio::time::timeout(Duration::from_secs(3), pebble.ready()).await??;

    let provider = Provider::build()
        .directory_url(yacme::service::provider::PEBBLE.parse().unwrap())
        .add_root_certificate(pebble.certificate())
        .timeout(Duration::from_secs(30))
        .build()
        .await?;

    let key = random_key();

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
        .dns("dns.example.test")
        .dns("other.example.test")
        .create()
        .await?;
    tracing::trace!("Order: \n{order:#?}");

    tracing::info!("Completing Authorizations");

    for auth in order.authorizations().await?.iter_mut() {
        tracing::info!("Authorizing {:?} with DNS01", auth.identifier());
        tracing::trace!("Authorization: \n{auth:#?}");

        if !matches!(auth.data().status, AuthorizationStatus::Pending) {
            continue;
        }

        let mut chall = auth
            .challenge(&ChallengeKind::Dns01)
            .ok_or("Pebble did not provide an dns-01 challenge")?;

        let schema = chall.data();
        let inner = match schema {
            Challenge::Dns01(inner) => inner,
            _ => panic!("wat? didn't we just check the challenge type?"),
        };

        pebble
            .dns01(
                &inner.record(&auth.identifier().to_string()),
                inner.digest(account.key().deref()).deref(),
            )
            .await;

        chall.ready().await?;
        tokio::time::timeout(Duration::from_secs(60), auth.finalize())
            .await
            .unwrap()?;
        tracing::info!("Authorization finalized");
    }

    tracing::info!("Finalizing order");
    tracing::debug!("Generating random certificate key");
    let certificate_key = Arc::new(rsa::pkcs1v15::SigningKey::random(&mut OsRng, 2048).unwrap());
    let cert = tokio::time::timeout(
        Duration::from_secs(60),
        order.finalize_and_download::<rsa::pkcs1v15::SigningKey<sha2::Sha256>, rsa::pkcs1v15::Signature>(&certificate_key),
    )
    .await??;
    println!("{}", cert.to_pem_documents()?.join(""));

    pebble.down();

    Ok(())
}
