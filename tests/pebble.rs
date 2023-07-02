//! Run a certificate issue process via the pebble local ACME server
//!
//! *Prerequisite*: Start the pebble server via docker-compose. It is defined in the
//! pebble/ directory, or available at https://github.com/letsencrypt/pebble/
//!
//! This example does not handle the challenge for you, you have to provide that
//! yourself.

use std::ops::Deref;
use std::sync::Arc;

use signature::rand_core::OsRng;
use yacme::schema::authorizations::AuthorizationStatus;
use yacme::schema::challenges::{Challenge, ChallengeKind};
use yacme::service::Provider;

#[tokio::test]
async fn http01() {
    let _ = tracing_subscriber::fmt::try_init();
    pebble_http01().await.unwrap()
}

#[tracing::instrument("http01")]
async fn pebble_http01() -> Result<(), Box<dyn std::error::Error>> {
    let pebble = yacme::pebble::Pebble::new();
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let provider = Provider::build()
        .directory_url(yacme::service::provider::PEBBLE.parse().unwrap())
        .add_root_certificate(pebble.certificate())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .await?;

    let key = Arc::new(p256::SecretKey::random(&mut OsRng));

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
        auth.finalize().await?;
        tracing::info!("Authorization finalized");
    }

    tracing::info!("Finalizing order");
    tracing::debug!("Generating random certificate key");
    let certificate_key = Arc::new(p256::SecretKey::random(&mut OsRng));
    let signer = ecdsa::SigningKey::from(certificate_key.deref());
    let cert = order.finalize_and_download(&signer).await?;

    println!("{}", cert.to_pem_documents()?.join(""));

    pebble.down();

    Ok(())
}

#[tokio::test]
async fn http01_failure() {
    let _ = tracing_subscriber::fmt::try_init();
    pebble_http01_failue().await.unwrap()
}

#[tracing::instrument("http01-failure")]
async fn pebble_http01_failue() -> Result<(), Box<dyn std::error::Error>> {
    let pebble = yacme::pebble::Pebble::new();
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let provider = Provider::build()
        .directory_url(yacme::service::provider::PEBBLE.parse().unwrap())
        .add_root_certificate(pebble.certificate())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .await?;

    let key: Arc<::elliptic_curve::SecretKey<p256::NistP256>> =
        Arc::new(::elliptic_curve::SecretKey::random(&mut OsRng));

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
        let _ = match schema {
            Challenge::Http01(inner) => inner,
            _ => panic!("wat? didn't we just check the challenge type?"),
        };

        // pebble
        //     .http01(inner.token(), inner.authorization(&account.key()).deref())
        //     .await;

        chall.ready().await?;
        let error = auth.finalize().await.unwrap_err();
        assert!(matches!(error, yacme::protocol::AcmeError::Acme(_)));
        tracing::info!("Authorization finalized");
    }

    pebble.down();

    Ok(())
}

#[tokio::test]
async fn dns01() {
    let _ = tracing_subscriber::fmt::try_init();
    pebble_dns01().await.unwrap()
}

#[tracing::instrument("dns01")]
async fn pebble_dns01() -> Result<(), Box<dyn std::error::Error>> {
    let pebble = yacme::pebble::Pebble::new();
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    let provider = Provider::build()
        .directory_url(yacme::service::provider::PEBBLE.parse().unwrap())
        .add_root_certificate(pebble.certificate())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .await?;

    let key = Arc::new(p256::SecretKey::random(&mut OsRng));

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
        auth.finalize().await?;
        tracing::info!("Authorization finalized");
    }

    tracing::info!("Finalizing order");
    tracing::debug!("Generating random certificate key");
    let certificate_key = Arc::new(p256::SecretKey::random(&mut OsRng));
    let signer = ecdsa::SigningKey::from(certificate_key.deref());
    let cert = order.finalize_and_download(&signer).await?;
    println!("{}", cert.to_pem_documents()?.join(""));

    pebble.down();

    Ok(())
}
