# yacme

Yet Another ACME Client

This crate provides the unified interface to using YACME sub-crates.

To get started, check out [`yacme::service`](https://docs.rs/yacme/latest/yacme/service/index.html), which provides
a high level, strongly typed interface to an ACME client.

An example is available in [`letsencrypt-pebble.rs`](https://github.com/alexrudy/yacme/blob/main/yacme-service/examples/letsencrypt-pebble.rs)

## Getting Started

Using the high level service interface, you can connect to letsencrypt (or really, and ACME provider) and issue a certificate:

(check out [`letsencrypt-pebble.rs`](https://github.com/alexrudy/yacme/blob/main/yacme-service/examples/letsencrypt-pebble.rs) for more details on this example)

```rust
let provider = yacme::service::Provider::build().
    directory_url("https://acme-v02.api.letsencrypt.org/directory")
        .build()
        .await?;

let account_key = Arc::new(SignatureKind::Ecdsa(crate::key::EcdsaAlgorithm::P256).random());
// Fetch an existing account
let account = provider.account().key(account_key).must_exist().get().await?;

// Create a new order
let mut order = account
    .order()
    .dns("www.example.test")
    .dns("internal.example.test")
    .create()
    .await?;

// Get the authorizations
let authz: Vec<Authorization> = order.authorizations().await?;
let auth = authz.first().unwrap();
let chall = auth
    .challenge("http-01")
    .ok_or("No http01 challenge provided")?;
let inner = chall.http01().unwrap();
// Complete the challenges, then call
chall.ready().await?;
// Wait for the service to acknowleged the challenge
auth.finalize().await?;

// Set a certifiacte key
let cert_key = Arc::new(SignatureKind::Ecdsa(crate::key::EcdsaAlgorithm::P256).random());

// Attach the certificate key to the order
order.certificate_key(key);

// Finalize and fetch the order
let cert = order.finalize_and_donwload().await?;

```

## License

MIT
