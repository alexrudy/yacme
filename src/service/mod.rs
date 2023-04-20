//! A high-level implementation of an ACME client
//!
//! Used for managing an acocunt and issuing certificates. The usual flow
//! for a client is:
//!
//! 1. Create a [`Provider`].
//! 2. Get or create an [`Account`].
//! 3. Create an [`Order`].
//! 4. For each identity, complete a [`Challenge`] attached to an [`Authorization`]
//!    on that order. Only one challenge per authorization is required.
//! 5. Finalize the order, submitting a certificate signing request, using [`Order::finalize`].
//! 6. Download the certificate with [`Order::download`].

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cert;
use crate::protocol::{AcmeError, Result, Url};
use crate::schema::directory::Directory;

pub mod account;
pub mod authorization;
// pub(crate) mod cache;
mod client;
pub mod order;

pub use self::account::Account;
pub use self::authorization::Authorization;
pub use self::authorization::Challenge;
pub use self::order::Order;

use self::client::Client;

/// An ACME Service Provider
///
/// Providers are identified by a directory URL, and store the
/// directory along side themselves when serialized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    name: Option<String>,
    url: Url,
    directory: Directory,
    #[serde(skip, default)]
    client: Client,
}

impl Provider {
    /// Create a new Provider from a directory URL.
    ///
    /// The URL will be fetched, and a default client configuration
    /// will be used.
    pub async fn from_url(&self, url: Url) -> Result<Self> {
        let client = Client::default();
        let directory: Directory = client.get(url.clone()).await?.into_inner();

        Ok(Provider {
            name: None,
            url,
            directory,
            client,
        })
    }

    /// The name of this ACME Service provider, if specified
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// The hostname for this ACME service provider
    pub fn host(&self) -> &str {
        self.url
            .host_str()
            .expect("ACME providers should have an https:// url with a well defined hostname")
    }

    /// The configuration directory for this ACME service provider
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    /// Get or create an account
    pub fn account<K>(&self, key: Arc<K>) -> self::account::AccountBuilder<K>
    where
        K: cert::KeyPair + Clone,
    {
        self::account::AccountBuilder::new(self.clone(), key)
    }

    #[inline]
    pub(crate) fn client(&self) -> &self::client::Client {
        &self.client
    }

    /// Get a builder for a new provider.
    ///
    /// See [`ProviderBuilder`] for more information.
    pub fn build() -> ProviderBuilder {
        ProviderBuilder::new()
    }
}

/// Error occured when building a provider,
/// or building the HTTP client used to power the provider.
#[derive(Debug, Error)]
pub enum BuilderError {
    /// An error occured while building the underlying HTTP client.
    #[error("Building HTTPS client: {0}")]
    Client(#[source] reqwest::Error),

    /// No directory URL was specified, and the directory was not specified.
    #[error("Missing provider URL")]
    Url,

    /// An error occured while fetching the provider directory.
    #[error("Fetching provider directory: {0}")]
    Directory(#[source] AcmeError),
}

/// Build a provider from a directory or the URL of a directory.
#[derive(Debug)]
pub struct ProviderBuilder {
    client: crate::protocol::client::ClientBuilder,
    url: Option<Url>,
    directory: Option<Directory>,
    name: Option<String>,
}

impl ProviderBuilder {
    fn new() -> Self {
        ProviderBuilder {
            client: crate::protocol::client::Client::builder(),
            url: None,
            directory: None,
            name: None,
        }
    }

    /// Explicitly add an additional root certificate to the underlying HTTP client.
    pub fn add_root_certificate(mut self, cert: reqwest::Certificate) -> Self {
        self.client = self.client.add_root_certificate(cert);
        self
    }

    /// Set a timeout for requests to complete.
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.client = self.client.timeout(timeout);
        self
    }

    /// Set a timeout for requests to connect.
    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.client = self.client.connect_timeout(timeout);
        self
    }

    /// Set the dircetory URL, which will be used to fetch the directory if it isn't provided.
    pub fn directory_url(mut self, url: Url) -> Self {
        self.url = Some(url);
        self
    }

    /// Set the full directory structure. This will be used instead of fetching the directory from
    /// the provided URL.
    pub fn directory(mut self, directory: Directory) -> Self {
        self.directory = Some(directory);
        self
    }

    /// Set the name of the provider, used for diagnostic messages.
    pub fn name<S: Into<String>>(mut self, name: S) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Build the provider.
    pub async fn build(self) -> ::std::result::Result<Provider, BuilderError> {
        let mut client = self.client.build().map_err(BuilderError::Client)?;

        let url = self.url.ok_or(BuilderError::Url)?;

        let directory = if let Some(directory) = self.directory {
            directory
        } else {
            client
                .get(url.clone())
                .await
                .map_err(BuilderError::Directory)?
                .into_inner()
        };

        client.set_new_nonce_url(directory.new_nonce.clone());

        Ok(Provider {
            name: self.name,
            url,
            directory,
            client: Client::new(client),
        })
    }
}

/// Included ACME provider information.
pub mod provider {

    /// The ACME directory for a local pebble deployment
    #[cfg(feature = "pebble")]
    pub const PEBBLE: &str = "https://localhost:14000/dir";

    /// The ACME directory URL for Let's Encrypt.
    pub const LETSENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
}
