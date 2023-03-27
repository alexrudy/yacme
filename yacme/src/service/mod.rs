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

use arc_swap::{ArcSwap, Guard};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

use crate::protocol::{
    request::{Encode, Key},
    AcmeError, Request, Response, Result, Url,
};
use crate::schema::directory::Directory;

pub mod account;
pub mod authorization;
pub(crate) mod cache;
mod client;
pub mod order;

pub use self::account::Account;
pub use self::authorization::Authorization;
pub use self::authorization::Challenge;
pub use self::order::Order;

use self::client::Client;

#[derive(Debug)]
pub(crate) struct InnerContainer<T, S> {
    schema: ArcSwap<T>,
    url: Url,
    state: S,
}

impl<T, S> InnerContainer<T, S> {
    pub(crate) fn new(schema: T, url: Url, state: S) -> Self {
        Self {
            schema: ArcSwap::new(Arc::new(schema)),
            url,
            state,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Container<T, S> {
    inner: Arc<InnerContainer<T, S>>,
}

impl<T, S> Container<T, S>
where
    S: Default,
{
    pub(crate) fn new(item: T, url: Url) -> Self {
        Self {
            inner: Arc::new(InnerContainer::new(item, url, S::default())),
        }
    }
}

impl<T, S> Clone for Container<T, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T, S> Container<T, S> {
    #[inline]
    pub(crate) fn store(&self, item: T) {
        self.inner.schema.store(Arc::new(item))
    }

    #[inline]
    pub(crate) fn schema(&self) -> Guard<Arc<T>> {
        self.inner.schema.load()
    }

    #[inline]
    pub(crate) fn state(&self) -> &S {
        &self.inner.state
    }

    #[inline]
    pub(crate) fn url(&self) -> &Url {
        &self.inner.url
    }
}
impl<T, S> Container<T, S>
where
    T: DeserializeOwned + Encode,
{
    pub(crate) async fn refresh<K: Into<Key>>(&self, client: &Client, key: K) -> Result<()> {
        let info: Response<T> = client
            .execute(Request::get(self.url().clone(), key))
            .await?;
        self.store(info.into_inner());
        Ok(())
    }
}

/// An ACME Service Provider
///
/// Providers are identified by a directory URL, and store the
/// directory along side themselves when serialized.
#[derive(Debug, Clone)]
pub struct Provider {
    data: Arc<ProviderData>,
    client: Client,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProviderData {
    name: Option<String>,
    url: Url,
    directory: Directory,
}

impl Provider {
    /// Create a new Provider from a directory URL.
    ///
    /// The URL will be fetched, and a default client configuration
    /// will be used.
    pub async fn from_url(&self, url: Url) -> Result<Self> {
        let client = Client::default();
        let directory: Directory = client.get(url.clone()).await?.into_inner();

        let data = ProviderData {
            name: None,
            url,
            directory,
        };

        Ok(Provider {
            data: Arc::new(data),
            client,
        })
    }

    /// The name of this ACME Service provider, if specified
    pub fn name(&self) -> Option<&str> {
        self.data.name.as_deref()
    }

    /// The hostname for this ACME service provider
    pub fn host(&self) -> &str {
        self.data
            .url
            .host_str()
            .expect("ACME providers should have an https:// url with a well defined hostname")
    }

    /// The configuration directory for this ACME service provider
    pub fn directory(&self) -> &Directory {
        &self.data.directory
    }

    /// Get or create an account
    pub fn account(&self) -> self::account::AccountBuilder {
        self::account::AccountBuilder::new(self.clone())
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

    /// No directory URL was specified, and the directory was not specified..
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

        let data = ProviderData {
            name: self.name,
            url,
            directory,
        };

        Ok(Provider {
            data: Arc::new(data),
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
