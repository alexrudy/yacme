//! A high-level implementation of an ACME client
//!
//! Used for managing an acocunt and issuing certificates

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use yacme_protocol::{AcmeError, Result, Url};
use yacme_schema::directory::Directory;

pub mod account;
mod client;
pub mod order;

use crate::client::Client;

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
    pub fn account(&self) -> crate::account::AccountBuilder {
        crate::account::AccountBuilder::new(self.clone())
    }

    #[inline]
    pub(crate) fn client(&self) -> &crate::client::Client {
        &self.client
    }

    pub fn build() -> ProviderBuilder {
        ProviderBuilder::new()
    }
}

#[derive(Debug, Error)]
pub enum BuilderError {
    #[error("Building HTTPS client: {0}")]
    Client(#[source] reqwest::Error),
    #[error("Missing provider URL")]
    Url,
    #[error("Fetching provider directory: {0}")]
    Directory(#[source] AcmeError),
}

#[derive(Debug)]
pub struct ProviderBuilder {
    client: yacme_protocol::client::ClientBuilder,
    url: Option<Url>,
    directory: Option<Directory>,
    name: Option<String>,
}

impl ProviderBuilder {
    fn new() -> Self {
        ProviderBuilder {
            client: yacme_protocol::client::Client::builder(),
            url: None,
            directory: None,
            name: None,
        }
    }

    pub fn add_root_certificate(mut self, cert: reqwest::Certificate) -> Self {
        self.client = self.client.add_root_certificate(cert);
        self
    }

    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.client = self.client.timeout(timeout);
        self
    }

    pub fn connect_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.client = self.client.connect_timeout(timeout);
        self
    }

    pub fn directory_url(mut self, url: Url) -> Self {
        self.url = Some(url);
        self
    }

    pub fn directory(mut self, directory: Directory) -> Self {
        self.directory = Some(directory);
        self
    }

    pub fn name<S: Into<String>>(mut self, name: S) -> Self {
        self.name = Some(name.into());
        self
    }

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
