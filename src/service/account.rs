//! An ACME service provider account
//!
use std::sync::Arc;

use jaws::key::SerializeJWK;

use crate::protocol::{request::Key, AcmeError, Request, Response, Url};
use crate::schema::{
    self,
    account::{Contacts, CreateAccount, ExternalAccountBindingRequest},
    directory::Directory,
};
use signature::Keypair;

use super::{
    order::{Order, OrderBuilder},
    Provider,
};

/// An account with an ACME provider
///
/// Accounts are identified by their signing key.
#[derive(Debug)]
pub struct Account<K> {
    provider: Provider,
    key: Arc<K>,
    data: schema::Account,
    url: Url,
}

impl<K> Account<K>
where
    K: Clone,
{
    fn new(provider: Provider, key: Arc<K>, data: schema::Account, url: Url) -> Self {
        Self {
            provider,
            key,
            data,
            url,
        }
    }

    #[inline]
    pub(crate) fn client(&self) -> &super::client::Client {
        self.provider.client()
    }

    #[inline]
    pub(crate) fn directory(&self) -> &Directory {
        self.provider.directory()
    }

    /// Refresh this account's data from the ACME service
    pub async fn refresh(&mut self) -> Result<(), AcmeError>
    where
        K: jaws::algorithms::TokenSigner + jaws::key::SerializeJWK + Clone,
    {
        let response: Response<schema::Account> = self
            .client()
            .execute(Request::get(self.url().clone(), self.request_key()))
            .await?;

        self.data = response.into_inner();
        Ok(())
    }

    /// Create an update request for an account.
    ///
    /// Update requests are built using the [`UpdateAccount`] builder.
    pub fn update(&mut self) -> UpdateAccount<K> {
        UpdateAccount::new(self)
    }

    /// The raw [`crate::schema::Account`] associated with this account
    pub fn data(&self) -> &schema::Account {
        &self.data
    }

    /// Signing key which identifies this account
    pub fn key(&self) -> Arc<K> {
        self.key.clone()
    }

    /// Identifying URL for this account
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// Key used for signing requests, including identifier
    pub(crate) fn request_key(&self) -> impl Into<Key<K>> {
        (self.key(), self.url.clone())
    }

    /// Create a new order for a certificate
    pub fn order(&self) -> OrderBuilder<K> {
        OrderBuilder::new(self)
    }

    /// Get a list of orders associated with this account
    pub async fn orders(&self, limit: Option<usize>) -> Result<Vec<Order<K>>, AcmeError>
    where
        K: jaws::algorithms::TokenSigner + jaws::key::SerializeJWK + Clone,
    {
        let orders = super::order::list(self, limit).await?;

        Ok(orders)
    }
}

/// Manage a request for a new or existing ACME account
/// from an ACME provider.
pub struct AccountBuilder<K> {
    contact: Contacts,
    terms_of_service_agreed: Option<bool>,
    only_return_existing: Option<bool>,
    external_account_binding: Option<ExternalAccountBindingRequest>,
    key: Arc<K>,
    provider: Provider,
}

impl<K> AccountBuilder<K>
where
    K: Clone,
{
    pub(crate) fn new(provider: Provider, key: Arc<K>) -> Self {
        AccountBuilder {
            contact: Default::default(),
            terms_of_service_agreed: None,
            only_return_existing: None,
            external_account_binding: None,
            key,
            provider,
        }
    }

    /// Bind this ACME account to an external account with some identifier.
    ///
    /// This allows accounts created with an ACME provider via their website to be linked
    /// to the automated accounts created during the ACME protocol.
    pub fn external_account(mut self, binding: ExternalAccountBindingRequest) -> AccountBuilder<K> {
        self.external_account_binding = Some(binding);
        self
    }

    /// Tell the provider that the user has taken action to agree to the terms of service.
    pub fn agree_to_terms_of_service(mut self) -> Self {
        self.terms_of_service_agreed = Some(true);
        self
    }

    /// Add a new contact url to the account.
    pub fn add_contact_url(mut self, url: Url) -> Self {
        self.contact.add_contact_url(url);
        self
    }

    /// Add a contact email address to the account, which will be converted to a mailto: URL.
    pub fn add_contact_email(
        mut self,
        email: &str,
    ) -> Result<Self, <reqwest::Url as std::str::FromStr>::Err> {
        self.contact.add_contact_email(email)?;
        Ok(self)
    }

    /// Require that the account already exists.
    pub fn must_exist(mut self) -> Self {
        self.only_return_existing = Some(true);
        self
    }

    /// Create a new account with the ACME provider.
    ///
    /// The request is sent as a [`CreateAccount`].
    /// If [`AccountBuilder::must_exist`] is set, this method acts like [`AccountBuilder::get`].
    pub async fn create(self) -> Result<Account<K>, AcmeError>
    where
        K: Keypair,
        K::VerifyingKey: SerializeJWK,
        K: jaws::algorithms::TokenSigner + jaws::key::SerializeJWK + Clone,
    {
        let url = self.provider.directory().new_account.clone();
        let public_key = self.key.verifying_key();
        let payload = CreateAccount {
            contact: self.contact,
            terms_of_service_agreed: self.terms_of_service_agreed,
            only_return_existing: self.only_return_existing,
            external_account_binding: self
                .external_account_binding
                .map(|binding| binding.token(&public_key, url.clone())),
        };

        let account: Response<crate::schema::Account> = self
            .provider
            .client()
            .execute(Request::post(payload, url, self.key.clone()))
            .await?;

        let account_url = account
            .location()
            .ok_or_else(|| AcmeError::MissingData("account id URL"))?;

        Ok(Account::new(
            self.provider,
            self.key,
            account.into_inner(),
            account_url,
        ))
    }

    /// Get an existing account.
    ///
    /// Uses `only_return_existing`, overriding the value set by [`AccountBuilder::must_exist`].
    pub async fn get(mut self) -> Result<Account<K>, AcmeError>
    where
        K: Keypair,
        K::VerifyingKey: SerializeJWK,
        K: jaws::algorithms::TokenSigner + jaws::key::SerializeJWK + Clone,
    {
        self.only_return_existing = Some(true);
        self.create().await
    }
}

/// Update the contacts associated with an account
#[derive(Debug)]
pub struct UpdateAccount<'a, K> {
    contact: Contacts,
    account: &'a mut Account<K>,
}

impl<'a, K> UpdateAccount<'a, K>
where
    K: Clone,
{
    fn new(account: &'a mut Account<K>) -> Self {
        UpdateAccount {
            contact: account.data().contact.clone(),
            account,
        }
    }

    /// A mutable reference to the contacts associated with this account, which can be
    /// edited before calling [`UpdateAccount::update`].
    pub fn contacts(&mut self) -> &mut Contacts {
        &mut self.contact
    }

    /// Update account information with the ACME provider.
    pub async fn update(self) -> Result<(), AcmeError>
    where
        K: jaws::algorithms::TokenSigner + jaws::key::SerializeJWK + Clone,
    {
        let url = self.account.url().clone();
        let key = self.account.key.clone();
        let request = crate::schema::account::UpdateAccount::new(self.contact);

        let account: Response<crate::schema::Account> = self
            .account
            .client()
            .execute(Request::post(request, url, key))
            .await?;

        let account_url = account
            .location()
            .ok_or_else(|| AcmeError::MissingData("account id URL"))?;

        assert_eq!(account_url, self.account.url);

        self.account.data = account.into_inner();
        Ok(())
    }
}
