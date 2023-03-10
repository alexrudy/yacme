//! An ACME service provider account
//!
use std::sync::Arc;

use arc_swap::Guard;

use yacme_key::SigningKey;
use yacme_protocol::{request::Key, AcmeError, Request, Response, Url};
use yacme_schema::{
    account::Account as AccountSchema,
    account::{Contacts, CreateAccount, ExternalAccountBindingRequest},
    directory::Directory,
};

use crate::{
    cache::Cache,
    order::{Order, OrderBuilder, OrderState},
    Container, Provider,
};

type AccountState = Cache<Order, OrderState>;

#[derive(Debug, Clone)]
pub struct Account {
    provider: Provider,
    key: Arc<yacme_key::SigningKey>,
    data: Container<AccountSchema, AccountState>,
}

impl Account {
    fn new(
        provider: Provider,
        key: Arc<yacme_key::SigningKey>,
        info: yacme_schema::Account,
        url: Url,
    ) -> Self {
        Self {
            provider,
            key,
            data: Container::new(info, url),
        }
    }

    #[inline]
    pub(crate) fn client(&self) -> &crate::client::Client {
        self.provider.client()
    }

    #[inline]
    pub(crate) fn directory(&self) -> &Directory {
        self.provider.directory()
    }

    /// Refresh this account's data from the ACME service
    pub async fn refresh(&self) -> Result<(), AcmeError> {
        self.data.refresh(self.client(), self.request_key()).await
    }

    pub async fn update(&self) -> UpdateAccount {
        UpdateAccount::new(self.clone())
    }

    /// The raw [`yacme_schema::Account`] associated with this account
    pub fn schema(&self) -> Guard<Arc<yacme_schema::Account>> {
        self.data.schema()
    }

    /// Signing key which identifies this account
    pub fn key(&self) -> Arc<yacme_key::SigningKey> {
        self.key.clone()
    }

    /// Identifying URL for this account
    pub fn url(&self) -> &Url {
        self.data.url()
    }

    /// Key used for signing requests, including identifier
    pub(crate) fn request_key(&self) -> impl Into<Key> {
        (self.key(), self.data.url().clone())
    }

    /// Create a new order for a certificate
    pub fn order(&self) -> OrderBuilder {
        OrderBuilder::new(self.clone())
    }

    /// Get a list of orders associated with this account
    pub async fn orders(&self, limit: Option<usize>) -> Result<Vec<Order>, AcmeError> {
        let orders = crate::order::list(self, limit).await?;

        let mut cache = self.cache().inner();

        for order in &orders {
            cache.insert(order.clone());
        }

        Ok(orders)
    }

    pub(crate) fn cache(&self) -> &Cache<Order, OrderState> {
        self.data.state()
    }
}

pub struct AccountBuilder {
    contact: Contacts,
    terms_of_service_agreed: Option<bool>,
    only_return_existing: Option<bool>,
    external_account_binding: Option<ExternalAccountBindingRequest>,
    key: Option<Arc<SigningKey>>,
    provider: Provider,
}

impl AccountBuilder {
    pub(crate) fn new(provider: Provider) -> Self {
        AccountBuilder {
            contact: Default::default(),
            terms_of_service_agreed: None,
            only_return_existing: None,
            external_account_binding: None,
            key: None,
            provider,
        }
    }

    pub fn external_account(mut self, binding: ExternalAccountBindingRequest) -> AccountBuilder {
        self.external_account_binding = Some(binding);
        self
    }

    pub fn agree_to_terms_of_service(mut self) -> Self {
        self.terms_of_service_agreed = Some(true);
        self
    }

    pub fn add_contact_url(mut self, url: Url) -> Self {
        self.contact.add_contact_url(url);
        self
    }

    pub fn must_exist(mut self) -> Self {
        self.only_return_existing = Some(true);
        self
    }

    pub fn add_contact_email(mut self, email: &str) -> Result<Self, url::ParseError> {
        self.contact.add_contact_email(email)?;
        Ok(self)
    }

    pub fn key(mut self, key: Arc<SigningKey>) -> Self {
        self.key = Some(key);
        self
    }

    pub async fn create(self) -> Result<Account, AcmeError> {
        let url = self.provider.directory().new_account.clone();
        let key = self.key.ok_or(AcmeError::MissingKey("account"))?;
        let public_key = key.public_key();
        let payload = CreateAccount {
            contact: self.contact,
            terms_of_service_agreed: self.terms_of_service_agreed,
            only_return_existing: self.only_return_existing,
            external_account_binding: self
                .external_account_binding
                .map(|binding| binding.token(&public_key, url.clone())),
        };

        let account: Response<yacme_schema::Account> = self
            .provider
            .client()
            .execute(Request::post(payload, url, key.clone()))
            .await?;

        let account_url = account
            .location()
            .ok_or_else(|| AcmeError::MissingData("account id URL"))?;

        Ok(Account::new(
            self.provider,
            key,
            account.into_inner(),
            account_url,
        ))
    }

    pub async fn get(mut self) -> Result<Account, AcmeError> {
        self.only_return_existing = Some(true);
        self.create().await
    }
}

#[derive(Debug)]
pub struct UpdateAccount {
    contact: Contacts,
    account: Account,
}

impl UpdateAccount {
    fn new(account: Account) -> Self {
        UpdateAccount {
            contact: account.schema().contact.clone(),
            account,
        }
    }

    pub fn contacts(&mut self) -> &mut Contacts {
        &mut self.contact
    }

    pub async fn update(self) -> Result<(), AcmeError> {
        let url = self.account.url().clone();
        let key = self.account.key.clone();
        let request = yacme_schema::account::UpdateAccount::new(self.contact);

        let account: Response<yacme_schema::Account> = self
            .account
            .client()
            .execute(Request::post(request, url, key))
            .await?;

        self.account.data.store(account.into_inner());
        Ok(())
    }
}
