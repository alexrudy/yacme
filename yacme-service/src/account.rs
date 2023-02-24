//! An ACME service provider account
//!
use std::sync::Arc;

use arc_swap::ArcSwap;

use yacme_key::SigningKey;
use yacme_protocol::{AcmeError, Request, Response, Url};
use yacme_schema::account::{Contacts, ExternalAccountBindingRequest};

use crate::Provider;

#[derive(Debug, Clone)]
pub struct Account {
    provider: Provider,
    key: Arc<yacme_key::SigningKey>,
    data: Arc<AccountData>,
}

impl Account {
    fn new(
        provider: Provider,
        key: Arc<yacme_key::SigningKey>,
        info: yacme_schema::Account,
        url: Url,
    ) -> Self {
        let data = AccountData {
            info: ArcSwap::new(Arc::new(info)),
            url,
        };

        Self {
            provider,
            key,
            data: Arc::new(data),
        }
    }

    #[inline]
    pub(crate) fn client(&self) -> &crate::client::Client {
        self.provider.client()
    }

    pub async fn refresh(&self) -> Result<(), AcmeError> {
        let info: Response<yacme_schema::Account> = self
            .client()
            .execute(Request::get(self.data.url.clone(), self.key.clone()))
            .await?;

        self.data.info.store(Arc::new(info.into_inner()));

        Ok(())
    }

    pub async fn update(&self) -> UpdateAccount {
        UpdateAccount::new(self.clone())
    }

    pub fn info(&self) -> Arc<yacme_schema::Account> {
        self.data.info.load_full()
    }
}

#[derive(Debug)]
struct AccountData {
    info: ArcSwap<yacme_schema::Account>,
    url: Url,
}

pub struct AccountBuilder {
    inner: yacme_schema::account::AccountBuilder,
    key: Option<Arc<SigningKey>>,
    provider: Provider,
}

impl AccountBuilder {
    pub(crate) fn new(provider: Provider) -> Self {
        AccountBuilder {
            inner: yacme_schema::Account::builder(),
            key: None,
            provider,
        }
    }

    pub fn external_account(mut self, binding: ExternalAccountBindingRequest) -> AccountBuilder {
        self.inner = self.inner.external_account(binding);
        self
    }

    pub fn agree_to_terms_of_service(mut self) -> Self {
        self.inner = self.inner.agree_to_terms_of_service();
        self
    }

    pub fn add_contact_url(mut self, url: Url) -> Self {
        self.inner = self.inner.add_contact_url(url);
        self
    }

    pub fn must_exist(mut self) -> Self {
        self.inner = self.inner.must_exist();
        self
    }

    pub fn add_contact_email(self, email: &str) -> Result<Self, url::ParseError> {
        let url: Url = format!("mailto:{email}").parse()?;
        Ok(self.add_contact_url(url))
    }

    pub fn key(mut self, key: Arc<SigningKey>) -> Self {
        self.key = Some(key);
        self
    }

    pub async fn create(self) -> Result<Account, AcmeError> {
        let url = self.provider.directory().new_account.clone();
        let key = self.key.ok_or(AcmeError::MissingKey)?;
        let public_key = key.public_key();
        let request = self.inner.build(&public_key, url.clone());

        let account: Response<yacme_schema::Account> = self
            .provider
            .client()
            .execute(Request::post(request, url, key.clone()))
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
        self.inner = self.inner.must_exist();
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
            contact: account.info().contact.clone(),
            account,
        }
    }

    pub fn contacts(&mut self) -> &mut Contacts {
        &mut self.contact
    }

    pub async fn update(self) -> Result<(), AcmeError> {
        let url = self.account.data.url.clone();
        let key = self.account.key.clone();
        let request = yacme_schema::account::UpdateAccount::new(self.contact);

        let account: Response<yacme_schema::Account> = self
            .account
            .client()
            .execute(Request::post(request, url, key))
            .await?;

        self.account.data.info.store(Arc::new(account.into_inner()));
        Ok(())
    }
}
