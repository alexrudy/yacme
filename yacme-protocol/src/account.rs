use std::convert::Infallible;
use std::sync::Arc;

use reqwest::{Response, Url};
use ring::hmac::Tag;
use ring::signature::EcdsaKeyPair;
use serde::{Deserialize, Serialize};

use super::errors::AcmeError;
use super::key::SignatureAlgorithm;
use super::transport::AccountKeyIdentifier;
use super::transport::Base64DataRef;
use super::transport::Client;
use super::transport::ProtectedHeader;
use super::transport::SignedToken;
use super::transport::UnsignedToken;
use super::PublicKey;

/// Account key for externally binding accounts, provided by the ACME
/// provider.
#[derive(Debug)]
pub struct Key(Vec<u8>);

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[derive(Serialize)]
struct ExternalAccountToken<'k>(SignedToken<'k, Base64DataRef<'k, PublicKey>, String, Key, Tag>);

/// Information for externally binding accounts, provided
/// by the ACME provider.
#[derive(Debug)]
pub struct ExternalAccountBindingRequest {
    pub id: String,
    pub key: Key,
}

impl ExternalAccountBindingRequest {
    fn token<'k>(&'_ self, public_key: &'k PublicKey, url: Url) -> ExternalAccountToken<'k> {
        let token = UnsignedToken::post(
            ProtectedHeader::new(
                SignatureAlgorithm::HS256,
                Some(self.id.clone().into()),
                None,
                url,
                None,
            ),
            public_key.into(),
        );

        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, self.key.as_ref());

        ExternalAccountToken(
            token
                .sign(|message| Ok::<_, Infallible>(ring::hmac::sign(&key, message)))
                .unwrap(),
        )
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountInfo {
    pub status: AccountStatus,
    #[serde(default)]
    pub contact: Vec<Url>,
    #[serde(default)]
    pub terms_of_service_agreed: Option<bool>,
    pub orders: Url,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateAccount<'k> {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    contact: Vec<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    terms_of_service_agreed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    only_return_existing: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_account_binding: Option<ExternalAccountToken<'k>>,
}

#[derive(Debug, Default)]
pub struct AccountBuilder {
    contact: Vec<Url>,
    terms_of_service_agreed: Option<bool>,
    only_return_existing: Option<bool>,
    external_account_binding: Option<ExternalAccountBindingRequest>,
}

impl AccountBuilder {
    pub fn new() -> Self {
        AccountBuilder {
            contact: Vec::new(),
            terms_of_service_agreed: None,
            only_return_existing: None,
            external_account_binding: None,
        }
    }

    pub fn external_account(self, binding: ExternalAccountBindingRequest) -> AccountBuilder {
        AccountBuilder {
            contact: self.contact,
            terms_of_service_agreed: self.terms_of_service_agreed,
            only_return_existing: self.only_return_existing,
            external_account_binding: Some(binding),
        }
    }

    pub fn agree_to_terms_of_service(mut self) -> Self {
        self.terms_of_service_agreed = Some(true);
        self
    }

    pub fn add_contact_url(mut self, url: Url) -> Self {
        self.contact.push(url);
        self
    }

    pub fn must_exist(mut self) -> Self {
        self.only_return_existing = Some(true);
        self
    }

    pub fn add_contact_email(self, email: String) -> Result<Self, ()> {
        let url: Url = format!("mailto:{email}").parse().unwrap();
        Ok(self.add_contact_url(url))
    }

    fn build(self, public_key: &PublicKey, url: Url) -> CreateAccount {
        CreateAccount {
            contact: self.contact,
            terms_of_service_agreed: self.terms_of_service_agreed,
            only_return_existing: self.only_return_existing,
            external_account_binding: self
                .external_account_binding
                .map(|e| e.token(public_key, url)),
        }
    }

    fn update<'c>(self) -> CreateAccount<'c> {
        CreateAccount {
            contact: self.contact,
            terms_of_service_agreed: None,
            only_return_existing: None,
            external_account_binding: None,
        }
    }
}

impl Client {
    fn process_account_key_id(&mut self, response: &Response) -> AccountKeyIdentifier {
        let account_url: Url = response
            .headers()
            .get(http::header::LOCATION)
            .expect("account location header")
            .to_str()
            .expect("account location header is valid utf8")
            .parse()
            .expect("location header is URL");

        account_url.into()
    }

    pub async fn create_account(&mut self, account: AccountBuilder) -> Result<Account, AcmeError> {
        let request = reqwest::Request::new(http::Method::POST, self.directory.new_account.clone());
        let key = *self.public_key();
        let payload = account.build(&key, self.directory.new_account.clone());
        let response = self.key_post(request, &payload).await?;
        let account_key = self.process_account_key_id(&response);
        let account = response.json().await.expect("valid JSON response");

        Ok(Account::new(account_key, self.key().clone(), account))
    }

    pub async fn update_account(
        &mut self,
        account: &Account,
        updates: AccountBuilder,
    ) -> Result<Account, AcmeError> {
        let request = reqwest::Request::new(http::Method::POST, account.key_identifier.to_url());

        let response = self
            .account_post(&account.key_identifier, request, &updates.update())
            .await?;

        let account_key = self.process_account_key_id(&response);
        let account = response.json().await.expect("valid JSON response");
        Ok(Account::new(account_key, self.key().clone(), account))
    }
}

#[derive(Debug)]
pub struct Account {
    key_identifier: AccountKeyIdentifier,
    key: Arc<EcdsaKeyPair>,
    account: AccountInfo,
}

impl Account {
    fn new(
        key_identifier: AccountKeyIdentifier,
        key: Arc<EcdsaKeyPair>,
        account: AccountInfo,
    ) -> Self {
        Self {
            key_identifier,
            key,
            account,
        }
    }

    pub fn info(&self) -> &AccountInfo {
        &self.account
    }

    pub(super) fn key_identifier(&self) -> &AccountKeyIdentifier {
        &self.key_identifier
    }

    pub(super) fn key(&self) -> &EcdsaKeyPair {
        &self.key
    }
}
