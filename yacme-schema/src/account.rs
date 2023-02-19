use std::fmt;
use std::sync::Arc;

use reqwest::Response;
use serde::{Deserialize, Serialize};
use signature::digest::KeyInit;

use yacme_key::jwk::Jwk;
use yacme_key::PublicKey;
use yacme_key::Signature;

use crate::client::Client;
use yacme_protocol::errors::AcmeError;
use yacme_protocol::jose::AccountKeyIdentifier;
use yacme_protocol::jose::ProtectedHeader;
use yacme_protocol::jose::SignatureAlgorithm;
use yacme_protocol::jose::SignedToken;
use yacme_protocol::jose::UnsignedToken;
use yacme_protocol::Url;

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
struct ExternalAccountToken(SignedToken<Jwk, String, Signature>);

// Create alias for HMAC-SHA256
type HmacSha256 = hmac::Hmac<sha2::Sha256>;
/// Information for externally binding accounts, provided
/// by the ACME provider.
#[derive(Debug)]
pub struct ExternalAccountBindingRequest {
    pub id: String,
    pub key: Key,
}

impl ExternalAccountBindingRequest {
    fn token(&self, public_key: &PublicKey, url: Url) -> ExternalAccountToken {
        let token = UnsignedToken::post(
            ProtectedHeader::new(
                SignatureAlgorithm::HS256,
                Some(self.id.clone()),
                None,
                url,
                None,
            ),
            public_key.to_jwk(),
        );

        let mac =
            HmacSha256::new_from_slice(self.key.as_ref()).expect("HMAC can take key of any size");

        ExternalAccountToken(token.digest(mac).unwrap())
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

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateAccount {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    contact: Vec<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    terms_of_service_agreed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    only_return_existing: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_account_binding: Option<ExternalAccountToken>,
}

#[cfg(test)]
#[derive(Serialize)]
pub(super) struct CreateAccountPayload(CreateAccount);

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

    pub fn add_contact_email(self, email: &str) -> Result<Self, url::ParseError> {
        let url: Url = format!("mailto:{email}").parse()?;
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

    #[cfg(test)]
    pub(super) fn build_payload(self, public_key: &PublicKey, url: Url) -> CreateAccountPayload {
        CreateAccountPayload(self.build(public_key, url))
    }

    fn update(self) -> CreateAccount {
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
        let request = reqwest::Request::new(
            http::Method::POST,
            self.directory.new_account.clone().into(),
        );
        let key = self.public_key();
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
        let request =
            reqwest::Request::new(http::Method::POST, account.key_identifier.to_url().into());

        let response = self
            .account_post(&account.key_identifier, request, &updates.update())
            .await?;

        let account_key = self.process_account_key_id(&response);
        let account = response.json().await.expect("valid JSON response");
        Ok(Account::new(account_key, self.key().clone(), account))
    }
}

pub struct Account {
    key_identifier: AccountKeyIdentifier,
    key: Arc<yacme_key::SigningKey>,
    account: AccountInfo,
}

impl fmt::Debug for Account {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Account")
            .field("url", &self.key_identifier.to_url())
            .field("status", &self.account.status)
            .field("contact", &self.account.contact)
            .field(
                "terms_of_service_agreed",
                &self.account.terms_of_service_agreed,
            )
            .field("orders", &self.account.orders)
            .finish()
    }
}

impl Account {
    fn new(
        key_identifier: AccountKeyIdentifier,
        key: Arc<yacme_key::SigningKey>,
        account: AccountInfo,
    ) -> Self {
        Self {
            key_identifier,
            key,
            account,
        }
    }

    pub fn builder() -> AccountBuilder {
        AccountBuilder::new()
    }

    pub fn info(&self) -> &AccountInfo {
        &self.account
    }

    pub(super) fn key_identifier(&self) -> &AccountKeyIdentifier {
        &self.key_identifier
    }

    pub(super) fn key(&self) -> &yacme_key::SigningKey {
        &self.key
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn deserialize_account() {
        let raw = crate::example!("account.json");
        let account: AccountInfo = serde_json::from_str(raw).unwrap();

        assert_eq!(account.status, AccountStatus::Valid);
        assert_eq!(
            account.orders,
            "https://example.com/acme/orders/rzGoeA".parse().unwrap()
        );
    }
}
