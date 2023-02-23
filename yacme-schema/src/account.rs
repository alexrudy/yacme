use serde::{Deserialize, Serialize};
use signature::digest::KeyInit;

use yacme_key::jwk::Jwk;
use yacme_key::PublicKey;
use yacme_key::Signature;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExternalAccountId(String);

impl From<String> for ExternalAccountId {
    fn from(value: String) -> Self {
        ExternalAccountId(value)
    }
}

impl From<&str> for ExternalAccountId {
    fn from(value: &str) -> Self {
        ExternalAccountId(value.into())
    }
}

/// The token used to bind an external account based on a Key from
/// the provider.
#[derive(Debug, Serialize)]
struct ExternalAccountToken(SignedToken<Jwk, ExternalAccountId, Signature>);

// Create alias for HMAC-SHA256
type HmacSha256 = hmac::Hmac<sha2::Sha256>;
/// Information for externally binding accounts, provided
/// by the ACME provider.
#[derive(Debug)]
pub struct ExternalAccountBindingRequest {
    pub id: ExternalAccountId,
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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub status: AccountStatus,
    #[serde(default)]
    pub contact: Vec<Url>,
    #[serde(default)]
    pub terms_of_service_agreed: Option<bool>,
    pub orders: Url,
}

impl Account {
    pub fn builder() -> AccountBuilder {
        AccountBuilder::new()
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccount {
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

    pub fn build(self, public_key: &PublicKey, url: Url) -> CreateAccount {
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

    pub fn update(self) -> CreateAccount {
        CreateAccount {
            contact: self.contact,
            terms_of_service_agreed: None,
            only_return_existing: None,
            external_account_binding: None,
        }
    }
}

#[cfg(test)]
mod test {

    use std::ops::Deref;

    use serde_json::Value;
    use yacme_protocol::jose::Nonce;

    use super::*;

    #[test]
    fn deserialize_account() {
        let raw = crate::example!("account.json");
        let account: Account = serde_json::from_str(raw).unwrap();

        assert_eq!(account.status, AccountStatus::Valid);
        assert_eq!(
            account.orders,
            "https://example.com/acme/orders/rzGoeA".parse().unwrap()
        );
    }

    #[test]
    fn new_account_request() {
        let nonce = "6S8IqOGY7eL2lsGoTZYifg";
        let key = crate::key!("ec-p255");
        let builder = crate::account::AccountBuilder::new()
            .add_contact_email("cert-admin@example.org")
            .unwrap()
            .add_contact_email("admin@example.org")
            .unwrap()
            .agree_to_terms_of_service();

        let header = ProtectedHeader::new_acme_header(
            &key,
            "https://example.com/acme/new-account".parse().unwrap(),
            Nonce::from(nonce.to_owned()),
        );
        let public = key.public_key();
        let payload = builder.build_payload(
            &public,
            "https://example.com/acme/new-account".parse().unwrap(),
        );

        let token = UnsignedToken::post(header, &payload);
        let signed_token = token.sign(key.deref()).unwrap();

        let serialized = serde_json::to_value(signed_token).unwrap();
        let expected = serde_json::from_str::<Value>(crate::example!("new-account.json")).unwrap();

        assert_eq!(
            serialized["payload"], expected["payload"],
            "payload mismatch"
        );
        assert_eq!(
            serialized["protected"], expected["protected"],
            "header mismatch"
        );
    }
}
