use std::collections::HashSet;

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
pub struct ExternalAccountToken(SignedToken<Jwk, ExternalAccountId, Signature>);

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
    pub fn token(&self, public_key: &PublicKey, url: Url) -> ExternalAccountToken {
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Contacts(HashSet<Url>);

impl Contacts {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_contact_url(&mut self, url: Url) {
        self.0.insert(url);
    }

    pub fn add_contact_email(&mut self, email: &str) -> Result<(), url::ParseError> {
        let url: Url = format!("mailto:{email}").parse()?;
        self.add_contact_url(url);
        Ok(())
    }

    pub fn clear(&mut self) {
        self.0.clear()
    }

    pub fn remove(&mut self, url: &Url) -> bool {
        self.0.remove(url)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    pub status: AccountStatus,
    #[serde(default)]
    pub contact: Contacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,
    pub orders: Url,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    Valid,
    Deactivated,
    Revoked,
}

/// Request payload for creating a new account
#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccount {
    /// List of contact URIs
    #[serde(skip_serializing_if = "Contacts::is_empty")]
    pub contact: Contacts,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<ExternalAccountToken>,
}

/// Request payload for updating an existing account
#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAccount {
    #[serde(skip_serializing_if = "Contacts::is_empty")]
    pub contact: Contacts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<ExternalAccountToken>,
}

impl UpdateAccount {
    pub fn new(contact: Contacts) -> Self {
        Self {
            contact,
            external_account_binding: None,
        }
    }
}

#[cfg(test)]
#[derive(Serialize)]
pub(super) struct CreateAccountPayload(CreateAccount);

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
        let mut contacts = Contacts::new();
        contacts
            .add_contact_email("cert-admin@example.org")
            .unwrap();
        contacts.add_contact_email("admin@example.org").unwrap();

        let header = ProtectedHeader::new_acme_header(
            &key,
            "https://example.com/acme/new-account".parse().unwrap(),
            Nonce::from(nonce.to_owned()),
        );

        let payload = CreateAccount {
            contact: contacts,
            terms_of_service_agreed: Some(true),
            only_return_existing: None,
            external_account_binding: None,
        };

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
