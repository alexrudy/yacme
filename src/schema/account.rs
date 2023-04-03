//! # Account creation and management
//!
//! Accounts are identified by their signing key for ACME.
//!
//! They can also be bound to an external accounts.

use std::collections::HashSet;

use serde::{ser, Deserialize, Serialize};

use crate::protocol::Url;

pub mod external {
    //! External account binding to connect provider accounts to ACME accounts.

    use serde::{Deserialize, Serialize};
    use signature::digest::KeyInit;

    use crate::key::jwk::Jwk;
    use crate::key::PublicKey;
    use crate::key::Signature;

    use crate::protocol::jose::ProtectedHeader;
    use crate::protocol::jose::SignatureAlgorithm;
    use crate::protocol::jose::SignedToken;
    use crate::protocol::jose::UnsignedToken;
    use crate::protocol::Base64Data;
    use crate::protocol::Url;

    /// Account key for externally binding accounts, provided by the ACME
    /// provider.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(from = "Base64Data<Key>", into = "Base64Data<Key>")]
    pub struct Key(Vec<u8>);

    impl AsRef<[u8]> for Key {
        fn as_ref(&self) -> &[u8] {
            self.0.as_slice()
        }
    }

    impl From<Base64Data<Key>> for Key {
        fn from(value: Base64Data<Key>) -> Self {
            value.0
        }
    }

    impl TryFrom<&[u8]> for Key {
        type Error = ();

        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            Ok(Key(value.into()))
        }
    }

    /// Identifier provided by an ACME service provider.
    ///
    /// which is used to bind this account to an account created elsewhere
    /// (e.g. on the provider's website).
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Information for externally binding accounts, provided by the ACME provider.
    ///
    /// This is the raw form - the fields and data provided by the ACME provider.
    /// To use this to authenticate and bind an account, you have to send a signed
    /// JWT token to the ACME provider. See [`ExternalAccountBindingRequest::token`]
    /// which can create that signed JWT.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ExternalAccountBindingRequest {
        /// The idnetifier provided by the ACME provider for the external account.
        pub id: ExternalAccountId,
        /// The key provided by the ACME provider used to sign the binding request.
        pub key: Key,
    }

    impl ExternalAccountBindingRequest {
        /// Create new external account binding request.
        pub fn new(id: ExternalAccountId, key: Key) -> Self {
            Self { id, key }
        }

        /// Create a JWT token signed in a way to bind to the key associated with an ACME
        /// account.
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

            let mac = HmacSha256::new_from_slice(self.key.as_ref())
                .expect("HMAC can take key of any size");

            ExternalAccountToken(token.digest(mac).unwrap())
        }
    }

    #[cfg(test)]
    mod test {
        use std::str::FromStr;

        use super::*;

        #[test]
        fn serde_external_account_binding() {
            let key = Key::try_from(&b"12345678901234567890123456789012"[..]).unwrap();
            let id = ExternalAccountId::from("12345678901234567890123456789012");
            let request = ExternalAccountBindingRequest { id, key };
            let serialized = serde_json::to_string(&request).unwrap();
            let deserialized: ExternalAccountBindingRequest =
                serde_json::from_str(&serialized).unwrap();
            assert_eq!(request, deserialized);
        }

        #[test]
        fn external_account_token() {
            let key = Key::try_from(&b"12345678901234567890123456789012"[..]).unwrap();
            let id = ExternalAccountId::from("12345678901234567890123456789012");
            let request = ExternalAccountBindingRequest { id, key };

            let account_key = crate::key!("ec-p255");
            let public_key = account_key.public_key();
            let url = Url::from_str("https://example.com").unwrap();
            let token = request.token(&public_key, url);
            let serialized = serde_json::to_value(&token).unwrap();

            let expected =
                serde_json::from_str::<serde_json::Value>(crate::example!("external-binding.json"))
                    .unwrap();

            assert_eq!(serialized, expected);
        }
    }
}

pub use external::*;

/// A set of contact addresses to assosciate with an account.
///
/// These should be considered lexographically ordered.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Contacts(HashSet<Url>);

impl Contacts {
    /// Create a new, empty set of contacts.
    pub fn new() -> Self {
        Default::default()
    }

    /// Add a url for contact.
    pub fn add_contact_url(&mut self, url: Url) {
        self.0.insert(url);
    }

    /// Add an email address (as a mailto: url) for contact.
    pub fn add_contact_email(&mut self, email: &str) -> Result<(), url::ParseError> {
        let url: Url = format!("mailto:{email}").parse()?;
        self.add_contact_url(url);
        Ok(())
    }

    /// Clear the contacts.
    pub fn clear(&mut self) {
        self.0.clear()
    }

    /// Remove a contact url.
    pub fn remove(&mut self, url: &Url) -> bool {
        self.0.remove(url)
    }

    /// Number of contacts in this datastructrue.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Is this set of contacts empty?
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate through the contact URLs in this set.
    pub fn iter(&self) -> impl Iterator<Item = &Url> {
        self.0.iter()
    }
}

impl ser::Serialize for Contacts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut contacts = self.0.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        contacts.sort();
        let mut seq = serializer.serialize_seq(Some(contacts.len()))?;
        for contact in contacts {
            seq.serialize_element(&contact)?;
        }
        seq.end()
    }
}

/// Account information provided by an ACME service provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// The status of the account - valid, deactivated, or revoked.
    pub status: AccountStatus,

    /// A list of contact URIs for this account.
    #[serde(default)]
    pub contact: Contacts,

    /// If the terms of service were agreed to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,

    /// The url to fetch a list of orders from the ACME provider.
    #[serde(default)]
    pub orders: Option<Url>,
}

/// # Account Status
///
/// From RFC 8885:
///
///  Account objects are created in the "valid" state, since no further
///    action is required to create an account after a successful newAccount
///    request.  If the account is deactivated by the client or revoked by
///    the server, it moves to the corresponding state.
///
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatus {
    /// Account objects are created in the valid state.
    Valid,

    /// Accounts can be deactivated by the client.
    Deactivated,

    /// The server has revoked the account.
    Revoked,
}

/// Request payload for creating a new account
#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccount {
    /// List of contact URIs
    #[serde(skip_serializing_if = "Contacts::is_empty")]
    pub contact: Contacts,

    /// Has the user agreed to the terms of service?
    ///
    /// This field should only be set to `true` if the user has actually had to
    /// take some action to agree to the terms of service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service_agreed: Option<bool>,

    /// Ask the ACME provider to only return an account if it already exists,
    /// don't create a new one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_return_existing: Option<bool>,

    /// External account binding information - used to associate an ACME account
    /// with an account established elsewhere with the ACME provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<ExternalAccountToken>,
}

/// Request payload for updating an existing account
#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAccount {
    /// Replace the list of accounts on this account.
    #[serde(skip_serializing_if = "Contacts::is_empty")]
    pub contact: Contacts,

    /// Add a new external account binding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<ExternalAccountToken>,
}

impl UpdateAccount {
    /// Create a new acccount update request
    pub fn new(contact: Contacts) -> Self {
        Self {
            contact,
            external_account_binding: None,
        }
    }
}

#[cfg(test)]
mod test {

    use std::ops::Deref;

    use crate::protocol::jose::ProtectedHeader;
    use crate::protocol::jose::UnsignedToken;
    use crate::protocol::{fmt::AcmeFormat, jose::Nonce};
    use serde_json::Value;

    use super::*;

    #[test]
    fn deserialize_account() {
        let raw = crate::example!("account.json");
        let account: Account = serde_json::from_str(raw).unwrap();

        assert_eq!(account.status, AccountStatus::Valid);
        assert_eq!(
            account.orders,
            "https://example.com/acme/orders/rzGoeA".parse().ok()
        );
    }

    #[test]
    fn deserialize_account_le() {
        let raw = crate::example!("account-le-style.json");
        let account: Account = serde_json::from_str(raw).unwrap();

        assert_eq!(account.status, AccountStatus::Valid);
        assert_eq!(account.orders, None);
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

        eprintln!("{}", signed_token.formatted());
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
