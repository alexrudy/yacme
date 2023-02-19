use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::challenges::Challenge;
use crate::client::Client;
use crate::identifier::Identifier;
use crate::Account;
use yacme_protocol::AcmeError;
use yacme_protocol::Url;

///
///   An ACME authorization object represents a server’s authorization for
///   an account to represent an identifier.  In addition to the
///   identifier, an authorization includes several metadata fields, such
///   as the status of the authorization (e.g., "pending", "valid", or
///   "revoked") and which challenges were used to validate possession of
///   the identifier.
#[derive(Debug, Deserialize)]
pub struct Authorization {
    pub identifier: Identifier,
    pub status: AuthroizationStatus,
    #[serde(default)]
    pub expires: Option<DateTime<Utc>>,
    pub challenges: Vec<Challenge>,
    #[serde(skip_serializing, default)]
    pub wildcard: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthroizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

impl Client {
    pub async fn authorization(
        &mut self,
        account: &Account,
        url: Url,
    ) -> Result<Authorization, AcmeError> {
        let request = reqwest::Request::new(http::Method::POST, url.into());
        let response = self.account_get(account.key_identifier(), request).await?;

        let body = response.bytes().await?;
        let auth: Authorization = serde_json::from_slice(&body).map_err(AcmeError::de)?;
        Ok(auth)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization() {
        let raw = crate::example!("authorization.json");
        let auth: Authorization = serde_json::from_str(raw).unwrap();
        assert_eq!(
            auth.identifier,
            Identifier::Dns {
                value: "www.example.org".into()
            }
        );
    }
}
