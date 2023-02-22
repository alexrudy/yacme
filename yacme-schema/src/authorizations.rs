use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::challenges::Challenge;
use crate::identifier::Identifier;

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
