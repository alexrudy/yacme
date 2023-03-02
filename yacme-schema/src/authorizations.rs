use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::challenges::Challenge;
use crate::identifier::Identifier;

/// Authorization of an ACME Account to represent a sepcific Identifier
/// for certificates.
///
///   An ACME authorization object represents a server’s authorization for
///   an account to represent an identifier.  In addition to the
///   identifier, an authorization includes several metadata fields, such
///   as the status of the authorization (e.g., "pending", "valid", or
///   "revoked") and which challenges were used to validate possession of
///   the identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    /// The identifier that the account is authorized to represent.
    pub identifier: Identifier,

    /// The status of this authorization
    pub status: AuthroizationStatus,

    /// The timestamp after which the serve will consider this authorization
    /// invalid
    #[serde(default)]
    pub expires: Option<DateTime<Utc>>,

    /// For pending authorizations, the challenges that the client can fulfill
    /// in order to prove possession of the identifier. For valid
    /// authorizations, the challenge that was validated. For invalid
    /// authorizations, the challenge that was attempted and failed.
    pub challenges: Vec<Challenge>,

    /// Indicates that this authorization corresponds to an order
    /// which requested an indentifier with a DNS wildcard.
    #[serde(skip_serializing, default)]
    pub wildcard: bool,
}

/// Status of an individual ACME authorization for an [`Identifier`]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthroizationStatus {
    /// The ACME server is waiting on the client to attempt authorization
    Pending,

    /// The ACME server is satisfied tha the client owns the [`Identifier`] in question.
    Valid,

    /// A challenge failed or encountered an error, and this authorization can't be recovered.
    Invalid,

    /// The ACME server has deactivated this authorization.
    Deactivated,

    /// The authorization is too old, and has expired.
    Expired,

    /// The authorization was revoked by the client.
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
