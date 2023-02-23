use serde::{Deserialize, Serialize};
use yacme_protocol::Url;

/// Directories are the single source required to configure an ACME client
/// for use with a specific provider. They can be fetched as JSON from an
/// advertised directory URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    /// URL used to fetch a new Nonce via a HEAD request
    pub new_nonce: Url,

    /// URL to create a new account
    pub new_account: Url,

    /// URL to create a new certificate order
    pub new_order: Url,

    /// (optional) URL to start a new pre-authorization
    #[serde(default)]
    pub new_authz: Option<Url>,

    /// URL to revoke an existing certificate
    pub revoke_cert: Url,

    /// URL to change the account signing key
    pub key_change: Url,

    /// Additional metadata
    #[serde(default)]
    pub meta: Option<Metadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    /// A URL to find and display terms of service for the ACME server
    #[serde(default)]
    pub terms_of_service: Option<Url>,

    /// A URL for the default website of the ACME server
    #[serde(default)]
    pub website: Option<Url>,

    /// The hostnames that the ACME server recognizes as referring to itself for the purposes of
    /// CAA record validation as defined in [RFC6844](https://www.rfc-editor.org/rfc/rfc6844).
    /// Each string represents the same sequence of ASCII code points that the server
    /// will expect to see as the "Issuer Domain Name" in a CAA issue or
    /// issuewild property tag.  This allows clients to determine the
    /// correct issuer domain name to use when configuring CAA records.
    #[serde(default)]
    pub caa_identities: Vec<String>,

    /// Whether an external account registration is required to register with this provider.
    #[serde(default)]
    pub external_account_required: Option<bool>,
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::response;

    #[test]
    fn deserialize_directory() {
        let response = response!("directory.http");

        let directory: Directory = serde_json::from_str(response.body()).unwrap();
        assert_eq!(
            directory.new_account,
            "https://example.com/acme/new-account".parse().unwrap()
        );
        assert_eq!(
            directory.meta.unwrap().website,
            Some("https://www.example.com/".parse().unwrap())
        )
    }
}
