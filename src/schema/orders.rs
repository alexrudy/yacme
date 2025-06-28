//! # Certificate orders
//!
//! Each order corresponds to a single request for a certificate chain, but may
//! include multiple identifiers.  The order is created by the client, and then validated
//! using the authorizations and challenges.

use crate::cert::SignedCertificateRequest;
use crate::protocol::Base64Data;
use chrono::{DateTime, Utc};
use der::Decode;
use der::EncodePem;
use pem_rfc7468::PemLabel;
use serde::{Deserialize, Serialize};
use signature::Keypair;
use x509_cert::spki::DynSignatureAlgorithmIdentifier;

use super::identifier::Identifier;
use crate::protocol::errors::AcmeError;
use crate::protocol::errors::AcmeErrorDocument;
use crate::protocol::Url;

const PEM_DOCUMENT_BEGIN: &str = "-----BEGIN";

/// The response from an ACME server when listing all orders known to the server for this account.
#[derive(Debug, Serialize, Deserialize)]
pub struct Orders {
    /// The list of orders.
    pub orders: Vec<Url>,

    /// The next page of orders, if any.
    #[serde(default)]
    pub next: Option<Url>,
}

/// An ACME order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    status: OrderStatus,
    expires: Option<DateTime<Utc>>,
    identifiers: Vec<Identifier>,
    #[cfg(feature = "acme-profiles")]
    profile: Option<String>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
    error: Option<AcmeErrorDocument>,
    authorizations: Vec<Url>,
    finalize: Url,
    certificate: Option<Url>,
}

impl Order {
    /// The status of the order.
    pub fn status(&self) -> &OrderStatus {
        &self.status
    }

    /// The time at which the order expires, and the provider will
    /// no longer consider it valid.
    pub fn expires(&self) -> Option<DateTime<Utc>> {
        self.expires
    }

    /// The identifiers which apply to this order.
    pub fn identifiers(&self) -> &[Identifier] {
        self.identifiers.as_ref()
    }

    #[cfg(feature = "acme-profiles")]
    /// Name of the selected certificate profile in use.
    pub fn profile(&self) -> Option<&str> {
        self.profile.as_deref()
    }

    /// The configured start time for the certificate.
    pub fn not_before(&self) -> Option<DateTime<Utc>> {
        self.not_before
    }

    /// The configured end time for the certificate.
    pub fn not_after(&self) -> Option<DateTime<Utc>> {
        self.not_after
    }

    /// The error, if any, which occurred while processing the order.
    pub fn error(&self) -> Option<&AcmeErrorDocument> {
        self.error.as_ref()
    }

    /// The urls pointing to the Authorization objects for this order.
    pub fn authorizations(&self) -> &[Url] {
        self.authorizations.as_ref()
    }

    /// The URL used to finalize this order with a CSR.
    pub fn finalize(&self) -> &Url {
        &self.finalize
    }

    /// The URL used to fetch this order's certificate chain.
    pub fn certificate(&self) -> Option<&Url> {
        self.certificate.as_ref()
    }
}

/// State of the order during processing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    /// Order is waiting for authorizations to be completed.
    Pending,
    /// Order is ready for a certificate signing request.
    Ready,

    /// ACME provider is processing the certificate signing request.
    Processing,

    /// ACME provider has issued the certificate.
    Valid,

    /// ACME provider has encountered an error while processing the order, and the entire
    /// order is now considered invalid.
    Invalid,
}

/// A request to create a new order associated with an ACME account.
///
/// The associated account is specified by the key used to sign the JWT request.
#[derive(Debug, Serialize, Default)]
pub struct NewOrderRequest {
    /// A list of identifiers to include in the order.
    pub identifiers: Vec<Identifier>,

    #[cfg(feature = "acme-profiles")]
    /// Name of the certificate profile to use.
    pub profile: Option<String>,

    /// Sets a time before which the issued certificate will not be valid.
    pub not_before: Option<DateTime<Utc>>,

    /// Sets a time after which the issued certificate will not be valid.
    pub not_after: Option<DateTime<Utc>>,
}

/// The request sent to finalize an order, including the certificate signing request.
#[derive(Debug, Clone, Serialize)]
pub struct FinalizeOrder {
    csr: Base64Data<SignedCertificateRequest>,
}

impl FinalizeOrder {
    /// Create a new finalize order request from an order and a certificate signing key.
    ///
    /// The signing key used here **must** not be the same key used to identify the ACME account.
    pub fn new<K, S>(order: &Order, key: &K) -> Self
    where
        K: signature::Signer<S> + Keypair + DynSignatureAlgorithmIdentifier,
        K::VerifyingKey:
            x509_cert::spki::EncodePublicKey + crate::cert::DynSubjectPublicKeyInfoOwned,
        S: x509_cert::spki::SignatureBitStringEncoding,
    {
        let mut csr = crate::cert::CertificateSigningRequest::new();

        for name in order.identifiers().iter().cloned() {
            csr.push(name);
        }
        let signed_csr = csr.sign(key);

        #[cfg(all(feature = "trace-requests", not(doc)))]
        {
            let doc = signed_csr.to_pem();
            tracing::trace!("CSR: \n{}", doc);
        }

        signed_csr.into()
    }
}

impl From<SignedCertificateRequest> for FinalizeOrder {
    fn from(value: SignedCertificateRequest) -> Self {
        FinalizeOrder { csr: value.into() }
    }
}

/// A chain of certificates, returned when an order is successful.
pub struct CertificateChain {
    chain: Vec<x509_cert::Certificate>,
}

impl CertificateChain {
    /// Try to create a new certificate chain from a list of DER encoded documents.
    pub fn try_from_der(documents: Vec<Vec<u8>>) -> Result<Self, AcmeError> {
        Ok(CertificateChain {
            chain: documents
                .iter()
                .map(|doc| x509_cert::Certificate::from_der(doc))
                .collect::<Result<Vec<_>, der::Error>>()?,
        })
    }

    /// The certificate chain
    pub fn chain(&self) -> &[x509_cert::Certificate] {
        &self.chain
    }

    /// Create a list of PEM documents representing the certificate chain.
    pub fn to_pem_documents(&self) -> Result<Vec<String>, AcmeError> {
        let docs = self
            .chain
            .iter()
            .map(|cert| {
                cert.to_pem(base64ct::LineEnding::default())
                    .map_err(AcmeError::from)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(docs)
    }
}

impl crate::protocol::response::Decode for CertificateChain {
    fn decode(data: &[u8]) -> Result<Self, AcmeError> {
        let documents_text = std::str::from_utf8(data)?.trim();

        let documents = documents_text
            .split(PEM_DOCUMENT_BEGIN)
            .filter(|doc| !doc.trim().is_empty())
            .map(|doc_part| {
                let mut doc = String::new();
                doc.push_str(PEM_DOCUMENT_BEGIN);
                doc.push_str(doc_part);

                let (label, data) = pem_rfc7468::decode_vec(doc.trim().as_bytes())?;
                if label != x509_cert::Certificate::PEM_LABEL {
                    return Err(pem_rfc7468::Error::Label);
                }
                Ok(data)
            })
            .collect::<Result<Vec<_>, pem_rfc7468::Error>>()
            .inspect_err(|&err| {
                tracing::error!(
                    "Error {} decoding certificate chain {}",
                    err,
                    documents_text
                );
            })?;

        Ok(CertificateChain {
            chain: documents
                .iter()
                .map(|doc| x509_cert::Certificate::from_der(doc))
                .collect::<Result<Vec<_>, der::Error>>()
                .inspect_err(|&err| {
                    tracing::error!(
                        "Error {} decoding certificate chain as DER: {}",
                        err,
                        documents_text
                    );
                })?,
        })
    }
}

impl pem_rfc7468::PemLabel for CertificateChain {
    const PEM_LABEL: &'static str = x509_cert::Certificate::PEM_LABEL;
}

impl crate::protocol::request::Encode for CertificateChain {
    fn encode(&self) -> Result<String, AcmeError> {
        Ok(self.to_pem_documents()?.join(""))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orders_list() {
        let response = crate::response!("order-list.http");
        let orders: Orders = serde_json::from_str(response.body()).unwrap();
        assert_eq!(orders.orders.len(), 3);
        assert!(orders.next.is_none());
    }

    #[test]
    fn order() {
        let raw = crate::example!("order.json");
        let order: Order = serde_json::from_str(raw).unwrap();
        assert_eq!(
            order.certificate,
            Some("https://example.com/acme/cert/mAt3xBGaobw".parse().unwrap())
        )
    }
}
