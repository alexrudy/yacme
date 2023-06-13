//! Yacme's cryptographic primatives for X.509 Certificate Signing Requests

use std::fmt;

use const_oid::AssociatedOid;
use der::{
    asn1::{Ia5StringRef, SetOfVec},
    Encode, FixedTag,
};
use sha2::Digest;
use signature::{rand_core::OsRng, RandomizedDigestSigner};
use x509_cert::ext::pkix;

use super::SigningKey;

const PEM_TAG_CSR: &str = "CERTIFICATE REQUEST";

/// Name to be certified by the certificate issued from this request.
///
/// Currently, only DNS names are supported.
#[derive(Debug)]
pub enum RequestedSubjectName {
    /// A name known to the Domain Name System, such as `www.example.com`
    Dns(String),
}

impl fmt::Display for RequestedSubjectName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            RequestedSubjectName::Dns(dns) => write!(f, "DNS:{}", dns),
        }
    }
}

impl From<String> for RequestedSubjectName {
    fn from(value: String) -> Self {
        RequestedSubjectName::Dns(value)
    }
}

impl From<&str> for RequestedSubjectName {
    fn from(value: &str) -> Self {
        Self::Dns(value.to_owned())
    }
}

/// The informational data in a certificate signing request sufficient to
/// fulfill an ACME certificate signing order's finalize step.
///
/// Unlike many CSRs, ACME CSRs only need to contain the signing cryptographic
/// information along with the subject names (no need for a distinguished name
/// with a CSR for ACME as ACME certificates only attest to that they were issued
/// to someone who controlled the resource originally).
///
/// All names in the CSR created will be contained in the X.509 extension
/// "SubjectAltNames", and the Subject will be left empty. This is acceptable for
/// ACME CSRs.
#[derive(Debug, Default)]
pub struct CertificateSigningRequest {
    names: Vec<RequestedSubjectName>,
}

impl CertificateSigningRequest {
    /// Create a new, empty ceritficate signing request.
    pub fn new() -> Self {
        CertificateSigningRequest { names: Vec::new() }
    }

    /// Number of names in this CSR
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// CSR contains no names
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Add a subject name to this certificate signing request
    pub fn push<N>(&mut self, name: N)
    where
        N: Into<RequestedSubjectName>,
    {
        self.names.push(name.into())
    }

    /// Sign this request with a [`SigningKey`], creating an X.509 certificate
    /// singing request, which will be serialized using ASN.1 DER
    ///
    /// The [`SigningKey`] here should not be the same as the account key used
    /// in the rest of the ACME protocol.
    pub fn sign(self, key: &SigningKey) -> SignedCertificateRequest {
        // CSR needs the public key info to know who signed it.
        let public_key = key.public_key();
        // let algorithm = public_key.algorithm();

        // let spki_public_key_data = {
        //     let mut buf = Vec::with_capacity(public_key.as_bytes().len() + 1);
        //     BitStringRef::from_bytes(&public_key.as_bytes())
        //         .unwrap()
        //         .encode_to_vec(&mut buf)
        //         .unwrap();
        //     buf
        // };

        let bytes = public_key.as_bytes();

        let spki = spki::SubjectPublicKeyInfoOwned {
            algorithm: public_key.algorithm(),
            subject_public_key: der::asn1::BitString::from_bytes(&bytes).unwrap(),
        };

        // let spki = pkcs8::SubjectPublicKeyInfo::try_from(spki_document.as_bytes()).unwrap();

        // CSR needs a list of Subject Alternative Names as GeneralName entries
        // with DNS specified.
        let san_names: Vec<_> = self
            .names
            .iter()
            .map(|san| match san {
                RequestedSubjectName::Dns(dns) => pkix::name::GeneralName::DnsName(
                    Ia5StringRef::new(dns.as_bytes())
                        .expect("ia-5 DNS valid names")
                        .into(),
                ),
            })
            .collect();

        // Encode the SubjectAltNames using ASN.1 DER

        let san = pkix::SubjectAltName::from(san_names)
            .to_der()
            .expect("DER encoded SAN");

        // Set up an X.509 extension with the SAN, and mark it as critical
        // (since the subject will be empty, this extension is required for
        // the CSR to be meaningful).
        let extension = x509_cert::ext::Extension {
            extn_id: pkix::SubjectAltName::OID,
            critical: true,
            extn_value: der::asn1::OctetString::new(san).unwrap(),
        };

        // Encode the extension using ASN.1 DER
        let extension_der = extension.to_der().unwrap();

        // Add a tagged Extesnion value
        let encoded_extensions =
            der::asn1::Any::new(x509_cert::ext::Extension::TAG, extension_der).unwrap();

        // Include the extension value in the set of extensions to be included
        // with the X.509 attribute
        let mut values = SetOfVec::new();
        values.insert(encoded_extensions).unwrap();

        let attr = x509_cert::attr::Attribute {
            oid: const_oid::db::rfc5912::ID_EXTENSION_REQ,
            values,
        };

        // Add the extension attribute as the only attribute attached to this CSR
        let mut attributes = SetOfVec::new();
        attributes.insert(attr).unwrap();

        // Create the CSR info, which will be signed once encoded in DER
        let csr_info = x509_cert::request::CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: Default::default(),
            public_key: spki,
            attributes,
        };

        // Digest sign the CSR target
        let csr_target = csr_info.to_der().expect("Valid encoding");
        let mut digest = sha2::Sha256::new();
        digest.update(&csr_target);

        let signature = key.sign_digest_with_rng(&mut OsRng, digest);

        // Create the final CSR, containing in the info and the signature.
        let csr = x509_cert::request::CertReq {
            info: csr_info,
            algorithm: key.algorithm(),
            signature: der::asn1::BitString::new(0, signature.to_der().as_bytes())
                .expect("valid signature"),
        };

        let mut buf = Vec::new();
        csr.encode_to_vec(&mut buf).expect("successful encoding");

        SignedCertificateRequest(buf)
    }
}

/// A certificate request, cryptographcially signed, and encoded as ASN.1 DER
#[derive(Debug, Clone)]
pub struct SignedCertificateRequest(Vec<u8>);

impl SignedCertificateRequest {
    /// Encode this CSR as a PEM document.
    pub fn to_pem(&self) -> String {
        pem_rfc7468::encode_string(PEM_TAG_CSR, base64ct::LineEnding::default(), &self.0)
            .expect("valid PEM")
    }
}

impl AsRef<[u8]> for SignedCertificateRequest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[cfg(test)]
mod test {
    use der::Decode;

    use crate::key::SignatureKind;

    use super::*;

    #[test]
    fn csr_signature_is_der() {
        let key = SignatureKind::Ecdsa(crate::key::EcdsaAlgorithm::P256).random();

        let mut csr = CertificateSigningRequest::new();
        csr.push("example.com");

        let signed = csr.sign(&key);

        let csr = x509_cert::request::CertReq::from_der(signed.as_ref()).expect("valid CSR");

        let doc = csr.signature.as_bytes().unwrap();
        let _ = der::Document::from_der(doc).expect("valid DER");
    }
}
