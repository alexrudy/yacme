use std::fmt;

use const_oid::AssociatedOid;
use der::{
    asn1::{BitStringRef, Ia5StringRef, SetOfVec},
    Encode, FixedTag,
};
use sha2::Digest;
use signature::DigestSigner;
use x509_cert::ext::pkix;

use crate::SigningKey;

const PEM_TAG_CSR: &str = "CERTIFICATE REQUEST";

#[derive(Debug)]
pub enum RequestedSubjectName {
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

#[derive(Debug, Default)]
pub struct CertificateSigningRequest {
    names: Vec<RequestedSubjectName>,
}

impl CertificateSigningRequest {
    pub fn new() -> Self {
        CertificateSigningRequest { names: Vec::new() }
    }

    pub fn push<N>(&mut self, name: N)
    where
        N: Into<RequestedSubjectName>,
    {
        self.names.push(name.into())
    }

    pub fn sign(self, key: &SigningKey) -> SignedCertificateRequest {
        let public_key = key.public_key();
        let subject_public_key = public_key.as_bytes();
        let algorithm = public_key.algorithm();
        let public_key = pkcs8::SubjectPublicKeyInfo {
            algorithm,
            subject_public_key: &subject_public_key,
        };
        // let mut values = Vec::new();

        let san_names: Vec<_> = self
            .names
            .iter()
            .map(|san| match san {
                RequestedSubjectName::Dns(dns) => pkix::name::GeneralName::DnsName(
                    Ia5StringRef::new(dns.as_bytes()).expect("ia-5 DNS valid names"),
                ),
            })
            .collect();

        let san = pkix::SubjectAltName::from(san_names)
            .to_vec()
            .expect("DER encoded SAN");

        let extension = x509_cert::ext::Extension {
            extn_id: pkix::SubjectAltName::OID,
            critical: true,
            extn_value: &san,
        };

        let extension_der = extension.to_vec().unwrap();

        // let extensions: x509_cert::ext::Extensions = vec![extension];
        // let extensions_der = extensions.to_vec().unwrap();

        let encoded_extensions =
            der::asn1::AnyRef::new(x509_cert::ext::Extension::TAG, &extension_der).unwrap();

        let mut values = SetOfVec::new();
        values.add(encoded_extensions).unwrap();

        let attr = x509_cert::attr::Attribute {
            oid: const_oid::db::rfc5912::ID_EXTENSION_REQ,
            values,
        };

        let mut attributes = SetOfVec::new();
        attributes.add(attr).unwrap();

        let csr_info = x509_cert::request::CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: Default::default(),
            public_key,
            attributes,
        };

        eprintln!("{:#?}", csr_info);

        let csr_target = csr_info.to_vec().expect("Valid encoding");
        let mut digest = sha2::Sha256::new();
        digest.update(&csr_target);

        let signature = key.sign_digest(digest);

        let csr = x509_cert::request::CertReq {
            info: csr_info,
            algorithm: key.algorithm(),
            signature: BitStringRef::new(0, signature.as_ref()).expect("valid signature"),
        };

        let mut buf = Vec::new();
        csr.encode_to_vec(&mut buf).expect("successful encoding");

        let data =
            pem_rfc7468::encode_string("CERTIFICATE REQUEST", base64ct::LineEnding::LF, &buf)
                .unwrap();
        eprintln!("{data}");

        SignedCertificateRequest(buf)
    }
}

#[derive(Debug, Clone)]
pub struct SignedCertificateRequest(Vec<u8>);

impl SignedCertificateRequest {
    pub fn to_pem(&self) -> String {
        pem_rfc7468::encode_string(PEM_TAG_CSR, base64ct::LineEnding::LF, &self.0)
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
    use crate::key;

    use super::*;

    #[test]
    fn create_csr() {
        let key = key!("ec-p255");

        let mut csr = CertificateSigningRequest::new();
        csr.push("www.example.org");
        csr.push("internal.example.org");
        let csr_signed = csr.sign(&key);

        let openssl_csr_pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/test-examples/csr/example.csr"
        ));

        let (label, openssl_csr_der) = pem_rfc7468::decode_vec(openssl_csr_pem.as_bytes()).unwrap();
        assert_eq!(label, PEM_TAG_CSR);

        let openssl_csr: x509_cert::request::CertReq =
            x509_cert::request::CertReq::try_from(openssl_csr_der.as_slice()).unwrap();

        eprintln!("{:#?}", openssl_csr);

        assert_eq!(csr_signed.to_pem(), openssl_csr_pem);
    }
}
