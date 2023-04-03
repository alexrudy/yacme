use yacme::key::cert::CertificateSigningRequest;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let key = {
        let pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/reference-keys/ec-p255-cert.pem"
        ));
        yacme::key::SigningKey::from_pkcs8_pem(
            pem,
            yacme::key::SignatureKind::Ecdsa(yacme::key::EcdsaAlgorithm::P256),
        )
        .unwrap()
    };

    let mut csr = CertificateSigningRequest::new();
    csr.push("www.example.org");
    csr.push("internal.example.org");
    let signed = csr.sign(&key);
    println!("{}", signed.to_pem());
}
