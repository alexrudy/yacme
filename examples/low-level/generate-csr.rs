use pkcs8::DecodePrivateKey;
use yacme::cert::CertificateSigningRequest;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let key = {
        let pem = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/reference-keys/ec-p255-cert.pem"
        ));
        ecdsa::SigningKey::<p256::NistP256>::from_pkcs8_pem(pem).unwrap()
    };

    let mut csr = CertificateSigningRequest::new();
    csr.push("www.example.org");
    csr.push("internal.example.org");
    let signed = csr.sign::<_, ecdsa::der::Signature<_>>(&key);
    println!("{}", signed.to_pem());
}
