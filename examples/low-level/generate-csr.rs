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
        p256::SecretKey::from_pkcs8_pem(pem).unwrap()
    };

    let signer = ecdsa::SigningKey::from(&key);

    let mut csr = CertificateSigningRequest::new();
    csr.push("www.example.org");
    csr.push("internal.example.org");
    let signed = csr.sign(&signer);
    println!("{}", signed.to_pem());
}
