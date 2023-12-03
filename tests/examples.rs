fn run_example(name: &str) -> std::process::Output {
    let output = std::process::Command::new("cargo")
        .args(["run", "--features=pebble", "--example", name])
        .output()
        .unwrap();

    if !output.status.success() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    assert!(output.status.success());
    output
}

#[tokio::test]
async fn letsencrypt_pebble() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let pebble = yacme::pebble::Pebble::new();
    pebble.ready().await.unwrap();
    run_example("pebble");
}

#[test]
fn generate_csr() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

    let output = run_example("generate-csr");
    let pem = String::from_utf8(output.stdout).unwrap();

    assert!(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
    let _ = reqwest::Certificate::from_pem(pem.as_bytes()).unwrap();
}
