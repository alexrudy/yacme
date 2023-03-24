use std::{
    io::{self, Read},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use lazy_static::lazy_static;
use serde::Serialize;

pub fn parse_http_response_example(data: &str) -> http::Response<String> {
    let mut lines = data.lines();

    let status = {
        let status_line = lines.next().unwrap().trim();
        let (version, status) = status_line.split_once(' ').unwrap();

        if version != "HTTP/1.1" {
            panic!("Expected HTTP/1.1, got {version}");
        }

        let (code, _reason) = status.split_once(' ').unwrap();
        http::StatusCode::from_u16(code.parse().expect("status code is u16"))
            .expect("known status code")
    };

    let mut headers = http::HeaderMap::new();

    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        } else {
            let (name, value) = line
                .trim()
                .split_once(": ")
                .expect("Header delimiter is ':'");
            headers.append(
                http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                value.parse().expect("valid header value"),
            );
        }
    }

    let body: String = lines.collect();
    let mut response = http::Response::new(body);
    *response.headers_mut() = headers;
    *response.status_mut() = status;
    *response.version_mut() = http::Version::HTTP_11;
    response
}

pub fn read_bytes<P: AsRef<Path>>(path: P) -> io::Result<Vec<u8>> {
    let mut rdr = io::BufReader::new(std::fs::File::open(path)?);
    let mut buf = Vec::new();
    rdr.read_to_end(&mut buf)?;
    Ok(buf)
}

pub fn read_string<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let mut rdr = io::BufReader::new(std::fs::File::open(path)?);
    let mut buf = String::new();
    rdr.read_to_string(&mut buf)?;
    Ok(buf)
}

const PEBBLE_DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../pebble/");

lazy_static! {
    static ref PEBBLE: Mutex<Arc<Pebble>> = Mutex::new(Arc::new(Pebble::create()));
}

#[derive(Debug)]
pub struct Pebble {
    directory: PathBuf,
}

impl Pebble {
    #[allow(clippy::new_without_default)]

    pub fn new() -> Arc<Self> {
        let pebble = PEBBLE.lock().unwrap();
        if Arc::strong_count(&pebble) == 1 {
            pebble.start();
        }
        pebble.clone()
    }

    fn create() -> Self {
        let pebble_directory = std::fs::canonicalize(PEBBLE_DIRECTORY).expect("valid pebble path");
        Pebble {
            directory: pebble_directory,
        }
    }

    fn start(&self) {
        let output = std::process::Command::new("docker")
            .arg("compose")
            .args([
                "up",
                "--detach",
                "--remove-orphans",
                "--renew-anon-volumes",
                "--wait",
            ])
            .current_dir(&self.directory)
            .output()
            .expect("able to spawn docker compose command");

        if !output.status.success() {
            panic!("Failed to start a pebble server");
        }
    }

    pub fn certificate(&self) -> reqwest::Certificate {
        let cert = self.directory.join("pebble.minica.pem");

        reqwest::Certificate::from_pem(&read_bytes(cert).unwrap()).expect("valid pebble root CA")
    }

    pub async fn dns_a(&self, host: &str, addresses: &[Ipv4Addr]) {
        #[derive(Debug, Serialize)]
        struct PebbleDNSRecord {
            host: String,
            addresses: Vec<String>,
        }

        let chall_setup = PebbleDNSRecord {
            host: host.to_owned(),
            addresses: addresses.iter().map(|ip| ip.to_string()).collect(),
        };

        let resp = reqwest::Client::new()
            .post("http://localhost:8055/add-a")
            .json(&chall_setup)
            .send()
            .await
            .expect("connect to pebble");
        match resp.error_for_status_ref() {
            Ok(_) => {}
            Err(_) => {
                eprintln!("Request:");
                eprintln!("{}", serde_json::to_string(&chall_setup).unwrap());
                eprintln!("ERROR:");
                eprintln!("Status: {:?}", resp.status().canonical_reason());
                eprintln!(
                    "{}",
                    resp.text().await.expect("get response body from pebble")
                );
                panic!("Failed to update challenge server");
            }
        }
    }

    pub async fn dns01(&self, host: &str, value: &str) {
        #[derive(Debug, Serialize)]
        struct Dns01TXT {
            host: String,
            value: String,
        }

        let chall_setup = Dns01TXT {
            host: host.to_owned(),
            value: value.to_owned(),
        };

        tracing::trace!(
            "Challenge Setup:\n{}",
            serde_json::to_string(&chall_setup).unwrap()
        );

        let resp = reqwest::Client::new()
            .post("http://localhost:8055/set-txt")
            .json(&chall_setup)
            .send()
            .await
            .expect("connect to pebble");
        match resp.error_for_status_ref() {
            Ok(_) => {}
            Err(_) => {
                eprintln!("Request:");
                eprintln!("{}", serde_json::to_string(&chall_setup).unwrap());
                eprintln!("ERROR:");
                eprintln!("Status: {:?}", resp.status().canonical_reason());
                eprintln!(
                    "{}",
                    resp.text().await.expect("get response body from pebble")
                );
                panic!("Failed to update challenge server");
            }
        }
    }

    pub async fn http01(&self, token: &str, content: &str) {
        #[derive(Debug, Serialize)]
        struct Http01ChallengeSetup {
            token: String,
            content: String,
        }

        let chall_setup = Http01ChallengeSetup {
            token: token.to_owned(),
            content: content.to_owned(),
        };

        tracing::trace!(
            "Challenge Setup:\n{}",
            serde_json::to_string(&chall_setup).unwrap()
        );

        let resp = reqwest::Client::new()
            .post("http://localhost:8055/add-http01")
            .json(&chall_setup)
            .send()
            .await
            .expect("connect to pebble");
        match resp.error_for_status_ref() {
            Ok(_) => {}
            Err(_) => {
                eprintln!("Request:");
                eprintln!("{}", serde_json::to_string(&chall_setup).unwrap());
                eprintln!("ERROR:");
                eprintln!("Status: {:?}", resp.status().canonical_reason());
                eprintln!(
                    "{}",
                    resp.text().await.expect("get response body from pebble")
                );
                panic!("Failed to update challenge server");
            }
        }
    }

    pub fn down(self: &Arc<Self>) {
        let pebble = PEBBLE.lock().unwrap();
        if Arc::strong_count(self) == 2 {
            self.down_internal();
        }
        drop(pebble)
    }

    fn down_internal(&self) {
        let output = std::process::Command::new("docker")
            .arg("compose")
            .args(["down", "--remove-orphans", "--volumes", "--timeout", "10"])
            .current_dir(&self.directory)
            .output()
            .expect("able to spawn docker compose command");

        if !output.status.success() {
            panic!("Failed to stop a pebble server");
        }
    }
}
