//! # Utilities for testing against the pebble ACME server
//!

use std::{
    collections::BTreeMap,
    io::{Read, Seek, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

use fd_lock::{RwLock, RwLockWriteGuard};
use serde::Serialize;

/// Parse an HTTP response formatted like an RFC 8555 example.
///
/// The response body is not parsed, and instead passed literally in the
/// returned response object.
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

const PEBBLE_DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/pebble/");

#[derive(Debug)]
struct PidRc {
    lock: RwLock<std::fs::File>,
    counts: BTreeMap<u32, usize>,
}

struct LockedPidRc<'l> {
    guard: RwLockWriteGuard<'l, std::fs::File>,
    counts: &'l mut BTreeMap<u32, usize>,
}

impl PidRc {
    fn new<P: AsRef<Path>>(path: &P) -> Self {
        let lock = RwLock::new(
            std::fs::File::options()
                .read(true)
                .append(true)
                .create(true)
                .open(path.as_ref())
                .unwrap(),
        );

        Self {
            lock,
            counts: Default::default(),
        }
    }

    fn lock(&mut self) -> LockedPidRc<'_> {
        let guard = self.lock.write().unwrap();
        LockedPidRc {
            guard,
            counts: &mut self.counts,
        }
    }
}

impl<'l> LockedPidRc<'l> {
    fn write(&mut self) {
        self.guard.set_len(0).expect("truncate lock file");

        for (pid, c) in self.counts.iter() {
            if *c > 0 {
                for _ in 0..*c {
                    writeln!(self.guard, "{}", pid).unwrap();
                }
            }
        }
    }

    fn read(&mut self) {
        self.guard.rewind().expect("rewind to start of lockfile");
        let mut buf = String::new();
        let _ = self.guard.read_to_string(&mut buf);

        self.counts.clear();
        for pid in buf.lines() {
            let count = self.counts.entry(pid.parse().unwrap()).or_insert(0);
            *count += 1;
        }
    }

    fn increment(&mut self) {
        self.read();

        let pid = std::process::id();
        let count = self.counts.entry(pid).or_insert(0);
        *count += 1;

        tracing::debug!(%pid, "increment: {}", count);

        self.write();
    }

    fn decrement(&mut self) -> bool {
        self.read();

        let pid = std::process::id();
        match self.counts.entry(pid) {
            std::collections::btree_map::Entry::Vacant(_) => {
                panic!("pid not found in lock file when decrementing");
            }
            std::collections::btree_map::Entry::Occupied(mut value) => {
                assert_ne!(value.get(), &0, "pid count is 0 when decrementing");
                tracing::debug!(%pid, "decrement: {}", value.get());

                let new_value = value.get().saturating_sub(1);
                if new_value > 0 {
                    value.insert(new_value);
                } else {
                    value.remove();
                }
            }
        }

        self.write();
        !self.counts.is_empty()
    }

    fn clear(&mut self) {
        self.counts.clear();
        self.write();
    }

    fn reset(&mut self) {
        self.counts.clear();
        self.counts.insert(std::process::id(), 1);
        self.write();
    }

    fn is_empty(&mut self) -> bool {
        self.read();
        self.counts.is_empty()
    }
}

/// RAII wrapper around a pebble service.
///
/// The pebble service will be started and managed via docker compose.
#[derive(Debug)]
pub struct Pebble {
    directory: PathBuf,
    lock: PidRc,
}

impl Pebble {
    #[allow(clippy::new_without_default)]

    /// Create a new pebble manager instance.
    ///
    /// This effectively acts as a signleton, in that only one pebble
    /// docker container will be started at any given time, but creating
    /// multiple `Pebble` instances will all refer to the same container.
    pub fn new() -> Self {
        let directory: PathBuf = PEBBLE_DIRECTORY.into();
        let lock = PidRc::new(&directory.join("lock"));
        let mut pebble = Self { directory, lock };

        pebble.start();

        pebble
    }

    fn start(&mut self) {
        let mut guard = self.lock.lock();

        if !guard.is_empty() {
            let output = std::process::Command::new("docker")
                .arg("compose")
                .args(["ps"])
                .current_dir(&self.directory)
                .output()
                .expect("able to spawn docker compose command");

            // must get more than 2 lines of output.
            if output.status.success()
                && output
                    .stdout
                    .iter()
                    .map(|&b| (b == '\n' as u8) as u32)
                    .sum::<u32>()
                    > 2
            {
                tracing::debug!("Pebble server already running");
                guard.increment();
                return;
            }
        }

        tracing::debug!("Starting pebble server");

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
            let stderr = String::from_utf8_lossy(&output.stderr);
            guard.clear(); // nothing is running, so clear the lock file
            panic!("Failed to start a pebble server: {stderr}");
        } else {
            tracing::debug!("Pebble server started");
            guard.reset();
        }
    }

    /// Wait for the pebble server to be ready.
    pub async fn ready(&self) -> Result<(), reqwest::Error> {
        let client = reqwest::Client::builder()
            .add_root_certificate(self.certificate())
            .build()
            .unwrap();

        loop {
            match client.get("https://localhost:14000/dir").send().await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        break;
                    }
                    tracing::trace!(
                        "Error response from pebble:\n{}",
                        resp.text().await.unwrap_or("".to_owned())
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(error) => {
                    tracing::trace!("Error connecting to pebble: {}", error);
                }
            };
        }

        Ok(())
    }

    /// Get the pebble root CA certificate.
    pub fn certificate(&self) -> reqwest::Certificate {
        let cert = self.directory.join("pebble.minica.pem");

        reqwest::Certificate::from_pem(&std::fs::read(cert).expect("read pebble root CA"))
            .expect("valid pebble root CA")
    }

    /// Set a DNS A record for a given host on the pebble challenge responder.
    #[tracing::instrument(skip(self, addresses))]
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

        tracing::trace!(
            "Challenge Setup:\n{}",
            serde_json::to_string(&chall_setup).unwrap()
        );

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

    /// Set a DNS01 TXT record for a given host on the pebble challenge responder.
    #[tracing::instrument(skip(self, value))]
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

    /// Configure the pebble challenge responder to serve a HTTP01 challenge.
    #[tracing::instrument(skip_all)]
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

    fn down_internal(&mut self) {
        let mut guard = self.lock.lock();

        if guard.decrement() {
            return;
        }

        tracing::debug!("Stopping pebble server");
        let output = std::process::Command::new("docker")
            .arg("compose")
            .args(["down", "--remove-orphans", "--volumes", "--timeout", "10"])
            .current_dir(&self.directory)
            .output()
            .expect("able to spawn docker compose command");

        if !output.status.success() {
            panic!("Failed to stop a pebble server");
        }
        tracing::debug!("Pebble server stopped");

        guard.clear();
    }
}

impl Drop for Pebble {
    fn drop(&mut self) {
        self.down_internal();
    }
}
