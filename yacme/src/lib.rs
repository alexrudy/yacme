//! # Yet Another Certificate Management Engine
//!
//! YACME is an implementation of the [ACME protocol](https://tools.ietf.org/html/rfc8555).
//!
//! ## Features
//!
//! YACME supports custom certificates, CAs, and ACME servers. It supports HTTP-01 and DNS-01 authorization challenges.
//! It does not currently support TLS-ALPN-01 challenges, but may at a future time.
//!
//! YACME also does not support certificate revocation or account certificate updates.
//!
//! YACME supports ec256 keys only at this point, but new key implementations would be welcome
//! additions to `yacme-key`.
//!
//! ## Usage
//!
//! YACME is split into several levels of api:
//!
//! - `service` is the high level API, and provides a simple interface for issuing certificates.
//! - `schema` provides all of the data structures to implement individual ACME endpoints.
//! - `protocol` provides the JWT protocol used by ACME servers.
//! - `key` provides support for ECDSA keys.

pub mod key;
pub mod protocol;
pub mod schema;
pub mod service;
