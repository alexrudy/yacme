# YACME - Yet another ACME Client

This is a yak-shave project to get an ACME client in rust that I like, and to learn more about ACME, and internet protocol cryptography in general.

This probably isn't good for production use, but it is based on the work of [RustCrypto](https://github.com/RustCrypto) who make good stuff.

The design goals of this project are:

- No OpenSSL dependency. The cryptography here should be pure rust.
- Modular and re-usable. This isn't an opinionated command line tool to help you get started. Instead, this crate hopes to be easy to integrate into existing projects, like those built on hyper.
- Easy to extend: adding new signature algorithms, challenge types, and other extensions (assuming they are supported by pure rust crates) should be relatively easy.
- Runtime flexible. Signature algorithms can be swapped out without changing types in the code calling in to the ACME service.

## Getting Started

Yeah... this project is getting started!

The main interface to this set of crates is in the [`yacme`](./yacme/) crate.

Check out [letsencrypt-pebble.rs](./yacme-service/examples/letsencrypt-pebble.rs) for a brief starting point (against LetsEncrypt's [pebble](https://github.com/letsencrypt/pebble)), and stay tuned for even more.
