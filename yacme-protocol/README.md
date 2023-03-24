# yacme-protocol

Implementation of the YACME protocol, specifically the JOSE, JWT/JWK parts, including authenticated
get-as-post and post requests.

## Unsafe code
This crate uses `unsafe` in `yacme_protocol::fmt` to provide a custom format to serde_json. It uses
the same `unsafe` code that `serde_json` uses [here](https://github.com/serde-rs/json/blob/master/src/ser.rs#L2144)

## License

MIT
