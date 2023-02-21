#!/usr/bin/env sh

ROOT=$(git rev-parse --show-toplevel)
openssl req -new -key "$ROOT/reference-keys/ec-p255-cert.pem" -subj / -config openssl-csr.conf -out example-openssl.csr
