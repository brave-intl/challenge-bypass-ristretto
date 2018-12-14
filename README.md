# challenge-bypass-ristretto [![](https://img.shields.io/crates/v/challenge-bypass-ristretto.svg)](https://crates.io/crates/challenge-bypass-ristretto) [![](https://docs.rs/challenge-bypass-ristretto/badge.svg)](https://docs.rs/challenge-bypass-ristretto) [![Build Status](https://travis-ci.org/brave-intl/challenge-bypass-ristretto.svg?branch=master)](https://travis-ci.org/brave-intl/challenge-bypass-ristretto)

**A rust implemention of the
[privacy pass cryptographic protocol](https://www.petsymposium.org/2018/files/papers/issue3/popets-2018-0026.pdf)
using the [Ristretto group.](https://ristretto.group/)**

This library utilizes the wonderful [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek)
which is a pure-Rust implementation of group operations on Ristretto.

It is only an implementation of the cryptographic protocol,
it does not provide a service or FFI for use by other languages.

**This crate is still a work in progress and is not yet recommended for external use.**

# FFI

This library exposes some functions intended to assist FFI creation but does
not implement a FFI itself.

For FFI see [challenge-bypass-ristretto-ffi](https://github.com/brave-intl/challenge-bypass-ristretto-ffi).

# Blinded Tokens

As originally implemented in the challenge bypass
[server](https://github.com/privacypass/challenge-bypass-server) and
[extension](https://github.com/privacypass/challenge-bypass-extension)
repositories, blinded tokens enable internet users can anonymously
bypass internet challenges (CAPTCHAs).

In this use case, upon completing a CAPTCHA a user is issued tokens which can be
redeemed in place of completing further CAPTCHAs. The issuer
can verify that the tokens are valid but cannot determine which user they
were issued to.

This method of token creation is generally useful as it allows for
authorization in a way that is unlinkable. This library is intended for
use in applications where these combined properties may be useful.

---

A short description of the protocol follows, [a more detailed writeup is also available].

The blinded token protocol has two parties and two stages. A client and
issuer first perform the signing stage, after which the client is
able to derive tokens which can later be used in the redemption phase.

## Signing

The client prepares random tokens, blinds
those tokens such that the issuer cannot determine the original token value,
and sends them to the issuer. The issuer signs the tokens using a secret key
and returns them to the client. The client then reverses the original blind to yield
a signed token.

## Redemption

The client proves the validity of their signed token to the server. The
server marks the token as spent so it cannot be used again.

# Use

This crate is still a work in progress and is not yet recommended for external use.

## Features

By default this crate uses `std` and the `u64_backend` of [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek). However it is `no-std` compatible and the other `curve25519-dalek` backends can be selected.

The optional features include `base64` and `serde`.

* `base64` exposes methods for base64 encoding / decoding of the various structures.
* `serde` implements the [serde](https://serde.rs) `Serialize` / `Deserialize` traits.

`merlin` is an experimental feature that uses [merlin](https://github.com/dalek-cryptography/merlin) to implement the DLEQ proofs. This diverges from
the original protocol specified in the privacy pass paper. It is not yet stable / intended for use and
is implemented in [`src/dleq_merlin.rs`].

# Development

Install rust.

## Building

Run `cargo build`

## Testing

Run `cargo test`

[`src/dleq_merlin.rs`]: src/dleq_merlin.rs
[a more detailed writeup is also available]: https://docs.rs/challenge-bypass-ristretto#cryptographic-protocol
