#![no_std]
#![deny(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", feature(tool_lints))]
#![cfg_attr(
    feature = "cargo-clippy",
    allow(clippy::many_single_char_names)
)]

//! Challenge Bypass using the Ristretto group
//!
//! Challenge Bypass can be thought of as a 'blind signature scheme' based on the concept
//! of a Verifiable, Oblivious Pseudorandom Function (VOPRF).
//!
//! # Notation
//!
//! We have tried to align notation with that used in the paper
//! [Privacy Pass: Bypassing Internet Challenges Anonymously](https://www.petsymposium.org/2018/files/papers/issue3/popets-2018-0026.pdf)
extern crate clear_on_drop;
extern crate crypto_mac;
extern crate curve25519_dalek;
extern crate digest;
extern crate hmac;
extern crate rand;

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(test)]
extern crate sha2;

mod dleq;
pub mod errors;
mod vorpf;

pub use self::dleq::*;
pub use self::errors::*;
pub use self::vorpf::*;
