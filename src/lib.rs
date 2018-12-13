#![no_std]
#![cfg_attr(all(feature = "alloc", not(feature = "std")), feature(alloc))]
#![deny(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", feature(tool_lints))]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::many_single_char_names))]
#![feature(external_doc)]
//! [`src/dleq_merlin.rs`]: javascript:void(0)
//! [a more detailed writeup is also available]: #cryptographic-protocol
//! [`T`]: struct.TokenPreimage.html#method.T
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![cfg_attr(feature = "nightly", doc(include = "../docs/PROTOCOL.md"))]

#[cfg(all(feature = "alloc", not(feature = "std")))]
extern crate alloc;

//#[cfg(any(test, feature = "base64", feature = "std"))]
#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;

extern crate clear_on_drop;
extern crate crypto_mac;
extern crate curve25519_dalek;
extern crate digest;
extern crate hmac;
extern crate rand;
extern crate rand_chacha;

#[cfg(feature = "base64")]
extern crate base64;

#[cfg(feature = "merlin")]
extern crate merlin;

#[cfg(feature = "serde")]
extern crate serde;

#[cfg(test)]
extern crate sha2;

#[macro_use]
mod macros;

#[cfg(not(feature = "merlin"))]
mod dleq;
#[cfg(feature = "merlin")]
mod dleq_merlin;

pub mod errors;
mod voprf;

#[cfg(not(feature = "merlin"))]
pub use self::dleq::*;
#[cfg(feature = "merlin")]
pub use self::dleq_merlin::*;

pub use self::errors::*;
pub use self::voprf::*;
