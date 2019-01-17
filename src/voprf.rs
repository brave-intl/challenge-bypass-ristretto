//! An implementation of a verifiable oblivious pseudorandom function

#[cfg(not(feature = "merlin"))]
pub use dleq::*;
#[cfg(feature = "merlin")]
pub use dleq_merlin::*;

pub use oprf::*;
