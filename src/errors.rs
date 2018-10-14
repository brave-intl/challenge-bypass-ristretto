//! Errors which may occur when parsing keys and/or tokens to or from wire formats,
//! or verifying proofs.

use core::fmt;
use core::fmt::Display;

/// Internal errors.  Most application-level developers will likely not
/// need to pay any attention to these.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum InternalError {
    /// An error occured when converting from a `CompressedRistretto` to a `RistrettoPoint`
    PointDecompressionError,
    /// An error in the length of bytes handed to a constructor.
    BytesLengthError {
        /// The name of the type
        name: &'static str,
        /// The expected number of bytes
        length: usize,
    },
    /// Verification failed
    VerifyError,
}

impl Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InternalError::PointDecompressionError => write!(f, "Cannot decompress Edwards point"),
            InternalError::BytesLengthError { name: n, length: l } => {
                write!(f, "{} must be {} bytes in length", n, l)
            }
            InternalError::VerifyError => write!(f, "Verification failed"),
        }
    }
}

/// Errors when keys and/or tokens to or from wire formats, or verifying proofs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TokenError(pub(crate) InternalError);

impl Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
