use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand::{CryptoRng, Rng};

use crate::errors::InternalError;
use crate::vorpf::SigningKey;

/// A `DLEQProof` is a proof of the equivalence of the discrete logarithm between two pairs of points.
#[repr(C)]
#[allow(non_snake_case)]
pub struct DLEQProof {
    /// `X` is a `CompressedRistretto`
    pub(crate) X: CompressedRistretto,
    /// `Y` is a `CompressedRistretto`
    pub(crate) Y: CompressedRistretto,
    /// `P` is a `CompressedRistretto`
    pub(crate) P: CompressedRistretto,
    /// `Q` is a `CompressedRistretto`
    pub(crate) Q: CompressedRistretto,
    /// `c` is a `Scalar`
    pub(crate) c: Scalar,
    /// `s` is a `Scalar`
    pub(crate) s: Scalar,
}

#[allow(non_snake_case)]
impl DLEQProof {
    /// Construct a new `DLEQProof`
    pub fn new<D, T>(
        rng: &mut T,
        X: RistrettoPoint,
        Y: RistrettoPoint,
        P: RistrettoPoint,
        Q: RistrettoPoint,
        k: SigningKey,
    ) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
        T: Rng + CryptoRng,
    {
        let t = Scalar::random(rng);

        let A = t * X;
        let B = t * P;

        let mut h = D::default();

        let X = X.compress();
        let Y = Y.compress();
        let P = P.compress();
        let Q = Q.compress();
        let A = A.compress();
        let B = B.compress();

        h.input(X.as_bytes());
        h.input(Y.as_bytes());
        h.input(P.as_bytes());
        h.input(Q.as_bytes());
        h.input(A.as_bytes());
        h.input(B.as_bytes());

        let c = Scalar::from_hash(h);

        let s = t - c * k.k;

        DLEQProof { X, Y, P, Q, c, s }
    }

    /// Verify the `DLEQProof`
    pub fn verify<D>(&self) -> Result<(), InternalError>
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let A = (self.s * self
            .X
            .decompress()
            .ok_or(InternalError::PointDecompressionError)?)
            + (self.c * self
                .Y
                .decompress()
                .ok_or(InternalError::PointDecompressionError)?);
        let B = (self.s * self
            .P
            .decompress()
            .ok_or(InternalError::PointDecompressionError)?)
            + (self.c * self
                .Q
                .decompress()
                .ok_or(InternalError::PointDecompressionError)?);
        let mut h = D::default();

        let A = A.compress();
        let B = B.compress();

        h.input(self.X.as_bytes());
        h.input(self.Y.as_bytes());
        h.input(self.P.as_bytes());
        h.input(self.Q.as_bytes());
        h.input(A.as_bytes());
        h.input(B.as_bytes());

        let c = Scalar::from_hash(h);

        if c == self.c {
            Ok(())
        } else {
            Err(InternalError::VerifyError)
        }
    }
}
