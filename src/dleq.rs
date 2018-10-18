use core::iter;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand::{ChaChaRng, CryptoRng, Rng, SeedableRng};

use errors::{InternalError, TokenError};
use vorpf::{BlindedToken, PublicKey, SignedToken, SigningKey};

/// The length of a `DLEQProof`, in bytes.
pub const DLEQ_PROOF_LENGTH: usize = 192;

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use sha2::Sha512;
    use vorpf::Token;

    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn dleq_proof_works() {
        let mut rng = OsRng::new().unwrap();

        let key1 = SigningKey::random(&mut rng);
        let key2 = SigningKey::random(&mut rng);

        let P = RistrettoPoint::random(&mut rng);
        let Q = key1.k * P;

        let proof = DLEQProof::new::<Sha512, OsRng>(&mut rng, P, Q, &key1).unwrap();

        assert!(proof.verify::<Sha512>().is_ok());

        let P = RistrettoPoint::random(&mut rng);
        let Q = key2.k * P;

        let proof = DLEQProof::new::<Sha512, OsRng>(&mut rng, P, Q, &key1).unwrap();

        assert!(!proof.verify::<Sha512>().is_ok());
    }

    #[test]
    #[allow(non_snake_case)]
    fn batch_dleq_proof_works() {
        use std::vec::Vec;

        let mut rng = OsRng::new().unwrap();

        let key = SigningKey::random(&mut rng);

        let blinded_tokens = vec![Token::random(&mut rng).blind()];
        let signed_tokens: Vec<SignedToken> = blinded_tokens
            .iter()
            .filter_map(|t| key.sign(t).ok())
            .collect();

        let batch_proof =
            BatchDLEQProof::new::<Sha512, OsRng>(&mut rng, &blinded_tokens, &signed_tokens, &key)
                .unwrap();

        assert!(
            batch_proof
                .verify::<Sha512>(&blinded_tokens, &signed_tokens, &key.public_key)
                .is_ok()
        );
    }
}

/// A `DLEQProof` is a proof of the equivalence of the discrete logarithm between two pairs of points.
#[repr(C)]
#[allow(non_snake_case)]
pub struct DLEQProof {
    /// `X` is a `CompressedRistretto`
    pub(crate) X: CompressedRistretto,
    /// `Y` is a `CompressedRistretto`
    /// \\(Y=X^k\\)
    /// Together X and Y form a committment to a particular signing key, a `PublicKey`
    pub(crate) Y: CompressedRistretto,
    /// `P` is a `CompressedRistretto`
    pub(crate) P: CompressedRistretto,
    /// `Q` is a `CompressedRistretto`
    /// \\(Q=P^k\\)
    pub(crate) Q: CompressedRistretto,
    /// `c` is a `Scalar`
    /// \\(c=H_3(X,Y,P,Q,A,B)\\)
    pub(crate) c: Scalar,
    /// `s` is a `Scalar`
    /// \\(s = (t - ck) \mod q\\)
    pub(crate) s: Scalar,
}

#[cfg(feature = "base64")]
impl_base64!(DLEQProof);

#[cfg(feature = "serde")]
impl_serde!(DLEQProof);

#[allow(non_snake_case)]
impl DLEQProof {
    /// Construct a new `DLEQProof`
    pub fn new<D, T>(
        rng: &mut T,
        P: RistrettoPoint,
        Q: RistrettoPoint,
        k: &SigningKey,
    ) -> Result<Self, TokenError>
    where
        D: Digest<OutputSize = U64> + Default,
        T: Rng + CryptoRng,
    {
        let t = Scalar::random(rng);

        let A = t * k
            .public_key
            .X
            .decompress()
            .ok_or(TokenError(InternalError::PointDecompressionError))?;
        let B = t * P;

        let mut h = D::default();

        let X = k.public_key.X;
        let Y = k.public_key.Y;
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

        Ok(DLEQProof { X, Y, P, Q, c, s })
    }

    /// Verify the `DLEQProof`
    pub fn verify<D>(&self) -> Result<(), TokenError>
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let A = (self.s * self
            .X
            .decompress()
            .ok_or(TokenError(InternalError::PointDecompressionError))?)
            + (self.c * self
                .Y
                .decompress()
                .ok_or(TokenError(InternalError::PointDecompressionError))?);
        let B = (self.s * self
            .P
            .decompress()
            .ok_or(TokenError(InternalError::PointDecompressionError))?)
            + (self.c * self
                .Q
                .decompress()
                .ok_or(TokenError(InternalError::PointDecompressionError))?);
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
            Err(TokenError(InternalError::VerifyError))
        }
    }

    /// Convert this `DLEQProof` to a byte array.
    pub fn to_bytes(&self) -> [u8; DLEQ_PROOF_LENGTH] {
        let mut proof_bytes: [u8; DLEQ_PROOF_LENGTH] = [0u8; DLEQ_PROOF_LENGTH];

        proof_bytes[..32].copy_from_slice(&self.X.to_bytes());
        proof_bytes[32..64].copy_from_slice(&self.Y.to_bytes());
        proof_bytes[64..96].copy_from_slice(&self.P.to_bytes());
        proof_bytes[96..128].copy_from_slice(&self.Q.to_bytes());
        proof_bytes[128..160].copy_from_slice(&self.c.to_bytes());
        proof_bytes[160..].copy_from_slice(&self.s.to_bytes());
        proof_bytes
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "DLEQProof",
            length: DLEQ_PROOF_LENGTH,
        })
    }

    /// Construct a `DLEQProof` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<DLEQProof, TokenError> {
        if bytes.len() != DLEQ_PROOF_LENGTH {
            return Err(DLEQProof::bytes_length_error());
        }

        let mut X_bits: [u8; 32] = [0u8; 32];
        let mut Y_bits: [u8; 32] = [0u8; 32];
        let mut P_bits: [u8; 32] = [0u8; 32];
        let mut Q_bits: [u8; 32] = [0u8; 32];
        let mut c_bits: [u8; 32] = [0u8; 32];
        let mut s_bits: [u8; 32] = [0u8; 32];

        X_bits.copy_from_slice(&bytes[..32]);
        Y_bits.copy_from_slice(&bytes[32..64]);
        P_bits.copy_from_slice(&bytes[64..96]);
        Q_bits.copy_from_slice(&bytes[96..128]);
        c_bits.copy_from_slice(&bytes[128..160]);
        s_bits.copy_from_slice(&bytes[160..]);

        let X = CompressedRistretto(X_bits);
        let Y = CompressedRistretto(Y_bits);
        let P = CompressedRistretto(P_bits);
        let Q = CompressedRistretto(Q_bits);

        let c = Scalar::from_canonical_bytes(c_bits)
            .ok_or(TokenError(InternalError::ScalarFormatError))?;
        let s = Scalar::from_canonical_bytes(s_bits)
            .ok_or(TokenError(InternalError::ScalarFormatError))?;

        Ok(DLEQProof { X, Y, P, Q, c, s })
    }
}

/// A `BatchDLEQProof` is a proof of the equivalence of the discrete logarithm between a common
/// pair of points and one or more other pairs of points.
#[repr(C)]
#[allow(non_snake_case)]
pub struct BatchDLEQProof(DLEQProof);

#[cfg(feature = "base64")]
impl_base64!(BatchDLEQProof);

#[cfg(feature = "serde")]
impl_serde!(BatchDLEQProof);

#[allow(non_snake_case)]
impl BatchDLEQProof {
    fn calculate_composites<D>(
        blinded_tokens: &[BlindedToken],
        signed_tokens: &[SignedToken],
        public_key: &PublicKey,
    ) -> Result<(RistrettoPoint, RistrettoPoint), TokenError>
    where
        D: Digest<OutputSize = U64> + Default,
    {
        if blinded_tokens.len() != signed_tokens.len() {
            return Err(TokenError(InternalError::LengthMismatchError));
        }

        let mut h = D::default();

        h.input(public_key.X.as_bytes());
        h.input(public_key.Y.as_bytes());

        let h = blinded_tokens
            .iter()
            .zip(signed_tokens.iter())
            .fold(h, |mut h, (Pi, Qi)| {
                h.input(Pi.0.as_bytes());
                h.input(Qi.0.as_bytes());
                h
            });

        let result = h.result();

        let mut seed: [u8; 32] = [0u8; 32];
        seed.copy_from_slice(&result[..32]);

        let mut prng_M: ChaChaRng = SeedableRng::from_seed(seed);
        let mut prng_Z = prng_M.clone();

        let M = RistrettoPoint::optional_multiscalar_mul(
            iter::repeat_with(|| Scalar::random(&mut prng_M)).take(blinded_tokens.len()),
            blinded_tokens.iter().map(|Pi| Pi.0.decompress()),
        )
        .ok_or(TokenError(InternalError::PointDecompressionError))?;

        let Z = RistrettoPoint::optional_multiscalar_mul(
            iter::repeat_with(|| Scalar::random(&mut prng_Z)).take(blinded_tokens.len()),
            signed_tokens.iter().map(|Qi| Qi.0.decompress()),
        )
        .ok_or(TokenError(InternalError::PointDecompressionError))?;

        Ok((M, Z))
    }

    /// Construct a new `BatchDLEQProof`
    pub fn new<D, T>(
        rng: &mut T,
        blinded_tokens: &[BlindedToken],
        signed_tokens: &[SignedToken],
        signing_key: &SigningKey,
    ) -> Result<Self, TokenError>
    where
        D: Digest<OutputSize = U64> + Default,
        T: Rng + CryptoRng,
    {
        let (M, Z) = BatchDLEQProof::calculate_composites::<D>(
            blinded_tokens,
            signed_tokens,
            &signing_key.public_key,
        )?;
        Ok(BatchDLEQProof(DLEQProof::new::<D, T>(
            rng,
            M,
            Z,
            signing_key,
        )?))
    }

    /// Verify a `BatchDLEQProof`
    pub fn verify<D>(
        &self,
        blinded_tokens: &[BlindedToken],
        signed_tokens: &[SignedToken],
        public_key: &PublicKey,
    ) -> Result<(), TokenError>
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let (M, Z) =
            BatchDLEQProof::calculate_composites::<D>(blinded_tokens, signed_tokens, public_key)?;
        if M != self
            .0
            .P
            .decompress()
            .ok_or(TokenError(InternalError::PointDecompressionError))?
            || Z != self
                .0
                .Q
                .decompress()
                .ok_or(TokenError(InternalError::PointDecompressionError))?
        {
            return Err(TokenError(InternalError::VerifyError));
        }

        self.0.verify::<D>()
    }

    /// Convert this `BatchDLEQProof` to a byte array.
    pub fn to_bytes(&self) -> [u8; DLEQ_PROOF_LENGTH] {
        self.0.to_bytes()
    }

    #[cfg(feature = "serde")]
    fn bytes_length_error() -> TokenError {
        DLEQProof::bytes_length_error()
    }

    /// Construct a `BatchDLEQProof` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<BatchDLEQProof, TokenError> {
        DLEQProof::from_bytes(bytes).map(BatchDLEQProof)
    }
}
