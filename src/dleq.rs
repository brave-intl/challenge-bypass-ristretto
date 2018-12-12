#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[cfg(all(feature = "std"))]
use std::vec::Vec;

use core::iter;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use errors::{InternalError, TokenError};
use voprf::{BlindedToken, PublicKey, SignedToken, SigningKey};

/// The length of a `DLEQProof`, in bytes.
pub const DLEQ_PROOF_LENGTH: usize = 64;

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use sha2::Sha512;
    use voprf::Token;

    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn dleq_proof_works() {
        let mut rng = OsRng::new().unwrap();

        let key1 = SigningKey::random(&mut rng);
        let key2 = SigningKey::random(&mut rng);

        let P = RistrettoPoint::random(&mut rng);
        let Q = key1.k * P;

        let proof = DLEQProof::_new::<Sha512, OsRng>(&mut rng, P, Q, &key1).unwrap();

        assert!(proof._verify::<Sha512>(P, Q, &key1.public_key).is_ok());

        let P = RistrettoPoint::random(&mut rng);
        let Q = key2.k * P;

        let proof = DLEQProof::_new::<Sha512, OsRng>(&mut rng, P, Q, &key1).unwrap();

        assert!(!proof._verify::<Sha512>(P, Q, &key1.public_key).is_ok());
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

        assert!(batch_proof
            .verify::<Sha512>(&blinded_tokens, &signed_tokens, &key.public_key)
            .is_ok());
    }
}

/// A `DLEQProof` is a proof of the equivalence of the discrete logarithm between two pairs of points.
#[allow(non_snake_case)]
pub struct DLEQProof {
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
    fn _new<D, T>(
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

        Ok(DLEQProof { c, s })
    }

    /// Construct a new `DLEQProof`
    pub fn new<D, T>(
        rng: &mut T,
        blinded_token: &BlindedToken,
        signed_token: &SignedToken,
        k: &SigningKey,
    ) -> Result<Self, TokenError>
    where
        D: Digest<OutputSize = U64> + Default,
        T: Rng + CryptoRng,
    {
        Self::_new::<D, T>(
            rng,
            blinded_token
                .0
                .decompress()
                .ok_or(TokenError(InternalError::PointDecompressionError))?,
            signed_token
                .0
                .decompress()
                .ok_or(TokenError(InternalError::PointDecompressionError))?,
            k,
        )
    }

    /// Verify the `DLEQProof`
    fn _verify<D>(
        &self,
        P: RistrettoPoint,
        Q: RistrettoPoint,
        public_key: &PublicKey,
    ) -> Result<(), TokenError>
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let X = public_key.X;
        let Y = public_key.Y;

        let A = (self.s
            * X.decompress()
                .ok_or(TokenError(InternalError::PointDecompressionError))?)
            + (self.c
                * Y.decompress()
                    .ok_or(TokenError(InternalError::PointDecompressionError))?);
        let B = (self.s * P) + (self.c * Q);

        let A = A.compress();
        let B = B.compress();
        let P = P.compress();
        let Q = Q.compress();

        let mut h = D::default();

        h.input(X.as_bytes());
        h.input(Y.as_bytes());
        h.input(P.as_bytes());
        h.input(Q.as_bytes());
        h.input(A.as_bytes());
        h.input(B.as_bytes());

        let c = Scalar::from_hash(h);

        if c == self.c {
            Ok(())
        } else {
            Err(TokenError(InternalError::VerifyError))
        }
    }

    /// Verify the `DLEQProof`
    pub fn verify<D>(
        &self,
        blinded_token: &BlindedToken,
        signed_token: &SignedToken,
        public_key: &PublicKey,
    ) -> Result<(), TokenError>
    where
        D: Digest<OutputSize = U64> + Default,
    {
        self._verify::<D>(
            blinded_token
                .0
                .decompress()
                .ok_or(TokenError(InternalError::PointDecompressionError))?,
            signed_token
                .0
                .decompress()
                .ok_or(TokenError(InternalError::PointDecompressionError))?,
            public_key,
        )
    }
}

impl DLEQProof {
    /// Convert this `DLEQProof` to a byte array.
    pub fn to_bytes(&self) -> [u8; DLEQ_PROOF_LENGTH] {
        let mut proof_bytes: [u8; DLEQ_PROOF_LENGTH] = [0u8; DLEQ_PROOF_LENGTH];

        proof_bytes[..32].copy_from_slice(&self.c.to_bytes());
        proof_bytes[32..].copy_from_slice(&self.s.to_bytes());
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

        let mut c_bits: [u8; 32] = [0u8; 32];
        let mut s_bits: [u8; 32] = [0u8; 32];

        c_bits.copy_from_slice(&bytes[..32]);
        s_bits.copy_from_slice(&bytes[32..]);

        let c = Scalar::from_canonical_bytes(c_bits)
            .ok_or(TokenError(InternalError::ScalarFormatError))?;
        let s = Scalar::from_canonical_bytes(s_bits)
            .ok_or(TokenError(InternalError::ScalarFormatError))?;

        Ok(DLEQProof { c, s })
    }
}

/// A `BatchDLEQProof` is a proof of the equivalence of the discrete logarithm between a common
/// pair of points and one or more other pairs of points.
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

        for (Pi, Qi) in blinded_tokens.iter().zip(signed_tokens.iter()) {
            h.input(Pi.0.as_bytes());
            h.input(Qi.0.as_bytes());
        }

        let result = h.result();

        let mut seed: [u8; 32] = [0u8; 32];
        seed.copy_from_slice(&result[..32]);

        let mut prng: ChaChaRng = SeedableRng::from_seed(seed);
        let c_m: Vec<Scalar> = iter::repeat_with(|| Scalar::random(&mut prng))
            .take(blinded_tokens.len())
            .collect();

        let M = RistrettoPoint::optional_multiscalar_mul(
            &c_m,
            blinded_tokens.iter().map(|Pi| Pi.0.decompress()),
        )
        .ok_or(TokenError(InternalError::PointDecompressionError))?;

        let Z = RistrettoPoint::optional_multiscalar_mul(
            &c_m,
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
        Ok(BatchDLEQProof(DLEQProof::_new::<D, T>(
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

        self.0._verify::<D>(M, Z, public_key)
    }
}

impl BatchDLEQProof {
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
