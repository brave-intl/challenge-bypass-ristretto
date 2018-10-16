use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::IsIdentity;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand::{ChaChaRng, CryptoRng, Rng, SeedableRng};

use errors::{InternalError, TokenError};
use vorpf::{BlindedToken, PublicKey, SignedToken, SigningKey};

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
}

/// A `BatchDLEQProof` is a proof of the equivalence of the discrete logarithm between a common
/// pair of points and one or more other pairs of points.
#[repr(C)]
#[allow(non_snake_case)]
pub struct BatchDLEQProof(DLEQProof);

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

        let mut prng: ChaChaRng = SeedableRng::from_seed(seed);

        let identity: RistrettoPoint = Default::default();
        debug_assert!(identity.is_identity());

        let (M, Z): (RistrettoPoint, RistrettoPoint) = blinded_tokens
            .iter()
            .zip(signed_tokens.iter())
            .try_fold((identity, identity), |(M, Z), (Pi, Qi)| {
                let ci = Scalar::random(&mut prng);
                let cM = ci * Pi
                    .0
                    .decompress()
                    .ok_or(TokenError(InternalError::PointDecompressionError))?;
                let cZ = ci * Qi
                    .0
                    .decompress()
                    .ok_or(TokenError(InternalError::PointDecompressionError))?;
                Ok((M + cM, Z + cZ))
            })?;

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
}
