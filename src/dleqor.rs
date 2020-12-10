//! Code for DLEQOR proof.
#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[cfg(all(feature = "std"))]
use std::vec::Vec;

use core::iter;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{VartimeMultiscalarMul, MultiscalarMul};
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use crate::errors::{InternalError, TokenError};
use crate::pbtokens::*;

/// The length of a `DLEQProof`, in bytes.
pub const DLEQOR_PROOF_LENGTH: usize = 192;

/// A `DLEQProof` is a proof of the equivalence of the discrete logarithm between two pairs of points.
#[allow(non_snake_case)]
pub struct DLEQORProof {
    /// `challenges` are the challenge of the ZKP
    pub(crate) challenges: Vec<Scalar>,
    /// `responses` are the provers responses
    pub(crate) responses: Vec<(Scalar, Scalar)>,
}

#[cfg(any(test, feature = "base64"))]
impl_base64!(DLEQORProof);

#[cfg(feature = "serde")]
impl_serde!(DLEQORProof);

// todo: probably we want to give details of the proof itself.
/// Assignments used by the prover
pub struct ProveAssignments<'a> {
    /// x secret key used in the signature
    pub sk_x: &'a Scalar,
    /// y secret key used in the signature
    pub sk_y: &'a Scalar,
    /// Bit used to sign
    pub b: &'a usize,
    /// Public key 0
    pub pk_X0: &'a RistrettoPoint,
    /// Public key 1
    pub pk_X1: &'a RistrettoPoint,
    /// First generator
    pub G: &'a RistrettoPoint,
    /// Second generator
    pub H: &'a RistrettoPoint,
    /// Point `T`
    pub T: &'a RistrettoPoint,
    /// Point `S`
    pub S: &'a RistrettoPoint,
    /// Point `W`
    pub W: &'a RistrettoPoint,
}

/// Assignments used by the verifier
pub struct VerifyAssignments<'a> {
    /// Public key 0
    pub pk_X0: &'a CompressedRistretto,
    /// Public key 1
    pub pk_X1: &'a CompressedRistretto,
    /// First generator
    pub G: &'a CompressedRistretto,
    /// Second generator
    pub H: &'a CompressedRistretto,
    /// Point `T`
    pub T: &'a CompressedRistretto,
    /// Point `S`
    pub S: &'a CompressedRistretto,
    /// Point `W`
    pub W: &'a CompressedRistretto,
}

#[allow(non_snake_case)]
impl DLEQORProof {
    /// Construct a new `DLEQProof`
    // fn _new<D, T>(
    fn new_alone<D, T>(
        rng: &mut T,
        assignments: ProveAssignments,
    ) -> Result<Self, TokenError>
        where
            D: Digest<OutputSize = U64> + Default,
            T: Rng + CryptoRng,
    {
        let bit = *assignments.b;
        let commitment_secret = [Scalar::random(rng); 2];
        let simulated_secrets = [Scalar::random(rng); 3];

        let mut commitments = [constants::RISTRETTO_BASEPOINT_POINT; 2];
        let mut alt_commitments = [constants::RISTRETTO_BASEPOINT_POINT; 2];

        let public_keys = [*assignments.pk_X0, *assignments.pk_X1];
        let pk_generators = [*assignments.G, *assignments.H];
        let signature_generators = [*assignments.T, *assignments.S];
        let simulated_pk_generators = [public_keys[1-bit], *assignments.G, *assignments.H];
        let simulated_signature_generators = [*assignments.W, *assignments.T, *assignments.S];

        commitments[bit] = RistrettoPoint::multiscalar_mul(&commitment_secret, &pk_generators);
        commitments[1-bit] = RistrettoPoint::multiscalar_mul(&simulated_secrets, &simulated_pk_generators);

        alt_commitments[bit] = RistrettoPoint::multiscalar_mul(&commitment_secret, &signature_generators);
        alt_commitments[1-bit] = RistrettoPoint::multiscalar_mul(&simulated_secrets, &simulated_signature_generators);

        let h = D::default()
            .chain(constants::RISTRETTO_BASEPOINT_COMPRESSED.as_bytes())
            .chain(assignments.G.compress().as_bytes())
            .chain(assignments.H.compress().as_bytes())
            .chain(assignments.T.compress().as_bytes())
            .chain(assignments.S.compress().as_bytes())
            .chain(assignments.W.compress().as_bytes())
            .chain(assignments.pk_X0.compress().as_bytes())
            .chain(assignments.pk_X1.compress().as_bytes())
            .chain(commitments[0].compress().as_bytes())
            .chain(commitments[1].compress().as_bytes())
            .chain(alt_commitments[0].compress().as_bytes())
            .chain(alt_commitments[1].compress().as_bytes());


        let real_challenge = Scalar::from_hash(h);

        let mut challenges = vec![Scalar::zero(); 2];
        challenges[1-bit] = simulated_secrets[0];
        challenges[bit] = real_challenge - challenges[1-bit];

        let mut responses = vec![(Scalar::zero(), Scalar::zero()); 2];
        responses[1-bit] = (simulated_secrets[1], simulated_secrets[2]);
        responses[bit] = (
            commitment_secret[0] - challenges[bit] * assignments.sk_x,
            commitment_secret[1] - challenges[bit] * assignments.sk_y,
        );

        Ok(DLEQORProof {
            challenges,
            responses,
        })
    }

    // /// Construct a new `DLEQProof`
    // pub fn new<D, T>(
    //     rng: &mut T,
    //     blinded_token: &BlindedToken,
    //     signed_token: &SignedToken,
    //     k: &SigningKey,
    // ) -> Result<Self, TokenError>
    //     where
    //         D: Digest<OutputSize = U64> + Default,
    //         T: Rng + CryptoRng,
    // {
    //     Self::_new::<D, T>(
    //         rng,
    //         blinded_token
    //             .0
    //             .decompress()
    //             .ok_or(TokenError(InternalError::PointDecompressionError))?,
    //         signed_token
    //             .0
    //             .decompress()
    //             .ok_or(TokenError(InternalError::PointDecompressionError))?,
    //         k,
    //     )
    // }

    /// Verify the `DLEQProof`
    // fn _verify<D>(
    fn verify_alone<D>(
        &self,
        assignments: VerifyAssignments,
    ) -> Result<(), TokenError>
        where
            D: Digest<OutputSize = U64> + Default,
    {
        let commitments: [RistrettoPoint; 2] = [
            RistrettoPoint::multiscalar_mul(
                &[
                    self.challenges[0],
                    self.responses[0].0,
                    self.responses[0].1,
                ],
                &[assignments.pk_X0.decompress().unwrap(), assignments.G.decompress().unwrap(), assignments.H.decompress().unwrap()],
            ),
            RistrettoPoint::multiscalar_mul(
                &[
                    self.challenges[1],
                    self.responses[1].0,
                    self.responses[1].1,
                ],
                &[assignments.pk_X1.decompress().unwrap(), assignments.G.decompress().unwrap(), assignments.H.decompress().unwrap()],
            ),
        ];

        let simulated_commitments: [RistrettoPoint; 2] = [
            RistrettoPoint::multiscalar_mul(
                &[
                    self.challenges[0],
                    self.responses[0].0,
                    self.responses[0].1,
                ],
                &[assignments.W.decompress().unwrap(), assignments.T.decompress().unwrap(), assignments.S.decompress().unwrap()],
            ),
            RistrettoPoint::multiscalar_mul(
                &[
                    self.challenges[1],
                    self.responses[1].0,
                    self.responses[1].1,
                ],
                &[assignments.W.decompress().unwrap(), assignments.T.decompress().unwrap(), assignments.S.decompress().unwrap()],
            ),
        ];
        let h = D::default()
            .chain(constants::RISTRETTO_BASEPOINT_COMPRESSED.as_bytes())
            .chain(assignments.G.as_bytes())
            .chain(assignments.H.as_bytes())
            .chain(assignments.T.as_bytes())
            .chain(assignments.S.as_bytes())
            .chain(assignments.W.as_bytes())
            .chain(assignments.pk_X0.as_bytes())
            .chain(assignments.pk_X1.as_bytes())
            .chain(commitments[0].compress().as_bytes())
            .chain(commitments[1].compress().as_bytes())
            .chain(simulated_commitments[0].compress().as_bytes())
            .chain(simulated_commitments[1].compress().as_bytes());

        let real_challenge = Scalar::from_hash(h);

        if real_challenge == self.challenges[0] + self.challenges[1] {
            Ok(())
        } else {
            Err(TokenError(InternalError::VerifyError))
        }
    }

    // /// Verify the `DLEQProof`
    // pub fn verify<D>(
    //     &self,
    //     blinded_token: &BlindedToken,
    //     signed_token: &SignedToken,
    //     public_key: &PublicKey,
    // ) -> Result<(), TokenError>
    //     where
    //         D: Digest<OutputSize = U64> + Default,
    // {
    //     self._verify::<D>(
    //         blinded_token
    //             .0
    //             .decompress()
    //             .ok_or(TokenError(InternalError::PointDecompressionError))?,
    //         signed_token
    //             .0
    //             .decompress()
    //             .ok_or(TokenError(InternalError::PointDecompressionError))?,
    //         public_key,
    //     )
    // }
}

impl DLEQORProof {
    /// Convert this `DLEQProof` to a byte array.
    pub fn to_bytes(&self) -> [u8; DLEQOR_PROOF_LENGTH] {
        let mut proof_bytes: [u8; DLEQOR_PROOF_LENGTH] = [0u8; DLEQOR_PROOF_LENGTH];

        proof_bytes[..32].copy_from_slice(&self.challenges[0].to_bytes());
        proof_bytes[32..64].copy_from_slice(&self.challenges[1].to_bytes());
        proof_bytes[64..96].copy_from_slice(&self.responses[0].0.to_bytes());
        proof_bytes[96..128].copy_from_slice(&self.responses[0].1.to_bytes());
        proof_bytes[128..160].copy_from_slice(&self.responses[1].0.to_bytes());
        proof_bytes[160..].copy_from_slice(&self.responses[1].1.to_bytes());

        proof_bytes
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "DLEQProof",
            length: DLEQOR_PROOF_LENGTH,
        })
    }

    /// Construct a `DLEQProof` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<DLEQORProof, TokenError> {
        if bytes.len() != DLEQOR_PROOF_LENGTH {
            return Err(DLEQORProof::bytes_length_error());
        }

        let mut c_bits: [[u8; 32]; 2] = [[0u8; 32]; 2];
        let mut s_bits: [([u8; 32], [u8; 32]); 2] = [([0u8; 32], [0u8; 32]); 2];

        c_bits[0].copy_from_slice(&bytes[..32]);
        c_bits[1].copy_from_slice(&bytes[32..64]);
        s_bits[0].0.copy_from_slice(&bytes[64..96]);
        s_bits[0].1.copy_from_slice(&bytes[96..128]);
        s_bits[1].0.copy_from_slice(&bytes[128..160]);
        s_bits[1].1.copy_from_slice(&bytes[160..192]);

        let c = vec![
            Scalar::from_canonical_bytes(c_bits[0])
            .ok_or(TokenError(InternalError::ScalarFormatError))?,
            Scalar::from_canonical_bytes(c_bits[1])
                .ok_or(TokenError(InternalError::ScalarFormatError))?
            ];
        let s = vec![
            (
                Scalar::from_canonical_bytes(s_bits[0].0)
            .ok_or(TokenError(InternalError::ScalarFormatError))?,
                Scalar::from_canonical_bytes(s_bits[0].1)
                    .ok_or(TokenError(InternalError::ScalarFormatError))?
            ),
            (
                Scalar::from_canonical_bytes(s_bits[1].0)
                    .ok_or(TokenError(InternalError::ScalarFormatError))?,
                Scalar::from_canonical_bytes(s_bits[1].1)
                    .ok_or(TokenError(InternalError::ScalarFormatError))?
            )
            ];

        Ok(DLEQORProof { challenges: c, responses: s })
    }
}

/// A `BatchDLEQProof` is a proof of the equivalence of the discrete logarithm between a common
/// pair of points and one or more other pairs of points.
#[allow(non_snake_case)]
pub struct BatchDLEQORProof(DLEQORProof);

#[cfg(any(test, feature = "base64"))]
impl_base64!(BatchDLEQORProof);

#[cfg(feature = "serde")]
impl_serde!(BatchDLEQORProof);

#[allow(non_snake_case)]
impl BatchDLEQORProof {
    fn calculate_composites<D>(
        blinded_tokens: &[BlindedPbToken],
        signed_tokens: &[SignedPbToken],
        S_vector: &[RistrettoPoint],
        public_key: &PbPublicKey,
    ) -> Result<(RistrettoPoint, RistrettoPoint, RistrettoPoint), TokenError>
        where
            D: Digest<OutputSize = U64> + Default,
    {
        if blinded_tokens.len() != signed_tokens.len() {
            return Err(TokenError(InternalError::LengthMismatchError));
        }

        let mut h = D::default();

        // todo: ensure that we are including tau correctly
        h.input(constants::RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
        h.input(public_key.pk_X0.as_bytes());
        h.input(public_key.pk_X1.as_bytes());

        for (Pi, Qi) in blinded_tokens.iter().zip(signed_tokens.iter()) {
            h.input(Pi.0.as_bytes());
            h.input(Qi.seed);
            h.input(Qi.point.as_bytes());
        }

        for point in S_vector {
            h.input(point.compress().as_bytes());
        }

        let result = h.result();

        let mut seed: [u8; 32] = [0u8; 32];
        seed.copy_from_slice(&result[..32]);

        let mut prng: ChaChaRng = SeedableRng::from_seed(seed);
        let c_m: Vec<Scalar> = iter::repeat_with(|| Scalar::random(&mut prng))
            .take(blinded_tokens.len())
            .collect();

        let T_bar = RistrettoPoint::optional_multiscalar_mul(
            &c_m,
            blinded_tokens.iter().map(|Pi| Pi.0.decompress()),
        )
            .ok_or(TokenError(InternalError::PointDecompressionError))?;

        let S_bar = RistrettoPoint::multiscalar_mul(
            &c_m,
            S_vector,
        );

        let W_bar = RistrettoPoint::optional_multiscalar_mul(
            &c_m,
            signed_tokens.iter().map(|Qi| Qi.point.decompress())
        )
            .ok_or(TokenError(InternalError::PointDecompressionError))?;

        Ok((T_bar, S_bar, W_bar))
    }

    /// Construct a new `BatchDLEQProof`
    pub fn new<D, T>(
        rng: &mut T,
        blinded_tokens: &[BlindedPbToken],
        signed_tokens: &[SignedPbToken],
        signing_key: &PbSigningKey,
        bit: bool,
    ) -> Result<Self, TokenError>
        where
            D: Digest<OutputSize = U64> + Default,
            T: Rng + CryptoRng,
    {
        let mut S_vector = Vec::new();
        for (bt, st) in blinded_tokens.iter().zip(signed_tokens.iter()) {
            let mut hash = D::default();
            hash.input(b"hash_derive_signing_point");
            hash.input(st.seed);
            hash.input(bt.0.as_bytes());

            S_vector.push(RistrettoPoint::from_hash(hash));
        }

        let (T_bar, S_bar, W_bar) = BatchDLEQORProof::calculate_composites::<D>(
            blinded_tokens,
            signed_tokens,
            &S_vector,
            &signing_key.public_key,
        )?;

        // todo: handle these decompressions correctly
        let prover_assignments = ProveAssignments{
            sk_x: &signing_key.sk_x[bit as usize],
            sk_y: &signing_key.sk_y[bit as usize],
            b: &(bit as usize),
            pk_X0: &signing_key.public_key.pk_X0.decompress().unwrap(),
            pk_X1: &signing_key.public_key.pk_X1.decompress().unwrap(),
            G: &constants::RISTRETTO_BASEPOINT_POINT,
            H: &constants::RISTRETTO_BASEPOINT_POINT,
            T: &T_bar,
            S: &S_bar,
            W: &W_bar,
        };

        Ok(BatchDLEQORProof(DLEQORProof::new_alone::<D, T>(
            rng,
            prover_assignments
        )?))
    }

    /// Verify a `BatchDLEQProof`
    pub fn verify<D>(
        &self,
        blinded_tokens: &[BlindedPbToken],
        signed_tokens: &[SignedPbToken],
        public_key: &PbPublicKey,
    ) -> Result<(), TokenError>
        where
            D: Digest<OutputSize = U64> + Default,
    {
        let mut S_vector = Vec::new();
        for (bt, st) in blinded_tokens.iter().zip(signed_tokens.iter()) {
            let mut hash = D::default();
            hash.input(b"hash_derive_signing_point");
            hash.input(st.seed);
            hash.input(bt.0.as_bytes());

            S_vector.push(RistrettoPoint::from_hash(hash));
        }

        let (T_bar, S_bar, W_bar) =
            BatchDLEQORProof::calculate_composites::<D>(blinded_tokens, signed_tokens, &S_vector, public_key)?;

        let verify_assignments = VerifyAssignments{
            pk_X0: &public_key.pk_X0,
            pk_X1: &public_key.pk_X1,
            G: &constants::RISTRETTO_BASEPOINT_COMPRESSED,
            H: &constants::RISTRETTO_BASEPOINT_COMPRESSED,
            T: &T_bar.compress(),
            S: &S_bar.compress(),
            W: &W_bar.compress(),
        };

        self.0.verify_alone::<D>(verify_assignments)
    }

    /// Verify the `BatchDLEQProof` then unblind the `SignedToken`s using each corresponding `Token`
    pub fn verify_and_unblind<'a, D, I>(
        &self,
        tokens: I,
        blinded_tokens: &[BlindedPbToken],
        signed_tokens: &[SignedPbToken],
        public_key: &PbPublicKey,
    ) -> Result<Vec<UnblindedPbToken>, TokenError>
        where
            D: Digest<OutputSize = U64> + Default,
            I: IntoIterator<Item = &'a PbToken>,
    {
        self.verify::<D>(blinded_tokens, signed_tokens, public_key)?;

        let unblinded_tokens: Result<Vec<UnblindedPbToken>, TokenError> = tokens
            .into_iter()
            .zip(signed_tokens.iter())
            .map(|(token, signed_token)| token.unblind::<D>(signed_token))
            .collect();
        unblinded_tokens.and_then(|unblinded_tokens| {
            if unblinded_tokens.len() != signed_tokens.len() {
                return Err(TokenError(InternalError::LengthMismatchError));
            }
            Ok(unblinded_tokens)
        })
    }
}

impl BatchDLEQORProof {
    /// Convert this `BatchDLEQProof` to a byte array.
    pub fn to_bytes(&self) -> [u8; DLEQOR_PROOF_LENGTH] {
        self.0.to_bytes()
    }

    #[cfg(feature = "serde")]
    fn bytes_length_error() -> TokenError {
        DLEQORProof::bytes_length_error()
    }

    /// Construct a `BatchDLEQProof` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<BatchDLEQORProof, TokenError> {
        DLEQORProof::from_bytes(bytes).map(BatchDLEQORProof)
    }
}

// todo: we definitely want more tests here

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Sha512;

    #[test]
    fn it_works_dleqor() {
        let mut csrng = rand::rngs::OsRng;

        let x = Scalar::random(&mut csrng);
        let y = Scalar::random(&mut csrng);
        let G = RistrettoPoint::random(&mut csrng);
        let H = RistrettoPoint::random(&mut csrng);
        let S = RistrettoPoint::random(&mut csrng);
        let T = RistrettoPoint::random(&mut csrng);
        let W = RistrettoPoint::multiscalar_mul(&[x, y], &[T, S]);
        let X1 = RistrettoPoint::multiscalar_mul(&[x, y], &[G, H]);
        let X0 = RistrettoPoint::random(&mut csrng);
        let b = 1usize;

        let proof = self::DLEQORProof::new_alone::<Sha512, rand::rngs::OsRng>(
            &mut csrng,
            ProveAssignments {
                sk_x: &x,
                sk_y: &y,
                b: &b,
                pk_X0: &X0,
                pk_X1: &X1,
                G: &G,
                H: &H,
                T: &T,
                S: &S,
                W: &W,
            },
        ).unwrap();

        let verification = proof.verify_alone::<Sha512>(
            VerifyAssignments {
                pk_X0: &X0.compress(),
                pk_X1: &X1.compress(),
                G: &G.compress(),
                H: &H.compress(),
                T: &T.compress(),
                S: &S.compress(),
                W: &W.compress(),
            },
        );
        assert!(verification.is_ok());
    }

    #[test]
    fn to_bytes_works() {
        let mut csrng = rand::rngs::OsRng;

        let x = Scalar::random(&mut csrng);
        let y = Scalar::random(&mut csrng);
        let G = RistrettoPoint::random(&mut csrng);
        let H = RistrettoPoint::random(&mut csrng);
        let S = RistrettoPoint::random(&mut csrng);
        let T = RistrettoPoint::random(&mut csrng);
        let W = RistrettoPoint::multiscalar_mul(&[x, y], &[T, S]);
        let X1 = RistrettoPoint::multiscalar_mul(&[x, y], &[G, H]);
        let X0 = RistrettoPoint::random(&mut csrng);
        let b = 1usize;

        let proof = self::DLEQORProof::new_alone::<Sha512, rand::rngs::OsRng>(
            &mut csrng,
            ProveAssignments {
                sk_x: &x,
                sk_y: &y,
                b: &b,
                pk_X0: &X0,
                pk_X1: &X1,
                G: &G,
                H: &H,
                T: &T,
                S: &S,
                W: &W,
            },
        ).unwrap();

        let proof_bytes = proof.to_bytes();

        let reconverted_proof = self::DLEQORProof::from_bytes(&proof_bytes).unwrap();

        let verification = reconverted_proof.verify_alone::<Sha512>(
            VerifyAssignments {
                pk_X0: &X0.compress(),
                pk_X1: &X1.compress(),
                G: &G.compress(),
                H: &H.compress(),
                T: &T.compress(),
                S: &S.compress(),
                W: &W.compress(),
            },
        );
        assert!(verification.is_ok());
    }

}
