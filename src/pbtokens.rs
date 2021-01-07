//! Implementation of the private bit privacy pass tokens
use core::fmt::Debug;

use clear_on_drop::clear::Clear;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::typenum::U64;
use digest::Digest;
use hmac::{Mac, NewMac};
use rand::{CryptoRng, Rng};
use std::convert::TryInto;

use sha2::Sha512;

#[cfg(any(feature = "base64", feature = "serde"))]
use hmac::digest::generic_array::GenericArray;

use crate::errors::{InternalError, TokenError};

/// The length of a `PbTokenPreimage`, in bytes.
pub const PBTOKEN_PREIMAGE_LENGTH: usize = 64;
/// The length of a `PbToken`, in bytes.
pub const PBTOKEN_LENGTH: usize = PBTOKEN_PREIMAGE_LENGTH + 32;
/// The length of a `BlindedPbToken`, in bytes.
pub const BLINDED_PBTOKEN_LENGTH: usize = 32;
/// The length of a `PbPublicKey`, in bytes.
pub const PB_PUBLIC_KEY_LENGTH: usize = 64;
/// The length of a `PbSigningKey`, in bytes.
pub const PB_SIGNING_KEY_LENGTH: usize = 128;
/// The length of a `SignedPbToken`, in bytes.
pub const SIGNED_PBTOKEN_LENGTH: usize = 32 + PBTOKEN_PREIMAGE_LENGTH;
/// The length of a `UnblindedPbToken`, in bytes.
pub const UNBLINDED_PBTOKEN_LENGTH: usize = 64 + PBTOKEN_PREIMAGE_LENGTH;
/// The length of a `PbVerificationSignature`, in bytes.
pub const PB_VERIFICATION_SIGNATURE_LENGTH: usize = 64;

lazy_static! {
    /// Second generator used in PbTokens protocol
    pub static ref H_GENERATOR: RistrettoPoint = RistrettoPoint::hash_from_bytes::<Sha512>(
            b"Second generator used in the DLEQOR proof, should have unknown DLOG with the generator .__."
        );
}

/// A `PbTokenPreimage` is a slice of bytes which can be hashed to a `RistrettoPoint`.
///
/// The hash function must ensure the discrete log with respect to other points is unknown.
/// In this construction `RistrettoPoint::from_uniform_bytes` is used as the hash function.
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Copy, Clone)]
pub struct PbTokenPreimage([u8; PBTOKEN_PREIMAGE_LENGTH]);

impl PartialEq for PbTokenPreimage {
    fn eq(&self, other: &PbTokenPreimage) -> bool {
        &self.0[..] == &other.0[..]
    }
}

#[cfg(any(test, feature = "base64"))]
impl_base64!(PbTokenPreimage);

#[cfg(feature = "serde")]
impl_serde!(PbTokenPreimage);

impl Debug for PbTokenPreimage {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "PbTokenPreimage: {:?}", &self.0[..])
    }
}

#[allow(non_snake_case)]
impl PbTokenPreimage {
    pub(crate) fn T(&self) -> RistrettoPoint {
        RistrettoPoint::from_uniform_bytes(&self.0)
    }

    /// Convert this `PbTokenPreimage` to a byte array.
    pub fn to_bytes(&self) -> [u8; PBTOKEN_PREIMAGE_LENGTH] {
        self.0
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "PbTokenPreimage",
            length: PBTOKEN_PREIMAGE_LENGTH,
        })
    }

    /// Construct a `PbTokenPreimage` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<PbTokenPreimage, TokenError> {
        if bytes.len() != PBTOKEN_PREIMAGE_LENGTH {
            return Err(PbTokenPreimage::bytes_length_error());
        }

        let mut bits: [u8; PBTOKEN_PREIMAGE_LENGTH] = [0u8; PBTOKEN_PREIMAGE_LENGTH];
        bits.copy_from_slice(&bytes);
        Ok(PbTokenPreimage(bits))
    }
}

/// A `PbToken` consists of a randomly chosen preimage and blinding factor.
///
/// Since a token includes the blinding factor it should be treated
/// as a client secret and NEVER revealed to the server.
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Debug)]
pub struct PbToken {
    /// `t` is a `PbTokenPreimage`
    pub(crate) t: PbTokenPreimage,
    /// `r` is a `Scalar` which is the blinding factor
    r: Scalar,
}

/// Overwrite the token blinding factor with null when it goes out of scope.
impl Drop for PbToken {
    fn drop(&mut self) {
        self.r.clear();
    }
}

#[cfg(any(test, feature = "base64"))]
impl_base64!(PbToken);

#[cfg(feature = "serde")]
impl_serde!(PbToken);

#[allow(non_snake_case)]
impl PbToken {
    /// Generates a new random `PbToken` using the provided random number generator.
    pub fn random<D, T>(rng: &mut T) -> Self
        where
            D: Digest<OutputSize = U64> + Default,
            T: Rng + CryptoRng,
    {
        let mut seed = [0u8; 64];
        rng.fill(&mut seed);
        let blinding_scalar = Scalar::random(rng);
        Self::hash_from_bytes_with_blind::<D>(&seed, blinding_scalar)
    }

    /// Creates a new `PbToken`, using hashing to derive a `PbTokenPreimage` and the specified blind
    pub(crate) fn hash_from_bytes_with_blind<D>(bytes: &[u8], blinding_scalar: Scalar) -> Self
        where
            D: Digest<OutputSize = U64> + Default,
    {
        let mut hash = D::default();
        let mut seed = [0u8; 64];
        hash.update(bytes);
        seed.copy_from_slice(&hash.finalize().as_slice());

        PbToken {
            t: PbTokenPreimage(seed),
            r: blinding_scalar,
        }
    }

    /// Creates a new `PbToken`, using hashing to derive a `PbTokenPreimage` and a random blind
    pub fn hash_from_bytes<D, T>(rng: &mut T, bytes: &[u8]) -> Self
        where
            D: Digest<OutputSize = U64> + Default,
            T: Rng + CryptoRng,
    {
        let blinding_scalar = Scalar::random(rng);
        Self::hash_from_bytes_with_blind::<D>(bytes, blinding_scalar)
    }

    /// Blinds the `PbToken`, returning a `BlindedPbToken` to be sent to the server.
    pub fn blind(&self) -> BlindedPbToken {
        BlindedPbToken((self.r * self.t.T()).compress())
    }

    /// Using the blinding factor of the original `PbToken`, unblind a `SignedPbToken`
    /// returned from the server.
    ///
    /// Returns a `PbTokenError` if the `SignedPbToken` point is not valid.
    pub (crate) fn unblind<D>(&self, Q: &SignedPbToken) -> Result<UnblindedPbToken, TokenError>
    where
        D: Digest<OutputSize = U64> + Default,
    {
        // todo: ensure these things coincide with the generation
        let T = self.r * RistrettoPoint::from_uniform_bytes(&self.t.0);
        let mut hash = D::default();
        hash.update(b"hash_derive_signing_point");
        hash.update(Q.seed);
        hash.update(T.compress().as_bytes());

        let S = RistrettoPoint::from_hash(hash);
        let decompressed_Q = Q.point
            .decompress()
            .ok_or(TokenError(InternalError::PointDecompressionError))?;

        let unblinded_S = self.r.invert() * S;
        let unblinded_W = self.r.invert() * decompressed_Q;
        Ok(UnblindedPbToken {
            t: self.t,
            sigma: [unblinded_S.compress(), unblinded_W.compress()]
        })
    }

    /// Convert this `PbToken` to a byte array.
    pub fn to_bytes(&self) -> [u8; PBTOKEN_LENGTH] {
        let mut token_bytes: [u8; PBTOKEN_LENGTH] = [0u8; PBTOKEN_LENGTH];

        token_bytes[..PBTOKEN_PREIMAGE_LENGTH].copy_from_slice(&self.t.to_bytes());
        token_bytes[PBTOKEN_PREIMAGE_LENGTH..].copy_from_slice(&self.r.to_bytes());
        token_bytes
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "PbToken",
            length: PBTOKEN_LENGTH,
        })
    }

    /// Construct a `PbToken` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<PbToken, TokenError> {
        if bytes.len() != PBTOKEN_LENGTH {
            return Err(PbToken::bytes_length_error());
        }

        let preimage = PbTokenPreimage::from_bytes(&bytes[..PBTOKEN_PREIMAGE_LENGTH])?;

        let mut blinding_factor_bits: [u8; 32] = [0u8; 32];
        blinding_factor_bits.copy_from_slice(&bytes[PBTOKEN_PREIMAGE_LENGTH..]);
        let blinding_factor = Scalar::from_canonical_bytes(blinding_factor_bits)
            .ok_or(TokenError(InternalError::ScalarFormatError))?;

        Ok(PbToken {
            t: preimage,
            r: blinding_factor,
        })
    }
}

/// A `BlindedPbToken` is sent to the server for signing.
///
/// It is the result of the scalar multiplication of the point derived from the token
/// preimage with the blinding factor.
///
/// \\(P = T^r = H_1(t)^r\\)
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Copy, Clone, Debug)]
pub struct BlindedPbToken(pub(crate) CompressedRistretto);

#[cfg(any(test, feature = "base64"))]
impl_base64!(BlindedPbToken);

#[cfg(feature = "serde")]
impl_serde!(BlindedPbToken);

impl BlindedPbToken {
    /// Convert this `BlindedPbToken` to a byte array.
    pub fn to_bytes(&self) -> [u8; BLINDED_PBTOKEN_LENGTH] {
        self.0.to_bytes()
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "BlindedPbToken",
            length: BLINDED_PBTOKEN_LENGTH,
        })
    }

    /// Construct a `BlindedPbToken` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<BlindedPbToken, TokenError> {
        if bytes.len() != BLINDED_PBTOKEN_LENGTH {
            return Err(BlindedPbToken::bytes_length_error());
        }

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);
        Ok(BlindedPbToken(CompressedRistretto(bits)))
    }
}

/// A `PbPublicKey` is a committment by the server to a particular `PbSigningKey`.
///
/// \\(Y = X^k\\)
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Copy, Clone, Debug)]
#[allow(non_snake_case)]
pub struct PbPublicKey {
    pub(crate) pk_X0: CompressedRistretto,
    pub(crate) pk_X1: CompressedRistretto,
}

#[cfg(any(test, feature = "base64"))]
impl_base64!(PbPublicKey);

#[cfg(feature = "serde")]
impl_serde!(PbPublicKey);

impl PbPublicKey {
    /// Convert this `PbPublicKey` to a byte array.
    pub fn to_bytes(&self) -> [u8; PB_PUBLIC_KEY_LENGTH] {
        let mut pk_bytes: [u8; PB_PUBLIC_KEY_LENGTH] = [0u8; PB_PUBLIC_KEY_LENGTH];

        pk_bytes[..32].copy_from_slice(&self.pk_X0.to_bytes());
        pk_bytes[32..].copy_from_slice(&self.pk_X1.to_bytes());
        pk_bytes
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "PbPublicKey",
            length: PB_PUBLIC_KEY_LENGTH,
        })
    }

    /// Construct a `PbPublicKey` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<PbPublicKey, TokenError> {
        if bytes.len() != PB_PUBLIC_KEY_LENGTH {
            return Err(PbPublicKey::bytes_length_error());
        }

        let mut bits_x0: [u8; 32] = [0u8; 32];
        bits_x0.copy_from_slice(&bytes[..32]);
        let mut bits_x1: [u8; 32] = [0u8; 32];
        bits_x1.copy_from_slice(&bytes[32..]);

        Ok(PbPublicKey {
            pk_X0: CompressedRistretto(bits_x0),
            pk_X1: CompressedRistretto(bits_x1),
        })
    }
}

/// A `PbSigningKey` is used to sign a `BlindedPbToken` and verify an `UnblindedPbToken`.
///
/// This is a server secret and should NEVER be revealed to the client.
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Debug)]
pub struct PbSigningKey {
    /// A `PbPublicKey` showing a committment to this particular key
    pub public_key: PbPublicKey,
    /// `k` is the actual key
    pub(crate) sk_x: [Scalar; 2],
    pub(crate) sk_y: [Scalar; 2],
}

#[cfg(any(test, feature = "base64"))]
impl_base64!(PbSigningKey);

#[cfg(feature = "serde")]
impl_serde!(PbSigningKey);

/// Overwrite signing key with null when it goes out of scope.
impl Drop for PbSigningKey {
    fn drop(&mut self) {
        self.sk_x[0].clear();
        self.sk_x[1].clear();
        self.sk_y[0].clear();
        self.sk_y[1].clear();
    }
}

#[allow(non_snake_case)]
impl PbSigningKey {
    /// Generates a new random `PbSigningKey` using the provided random number generator.
    pub fn random<T: Rng + CryptoRng>(rng: &mut T) -> Self {
        let (mut pk_X0, mut pk_X1) = (constants::RISTRETTO_BASEPOINT_POINT, constants::RISTRETTO_BASEPOINT_POINT);
        let (mut sk_x, mut sk_y) = ([Scalar::zero(); 2], [Scalar::zero(); 2]);
        while pk_X0 == pk_X1 {
            sk_x = [Scalar::random(rng), Scalar::random(rng)];
            sk_y = [Scalar::random(rng), Scalar::random(rng)];

            pk_X0 = &sk_x[0] * &constants::RISTRETTO_BASEPOINT_TABLE + &sk_y[0] * &(*H_GENERATOR);
            pk_X1 = &sk_x[1] * &constants::RISTRETTO_BASEPOINT_TABLE + &sk_y[1] * &(*H_GENERATOR);
        }
        PbSigningKey {
            sk_x,
            sk_y,
            public_key: PbPublicKey {pk_X0: pk_X0.compress(), pk_X1: pk_X1.compress()},
        }
    }

    /// Signs the provided `BlindedPbToken`, and returns the point `S` needed in the ZKP.
    ///
    /// Returns None if the `BlindedPbToken` point is not valid.
    pub fn sign<D, T>(&self, P: &BlindedPbToken, bit: bool, rng: &mut T) -> Result<(SignedPbToken, RistrettoPoint), TokenError>
    where
        D: Digest<OutputSize = U64> + Default,
        T: Rng + CryptoRng,
    {
        let mut seed = [0u8; PBTOKEN_PREIMAGE_LENGTH];
        rng.fill(&mut seed);

        let mut hash = D::default();
        hash.update(b"hash_derive_signing_point");
        hash.update(seed);
        hash.update(P.0.as_bytes());

        let S = RistrettoPoint::from_hash(hash);
        let decompressed_token = P.0
            .decompress()
            .ok_or(TokenError(InternalError::PointDecompressionError))?;
        let W = self.sk_x[bit as usize] * decompressed_token  + self.sk_y[bit as usize] * S;

        Ok((SignedPbToken {
            point: W.compress(),
            seed,
        }, S))
    }

    // todo: Give a more thorough description of the function
    /// Check signature bit of received token. This checks the validity and the bit with
    /// which it was signed.
    pub fn check_signature_bit(&self, token: &UnblindedPbToken) -> Result<bool, TokenError>
    {
        let T = token.t.T();
        let S = token.sigma[0]
            .decompress()
            .ok_or(TokenError(InternalError::PointDecompressionError))?;
        let w_1 = &self.sk_x[0] * &T + &self.sk_y[0] * &S;
        let w_2 = &self.sk_x[1] * &T + &self.sk_y[1] * &S;

        if token.sigma[1] == w_1.compress() && token.sigma[1] != w_2.compress() {
            Ok(false)
        }
        else if token.sigma[1] != w_1.compress() && token.sigma[1] == w_2.compress() {
            Ok(true)
        }
        else {
            Err(TokenError(InternalError::VerifyError))
        }
    }


    /// Convert this `PbSigningKey` to a byte array.
    pub fn to_bytes(&self) -> [u8; PB_SIGNING_KEY_LENGTH] {
        let mut sk_bytes: [u8; PB_SIGNING_KEY_LENGTH] = [0u8; PB_SIGNING_KEY_LENGTH];

        sk_bytes[..32].copy_from_slice(&self.sk_x[0].to_bytes());
        sk_bytes[32..64].copy_from_slice(&self.sk_x[1].to_bytes());
        sk_bytes[64..96].copy_from_slice(&self.sk_y[0].to_bytes());
        sk_bytes[96..128].copy_from_slice(&self.sk_y[1].to_bytes());
        sk_bytes
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "PbSigningKey",
            length: PB_SIGNING_KEY_LENGTH,
        })
    }

    /// Construct a `PbSigningKey` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<PbSigningKey, TokenError> {
        if bytes.len() != PB_SIGNING_KEY_LENGTH {
            return Err(PbSigningKey::bytes_length_error());
        }

        let mut bits_x0: [u8; 32] = [0u8; 32];
        let mut bits_x1: [u8; 32] = [0u8; 32];
        let mut bits_y0: [u8; 32] = [0u8; 32];
        let mut bits_y1: [u8; 32] = [0u8; 32];

        bits_x0.copy_from_slice(&bytes[..32]);
        bits_x1.copy_from_slice(&bytes[32..64]);
        bits_y0.copy_from_slice(&bytes[64..96]);
        bits_y1.copy_from_slice(&bytes[96..128]);

        let x0 = Scalar::from_canonical_bytes(bits_x0)
            .ok_or(TokenError(InternalError::ScalarFormatError))?;
        let x1 = Scalar::from_canonical_bytes(bits_x1)
            .ok_or(TokenError(InternalError::ScalarFormatError))?;
        let y0 = Scalar::from_canonical_bytes(bits_y0)
            .ok_or(TokenError(InternalError::ScalarFormatError))?;
        let y1 = Scalar::from_canonical_bytes(bits_y1)
            .ok_or(TokenError(InternalError::ScalarFormatError))?;

        let pk_X0 = &x0 * &constants::RISTRETTO_BASEPOINT_TABLE + &y0 * &(*H_GENERATOR);
        let pk_X1 = &x1 * &constants::RISTRETTO_BASEPOINT_TABLE + &y1 * &(*H_GENERATOR);

        Ok(PbSigningKey {
            public_key: PbPublicKey {pk_X0: pk_X0.compress(), pk_X1: pk_X1.compress()},
            sk_x: [x0, x1],
            sk_y: [y0, y1],
        })
    }
}

/// A `SignedPbToken` is the result of signing a `BlindedPbToken`.
///
/// \\(Q = P^k = (T^r)^k\\)
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Copy, Clone, Debug)]
pub struct SignedPbToken {
    pub(crate) point: CompressedRistretto,
    pub(crate) seed: [u8; PBTOKEN_PREIMAGE_LENGTH],
}

#[cfg(any(test, feature = "base64"))]
impl_base64!(SignedPbToken);

#[cfg(feature = "serde")]
impl_serde!(SignedPbToken);

impl SignedPbToken {
    /// Convert this `SignedPbToken` to a byte array.
    pub fn to_bytes(&self) -> [u8; SIGNED_PBTOKEN_LENGTH] {
        let mut st_bytes: [u8; SIGNED_PBTOKEN_LENGTH] = [0u8; SIGNED_PBTOKEN_LENGTH];

        st_bytes[..PBTOKEN_PREIMAGE_LENGTH].copy_from_slice(&self.seed);
        st_bytes[PBTOKEN_PREIMAGE_LENGTH..].copy_from_slice(&self.point.to_bytes());
        st_bytes
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "SignedPbToken",
            length: SIGNED_PBTOKEN_LENGTH,
        })
    }

    /// Construct a `SignedPbToken` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<SignedPbToken, TokenError> {
        if bytes.len() != SIGNED_PBTOKEN_LENGTH {
            return Err(SignedPbToken::bytes_length_error());
        }

        let mut bits_seed: [u8; PBTOKEN_PREIMAGE_LENGTH] = [0u8; PBTOKEN_PREIMAGE_LENGTH];
        let mut bits_point: [u8; 32] = [0u8; 32];
        bits_seed.copy_from_slice(&bytes[..PBTOKEN_PREIMAGE_LENGTH]);
        bits_point.copy_from_slice(&bytes[PBTOKEN_PREIMAGE_LENGTH..]);
        Ok(
            SignedPbToken {
                point: CompressedRistretto(bits_point),
                seed: bits_seed
            }
        )
    }
}

/// An `UnblindedPbToken` is the result of unblinding a `SignedPbToken`.
///
/// While both the client and server both "know" this value,
/// it should nevertheless not be sent between the two.
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[allow(non_snake_case)]
#[derive(Clone, Copy, Debug)]
pub struct UnblindedPbToken {
    /// `t` is the `PbTokenPreimage`
    pub t: PbTokenPreimage,
    /// `sigma` is the unblinded values S and W
    ///
    /// \\(S = S'^{1/r}\\)
    /// \\(W = W'^{1/r}\\)
    sigma: [CompressedRistretto; 2],
}

#[cfg(any(test, feature = "base64"))]
impl_base64!(UnblindedPbToken);

#[cfg(feature = "serde")]
impl_serde!(UnblindedPbToken);

impl UnblindedPbToken {
    /// Derive the `PbVerificationKey` for this particular `UnblindedPbToken`
    pub fn derive_verification_key<D>(&self) -> PbVerificationKey
        where
            D: Digest<OutputSize = U64> + Default,
    {
        let mut hash = D::default();
        hash.update(b"hash_derive_key");

        hash.update(self.t.0.as_ref());
        hash.update(self.sigma[0].as_bytes());
        hash.update(self.sigma[1].as_bytes());

        let output = hash.finalize();
        let mut output_bytes = [0u8; 64];
        output_bytes.copy_from_slice(&output.as_slice());

        PbVerificationKey(output_bytes)
    }

    /// Convert this `UnblindedPbToken` to a byte array.
    pub fn to_bytes(&self) -> [u8; UNBLINDED_PBTOKEN_LENGTH] {
        let mut unblinded_token_bytes: [u8; UNBLINDED_PBTOKEN_LENGTH] = [0u8; UNBLINDED_PBTOKEN_LENGTH];

        unblinded_token_bytes[..32].copy_from_slice(&self.sigma[0].to_bytes());
        unblinded_token_bytes[32..64].copy_from_slice(&self.sigma[1].to_bytes());
        unblinded_token_bytes[64..].copy_from_slice(&self.t.to_bytes());
        unblinded_token_bytes
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "UnblindedPbToken",
            length: UNBLINDED_PBTOKEN_LENGTH,
        })
    }

    /// Construct a `UnblindedPbToken` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<UnblindedPbToken, TokenError> {
        if bytes.len() != UNBLINDED_PBTOKEN_LENGTH {
            return Err(UnblindedPbToken::bytes_length_error());
        }

        let preimage = PbTokenPreimage::from_bytes(&bytes[64..])?;

        let mut sigma_s_bits: [u8; 32] = [0u8; 32];
        let mut sigma_w_bits: [u8; 32] = [0u8; 32];
        sigma_s_bits.copy_from_slice(&bytes[..32]);
        sigma_w_bits.copy_from_slice(&bytes[32..64]);
        Ok(UnblindedPbToken {
            t: preimage,
            sigma: [CompressedRistretto(sigma_s_bits), CompressedRistretto(sigma_w_bits)],
        })
    }
}

/// The shared `PbVerificationKey` for proving / verifying the validity of an `UnblindedPbToken`.
///
/// \\(K = H_2(t, W)\\)
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
pub struct PbVerificationKey([u8; 64]);

impl Debug for PbVerificationKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "VerificationKey: {:?}", &self.0[..])
    }
}

impl PbVerificationKey {
    /// Use the `PbVerificationKey` to "sign" a message, producing a `PbVerificationSignature`
    pub fn sign<D>(&self, message: &[u8]) -> PbVerificationSignature
        where
            D: Mac<OutputSize = U64> + NewMac,
    {
        let mut mac = D::new_varkey(self.0.as_ref()).unwrap();
        mac.update(message);

        PbVerificationSignature(mac
            .finalize()
            .into_bytes()
            .as_slice()
            .try_into()
            .expect("Output size is U64")
        )
    }

    /// Use the `PbVerificationKey` to check that the signature of a message matches the
    /// provided `PbVerificationSignature`
    pub fn verify<D>(&self, sig: &PbVerificationSignature, message: &[u8]) -> bool
        where
            D: Mac<OutputSize = U64> + NewMac,
    {
        &self.sign::<D>(message) == sig
    }
}

/// A `PbVerificationSignature` which can be verified given the `PbVerificationKey` and message
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
pub struct PbVerificationSignature([u8; PB_VERIFICATION_SIGNATURE_LENGTH]);

#[cfg(any(test, feature = "base64"))]
impl_base64!(PbVerificationSignature);

#[cfg(feature = "serde")]
impl_serde!(PbVerificationSignature);

impl PartialEq for PbVerificationSignature {
    fn eq(&self, other: &PbVerificationSignature) -> bool {
        // These useless slices make the optimizer elide the bounds checks.
        // See the comment in clone_from_slice() added on Rust commit 6a7bc47.
        // Reproducing constant time implementation of crate `constant_time_eq`,
        // to avoid another dependency.
        let a = &self.0[..PB_VERIFICATION_SIGNATURE_LENGTH];
        let b = &other.0[..PB_VERIFICATION_SIGNATURE_LENGTH];
        let mut comparison = 0;
        for i in 0..PB_VERIFICATION_SIGNATURE_LENGTH {
            comparison |= a[i] ^ b[i];
        }
        comparison == 0
    }
}

#[cfg(any(test, feature = "base64", feature = "serde"))]
impl PbVerificationSignature {
    /// Convert this `VerificationSignature` to a byte array.
    /// We intentionally keep this private to avoid accidental non constant time comparisons
    fn to_bytes(&self) -> [u8; PB_VERIFICATION_SIGNATURE_LENGTH] {
        self.0.clone()
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "VerificationSignature",
            length: PB_VERIFICATION_SIGNATURE_LENGTH,
        })
    }

    /// Construct a `VerificationSignature` from a slice of bytes.
    fn from_bytes(bytes: &[u8]) -> Result<PbVerificationSignature, TokenError> {
        if bytes.len() != PB_VERIFICATION_SIGNATURE_LENGTH {
            return Err(PbVerificationSignature::bytes_length_error());
        }

        let mut key: [u8; PB_VERIFICATION_SIGNATURE_LENGTH] = [0u8; PB_VERIFICATION_SIGNATURE_LENGTH];

        key.copy_from_slice(&bytes[..]);
        Ok(PbVerificationSignature(key))
    }
}

#[cfg(test)]
mod tests {
    use hmac::Hmac;
    use rand::rngs::OsRng;
    use sha2::Sha512;

    use super::*;

//     #[allow(non_snake_case)]
//     #[test]
//     fn vector_tests() {
//         // Generated using tools/oprf-test-gen
//         let vectors = [
//             ("SlPD+7xZlw7l+Fr4E4dd/8E6kEouU65+ZfoN6m5iyQE=", "nGajOcg0T5IvwyBstdroFKWUwBd90yNcJU2cQJpluAg=", "nwfnvlVROHqYupd8cy0IDcsPKaBI42VpEsZTPjLueu0ptyF2nOZOQ9VxM7B02DnVMe0fKFEK+0Ws4QofS3lNbw==", "rBKvQjzCywrH+WAHjvVpB4P59cy1A0CCcYjeUioWdA0=", "iKt8hXS7Zyqy5/xbbknh/CuCmQM+Cti6uOibdKZBlEM=", "OFccZ1mrx9SSrRSoj95nEVmkbMAdggfpj6haKO0BrQQ=", "JFJyI4tUdjjtud9a4qZalp5i9QY4I0x/VhChVu4P714="),
//             ("7oD3U1ZwWQN/2eZhiXfHtnwmhR+yl3P7Gta+T123awI=", "vtiIh6vgqE9kaR/gvfo9rxps1pehPweuB1iJEM45ySc=", "5aaIdCtHxa37WdTfdv0dseUe4Dscqfgqyhc+24tyk0dOvpgPkE0QyRZEK0eDoOmEhgy2yVeznDjtj1HP+qaKTQ==", "yhpWSFSxFQRlZH9QtcmCrL1p27dYMEKs+sub7hfVbA8=", "qDUfb1GhqEsJg2MEo0jI5fUDsKitwSSkV6kaF3wWHBU=", "goTV+GGlPyIodeEfRu62nWVJFpj3lXMjZY6w4ABaolc=", "sgJfuuExkd+VoIXOr9gv+M7VlRnjnUtveVzWcOY6YzM="),
//             ("tviSLm/W8oFds67y9lMs990fjh08hQNV17/4V2bmOQY=", "5ufRlCvVKvXp1yuxxS7Jvw9LSwQUl6Q/MlT6HY2l1Hc=", "7aq3TaFBD8BV6gaMmekmCsvjN89dPgDlsyMP/tsLmQeH0McOC/5BmOpnWN1aYftf7C35gfMb7+FT+B0XFheE2w==", "Ge3prZ2jJSoh1A3ZvrSfaSA1kDziGW2I+Gmh6jniaAs=", "pOTANELrS8oor67hIYyCvrbmlMrn6Fr+04nBmFgrvxU=", "JjbfZ+UifRtHLdxcvVdI6C2SXYls9aWS0UyS6vyfCAY=", "Ki8Vb+Fm7qqeeL63/Oco95UaMOO62bRGq2fMTz5xPU8="),
//             ("2srhyAUoqF+s2y+NfSXluDXVxC7JBgiD2ttOSXBYPww=", "HhdUX1s812RxwznoreV7i/BHvj2Xy9tJo24GxNDmtF8=", "bQqtuvgVfQYqyyQYwXakdVEbNcP2IYpWaOpbxvVLh4L4s0DwCsG+ul5izWMqfOeAnHJWCKyl7798QfI3ZD8GwA==", "gfes2hjQSpt6QOBJnz4t/N/utBkdDS+W4GRQIYjb/wQ=", "ZnaqI3kpS5nh9B3jw6uOeUld//Q2+olaAlimWRFvcDE=", "0pISjRRLsiYWLzqiukHe1xkIEuDmibUcg9m/5zcPwSo=", "2lSAwKDv4mdzZuMSEEngBXSQBJRJoprzqKMtX9Bi/zs="),
//             ("pfwD6XL8PnQfJPuzg/LKKVf3QRLc4ZclvC+6GBBETgo=", "Vv9rfOewgYx7jHMyfAZfBFEBt5IuwIKwz2NbDpra+UM=", "FtP6gVFikwP+l0FWLtBl2068AFDvVYNkroESSij1wBMTIy+8SW39iiVoZXtobXIUOCoaAJAwF92paYeEQrpa/w==", "xrF8ZzEtEsGbRfJGjULVkNisgpaAO69AHZKYhyQmng4=", "rHUztBaoMDDVwOTnOxFQgEOEeG6lKBL7Tb+fluztCxo=", "dhQv3WoCFW+EcV1dpCARarugjhU/enn0UlamXDPoFxc=", "GgWeq8r+ZRsPJa50bP7y3kVAq7yBSSN8eM0oOn/U2CM="),
//             ("xNWxYjBW6Sty2Yy33S38IPkX6v4zAwK10Ge/WPxVVwU=", "GrqZp9KBIAi1mExq2VUhG8lIuNO/J9Ap4xATdJ5TfmM=", "xP/wuGwC7WYtLSUiZHofCaey+e6lbn4gsfBszdnOw347LSCBLfNpl4Y2wiZGYDZ1gEEEdF0pl+KN9dgkKq0ZyA==", "RclUsYJkWG7Uw0tM/rn+nyvDey/Ibwl7WkmmvkIPWwc=", "fiD5jlU2Bhu+chVrhWKvZTaVJnbmBTpDcfEAH9Kcjg4=", "mCFMTFdnxZ/gvTnVNGMmZkXWqlnnZH3JnwDKhTBT3x0=", "krmSP8LTAA0O35g7uk+o7MMYTl2qACiWu+CDZXtQJSo="),
//             ("lE2Tu2LzhNgU77KnsEFbqVYOc5wsbMYYzBQOcpi32Ag=", "EuJk2I4y6ZrbIn04deR+lzJS1xrBIpN+RthbPknv+gA=", "DPw4xN363pkKIT0gj794mDNPTe7X5YMP0mZ1ExVDWuGbuU9NPckmUvJD3R+W81latHPSNW2PqPbWTMT2SxLKmQ==", "Dbpt5WypybRRaQiInYndWLf/O2ewT3IEYOOdxKywNg8=", "QJH62wtVRKX0Eq1GTWVyAVuML0mpEl18VvxFn3TvTDI=", "TMRELsL1kWbyRNLQhWuIyU2j7M2FJk0trp+uR1w4hHw=", "nDiCPlbQ6HfR3MX9jRqY3id4DWo3GaZ1FvUfkmAjWyg="),
//             ("Tmfvkm6Kvi/BWAvqNsGsdQzJTI9tkGa4Sr0dNPTMCwc=", "iPXJcLCmT9SYYVYVfNx6br3VG1rHHF2hIrD2cVx8YGE=", "BdOrSDfezktj/f1d0HordqjIJWbfGiFn2uXhJbaqDna52ZyoRmT1Du6lTkSfDlhwORN/V1Q9iSBUgxQckzFmtg==", "0web3hpMwnqhIhu9mjAKNLfmFdJUfY3pu4clcs0G8AQ=", "Qll/1fI1hlcc3Dm6xtfo3LlJwu6fgoffCZ3VzzQvCAs=", "KNbnK4jL8SThHByYWWrzdpZHxvrTVid7aBYHnZD2BW0=", "Lti4tRDBQzwNIiTbGpPVVViHMvCEfC7ov2Ne3LrQdRg="),
//             ("N8oRiMuSrYdp9TMKp++AP8ridXqdX6BoPOucx2eRCQE=", "mnikks9ySHzZGMgoPZ0SRA8/JJkMh5aA+m3eqeMfqTE=", "9sNH3G618rH0vy3TKBMNRQDKOb66LUKBo9jOtMsezeN4sgAp+2pMVDMS5BATkVxXAW5dpoGUTMJ3+cfnX0plSg==", "f44zH9r/YnCyaHZnKtEc/68diotEo1GjQ5MWepNEXAk=", "EEH0FTbmxN5XoXnAHmIH0y4VjcixJ5U9T8WqXgP2IAg=", "Km0KASMeIqj0s5vswz+WEYptTx2Y0fOb9cVjb+UKexw=", "lNDdKND+R/JmDrM08Q7w7ePoXT7/hgzGU6xVBU5RFig="),
//             ("Nye8fMOQJv1HjCY6qxG0Br661wjd8OwNI1O0ZbkmGAc=", "5szoRS3/9jdVTmhswiS9yyaLeC2I0CfBAUzfe0zGjz8=", "OkOqxU+boJmNIhmzusoRGUDVJLfPlGd9bFV3UPpNueEHfu21um4zwQSuJUQ8hr8VgzU63fb93Rmk/0kRiOPUhw==", "ZBztTnJvQKmPkxfgzGzufhRa6o4oUPublpOIhODHKA4=", "lD1eLLmRw7ebLOd51OQSps51cZGTIg2DM+GL38bQQww=", "qA27hu9S60UX0jfnWJQgUBllQvfOPu+jQVkphi6Sv24=", "HhPZFQiNAYzG+niNmUiWut2g/YMhox86h1XyZypQfVk="),
//         ];
//         for i in 0..vectors.len() {
//             let (k, Y, seed, r, P, Q, W) = vectors[i];
//
//             let server_key = SigningKey::decode_base64(k).unwrap();
//             let seed = base64::decode(seed).unwrap();
//
//             assert!(server_key.public_key.encode_base64() == Y);
//
//             let r_bytes = base64::decode(r).unwrap();
//             let mut r_bits: [u8; 32] = [0u8; 32];
//             r_bits.copy_from_slice(&r_bytes);
//             let r = Scalar::from_canonical_bytes(r_bits).unwrap();
//
//             let token = Token::hash_from_bytes_with_blind::<Sha512>(&seed, r);
//
//             let blinded_token = token.blind();
//
//             assert!(blinded_token.encode_base64() == P);
//
//             let mut rng = OsRng;
//             let signed_token = server_key.sign(&blinded_token, true, rng).unwrap();
//
//             assert!(signed_token.encode_base64() == Q);
//
//             let unblinded_token = token.unblind(&signed_token).unwrap();
//
//             let W_bytes = base64::decode(W).unwrap();
//             let mut W_bits: [u8; 32] = [0u8; 32];
//             W_bits.copy_from_slice(&W_bytes[..32]);
//             let W = CompressedRistretto(W_bits);
//
//             let unblinded_token_expected = UnblindedToken { W: W, t: token.t };
//             assert!(unblinded_token.encode_base64() == unblinded_token_expected.encode_base64());
//         }
//     }
//
    #[test]
    fn works() {
        let mut rng = OsRng;

        // Server setup

        let server_key = PbSigningKey::random(&mut rng);

        // Signing

        // client prepares a random token and blinding scalar
        let token = PbToken::random::<Sha512, _>(&mut rng);
        // client blinds the token and sends it to the server
        let blinded_token = token.blind();

        // server signs the blinded token and returns it to the client
        let (signed_token, _) = server_key.sign::<Sha512, _>(&blinded_token, false, &mut rng).unwrap();

        // client uses the blinding scalar to unblind the returned signed token
        let unblinded_token = token.unblind::<Sha512>(&signed_token).unwrap();

        // Redemption

        // client sends the token preimage, signature and message to the server

        // server checks the validity and the boolean of the client
        let server_bit_verification = server_key.check_signature_bit(&unblinded_token).unwrap();

        // The server uses the output bit for verification.
        assert!(server_bit_verification == false);
    }
}
