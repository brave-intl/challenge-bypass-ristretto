use core::fmt::Debug;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::typenum::U64;
use digest::{Digest, KeyInit};
use hmac::digest::generic_array::GenericArray;
use hmac::Mac;
use rand::{CryptoRng, Rng};
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use curve25519_dalek::traits::IsIdentity;
use digest::core_api::BlockSizeUser;

use crate::errors::{InternalError, TokenError};

/// RFC 9497 §3.1 and §4.1, OPRF(ristretto255, SHA-512).
/// modeOPRF = 0x00. contextString = "OPRFV1-" || mode || "-" || identifier.
// Note: this is for OPRF
const DST_HASH_TO_GROUP: &[u8] = b"HashToGroup-OPRFV1-\x00-ristretto255-SHA512";
/// RFC 9497 §3.2.1,"DeriveKeyPair" || contextString.
const DST_DERIVE_KEYPAIR: &[u8] = b"DeriveKeyPairOPRFV1-\x00-ristretto255-SHA512";

/// The length of a `TokenPreimage`, in bytes.
pub const TOKEN_PREIMAGE_LENGTH: usize = 64;
/// The length of a `Token`, in bytes.
pub const TOKEN_LENGTH: usize = 96;
/// The length of a `BlindedToken`, in bytes.
pub const BLINDED_TOKEN_LENGTH: usize = 32;
/// The length of a `PublicKey`, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;
/// The length of a `SigningKey`, in bytes.
pub const SIGNING_KEY_LENGTH: usize = 32;
/// The length of a `SignedToken`, in bytes.
pub const SIGNED_TOKEN_LENGTH: usize = 32;
/// The length of a `UnblindedToken`, in bytes.
pub const UNBLINDED_TOKEN_LENGTH: usize = 96;
/// The length of a `VerificationSignature`, in bytes.
pub const VERIFICATION_SIGNATURE_LENGTH: usize = 64;
/// The length of wide scalar input, in bytes.
pub const SCALAR_WIDE_INPUT_LENGTH: usize = 64;

/// RFC 9380 §5.3.1 `expand_message_xmd`, for `len_in_bytes == 64`.
fn expand_message_xmd_64_parts<D>(msg_parts: &[&[u8]], dst: &[u8]) -> [u8; 64]
where
    D: Digest<OutputSize = U64> + BlockSizeUser + Default,
{
    debug_assert!(dst.len() <= 255, "DST must be <= 255 bytes");

    let dst_len = [dst.len() as u8];
    let z_pad = GenericArray::<u8, <D as BlockSizeUser>::BlockSize>::default();
    let l_i_b_str = [0u8, 64u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut h = D::default();
    h.update(z_pad.as_slice());
    for part in msg_parts {
        h.update(part);
    }
    h.update(&l_i_b_str);
    h.update(&[0u8]);
    h.update(dst);
    h.update(&dst_len);
    let b0 = h.finalize();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut h = D::default();
    h.update(b0.as_slice());
    h.update(&[1u8]);
    h.update(dst);
    h.update(&dst_len);
    let b1 = h.finalize();

    let mut out = [0u8; 64];
    out.copy_from_slice(b1.as_slice());
    out
}

fn expand_message_xmd_64<D>(msg: &[u8], dst: &[u8]) -> [u8; 64]
where
    D: Digest<OutputSize = U64> + BlockSizeUser + Default,
{
    expand_message_xmd_64_parts::<D>(&[msg], dst)
}

/// RFC 9497 §4.1 HashToGroup: hash_to_ristretto255 (RFC 9380 App. B),
/// expand_message_xmd, DST = "HashToGroup-" || contextString.
fn hash_to_group<D>(input: &[u8]) -> RistrettoPoint
where
    D: Digest<OutputSize = U64> + BlockSizeUser + Default,
{
    RistrettoPoint::from_uniform_bytes(&expand_message_xmd_64::<D>(input, DST_HASH_TO_GROUP))
}

/// RFC 9497 §4.1 HashToScalar
fn hash_to_scalar<D>(msg_parts: &[&[u8]], dst: &[u8]) -> Scalar
where
    D: Digest<OutputSize = U64> + BlockSizeUser + Default,
{
    Scalar::from_bytes_mod_order_wide(&expand_message_xmd_64_parts::<D>(msg_parts, dst))
}

/// RFC 9497 §3.3.1 Finalize hash:
/// Hash(I2OSP(len(input),2) || input || I2OSP(len(N),2) || SerializeElement(N) || "Finalize")
fn finalize<D>(input: &[u8], unblinded_element: &CompressedRistretto) -> [u8; 64]
where
    D: Digest<OutputSize = U64> + Default,
{
    let unblinded = unblinded_element.as_bytes();

    let mut hash = D::default();
    hash.update((input.len() as u16).to_be_bytes()); // I2OSP(len(input), 2)
    hash.update(input);
    hash.update((unblinded.len() as u16).to_be_bytes()); // I2OSP(len(N), 2)
    hash.update(unblinded);
    hash.update(b"Finalize");

    let mut out = [0u8; 64];
    out.copy_from_slice(hash.finalize().as_slice());
    out
}

/// A `TokenPreimage` is a slice of bytes which can be hashed to a `RistrettoPoint`.
///
/// The hash function must ensure the discrete log with respect to other points is unknown.
/// In this construction `RistrettoPoint::from_uniform_bytes` is used as the hash function.
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Copy, Clone)]
pub struct TokenPreimage([u8; TOKEN_PREIMAGE_LENGTH]);

impl PartialEq for TokenPreimage {
    fn eq(&self, other: &TokenPreimage) -> bool {
        self.0[..] == other.0[..]
    }
}

#[cfg(any(test, feature = "base64"))]
impl_base64!(TokenPreimage);

#[cfg(feature = "serde")]
impl_serde!(TokenPreimage);

impl Debug for TokenPreimage {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "TokenPreimage: {:?}", &self.0[..])
    }
}

#[allow(non_snake_case)]
impl TokenPreimage {
    pub(crate) fn T<D>(&self) -> Result<RistrettoPoint, TokenError>
    where
        D: Digest<OutputSize = U64> + BlockSizeUser + Default,
    {
        let input_element = hash_to_group::<D>(&self.0);
        if bool::from(input_element.is_identity()) {
            return Err(TokenError(InternalError::InvalidInput));
        }
        Ok(input_element)
    }

    /// Convert this `TokenPreimage` to a byte array.
    pub fn to_bytes(&self) -> [u8; TOKEN_PREIMAGE_LENGTH] {
        self.0
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "TokenPreimage",
            length: TOKEN_PREIMAGE_LENGTH,
        })
    }

    /// Construct a `TokenPreimage` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<TokenPreimage, TokenError> {
        if bytes.len() != TOKEN_PREIMAGE_LENGTH {
            return Err(TokenPreimage::bytes_length_error());
        }

        let mut bits: [u8; TOKEN_PREIMAGE_LENGTH] = [0u8; TOKEN_PREIMAGE_LENGTH];
        bits.copy_from_slice(bytes);
        Ok(TokenPreimage(bits))
    }
}

/// A `Token` consists of a randomly chosen preimage and blinding factor.
///
/// Since a token includes the blinding factor it should be treated
/// as a client secret and NEVER revealed to the server.
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Debug, Clone)]
pub struct Token {
    /// `t` is a `TokenPreimage`
    pub(crate) t: TokenPreimage,
    /// `r` is a `Scalar` which is the blinding factor
    r: Scalar,
}

/// Overwrite the token blinding factor with null when it goes out of scope.
impl Drop for Token {
    fn drop(&mut self) {
        self.r.zeroize();
    }
}

#[cfg(any(test, feature = "base64"))]
impl_base64!(Token);

#[cfg(feature = "serde")]
impl_serde!(Token);

#[allow(non_snake_case)]
impl Token {
    /// Generates a new random `Token` using the provided random number generator.
    /// For ristretto, this should be fixed to SHA-512.
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

    /// Creates a new `Token`, using hashing to derive a `TokenPreimage` and the specified blind
    pub(crate) fn hash_from_bytes_with_blind<D>(bytes: &[u8], blinding_scalar: Scalar) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
    {
        // There is no need for this hash
        let mut hash = D::default();
        let mut seed = [0u8; 64];
        hash.update(bytes);
        seed.copy_from_slice(hash.finalize().as_slice());

        Token {
            t: TokenPreimage(seed),
            r: blinding_scalar,
        }
    }

    /// Creates a new `Token`, using hashing to derive a `TokenPreimage` and a random blind
    pub fn hash_from_bytes<D, T>(rng: &mut T, bytes: &[u8]) -> Self
    where
        D: Digest<OutputSize = U64> + Default,
        T: Rng + CryptoRng,
    {
        let blinding_scalar = Scalar::random(rng);
        Self::hash_from_bytes_with_blind::<D>(bytes, blinding_scalar)
    }

    /// Blinds the `Token`, returning a `BlindedToken` to be sent to the server.
    pub fn blind<D>(&self) -> Result<BlindedToken, TokenError>
    where
        D: Digest<OutputSize = U64> + BlockSizeUser + Default,
    {
        Ok(BlindedToken((self.r * self.t.T::<D>()?).compress()))
    }

    /// Using the blinding factor of the original `Token`, unblind a `SignedToken`
    /// returned from the server.
    ///
    /// Returns a `TokenError` if the `SignedToken` point is not valid.
    pub(crate) fn unblind(&self, Q: &SignedToken) -> Result<UnblindedToken, TokenError> {
        let evaluated_element =
            Q.0.decompress()
                .ok_or(TokenError(InternalError::PointDecompressionError))?;
        if bool::from(evaluated_element.is_identity()) {
            return Err(TokenError(InternalError::InvalidInput));
        }

        Ok(UnblindedToken {
            t: self.t,
            W: (self.r.invert() * evaluated_element).compress(),
        })
    }

    /// Convert this `Token` to a byte array.
    pub fn to_bytes(&self) -> [u8; TOKEN_LENGTH] {
        let mut token_bytes: [u8; TOKEN_LENGTH] = [0u8; TOKEN_LENGTH];

        token_bytes[..TOKEN_PREIMAGE_LENGTH].copy_from_slice(&self.t.to_bytes());
        token_bytes[TOKEN_PREIMAGE_LENGTH..].copy_from_slice(&self.r.to_bytes());
        token_bytes
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "Token",
            length: TOKEN_LENGTH,
        })
    }

    /// Construct a `Token` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Token, TokenError> {
        if bytes.len() != TOKEN_LENGTH {
            return Err(Token::bytes_length_error());
        }

        let preimage = TokenPreimage::from_bytes(&bytes[..TOKEN_PREIMAGE_LENGTH])?;

        let mut blinding_factor_bits: [u8; 32] = [0u8; 32];
        blinding_factor_bits.copy_from_slice(&bytes[TOKEN_PREIMAGE_LENGTH..]);
        let blinding_factor = Option::from(Scalar::from_canonical_bytes(blinding_factor_bits))
            .ok_or(TokenError(InternalError::ScalarFormatError))?;

        Ok(Token {
            t: preimage,
            r: blinding_factor,
        })
    }
}

/// A `BlindedToken` is sent to the server for signing.
///
/// It is the result of the scalar multiplication of the point derived from the token
/// preimage with the blinding factor.
///
/// \\(P = T^r = H_1(t)^r\\)
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Copy, Clone, Debug)]
pub struct BlindedToken(pub(crate) CompressedRistretto);

#[cfg(any(test, feature = "base64"))]
impl_base64!(BlindedToken);

#[cfg(feature = "serde")]
impl_serde!(BlindedToken);

impl BlindedToken {
    /// Convert this `BlindedToken` to a byte array.
    pub fn to_bytes(&self) -> [u8; BLINDED_TOKEN_LENGTH] {
        self.0.to_bytes()
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "BlindedToken",
            length: BLINDED_TOKEN_LENGTH,
        })
    }

    /// Construct a `BlindedToken` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<BlindedToken, TokenError> {
        if bytes.len() != BLINDED_TOKEN_LENGTH {
            return Err(BlindedToken::bytes_length_error());
        }

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);
        Ok(BlindedToken(CompressedRistretto(bits)))
    }
}

/// A `PublicKey` is a committment by the server to a particular `SigningKey`.
///
/// \\(Y = X^k\\)
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Copy, Clone, Debug)]
#[allow(non_snake_case)]
pub struct PublicKey(pub(crate) CompressedRistretto);

#[cfg(any(test, feature = "base64"))]
impl_base64!(PublicKey);

#[cfg(feature = "serde")]
impl_serde!(PublicKey);

impl PublicKey {
    /// Convert this `PublicKey` to a byte array.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.0.to_bytes()
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "PublicKey",
            length: PUBLIC_KEY_LENGTH,
        })
    }

    /// Construct a `PublicKey` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, TokenError> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(PublicKey::bytes_length_error());
        }

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);

        Ok(PublicKey(CompressedRistretto(bits)))
    }
}

/// A `SigningKey` is used to sign a `BlindedToken` and verify an `UnblindedToken`.
///
/// This is a server secret and should NEVER be revealed to the client.
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Debug, Clone)]
pub struct SigningKey {
    /// A `PublicKey` showing a committment to this particular key
    pub public_key: PublicKey,
    /// `k` is the actual key
    pub(crate) k: Scalar,
}

#[cfg(any(test, feature = "base64"))]
impl_base64!(SigningKey);

#[cfg(feature = "serde")]
impl_serde!(SigningKey);

/// Overwrite signing key with null when it goes out of scope.
impl Drop for SigningKey {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

#[allow(non_snake_case)]
impl SigningKey {
    /// RFC 9497 §3.2.1 DeriveKeyPair for OPRF(ristretto255, SHA-512).
    /// `seed` is 32 bytes per the RFC; `info` is an optional public string.
    pub fn derive_key_pair<D>(seed: &[u8], info: &[u8]) -> Result<SigningKey, TokenError>
    where
        D: Digest<OutputSize = U64> + BlockSizeUser + Default,
    {
        if info.len() > u16::MAX as usize {
            return Err(TokenError(InternalError::InvalidInput));
        }
        // deriveInput = seed || I2OSP(len(info), 2) || info
        let info_len = (info.len() as u16).to_be_bytes();

        let mut counter: u16 = 0;
        loop {
            if counter > 255 {
                return Err(TokenError(InternalError::InvalidInput));
            }
            let counter_byte = [counter as u8];
            // HashToScalar(deriveInput || I2OSP(counter, 1)) with the DeriveKeyPair DST.
            let k =
                hash_to_scalar::<D>(&[seed, &info_len, info, &counter_byte], DST_DERIVE_KEYPAIR);
            if !bool::from(k.ct_eq(&Scalar::ZERO)) {
                let Y = k * constants::RISTRETTO_BASEPOINT_POINT;
                return Ok(SigningKey {
                    k,
                    public_key: PublicKey(Y.compress()),
                });
            }
            counter += 1;
        }
    }

    /// Generates a new random `SigningKey` using the provided random number generator.
    pub fn random<T: Rng + CryptoRng>(rng: &mut T) -> Self {
        let k = Scalar::random(rng);
        let Y = k * constants::RISTRETTO_BASEPOINT_POINT;
        SigningKey {
            k,
            public_key: PublicKey(Y.compress()),
        }
    }

    /// Construct a `SigningKey` from 64 random bytes.
    ///
    /// The random bytes MUST be cryptographically strong, uniform random bytes
    /// such as those output from a CSPRNG or appropriately seeded KDF.
    pub fn from_random_bytes(bytes: &[u8]) -> Result<SigningKey, TokenError> {
        if bytes.len() != SCALAR_WIDE_INPUT_LENGTH {
            return Err(TokenError(InternalError::BytesLengthError {
                name: "SigningKey random bytes",
                length: SCALAR_WIDE_INPUT_LENGTH,
            }));
        }

        let mut bytes_array = [0u8; SCALAR_WIDE_INPUT_LENGTH];
        bytes_array.copy_from_slice(bytes);

        let k = Scalar::from_bytes_mod_order_wide(&bytes_array);
        let Y = k * constants::RISTRETTO_BASEPOINT_POINT;
        Ok(SigningKey {
            k,
            public_key: PublicKey(Y.compress()),
        })
    }

    /// Signs the provided `BlindedToken`
    ///
    /// Returns None if the `BlindedToken` point is not valid.
    pub fn sign(&self, P: &BlindedToken) -> Result<SignedToken, TokenError> {
        let point =
            P.0.decompress()
                .ok_or(TokenError(InternalError::PointDecompressionError))?;
        if bool::from(point.is_identity()) {
            return Err(TokenError(InternalError::InvalidInput));
        }

        Ok(SignedToken((self.k * point).compress()))
    }

    /// Rederives an `UnblindedToken` via the token preimage of the provided `UnblindedToken`
    ///
    /// W' = T^k = H_1(t)^k
    pub fn rederive_unblinded_token<D>(
        &self,
        t: &TokenPreimage,
    ) -> Result<UnblindedToken, TokenError>
    where
        D: Digest<OutputSize = U64> + BlockSizeUser + Default,
    {
        Ok(UnblindedToken {
            t: *t,
            W: (self.k * t.T::<D>()?).compress(),
        })
    }

    /// Convert this `SigningKey` to a byte array.
    pub fn to_bytes(&self) -> [u8; SIGNING_KEY_LENGTH] {
        self.k.to_bytes()
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "SigningKey",
            length: SIGNING_KEY_LENGTH,
        })
    }

    /// Construct a `SigningKey` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<SigningKey, TokenError> {
        if bytes.len() != SIGNING_KEY_LENGTH {
            return Err(SigningKey::bytes_length_error());
        }

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);
        let k = Option::from(Scalar::from_canonical_bytes(bits))
            .ok_or(TokenError(InternalError::ScalarFormatError))?;

        let Y: RistrettoPoint = k * constants::RISTRETTO_BASEPOINT_POINT;

        Ok(SigningKey {
            public_key: PublicKey(Y.compress()),
            k,
        })
    }
}

/// A `SignedToken` is the result of signing a `BlindedToken`.
///
/// \\(Q = P^k = (T^r)^k\\)
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Copy, Clone, Debug)]
pub struct SignedToken(pub(crate) CompressedRistretto);

#[cfg(any(test, feature = "base64"))]
impl_base64!(SignedToken);

#[cfg(feature = "serde")]
impl_serde!(SignedToken);

impl SignedToken {
    /// Convert this `SignedToken` to a byte array.
    pub fn to_bytes(&self) -> [u8; SIGNED_TOKEN_LENGTH] {
        self.0.to_bytes()
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "SignedToken",
            length: SIGNED_TOKEN_LENGTH,
        })
    }

    /// Construct a `SignedToken` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<SignedToken, TokenError> {
        if bytes.len() != SIGNED_TOKEN_LENGTH {
            return Err(SignedToken::bytes_length_error());
        }

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);
        Ok(SignedToken(CompressedRistretto(bits)))
    }
}

/// An `UnblindedToken` is the result of unblinding a `SignedToken`.
///
/// While both the client and server both "know" this value,
/// it should nevertheless not be sent between the two.
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[allow(non_snake_case)]
#[derive(Debug, Clone)]
pub struct UnblindedToken {
    /// `t` is the `TokenPreimage`
    pub t: TokenPreimage,
    /// `W` is the unblinded signed `CompressedRistretto` point
    ///
    /// \\(W = Q^{1/r} = P^{k(1/r)} = T^{rk(1/r)} = T^k\\)
    W: CompressedRistretto,
}

#[cfg(any(test, feature = "base64"))]
impl_base64!(UnblindedToken);

#[cfg(feature = "serde")]
impl_serde!(UnblindedToken);

impl UnblindedToken {
    /// Derive the `VerificationKey` for this particular `UnblindedToken`
    pub fn derive_verification_key<D>(&self) -> VerificationKey
    where
        D: Digest<OutputSize = U64> + Default,
    {
        VerificationKey(finalize::<D>(&self.t.0, &self.W))
    }

    /// Convert this `UnblindedToken` to a byte array.
    pub fn to_bytes(&self) -> [u8; UNBLINDED_TOKEN_LENGTH] {
        let mut unblinded_token_bytes: [u8; UNBLINDED_TOKEN_LENGTH] = [0u8; UNBLINDED_TOKEN_LENGTH];

        unblinded_token_bytes[..TOKEN_PREIMAGE_LENGTH].copy_from_slice(&self.t.to_bytes());
        unblinded_token_bytes[TOKEN_PREIMAGE_LENGTH..].copy_from_slice(&self.W.to_bytes());
        unblinded_token_bytes
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "UnblindedToken",
            length: UNBLINDED_TOKEN_LENGTH,
        })
    }

    /// Construct a `UnblindedToken` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<UnblindedToken, TokenError> {
        if bytes.len() != UNBLINDED_TOKEN_LENGTH {
            return Err(UnblindedToken::bytes_length_error());
        }

        let preimage = TokenPreimage::from_bytes(&bytes[..TOKEN_PREIMAGE_LENGTH])?;

        let mut w_bits: [u8; 32] = [0u8; 32];
        w_bits.copy_from_slice(&bytes[TOKEN_PREIMAGE_LENGTH..]);
        Ok(UnblindedToken {
            t: preimage,
            W: CompressedRistretto(w_bits),
        })
    }
}

/// The shared `VerificationKey` for proving / verifying the validity of an `UnblindedToken`.
///
/// \\(K = H_2(t, W)\\)
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Clone)]
pub struct VerificationKey([u8; 64]);

impl Debug for VerificationKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "VerificationKey: {:?}", &self.0[..])
    }
}

impl VerificationKey {
    /// Use the `VerificationKey` to "sign" a message, producing a `VerificationSignature`
    pub fn sign<D>(&self, message: &[u8]) -> VerificationSignature
    where
        D: Mac<OutputSize = U64> + KeyInit,
    {
        let mut mac = <D as Mac>::new_from_slice(self.0.as_ref()).unwrap();
        mac.update(message);

        VerificationSignature(mac.finalize().into_bytes())
    }

    /// Use the `VerificationKey` to check that the signature of a message matches the
    /// provided `VerificationSignature`
    pub fn verify<D>(&self, sig: &VerificationSignature, message: &[u8]) -> bool
    where
        D: Mac<OutputSize = U64> + KeyInit,
    {
        &self.sign::<D>(message) == sig
    }
}

/// A `VerificationSignature` which can be verified given the `VerificationKey` and message
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Clone)]
pub struct VerificationSignature(GenericArray<u8, U64>);

#[cfg(any(test, feature = "base64"))]
impl_base64!(VerificationSignature);

#[cfg(feature = "serde")]
impl_serde!(VerificationSignature);

impl ConstantTimeEq for VerificationSignature {
    fn ct_eq(&self, other: &VerificationSignature) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl PartialEq for VerificationSignature {
    fn eq(&self, other: &VerificationSignature) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

#[cfg(any(test, feature = "serde", feature = "base64"))]
impl VerificationSignature {
    /// Convert this `VerificationSignature` to a byte array.
    /// We intentionally keep this private to avoid accidental non constant time comparisons
    fn to_bytes(&self) -> [u8; VERIFICATION_SIGNATURE_LENGTH] {
        let mut bytes: [u8; VERIFICATION_SIGNATURE_LENGTH] = [0u8; VERIFICATION_SIGNATURE_LENGTH];
        bytes.copy_from_slice(self.0.as_slice());
        bytes
    }

    fn bytes_length_error() -> TokenError {
        TokenError(InternalError::BytesLengthError {
            name: "VerificationSignature",
            length: VERIFICATION_SIGNATURE_LENGTH,
        })
    }

    /// Construct a `VerificationSignature` from a slice of bytes.
    fn from_bytes(bytes: &[u8]) -> Result<VerificationSignature, TokenError> {
        if bytes.len() != VERIFICATION_SIGNATURE_LENGTH {
            return Err(VerificationSignature::bytes_length_error());
        }

        let arr: &GenericArray<u8, U64> = GenericArray::from_slice(bytes);
        Ok(VerificationSignature(*arr))
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::Engine as _, prelude::BASE64_STANDARD};
    use hmac::Hmac;
    use rand::rngs::OsRng;
    use sha2::Sha512;
    use std::string::String;
    use std::vec::Vec;

    use super::*;
    type HmacSha512 = Hmac<Sha512>;

    #[allow(non_snake_case)]
    #[test]
    fn vector_tests() {
        // Generated using tools/oprf-test-gen
        let vectors = [
            ("SlPD+7xZlw7l+Fr4E4dd/8E6kEouU65+ZfoN6m5iyQE=", "nGajOcg0T5IvwyBstdroFKWUwBd90yNcJU2cQJpluAg=", "nwfnvlVROHqYupd8cy0IDcsPKaBI42VpEsZTPjLueu0ptyF2nOZOQ9VxM7B02DnVMe0fKFEK+0Ws4QofS3lNbw==", "rBKvQjzCywrH+WAHjvVpB4P59cy1A0CCcYjeUioWdA0=", "iKt8hXS7Zyqy5/xbbknh/CuCmQM+Cti6uOibdKZBlEM=", "OFccZ1mrx9SSrRSoj95nEVmkbMAdggfpj6haKO0BrQQ=", "JFJyI4tUdjjtud9a4qZalp5i9QY4I0x/VhChVu4P714="),
            ("7oD3U1ZwWQN/2eZhiXfHtnwmhR+yl3P7Gta+T123awI=", "vtiIh6vgqE9kaR/gvfo9rxps1pehPweuB1iJEM45ySc=", "5aaIdCtHxa37WdTfdv0dseUe4Dscqfgqyhc+24tyk0dOvpgPkE0QyRZEK0eDoOmEhgy2yVeznDjtj1HP+qaKTQ==", "yhpWSFSxFQRlZH9QtcmCrL1p27dYMEKs+sub7hfVbA8=", "qDUfb1GhqEsJg2MEo0jI5fUDsKitwSSkV6kaF3wWHBU=", "goTV+GGlPyIodeEfRu62nWVJFpj3lXMjZY6w4ABaolc=", "sgJfuuExkd+VoIXOr9gv+M7VlRnjnUtveVzWcOY6YzM="),
            ("tviSLm/W8oFds67y9lMs990fjh08hQNV17/4V2bmOQY=", "5ufRlCvVKvXp1yuxxS7Jvw9LSwQUl6Q/MlT6HY2l1Hc=", "7aq3TaFBD8BV6gaMmekmCsvjN89dPgDlsyMP/tsLmQeH0McOC/5BmOpnWN1aYftf7C35gfMb7+FT+B0XFheE2w==", "Ge3prZ2jJSoh1A3ZvrSfaSA1kDziGW2I+Gmh6jniaAs=", "pOTANELrS8oor67hIYyCvrbmlMrn6Fr+04nBmFgrvxU=", "JjbfZ+UifRtHLdxcvVdI6C2SXYls9aWS0UyS6vyfCAY=", "Ki8Vb+Fm7qqeeL63/Oco95UaMOO62bRGq2fMTz5xPU8="),
            ("2srhyAUoqF+s2y+NfSXluDXVxC7JBgiD2ttOSXBYPww=", "HhdUX1s812RxwznoreV7i/BHvj2Xy9tJo24GxNDmtF8=", "bQqtuvgVfQYqyyQYwXakdVEbNcP2IYpWaOpbxvVLh4L4s0DwCsG+ul5izWMqfOeAnHJWCKyl7798QfI3ZD8GwA==", "gfes2hjQSpt6QOBJnz4t/N/utBkdDS+W4GRQIYjb/wQ=", "ZnaqI3kpS5nh9B3jw6uOeUld//Q2+olaAlimWRFvcDE=", "0pISjRRLsiYWLzqiukHe1xkIEuDmibUcg9m/5zcPwSo=", "2lSAwKDv4mdzZuMSEEngBXSQBJRJoprzqKMtX9Bi/zs="),
            ("pfwD6XL8PnQfJPuzg/LKKVf3QRLc4ZclvC+6GBBETgo=", "Vv9rfOewgYx7jHMyfAZfBFEBt5IuwIKwz2NbDpra+UM=", "FtP6gVFikwP+l0FWLtBl2068AFDvVYNkroESSij1wBMTIy+8SW39iiVoZXtobXIUOCoaAJAwF92paYeEQrpa/w==", "xrF8ZzEtEsGbRfJGjULVkNisgpaAO69AHZKYhyQmng4=", "rHUztBaoMDDVwOTnOxFQgEOEeG6lKBL7Tb+fluztCxo=", "dhQv3WoCFW+EcV1dpCARarugjhU/enn0UlamXDPoFxc=", "GgWeq8r+ZRsPJa50bP7y3kVAq7yBSSN8eM0oOn/U2CM="),
            ("xNWxYjBW6Sty2Yy33S38IPkX6v4zAwK10Ge/WPxVVwU=", "GrqZp9KBIAi1mExq2VUhG8lIuNO/J9Ap4xATdJ5TfmM=", "xP/wuGwC7WYtLSUiZHofCaey+e6lbn4gsfBszdnOw347LSCBLfNpl4Y2wiZGYDZ1gEEEdF0pl+KN9dgkKq0ZyA==", "RclUsYJkWG7Uw0tM/rn+nyvDey/Ibwl7WkmmvkIPWwc=", "fiD5jlU2Bhu+chVrhWKvZTaVJnbmBTpDcfEAH9Kcjg4=", "mCFMTFdnxZ/gvTnVNGMmZkXWqlnnZH3JnwDKhTBT3x0=", "krmSP8LTAA0O35g7uk+o7MMYTl2qACiWu+CDZXtQJSo="),
            ("lE2Tu2LzhNgU77KnsEFbqVYOc5wsbMYYzBQOcpi32Ag=", "EuJk2I4y6ZrbIn04deR+lzJS1xrBIpN+RthbPknv+gA=", "DPw4xN363pkKIT0gj794mDNPTe7X5YMP0mZ1ExVDWuGbuU9NPckmUvJD3R+W81latHPSNW2PqPbWTMT2SxLKmQ==", "Dbpt5WypybRRaQiInYndWLf/O2ewT3IEYOOdxKywNg8=", "QJH62wtVRKX0Eq1GTWVyAVuML0mpEl18VvxFn3TvTDI=", "TMRELsL1kWbyRNLQhWuIyU2j7M2FJk0trp+uR1w4hHw=", "nDiCPlbQ6HfR3MX9jRqY3id4DWo3GaZ1FvUfkmAjWyg="),
            ("Tmfvkm6Kvi/BWAvqNsGsdQzJTI9tkGa4Sr0dNPTMCwc=", "iPXJcLCmT9SYYVYVfNx6br3VG1rHHF2hIrD2cVx8YGE=", "BdOrSDfezktj/f1d0HordqjIJWbfGiFn2uXhJbaqDna52ZyoRmT1Du6lTkSfDlhwORN/V1Q9iSBUgxQckzFmtg==", "0web3hpMwnqhIhu9mjAKNLfmFdJUfY3pu4clcs0G8AQ=", "Qll/1fI1hlcc3Dm6xtfo3LlJwu6fgoffCZ3VzzQvCAs=", "KNbnK4jL8SThHByYWWrzdpZHxvrTVid7aBYHnZD2BW0=", "Lti4tRDBQzwNIiTbGpPVVViHMvCEfC7ov2Ne3LrQdRg="),
            ("N8oRiMuSrYdp9TMKp++AP8ridXqdX6BoPOucx2eRCQE=", "mnikks9ySHzZGMgoPZ0SRA8/JJkMh5aA+m3eqeMfqTE=", "9sNH3G618rH0vy3TKBMNRQDKOb66LUKBo9jOtMsezeN4sgAp+2pMVDMS5BATkVxXAW5dpoGUTMJ3+cfnX0plSg==", "f44zH9r/YnCyaHZnKtEc/68diotEo1GjQ5MWepNEXAk=", "EEH0FTbmxN5XoXnAHmIH0y4VjcixJ5U9T8WqXgP2IAg=", "Km0KASMeIqj0s5vswz+WEYptTx2Y0fOb9cVjb+UKexw=", "lNDdKND+R/JmDrM08Q7w7ePoXT7/hgzGU6xVBU5RFig="),
            ("Nye8fMOQJv1HjCY6qxG0Br661wjd8OwNI1O0ZbkmGAc=", "5szoRS3/9jdVTmhswiS9yyaLeC2I0CfBAUzfe0zGjz8=", "OkOqxU+boJmNIhmzusoRGUDVJLfPlGd9bFV3UPpNueEHfu21um4zwQSuJUQ8hr8VgzU63fb93Rmk/0kRiOPUhw==", "ZBztTnJvQKmPkxfgzGzufhRa6o4oUPublpOIhODHKA4=", "lD1eLLmRw7ebLOd51OQSps51cZGTIg2DM+GL38bQQww=", "qA27hu9S60UX0jfnWJQgUBllQvfOPu+jQVkphi6Sv24=", "HhPZFQiNAYzG+niNmUiWut2g/YMhox86h1XyZypQfVk="),
        ];
        for (k, Y, seed, r, P, Q, W) in vectors {
            let server_key = SigningKey::decode_base64(k).unwrap();
            let seed = BASE64_STANDARD.decode(seed).unwrap();

            assert!(server_key.public_key.encode_base64() == Y);

            let r_bytes = BASE64_STANDARD.decode(r).unwrap();
            let mut r_bits: [u8; 32] = [0u8; 32];
            r_bits.copy_from_slice(&r_bytes);
            let r = Scalar::from_canonical_bytes(r_bits).unwrap();

            let token = Token::hash_from_bytes_with_blind::<Sha512>(&seed, r);

            let blinded_token = token.blind::<Sha512>().unwrap();

            assert!(blinded_token.encode_base64() == P);

            let signed_token = server_key.sign(&blinded_token).unwrap();

            assert!(signed_token.encode_base64() == Q);

            let unblinded_token = token.unblind(&signed_token).unwrap();

            let W_bytes = BASE64_STANDARD.decode(W).unwrap();
            let mut W_bits: [u8; 32] = [0u8; 32];
            W_bits.copy_from_slice(&W_bytes[..32]);
            let W = CompressedRistretto(W_bits);

            let unblinded_token_expected = UnblindedToken { W, t: token.t };
            assert!(unblinded_token.encode_base64() == unblinded_token_expected.encode_base64());
        }
    }

    #[test]
    fn works() {
        let mut rng = OsRng;

        // Server setup

        let server_key = SigningKey::random(&mut rng);

        // Signing

        // client prepares a random token and blinding scalar
        let token = Token::random::<Sha512, _>(&mut rng);
        // client blinds the token and sends it to the server
        let blinded_token = token.blind::<Sha512>().unwrap();

        // server signs the blinded token and returns it to the client
        let signed_token = server_key.sign(&blinded_token).unwrap();

        // client uses the blinding scalar to unblind the returned signed token
        let unblinded_token = token.unblind(&signed_token).unwrap();

        // Redemption

        // client derives the shared key from the unblinded token
        let client_verification_key = unblinded_token.derive_verification_key::<Sha512>();
        // client signs a message using the shared key
        let client_sig = client_verification_key.sign::<HmacSha512>(b"test message");

        // client sends the token preimage, signature and message to the server

        // server derives the unblinded token using it's key and the clients token preimage
        let server_unblinded_token = server_key
            .rederive_unblinded_token::<Sha512>(&unblinded_token.t)
            .unwrap();
        // server derives the shared key from the unblinded token
        let server_verification_key = server_unblinded_token.derive_verification_key::<Sha512>();
        // server signs the same message using the shared key
        let server_sig = server_verification_key.sign::<HmacSha512>(b"test message");

        // The server compares the client signature to it's own
        assert!(client_sig == server_sig);

        // and a failing equality
        let server_sig_fail = server_verification_key.sign::<HmacSha512>(b"failing test message");
        assert!(!(client_sig == server_sig_fail));
    }

    #[test]
    fn from_random_bytes_test() {
        let seeds = [
            "nwfnvlVROHqYupd8cy0IDcsPKaBI42VpEsZTPjLueu0ptyF2nOZOQ9VxM7B02DnVMe0fKFEK+0Ws4QofS3lNbw==",
            "5aaIdCtHxa37WdTfdv0dseUe4Dscqfgqyhc+24tyk0dOvpgPkE0QyRZEK0eDoOmEhgy2yVeznDjtj1HP+qaKTQ==",
        ];

        let mut keys = Vec::new();

        // Test correctness and determinism
        for seed in seeds.iter() {
            let seed_bytes = BASE64_STANDARD.decode(seed).unwrap();
            assert_eq!(seed_bytes.len(), SCALAR_WIDE_INPUT_LENGTH);

            let key = SigningKey::from_random_bytes(&seed_bytes).unwrap();

            let mut bytes_array = [0u8; SCALAR_WIDE_INPUT_LENGTH];
            bytes_array.copy_from_slice(&seed_bytes);
            let scalar = Scalar::from_bytes_mod_order_wide(&bytes_array);
            let scalar_bytes = scalar.to_bytes();
            let key_manual = SigningKey::from_bytes(&scalar_bytes).unwrap();

            assert!(key.to_bytes() == key_manual.to_bytes());
            assert!(key.public_key.encode_base64() == key_manual.public_key.encode_base64());

            let key2 = SigningKey::from_random_bytes(&seed_bytes).unwrap();
            assert!(key.to_bytes() == key2.to_bytes());
            assert!(key.public_key.encode_base64() == key2.public_key.encode_base64());

            keys.push(key);
        }

        // Test edge cases
        let all_zeros = [0u8; SCALAR_WIDE_INPUT_LENGTH];
        let all_ones = [0xFFu8; SCALAR_WIDE_INPUT_LENGTH];

        let key_zeros = SigningKey::from_random_bytes(&all_zeros).unwrap();
        let key_ones = SigningKey::from_random_bytes(&all_ones).unwrap();

        // Test functionality
        let mut rng = OsRng;
        let token = Token::random::<Sha512, _>(&mut rng);
        let blinded_token = token.blind::<Sha512>().unwrap();

        for key in keys.iter().chain([&key_zeros, &key_ones]) {
            assert_eq!(key.to_bytes().len(), SIGNING_KEY_LENGTH);
            assert_eq!(key.public_key.encode_base64().len(), 44);
            assert!(key.sign(&blinded_token).is_ok());
        }

        // Test uniqueness
        let all_keys: Vec<&SigningKey> = keys.iter().chain([&key_zeros, &key_ones]).collect();
        for i in 0..all_keys.len() {
            for j in (i + 1)..all_keys.len() {
                assert!(!(all_keys[i].to_bytes() == all_keys[j].to_bytes()));
                assert!(
                    !(all_keys[i].public_key.encode_base64()
                        == all_keys[j].public_key.encode_base64())
                );
            }
        }

        // Test error handling
        assert!(SigningKey::from_random_bytes(&[0u8; 32]).is_err());
        assert!(SigningKey::from_random_bytes(&[0u8; 63]).is_err());
        assert!(SigningKey::from_random_bytes(&[0u8; 65]).is_err());
        assert!(SigningKey::from_random_bytes(&[]).is_err());
        assert!(SigningKey::from_random_bytes(&[0u8; 128]).is_err());
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }

    #[test]
    fn rfc9497_ristretto255_sha512_oprf_vectors() {
        // RFC 9497 Appendix A.1.1, OPRF(ristretto255, SHA-512), OPRF mode.
        let seed = hex(&"a3".repeat(32));
        let key_info = hex("74657374206b6579"); // "test key"
        let sksm = "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e";

        let server_key = SigningKey::derive_key_pair::<Sha512>(&seed, &key_info).unwrap();
        assert_eq!(hex_encode(server_key.to_bytes()), sksm);

        // (Input, Blind, BlindedElement, EvaluationElement, Output)
        let vectors = [
            (
                "00",
                "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
                "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c",
                "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e",
                "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3\
             ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6",
            ),
            (
                "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
                "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706",
                "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418",
                "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25",
                "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4\
             f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73",
            ),
        ];

        for (input, blind, blinded, evaluated, output) in vectors {
            let input = hex(input);

            let mut blind_bytes = [0u8; 32];
            blind_bytes.copy_from_slice(&hex(blind));
            let blind: Scalar = Option::from(Scalar::from_canonical_bytes(blind_bytes)).unwrap();

            // Blind: blindedElement = blind * HashToGroup(input)
            let input_element = hash_to_group::<Sha512>(&input);
            let blinded_element = (blind * input_element).compress();
            assert_eq!(hex_encode(blinded_element.to_bytes()), blinded);

            // BlindEvaluate via the real SigningKey::sign.
            let signed = server_key.sign(&BlindedToken(blinded_element)).unwrap();
            assert_eq!(hex_encode(signed.to_bytes()), evaluated);

            // Finalize: N = blind^-1 * evaluatedElement and finalize().
            let evaluated_point = signed.0.decompress().unwrap();
            let n = (blind.invert() * evaluated_point).compress();
            assert_eq!(hex_encode(finalize::<Sha512>(&input, &n)), output);
        }
    }
}
