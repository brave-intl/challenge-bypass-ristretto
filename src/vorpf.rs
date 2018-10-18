use core::fmt::Debug;

use clear_on_drop::clear::Clear;
use crypto_mac::MacResult;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use digest::generic_array::typenum::U64;
use digest::Digest;
use hmac::digest::generic_array::ArrayLength;
pub use hmac::digest::FixedOutput;
use hmac::digest::{BlockInput, Input};
use hmac::{Hmac, Mac};
use rand::{CryptoRng, Rng};

#[cfg(any(feature = "base64", feature = "serde"))]
use hmac::digest::generic_array::GenericArray;

use errors::{InternalError, TokenError};

/// The length of a `TokenPreimage`, in bytes.
pub const TOKEN_PREIMAGE_LENGTH: usize = 64;
/// The length of a `Token`, in bytes.
pub const TOKEN_LENGTH: usize = 96;
/// The length of a `BlindedToken`, in bytes.
pub const BLINDED_TOKEN_LENGTH: usize = 32;
/// The length of a `PublicKey`, in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 64;
/// The length of a `SIGNING_KEY_LENGTH`, in bytes.
pub const SIGNING_KEY_LENGTH: usize = 96;
/// The length of a `SIGNED_TOKEN_LENGTH`, in bytes.
pub const SIGNED_TOKEN_LENGTH: usize = 32;
/// The length of a `UNBLINDED_TOKEN_LENGTH`, in bytes.
pub const UNBLINDED_TOKEN_LENGTH: usize = 96;
/// The length of a `VERIFICATION_SIGNATURE_LENGTH`, in bytes.
pub const VERIFICATION_SIGNATURE_LENGTH: usize = 64;

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use sha2::Sha512;

    use super::*;

    #[test]
    fn it_works() {
        let mut rng = OsRng::new().unwrap();

        // Server setup

        let server_key = SigningKey::random(&mut rng);

        // Signing

        // client prepares a random token and blinding scalar
        let token = Token::random(&mut rng);
        // client blinds the token and sends it to the server
        let blinded_token = token.blind();

        // server signs the blinded token and returns it to the client
        let signed_token = server_key.sign(&blinded_token).unwrap();

        // client uses the blinding scalar to unblind the returned signed token
        let unblinded_token = token.unblind(&signed_token).unwrap();

        // Redemption

        // client derives the shared key from the unblinded token
        let client_verification_key = unblinded_token.derive_verification_key::<Sha512>();
        // client signs a message using the shared key
        let client_sig = client_verification_key.sign::<Sha512>(b"test message");

        // client sends the token preimage, signature and message to the server

        // server derives the unblinded token using it's key and the clients token preimage
        let server_unblinded_token = server_key.rederive_unblinded_token(&unblinded_token.t);
        // server derives the shared key from the unblinded token
        let server_verification_key = server_unblinded_token.derive_verification_key::<Sha512>();
        // server signs the same message using the shared key
        let server_sig = server_verification_key.sign::<Sha512>(b"test message");

        // The server compares the client signature to it's own
        assert!(client_sig == server_sig);
    }
}

/// A `TokenPreimage` is a slice of bytes which can be hashed to a `RistrettoPoint`.
///
/// The hash function must ensure the discrete log with respect to other points is unknown.
/// In this construction `RistrettoPoint::from_uniform_bytes` is used as the hash function.
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Copy, Clone)]
pub struct TokenPreimage([u8; TOKEN_PREIMAGE_LENGTH]);

#[cfg(feature = "base64")]
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
    pub(crate) fn T(&self) -> RistrettoPoint {
        RistrettoPoint::from_uniform_bytes(&self.0)
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
        bits.copy_from_slice(&bytes);
        Ok(TokenPreimage(bits))
    }
}

/// A `Token` consists of a randomly chosen preimage and blinding factor.
///
/// Since a token includes the blinding factor it should be treated
/// as a client secret and NEVER revealed to the server.
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Debug)]
pub struct Token {
    /// `t` is a `TokenPreimage`
    t: TokenPreimage,
    /// `r` is a `Scalar` which is the blinding factor
    r: Scalar,
}

/// Overwrite the token blinding factor with null when it goes out of scope.
impl Drop for Token {
    fn drop(&mut self) {
        self.r.clear();
    }
}

#[cfg(feature = "base64")]
impl_base64!(Token);

#[cfg(feature = "serde")]
impl_serde!(Token);

#[allow(non_snake_case)]
impl Token {
    /// Generates a new random `Token` using the provided random number generator.
    pub fn random<T: Rng + CryptoRng>(rng: &mut T) -> Self {
        let mut seed = [0u8; 64];
        rng.fill(&mut seed);
        let blinding_scalar = Scalar::random(rng);
        Token {
            t: TokenPreimage(seed),
            r: blinding_scalar,
        }
    }

    /// Blinds the `Token`, returning a `BlindedToken` to be sent to the server.
    pub fn blind(&self) -> BlindedToken {
        BlindedToken((self.r * self.t.T()).compress())
    }

    /// Using the blinding factor of the original `Token`, unblind a `SignedToken`
    /// returned from the server.
    ///
    /// Returns a `TokenError` if the `SignedToken` point is not valid.
    pub fn unblind(&self, Q: &SignedToken) -> Result<UnblindedToken, TokenError> {
        Ok(UnblindedToken {
            t: self.t,
            W: (self.r.invert() * Q
                .0
                .decompress()
                .ok_or(TokenError(InternalError::PointDecompressionError))?).compress(),
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
        let blinding_factor = Scalar::from_canonical_bytes(blinding_factor_bits)
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
#[derive(Debug)]
pub struct BlindedToken(pub(crate) CompressedRistretto);

#[cfg(feature = "base64")]
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
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct PublicKey {
    /// `X` is a generator
    pub(crate) X: CompressedRistretto,
    /// `Y` is the committment to a particular key
    ///
    /// \\(Y = X^k\\)
    pub(crate) Y: CompressedRistretto,
}

#[cfg(feature = "base64")]
impl_base64!(PublicKey);

#[cfg(feature = "serde")]
impl_serde!(PublicKey);

impl PublicKey {
    /// Convert this `PublicKey` to a byte array.
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        let mut public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = [0u8; PUBLIC_KEY_LENGTH];

        public_key_bytes[..32].copy_from_slice(&self.X.to_bytes());
        public_key_bytes[32..].copy_from_slice(&self.Y.to_bytes());
        public_key_bytes
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

        let mut x_bits: [u8; 32] = [0u8; 32];
        let mut y_bits: [u8; 32] = [0u8; 32];
        x_bits.copy_from_slice(&bytes[..32]);
        y_bits.copy_from_slice(&bytes[32..]);

        Ok(PublicKey {
            X: CompressedRistretto(x_bits),
            Y: CompressedRistretto(y_bits),
        })
    }
}

/// A `SigningKey` is used to sign a `BlindedToken` and verify an `UnblindedToken`.
///
/// This is a server secret and should NEVER be revealed to the client.
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Debug)]
pub struct SigningKey {
    /// A `PublicKey` showing a committment to this particular key
    pub(crate) public_key: PublicKey,
    /// `k` is the actual key
    pub(crate) k: Scalar,
}

#[cfg(feature = "base64")]
impl_base64!(SigningKey);

#[cfg(feature = "serde")]
impl_serde!(SigningKey);

/// Overwrite signing key with null when it goes out of scope.
impl Drop for SigningKey {
    fn drop(&mut self) {
        self.k.clear();
    }
}

#[allow(non_snake_case)]
impl SigningKey {
    /// Generates a new random `SigningKey` using the provided random number generator.
    pub fn random<T: Rng + CryptoRng>(rng: &mut T) -> Self {
        let X = RistrettoPoint::random(rng);
        let k = Scalar::random(rng);
        let Y = k * X;
        SigningKey {
            k,
            public_key: PublicKey {
                X: X.compress(),
                Y: Y.compress(),
            },
        }
    }

    /// Signs the provided `BlindedToken`
    ///
    /// Returns None if the `BlindedToken` point is not valid.
    pub fn sign(&self, P: &BlindedToken) -> Result<SignedToken, TokenError> {
        Ok(SignedToken(
            (self.k * P
                .0
                .decompress()
                .ok_or(TokenError(InternalError::PointDecompressionError))?).compress(),
        ))
    }

    /// Rederives an `UnblindedToken` via the token preimage of the provided `UnblindedToken`
    ///
    /// W' = T^k = H_1(t)^k
    pub fn rederive_unblinded_token(&self, t: &TokenPreimage) -> UnblindedToken {
        UnblindedToken {
            t: *t,
            W: (self.k * t.T()).compress(),
        }
    }

    /// Convert this `SigningKey` to a byte array.
    pub fn to_bytes(&self) -> [u8; SIGNING_KEY_LENGTH] {
        let mut signing_key_bytes: [u8; SIGNING_KEY_LENGTH] = [0u8; SIGNING_KEY_LENGTH];

        signing_key_bytes[..PUBLIC_KEY_LENGTH].copy_from_slice(&self.public_key.to_bytes());
        signing_key_bytes[PUBLIC_KEY_LENGTH..].copy_from_slice(&self.k.to_bytes());
        signing_key_bytes
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

        let public_key = PublicKey::from_bytes(&bytes[..PUBLIC_KEY_LENGTH])?;

        let mut k_bits: [u8; 32] = [0u8; 32];
        k_bits.copy_from_slice(&bytes[PUBLIC_KEY_LENGTH..]);
        let k = Scalar::from_canonical_bytes(k_bits)
            .ok_or(TokenError(InternalError::ScalarFormatError))?;

        Ok(SigningKey { public_key, k })
    }
}

/// A `SignedToken` is the result of signing an `BlindedToken`.
///
/// \\(Q = P^k = (T^r)^k\\)
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
#[derive(Debug)]
pub struct SignedToken(pub(crate) CompressedRistretto);

#[cfg(feature = "base64")]
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
#[derive(Debug)]
pub struct UnblindedToken {
    /// `t` is the `TokenPreimage`
    pub t: TokenPreimage,
    /// `W` is the unblinded signed `CompressedRistretto` point
    ///
    /// \\(W = Q^(1/r) = (P^k)^(1/r) = ((T^r)^k)^(1/r) = ((T^k)^r)^(1/r) = T^k\\)
    W: CompressedRistretto,
}

#[cfg(feature = "base64")]
impl_base64!(UnblindedToken);

#[cfg(feature = "serde")]
impl_serde!(UnblindedToken);

impl UnblindedToken {
    /// Derive the `VerificationKey` for this particular `UnblindedToken`
    pub fn derive_verification_key<D>(&self) -> VerificationKey
    where
        D: Digest<OutputSize = U64> + Default,
    {
        let mut hash = D::default();
        hash.input(b"hash_derive_key");

        hash.input(self.t.0.as_ref());
        hash.input(self.W.as_bytes());

        let output = hash.result();
        let mut output_bytes = [0u8; 64];
        output_bytes.copy_from_slice(&output.as_slice());

        VerificationKey(output_bytes)
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
        D: Digest<OutputSize = U64> + Input + BlockInput + FixedOutput + Default + Clone,
        D::BlockSize: ArrayLength<u8> + Clone,
    {
        let mut mac = Hmac::<D>::new_varkey(self.0.as_ref()).unwrap();
        mac.input(message);

        VerificationSignature(mac.result())
    }

    /// Use the `VerificationKey` to check that the signature of a message matches the
    /// provided `VerificationSignature`
    pub fn verify<D>(&self, sig: &VerificationSignature, message: &[u8]) -> bool
    where
        D: Digest<OutputSize = U64> + Input + BlockInput + FixedOutput + Default + Clone,
        D::BlockSize: ArrayLength<u8> + Clone,
    {
        &self.sign::<D>(message) == sig
    }
}

/// A `VerificationSignature` which can be verified given the `VerificationKey` and message
#[cfg_attr(not(feature = "cbindgen"), repr(C))]
pub struct VerificationSignature(MacResult<U64>);

#[cfg(feature = "base64")]
impl_base64!(VerificationSignature);

#[cfg(feature = "serde")]
impl_serde!(VerificationSignature);

impl PartialEq for VerificationSignature {
    fn eq(&self, other: &VerificationSignature) -> bool {
        self.0 == other.0
    }
}

#[cfg(any(feature = "base64", feature = "serde"))]
impl VerificationSignature {
    /// Convert this `VerificationSignature` to a byte array.
    /// We intentionally keep this private to avoid accidental non constant time comparisons
    fn to_bytes(&self) -> [u8; VERIFICATION_SIGNATURE_LENGTH] {
        let mut bytes: [u8; VERIFICATION_SIGNATURE_LENGTH] = [0u8; VERIFICATION_SIGNATURE_LENGTH];
        bytes.copy_from_slice(self.0.clone().code().as_slice());
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
        Ok(VerificationSignature(MacResult::new(*arr)))
    }
}
