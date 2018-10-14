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

#[cfg(feature = "serde")]
use serde::de::Error as SerdeError;
#[cfg(feature = "serde")]
use serde::de::Visitor;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde::{Deserializer, Serializer};

use errors::{InternalError, TokenError};

/// The length of a `BlindedToken`, in bytes.
pub const BLINDED_TOKEN_LENGTH: usize = 32;

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
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TokenPreimage([u8; 64]);
#[allow(non_snake_case)]
impl TokenPreimage {
    pub(crate) fn T(&self) -> RistrettoPoint {
        RistrettoPoint::from_uniform_bytes(&self.0)
    }
}

impl Debug for TokenPreimage {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "TokenPreimage: {:?}", &self.0[..])
    }
}

/// A `Token` consists of a randomly chosen preimage and blinding factor.
///
/// Since a token includes the blinding factor it should be treated
/// as a client secret and NEVER revealed to the server.
#[repr(C)]
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
}

/// A `BlindedToken` is sent to the server for signing.
///
/// It is the result of the scalar multiplication of the point derived from the token
/// preimage with the blinding factor.
///
/// \\(P = T^r = H_1(t)^r\\)
#[repr(C)]
#[derive(Debug)]
pub struct BlindedToken(CompressedRistretto);

impl BlindedToken {
    /// Convert this `BlindedToken` to a byte array.
    pub fn to_bytes(&self) -> [u8; BLINDED_TOKEN_LENGTH] {
        self.0.to_bytes()
    }

    /// Construct a `BlindedToken` from a slice of bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<BlindedToken, TokenError> {
        if bytes.len() != BLINDED_TOKEN_LENGTH {
            return Err(TokenError(InternalError::BytesLengthError {
                name: "BlindedToken",
                length: BLINDED_TOKEN_LENGTH,
            }));
        }

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[..32]);
        Ok(BlindedToken(CompressedRistretto(bits)))
    }
}

#[cfg(feature = "serde")]
impl Serialize for BlindedToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.to_bytes())
    }
}

#[cfg(feature = "serde")]
impl<'d> Deserialize<'d> for BlindedToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        struct BlindedTokenVisitor;

        impl<'d> Visitor<'d> for BlindedTokenVisitor {
            type Value = BlindedToken;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("A blinded token must be 32 bytes.")
            }

            fn visit_bytes<E>(self, bytes: &[u8]) -> Result<BlindedToken, E>
            where
                E: SerdeError,
            {
                BlindedToken::from_bytes(bytes)
                    .or(Err(SerdeError::invalid_length(bytes.len(), &self)))
            }
        }
        deserializer.deserialize_bytes(BlindedTokenVisitor)
    }
}

/// A `PublicKey` is a committment by the server to a particular `SigningKey`.
#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct PublicKey {
    /// `X` is a generator
    X: CompressedRistretto,
    /// `Y` is the committment to a particular key
    ///
    /// \\(Y = X^k\\)
    Y: CompressedRistretto,
}

/// A `SigningKey` is used to sign a `BlindedToken` and verify an `UnblindedToken`.
///
/// This is a server secret and should NEVER be revealed to the client.
#[repr(C)]
#[derive(Debug)]
pub struct SigningKey {
    /// `k` is the actual key
    pub(crate) k: Scalar,
    /// A `PublicKey` showing a committment to this particular key
    public_key: PublicKey,
}

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
}

/// A `SignedToken` is the result of signing an `BlindedToken`.
///
/// \\(Q = P^k = (T^r)^k\\)
#[repr(C)]
#[derive(Debug)]
pub struct SignedToken(CompressedRistretto);

/// An `UnblindedToken` is the result of unblinding a `SignedToken`.
///
/// While both the client and server both "know" this value,
/// it should nevertheless not be sent between the two.
#[repr(C)]
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
}

/// The shared `VerificationKey` for proving / verifying the validity of an `UnblindedToken`.
///
/// \\(K = H_2(t, W)\\)
#[repr(C)]
pub struct VerificationKey([u8; 64]);

impl Debug for VerificationKey {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(f, "VerificationKey: {:?}", &self.0[..])
    }
}

impl VerificationKey {
    /// Use the `VerificationKey` to "sign" a message, producing a `VerificationSignature`
    pub fn sign<D>(&self, message: &[u8]) -> VerificationSignature<D::OutputSize>
    where
        D: Input + BlockInput + FixedOutput + Default + Clone,
        D::BlockSize: ArrayLength<u8> + Clone,
        D::OutputSize: ArrayLength<u8>,
    {
        let mut mac = Hmac::<D>::new_varkey(self.0.as_ref()).unwrap();
        mac.input(message);

        VerificationSignature(mac.result())
    }
}

/// A `VerificationSignature` which can be checked for equality between the client and server.
#[repr(C)]
pub struct VerificationSignature<N>(MacResult<N>)
where
    N: ArrayLength<u8>;

impl<N> PartialEq for VerificationSignature<N>
where
    N: ArrayLength<u8>,
{
    fn eq(&self, other: &VerificationSignature<N>) -> bool {
        self.0 == other.0
    }
}
