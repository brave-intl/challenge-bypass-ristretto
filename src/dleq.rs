#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;

#[cfg(all(feature = "std"))]
use std::vec::Vec;

use core::iter;

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use errors::{InternalError, TokenError};
use oprf::*;

/// The length of a `DLEQProof`, in bytes.
pub const DLEQ_PROOF_LENGTH: usize = 64;

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

        let A = &t * &constants::RISTRETTO_BASEPOINT_TABLE;
        let B = t * P;

        let mut h = D::default();

        let X = constants::RISTRETTO_BASEPOINT_COMPRESSED;
        let Y = k.public_key.0;
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
        let X = constants::RISTRETTO_BASEPOINT_COMPRESSED;
        let Y = public_key.0;

        let A = (&self.s * &constants::RISTRETTO_BASEPOINT_TABLE)
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

        h.input(constants::RISTRETTO_BASEPOINT_COMPRESSED.as_bytes());
        h.input(public_key.0.as_bytes());

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

    /// Verify the `BatchDLEQProof` then unblind the `SignedToken`s using each corresponding `Token`
    pub fn verify_and_unblind<'a, D, I>(
        &self,
        tokens: I,
        blinded_tokens: &[BlindedToken],
        signed_tokens: &[SignedToken],
        public_key: &PublicKey,
    ) -> Result<Vec<UnblindedToken>, TokenError>
    where
        D: Digest<OutputSize = U64> + Default,
        I: IntoIterator<Item = &'a Token>,
    {
        self.verify::<D>(blinded_tokens, signed_tokens, public_key)?;

        let unblinded_tokens: Result<Vec<UnblindedToken>, TokenError> = tokens
            .into_iter()
            .zip(signed_tokens.iter())
            .map(|(token, signed_token)| token.unblind(signed_token))
            .collect();
        unblinded_tokens.and_then(|unblinded_tokens| {
            if unblinded_tokens.len() != signed_tokens.len() {
                return Err(TokenError(InternalError::LengthMismatchError));
            }
            Ok(unblinded_tokens)
        })
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

#[cfg(test)]
mod tests {
    use curve25519_dalek::ristretto::CompressedRistretto;
    use oprf::Token;
    use rand::rngs::OsRng;
    use sha2::Sha512;

    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn works() {
        let mut rng = OsRng::new().unwrap();

        let key1 = SigningKey::random(&mut rng);
        let key2 = SigningKey::random(&mut rng);

        let P = RistrettoPoint::random(&mut rng);
        let Q = key1.k * P;

        let proof = DLEQProof::_new::<Sha512, _>(&mut rng, P, Q, &key1).unwrap();

        assert!(proof._verify::<Sha512>(P, Q, &key1.public_key).is_ok());

        let P = RistrettoPoint::random(&mut rng);
        let Q = key2.k * P;

        let proof = DLEQProof::_new::<Sha512, _>(&mut rng, P, Q, &key1).unwrap();

        assert!(!proof._verify::<Sha512>(P, Q, &key1.public_key).is_ok());
    }

    #[cfg(feature = "base64")]
    #[allow(non_snake_case)]
    #[test]
    fn vector_tests() {
        // Generated using tools/dleq-test-gen
        let vectors = [
("SlPD+7xZlw7l+Fr4E4dd/8E6kEouU65+ZfoN6m5iyQE=", "nGajOcg0T5IvwyBstdroFKWUwBd90yNcJU2cQJpluAg=", "RkvaRYJENhsWmaWMWXj7QnwgMMoDt4iYOyEiRBwQ5Aw=", "cp6yHGUJjHOLXt9rv1wV9K6GuMDGRoznEljJNar7zxc=", "XbkmyWU9o+EUyUM7Dj0YU4389lguLoTVDTJ3sVp2xAs3VffxEUXkcv5JEOk3TuWRsaL5dk07u0KRAVvu1SHJAg=="),
("7eo7zzSJFODsiADhOXJlbYxD1BvX5MwhkpJmG9QTEQY=", "6LTXo+hQaWBrgNRp1+vcScJttpUZWrt91ZTs3eD6DB8=", "xlMTcTB9FJE5jNimEWd5j+cOXo6DCWaICPziWym6sxg=", "UrINHL3LHXMt8PI9LLEcFLcLZ5FtvJosJD5Iu3sLNF4=", "YUkFBg0Vw8Q7YeOjoDq/+fvvfDqwZJ0aNO7bO3xNAAc+JgLcmcslD4tTpejqKszKomn5hIKSrXm1yE+KPKTGDg=="),
("7oD3U1ZwWQN/2eZhiXfHtnwmhR+yl3P7Gta+T123awI=", "vtiIh6vgqE9kaR/gvfo9rxps1pehPweuB1iJEM45ySc=", "9Knf2H2WJsYuRfdPKr35gwAwf+S5jlWMR2Z2htcf10g=", "DrL0Cx/U+1eyKT/4p3Q2dgU3W+HjgGWYjX7H8fbDUBk=", "9HzYX9bioi0DPDl/VhRqgNdnikKveUHHOyOxlpx4wAzy8PAdZEJ0vgoZDcXTnnI+/6/8RtxpQMBbpQ34BJHXBw=="),
("9WYryPcY2pZRP59ct9TDJzpiphZSBU3vHH3KQwGZKAo=", "EMUGgOYuU6TLCoA8ElaZUeUstPRo9OXiUK9V/YT/cGg=", "pKvuK6b09tuS0eCmbox3X7OBtSzn+fkPknlCluLTylM=", "ZA1zPTuQ9iZvFInWHPH0Oms9unhFHZkUj+TYZTqj4mY=", "t1P9ekmyO0rYhzXiedWA/Ac8wejOL37xdXIQppQB0QWlw7Fg/JLymggSASPxEgRBTh/VF7m4BrWD95+7gy0+DA=="),
("tviSLm/W8oFds67y9lMs990fjh08hQNV17/4V2bmOQY=", "5ufRlCvVKvXp1yuxxS7Jvw9LSwQUl6Q/MlT6HY2l1Hc=", "lIha1HepcnEfwI4t2RUdu7634Zyu80+RGeVFFmY7VQo=", "4l0+f9giNahNnmwH1XU92pqmTahwAm73fbBTtDLPHzM=", "jT9xZiOo68ZUV1S1UtrmnUvC/Zfuzbns2SkdJEVqPweK8qwIzd34ohTjuh847BZVy4mPf4rFDj0pyA+GjYyKAA=="),
        ];
        for i in 0..vectors.len() {
            let (k, Y, P, Q_b64, dleq_b64) = vectors[i];

            let server_key = SigningKey::decode_base64(k).unwrap();

            assert_eq!(server_key.public_key.encode_base64(), Y);

            let P_bytes = base64::decode(P).unwrap();
            let mut P_bits: [u8; 32] = [0u8; 32];
            P_bits.copy_from_slice(&P_bytes[..32]);
            let P = CompressedRistretto(P_bits).decompress().unwrap();

            let Q = P * server_key.k;

            assert_eq!(base64::encode(&Q.compress().to_bytes()[..]), Q_b64);

            let mut seed: [u8; 32] = [0u8; 32];
            let mut prng: ChaChaRng = SeedableRng::from_seed(seed);

            let dleq = DLEQProof::_new::<Sha512, _>(&mut prng, P, Q, &server_key).unwrap();
            assert_eq!(dleq.encode_base64(), dleq_b64);

            assert!(dleq._verify::<Sha512>(P, Q, &server_key.public_key).is_ok());
        }
    }

    #[cfg(feature = "base64")]
    #[allow(non_snake_case)]
    #[test]
    fn batch_vector_tests() {
        // Generated using tools/dleq-test-gen
        let vectors = [
("3+VDYxU5XClaZqv8mXdSxPA6LVgMjhnHZAEL0aQk1Ag=", "VIOf/CsOJJRtf5+Q41Y7zPd1x9o5p9NMaUKrdNiBQng=", "dnHYNecVks7WACjwmSv3q4D+4WXrykjSB8xDepodqzo=,Ho6GDKcJPq6xV9rgkvmUZck37MH4fkaLtf6oGGYBqlQ=,2LnpWgUZmlTyWtaIZ/g2dm03QwgPeWymHdCgtBx1NFw=,7sTlD8oqdioIEBSN1PMt9ggtUUHzpP5m39ow88Ponzw=,SjinBBbi8e+4CeEV+rTNeVaBbtIZFDpou1SBT/mtvhI=", "pNkMyqCcdyINeh55ZDbQoJUgn8IWkCUm0fapbPovJx8=,JmgBji8nAGMc4WEBVJQ29hniN/T8UZ3WLMrr/aLlakA=,hH9yysFjFx/NXsix7N7w1ftnUPgccM1ZvAszzQD18DY=,dJzhbX7Xytb7nlw7PIC67Mrg+Chfnj7Oc4xNOMEUMH0=,wMCyMp/C3EW+gKxcMZWnx3tshnZ0oa5zNgZj6GfZci0=", "SPYURTHMHuIon+kZhVBenqV4zDvSStoWkMWHgewF7SE=", "1gyuf5ymtyQSnOqYSxEBDKavduQe+LA2CIZIsfB9ijc=", "dtf18PF98KW4/lTpmlvzOPuXKKNj8MhtNyfNoHB2NwQ2meA3rSFGDkft6ovBdDUlzLJBGlySz1ikKnUKcSsaCg=="),
("gfes2hjQSpt6QOBJnz4t/N/utBkdDS+W4GRQIYjb/wQ=", "wHJTHUZLBhyf2pB18jB2LoNJjio4BI4z7VnoXnpD9jQ=", "Tt9+maMuYuRGwP707/6qpUxT95vCvo6mfsuEiw6Mgm4=,tsE4OlQnzLBu2tLHvYoexTnCrEcGBGLx2wVGvYf9dhg=,yJD1w+qxFVRB72tKgutXfp1H29quqeGOSGZFKmJtjnA=,lOzlh61kr4nhdQKUxM5cEgg6bqof0jiHXbEKC6Ka8H8=,Qh2siPKVS/cz14aUFAwAKo90wruH/T773JYtGFZqHVU=", "1kG5ny6G6WdYW47bqPkc/46Sj39HTCa/bT2GY6TEXnY=,UsZEO7WSzM5PdrLipLcicWlJG4L9U3RfvMStmY7KEX0=,cO2106oZ0FI0EpV8sCrZEv2tjDGVmIEE3M+rIe4KKW0=,UPJOD3VOoUZvPKdYy8FkeXbys5mYSWmJ00hmjMfr6nk=,EkCBieLQvdBoM1nQxFkNw2i8bjCJ6W8lrgP9eHkCyUA=", "wvu0ubff28p7viNhhPimN2u7kAVy/ISj7iiUlDFsegM=", "7K+RdATkhtrZefkFuNG6TyMjEOQ5/L4Dl7rZi4JbDnw=", "88x3CIUi9OoTVy0ekk5dS9iAj8Ai+nz8lrPfGXKs5wnrREg2AomuFgnyVICIiG/oLpbW+ZfdSQEUozhAfm7nBg=="),
("23TsbDwm/wxRP0Gct3OK0/qaEjk9/OmqoufRPQN32wk=", "pJh62HrNgGC2p+W1ZyxyshvL7YnLV2KUN+78NvuyHWE=", "MjhMiq+lC5cps0vut+eznnIm0Emf6fqZiG7efa03c1k=,0neLPqx+mlGEzh83VcTHDu+PvP3TIebxOuo89T/D9Ek=,MtgEm18Rci4RMq5JJCz06m4EMtttL61tSpq1ZXL9FGc=,aLOJ8sfEFuQZu7FIENZ67isxmbdHRw6+8TaAeeNLvwk=,4J45hkx8knJypxe+CPwR3LH71X5PK85nsdvUyQ/4SCg=", "CD8eQf5eeln+9umaTM+2+JmPm2p9TZZCuuMeWZxAclc=,6CnzwfiWtNW6R8pSxKn5MUhEXA5ddowEULH2f23JgzE=,1hXHqOHh5BwE+/Vymt8chDjejzOiQ/r9WGSZBqfKD24=,IEI8ibTTC2QafWtPsuYL1H4DXj9LkfpFwvPSrmS/nyk=,aAB78g4QNs03gegi46ZRuJKu3X3VKwOyVcTm1BJ+CnQ=", "JLDtL4XdaKXfM69mqPKyB0IjSBGMKFQLxRrBNx6bVVs=", "Fo8woFaN3qJM+0k3UuKzHHXnWFZbN5oZtqFBXjLTrVk=", "y+NT8G6YSTsGo5L70+Pj7MbzN/orwMn4q9kN+cWJIAjMLpsRowZwy5bYS9725NW7jNwdX4f3L6b0LvvJ4zsuAw=="),
("lE2Tu2LzhNgU77KnsEFbqVYOc5wsbMYYzBQOcpi32Ag=", "EuJk2I4y6ZrbIn04deR+lzJS1xrBIpN+RthbPknv+gA=", "jGb/yJT2qrVOiiXBd/2p99nwjZ8F/OG63RVOdfEY6xI=,FpC/vuzh4F1bsnO9gghvfwLOj43sAh83R1DGEi8q+3w=,ICzVE9rY5roZQAOnCuHMCVU4e4rUHLE72ifSryVcQhA=,ijtepj269DyT5FQB+WEOasRs5yhqFiyIpNnzHjtfVRk=,0HXVVoth6V+3GGRGB07kJOXRt3VG1OUjPOumGpgccyQ=", "0iQWbnMLnSqtnttVKC7QS1v3i4JFPyFNvexBKIQzTy0=,ikwYgikxp7hFK3KZleHg6r/OLfOIX0r6sx8fsFSi4Qo=,FERyMip8iLR9MLMdpjcq3c0fjEUtBYu4tMkHtDcZP1I=,Gj6JZZdxcO/3Wle8CgkqkTYYTXxNCwwJdb3OAuXSmTI=,QKqMxNGgxeqXdVfH3T+1gtZU13IJVHq46MrEKFAsFVk=", "FrM4Z1YfSXQnA42Ko73zyzBGsPGhYG9Q6Hyyi9ydZG4=", "2sddY0mNrmQCZEV0VVqQ4Pk0w3w6z+++ePb+9m2zyRQ=", "uDu4pqqFl+3DB6l2stbG/XZsBPJjtjHGFPeYHFDNBA7BKO+fjGfW4fqonbbgEPQq2ejz3xe7BKg++LYleUAVBw=="),
("5nfTfFFQzawMgrorZbZNCIghq2Jb4dUbGTp22AdBmQw=", "qtfxMqySfIh8p21NHqvJc6feAsjNc8Hgs/2bs+abmEM=", "XKtm6Y4UXhrxtGhJOkn5Xgg7+fhIlHSVd63mHg4OxyM=,fqaYcVb98Jd82CMXTnibuLQJtKZtcOHLd7zhCtHRCCE=,1L9ojdSdfk0CvIoipYqR4K4HETaHp1is9s6m9V9+AUc=,8GWU/iY819DALqChfM3aFhHn3bj0FpJLktW6ZYYJE0A=,7vtPYUMo8lqzkbsj5HPlzykK/TJ1bAOFoHwkCu38ITs=", "nhh4yCvrZGfZRx365HO7RTlcIgFTXwevh+wXEbe0QQg=,FEPl794KaxOUfco0wx5KPoHNijZjWANQDK64MT52Mik=,PjfhEDfvM9GMXjy1HjOyqAhTSlaBG4TKAPmSkU0j5yo=,CNPp1E4wo6gMbKCZRcG3sHA6PuEdVvszZK6IL1/SC2c=,DK4UqyE4OzdxSrL7IOUaWZyep3L8hoa37JPv3IRBPy4=", "OCKqPD6aOVBMRQT8H6ke98/hd9FkReKtsFKowNeqfi4=", "vIa8JkEqlQsDzsAGERke9YjqplIE5klwZiq7QZHlT0E=", "c2WMBejq7GLX+LcZNh31eViecinXXf+plCCgTMb4pAihpmCvMjfDu4ET1g//xPf8yg6aADpv+DPgm1bcclw3Bw=="),
        ];
        for i in 0..vectors.len() {
            let (k, Y, P, Q, M_b64, Z_b64, dleq_b64) = vectors[i];

            let server_key = SigningKey::decode_base64(k).unwrap();

            assert_eq!(server_key.public_key.encode_base64(), Y);

            let P: Vec<&str> = P.split(',').collect();
            let Q: Vec<&str> = Q.split(',').collect();

            let P: Vec<BlindedToken> = P
                .iter()
                .map(|P_i| BlindedToken::decode_base64(P_i).unwrap())
                .collect();

            let Q: Vec<SignedToken> = P
                .iter()
                .zip(Q.into_iter())
                .map(|(P_i, Q_i_b64)| {
                    let Q_i = server_key.sign(P_i).unwrap();
                    assert_eq!(Q_i.encode_base64(), Q_i_b64);
                    Q_i
                })
                .collect();

            let (M, Z) =
                BatchDLEQProof::calculate_composites::<Sha512>(&P, &Q, &server_key.public_key)
                    .unwrap();

            assert_eq!(base64::encode(&M.compress().to_bytes()[..]), M_b64);
            assert_eq!(base64::encode(&Z.compress().to_bytes()[..]), Z_b64);

            let mut seed: [u8; 32] = [0u8; 32];
            let mut prng: ChaChaRng = SeedableRng::from_seed(seed);

            let batch_proof =
                BatchDLEQProof::new::<Sha512, _>(&mut prng, &P, &Q, &server_key).unwrap();
            assert_eq!(batch_proof.encode_base64(), dleq_b64);

            assert!(batch_proof
                .verify::<Sha512>(&P, &Q, &server_key.public_key)
                .is_ok());
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn batch_works() {
        use std::vec::Vec;

        let mut rng = OsRng::new().unwrap();

        let key = SigningKey::random(&mut rng);

        let blinded_tokens = vec![Token::random::<Sha512, _>(&mut rng).blind()];
        let signed_tokens: Vec<SignedToken> = blinded_tokens
            .iter()
            .filter_map(|t| key.sign(t).ok())
            .collect();

        let batch_proof =
            BatchDLEQProof::new::<Sha512, _>(&mut rng, &blinded_tokens, &signed_tokens, &key)
                .unwrap();

        assert!(batch_proof
            .verify::<Sha512>(&blinded_tokens, &signed_tokens, &key.public_key)
            .is_ok());
    }
}
