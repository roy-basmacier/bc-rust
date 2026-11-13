//! The module's approved services as concrete types, for a FIPS-approved build (the
//! `approved-only` feature).
//!
//! The algorithm crates stay generic: `HKDF<H>` and `HMAC<H>` take any hash that implements
//! `HMACParams`, which any crate can implement, and ECDSA's key generation and signing take any
//! `&mut dyn RNG`. A compile-time switch cannot remove a generic, so a FIPS-approved application
//! uses the services through this module instead, which names only approved choices:
//!
//! * HKDF over SHA-2, as the aliases [`HKDF_SHA256`], [`HKDF_SHA384`] and [`HKDF_SHA512`] (each
//!   hash is in SP 800-56C Rev. 2, Table 4, "MAC( salt, Z, …) = HMAC-hash( salt, Z )").
//! * HMAC over SHA-2, as the aliases [`HMAC_SHA224`] to [`HMAC_SHA512_256`].
//! * ECDSA key generation and signing with a random `k`, drawing only from an SP 800-90A Hash_DRBG
//!   ([`HashDRBG_SHA256`], [`HashDRBG_SHA512`]): the [`ApprovedDRBG`] trait is sealed, so no other
//!   RNG can be passed. Deterministic ECDSA and verification draw nothing, and are used through
//!   `bouncycastle-ecdsa` directly.
//!
//! The curves are P-256, P-384, P-521, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 and
//! secp256k1. SP 800-186 allows the Brainpool curves "for interoperability reasons" (Appendix H.1)
//! and secp256k1 "for blockchain-related applications" (Appendix H.2); the module cannot check
//! the caller's purpose, so meeting those conditions is the application's responsibility.
//!
//! # Usage Examples
//!
//! ```
//! # #[cfg(feature = "sha2")]
//! # bouncycastle_fips::power_on_self_tests().expect("self-tests pass");
//! use bouncycastle_core::signature_key::VerifyingKey;
//! use bouncycastle_fips::approved::{HashDRBG_SHA512, ecdsa_p256_keygen, ecdsa_sign};
//!
//! let mut drbg = HashDRBG_SHA512::new_from_os();
//! let (pk, sk) = ecdsa_p256_keygen(&mut drbg).expect("a SHA-512 DRBG is strong enough");
//! let sig = ecdsa_sign(&sk, &mut drbg, b"message").expect("signing succeeds");
//! pk.verify(b"message", None, &sig).expect("the signature verifies");
//! ```

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::signature_key::{SignatureAlgorithm, SigningKey};
use bouncycastle_core::traits::RNG;
use bouncycastle_ecdsa::{
    keys_bp256r1, keys_bp384r1, keys_bp512r1, keys_p256, keys_p256k1, keys_p384, keys_p521,
};

pub use bouncycastle_ecdsa::keys_bp256r1::{ECDSABp256r1PrivateKey, ECDSABp256r1PublicKey};
pub use bouncycastle_ecdsa::keys_bp384r1::{ECDSABp384r1PrivateKey, ECDSABp384r1PublicKey};
pub use bouncycastle_ecdsa::keys_bp512r1::{ECDSABp512r1PrivateKey, ECDSABp512r1PublicKey};
pub use bouncycastle_ecdsa::keys_p256::{ECDSAP256PrivateKey, ECDSAP256PublicKey};
pub use bouncycastle_ecdsa::keys_p256k1::{ECDSASecp256K1PrivateKey, ECDSASecp256K1PublicKey};
pub use bouncycastle_ecdsa::keys_p384::{ECDSAP384PrivateKey, ECDSAP384PublicKey};
pub use bouncycastle_ecdsa::keys_p521::{ECDSAP521PrivateKey, ECDSAP521PublicKey};
pub use bouncycastle_rng::{HashDRBG_SHA256, HashDRBG_SHA512};
pub use bouncycastle_sha2::hkdf::{HKDF_SHA256, HKDF_SHA384, HKDF_SHA512};
pub use bouncycastle_sha2::hmac::{
    HMAC_SHA224, HMAC_SHA256, HMAC_SHA384, HMAC_SHA512, HMAC_SHA512_224, HMAC_SHA512_256,
};

/// The seal: only this module can implement [`ApprovedDRBG`] and [`ApprovedECDSAKey`].
mod sealed {
    pub trait Sealed {}
}

/// An approved random bit generator: an SP 800-90A Hash_DRBG. Sealed; implemented only for
/// [`HashDRBG_SHA256`] and [`HashDRBG_SHA512`].
pub trait ApprovedDRBG: RNG + sealed::Sealed {}

impl sealed::Sealed for HashDRBG_SHA256 {}
impl ApprovedDRBG for HashDRBG_SHA256 {}
impl sealed::Sealed for HashDRBG_SHA512 {}
impl ApprovedDRBG for HashDRBG_SHA512 {}

/// An ECDSA private key on an approved curve. Sealed; implemented only for the seven private key
/// types re-exported here.
pub trait ApprovedECDSAKey: sealed::Sealed {}

impl sealed::Sealed for ECDSAP256PrivateKey {}
impl ApprovedECDSAKey for ECDSAP256PrivateKey {}
impl sealed::Sealed for ECDSAP384PrivateKey {}
impl ApprovedECDSAKey for ECDSAP384PrivateKey {}
impl sealed::Sealed for ECDSAP521PrivateKey {}
impl ApprovedECDSAKey for ECDSAP521PrivateKey {}
impl sealed::Sealed for ECDSABp256r1PrivateKey {}
impl ApprovedECDSAKey for ECDSABp256r1PrivateKey {}
impl sealed::Sealed for ECDSABp384r1PrivateKey {}
impl ApprovedECDSAKey for ECDSABp384r1PrivateKey {}
impl sealed::Sealed for ECDSABp512r1PrivateKey {}
impl ApprovedECDSAKey for ECDSABp512r1PrivateKey {}
impl sealed::Sealed for ECDSASecp256K1PrivateKey {}
impl ApprovedECDSAKey for ECDSASecp256K1PrivateKey {}

/// An ECDSA P-256 key pair, as `bouncycastle_ecdsa::keys_p256::keygen` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 128-bit security
/// strength or fails.
pub fn ecdsa_p256_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSAP256PublicKey, ECDSAP256PrivateKey), SignatureError> {
    keys_p256::keygen(drbg)
}

/// An ECDSA P-384 key pair, as `bouncycastle_ecdsa::keys_p384::keygen` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 192-bit security
/// strength (so [`HashDRBG_SHA256`] is refused) or fails.
pub fn ecdsa_p384_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSAP384PublicKey, ECDSAP384PrivateKey), SignatureError> {
    keys_p384::keygen(drbg)
}

/// An ECDSA P-521 key pair, as `bouncycastle_ecdsa::keys_p521::keygen` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 256-bit security
/// strength (so [`HashDRBG_SHA256`] is refused) or fails.
pub fn ecdsa_p521_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSAP521PublicKey, ECDSAP521PrivateKey), SignatureError> {
    keys_p521::keygen(drbg)
}

/// An ECDSA brainpoolP256r1 key pair, as `bouncycastle_ecdsa::keys_bp256r1::keygen` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 128-bit security
/// strength or fails.
pub fn ecdsa_bp256r1_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSABp256r1PublicKey, ECDSABp256r1PrivateKey), SignatureError> {
    keys_bp256r1::keygen(drbg)
}

/// An ECDSA brainpoolP384r1 key pair, as `bouncycastle_ecdsa::keys_bp384r1::keygen` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 192-bit security
/// strength (so [`HashDRBG_SHA256`] is refused) or fails.
pub fn ecdsa_bp384r1_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSABp384r1PublicKey, ECDSABp384r1PrivateKey), SignatureError> {
    keys_bp384r1::keygen(drbg)
}

/// An ECDSA brainpoolP512r1 key pair, as `bouncycastle_ecdsa::keys_bp512r1::keygen` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 256-bit security
/// strength (so [`HashDRBG_SHA256`] is refused) or fails.
pub fn ecdsa_bp512r1_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSABp512r1PublicKey, ECDSABp512r1PrivateKey), SignatureError> {
    keys_bp512r1::keygen(drbg)
}

/// An ECDSA secp256k1 key pair, as `bouncycastle_ecdsa::keys_p256k1::keygen` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 128-bit security
/// strength or fails.
pub fn ecdsa_secp256k1_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSASecp256K1PublicKey, ECDSASecp256K1PrivateKey), SignatureError> {
    keys_p256k1::keygen(drbg)
}

/// Begins an ECDSA signature with `sk`, drawing the per-message secret `k` from `drbg`: the
/// key's `SigningKey::create_signer` with no context.
///
/// # Errors
/// As `create_signer`: [`SignatureError::RNGError`] if `drbg` fails.
pub fn ecdsa_create_signer<'k, K, A, const SIG_LEN: usize>(
    sk: &'k K,
    drbg: &mut impl ApprovedDRBG,
) -> Result<K::Signer<'k>, SignatureError>
where
    K: ApprovedECDSAKey + SigningKey<A, SIG_LEN>,
    A: SignatureAlgorithm,
{
    sk.create_signer(drbg, None)
}

/// The ECDSA signature of `msg` under `sk`, with `k` drawn from `drbg`: the key's
/// `SigningKey::sign` with no context.
///
/// # Errors
/// Those of [`ecdsa_create_signer`], and [`SignatureError::GenericError`] in the case, of
/// probability about 2^-n for an n-bit curve order, that `r` or `s` comes out zero.
pub fn ecdsa_sign<K, A, const SIG_LEN: usize>(
    sk: &K,
    drbg: &mut impl ApprovedDRBG,
    msg: &[u8],
) -> Result<[u8; SIG_LEN], SignatureError>
where
    K: ApprovedECDSAKey + SigningKey<A, SIG_LEN>,
    A: SignatureAlgorithm,
{
    sk.sign(drbg, msg, None)
}

/// As [`ecdsa_sign`], into `output`, which is zeroized first; returns the number of bytes
/// written, always `SIG_LEN`.
///
/// # Errors
/// As [`ecdsa_sign`].
pub fn ecdsa_sign_out<K, A, const SIG_LEN: usize>(
    sk: &K,
    drbg: &mut impl ApprovedDRBG,
    msg: &[u8],
    output: &mut [u8; SIG_LEN],
) -> Result<usize, SignatureError>
where
    K: ApprovedECDSAKey + SigningKey<A, SIG_LEN>,
    A: SignatureAlgorithm,
{
    sk.sign_out(drbg, msg, None, output)
}
