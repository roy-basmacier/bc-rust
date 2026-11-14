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
//!   `bouncycastle-ecdsa` directly. `bouncycastle-ecdsa` takes any `HMACParams` hash as well; the
//!   keys here fix it to the SHA-2 hash of each curve's strength ([`ECDSAP256PrivateKey`] is
//!   `ECDSAPrivateKey<P256, SHA256>`, and so on).
//!
//! The curves are P-256, P-384, P-521, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 and
//! secp256k1. SP 800-186 allows the Brainpool curves "for interoperability reasons" (Appendix H.1)
//! and secp256k1 "for blockchain-related applications" (Appendix H.2); the module cannot check
//! the caller's purpose, so meeting those conditions is the application's responsibility.
//!
//! # Usage Examples
//!
//! ```
//! # // Under `integrity` power-on fails until `bc-fips-install` has written the slot, which a
//! # // doctest binary never gets.
//! # if cfg!(feature = "integrity") { return; }
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
use bouncycastle_ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle_ecdsa::keys::{ECDSAPrivateKey, ECDSAPublicKey, keygen};
use bouncycastle_sha2::{SHA256, SHA384, SHA512};

// `bouncycastle-ecdsa` is generic over the curve and over any `HMACParams` hash. The facade
// names one pairing per curve, the hash of the curve's security strength, which is the pairing
// the crate's own `ECDSAP256` ... `ECDSABp512r1` aliases make.

/// An ECDSA P-256 private key, with SHA-256.
pub type ECDSAP256PrivateKey = ECDSAPrivateKey<P256, SHA256>;
/// An ECDSA P-256 public key, with SHA-256.
pub type ECDSAP256PublicKey = ECDSAPublicKey<P256, SHA256>;
/// An ECDSA P-384 private key, with SHA-384.
pub type ECDSAP384PrivateKey = ECDSAPrivateKey<P384, SHA384>;
/// An ECDSA P-384 public key, with SHA-384.
pub type ECDSAP384PublicKey = ECDSAPublicKey<P384, SHA384>;
/// An ECDSA P-521 private key, with SHA-512.
pub type ECDSAP521PrivateKey = ECDSAPrivateKey<P521, SHA512>;
/// An ECDSA P-521 public key, with SHA-512.
pub type ECDSAP521PublicKey = ECDSAPublicKey<P521, SHA512>;
/// An ECDSA brainpoolP256r1 private key, with SHA-256.
pub type ECDSABp256r1PrivateKey = ECDSAPrivateKey<Bp256r1, SHA256>;
/// An ECDSA brainpoolP256r1 public key, with SHA-256.
pub type ECDSABp256r1PublicKey = ECDSAPublicKey<Bp256r1, SHA256>;
/// An ECDSA brainpoolP384r1 private key, with SHA-384.
pub type ECDSABp384r1PrivateKey = ECDSAPrivateKey<Bp384r1, SHA384>;
/// An ECDSA brainpoolP384r1 public key, with SHA-384.
pub type ECDSABp384r1PublicKey = ECDSAPublicKey<Bp384r1, SHA384>;
/// An ECDSA brainpoolP512r1 private key, with SHA-512.
pub type ECDSABp512r1PrivateKey = ECDSAPrivateKey<Bp512r1, SHA512>;
/// An ECDSA brainpoolP512r1 public key, with SHA-512.
pub type ECDSABp512r1PublicKey = ECDSAPublicKey<Bp512r1, SHA512>;
/// An ECDSA secp256k1 private key, with SHA-256.
pub type ECDSASecp256K1PrivateKey = ECDSAPrivateKey<Secp256K1, SHA256>;
/// An ECDSA secp256k1 public key, with SHA-256.
pub type ECDSASecp256K1PublicKey = ECDSAPublicKey<Secp256K1, SHA256>;
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

/// An ECDSA P-256 key pair, as `bouncycastle_ecdsa::keys::keygen::<P256, SHA256>` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 128-bit security
/// strength or fails.
pub fn ecdsa_p256_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSAP256PublicKey, ECDSAP256PrivateKey), SignatureError> {
    keygen::<P256, SHA256>(drbg)
}

/// An ECDSA P-384 key pair, as `bouncycastle_ecdsa::keys::keygen::<P384, SHA384>` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 192-bit security
/// strength (so [`HashDRBG_SHA256`] is refused) or fails.
pub fn ecdsa_p384_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSAP384PublicKey, ECDSAP384PrivateKey), SignatureError> {
    keygen::<P384, SHA384>(drbg)
}

/// An ECDSA P-521 key pair, as `bouncycastle_ecdsa::keys::keygen::<P521, SHA512>` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 256-bit security
/// strength (so [`HashDRBG_SHA256`] is refused) or fails.
pub fn ecdsa_p521_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSAP521PublicKey, ECDSAP521PrivateKey), SignatureError> {
    keygen::<P521, SHA512>(drbg)
}

/// An ECDSA brainpoolP256r1 key pair, as `bouncycastle_ecdsa::keys::keygen::<Bp256r1, SHA256>` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 128-bit security
/// strength or fails.
pub fn ecdsa_bp256r1_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSABp256r1PublicKey, ECDSABp256r1PrivateKey), SignatureError> {
    keygen::<Bp256r1, SHA256>(drbg)
}

/// An ECDSA brainpoolP384r1 key pair, as `bouncycastle_ecdsa::keys::keygen::<Bp384r1, SHA384>` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 192-bit security
/// strength (so [`HashDRBG_SHA256`] is refused) or fails.
pub fn ecdsa_bp384r1_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSABp384r1PublicKey, ECDSABp384r1PrivateKey), SignatureError> {
    keygen::<Bp384r1, SHA384>(drbg)
}

/// An ECDSA brainpoolP512r1 key pair, as `bouncycastle_ecdsa::keys::keygen::<Bp512r1, SHA512>` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 256-bit security
/// strength (so [`HashDRBG_SHA256`] is refused) or fails.
pub fn ecdsa_bp512r1_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSABp512r1PublicKey, ECDSABp512r1PrivateKey), SignatureError> {
    keygen::<Bp512r1, SHA512>(drbg)
}

/// An ECDSA secp256k1 key pair, as `bouncycastle_ecdsa::keys::keygen::<Secp256K1, SHA256>` with `drbg`.
///
/// # Errors
/// As that function: [`SignatureError::RNGError`] if `drbg` offers less than 128-bit security
/// strength or fails.
pub fn ecdsa_secp256k1_keygen(
    drbg: &mut impl ApprovedDRBG,
) -> Result<(ECDSASecp256K1PublicKey, ECDSASecp256K1PrivateKey), SignatureError> {
    keygen::<Secp256K1, SHA256>(drbg)
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
