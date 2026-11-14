//! The `approved` facade of an `approved-only` build: each wrapper does what the function it
//! wraps does with the same DRBG state, the DRBG strength checks still apply, and the re-exported
//! aliases are the algorithm crates' own.
//!
//! The wrappers' signatures are what keeps a non-approved RNG out; that `ApprovedDRBG` is sealed
//! is a compile-time property, so no test here could pass anything else to observe a refusal.

#![cfg(feature = "approved-only")]

use std::any::TypeId;
use std::fmt::Debug;

use bouncycastle_core::errors::{RNGError, SignatureError};
use bouncycastle_core::key_material::{KeyMaterial0, KeyMaterial512, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::signature_key::{SignatureAlgorithm, SigningKey, VerifyingKey};
use bouncycastle_core::traits::{RNG, SignatureSigner};
use bouncycastle_ec::{Bp256r1, Bp384r1, Bp512r1, P256, P384, P521, Secp256K1};
use bouncycastle_ecdsa::keys::keygen;
use bouncycastle_fips::approved::*;
use bouncycastle_rng::Sp80090ADrbg;
use bouncycastle_rng::hazmat::NewUninitialized;
use bouncycastle_sha2::{SHA256, SHA384, SHA512};

/// SHA-2's self-test, which the DRBG and ECDSA's hashes need under the `sha2` feature, then
/// ECDSA's, which gates its key pairs and signers under the `ecdsa` feature (and needs SHA-256 to
/// have passed). Not the whole power-on, which fails under `integrity`.
fn power_on() {
    #[cfg(feature = "sha2")]
    bouncycastle_sha2::self_test().expect("SHA-2 self-tests pass");
    #[cfg(feature = "ecdsa")]
    bouncycastle_ecdsa::self_test().expect("ECDSA self-tests pass");
}

/// A Hash_DRBG instantiated from a fixed seed, so two of them produce the same output.
fn drbg_sha512(seed: u8) -> HashDRBG_SHA512 {
    let mut drbg = HashDRBG_SHA512::new_uninitialized();
    let seed = KeyMaterial512::from_bytes_as_type(&[seed; 64], KeyType::Seed).unwrap();
    drbg.instantiate(
        false,
        seed,
        &KeyMaterial0::new(),
        b"approved_tests",
        SecurityStrength::_256bit,
    )
    .unwrap();
    drbg
}

fn drbg_sha256(seed: u8) -> HashDRBG_SHA256 {
    let mut drbg = HashDRBG_SHA256::new_uninitialized();
    let seed = KeyMaterial512::from_bytes_as_type(&[seed; 32], KeyType::Seed).unwrap();
    drbg.instantiate(
        false,
        seed,
        &KeyMaterial0::new(),
        b"approved_tests",
        SecurityStrength::_128bit,
    )
    .unwrap();
    drbg
}

type KeyPair<Pk, Sk> = Result<(Pk, Sk), SignatureError>;

/// One curve through the facade against the same calls made directly on `bouncycastle-ecdsa`,
/// each side with its own identically seeded DRBG: the same key pair, the same signatures from
/// each signing form, and the signatures verify.
fn same_as_direct<Pk, Sk, A, const SIG_LEN: usize>(
    facade_keygen: impl Fn(&mut HashDRBG_SHA512) -> KeyPair<Pk, Sk>,
    direct_keygen: impl Fn(&mut dyn RNG) -> KeyPair<Pk, Sk>,
) where
    Pk: VerifyingKey<A, SIG_LEN> + PartialEq + Debug,
    Sk: ApprovedECDSAKey + SigningKey<A, SIG_LEN> + PartialEq + Debug,
    A: SignatureAlgorithm,
{
    let mut facade = drbg_sha512(1);
    let mut direct = drbg_sha512(1);
    let (pk, sk) = facade_keygen(&mut facade).unwrap();
    let (direct_pk, direct_sk) = direct_keygen(&mut direct).unwrap();
    assert_eq!(pk, direct_pk);
    assert_eq!(sk, direct_sk);

    let msg = b"approved-only facade";
    let sig = ecdsa_sign(&sk, &mut facade, msg).unwrap();
    assert_eq!(sig, sk.sign(&mut direct, msg, None).unwrap());
    pk.verify(msg, None, &sig).unwrap();

    let mut out = [0xffu8; SIG_LEN];
    assert_eq!(ecdsa_sign_out(&sk, &mut facade, msg, &mut out).unwrap(), SIG_LEN);
    let mut direct_out = [0u8; SIG_LEN];
    sk.sign_out(&mut direct, msg, None, &mut direct_out).unwrap();
    assert_eq!(out, direct_out);
    pk.verify(msg, None, &out).unwrap();

    let mut signer = ecdsa_create_signer(&sk, &mut facade).unwrap();
    signer.do_update(&msg[..5]);
    signer.do_update(&msg[5..]);
    let streamed = signer.do_final().unwrap();
    assert_eq!(streamed, sk.sign(&mut direct, msg, None).unwrap());
    pk.verify(msg, None, &streamed).unwrap();
    // k is drawn afresh each time, so the four signatures differ.
    assert_ne!(sig, out);
    assert_ne!(out, streamed);
}

#[test]
fn ecdsa_wrappers_match_bouncycastle_ecdsa() {
    power_on();
    same_as_direct(|d| ecdsa_p256_keygen(d), keygen::<P256, SHA256>);
    same_as_direct(|d| ecdsa_p384_keygen(d), keygen::<P384, SHA384>);
    same_as_direct(|d| ecdsa_p521_keygen(d), keygen::<P521, SHA512>);
    same_as_direct(|d| ecdsa_bp256r1_keygen(d), keygen::<Bp256r1, SHA256>);
    same_as_direct(|d| ecdsa_bp384r1_keygen(d), keygen::<Bp384r1, SHA384>);
    same_as_direct(|d| ecdsa_bp512r1_keygen(d), keygen::<Bp512r1, SHA512>);
    same_as_direct(|d| ecdsa_secp256k1_keygen(d), keygen::<Secp256K1, SHA256>);
}

fn insufficient<T>(result: Result<T, SignatureError>) -> bool {
    matches!(
        result,
        Err(SignatureError::RNGError(RNGError::SecurityStrengthInsufficientForAlgorithm))
    )
}

/// Key generation with a 128-bit Hash_DRBG: the 256-bit curves accept it, the larger ones refuse it.
#[test]
fn the_drbg_strength_check_still_applies() {
    power_on();
    let mut d = drbg_sha256(2);
    let (_, sk) = ecdsa_p256_keygen(&mut d).unwrap();
    ecdsa_sign(&sk, &mut d, b"m").unwrap();
    ecdsa_bp256r1_keygen(&mut d).unwrap();
    ecdsa_secp256k1_keygen(&mut d).unwrap();
    assert!(insufficient(ecdsa_p384_keygen(&mut d)));
    assert!(insufficient(ecdsa_p521_keygen(&mut d)));
    assert!(insufficient(ecdsa_bp384r1_keygen(&mut d)));
    assert!(insufficient(ecdsa_bp512r1_keygen(&mut d)));
}

#[test]
fn the_aliases_are_the_algorithm_crates_own() {
    use bouncycastle_sha2::{hkdf, hmac};
    assert_eq!(TypeId::of::<HKDF_SHA256>(), TypeId::of::<hkdf::HKDF_SHA256>());
    assert_eq!(TypeId::of::<HKDF_SHA384>(), TypeId::of::<hkdf::HKDF_SHA384>());
    assert_eq!(TypeId::of::<HKDF_SHA512>(), TypeId::of::<hkdf::HKDF_SHA512>());
    assert_eq!(
        TypeId::of::<HMAC_SHA224<'static, ()>>(),
        TypeId::of::<hmac::HMAC_SHA224<'static, ()>>()
    );
    assert_eq!(
        TypeId::of::<HMAC_SHA256<'static, ()>>(),
        TypeId::of::<hmac::HMAC_SHA256<'static, ()>>()
    );
    assert_eq!(
        TypeId::of::<HMAC_SHA384<'static, ()>>(),
        TypeId::of::<hmac::HMAC_SHA384<'static, ()>>()
    );
    assert_eq!(
        TypeId::of::<HMAC_SHA512<'static, ()>>(),
        TypeId::of::<hmac::HMAC_SHA512<'static, ()>>()
    );
    assert_eq!(
        TypeId::of::<HMAC_SHA512_224<'static, ()>>(),
        TypeId::of::<hmac::HMAC_SHA512_224<'static, ()>>()
    );
    assert_eq!(
        TypeId::of::<HMAC_SHA512_256<'static, ()>>(),
        TypeId::of::<hmac::HMAC_SHA512_256<'static, ()>>()
    );
    assert_ne!(TypeId::of::<HKDF_SHA256>(), TypeId::of::<HKDF_SHA512>());
}
