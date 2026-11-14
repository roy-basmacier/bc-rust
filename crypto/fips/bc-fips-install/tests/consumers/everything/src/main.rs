//! One of the two programs of `two_consumers_tests.rs`: powers on bouncycastle-fips, with the
//! software integrity test, prints the module info, and uses every crate of the module -- AES,
//! Ascon, SHA-2, SHA-3, HMAC, HKDF, the Hash_DRBG and ECDSA over the EC crate. Exits 0 only if all
//! of that succeeds.

use std::process::ExitCode;

use bouncycastle_aes::AES256Key;
use bouncycastle_ascon::{AsconAEAD128Key, AsconHash256};
use bouncycastle_cipher::modes::GCM;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterial256, KeyType};
use bouncycastle_core::signature_key::{DeterministicSigningKey, VerifyingKey};
use bouncycastle_core::symmetric_key::{
    AeadDecryptionKey, AeadEncryptionKey, FromAnyKeyMaterial, FromKeyMaterial, MacGenerationKey,
    MacVerificationKey,
};
use bouncycastle_core::traits::{HashOneShot, KDF, MACGenerator};
use bouncycastle_ec::P256;
use bouncycastle_ecdsa::keys::keygen;
use bouncycastle_fips::{module_info, power_on_self_tests};
use bouncycastle_hkdf::HKDF;
use bouncycastle_hmac::HmacKey;
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha2::{SHA256, SHA512};
use bouncycastle_sha3::SHA3_256;

/// Printed after power-on passes. The test flips one of its bytes in the file: it is data the
/// program reads only after the integrity test has run.
const PASSED: &str = "everything consumer: power-on passed";

fn main() -> ExitCode {
    if let Err(e) = power_on_self_tests() {
        eprintln!("everything consumer: power-on failed: {e:?}");
        return ExitCode::FAILURE;
    }
    println!("{PASSED}");
    print!("{}", module_info().expect("HMAC-SHA-512 passed at power-on"));

    // Fixed keys and nonces: a test program, never a pattern to copy.
    let mut rng = HashDRBG_SHA512::new_from_os();

    let material = KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey)
        .expect("32 bytes fit");
    let aes = AES256Key::<GCM>::from_key_material(&material).expect("AES has passed");
    let mut sealed = [0u8; 5 + 16];
    aes.encrypt_with_aad_nonce_out(&[7; 12], b"aad", b"hello", &mut sealed).expect("encrypt");
    let mut opened = [0u8; 5];
    aes.decrypt_with_aad_out(&[7; 12], b"aad", &sealed, &mut opened).expect("decrypt");
    assert_eq!(&opened, b"hello");

    let material = KeyMaterial::<16>::from_bytes_as_type(&[0x24; 16], KeyType::SymmetricCipherKey)
        .expect("16 bytes fit");
    let ascon = AsconAEAD128Key::from_key_material(&material).expect("a 16-byte key");
    ascon.encrypt_with_aad_nonce_out(&[1; 16], b"aad", b"hello", &mut sealed).expect("encrypt");
    ascon.decrypt_with_aad_out(&[1; 16], b"aad", &sealed, &mut opened).expect("decrypt");
    assert_eq!(&opened, b"hello");

    assert_eq!(SHA256::hash(b"abc").len(), 32);
    assert_eq!(SHA512::hash(b"abc").len(), 64);
    assert_eq!(SHA3_256::hash(b"abc").len(), 32);
    assert_eq!(AsconHash256::hash(b"abc").len(), 32);

    let mac = HmacKey::<SHA256>::generate(&mut rng).expect("a MAC key from the DRBG");
    let mut generator = mac.create_generator();
    generator.do_update(b"message");
    let tag: [u8; 32] = generator.do_final();
    assert!(mac.verify(b"message", &tag).is_ok());

    let ikm = KeyMaterial256::from_bytes_as_type(&[0x0b; 22], KeyType::Seed).expect("22 bytes fit");
    let okm = HKDF::<SHA256>::new().derive_key(&ikm, b"info", 32).expect("HKDF derives");
    assert_eq!(okm.key_len(), 32);

    let (pk, sk) = keygen::<P256, SHA256>(&mut rng).expect("a P-256 key pair");
    let signature = sk.sign_deterministic(b"message", None).expect("ECDSA signs");
    assert!(pk.verify(b"message", None, &signature).is_ok());
    assert!(pk.verify(b"another message", None, &signature).is_err());

    println!("every module crate used ok");
    ExitCode::SUCCESS
}
