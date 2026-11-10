//! Before [`power_on_self_tests`] has been called, no gated service can be created. Nothing in
//! this test binary runs the self-tests (the status table is process-wide, so the scenario has a
//! binary of its own).
//!
//! [`power_on_self_tests`]: bouncycastle_fips::power_on_self_tests

use bouncycastle_fips::{SELF_TESTED, SelfTestStatus, self_test_status};

#[test]
fn nothing_has_run() {
    for &algorithm in SELF_TESTED {
        assert_eq!(self_test_status(algorithm), SelfTestStatus::NotRun, "{algorithm:?}");
    }
}

#[cfg(feature = "aes")]
#[test]
fn aes_keys_of_every_mode_and_size_are_refused() {
    use bouncycastle_aes::hazmat::AES128Internal;
    use bouncycastle_aes::{AES128Key, AES192Key, AES256Key};
    use bouncycastle_cipher::modes::{Blocks, CBC, CTR, GCM};
    use bouncycastle_core::errors::SymmetricCipherError;
    use bouncycastle_core::hazmat::KeyExpansion;
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core::symmetric_key::FromKeyMaterial;

    const REFUSED: SymmetricCipherError =
        SymmetricCipherError::SelfTestNotPassed(SelfTestStatus::NotRun);
    let k16 =
        KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
    let k24 =
        KeyMaterial::<24>::from_bytes_as_type(&[0x42; 24], KeyType::SymmetricCipherKey).unwrap();
    let k32 =
        KeyMaterial::<32>::from_bytes_as_type(&[0x42; 32], KeyType::SymmetricCipherKey).unwrap();

    assert_eq!(AES128Key::<GCM>::from_key_material(&k16).err(), Some(REFUSED));
    assert_eq!(AES192Key::<CTR>::from_key_material(&k24).err(), Some(REFUSED));
    assert_eq!(AES256Key::<CBC<Blocks>>::from_key_material(&k32).err(), Some(REFUSED));
    // The raw permutation is gated too: it is where every key above is expanded.
    assert_eq!(<AES128Internal as KeyExpansion<16>>::new(&k16).err(), Some(REFUSED));
}

#[cfg(feature = "aes")]
#[test]
fn mode_layer_key_type_check_comes_before_the_gate() {
    use bouncycastle_aes::AES128Key;
    use bouncycastle_cipher::modes::GCM;
    use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core::symmetric_key::FromKeyMaterial;

    // The gate is in AES's key expansion, which `bouncycastle-cipher`'s shared key constructor
    // calls only after its own key-type check; a key of the wrong type is refused for that
    // first, without a self-test error.
    let wrong = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::MACKey).unwrap();
    assert!(matches!(
        AES128Key::<GCM>::from_key_material(&wrong).err(),
        Some(SymmetricCipherError::KeyMaterialError(KeyMaterialError::InvalidKeyType(_)))
    ));
}

#[cfg(feature = "sha2")]
#[test]
fn every_sha2_constructor_panics() {
    use bouncycastle_core::traits::{HashOneShot, Suspendable};
    use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256};
    use std::panic::catch_unwind;

    assert!(catch_unwind(SHA256::new).is_err(), "SHA256::new");
    assert!(catch_unwind(SHA224::new).is_err(), "SHA224::new");
    assert!(catch_unwind(SHA512::new).is_err(), "SHA512::new");
    assert!(catch_unwind(SHA384::new).is_err(), "SHA384::new");
    assert!(catch_unwind(SHA512_224::new).is_err(), "SHA512_224::new");
    assert!(catch_unwind(SHA512_256::new).is_err(), "SHA512_256::new");
    assert!(catch_unwind(SHA256::default).is_err(), "SHA256::default");
    assert!(catch_unwind(|| SHA256::hash_out(b"abc", &mut [0u8; 32])).is_err(), "one-shot");
    assert!(catch_unwind(|| SHA512::hash_out(b"abc", &mut [0u8; 64])).is_err(), "one-shot");
    // A resumed state is gated too, whatever the bytes (the gate runs before they are parsed).
    assert!(catch_unwind(|| SHA256::from_suspended([0u8; 108])).is_err(), "SHA256 resume");
    assert!(catch_unwind(|| SHA512::from_suspended([0u8; 204])).is_err(), "SHA512 resume");
}

#[cfg(feature = "sha2")]
#[test]
fn hmac_over_sha2_panics() {
    use bouncycastle_core::key_material::{KeyMaterial256, KeyType};
    use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
    use bouncycastle_hmac::HmacKey;
    use bouncycastle_sha2::SHA256;

    let material = KeyMaterial256::from_bytes_as_type(&[0x42; 32], KeyType::MACKey).unwrap();
    let mac = std::panic::catch_unwind(|| {
        let key = HmacKey::<SHA256>::from_key_material(&material).unwrap();
        key.mac(b"data")
    });
    assert!(mac.is_err());
}
