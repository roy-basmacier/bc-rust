//! After a self-test failure: every gated service refuses, of every algorithm, and neither
//! entry point can clear it.
//!
//! The KAT failure itself is injected in the algorithm crates' unit tests, which run their
//! private KAT over a corrupted copy of the vectors (`crypto/aes/src/self_test.rs`,
//! `crypto/sha2/src/self_test.rs`); no public item can make a KAT fail. What a mismatch then does
//! is enter the module error state, through a public function (it can only stop services), so
//! this file starts there: the error state is entered naming the first self-tested algorithm,
//! as its own failing self-test enters it.
#![cfg(all(any(feature = "aes", feature = "sha2", feature = "eccdh"), not(feature = "integrity")))]

mod common;

#[cfg(feature = "aes")]
use bouncycastle_cipher::modes::{CTR, GMAC};
use bouncycastle_core::fips::enter_error_state;
use bouncycastle_fips::{
    SELF_TESTED, SelfTestError, SelfTestStatus, power_on_self_tests, run_self_tests,
    self_test_status,
};

fn all_failed() -> bool {
    SELF_TESTED.iter().all(|a| self_test_status(*a) == SelfTestStatus::Failed)
}

#[test]
fn one_failure_stops_every_algorithm_until_restart() {
    assert_eq!(power_on_self_tests(), Ok(()));
    common::assert_services(None);
    let held = common::held();
    assert!(held.usable().iter().all(|u| *u));
    // Two AES workers whose next output needs no new block: a GMAC generator, whose tag is masked
    // with a block computed when it was made, and a CTR encryptor with 11 bytes of keystream left
    // from its first call.
    #[cfg(feature = "aes")]
    let (gmac_key, ctr_key) = held_worker_keys();
    #[cfg(feature = "aes")]
    let (mut generator, mut encryptor) = {
        use bouncycastle_core::symmetric_key::{NonceMacGenerationKey, SymmetricEncryptionKey};
        use bouncycastle_core::traits::{MACGenerator, StreamCipherEncryptor};
        let mut generator = gmac_key.create_generator_nonce(&[0; 12]);
        generator.do_update(b"ab");
        let mut encryptor = ctr_key.create_encryptor_nonce(&[0; 12]);
        assert_eq!(encryptor.do_encrypt_inplace(&mut [0; 5]), Ok(5));
        (generator, encryptor)
    };

    // One algorithm fails, outside this crate: every algorithm stops at once, before any call
    // into it.
    let failed = SELF_TESTED[0];
    enter_error_state(failed);
    assert!(all_failed());
    common::assert_services(Some(SelfTestStatus::Failed));
    // Services made before the failure stop too: keys, hashes in progress, key pairs.
    assert!(held.usable().iter().all(|u| !*u));
    // ...including the workers whose output takes no new block.
    #[cfg(feature = "aes")]
    {
        use bouncycastle_core::traits::{MACGenerator, StreamCipherEncryptor};
        use std::panic::{AssertUnwindSafe, catch_unwind};
        let more = catch_unwind(AssertUnwindSafe(|| encryptor.do_encrypt_inplace(&mut [0; 3])));
        assert!(more.is_err(), "CTR must not use buffered keystream in the error state");
        let tag = catch_unwind(AssertUnwindSafe(|| {
            generator.do_update(b"c");
            generator.do_final()
        }));
        assert!(tag.is_err(), "GMAC must not release a tag in the error state");
    }

    // Nothing runs, nothing clears it, and every call names the algorithm that failed.
    let expected = Err(SelfTestError::NotPassed(failed, SelfTestStatus::Failed));
    assert_eq!(run_self_tests(), expected);
    assert_eq!(power_on_self_tests(), expected);
    assert_eq!(run_self_tests(), expected);
    #[cfg(feature = "sha2")]
    assert_eq!(
        bouncycastle_sha2::self_test(),
        Err(SelfTestError::NotPassed(
            bouncycastle_fips::SelfTestedAlgorithm::SHA256,
            SelfTestStatus::Failed
        ))
    );
    #[cfg(feature = "aes")]
    assert_eq!(
        bouncycastle_aes::self_test(),
        Err(SelfTestError::NotPassed(
            bouncycastle_fips::SelfTestedAlgorithm::AES,
            SelfTestStatus::Failed
        ))
    );
    #[cfg(feature = "ecdsa")]
    assert_eq!(
        bouncycastle_ecdsa::self_test(),
        Err(SelfTestError::NotPassed(
            bouncycastle_fips::SelfTestedAlgorithm::ECDSA,
            SelfTestStatus::Failed
        ))
    );
    #[cfg(feature = "eccdh")]
    assert_eq!(
        bouncycastle_eccdh::self_test(),
        Err(SelfTestError::NotPassed(
            bouncycastle_fips::SelfTestedAlgorithm::ECC_CDH,
            SelfTestStatus::Failed
        ))
    );
    assert!(all_failed());
    common::assert_services(Some(SelfTestStatus::Failed));
}

/// An AES-GMAC key and an AES-CTR key, made while AES is available.
#[cfg(feature = "aes")]
fn held_worker_keys() -> (bouncycastle_aes::AES128Key<GMAC>, bouncycastle_aes::AES128Key<CTR>) {
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core::symmetric_key::FromKeyMaterial;
    let key = |key_type| KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], key_type).unwrap();
    (
        bouncycastle_aes::AES128Key::<GMAC>::from_key_material(&key(KeyType::MACKey)).unwrap(),
        bouncycastle_aes::AES128Key::<CTR>::from_key_material(&key(KeyType::SymmetricCipherKey))
            .unwrap(),
    )
}
