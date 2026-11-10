//! A failing known-answer test blocks service creation.
//!
//! The library has no way to make a KAT fail, and gets none for this test. Instead this binary
//! compiles the library's own self-test driver and KATs (`src/driver.rs`, `src/kats.rs`,
//! `src/vectors.rs`) a second time, as modules of the test, and runs them exactly as
//! `power_on_self_tests` does except that one byte of the AES-GCM tag is flipped and the
//! status is written through a writer of the test's own. Because that writer writes first, it
//! is the status table's writer for this process (see "Who can record a pass" in the crate
//! docs); the gates read the failure it recorded exactly as they would the library's.
#![cfg(feature = "aes")]

#[allow(dead_code)]
#[path = "../src/driver.rs"]
mod driver;
#[allow(dead_code)]
#[path = "../src/kats.rs"]
mod kats;
#[allow(dead_code)]
#[path = "../src/vectors.rs"]
mod vectors;

use bouncycastle_core::fips::SelfTestStatusWriter;
use bouncycastle_fips::{
    SELF_TESTED, SelfTestError, SelfTestStatus, SelfTestedAlgorithm, power_on_self_tests,
    run_self_tests, self_test_status,
};

static TEST_WRITER: SelfTestStatusWriter = SelfTestStatusWriter::new();

/// The library's KATs, with the AES-GCM vector's tag corrupted.
fn corrupted_kat(algorithm: SelfTestedAlgorithm) -> bool {
    match algorithm {
        #[cfg(feature = "sha2")]
        SelfTestedAlgorithm::SHA256 => kats::sha256(&vectors::SHA256_KAT),
        #[cfg(feature = "sha2")]
        SelfTestedAlgorithm::SHA512 => kats::sha512(&vectors::SHA512_KAT),
        SelfTestedAlgorithm::AES => {
            let mut gcm = vectors::AES_GCM_128_KAT;
            gcm.tag[0] ^= 0x01;
            kats::aes(&gcm, &vectors::AES_CBC_128_DECRYPT_KAT)
        }
        _ => false,
    }
}

#[test]
fn failing_aes_kat_blocks_every_service_until_restart() {
    use bouncycastle_aes::AES128Key;
    use bouncycastle_cipher::modes::GCM;
    use bouncycastle_core::errors::SymmetricCipherError;
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core::symmetric_key::FromKeyMaterial;

    assert_eq!(
        driver::run(&TEST_WRITER, SELF_TESTED, corrupted_kat, false),
        Err(SelfTestError::KnownAnswerMismatch(SelfTestedAlgorithm::AES))
    );
    assert_eq!(self_test_status(SelfTestedAlgorithm::AES), SelfTestStatus::Failed);

    // AES key creation is refused, in every mode.
    let k16 = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
    assert_eq!(
        AES128Key::<GCM>::from_key_material(&k16).err(),
        Some(SymmetricCipherError::SelfTestNotPassed(SelfTestStatus::Failed))
    );

    // The error state is module-wide: SHA-2 passed its own KATs, and is refused anyway.
    #[cfg(feature = "sha2")]
    {
        assert_eq!(self_test_status(SelfTestedAlgorithm::SHA256), SelfTestStatus::Passed);
        assert!(std::panic::catch_unwind(bouncycastle_sha2::SHA256::new).is_err());
        assert!(std::panic::catch_unwind(bouncycastle_sha2::SHA512::new).is_err());
    }

    // A re-run on the real vectors, through the same driver and writer, runs nothing and does
    // not clear the failure.
    assert_eq!(
        driver::run(&TEST_WRITER, SELF_TESTED, kats_unmodified, true),
        Err(SelfTestError::NotPassed(SelfTestedAlgorithm::AES, SelfTestStatus::Failed))
    );
    // The library's own entry points cannot write while the test's writer owns the table, and
    // say so before anything else.
    assert_eq!(power_on_self_tests(), Err(SelfTestError::StatusWriterTaken));
    assert_eq!(run_self_tests(), Err(SelfTestError::StatusWriterTaken));
    assert_eq!(self_test_status(SelfTestedAlgorithm::AES), SelfTestStatus::Failed);
}

/// The library's KATs on the real vectors.
fn kats_unmodified(algorithm: SelfTestedAlgorithm) -> bool {
    match algorithm {
        #[cfg(feature = "sha2")]
        SelfTestedAlgorithm::SHA256 => kats::sha256(&vectors::SHA256_KAT),
        #[cfg(feature = "sha2")]
        SelfTestedAlgorithm::SHA512 => kats::sha512(&vectors::SHA512_KAT),
        SelfTestedAlgorithm::AES => {
            kats::aes(&vectors::AES_GCM_128_KAT, &vectors::AES_CBC_128_DECRYPT_KAT)
        }
        _ => false,
    }
}
