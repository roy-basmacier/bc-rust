//! What stops other code from marking an algorithm as passed: nothing, if it writes before
//! `bouncycastle-fips` first does; but `bouncycastle-fips` then reports it. See "Who can record a
//! pass" in the crate docs. A binary of its own, because the status table is process-wide.
#![cfg(feature = "aes")]

use bouncycastle_core::fips::{SelfTestStatusWriter, set_self_test_status};
use bouncycastle_fips::{
    SelfTestError, SelfTestStatus, SelfTestedAlgorithm, power_on_self_tests, run_self_tests,
    self_test_status,
};

static ROGUE: SelfTestStatusWriter = SelfTestStatusWriter::new();

#[test]
fn a_writer_that_writes_first_can_mark_passed_and_the_self_tests_then_refuse() {
    use bouncycastle_aes::AES128Key;
    use bouncycastle_cipher::modes::GCM;
    use bouncycastle_core::key_material::{KeyMaterial, KeyType};
    use bouncycastle_core::symmetric_key::FromKeyMaterial;

    let k16 = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
    assert!(AES128Key::<GCM>::from_key_material(&k16).is_err());

    // Any crate can do this before the self-tests first run, and AES is then usable untested.
    set_self_test_status(&ROGUE, SelfTestedAlgorithm::AES, SelfTestStatus::Passed).unwrap();
    assert_eq!(self_test_status(SelfTestedAlgorithm::AES), SelfTestStatus::Passed);
    assert!(AES128Key::<GCM>::from_key_material(&k16).is_ok());

    // The self-tests cannot record anything now, and say so.
    assert_eq!(power_on_self_tests(), Err(SelfTestError::StatusWriterTaken));
    assert_eq!(run_self_tests(), Err(SelfTestError::StatusWriterTaken));
}
