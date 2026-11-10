//! Before the power-on self-tests: nothing has run and every gated service refuses.
#![cfg(all(feature = "aes", feature = "sha2"))]

mod common;

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_fips::{SELF_TESTED, SelfTestStatus, self_test_status};
use bouncycastle_sha2::SHA256;

#[test]
fn services_refuse_before_power_on() {
    for algorithm in SELF_TESTED {
        assert_eq!(self_test_status(*algorithm), SelfTestStatus::NotRun, "{algorithm:?}");
    }
    assert_eq!(
        common::aes_keys(),
        Err(SymmetricCipherError::SelfTestNotPassed(SelfTestStatus::NotRun))
    );
    assert_eq!(common::sha2_hashes(), [false; 5]);
    // Refusing changes nothing.
    for algorithm in SELF_TESTED {
        assert_eq!(self_test_status(*algorithm), SelfTestStatus::NotRun, "{algorithm:?}");
    }
}

#[test]
#[should_panic(expected = "SHA-256 cannot be used: its FIPS 140-3 self-test is NotRun")]
fn sha256_new_panics_before_power_on() {
    let _ = SHA256::new();
}
