//! After a self-test failure: every gated service refuses, of every algorithm, and neither
//! entry point can clear it.
//!
//! The KAT failure itself is injected in the algorithm crates' unit tests, which run their
//! private KAT over a corrupted copy of the vectors (`crypto/aes/src/self_test.rs`,
//! `crypto/sha2/src/self_test.rs`); no public item can make a KAT fail. What a mismatch then does
//! to the crate is call its error-state hook, which is public (it can only stop services), so this
//! file starts there: AES is put in the error state the way its own failing self-test puts it.
#![cfg(all(feature = "aes", feature = "sha2"))]

mod common;

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_fips::{
    SELF_TESTED, SelfTestError, SelfTestStatus, SelfTestedAlgorithm, power_on_self_tests,
    run_self_tests, self_test_status,
};

fn all_failed() -> bool {
    SELF_TESTED.iter().all(|a| self_test_status(*a) == SelfTestStatus::Failed)
}

#[test]
fn one_failure_stops_every_algorithm_until_restart() {
    assert_eq!(power_on_self_tests(), Ok(()));
    assert_eq!(common::aes_keys(), Ok(()));
    assert_eq!(common::sha2_hashes(), [true; 5]);

    // AES fails on its own, outside this crate.
    bouncycastle_aes::self_test_enter_error_state();
    assert_eq!(self_test_status(SelfTestedAlgorithm::AES), SelfTestStatus::Failed);
    assert_eq!(
        common::aes_keys(),
        Err(SymmetricCipherError::SelfTestNotPassed(SelfTestStatus::Failed))
    );

    // The next call runs nothing, reports AES, and stops SHA-2 as well.
    let expected = Err(SelfTestError::NotPassed(SelfTestedAlgorithm::AES, SelfTestStatus::Failed));
    assert_eq!(run_self_tests(), expected);
    assert!(all_failed());
    assert_eq!(common::sha2_hashes(), [false; 5]);

    // Nothing clears it, and it keeps naming the algorithm that failed first.
    assert_eq!(power_on_self_tests(), expected);
    assert_eq!(run_self_tests(), expected);
    assert_eq!(
        bouncycastle_sha2::self_test(),
        Err(SelfTestError::NotPassed(SelfTestedAlgorithm::SHA256, SelfTestStatus::Failed))
    );
    assert_eq!(
        bouncycastle_aes::self_test(),
        Err(SelfTestError::NotPassed(SelfTestedAlgorithm::AES, SelfTestStatus::Failed))
    );
    assert!(all_failed());
    assert_eq!(
        common::aes_keys(),
        Err(SymmetricCipherError::SelfTestNotPassed(SelfTestStatus::Failed))
    );
    assert_eq!(common::sha2_hashes(), [false; 5]);
}
