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

    // One algorithm fails, outside this crate: every algorithm stops at once, before any call
    // into it.
    let failed = SELF_TESTED[0];
    enter_error_state(failed);
    assert!(all_failed());
    common::assert_services(Some(SelfTestStatus::Failed));
    // Services made before the failure stop too: keys, hashes in progress, key pairs.
    assert!(held.usable().iter().all(|u| !*u));

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
