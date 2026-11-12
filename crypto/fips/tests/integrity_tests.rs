//! Power-on with the software integrity test, in a test binary: its slot is empty, since the
//! post-link tool never ran on it, so the test fails closed after the SHA-2 and HMAC-SHA-512
//! self-tests and before the remaining ones, and the module is in the error state.
#![cfg(feature = "integrity")]

mod common;

use bouncycastle_fips::{
    SELF_TESTED, SelfTestError, SelfTestStatus, SelfTestedAlgorithm, power_on_self_tests,
    run_self_tests, self_test_status,
};

#[test]
fn an_empty_slot_fails_power_on_for_good() {
    assert_eq!(self_test_status(SelfTestedAlgorithm::SoftwareIntegrity), SelfTestStatus::NotRun);
    assert_eq!(
        power_on_self_tests(),
        Err(SelfTestError::KnownAnswerMismatch(SelfTestedAlgorithm::SoftwareIntegrity))
    );
    for algorithm in SELF_TESTED {
        assert_eq!(self_test_status(*algorithm), SelfTestStatus::Failed, "{algorithm:?}");
    }
    common::assert_services(Some(SelfTestStatus::Failed));
    let expected = Err(SelfTestError::NotPassed(
        SelfTestedAlgorithm::SoftwareIntegrity,
        SelfTestStatus::Failed,
    ));
    assert_eq!(power_on_self_tests(), expected);
    assert_eq!(run_self_tests(), expected);
}
