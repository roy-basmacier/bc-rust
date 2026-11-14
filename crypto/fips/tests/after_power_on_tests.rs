//! After the power-on self-tests have passed: every service works, a second power-on call is a
//! no-op, and an on-demand re-run passes and keeps the services usable.
#![cfg(all(any(feature = "aes", feature = "sha2", feature = "eccdh"), not(feature = "integrity")))]

mod common;

use bouncycastle_fips::{
    SELF_TESTED, SelfTestStatus, power_on_self_tests, run_self_tests, self_test_status,
};

fn all_passed() -> bool {
    SELF_TESTED.iter().all(|a| self_test_status(*a) == SelfTestStatus::Passed)
}

#[test]
fn services_work_after_power_on_and_across_re_runs() {
    assert_eq!(power_on_self_tests(), Ok(()));
    assert!(all_passed());
    common::assert_services(None);

    // A key and a hash created before a re-run are still usable afterwards, and give the right
    // answer (SHA-256("abc"), from the NIST SHA examples FIPS 180-4 A.2 points to, is not one of
    // the KATs, so this also checks a value they don't).
    let held = common::held();

    assert_eq!(power_on_self_tests(), Ok(()), "second call is a no-op");
    for _ in 0..3 {
        assert_eq!(run_self_tests(), Ok(()));
        assert!(all_passed());
        common::assert_services(None);
    }
    assert!(held.usable().iter().all(|u| *u));
}
