//! After the power-on self-tests have passed: every service works, a second power-on call is a
//! no-op, and an on-demand re-run passes and keeps the services usable.
#![cfg(all(feature = "aes", feature = "sha2"))]

mod common;

use bouncycastle_core::traits::{Hash, HashOneShot};
use bouncycastle_fips::{
    SELF_TESTED, SelfTestStatus, power_on_self_tests, run_self_tests, self_test_status,
};
use bouncycastle_sha2::SHA256;

fn all_passed() -> bool {
    SELF_TESTED.iter().all(|a| self_test_status(*a) == SelfTestStatus::Passed)
}

#[test]
fn services_work_after_power_on_and_across_re_runs() {
    assert_eq!(power_on_self_tests(), Ok(()));
    assert!(all_passed());
    assert_eq!(common::aes_keys(), Ok(()));
    assert_eq!(common::sha2_hashes(), [true; 5]);

    // A hash created before a re-run is still usable afterwards, and gives the right answer
    // (FIPS 180-4 Appendix B.1 is not one of the KATs, so this also checks a value they don't).
    let mut held = SHA256::new();
    held.do_update(b"ab");

    assert_eq!(power_on_self_tests(), Ok(()), "second call is a no-op");
    for _ in 0..3 {
        assert_eq!(run_self_tests(), Ok(()));
        assert!(all_passed());
        assert_eq!(common::aes_keys(), Ok(()));
        assert_eq!(common::sha2_hashes(), [true; 5]);
    }
    held.do_update(b"c");
    assert_eq!(held.do_final(), SHA256::hash(b"abc"));
}
