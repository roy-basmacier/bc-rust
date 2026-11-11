//! After the power-on self-tests have passed: every service works, a second power-on call is a
//! no-op, and an on-demand re-run passes and keeps the services usable.
#![cfg(any(feature = "aes", feature = "sha2"))]

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

    // A hash created before a re-run is still usable afterwards, and gives the right answer
    // (FIPS 180-4 Appendix B.1 is not one of the KATs, so this also checks a value they don't).
    #[cfg(feature = "sha2")]
    let mut held = {
        use bouncycastle_core::traits::Hash;
        let mut held = bouncycastle_sha2::SHA256::new();
        held.do_update(b"ab");
        held
    };

    assert_eq!(power_on_self_tests(), Ok(()), "second call is a no-op");
    for _ in 0..3 {
        assert_eq!(run_self_tests(), Ok(()));
        assert!(all_passed());
        common::assert_services(None);
    }

    #[cfg(feature = "sha2")]
    {
        use bouncycastle_core::traits::{Hash, HashOneShot};
        held.do_update(b"c");
        assert_eq!(held.do_final(), bouncycastle_sha2::SHA256::hash(b"abc"));
    }
}
