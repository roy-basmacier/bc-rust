//! Concurrent runs: several threads power on and re-run the self-tests while creating services;
//! the services stay usable throughout, and a run that overlaps another reports `Running` rather
//! than failing.
#![cfg(all(feature = "aes", feature = "sha2"))]

mod common;

use bouncycastle_fips::{
    SELF_TESTED, SelfTestError, SelfTestStatus, power_on_self_tests, run_self_tests,
    self_test_status,
};

#[test]
fn re_runs_from_several_threads_keep_services_usable() {
    // Whichever thread gets here first does the power-on run; the others may see it Running.
    let threads: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                while power_on_self_tests().is_err() {}
                for _ in 0..20 {
                    // A concurrent run makes this report Running; it never fails.
                    if let Err(e) = run_self_tests() {
                        assert!(
                            matches!(e, SelfTestError::NotPassed(_, SelfTestStatus::Running)),
                            "{e:?}"
                        );
                    }
                    assert_eq!(common::aes_keys(), Ok(()));
                    assert_eq!(common::sha2_hashes(), [true; 5]);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert!(SELF_TESTED.iter().all(|a| self_test_status(*a) == SelfTestStatus::Passed));
}
