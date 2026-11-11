//! Concurrent runs: several threads power on and re-run the self-tests while creating services.
//! Every call succeeds -- one that overlaps another thread's run waits for it and reports its
//! result -- and the services stay usable throughout.
#![cfg(any(feature = "aes", feature = "sha2"))]

mod common;

use bouncycastle_fips::{
    SELF_TESTED, SelfTestStatus, power_on_self_tests, run_self_tests, self_test_status,
};

#[test]
fn power_on_and_re_runs_from_several_threads_all_succeed() {
    let threads: Vec<_> = (0..4)
        .map(|_| {
            std::thread::spawn(|| {
                assert_eq!(power_on_self_tests(), Ok(()));
                for _ in 0..20 {
                    assert_eq!(run_self_tests(), Ok(()));
                    common::assert_services(None);
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert!(SELF_TESTED.iter().all(|a| self_test_status(*a) == SelfTestStatus::Passed));
}
