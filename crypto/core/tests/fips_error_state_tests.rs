//! The module error state and the failure paths of `SelfTestStatusCell::run`, in a file of their
//! own and in one test, because the error state is process-global and permanent. Run with
//! `cargo test -p bouncycastle-core --features fips`; without the feature this file is empty.
#![cfg(feature = "fips")]

use bouncycastle_core::fips::{
    SelfTestError, SelfTestStatus, SelfTestStatusCell, SelfTestedAlgorithm, enter_error_state,
    error_state,
};
use std::panic::{AssertUnwindSafe, catch_unwind};

static AES: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::AES);
static SHA256: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::SHA256);
static SHA512: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::SHA512);

#[test]
fn a_failure_enters_the_error_state_for_every_cell_for_good() {
    assert_eq!(error_state(), None);
    assert_eq!(SHA256.run(|| true), Ok(()));

    // A KAT that panics is recorded as a failure of its algorithm, not left Running.
    let panicked = catch_unwind(AssertUnwindSafe(|| SHA512.run(|| panic!("faulty KAT"))));
    assert!(panicked.is_err());
    assert_eq!(error_state(), Some(SelfTestedAlgorithm::SHA512));
    // Every cell reads Failed, including one that passed and one never run.
    for cell in [&AES, &SHA256, &SHA512] {
        assert_eq!(cell.get(), SelfTestStatus::Failed);
    }

    // No cell runs its KAT again.
    for (cell, algorithm) in [
        (&AES, SelfTestedAlgorithm::AES),
        (&SHA256, SelfTestedAlgorithm::SHA256),
        (&SHA512, SelfTestedAlgorithm::SHA512),
    ] {
        assert_eq!(
            cell.run(|| unreachable!("no KAT runs in the error state")),
            Err(SelfTestError::NotPassed(algorithm, SelfTestStatus::Failed))
        );
    }

    // A later failure changes nothing: the first cause is the one reported, on any thread.
    enter_error_state(SelfTestedAlgorithm::AES);
    std::thread::spawn(|| enter_error_state(SelfTestedAlgorithm::SHA256)).join().unwrap();
    assert_eq!(std::thread::spawn(error_state).join().unwrap(), Some(SelfTestedAlgorithm::SHA512));
}
