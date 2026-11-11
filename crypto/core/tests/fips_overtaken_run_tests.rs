//! A self-test run during which the module enters the error state, in a file of its own because
//! that state is process-global and permanent. Run with `cargo test -p bouncycastle-core
//! --features fips`; without the feature this file is empty.
#![cfg(feature = "fips")]

use bouncycastle_core::fips::{
    SelfTestError, SelfTestStatus, SelfTestStatusCell, SelfTestedAlgorithm, enter_error_state,
};

#[test]
fn a_run_overtaken_by_the_error_state_does_not_report_a_pass() {
    // Another algorithm fails while this KAT runs: the KAT's own answer was right, but the module
    // is stopped, and the run says so.
    static SHA512: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::SHA512);
    let result = SHA512.run(|| {
        enter_error_state(SelfTestedAlgorithm::SHA256);
        true
    });
    assert_eq!(
        result,
        Err(SelfTestError::NotPassed(SelfTestedAlgorithm::SHA512, SelfTestStatus::Failed))
    );
    assert_eq!(SHA512.get(), SelfTestStatus::Failed);
}
