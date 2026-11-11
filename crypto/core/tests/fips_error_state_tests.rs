//! The module error state, in a file of its own because it is process-global and permanent. Run
//! with `cargo test -p bouncycastle-core --features fips`; without the feature this file is empty.
#![cfg(feature = "fips")]

use bouncycastle_core::fips::{SelfTestedAlgorithm, enter_error_state, error_state};

#[test]
fn error_state_is_entered_once_keeps_the_first_cause_and_is_seen_everywhere() {
    assert_eq!(error_state(), None);
    std::thread::spawn(|| enter_error_state(SelfTestedAlgorithm::SHA512)).join().unwrap();
    assert_eq!(error_state(), Some(SelfTestedAlgorithm::SHA512));
    // A later failure changes nothing: the first cause is the one reported.
    enter_error_state(SelfTestedAlgorithm::AES);
    enter_error_state(SelfTestedAlgorithm::SHA256);
    assert_eq!(error_state(), Some(SelfTestedAlgorithm::SHA512));
}
