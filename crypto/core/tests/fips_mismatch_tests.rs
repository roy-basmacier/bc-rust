//! A known-answer test that returns `false`, in a file of its own because the error state it
//! enters is process-global and permanent. Run with `cargo test -p bouncycastle-core --features
//! fips`; without the feature this file is empty.
#![cfg(feature = "fips")]

use bouncycastle_core::fips::{
    SelfTestError, SelfTestStatus, SelfTestStatusCell, SelfTestedAlgorithm, error_state,
};

static AES: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::AES);
static SHA256: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::SHA256);

#[test]
fn a_wrong_answer_fails_its_algorithm_and_stops_the_module() {
    assert_eq!(SHA256.run(|| true), Ok(()));
    assert_eq!(
        AES.run(|| false),
        Err(SelfTestError::KnownAnswerMismatch(SelfTestedAlgorithm::AES))
    );
    assert_eq!(error_state(), Some(SelfTestedAlgorithm::AES));
    assert_eq!(AES.get(), SelfTestStatus::Failed);
    assert_eq!(SHA256.get(), SelfTestStatus::Failed);
}
