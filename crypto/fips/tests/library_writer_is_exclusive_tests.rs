//! Once `bouncycastle-fips` has written a status, no other writer can, so a pass cannot be
//! forged after the power-on self-tests and a failure cannot be cleared. A binary of its own,
//! because the status table is process-wide.

use bouncycastle_core::fips::{SelfTestStatusWriter, set_self_test_status};
use bouncycastle_fips::{
    SELF_TESTED, SelfTestError, SelfTestStatus, power_on_self_tests, self_test_status,
};

static LATE: SelfTestStatusWriter = SelfTestStatusWriter::new();

#[test]
fn a_writer_after_power_on_is_refused() {
    assert_eq!(power_on_self_tests(), Ok(()));
    for &algorithm in SELF_TESTED {
        for status in [SelfTestStatus::NotRun, SelfTestStatus::Failed, SelfTestStatus::Passed] {
            assert_eq!(
                set_self_test_status(&LATE, algorithm, status),
                Err(SelfTestError::StatusWriterTaken)
            );
        }
        assert_eq!(self_test_status(algorithm), SelfTestStatus::Passed);
    }
}
