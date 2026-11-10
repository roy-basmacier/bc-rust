//! Tests for the `fips` feature's self-test types. Run with
//! `cargo test -p bouncycastle-core --features fips`; without the feature this file is empty.
#![cfg(feature = "fips")]

use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::fips::{
    SelfTestError, SelfTestStatus, SelfTestStatusCell, SelfTestedAlgorithm,
};

const STATUSES: [SelfTestStatus; 4] = [
    SelfTestStatus::NotRun,
    SelfTestStatus::Running,
    SelfTestStatus::Passed,
    SelfTestStatus::Failed,
];

#[test]
fn status_u8_encoding_round_trips_and_rejects_other_values() {
    for (i, status) in STATUSES.iter().enumerate() {
        assert_eq!(status.as_u8(), i as u8);
        assert_eq!(SelfTestStatus::from_u8(i as u8), Some(*status));
    }
    for value in 4..=u8::MAX {
        assert_eq!(SelfTestStatus::from_u8(value), None);
    }
}

#[test]
fn status_cell_starts_not_run_and_holds_what_was_set() {
    static CELL: SelfTestStatusCell = SelfTestStatusCell::new();
    assert_eq!(CELL.get(), SelfTestStatus::NotRun);
    assert_eq!(SelfTestStatusCell::default().get(), SelfTestStatus::NotRun);
    for status in STATUSES {
        CELL.set(status);
        assert_eq!(CELL.get(), status);
    }
}

#[test]
fn status_cell_set_on_one_thread_is_seen_on_another() {
    static CELL: SelfTestStatusCell = SelfTestStatusCell::new();
    std::thread::spawn(|| CELL.set(SelfTestStatus::Passed)).join().unwrap();
    assert_eq!(CELL.get(), SelfTestStatus::Passed);
}

#[test]
fn algorithms_run_hashes_first_and_have_their_ig_names() {
    assert_eq!(
        SelfTestedAlgorithm::ALL,
        [SelfTestedAlgorithm::SHA256, SelfTestedAlgorithm::SHA512, SelfTestedAlgorithm::AES]
    );
    assert_eq!(SelfTestedAlgorithm::AES.name(), "AES");
    assert_eq!(SelfTestedAlgorithm::SHA256.name(), "SHA-256");
    assert_eq!(SelfTestedAlgorithm::SHA512.name(), "SHA-512");
}

#[test]
fn errors_carry_algorithm_and_status() {
    let e = SelfTestError::NotPassed(SelfTestedAlgorithm::AES, SelfTestStatus::Failed);
    assert_ne!(e, SelfTestError::NotPassed(SelfTestedAlgorithm::AES, SelfTestStatus::NotRun));
    assert_ne!(e, SelfTestError::KnownAnswerMismatch(SelfTestedAlgorithm::AES));
    assert_eq!(
        SymmetricCipherError::SelfTestNotPassed(SelfTestStatus::NotRun),
        SymmetricCipherError::SelfTestNotPassed(SelfTestStatus::NotRun)
    );
}
