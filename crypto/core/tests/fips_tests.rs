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
fn status_cell_starts_not_run_and_passes_when_the_kat_does() {
    static CELL: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::AES);
    assert_eq!(CELL.get(), SelfTestStatus::NotRun);
    let mut seen = None;
    assert_eq!(
        CELL.run(|| {
            seen = Some(CELL.get());
            true
        }),
        Ok(())
    );
    assert_eq!(seen, Some(SelfTestStatus::Running), "Running while the KAT runs");
    assert_eq!(CELL.get(), SelfTestStatus::Passed);
    // A re-run from Passed runs the KAT again.
    let mut runs = 0;
    assert_eq!(
        CELL.run(|| {
            runs += 1;
            true
        }),
        Ok(())
    );
    assert_eq!(runs, 1);
    assert_eq!(CELL.get(), SelfTestStatus::Passed);
}

#[test]
fn status_cell_refuses_a_second_run_while_one_is_in_progress() {
    static CELL: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::SHA256);
    let inner = CELL.run(|| {
        assert_eq!(
            CELL.run(|| unreachable!("a second run must not start")),
            Err(SelfTestError::NotPassed(SelfTestedAlgorithm::SHA256, SelfTestStatus::Running))
        );
        true
    });
    assert_eq!(inner, Ok(()));
}

#[test]
fn status_cell_pass_on_one_thread_is_seen_on_another() {
    static CELL: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::SHA512);
    std::thread::spawn(|| CELL.run(|| true)).join().unwrap().unwrap();
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
