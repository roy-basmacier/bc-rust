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
    // A re-run from Passed runs the KAT again, reading Passed throughout.
    let mut seen = None;
    assert_eq!(
        CELL.run(|| {
            seen = Some(CELL.get());
            true
        }),
        Ok(())
    );
    assert_eq!(seen, Some(SelfTestStatus::Passed), "a re-run keeps the algorithm available");
    assert_eq!(CELL.get(), SelfTestStatus::Passed);
}

#[test]
fn status_cell_run_overlapping_another_waits_for_it_and_reports_its_result() {
    static CELL: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::SHA256);
    let (started, wait_started) = std::sync::mpsc::channel();
    let first = std::thread::spawn(move || {
        CELL.run(|| {
            started.send(()).unwrap();
            // Long enough for the second call to arrive while this run is in progress.
            std::thread::sleep(std::time::Duration::from_millis(200));
            true
        })
    });
    wait_started.recv().unwrap();
    assert_eq!(CELL.get(), SelfTestStatus::Running);
    assert_eq!(CELL.run(|| unreachable!("the run in progress answers for this call")), Ok(()));
    assert_eq!(first.join().unwrap(), Ok(()));
    assert_eq!(CELL.get(), SelfTestStatus::Passed);

    // Likewise for a re-run, which reads Passed while it runs.
    let (started, wait_started) = std::sync::mpsc::channel();
    let rerun = std::thread::spawn(move || {
        CELL.run(|| {
            started.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(200));
            true
        })
    });
    wait_started.recv().unwrap();
    assert_eq!(CELL.get(), SelfTestStatus::Passed);
    assert_eq!(CELL.run(|| unreachable!("the re-run in progress answers for this call")), Ok(()));
    assert_eq!(rerun.join().unwrap(), Ok(()));
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
