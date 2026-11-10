//! Runs the self-tests and records their results in `bouncycastle-core`'s status table.
//!
//! Separate from `lib.rs`, and given the writer and the KATs as parameters, so that this crate's
//! failure-path test can run this same code with a corrupted vector and a writer of its own,
//! without the library carrying any hook for it.

use bouncycastle_core::fips::{
    SelfTestError, SelfTestStatus, SelfTestStatusWriter, SelfTestedAlgorithm,
    claim_self_test_status_writer, self_test_status, set_self_test_status,
};

/// Runs the self-test `kat` of each of `algorithms`, in order, recording each result as `writer`.
///
/// With `rerun_passed` false an algorithm that has already passed is skipped (the power-on
/// self-test, done once); with it true every one runs again (the on-demand self-test).
///
/// An algorithm's status is `Running` while its self-test runs, which lets the self-test, and
/// every other thread, create services of it (see "Self-test in progress" in the crate docs).
/// It stops at the first failure: the module is then in the error state, and the algorithms not
/// yet run are refused anyway.
pub(crate) fn run(
    writer: &'static SelfTestStatusWriter,
    algorithms: &[SelfTestedAlgorithm],
    kat: fn(SelfTestedAlgorithm) -> bool,
    rerun_passed: bool,
) -> Result<(), SelfTestError> {
    // First, so that a table some other writer owns is reported even when every algorithm reads
    // `Passed` and nothing would be written: that writer may have recorded those passes.
    claim_self_test_status_writer(writer)?;

    // The error state is module-wide and only a restart leaves it, so after any failure nothing
    // is run (crate docs, "Requirements", on failure).
    for algorithm in SelfTestedAlgorithm::ALL {
        if self_test_status(algorithm) == SelfTestStatus::Failed {
            return Err(SelfTestError::NotPassed(algorithm, SelfTestStatus::Failed));
        }
    }

    for &algorithm in algorithms {
        if !rerun_passed && self_test_status(algorithm) == SelfTestStatus::Passed {
            continue;
        }
        set_self_test_status(writer, algorithm, SelfTestStatus::Running)?;
        // `Running` admits services, so it must not outlive the KAT: if the KAT panics and the
        // panic is caught further up, the guard records a failure on the way out.
        let guard = FailOnUnwind { writer, algorithm };
        let passed = kat(algorithm);
        core::mem::forget(guard);
        if passed {
            // Refused if another thread's run recorded a failure meanwhile, which then stands.
            set_self_test_status(writer, algorithm, SelfTestStatus::Passed)?;
        } else {
            set_self_test_status(writer, algorithm, SelfTestStatus::Failed)?;
            return Err(SelfTestError::KnownAnswerMismatch(algorithm));
        }
    }
    Ok(())
}

/// Records `algorithm` as failed when dropped; forgotten once its KAT has returned.
struct FailOnUnwind {
    writer: &'static SelfTestStatusWriter,
    algorithm: SelfTestedAlgorithm,
}

impl Drop for FailOnUnwind {
    fn drop(&mut self) {
        // Writing `Failed` can only be refused if `writer` is not the table's writer, and it
        // just wrote `Running`; there is nothing else to do with an error while unwinding.
        let _ = set_self_test_status(self.writer, self.algorithm, SelfTestStatus::Failed);
    }
}
