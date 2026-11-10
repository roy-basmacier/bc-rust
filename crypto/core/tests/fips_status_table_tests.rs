//! The `fips` feature's status table, gates and writer. Run with
//! `cargo test -p bouncycastle-core --features fips`; without the feature this file is empty.
//!
//! The table is process-global and a failure in it is final, so the whole lifecycle is one test
//! in its own test binary: nothing else in this process reads or writes the table.
#![cfg(feature = "fips")]

use bouncycastle_core::fips::{
    SelfTestError, SelfTestStatus, SelfTestStatusWriter, SelfTestedAlgorithm, assert_self_test,
    check_self_test, claim_self_test_status_writer, self_test_status, set_self_test_status,
};

static WRITER: SelfTestStatusWriter = SelfTestStatusWriter::new();
static OTHER_WRITER: SelfTestStatusWriter = SelfTestStatusWriter::new();

use SelfTestStatus::{Failed, NotRun, Passed, Running};
use SelfTestedAlgorithm::{AES, SHA256, SHA512};

fn panics(algorithm: SelfTestedAlgorithm) -> bool {
    std::panic::catch_unwind(|| assert_self_test(algorithm)).is_err()
}

#[test]
fn status_table_lifecycle() {
    // Nothing run: every gate refuses with `NotRun`.
    for alg in SelfTestedAlgorithm::ALL {
        assert_eq!(self_test_status(alg), NotRun);
        assert_eq!(check_self_test(alg), Err(NotRun));
        assert!(panics(alg));
    }

    // The first write claims the table for `WRITER`; `Running` admits services of that
    // algorithm only.
    set_self_test_status(&WRITER, SHA256, Running).unwrap();
    assert_eq!(self_test_status(SHA256), Running);
    assert_eq!(check_self_test(SHA256), Ok(()));
    assert!(!panics(SHA256));
    assert_eq!(check_self_test(SHA512), Err(NotRun));

    // Any other writer is refused, and records nothing; claiming again is a no-op for the owner.
    assert_eq!(claim_self_test_status_writer(&WRITER), Ok(()));
    assert_eq!(claim_self_test_status_writer(&OTHER_WRITER), Err(SelfTestError::StatusWriterTaken));
    assert_eq!(
        set_self_test_status(&OTHER_WRITER, AES, Passed),
        Err(SelfTestError::StatusWriterTaken)
    );
    assert_eq!(self_test_status(AES), NotRun);

    set_self_test_status(&WRITER, SHA256, Passed).unwrap();
    set_self_test_status(&WRITER, AES, Passed).unwrap();
    assert_eq!(check_self_test(SHA256), Ok(()));
    assert_eq!(check_self_test(AES), Ok(()));
    assert_eq!(check_self_test(SHA512), Err(NotRun));

    // A re-run can go back through `Running` without refusing anything.
    set_self_test_status(&WRITER, AES, Running).unwrap();
    assert_eq!(check_self_test(AES), Ok(()));
    set_self_test_status(&WRITER, AES, Passed).unwrap();

    // One failure puts every algorithm in the error state, passed or not.
    set_self_test_status(&WRITER, SHA512, Failed).unwrap();
    for alg in SelfTestedAlgorithm::ALL {
        assert_eq!(check_self_test(alg), Err(Failed), "{alg:?}");
        assert!(panics(alg), "{alg:?}");
    }
    assert_eq!(self_test_status(AES), Passed, "the others keep their own status");

    // `Failed` is final: nothing but `Failed` again may be written over it.
    for status in [NotRun, Running, Passed] {
        assert_eq!(
            set_self_test_status(&WRITER, SHA512, status),
            Err(SelfTestError::NotPassed(SHA512, Failed))
        );
        assert_eq!(self_test_status(SHA512), Failed);
    }
    assert_eq!(set_self_test_status(&WRITER, SHA512, Failed), Ok(()));
    assert_eq!(self_test_status(SHA512), Failed);
}

#[test]
fn writer_default_is_new() {
    // No state: a writer is only an address. This only checks `Default` exists for a `static`.
    let _ = SelfTestStatusWriter::default();
}
