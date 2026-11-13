//! The FIPS 140-3 self-tests, with the cli's `fips` cargo feature: the power-on run every
//! invocation makes before its subcommand, the `fips-self-test` subcommand that runs them again
//! on demand, and `fips-info`.
//!
//! The power-on run is a function of the process: each `bc-rust` invocation is a new process,
//! so each runs the self-tests once at startup, and "rebooting" the module is running the command
//! again. Its order is `bouncycastle_fips`'s: the SHA-2 self-tests (HMAC-SHA-512 cannot run
//! before SHA-512 has passed), HMAC-SHA-512, the software integrity test (the binary HMAC), the
//! module integrity check (the module HMAC; `fips-validated` only), then AES.

use bouncycastle_fips::{
    SELF_TESTED, SelfTestError, SelfTestStatus, SelfTestedAlgorithm, module_info,
    power_on_self_tests, run_self_tests, self_test_status,
};
use std::process::exit;

/// The exit status of an invocation stopped by a failed self-test.
const SELF_TEST_FAILED: i32 = 3;

/// Runs the power-on self-tests and exits with [`SELF_TEST_FAILED`], saying which algorithm
/// failed, if they do not pass; no subcommand runs after a failure.
///
/// `simulate_failure` first puts the module in the error state as a failing AES self-test
/// would, so that the failure path can be exercised end to end. It can only stop the module.
pub fn power_on(simulate_failure: bool) {
    if simulate_failure {
        bouncycastle::core::fips::enter_error_state(SelfTestedAlgorithm::AES);
    }
    if let Err(e) = power_on_self_tests() {
        eprintln!("Error: FIPS 140-3 power-on self-tests failed: {}", describe(e));
        eprintln!("No command was run; every self-tested algorithm is refused in this process.");
        exit(SELF_TEST_FAILED);
    }
}

/// `fips-self-test`: runs every self-test again and prints one `<algorithm>: <status>` line per
/// self-tested algorithm on stdout. Exits with [`SELF_TEST_FAILED`] if any fails.
pub fn fips_self_test_cmd() {
    let result = run_self_tests();
    for algorithm in SELF_TESTED {
        println!("{}: {:?}", algorithm.name(), self_test_status(*algorithm));
    }
    if let Err(e) = result {
        eprintln!("Error: FIPS 140-3 self-tests failed: {}", describe(e));
        exit(SELF_TEST_FAILED);
    }
}

/// `fips-info`: prints the module table, the module HMAC and the toolchain record on stdout, in
/// the format of `bouncycastle_fips::ModuleInfo`.
pub fn fips_info_cmd() {
    match module_info() {
        Ok(info) => print!("{info}"),
        // Power-on has passed by now, HMAC-SHA-512 with it, so this is not expected.
        Err(e) => {
            eprintln!("Error: the module HMAC could not be computed: {}", describe(e));
            exit(SELF_TEST_FAILED);
        }
    }
}

/// The error in words, naming the algorithm.
fn describe(e: SelfTestError) -> String {
    match e {
        SelfTestError::KnownAnswerMismatch(SelfTestedAlgorithm::SoftwareIntegrity) => {
            "the software integrity test failed: this program's binary HMAC does not match the \
             value bc-fips-install wrote into it, or bc-fips-install has not been run on it"
                .to_string()
        }
        SelfTestError::KnownAnswerMismatch(a) => {
            format!("the {} self-test produced a wrong answer", a.name())
        }
        SelfTestError::NotPassed(a, SelfTestStatus::Failed) => {
            format!("the module is in the error state since the {} self-test failed", a.name())
        }
        SelfTestError::NotPassed(a, status) => {
            format!("the {} self-test has not passed (status {status:?})", a.name())
        }
        other => format!("{other:?}"),
    }
}
