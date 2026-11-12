//! The test program for `bc-fips-install`: powers on bouncycastle-fips, with the software
//! integrity test, and uses SHA-256 if that passes. Exits 0 and prints [`PASSED`] only then.

use std::process::ExitCode;

use bouncycastle_core::traits::HashOneShot;
use bouncycastle_fips::power_on_self_tests;
use bouncycastle_sha2::SHA256;

/// Printed after power-on passes. The tests find it in the file, in a read-only segment, and flip
/// one of its bytes: it is data the program reads only after the integrity test has run.
const PASSED: &str = "bc-fips-install consumer: power-on passed";

fn main() -> ExitCode {
    if let Err(e) = power_on_self_tests() {
        eprintln!("bc-fips-install consumer: power-on failed: {e:?}");
        return ExitCode::FAILURE;
    }
    println!("{PASSED}");
    let digest = SHA256::hash(b"abc");
    println!("sha256(abc) = {}", digest.iter().map(|b| format!("{b:02x}")).collect::<String>());
    ExitCode::SUCCESS
}
