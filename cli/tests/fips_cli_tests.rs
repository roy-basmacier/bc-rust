//! The cli's `fips` feature: the power-on self-tests every invocation runs first, and the
//! `fips-self-test` subcommand. Run with `cargo test -p cli --features fips`; without the feature
//! only the check that the subcommand does not exist runs.

use std::process::{Command, Output};

const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    use std::io::Write;
    let mut child = Command::new(BC_RUST)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");
    // A command that exits before reading stdin closes the pipe; that is not a test failure.
    let _ = child.stdin.as_mut().expect("stdin piped").write_all(stdin_bytes);
    child.wait_with_output().expect("failed to wait for bc-rust")
}

#[cfg(not(feature = "fips"))]
#[test]
fn without_the_feature_there_is_no_self_test_command() {
    let out = run(&["fips-self-test"], b"");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unrecognized subcommand"));
}

#[cfg(feature = "fips")]
mod fips {
    use super::run;
    use bouncycastle::core::traits::HashOneShot;
    use bouncycastle::sha2::SHA256;

    /// The exit status of an invocation stopped by a failed self-test.
    const SELF_TEST_FAILED: i32 = 3;

    #[test]
    fn self_test_command_reports_every_algorithm_passed() {
        let out = run(&["fips-self-test"], b"");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            "SHA-256: Passed\nSHA-512: Passed\nAES: Passed\n"
        );
    }

    #[test]
    fn gated_commands_run_after_the_power_on_self_tests() {
        // The answer the library gives in this process once its own self-tests have passed.
        bouncycastle_fips::power_on_self_tests().unwrap();
        let expected = SHA256::hash(b"abc");
        let out = run(&["sha256"], b"abc");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        // The raw digest, then the newline the command ends its output with.
        assert_eq!(out.stdout.strip_suffix(b"\n"), Some(expected.as_slice()));

        // AES: an encrypt/decrypt round trip through two invocations.
        let key = "000102030405060708090a0b0c0d0e0f";
        let ct = run(&["aes128-gcm", "--direction", "encrypt", "--key", key], b"attack at dawn");
        assert!(ct.status.success(), "{}", String::from_utf8_lossy(&ct.stderr));
        let pt = run(&["aes128-gcm", "--direction", "decrypt", "--key", key], &ct.stdout);
        assert!(pt.status.success(), "{}", String::from_utf8_lossy(&pt.stderr));
        assert_eq!(pt.stdout, b"attack at dawn");
    }

    #[test]
    fn a_failed_power_on_runs_no_command_and_exits_non_zero() {
        for args in [
            &["--fips-simulate-failure", "sha256"][..],
            &["--fips-simulate-failure", "fips-self-test"][..],
            &["--fips-simulate-failure", "sm3"][..],
        ] {
            let out = run(args, b"abc");
            assert_eq!(out.status.code(), Some(SELF_TEST_FAILED), "{args:?}");
            assert!(out.stdout.is_empty(), "{args:?}: no output after a failure");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(
                stderr.contains(
                    "FIPS 140-3 power-on self-tests failed: the module is in the error state \
                     since the AES self-test failed"
                ),
                "{args:?}: {stderr}"
            );
        }
    }

    #[test]
    fn the_failure_hook_is_not_listed() {
        let out = run(&["--help"], b"");
        assert!(!String::from_utf8_lossy(&out.stdout).contains("simulate"));
    }
}
