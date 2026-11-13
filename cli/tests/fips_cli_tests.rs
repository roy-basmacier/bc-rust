//! The cli's `fips` feature: the power-on self-tests every invocation runs first, the software
//! integrity test among them, and the `fips-self-test` and `fips-info` subcommands. Run with
//! `cargo test -p cli --features fips` (and `--features fips-validated`); without the feature
//! only the checks that the subcommands do not exist run.
//!
//! With the feature, `bc-rust` refuses to run until the post-link tool has written its binary
//! HMAC, so the tests run copies installed by `common::fips_install`.

use std::path::Path;
use std::process::{Command, Output};

mod common;

use common::BC_RUST;

/// Runs the `bc-rust` under test as built. With the feature, the tests run an installed copy.
#[cfg(not(feature = "fips"))]
fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    run_program(Path::new(BC_RUST), args, stdin_bytes)
}

fn run_program(program: &Path, args: &[&str], stdin_bytes: &[u8]) -> Output {
    use std::io::Write;
    let mut child = Command::new(program)
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
fn without_the_feature_there_are_no_fips_commands() {
    for command in ["fips-self-test", "fips-info"] {
        let out = run(&[command], b"");
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("unrecognized subcommand"));
    }
}

/// Without the feature the CLI runs as built: there is no integrity test to fail.
#[cfg(not(feature = "fips"))]
#[test]
fn without_the_feature_the_binary_runs_as_built() {
    let out = run(&["sha256"], b"abc");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[cfg(feature = "fips")]
mod fips {
    use super::run_program;
    use crate::common::fips_install::{installed, repo, shared};
    use bouncycastle::core::traits::HashOneShot;
    use bouncycastle::sha2::SHA256;
    use bouncycastle_fips::binary_hmac::{SLOT_LEN, SLOT_MAGIC, find_slot, read_only_segments};
    use std::fs;
    use std::path::Path;
    use std::process::{Command, Output};

    /// The exit status of an invocation stopped by a failed self-test.
    const SELF_TEST_FAILED: i32 = 3;

    /// What power-on reports when the software integrity test fails.
    const INTEGRITY_FAILED: &str = "FIPS 140-3 power-on self-tests failed: the software \
                                    integrity test failed";

    fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
        run_program(shared(), args, stdin_bytes)
    }

    fn flip_byte(path: &Path, at: usize) {
        let mut bytes = fs::read(path).unwrap();
        bytes[at] ^= 0x01;
        fs::write(path, bytes).unwrap();
    }

    /// Asserts that `program` ran no command and reported a failed integrity test.
    fn assert_refuses_to_run(program: &Path) {
        for args in [&["sha256"][..], &["fips-info"][..]] {
            let out = run_program(program, args, b"abc");
            assert_eq!(out.status.code(), Some(SELF_TEST_FAILED), "{args:?}");
            assert!(out.stdout.is_empty(), "{args:?}: no output after a failure");
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert!(stderr.contains(INTEGRITY_FAILED), "{args:?}: {stderr}");
        }
    }

    #[test]
    fn self_test_command_reports_every_algorithm_passed() {
        let out = run(&["fips-self-test"], b"");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        // In the order they run: the software integrity test after HMAC-SHA-512's, the module
        // integrity check after it.
        let module =
            if cfg!(feature = "fips-validated") { "module integrity: Passed\n" } else { "" };
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            format!(
                "SHA-256: Passed\nSHA-512: Passed\nHMAC-SHA-512: Passed\n\
                 software integrity: Passed\n{module}AES: Passed\n"
            )
        );
    }

    /// As built, the slot is empty: the binary refuses to run, whatever the command.
    #[test]
    fn an_empty_slot_runs_no_command() {
        assert_refuses_to_run(Path::new(super::BC_RUST));

        // Emptied again after the tool ran.
        let program = installed("emptied");
        let slot = find_slot(&fs::read(&program).unwrap()).unwrap() as usize;
        let mut bytes = fs::read(&program).unwrap();
        bytes[slot + SLOT_MAGIC.len()..slot + SLOT_LEN].fill(0);
        fs::write(&program, bytes).unwrap();
        assert_refuses_to_run(&program);
    }

    /// One byte of a read-only segment changed, after the tool ran: data, so that the program
    /// gets as far as the test and reports it rather than crashing on a changed instruction.
    #[test]
    fn a_changed_read_only_byte_runs_no_command() {
        let program = installed("changed");
        let image = fs::read(&program).unwrap();
        // The text of `fips-info`'s help, which clap holds as one string.
        let needle = b"with dev_scripts/fips_module_hmac.py";
        let mut found = image.windows(needle.len()).enumerate().filter(|(_, w)| w == needle);
        let (at, _) = found.next().expect("the help text is in the binary");
        assert!(found.next().is_none(), "the help text is in the binary once");
        let segments = read_only_segments(&image).unwrap();
        let at = at as u64;
        assert!(segments.as_slice().iter().any(|s| s.offset <= at && at < s.offset + s.filesz));

        flip_byte(&program, at as usize);
        assert_refuses_to_run(&program);
        // The same file with the byte back runs.
        flip_byte(&program, at as usize);
        let out = run_program(&program, &["sha256"], b"abc");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    /// `fips-info` prints the module table, the module HMAC and the toolchain record that the
    /// library embeds, and its table and module HMAC are what the independent script computes
    /// over this checkout. Skipped, with a notice, where there is no `python3`.
    #[test]
    fn fips_info_agrees_with_the_library_and_the_independent_script() {
        let out = run(&["fips-info"], b"");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let printed = String::from_utf8(out.stdout).unwrap();
        let (pin, toolchain) = printed.split_at(printed.find("toolchain.").unwrap());

        // The table this process embeds, which needs no self-test to read.
        let table = bouncycastle_fips::module_table();
        let lines: Vec<&str> = pin.lines().collect();
        assert_eq!(lines.len(), table.len() + 1);
        for (line, entry) in lines.iter().zip(table) {
            assert_eq!(*line, format!("{} {}", entry.package, hex(&entry.hmac)));
        }
        let module = lines[table.len()].strip_prefix("module-hmac ").expect("module-hmac line");
        assert_eq!(module.len(), 128);

        let t = bouncycastle_fips::toolchain();
        let features: String = t.features.iter().map(|f| format!(" {f}")).collect();
        assert_eq!(
            toolchain,
            format!(
                "toolchain.rustc {}\ntoolchain.host {}\ntoolchain.target {}\n\
                 toolchain.opt-level {}\ntoolchain.profile {}\ntoolchain.features{features}\n",
                t.rustc, t.host, t.target, t.opt_level, t.profile
            )
        );
        assert!(t.features.contains(&"integrity"));

        let mut cmd = Command::new("python3");
        cmd.arg("-I").arg(repo().join("dev_scripts/fips_module_hmac.py"));
        for entry in table {
            let name = entry.package.strip_prefix("bouncycastle-").unwrap();
            cmd.arg(repo().join("crypto").join(name));
        }
        let script = match cmd.output() {
            Ok(output) => output,
            Err(e) => {
                eprintln!("python3 not run ({e}); skipping the independent-script check");
                return;
            }
        };
        assert!(script.status.success(), "{}", String::from_utf8_lossy(&script.stderr));
        assert_eq!(String::from_utf8(script.stdout).unwrap(), pin);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn gated_commands_run_after_the_power_on_self_tests() {
        // The answer the library gives in this process once SHA-2's self-tests have passed. Not
        // the full power-on: this test program has an empty slot, so that fails and would stop
        // SHA-256 here.
        bouncycastle::sha2::self_test().unwrap();
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
