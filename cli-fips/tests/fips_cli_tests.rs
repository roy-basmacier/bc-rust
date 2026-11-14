//! The approved-mode `bc-rust`, `cli-fips`: it refuses to run without `bc-fips-install`, runs its
//! subcommands after it, offers only the approved ones, and refuses to build with SM2 on. Run with
//! `cargo test --manifest-path cli-fips/Cargo.toml`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

mod common;

use common::BC_RUST;
use common::fips_install::{installed, shared};

/// The exit status of an invocation stopped by a failed self-test.
const SELF_TEST_FAILED: i32 = 3;

fn run_program(program: &Path, args: &[&str], stdin_bytes: &[u8]) -> Output {
    use std::io::Write;
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn bc-rust");
    // A command that exits before reading stdin closes the pipe; that is not a test failure.
    let _ = child.stdin.as_mut().expect("stdin piped").write_all(stdin_bytes);
    child.wait_with_output().expect("failed to wait for bc-rust")
}

/// The installed binary.
fn run(args: &[&str], stdin_bytes: &[u8]) -> Output {
    run_program(shared(), args, stdin_bytes)
}

fn ok(out: Output) -> Vec<u8> {
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    out.stdout
}

/// As built, the slot is empty: the binary refuses to run, whatever the command, and says why.
#[test]
fn without_bc_fips_install_no_command_runs() {
    for args in [&["sha256"][..], &["aes128-gcm", "--direction", "encrypt"][..], &["fips-info"][..]]
    {
        let out = run_program(Path::new(BC_RUST), args, b"abc");
        assert_eq!(out.status.code(), Some(SELF_TEST_FAILED), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: no output after a failure");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(
                "FIPS 140-3 power-on self-tests failed: the software integrity test failed"
            ),
            "{args:?}: {stderr}"
        );
    }
}

#[test]
fn self_test_command_reports_every_algorithm_passed() {
    let out = String::from_utf8(ok(run(&["fips-self-test"], b""))).unwrap();
    assert_eq!(
        out,
        "SHA-256: Passed\nSHA-512: Passed\nHMAC-SHA-512: Passed\n\
         software integrity: Passed\nAES: Passed\n"
    );
}

#[test]
fn hashes_and_macs_give_the_published_answers() {
    // FIPS 180-4 / RFC 4231 / RFC 5869 answers, as hex.
    assert_eq!(
        ok(run(&["sha256", "-x"], b"abc")),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
    );
    assert_eq!(
        ok(run(&["sha3-256", "-x"], b"abc")),
        b"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532\n"
    );
    // RFC 4231 test case 2.
    let mac = ok(run(&["hmac-sha256", "--key", "4a656665", "-x"], b"what do ya want for nothing?"));
    assert_eq!(mac, b"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843\n");
    // RFC 5869 test case 1.
    let okm = ok(run(
        &[
            "hkdf-sha256",
            "--ikm",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "--salt",
            "000102030405060708090a0b0c",
            "--additional-input",
            "f0f1f2f3f4f5f6f7f8f9",
            "--len",
            "42",
            "-x",
        ],
        b"",
    ));
    assert_eq!(
        okm,
        b"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865\n"
    );
}

#[test]
fn aes_round_trips_across_two_invocations() {
    let key = "000102030405060708090a0b0c0d0e0f";
    let ct = ok(run(&["aes128-gcm", "--direction", "encrypt", "--key", key], b"attack at dawn"));
    let pt = ok(run(&["aes128-gcm", "--direction", "decrypt", "--key", key], &ct));
    assert_eq!(pt, b"attack at dawn");
}

#[test]
fn ecdsa_signs_and_verifies_through_files() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fips-cli-ecdsa");
    std::fs::create_dir_all(&dir).unwrap();
    let (sk, pk, sig) = (dir.join("sk"), dir.join("pk"), dir.join("sig"));
    let path = |p: &PathBuf| p.to_str().unwrap().to_string();

    std::fs::write(&sk, ok(run(&["ecdsa-p256", "keygen"], b""))).unwrap();
    std::fs::write(&pk, ok(run(&["ecdsa-p256", "pk-from-sk", "--skfile", &path(&sk)], b"")))
        .unwrap();
    std::fs::write(&sig, ok(run(&["ecdsa-p256", "sign", "--skfile", &path(&sk)], b"message")))
        .unwrap();
    let verify = |msg: &[u8]| {
        run(&["ecdsa-p256", "verify", "--pkfile", &path(&pk), "--sigfile", &path(&sig)], msg)
    };
    assert!(verify(b"message").status.success());
    assert!(!verify(b"another message").status.success());
}

/// Every service outside the module boundary, and the encoders, are unknown subcommands.
#[test]
fn only_approved_subcommands_are_offered() {
    for command in [
        "sm2", "sm3", "sm4-cbc", "hkdf-sm3", "hmac-sm3", "aria128-cbc", "aria128-kw",
        "camellia128-cbc", "camellia128-kw", "chacha20", "chacha20-poly1305", "poly1305",
        "blake2b-512", "blake3", "mlkem512", "mldsa44", "hash-mldsa44", "hex-encode",
        "base64-encode",
    ] {
        let out = run(&[command], b"");
        assert!(!out.status.success(), "{command}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("unrecognized subcommand"),
            "{command}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    // Help lists none of them, and does list the approved ones.
    let help = String::from_utf8(ok(run(&["--help"], b""))).unwrap();
    let commands = help.split("Commands:").nth(1).unwrap().split("Options:").next().unwrap();
    let listed: Vec<&str> = commands
        .lines()
        .filter_map(|l| l.strip_prefix("  "))
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    assert!(listed.len() > 90, "{listed:?}");
    for approved in [
        "aes128-gcm", "aes256-kw", "ecdsa-p256", "ecdsa-secp256k1", "eccdh-p384", "hkdf-sha512",
        "hmac-sha3-256", "sha256", "shake128", "rng", "fips-info",
    ] {
        assert!(listed.contains(&approved), "{approved} missing from help");
    }
    for name in &listed {
        for banned in [
            "sm2", "sm3", "sm4", "aria", "camellia", "chacha", "poly1305", "blake", "mlkem",
            "mldsa", "hex", "base64",
        ] {
            assert!(!name.contains(banned), "{name} is listed");
        }
    }
}

#[test]
fn fips_info_records_an_approved_only_build() {
    let printed = String::from_utf8(ok(run(&["fips-info"], b""))).unwrap();
    let features = printed.lines().find(|l| l.starts_with("toolchain.features")).unwrap();
    let features: Vec<&str> = features.split_whitespace().skip(1).collect();
    assert!(features.contains(&"approved-only"), "{features:?}");
    assert!(features.contains(&"integrity"), "{features:?}");
    // No boundary crate has the non-approved feature on.
    assert!(!printed.contains("sm2"), "{printed}");
}

#[test]
fn a_failed_power_on_runs_no_command_and_exits_non_zero() {
    for args in
        [&["--fips-simulate-failure", "sha256"][..], &["--fips-simulate-failure", "fips-info"][..]]
    {
        let out = run(args, b"abc");
        assert_eq!(out.status.code(), Some(SELF_TEST_FAILED), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?}: no output after a failure");
    }
}

/// One byte of the installed binary's HMAC slot changed: the program no longer runs.
#[test]
fn a_binary_changed_after_install_refuses_to_run() {
    let program = installed("changed");
    let mut bytes = std::fs::read(&program).unwrap();
    let slot = bouncycastle_fips::binary_hmac::find_slot(&bytes).unwrap() as usize;
    bytes[slot + bouncycastle_fips::binary_hmac::SLOT_MAGIC.len()] ^= 1;
    std::fs::write(&program, bytes).unwrap();
    let out = run_program(&program, &["sha256"], b"abc");
    assert_eq!(out.status.code(), Some(SELF_TEST_FAILED));
    assert!(out.stdout.is_empty());
}

/// The approved build refuses to build when anything turns SM2 on: the `refuse-test-sm2` feature
/// turns on `bouncycastle-ec/sm2`, as `bouncycastle-sm2` would.
#[test]
fn building_with_sm2_on_fails() {
    let output = Command::new(env!("CARGO"))
        .args(["build", "--quiet", "--manifest-path"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .arg("--target-dir")
        .arg(Path::new(env!("CARGO_TARGET_TMPDIR")).join("sm2-refusal-target"))
        .args(["--features", "refuse-test-sm2"])
        .output()
        .expect("cargo runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "`approved-only` is on, but `bouncycastle-ec` has the non-approved feature `sm2` on"
        ),
        "{stderr}"
    );
}
