//! End to end, over two programs that link different subsets of the module (`tests/consumers`:
//! one uses AES only, the other every crate of the module): each is built in release, installed
//! with the tool, and run. Both must embed the same module table and module HMAC, equal to what
//! the independent `dev_scripts/fips_module_hmac.py` computes over this checkout and the
//! consumers' own `Cargo.lock`; both must pass
//! the binary HMAC; and each must refuse to run with its slot empty or one byte changed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use bouncycastle_fips::binary_hmac::{SLOT_LEN, SLOT_MAGIC, find_slot, read_only_segments};
use bouncycastle_fips::{external_crates, module_table};

/// What a consumer prints when its integrity test fails.
const INTEGRITY_FAILED: &str = "power-on failed: KnownAnswerMismatch(SoftwareIntegrity)";

/// One of the two programs.
struct Consumer {
    /// Its package in `tests/consumers`, and its binary's name.
    package: &'static str,
    /// The first line it prints once power-on has passed (its `PASSED`).
    passed: &'static str,
    /// The last line it prints, once it has used the algorithms.
    done: &'static str,
}

const AES_ONLY: Consumer = Consumer {
    package: "fips-consumer-aes-only",
    passed: "aes-only consumer: power-on passed",
    done: "aes-gcm round trip ok",
};

const EVERYTHING: Consumer = Consumer {
    package: "fips-consumer-everything",
    passed: "everything consumer: power-on passed",
    done: "every module crate used ok",
};

/// The `crypto` directory of this checkout.
fn crypto_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Builds `consumer` in release, once per test run, each on its own (`-p`) so that neither's
/// features reach the other, and returns the binary.
fn build(consumer: &Consumer) -> &'static Path {
    static AES_ONLY_BUILT: OnceLock<PathBuf> = OnceLock::new();
    static EVERYTHING_BUILT: OnceLock<PathBuf> = OnceLock::new();
    let cell =
        if consumer.package == AES_ONLY.package { &AES_ONLY_BUILT } else { &EVERYTHING_BUILT };
    cell.get_or_init(|| {
        let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("consumers-target");
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/consumers/Cargo.toml");
        let status = Command::new(env!("CARGO"))
            .args(["build", "--release", "--quiet", "-p", consumer.package, "--manifest-path"])
            .arg(&manifest)
            .arg("--target-dir")
            .arg(&target)
            .status()
            .expect("cargo runs");
        assert!(status.success(), "building {} failed", consumer.package);
        target.join("release").join(consumer.package)
    })
}

/// A fresh copy of `consumer`, as built, private to the test `name`.
fn copy_of(consumer: &Consumer, name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("two-consumers-tests").join(name);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(consumer.package);
    fs::copy(build(consumer), &path).unwrap();
    path
}

fn install(program: &Path) {
    let output = Command::new(env!("CARGO_BIN_EXE_bc-fips-install")).arg(program).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

fn run(program: &Path) -> Output {
    Command::new(program).output().unwrap()
}

/// Runs the installed `consumer` at `program`, asserts that it passed power-on and used its
/// algorithms, and returns the module info it printed.
fn module_info_of(consumer: &Consumer, program: &Path) -> String {
    let output = run(program);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let info = stdout.strip_prefix(&format!("{}\n", consumer.passed)).expect("PASSED first");
    info.strip_suffix(&format!("{}\n", consumer.done)).expect("the algorithms used").to_string()
}

/// Asserts that `program` failed its integrity test, and ran nothing after it.
fn assert_refuses_to_run(program: &Path) {
    let output = run(program);
    assert_eq!(output.status.code(), Some(1), "{}", program.display());
    assert!(output.stdout.is_empty(), "{}: no output after a failure", program.display());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(INTEGRITY_FAILED), "{stderr}");
}

fn flip_byte(path: &Path, at: usize) {
    let mut bytes = fs::read(path).unwrap();
    bytes[at] ^= 0x01;
    fs::write(path, bytes).unwrap();
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The lines of the module info up to and including `module-hmac`: the module table and the
/// module HMAC, without the toolchain record, which may differ between the two programs.
fn source_pin(info: &str) -> &str {
    let end = info.find("toolchain.").expect("the toolchain record follows the module HMAC");
    &info[..end]
}

#[test]
fn both_programs_embed_the_same_table_and_module_hmac_as_the_independent_script() {
    let aes_only = copy_of(&AES_ONLY, "same-table");
    let everything = copy_of(&EVERYTHING, "same-table");
    // Different subsets of the module, and so different programs.
    assert_ne!(fs::read(&aes_only).unwrap(), fs::read(&everything).unwrap());
    install(&aes_only);
    install(&everything);
    let aes_only_info = module_info_of(&AES_ONLY, &aes_only);
    let everything_info = module_info_of(&EVERYTHING, &everything);

    let pin = source_pin(&aes_only_info);
    assert_eq!(pin, source_pin(&everything_info));
    // Built with different features of bouncycastle-fips, as the toolchain record says.
    assert!(aes_only_info.ends_with("toolchain.features aes integrity sha2\n"), "{aes_only_info}");
    assert!(
        everything_info
            .ends_with("toolchain.features aes default eccdh ecdsa integrity sha2\n"),
        "{everything_info}"
    );

    // The table is this crate's, entry by entry, then the module HMAC, then the external crates.
    let table = module_table();
    let external = external_crates();
    let lines: Vec<&str> = pin.lines().collect();
    assert_eq!(lines.len(), table.len() + 1 + external.len());
    for (line, entry) in lines.iter().zip(table) {
        assert_eq!(*line, format!("{} {}", entry.package, hex(&entry.hmac)));
    }
    assert!(lines[table.len()].starts_with("module-hmac "));
    for (line, e) in lines[table.len() + 1..].iter().zip(external) {
        assert_eq!(*line, format!("external {} {} {}", e.package, e.version, hex(&e.checksum)));
    }

    // And it is what the independent script computes over the boundary crates of this checkout
    // and the lock file the two programs were built with, which `consumer_program` has made.
    let lock = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/consumers/Cargo.lock");
    let mut cmd = Command::new("python3");
    cmd.arg("-I").arg(crypto_dir().join("../dev_scripts/fips_module_hmac.py"));
    cmd.arg("--lock").arg(lock);
    for entry in table.iter().filter(|e| e.package.starts_with("bouncycastle-")) {
        cmd.arg(crypto_dir().join(entry.package.strip_prefix("bouncycastle-").unwrap()));
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

#[test]
fn each_program_refuses_to_run_with_an_empty_slot_or_a_changed_byte() {
    for consumer in [&AES_ONLY, &EVERYTHING] {
        let program = copy_of(consumer, "refuses");
        // As built, the slot is empty.
        assert_refuses_to_run(&program);
        install(&program);
        module_info_of(consumer, &program);

        // One byte of a read-only segment: of data the program reads only after the integrity
        // test, so that it runs into the test and reports it, rather than crashing on a changed
        // instruction. `bc-fips-install`'s own tests change bytes across every segment.
        let image = fs::read(&program).unwrap();
        let marker = image
            .windows(consumer.passed.len())
            .position(|w| w == consumer.passed.as_bytes())
            .expect("PASSED is in the file");
        let at = marker as u64 + 3;
        let segments = read_only_segments(&image).unwrap();
        assert!(segments.as_slice().iter().any(|s| s.offset <= at && at < s.offset + s.filesz));
        flip_byte(&program, at as usize);
        assert_refuses_to_run(&program);
        flip_byte(&program, at as usize);
        module_info_of(consumer, &program);

        // The slot emptied again after the tool ran.
        let slot = find_slot(&image).unwrap() as usize;
        let mut emptied = image.clone();
        emptied[slot + SLOT_MAGIC.len()..slot + SLOT_LEN].fill(0);
        fs::write(&program, emptied).unwrap();
        assert_refuses_to_run(&program);
    }
}
