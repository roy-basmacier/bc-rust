//! End-to-end tests of `bc-fips-install`: a release build of `tests/consumer`, a program that
//! powers on bouncycastle-fips with the software integrity test, is installed with the tool and
//! run, intact and with single bytes changed; and the tool's refusals.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use bouncycastle_fips::binary_hmac::{
    BinaryHmacError, SLOT_LEN, SLOT_MAGIC, find_slot, read_only_segments,
};

/// What the consumer prints once power-on has passed (its `PASSED`).
const PASSED: &[u8] = b"bc-fips-install consumer: power-on passed";
/// What it prints when the integrity test fails.
const INTEGRITY_FAILED: &str = "power-on failed: KnownAnswerMismatch(SoftwareIntegrity)";

/// The consumer, built once per test run in release, as the tool's users build theirs.
fn consumer() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("consumer-target");
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/consumer/Cargo.toml");
        let status = Command::new(env!("CARGO"))
            .args(["build", "--release", "--quiet", "--manifest-path"])
            .arg(&manifest)
            .arg("--target-dir")
            .arg(&target)
            .status()
            .expect("cargo runs");
        assert!(status.success(), "building the consumer failed");
        target.join("release/bc-fips-install-consumer")
    })
}

/// A fresh copy of the consumer, private to the test `name`.
fn copy_of_consumer(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("install-tests").join(name);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("consumer");
    fs::copy(consumer(), &path).unwrap();
    path
}

fn tool(args: &[&Path]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bc-fips-install")).args(args).output().unwrap()
}

fn run(program: &Path) -> Output {
    // The tests run on threads of one process, and each writes its own copy of a program. A
    // child forked by one thread while another has its copy open for writing inherits that
    // descriptor until it execs, and running the copy in that window fails with ETXTBSY.
    loop {
        match Command::new(program).output() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            output => return output.unwrap(),
        }
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Asserts that the consumer at `program` passed power-on.
fn assert_passes(program: &Path) {
    let output = run(program);
    assert!(output.status.success(), "{}: {}", program.display(), stderr(&output));
    assert!(stdout(&output).starts_with(std::str::from_utf8(PASSED).unwrap()));
}

/// Asserts that the consumer at `program` failed its integrity test.
fn assert_integrity_fails(program: &Path) {
    let output = run(program);
    assert_eq!(output.status.code(), Some(1), "{}", program.display());
    assert!(stderr(&output).contains(INTEGRITY_FAILED), "{}", stderr(&output));
}

/// Installs `program`, asserting that the tool succeeded.
fn install(program: &Path) -> Output {
    let output = tool(&[program]);
    assert!(output.status.success(), "{}", stderr(&output));
    output
}

/// The tool's refusal of `program`: exit status 1, the file unchanged, and `message` in stderr.
fn assert_refused(program: &Path, message: &str) {
    let before = fs::read(program).unwrap();
    let output = tool(&[program]);
    assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
    assert!(stderr(&output).contains(message), "{}", stderr(&output));
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read(program).unwrap(), before, "a refused file is not written");
}

fn flip_byte(path: &Path, at: usize) {
    let mut bytes = fs::read(path).unwrap();
    bytes[at] ^= 0x01;
    fs::write(path, bytes).unwrap();
}

fn write_bytes(path: &Path, at: usize, new: &[u8]) {
    let mut bytes = fs::read(path).unwrap();
    bytes[at..at + new.len()].copy_from_slice(new);
    fs::write(path, bytes).unwrap();
}

/// The one offset of `needle` in `haystack`.
fn only_offset(haystack: &[u8], needle: &[u8]) -> usize {
    let mut found = haystack.windows(needle.len()).enumerate().filter(|(_, w)| *w == needle);
    let (at, _) = found.next().expect("found");
    assert!(found.next().is_none(), "found once");
    at
}

/// Whether file offset `at` is in a read-only `PT_LOAD` segment of `image`.
fn in_read_only_segment(image: &[u8], at: usize) -> bool {
    let at = at as u64;
    read_only_segments(image)
        .unwrap()
        .as_slice()
        .iter()
        .any(|s| s.offset <= at && at < s.offset + s.filesz)
}

#[test]
fn installed_program_passes_power_on() {
    let program = copy_of_consumer("passes");
    let original = fs::read(&program).unwrap();
    // As built, the slot is empty and the program fails closed.
    assert_integrity_fails(&program);

    let output = install(&program);
    let installed = fs::read(&program).unwrap();
    let slot = find_slot(&original).unwrap() as usize;
    let value = &installed[slot + SLOT_MAGIC.len()..slot + SLOT_LEN];
    let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        stdout(&output),
        format!("{}: slot at file offset {slot:#x}: {hex}\n", program.display())
    );
    // Only the value's 64 bytes changed, and they are no longer zero.
    assert_eq!(installed.len(), original.len());
    let changed: Vec<usize> =
        (0..original.len()).filter(|&i| original[i] != installed[i]).collect();
    assert!(changed.iter().all(|&i| slot + SLOT_MAGIC.len() <= i && i < slot + SLOT_LEN));
    assert!(value.iter().any(|&b| b != 0));
    assert_passes(&program);

    // Running it again on the installed file writes the same value.
    assert_eq!(stdout(&install(&program)), stdout(&output));
    assert_eq!(fs::read(&program).unwrap(), installed);
}

#[test]
fn a_changed_read_only_byte_fails_power_on() {
    let program = copy_of_consumer("changed");
    install(&program);
    assert_passes(&program);
    let image = fs::read(&program).unwrap();
    let slot = find_slot(&image).unwrap() as usize;

    // A byte of data the program reads only after the integrity test, so the program runs into
    // the test and reports it, rather than crashing on a changed instruction.
    let marker = only_offset(&image, PASSED);
    assert!(in_read_only_segment(&image, marker));
    flip_byte(&program, marker + 5);
    assert_integrity_fails(&program);
    flip_byte(&program, marker + 5);
    assert_passes(&program);

    // One bit of the value in the slot.
    flip_byte(&program, slot + SLOT_LEN - 1);
    assert_integrity_fails(&program);
    flip_byte(&program, slot + SLOT_LEN - 1);
    assert_passes(&program);

    // The first and last byte of every read-only segment past the ELF header's identification:
    // whatever the byte is, the program must not pass. (A changed instruction or header may stop
    // it before the test reports, so only the exit status is checked.)
    let segments = read_only_segments(&image).unwrap();
    assert!(segments.as_slice().len() >= 2);
    for s in segments.as_slice() {
        let (start, end) = (s.offset as usize, (s.offset + s.filesz) as usize);
        for at in [start.max(16), end - 1] {
            assert!(!(slot..slot + SLOT_LEN).contains(&at));
            flip_byte(&program, at);
            // A changed header byte may stop the kernel from running it at all.
            let passed = Command::new(&program).output().is_ok_and(|o| o.status.success());
            assert!(!passed, "byte {at:#x} changed, power-on passed");
            flip_byte(&program, at);
        }
    }
    assert_passes(&program);
}

#[test]
fn bytes_outside_the_read_only_segments_are_not_covered() {
    let program = copy_of_consumer("outside");
    install(&program);
    let image = fs::read(&program).unwrap();
    // The section header table, at the end of the file, is not loaded.
    let last = image.len() - 1;
    assert!(!in_read_only_segment(&image, last));
    flip_byte(&program, last);
    assert_passes(&program);
}

#[test]
fn strip_goes_before_the_tool() {
    if Command::new("strip").arg("--version").output().is_err() {
        eprintln!("`strip` not found; skipping");
        return;
    }
    // Stripped, then installed: the slot is found by its magic, with no symbols left.
    let program = copy_of_consumer("strip-first");
    assert!(Command::new("strip").arg(&program).status().unwrap().success());
    install(&program);
    assert_passes(&program);

    // Installed, then stripped: strip rewrites the ELF header, which is hashed.
    let program = copy_of_consumer("strip-after");
    install(&program);
    assert!(Command::new("strip").arg(&program).status().unwrap().success());
    assert_integrity_fails(&program);
    // Installing again repairs it.
    install(&program);
    assert_passes(&program);
}

#[test]
fn refuses_a_file_with_no_slot() {
    let program = copy_of_consumer("no-slot");
    let slot = find_slot(&fs::read(&program).unwrap()).unwrap() as usize;
    flip_byte(&program, slot);
    assert_refused(&program, "no integrity slot");
}

/// A program that searches for the slot must not contain the magic outside its own slot. The tool
/// is such a program, built without `integrity`: it has no slot, so it must refuse itself and
/// leave the copy as it was. (It once found the constant `find_slot` compared with, and wrote the
/// value over the 64 bytes of read-only data after it.)
#[test]
fn refuses_itself_because_the_search_does_not_contain_the_magic() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("install-tests").join("itself");
    fs::create_dir_all(&dir).unwrap();
    let copy = dir.join("bc-fips-install");
    fs::copy(env!("CARGO_BIN_EXE_bc-fips-install"), &copy).unwrap();
    let before = fs::read(&copy).unwrap();
    assert_eq!(find_slot(&before), Err(BinaryHmacError::NoSlot));
    assert_refused(&copy, "no integrity slot");
    assert_eq!(fs::read(&copy).unwrap(), before);
}

#[test]
fn refuses_a_file_with_two_slots() {
    // A second magic in a read-only segment.
    let program = copy_of_consumer("two-slots");
    let marker = only_offset(&fs::read(&program).unwrap(), PASSED);
    write_bytes(&program, marker, &SLOT_MAGIC);
    assert_refused(&program, "more than one integrity slot");

    // A second magic outside every loaded segment, in an installed file.
    let program = copy_of_consumer("two-slots-unloaded");
    install(&program);
    let len = fs::read(&program).unwrap().len();
    write_bytes(&program, len - SLOT_MAGIC.len(), &SLOT_MAGIC);
    assert_refused(&program, "more than one integrity slot");
}

#[test]
fn refuses_a_slot_outside_the_read_only_segments() {
    let program = copy_of_consumer("slot-outside");
    let image = fs::read(&program).unwrap();
    let slot = find_slot(&image).unwrap() as usize;
    flip_byte(&program, slot);
    let at = image.len() - SLOT_LEN;
    assert!(!in_read_only_segment(&image, at));
    write_bytes(&program, at, &SLOT_MAGIC);
    assert_refused(&program, "not inside a read-only loaded segment");
}

#[test]
fn refuses_a_file_that_is_not_elf() {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("install-tests/not-elf");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("file");
    // With a slot in it, so the refusal is for the format and not for the slot.
    fs::write(&path, [&b"#!/bin/sh\n"[..], &SLOT_MAGIC, &[0; 64]].concat()).unwrap();
    assert_refused(&path, "not an ELF file");
}

#[test]
fn refuses_a_file_it_cannot_open() {
    let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("install-tests/does-not-exist");
    let output = tool(&[&path]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).starts_with("bc-fips-install: "), "{}", stderr(&output));
}

#[test]
fn usage() {
    let both = |output: &Output| stdout(output) + &stderr(output);

    let output = tool(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).starts_with("usage: bc-fips-install <ELF file>"));

    for help in ["-h", "--help"] {
        let output = tool(&[Path::new(help)]);
        assert_eq!(output.status.code(), Some(0));
        assert!(stdout(&output).starts_with("usage: bc-fips-install <ELF file>"));
        assert!(output.stderr.is_empty());
    }

    // An unknown option is not taken for a file name; two files are one too many.
    let program = copy_of_consumer("usage");
    for args in [&[Path::new("--verify"), &program][..], &[Path::new("-x")], &[&program, &program]]
    {
        let output = tool(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(both(&output).starts_with("usage:"));
    }
}
