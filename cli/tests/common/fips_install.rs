//! With the cli's `fips` feature, `bc-rust` refuses to run until the post-link tool
//! `bc-fips-install` has written its binary HMAC. This builds the tool (a member of the
//! `crypto/fips` workspace, outside the root one) and runs it on copies of the binary under test.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The repository root.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// `bc-fips-install`, built once per test program, in a target directory of its own.
fn tool() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let target = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fips-target");
        let status = Command::new(env!("CARGO"))
            .args(["build", "--release", "--quiet", "-p", "bc-fips-install", "--manifest-path"])
            .arg(repo().join("crypto/fips/Cargo.toml"))
            .arg("--target-dir")
            .arg(&target)
            .status()
            .expect("cargo runs");
        assert!(status.success(), "building bc-fips-install failed");
        target.join("release/bc-fips-install")
    })
}

/// A copy of the `bc-rust` under test with the tool run on it, private to the test program and
/// to `name`.
pub fn installed(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("fips-cli-tests")
        .join(env!("CARGO_CRATE_NAME"))
        .join(name);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bc-rust");
    fs::copy(super::BC_RUST, &path).unwrap();
    let out = Command::new(tool()).arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    path
}

/// The installed `bc-rust` that the tests of a program which do not change the file share.
pub fn shared() -> &'static Path {
    static INSTALLED: OnceLock<PathBuf> = OnceLock::new();
    INSTALLED.get_or_init(|| installed("shared"))
}
