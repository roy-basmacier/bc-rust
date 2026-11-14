//! The approved-mode switch end to end, on `tests/approved_mode`, a program that prints the module
//! table, the module HMAC and the toolchain record of the bouncycastle-fips it links:
//!
//! * a full build, in which another dependency turns `bouncycastle-ec/sm2` on, and an
//!   `approved-only` build embed the same table and module HMAC, and their toolchain records
//!   differ only in the feature lines;
//! * an `approved-only` build with that dependency fails to compile, naming the crate and the
//!   feature.
//!
//! Each build is a separate `cargo` run of the program's own workspace, so the features here never
//! reach this crate's own build.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The program's manifest.
fn manifest() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/approved_mode/Cargo.toml")
}

/// `cargo <subcommand>` on the program with `features`, in a target directory shared by every
/// build here (Cargo locks it, and keeps each feature set's artifacts apart).
fn cargo(subcommand: &str, features: &str) -> Output {
    Command::new(env!("CARGO"))
        .args([subcommand, "--quiet", "--manifest-path"])
        .arg(manifest())
        .arg("--target-dir")
        .arg(Path::new(env!("CARGO_TARGET_TMPDIR")).join("approved-mode-target"))
        .args(["--features", features])
        .output()
        .expect("cargo runs")
}

/// The program's output with `features`, which must build and run.
fn run(features: &str) -> String {
    let output = cargo("run", features);
    assert!(
        output.status.success(),
        "features `{features}`: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// Whether `line` is one of the toolchain record's feature lines.
fn is_feature_line(line: &str) -> bool {
    line.starts_with("features ") || line.starts_with("crate-features ")
}

#[test]
fn full_and_approved_builds_embed_the_same_table() {
    let full = run("sm2");
    let approved = run("approved-only");
    let full: Vec<&str> = full.lines().collect();
    let approved: Vec<&str> = approved.lines().collect();

    // The table and the module HMAC are equal, and they are there.
    let pinned = |lines: &[&str]| -> Vec<String> {
        lines
            .iter()
            .filter(|l| l.starts_with("table ") || l.starts_with("module-hmac "))
            .map(|l| l.to_string())
            .collect()
    };
    assert_eq!(pinned(&full), pinned(&approved));
    // 15 boundary crates and 4 external ones (EXTERNAL_CRATES.md), then the module HMAC.
    assert_eq!(pinned(&full).len(), 15 + 4 + 1, "{full:?}");

    // Every other line is equal, line for line, unless it is a feature line.
    assert_eq!(full.len(), approved.len());
    let mut differing = Vec::new();
    for (f, a) in full.iter().zip(&approved) {
        if f != a {
            assert!(is_feature_line(f) && is_feature_line(a), "`{f}` against `{a}`");
            differing.push((*f, *a));
        }
    }
    // And the feature lines differ exactly where the switch is: bouncycastle-fips's own
    // `approved-only`, and the SM2 that the other dependency turned on in the full build.
    assert_eq!(
        differing,
        [
            (
                "features aes,default,eccdh,ecdsa,sha2",
                "features aes,approved-only,default,eccdh,ecdsa,sha2",
            ),
            ("crate-features bouncycastle-ec sm2", "crate-features bouncycastle-ec "),
        ]
    );
}

#[test]
fn approved_only_with_sm2_fails_to_build() {
    let output = cargo("build", "approved-only,sm2");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains(
            "`approved-only` is on, but `bouncycastle-ec` has the non-approved feature `sm2` on"
        ),
        "{stderr}"
    );
}
