//! The embedded source pin: the table against the sources in this checkout, the module HMAC
//! against the build-time encoding and the independent script, the external crates against
//! `crypto/fips/Cargo.lock`, the toolchain record, and the `fips-validated` gate at power-on.
//!
//! The table needs only SHA-2's self-test to recompute; the public [`module_hmac`] needs
//! HMAC-SHA-512's, which only a successful power-on records, and that fails closed under the
//! `integrity` feature (`integrity_tests.rs`), so those tests are left out there.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bouncycastle_fips::{
    MODULE_HMAC_KEY, ModuleTableEntry, external_crates, module_table, toolchain,
};
#[cfg(not(feature = "integrity"))]
use bouncycastle_fips::{
    SelfTestStatus, SelfTestedAlgorithm, module_hmac, module_info, power_on_self_tests,
    self_test_status,
};
use bouncycastle_fips_build::{
    BOUNDARY, BoundaryCrate, EXTERNAL_PINS, build_table, dep_var_links, external_hmac, hex,
    read_crate,
};

fn crypto_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// The directory of a boundary crate in this checkout: `bouncycastle-aes` is `crypto/aes`.
fn crate_dir(package: &str) -> PathBuf {
    crypto_dir().join(package.strip_prefix("bouncycastle-").unwrap())
}

#[test]
fn the_key_is_the_published_string() {
    assert_eq!(MODULE_HMAC_KEY, b"Legion of the Bouncy Castle FIPS Rust API");
}

fn sha2_self_test() {
    #[cfg(feature = "sha2")]
    bouncycastle_sha2::self_test().expect("SHA-2 self-tests pass");
}

/// The table recomputed from this checkout with the build script's code.
fn recomputed_table() -> Vec<(String, [u8; 64])> {
    sha2_self_test();
    let crates: Vec<BoundaryCrate> = BOUNDARY
        .iter()
        .map(|package| {
            let (manifest, files) = read_crate(&crate_dir(package)).unwrap();
            let dep_links = dep_var_links(manifest.links.as_deref().unwrap());
            BoundaryCrate { dep_links, manifest, files }
        })
        .collect();
    build_table(&crates).unwrap()
}

fn embedded_table() -> Vec<(String, [u8; 64])> {
    module_table().iter().map(|e| (e.package.to_string(), e.hmac)).collect()
}

#[test]
fn the_table_pins_the_sources_of_this_checkout() {
    assert_eq!(embedded_table(), recomputed_table());
}

/// The run-time encoding of the module HMAC is the build-time one.
#[cfg(not(feature = "integrity"))]
#[test]
fn the_module_hmac_is_derived_from_the_table() {
    power_on_self_tests().expect("self-tests pass");
    assert_eq!(module_hmac(), Ok(bouncycastle_fips_build::module_hmac(&embedded_table())));
}

/// `ModuleInfo` holds the three public values and prints them in the format of
/// `bc-rust fips-info`: the independent script's lines, then the toolchain record.
#[cfg(not(feature = "integrity"))]
#[test]
fn module_info_prints_the_table_the_module_hmac_and_the_toolchain() {
    power_on_self_tests().expect("self-tests pass");
    let info = module_info().expect("HMAC-SHA-512 has passed");
    assert_eq!(info.table, module_table());
    assert_eq!(Ok(info.module_hmac), module_hmac());
    assert_eq!(info.toolchain, toolchain());

    let mut expected = String::new();
    for e in module_table() {
        expected.push_str(&format!("{} {}\n", e.package, hex(&e.hmac)));
    }
    expected.push_str(&format!("module-hmac {}\n", hex(&info.module_hmac)));
    for e in external_crates() {
        expected.push_str(&format!("external {} {} {}\n", e.package, e.version, hex(&e.checksum)));
    }
    assert_eq!(info.external, external_crates());
    let t = toolchain();
    expected.push_str(&format!(
        "toolchain.rustc {}\ntoolchain.host {}\ntoolchain.target {}\ntoolchain.opt-level {}\n\
         toolchain.profile {}\ntoolchain.features{}\n",
        t.rustc,
        t.host,
        t.target,
        t.opt_level,
        t.profile,
        t.features.iter().map(|f| format!(" {f}")).collect::<String>()
    ));
    assert_eq!(info.to_string(), expected);
}

#[test]
fn the_table_is_the_boundary_and_the_external_crates_in_bytewise_order() {
    let names: Vec<&str> = module_table().iter().map(|e: &ModuleTableEntry| e.package).collect();
    let expected: Vec<&str> = BOUNDARY.into_iter().chain(EXTERNAL_PINS.map(|p| p.name)).collect();
    assert_eq!(names, expected);
    assert!(names.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes()));
}

/// The external crates are the pins, and their rows are made from them.
#[test]
fn the_external_crates_are_the_pins() {
    sha2_self_test();
    assert_eq!(external_crates().len(), EXTERNAL_PINS.len());
    for (e, pin) in external_crates().iter().zip(EXTERNAL_PINS) {
        assert_eq!(
            (e.package, e.version, hex(&e.checksum)),
            (pin.name, pin.version, pin.checksum.to_string())
        );
        let row = module_table().iter().find(|r| r.package == e.package).unwrap();
        assert_eq!(row.hmac, external_hmac(e.package, e.version, &e.checksum));
    }
}

/// The reference lock of the module's own workspace, which is committed.
fn reference_lock() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock")
}

/// `dev_scripts/fips_module_hmac.py` over the boundary crates of this checkout and `lock`, or
/// `None`, with a notice, where there is no `python3`.
fn run_script(lock: &Path) -> Option<Output> {
    let script = crypto_dir().join("../dev_scripts/fips_module_hmac.py");
    let mut cmd = Command::new("python3");
    cmd.arg("-I").arg(&script).arg("--lock").arg(lock);
    for package in BOUNDARY {
        cmd.arg(crate_dir(package));
    }
    match cmd.output() {
        Ok(output) => Some(output),
        Err(e) => {
            eprintln!("python3 not run ({e}); skipping the independent-script check");
            None
        }
    }
}

/// What the script prints for the embedded table, module HMAC and external crates.
fn expected_script_output() -> String {
    let mut expected = String::new();
    for e in module_table() {
        expected.push_str(&format!("{} {}\n", e.package, hex(&e.hmac)));
    }
    let module = bouncycastle_fips_build::module_hmac(&embedded_table());
    expected.push_str(&format!("module-hmac {}\n", hex(&module)));
    for e in external_crates() {
        expected.push_str(&format!("external {} {} {}\n", e.package, e.version, hex(&e.checksum)));
    }
    expected
}

/// `dev_scripts/fips_module_hmac.py`, the independent recomputation, over the boundary crates of
/// this checkout and the reference lock prints exactly the embedded table, the module HMAC and
/// the pins: the lock and EXTERNAL_PINS agree. Skipped, with a notice, where there is no
/// `python3`.
#[test]
fn the_independent_script_agrees() {
    sha2_self_test();
    let Some(output) = run_script(&reference_lock()) else { return };
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected_script_output());
}

/// A copy of the reference lock with `from` replaced by `to`, in a directory of its own.
fn changed_lock(name: &str, from: &str, to: &str) -> PathBuf {
    let text = fs::read_to_string(reference_lock()).unwrap();
    assert!(text.contains(from), "{from}");
    let dir = std::env::temp_dir().join(format!("bc-fips-lock-{}-{name}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("Cargo.lock");
    fs::write(&path, text.replacen(from, to, 1)).unwrap();
    path
}

/// A lock with another version or checksum of an external crate gives another module HMAC, and
/// the script prints what it read; so a program built from it does not match the published one.
#[test]
fn the_script_on_a_changed_version_or_checksum() {
    sha2_self_test();
    let getrandom = EXTERNAL_PINS[1];
    let checksum = format!("checksum = \"{}\"", getrandom.checksum);
    let mut other = getrandom.checksum.to_string();
    other.replace_range(0..1, if other.starts_with('0') { "1" } else { "0" });
    let cases = [
        ("checksum", checksum.clone(), format!("checksum = \"{other}\""), "0.4.3", other.clone()),
        (
            "version",
            "name = \"getrandom\"\nversion = \"0.4.3\"".to_string(),
            "name = \"getrandom\"\nversion = \"0.4.4\"".to_string(),
            "0.4.4",
            getrandom.checksum.to_string(),
        ),
    ];
    let expected = expected_script_output();
    for (name, from, to, version, sum) in cases {
        let lock = changed_lock(name, &from, &to);
        let Some(output) = run_script(&lock) else { return };
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let printed = String::from_utf8(output.stdout).unwrap();
        assert_ne!(printed, expected, "{name}");
        let module =
            |s: &str| s.lines().find(|l| l.starts_with("module-hmac ")).unwrap().to_string();
        assert_ne!(module(&printed), module(&expected), "{name}");
        assert!(printed.contains(&format!("external getrandom {version} {sum}\n")), "{printed}");
        // The boundary crates' rows are untouched.
        let boundary_rows = |s: &str| s.lines().take(BOUNDARY.len()).collect::<Vec<_>>().join("\n");
        assert_eq!(boundary_rows(&printed), boundary_rows(&expected), "{name}");
        fs::remove_dir_all(lock.parent().unwrap()).unwrap();
    }
}

/// The script refuses a lock in which an external crate is not the crates.io package with a
/// checksum: a `[patch]` from git or a path, another registry, or no checksum.
#[test]
fn the_script_refuses_what_is_not_from_crates_io() {
    let getrandom = EXTERNAL_PINS[1];
    let checksum = format!("checksum = \"{}\"\n", getrandom.checksum);
    let source = "name = \"getrandom\"\nversion = \"0.4.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    for (name, from, to, wanted) in [
        (
            "git",
            source.to_string(),
            source.replace(
                "registry+https://github.com/rust-lang/crates.io-index",
                "git+https://example.com/getrandom#0123",
            ),
            "is not a crates.io package",
        ),
        (
            "path",
            source.to_string(),
            "name = \"getrandom\"\nversion = \"0.4.3\"\n".to_string(),
            "is not a crates.io package (source a path)",
        ),
        (
            "registry",
            source.to_string(),
            source.replace("crates.io-index", "other-index"),
            "is not a crates.io package",
        ),
        ("no-checksum", checksum.clone(), String::new(), "getrandom 0.4.3 has no checksum"),
    ] {
        let lock = changed_lock(name, &from, &to);
        let Some(output) = run_script(&lock) else { return };
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{name}");
        assert!(stderr.contains(wanted), "{name}: {stderr}");
        fs::remove_dir_all(lock.parent().unwrap()).unwrap();
    }
}

#[test]
fn the_toolchain_record() {
    let t = toolchain();
    assert!(t.rustc.starts_with("rustc "), "{}", t.rustc);
    assert!(!t.host.is_empty() && !t.target.is_empty());
    assert!(["0", "1", "2", "3", "s", "z"].contains(&t.opt_level), "{}", t.opt_level);
    assert!(["debug", "release"].contains(&t.profile), "{}", t.profile);
    let mut expected = Vec::new();
    for (feature, on) in [
        ("aes", cfg!(feature = "aes")),
        ("approved-only", cfg!(feature = "approved-only")),
        ("default", cfg!(feature = "default")),
        ("eccdh", cfg!(feature = "eccdh")),
        ("ecdsa", cfg!(feature = "ecdsa")),
        ("fips-validated", cfg!(feature = "fips-validated")),
        ("integrity", cfg!(feature = "integrity")),
        ("sha2", cfg!(feature = "sha2")),
    ] {
        if on {
            expected.push(feature);
        }
    }
    assert_eq!(t.features, expected.as_slice());
    assert_eq!(t.approved_only(), cfg!(feature = "approved-only"));
}

/// The boundary crates' features: one entry per boundary crate, in table order, each sorted; and
/// SM2 off, since nothing in this crate's own build asks for it.
#[test]
fn the_crate_features_in_the_record() {
    let t = toolchain();
    let packages: Vec<&str> = t.crate_features.iter().map(|c| c.package).collect();
    assert_eq!(packages, BOUNDARY);
    for c in t.crate_features {
        assert!(c.features.is_sorted(), "{c:?}");
    }
    let ec = t.crate_features.iter().find(|c| c.package == "bouncycastle-ec").unwrap();
    assert_eq!(ec.features, &[] as &[&str]);
    // The algorithm crates' `fips` features that this crate's own features turn on.
    let sha2 = t.crate_features.iter().find(|c| c.package == "bouncycastle-sha2").unwrap();
    assert_eq!(sha2.features.contains(&"fips"), cfg!(feature = "sha2"));
    let ecdsa = t.crate_features.iter().find(|c| c.package == "bouncycastle-ecdsa").unwrap();
    assert_eq!(ecdsa.features.contains(&"fips"), cfg!(feature = "ecdsa"));
    let eccdh = t.crate_features.iter().find(|c| c.package == "bouncycastle-eccdh").unwrap();
    assert_eq!(eccdh.features.contains(&"fips"), cfg!(feature = "eccdh"));
}

/// With `fips-validated`, power-on checks the module HMAC against the published constant and it
/// passes, since the build already refused any other; without, nothing is compared.
#[cfg(not(feature = "integrity"))]
#[test]
fn the_validated_gate_at_power_on() {
    power_on_self_tests().expect("self-tests pass");
    let expected = if cfg!(feature = "fips-validated") {
        SelfTestStatus::Passed
    } else {
        SelfTestStatus::NotRun
    };
    assert_eq!(self_test_status(SelfTestedAlgorithm::ModuleIntegrity), expected);
}

/// Without the `sha2` feature nothing gates SHA-512, so there is nothing to wait for.
#[cfg(not(feature = "sha2"))]
#[test]
fn without_sha2_the_module_hmac_needs_no_power_on() {
    assert!(bouncycastle_fips::module_hmac().is_ok());
}
