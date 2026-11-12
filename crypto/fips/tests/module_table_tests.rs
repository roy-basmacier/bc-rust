//! The embedded source pin: the table against the sources in this checkout, the module HMAC
//! against the build-time encoding and the independent script, the toolchain record, and the
//! `fips-validated` gate at power-on.
//!
//! The table needs only SHA-2's self-test to recompute; the public [`module_hmac`] needs
//! HMAC-SHA-512's, which only a successful power-on records, and that fails closed under the
//! `integrity` feature (`integrity_tests.rs`), so those tests are left out there.

use std::path::{Path, PathBuf};
use std::process::Command;

use bouncycastle_fips::{MODULE_HMAC_KEY, ModuleTableEntry, module_table, toolchain};
#[cfg(not(feature = "integrity"))]
use bouncycastle_fips::{
    SelfTestStatus, SelfTestedAlgorithm, module_hmac, module_info, power_on_self_tests,
    self_test_status,
};
use bouncycastle_fips_build::{
    BOUNDARY, BoundaryCrate, build_table, dep_var_links, hex, read_crate,
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
fn the_table_is_the_boundary_in_bytewise_order() {
    let names: Vec<&str> = module_table().iter().map(|e: &ModuleTableEntry| e.package).collect();
    assert_eq!(names, BOUNDARY);
    assert!(names.windows(2).all(|w| w[0].as_bytes() < w[1].as_bytes()));
}

/// `dev_scripts/fips_module_hmac.py`, the independent recomputation, over the boundary crates of
/// this checkout prints exactly the embedded table and the module HMAC. Skipped, with a notice,
/// where there is no `python3`.
#[test]
fn the_independent_script_agrees() {
    sha2_self_test();
    let script = crypto_dir().join("../dev_scripts/fips_module_hmac.py");
    let mut cmd = Command::new("python3");
    cmd.arg("-I").arg(&script);
    for e in module_table() {
        cmd.arg(crate_dir(e.package));
    }
    let output = match cmd.output() {
        Ok(output) => output,
        Err(e) => {
            eprintln!("python3 not run ({e}); skipping the independent-script check");
            return;
        }
    };
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let mut expected = String::new();
    for e in module_table() {
        expected.push_str(&format!("{} {}\n", e.package, hex(&e.hmac)));
    }
    let module = bouncycastle_fips_build::module_hmac(&embedded_table());
    expected.push_str(&format!("module-hmac {}\n", hex(&module)));
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
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
        ("default", cfg!(feature = "default")),
        ("fips-validated", cfg!(feature = "fips-validated")),
        ("integrity", cfg!(feature = "integrity")),
        ("sha2", cfg!(feature = "sha2")),
    ] {
        if on {
            expected.push(feature);
        }
    }
    assert_eq!(t.features, expected.as_slice());
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
