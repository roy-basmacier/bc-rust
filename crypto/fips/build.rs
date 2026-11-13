//! Build script of `bouncycastle-fips`: the source pin of the module.
//!
//! Each boundary crate's own build script hands this one its directory, as the `links` metadata
//! `DEP_BOUNCYCASTLE_<NAME>_SRC_DIR`. This script reads every one, checks that they are exactly
//! the module boundary and that the boundary is closed under normal dependencies, computes each
//! crate's source HMAC and the module HMAC over the table of them, and writes the table and a
//! record of the toolchain into `$OUT_DIR/module_table.rs`, which `src/lib.rs` includes. With the
//! `fips-validated` feature, a module HMAC other than the published constant in
//! `src/expected_module_hmac.rs` fails the build.
//!
//! Each boundary crate also hands over its enabled cargo features, as
//! `DEP_BOUNCYCASTLE_<NAME>_FEATURES`; they go into the toolchain record. With the
//! `approved-only` feature, a non-approved one (`bouncycastle-ec`'s `sm2`) fails the build. Cargo
//! unifies features across the whole build, so this is how a dependency elsewhere in the program
//! that turns one on is caught; see crypto/fips/APPROVED_MODE.md.
//!
//! The work is done by `bouncycastle-fips-build` (`build-support/`), whose copy of
//! `bouncycastle-sha2` never has the `fips` feature (see `build-support/Cargo.toml`). Were it on,
//! SHA-512 would panic here, before any self-test, so a successful build with the `sha2` feature
//! is itself the check that it is off.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[path = "src/expected_module_hmac.rs"]
mod expected_module_hmac;

use bouncycastle_fips_build as source_pin;
use source_pin::{BoundaryCrate, CrateFeatures, Toolchain};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/expected_module_hmac.rs");

    let mut crates = Vec::new();
    let mut crate_features: Vec<CrateFeatures> = Vec::new();
    for (var, dir) in env::vars_os() {
        let Some(var) = var.to_str() else { continue };
        let Some(links) = var.strip_prefix("DEP_").and_then(|v| v.strip_suffix("_SRC_DIR")) else {
            continue;
        };
        if !links.starts_with("BOUNCYCASTLE_") {
            continue;
        }
        let dir = PathBuf::from(dir);
        // The boundary crate's own build script reruns on these, but its metadata need not
        // change when its sources do, so this script watches them too.
        for watched in ["src", "Cargo.toml", "build.rs"] {
            println!("cargo:rerun-if-changed={}", dir.join(watched).display());
        }
        let (manifest, files) = source_pin::read_crate(&dir).unwrap_or_else(|e| fail(&e));
        let features_var = format!("DEP_{links}_FEATURES");
        let features = env::var(&features_var).unwrap_or_else(|_| {
            fail(&format!(
                "`{}` set DEP_{links}_SRC_DIR but not {features_var}: its build script must also \
                 emit `cargo:features=`",
                manifest.name
            ))
        });
        crate_features.push((manifest.name.clone(), source_pin::parse_features(&features)));
        crates.push(BoundaryCrate { dep_links: links.to_string(), manifest, files });
    }

    let table = source_pin::build_table(&crates).unwrap_or_else(|e| fail(&e));
    let module = source_pin::module_hmac(&table);
    let expected = env::var_os("CARGO_FEATURE_FIPS_VALIDATED")
        .map(|_| &expected_module_hmac::EXPECTED_MODULE_HMAC);
    source_pin::check_expected(&module, expected).unwrap_or_else(|e| fail(&e));

    // In table order, which is bytewise by package name.
    crate_features.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    if env::var_os("CARGO_FEATURE_APPROVED_ONLY").is_some() {
        source_pin::check_approved_only(&crate_features).unwrap_or_else(|e| fail(&e));
    }

    let generated = source_pin::render(&table, &toolchain(crate_features));
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    fs::write(out.join("module_table.rs"), generated).expect("OUT_DIR is writable");
}

/// The toolchain record: `rustc -vV`'s version and host, Cargo's description of this build, and
/// the boundary crates' features.
fn toolchain(crate_features: Vec<CrateFeatures>) -> Toolchain {
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(&rustc)
        .arg("-vV")
        .output()
        .unwrap_or_else(|e| fail(&format!("running `{} -vV`: {e}", rustc.to_string_lossy())));
    let version = String::from_utf8_lossy(&output.stdout).into_owned();
    let host = version
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .unwrap_or_else(|| fail("`rustc -vV` printed no host"))
        .to_string();
    let mut features: Vec<String> = env::vars()
        .filter_map(|(k, _)| {
            k.strip_prefix("CARGO_FEATURE_").map(|f| f.to_ascii_lowercase().replace('_', "-"))
        })
        .collect();
    features.sort();
    Toolchain {
        rustc: version.lines().next().unwrap_or_default().to_string(),
        host,
        target: cargo_env("TARGET"),
        opt_level: cargo_env("OPT_LEVEL"),
        profile: cargo_env("PROFILE"),
        features,
        crate_features,
    }
}

/// A variable Cargo always sets for a build script.
fn cargo_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| fail(&format!("Cargo did not set {name}")))
}

/// Stops the build with `message`.
fn fail(message: &str) -> ! {
    panic!("bouncycastle-fips module source pin:\n{message}");
}
