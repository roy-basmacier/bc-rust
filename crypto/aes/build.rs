//! Build script for the FIPS module-integrity source pin.
//!
//! This script hashes nothing. It exists so that Cargo's `links` key lets it hand this crate's
//! manifest directory to the crate that combines the module (`bouncycastle-fips`), which reads
//! it as `DEP_BOUNCYCASTLE_AES_SRC_DIR` in its own build script and does the HMAC there. The
//! `rerun-if-changed` lines make Cargo re-run the combining script whenever a pinned file
//! changes: `src/`, `Cargo.toml` and `build.rs`.
//!
//! It also hands over this crate's enabled cargo features, which the combining crate writes into
//! its toolchain record and, in a FIPS-approved build, checks for non-approved ones.

fn main() {
    // `cargo:src_dir=...` is exported to dependents as `DEP_BOUNCYCASTLE_AES_SRC_DIR`.
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("Cargo always sets CARGO_MANIFEST_DIR");
    println!("cargo:src_dir={manifest_dir}");

    // `cargo:features=...` is exported as `DEP_BOUNCYCASTLE_AES_FEATURES`: this crate's cargo
    // features as Cargo unified them for this build, lower case with `-`, sorted and
    // comma-separated, which `bouncycastle-fips` records and checks.
    let mut features: Vec<String> = std::env::vars()
        .filter_map(|(var, _)| {
            var.strip_prefix("CARGO_FEATURE_").map(|f| f.to_ascii_lowercase().replace('_', "-"))
        })
        .collect();
    features.sort();
    println!("cargo:features={}", features.join(","));

    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");
}
