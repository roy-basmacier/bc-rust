//! Build script for the FIPS module-integrity source pin.
//!
//! This script hashes nothing. It exists so that Cargo's `links` key lets it hand this crate's
//! manifest directory to the crate that combines the module (`bouncycastle-fips`), which reads
//! it as `DEP_BOUNCYCASTLE_SHA3_SRC_DIR` in its own build script and does the HMAC there. The
//! `rerun-if-changed` lines make Cargo re-run the combining script whenever a pinned file
//! changes: `src/`, `Cargo.toml` and `build.rs`.

fn main() {
    // `cargo:src_dir=...` is exported to dependents as `DEP_BOUNCYCASTLE_SHA3_SRC_DIR`.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("Cargo always sets CARGO_MANIFEST_DIR");
    println!("cargo:src_dir={manifest_dir}");

    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");
}
