//! The binary under test, and the post-link tool's copies of it, which are the `cli` tests' own
//! (`cli/tests/common/fips_install.rs`; its `repo()` is this crate's parent directory too).

/// The approved-mode `bc-rust` as built, which refuses to run until the post-link tool has
/// written its binary HMAC.
pub const BC_RUST: &str = env!("CARGO_BIN_EXE_bc-rust");

#[path = "../../../cli/tests/common/fips_install.rs"]
pub mod fips_install;
