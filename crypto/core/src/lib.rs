//! This crate defines the core traits and types used by the rest of the bc-rust.test library.
//!
//! # Cargo features
//!
//! * `std` (default): the allocating (`Vec`-returning) one-shot APIs.
//! * `fips` (off by default): the `fips` module -- the FIPS 140-3 self-test status types, the
//!   `SelfTestStatusCell` an algorithm crate runs its known-answer test through, and the
//!   process-wide module error state every self-tested algorithm's gate reads -- plus the
//!   `SelfTestNotPassed` variants of `SymmetricCipherError` and `SuspendableError`. The algorithm
//!   crates' own `fips` features turn it on; see `bouncycastle-fips`, a self-test prototype for
//!   AES and SHA-2, not a validated module.

// todo -- this is the goal, but first need to remove all the Vec in favour of compile-time array sizing.
// #![no_std]

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

pub mod direction;
pub mod errors;
#[cfg(feature = "fips")]
pub mod fips;
pub mod hazmat;
pub mod kdf_params;
pub mod kem_key;
pub mod key_material;
mod provided;
pub mod security_strength;
pub mod signature_key;
pub mod symmetric_key;
pub mod traits;
