//! This crate defines the core traits and types used by the rest of the bc-rust.test library.

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
