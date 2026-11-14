#![forbid(unsafe_code)]
#![forbid(missing_docs)]
//! The `bouncycastle` umbrella crate restricted to the crates of the FIPS module boundary (and
//! `hex`), for the approved-mode `bc-rust` in `cli-fips`.
//!
//! The full umbrella crate also re-exports `bouncycastle-sm2`, `-sm3`, `-sm4`, `-aria`,
//! `-camellia`, `-chacha20`, `-poly1305`, `-blake2`, `-blake3`, ML-KEM and ML-DSA, none of which is
//! in the boundary. Here they do not exist, so a command that names one fails to compile instead
//! of being offered by an approved build. `bouncycastle-ec` is re-exported for the curve markers
//! the ECDSA and ECC CDH commands are generic over; it is taken without its default `sm2`
//! feature, so the SM2 curve is not compiled, and `bouncycastle-fips`'s build script refuses the
//! build if anything else in the graph turns that feature on.

pub use bouncycastle_aes as aes;
pub use bouncycastle_ascon as ascon;
pub use bouncycastle_cipher as cipher;
pub use bouncycastle_concatkdf as concatkdf;
pub use bouncycastle_core as core;
pub use bouncycastle_ec as ec;
pub use bouncycastle_eccdh as eccdh;
pub use bouncycastle_ecdsa as ecdsa;
pub use bouncycastle_hex as hex;
pub use bouncycastle_hkdf as hkdf;
pub use bouncycastle_hmac as hmac;
pub use bouncycastle_rng as rng;
pub use bouncycastle_sha2 as sha2;
pub use bouncycastle_sha3 as sha3;
pub use bouncycastle_x963kdf as x963kdf;
