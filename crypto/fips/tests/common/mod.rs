//! What every scenario file checks services with. Each scenario is its own test file, and so its
//! own process, because the self-test statuses are process-global. Every scenario runs with any
//! combination of the `aes` and `sha2` features; the checks cover the enabled ones.

#![allow(dead_code)]

#[cfg(feature = "aes")]
use bouncycastle_aes::AES128Key;
#[cfg(feature = "aes")]
use bouncycastle_cipher::modes::{Blocks, CBC, GCM};
#[cfg(feature = "aes")]
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::fips::SelfTestStatus;
#[cfg(feature = "aes")]
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
#[cfg(feature = "aes")]
use bouncycastle_core::symmetric_key::FromKeyMaterial;
#[cfg(feature = "sha2")]
use bouncycastle_core::traits::HashOneShot;
#[cfg(feature = "sha2")]
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_256};
#[cfg(feature = "sha2")]
use std::panic::catch_unwind;

/// An AES-GCM key and an AES-CBC key from the public constructor: `Ok` or the error both gave.
#[cfg(feature = "aes")]
pub fn aes_keys() -> Result<(), SymmetricCipherError> {
    let material =
        KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
    let gcm = AES128Key::<GCM>::from_key_material(&material).map(|_| ());
    let cbc = AES128Key::<CBC<Blocks>>::from_key_material(&material).map(|_| ());
    assert_eq!(gcm, cbc, "every AES mode is gated alike");
    gcm
}

/// Whether each SHA-2 hash could be created: `[SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256]`.
#[cfg(feature = "sha2")]
pub fn sha2_hashes() -> [bool; 5] {
    [
        catch_unwind(SHA224::new).is_ok(),
        catch_unwind(SHA256::new).is_ok(),
        catch_unwind(SHA384::new).is_ok(),
        catch_unwind(|| SHA512::hash(b"abc")).is_ok(),
        catch_unwind(SHA512_256::default).is_ok(),
    ]
}

/// Checks every enabled algorithm's services: all created when `refused` is `None`; all refused
/// otherwise, an AES key with `SelfTestNotPassed` of that status.
pub fn assert_services(refused: Option<SelfTestStatus>) {
    #[cfg(feature = "aes")]
    assert_eq!(
        aes_keys(),
        refused.map_or(Ok(()), |s| Err(SymmetricCipherError::SelfTestNotPassed(s)))
    );
    #[cfg(feature = "sha2")]
    assert_eq!(sha2_hashes(), [refused.is_none(); 5]);
    let _ = refused;
}
