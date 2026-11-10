//! What every scenario file checks services with. Each scenario is its own test file, and so its
//! own process, because the self-test statuses are process-global.

#![allow(dead_code)]

use bouncycastle_aes::AES128Key;
use bouncycastle_cipher::modes::{Blocks, CBC, GCM};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use bouncycastle_core::traits::HashOneShot;
use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_256};
use std::panic::catch_unwind;

fn material() -> KeyMaterial<16> {
    KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap()
}

/// An AES-GCM key and an AES-CBC key from the public constructor: `Ok` or the error both gave.
pub fn aes_keys() -> Result<(), SymmetricCipherError> {
    let gcm = AES128Key::<GCM>::from_key_material(&material()).map(|_| ());
    let cbc = AES128Key::<CBC<Blocks>>::from_key_material(&material()).map(|_| ());
    assert_eq!(gcm, cbc, "every AES mode is gated alike");
    gcm
}

/// Whether each SHA-2 hash could be created: `[SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256]`.
pub fn sha2_hashes() -> [bool; 5] {
    [
        catch_unwind(SHA224::new).is_ok(),
        catch_unwind(SHA256::new).is_ok(),
        catch_unwind(SHA384::new).is_ok(),
        catch_unwind(|| SHA512::hash(b"abc")).is_ok(),
        catch_unwind(SHA512_256::default).is_ok(),
    ]
}
