//! The cryptographic algorithm self-tests (CASTs) themselves: each drives an algorithm crate
//! through its public API only, exactly as an application would, and compares the result with
//! the known answer. Each returns `true` on a match and `false` otherwise, including when a
//! service refuses to be created or reports an error.
//!
//! The services are created through the same gated constructors as everyone else's, so these run
//! only while the status of the algorithm under test is `Running` (see `driver::run`).
//!
//! The vectors are parameters rather than read from `crate::vectors` here, so that this crate's
//! failure-path test can run the same code on a corrupted copy of one.

#[cfg(feature = "aes")]
use crate::vectors::{CbcKat, GcmKat};
#[cfg(feature = "sha2")]
use crate::vectors::HashKat;

/// The SHA-256 CAST (FIPS 140-3 IG 10.3.A Resolution 2), which also covers SHA-224.
#[cfg(feature = "sha2")]
pub(crate) fn sha256(kat: &HashKat<3, 32>) -> bool {
    use bouncycastle_core::traits::Hash;

    let mut hash = bouncycastle_sha2::SHA256::new();
    hash.do_update(&kat.msg);
    let mut md = [0u8; 32];
    let written = hash.do_final_out(&mut md);
    written == md.len() && md == kat.md
}

/// The SHA-512 CAST (FIPS 140-3 IG 10.3.A Resolution 2), which also covers SHA-384,
/// SHA-512/224 and SHA-512/256.
#[cfg(feature = "sha2")]
pub(crate) fn sha512(kat: &HashKat<3, 64>) -> bool {
    use bouncycastle_core::traits::Hash;

    let mut hash = bouncycastle_sha2::SHA512::new();
    hash.do_update(&kat.msg);
    let mut md = [0u8; 64];
    let written = hash.do_final_out(&mut md);
    written == md.len() && md == kat.md
}

/// The AES CASTs (FIPS 140-3 IG 10.3.A Resolution 1): GCM encryption (1.a, and the forward cipher
/// of 1.c), GCM decryption (1.b) and CBC decryption (the inverse cipher of 1.c), all AES-128,
/// the smallest key length [10.29]. All three must pass.
#[cfg(feature = "aes")]
pub(crate) fn aes(gcm: &GcmKat, cbc: &CbcKat) -> bool {
    // Not short-circuited: every CAST runs, whatever an earlier one returned.
    let encrypt = aes_gcm_128_encrypt(gcm);
    let decrypt = aes_gcm_128_decrypt(gcm);
    let inverse = aes_cbc_128_decrypt(cbc);
    encrypt & decrypt & inverse
}

/// The vector's key as AES-128 key material.
#[cfg(feature = "aes")]
fn key_material(
    key: &[u8; 16],
) -> Option<bouncycastle_core::key_material::KeyMaterial128> {
    use bouncycastle_core::key_material::{KeyMaterial128, KeyType};

    KeyMaterial128::from_bytes_as_type(key, KeyType::SymmetricCipherKey).ok()
}

/// IG 10.3.A 1.a: authenticated encryption of the vector's plaintext under its key, IV and AAD
/// gives its ciphertext and tag. The IV is the vector's, through the `_nonce` form.
#[cfg(feature = "aes")]
fn aes_gcm_128_encrypt(kat: &GcmKat) -> bool {
    use bouncycastle_aes::AES128Key;
    use bouncycastle_cipher::modes::GCM;
    use bouncycastle_core::symmetric_key::{AeadEncryptionKey, FromKeyMaterial};

    let Some(material) = key_material(&kat.key) else { return false };
    let Ok(key) = AES128Key::<GCM>::from_key_material(&material) else { return false };
    let mut data = kat.pt;
    match key.encrypt_detached_in_place_nonce(&kat.iv, &kat.aad, &mut data) {
        Ok(tag) => data == kat.ct && tag == kat.tag,
        Err(_) => false,
    }
}

/// IG 10.3.A 1.b: authenticated decryption of the vector's ciphertext and tag accepts the tag and
/// gives its plaintext.
#[cfg(feature = "aes")]
fn aes_gcm_128_decrypt(kat: &GcmKat) -> bool {
    use bouncycastle_aes::AES128Key;
    use bouncycastle_cipher::modes::GCM;
    use bouncycastle_core::symmetric_key::{AeadDecryptionKey, FromKeyMaterial};

    let Some(material) = key_material(&kat.key) else { return false };
    let Ok(key) = AES128Key::<GCM>::from_key_material(&material) else { return false };
    let mut data = kat.ct;
    let accepted = key.decrypt_detached_in_place(&kat.iv, &kat.aad, &mut data, &kat.tag).is_ok();
    accepted && data == kat.pt
}

/// IG 10.3.A 1.c, the inverse cipher: CBC decryption of the vector's four ciphertext blocks gives
/// its plaintext. CBC decryption runs INVCIPHER() on every block.
#[cfg(feature = "aes")]
fn aes_cbc_128_decrypt(kat: &CbcKat) -> bool {
    use bouncycastle_aes::AES128Key;
    use bouncycastle_cipher::modes::{Blocks, CBC};
    use bouncycastle_core::symmetric_key::{BlockDecryptionKey, FromKeyMaterial};

    let Some(material) = key_material(&kat.key) else { return false };
    let Ok(key) = AES128Key::<CBC<Blocks>>::from_key_material(&material) else { return false };
    let mut data = kat.ct;
    match key.decrypt_inplace(&kat.iv, &mut data) {
        Ok(written) => written == data.len() && data == kat.pt,
        Err(_) => false,
    }
}
