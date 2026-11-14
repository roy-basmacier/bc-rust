//! A worker whose permutation stops while the worker is alive -- as an AES key's does when a FIPS
//! 140-3 module enters its error state -- releases nothing more, including output that needs no
//! new block: keystream left over from an earlier call (CTR, CFB, CCM's payload) and a tag masked
//! with a block computed when the worker was made (GCM, GMAC).
//!
//! [`StoppableToy`]'s block methods and its `assert_operational` panic with different messages
//! once stopped, so each test can tell that it was the mode's `assert_operational` call that
//! refused, not a block call it happened to make. Every operation after the stop below makes no
//! block call, so without that call each would succeed.

mod common;

use bouncycastle_cipher::BlockCipherKey;
use bouncycastle_cipher::modes::{CCM_Packet, CFB, CTR, GCM, GCM_NONCE_LEN, GMAC, ModeNames};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::hazmat::{BlockPermutation, KeyExpansion};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial, NonceMacGenerationKey,
    NonceMacVerificationKey, SymmetricDecryptionKey, SymmetricEncryptionKey,
};
use bouncycastle_core::traits::{
    AEADCipherDecryptor, AEADCipherEncryptor, Algorithm, MACGenerator, MACVerifier,
    StreamCipherDecryptor, StreamCipherEncryptor, SymmetricCipherDecryptor,
    SymmetricCipherEncryptor,
};
use common::{TOY_LEN, Toy, toy_key};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};

/// One flag per test, since the tests of this binary run in parallel and a key builds its
/// permutation from key material alone, so the flag cannot be handed to it.
static STOPPED: [AtomicBool; 8] = [const { AtomicBool::new(false) }; 8];

const HOOK_PANIC: &str = "StoppableToy: assert_operational after stop";
const BLOCK_PANIC: &str = "StoppableToy: block call after stop";

/// [`Toy`], until `STOPPED[ID]` is set; then every method panics, as an AES permutation does in
/// the FIPS error state.
#[derive(Clone)]
struct StoppableToy<const ID: usize>(Toy);

impl<const ID: usize> StoppableToy<ID> {
    fn stop() {
        STOPPED[ID].store(true, Ordering::SeqCst);
    }

    fn block(&self) {
        if STOPPED[ID].load(Ordering::SeqCst) {
            panic!("{BLOCK_PANIC}");
        }
    }
}

impl<const ID: usize> Algorithm for StoppableToy<ID> {
    const ALG_NAME: &'static str = "StoppableToy";
    const MAX_SECURITY_STRENGTH: SecurityStrength = SecurityStrength::_128bit;
}

impl<const ID: usize> ModeNames for StoppableToy<ID> {
    const CBC_ALG_NAME: &'static str = "StoppableToy_CBC";
    const CCM_ALG_NAME: &'static str = "StoppableToy_CCM";
    const CFB_ALG_NAME: &'static str = "StoppableToy_CFB";
    const CFB8_ALG_NAME: &'static str = "StoppableToy_CFB8";
    const CMAC_ALG_NAME: &'static str = "StoppableToy_CMAC";
    const CTR_ALG_NAME: &'static str = "StoppableToy_CTR";
    const ECB_ALG_NAME: &'static str = "StoppableToy_ECB";
    const GCM_ALG_NAME: &'static str = "StoppableToy_GCM";
    const GMAC_ALG_NAME: &'static str = "StoppableToy_GMAC";
    const KW_ALG_NAME: &'static str = "StoppableToy_KW";
    const KWP_ALG_NAME: &'static str = "StoppableToy_KWP";
}

impl<const ID: usize> KeyExpansion<TOY_LEN> for StoppableToy<ID> {
    fn new(key: &KeyMaterial<TOY_LEN>) -> Result<Self, SymmetricCipherError> {
        Ok(Self(Toy::new(key)?))
    }
}

impl<const ID: usize> BlockPermutation<TOY_LEN> for StoppableToy<ID> {
    fn encrypt_block(&self, block: &mut [u8; TOY_LEN]) {
        self.block();
        self.0.encrypt_block(block)
    }
    fn decrypt_block(&self, block: &mut [u8; TOY_LEN]) {
        self.block();
        self.0.decrypt_block(block)
    }
    fn encrypt_2blocks(&self, blocks: &mut [[u8; TOY_LEN]; 2]) {
        self.block();
        self.0.encrypt_2blocks(blocks)
    }
    fn decrypt_2blocks(&self, blocks: &mut [[u8; TOY_LEN]; 2]) {
        self.block();
        self.0.decrypt_2blocks(blocks)
    }
    fn encrypt_4blocks(&self, blocks: &mut [[u8; TOY_LEN]; 4]) {
        self.block();
        self.0.encrypt_4blocks(blocks)
    }
    fn decrypt_4blocks(&self, blocks: &mut [[u8; TOY_LEN]; 4]) {
        self.block();
        self.0.decrypt_4blocks(blocks)
    }
    fn assert_operational(&self) {
        if STOPPED[ID].load(Ordering::SeqCst) {
            panic!("{HOOK_PANIC}");
        }
    }
}

/// Runs `f`, which must panic, and returns its panic message.
fn panic_message<R>(f: impl FnOnce() -> R) -> String {
    let payload = catch_unwind(AssertUnwindSafe(f)).err().expect("the stopped worker must panic");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

fn key<K: FromKeyMaterial<TOY_LEN>>() -> K {
    K::from_key_material(&toy_key()).expect("the toy key")
}

fn mac_key<K: FromKeyMaterial<TOY_LEN>>() -> K {
    let material =
        KeyMaterial::<TOY_LEN>::from_bytes_as_type(toy_key().ref_to_bytes(), KeyType::MACKey)
            .unwrap();
    K::from_key_material(&material).expect("the toy MAC key")
}

const GCM_NONCE: [u8; GCM_NONCE_LEN] = [0x5A; GCM_NONCE_LEN];
/// The CFB IV.
const IV: [u8; TOY_LEN] = [0x3C; TOY_LEN];

/// CTR: the 11 bytes of keystream left from the first call are not used after the stop.
#[test]
fn ctr_encryptor_uses_no_buffered_keystream_after_stop() {
    type P = StoppableToy<0>;
    let key: BlockCipherKey<P, CTR> = key();
    let mut enc = key.create_encryptor_nonce(&[0x3C; 12]);
    assert_eq!(enc.do_encrypt_inplace(&mut [0u8; 5]), Ok(5));
    P::stop();
    assert_eq!(panic_message(|| enc.do_encrypt_inplace(&mut [0u8; 3])), HOOK_PANIC);
}

/// CFB encryption: the open segment's keystream is not used after the stop.
#[test]
fn cfb_encryptor_uses_no_buffered_keystream_after_stop() {
    type P = StoppableToy<1>;
    let key: BlockCipherKey<P, CFB> = key();
    let mut enc = key.create_encryptor_nonce(&IV);
    assert_eq!(enc.do_encrypt_inplace(&mut [0u8; 5]), Ok(5));
    P::stop();
    assert_eq!(panic_message(|| enc.do_encrypt_inplace(&mut [0u8; 3])), HOOK_PANIC);
}

/// CFB decryption, whose byte path is separate code.
#[test]
fn cfb_decryptor_uses_no_buffered_keystream_after_stop() {
    type P = StoppableToy<2>;
    let key: BlockCipherKey<P, CFB> = key();
    let mut dec = key.create_decryptor(&IV);
    assert_eq!(dec.do_decrypt_inplace(&mut [0u8; 5]), Ok(5));
    P::stop();
    assert_eq!(panic_message(|| dec.do_decrypt_inplace(&mut [0u8; 3])), HOOK_PANIC);
}

/// GCM encryption: no tag after the stop, though `CIPH_K(J0)` was computed before it.
#[test]
fn gcm_encryptor_releases_no_tag_after_stop() {
    type P = StoppableToy<3>;
    let key: BlockCipherKey<P, GCM> = key();
    let mut enc = key.create_encryptor_nonce(&GCM_NONCE);
    enc.do_update_aad(b"header").unwrap();
    let mut out = [0u8; 16];
    assert_eq!(enc.do_encrypt_out(&[0u8; 16], &mut out), Ok(16));
    P::stop();
    assert_eq!(panic_message(|| enc.do_encrypt_final_detached()), HOOK_PANIC);
}

/// GCM decryption: no verdict after the stop.
#[test]
fn gcm_decryptor_gives_no_verdict_after_stop() {
    type P = StoppableToy<4>;
    let key: BlockCipherKey<P, GCM> = key();
    let mut ct = [0u8; 16];
    let tag = key.encrypt_detached_in_place_nonce(&GCM_NONCE, b"header", &mut ct).unwrap();
    let mut ct_and_tag = [0u8; 32];
    ct_and_tag[..16].copy_from_slice(&ct);
    ct_and_tag[16..].copy_from_slice(&tag);
    let mut dec = key.create_decryptor(&GCM_NONCE);
    dec.do_update_aad(b"header").unwrap();
    // The last 16 bytes are held back as the tag, so the first 16 are released here.
    let mut out = [0u8; 32];
    assert_eq!(dec.do_decrypt_out(&ct_and_tag, &mut out), Ok(16));
    P::stop();
    assert_eq!(panic_message(|| dec.do_decrypt_final()), HOOK_PANIC);
}

/// GMAC generation: no tag after the stop, though GMAC makes no block call after construction.
#[test]
fn gmac_generator_releases_no_tag_after_stop() {
    type P = StoppableToy<5>;
    let key: BlockCipherKey<P, GMAC> = mac_key();
    let mut generator = key.create_generator_nonce(&GCM_NONCE);
    generator.do_update(b"message");
    P::stop();
    assert_eq!(panic_message(|| generator.do_final()), HOOK_PANIC);
}

/// GMAC verification: no verdict after the stop.
#[test]
fn gmac_verifier_gives_no_verdict_after_stop() {
    type P = StoppableToy<6>;
    let key: BlockCipherKey<P, GMAC> = mac_key();
    let mut generator = key.create_generator_nonce(&GCM_NONCE);
    generator.do_update(b"message");
    let tag = generator.do_final();
    let mut verifier = key.create_verifier(&GCM_NONCE);
    verifier.do_update(b"message");
    P::stop();
    assert_eq!(panic_message(|| verifier.do_verify_final(&tag)), HOOK_PANIC);
}

/// CCM: the payload's leftover keystream is not used after the stop. The 8 bytes stay within one
/// CBC-MAC block, so the MAC makes no block call either.
#[test]
fn ccm_encryptor_uses_no_buffered_keystream_after_stop() {
    type P = StoppableToy<7>;
    let key: BlockCipherKey<P, CCM_Packet<12, 16, 16, 8>> = key();
    let mut enc = key.create_encryptor_nonce(&[0xA0; 12]);
    let mut out = [0u8; 5];
    assert_eq!(enc.do_encrypt_out(&[0u8; 5], &mut out), Ok(5));
    P::stop();
    assert_eq!(panic_message(|| enc.do_encrypt_out(&[0u8; 3], &mut [0u8; 3])), HOOK_PANIC);
}
