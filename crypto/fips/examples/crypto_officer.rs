//! The application flow the FIPS 140-3 self-tests are designed for, from the point of view of the
//! crypto officer who builds and runs the application.
//!
//! 1. **Enable the features.** The application depends on `bouncycastle-fips` (default features
//!    `aes` and `sha2`), which turns on the `fips` feature of `bouncycastle-aes`,
//!    `bouncycastle-sha2` and `bouncycastle-core`: from then on every AES key and SHA-2 hash in the
//!    whole program is gated on the self-tests.
//! 2. **Power on.** The first thing `main` does is `power_on_self_tests()`; if it fails, the
//!    program stops.
//! 3. **Use the services**, here an AES-GCM key and a SHA-256 hash, as usual.
//! 4. **Re-run on demand** with `run_self_tests()` (the periodic self-test of a Security Level 1
//!    module, FIPS 140-3 IG 10.3.E); services stay usable while it runs. Restarting the program is
//!    the other way to re-run them.
//!
//! It first shows what an application that skips step 2 sees. This is a self-test prototype for
//! AES and SHA-2, not a validated module.
//!
//! Run it with `cargo run --example crypto_officer --manifest-path crypto/fips/Cargo.toml`.

use bouncycastle_aes::AES128Key;
use bouncycastle_cipher::modes::GCM;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_core::traits::Hash;
use bouncycastle_fips::{
    SELF_TESTED, SelfTestStatus, power_on_self_tests, run_self_tests, self_test_status,
};
use bouncycastle_rng::HashDRBG_SHA512;
use bouncycastle_sha2::SHA256;

fn main() {
    // --- Before power-on: what an application that skips it sees. ---------------------------
    print_statuses("before power-on");
    // An AES constructor, which returns a Result, refuses with an error...
    let material =
        KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey).unwrap();
    match AES128Key::<GCM>::from_key_material(&material) {
        Err(SymmetricCipherError::SelfTestNotPassed(status)) => {
            println!("  AES key refused: self-test {status:?}")
        }
        other => panic!("expected a refusal, got {:?}", other.map(|_| ())),
    }
    // ...and an infallible SHA-2 constructor panics. (A real application would not catch this;
    // the example does, to carry on.)
    std::panic::set_hook(Box::new(|info| {
        let message = info.payload().downcast_ref::<String>().map_or("", String::as_str);
        println!("  SHA-256 hash refused (panic): {message}");
    }));
    assert!(std::panic::catch_unwind(SHA256::new).is_err());
    let _ = std::panic::take_hook();

    // --- Step 2: power on. ------------------------------------------------------------------
    if let Err(e) = power_on_self_tests() {
        eprintln!("FIPS self-tests failed: {e:?}");
        std::process::exit(1);
    }
    print_statuses("after power-on");

    // --- Step 3: use the services. ----------------------------------------------------------
    // The DRBG is SHA-512 underneath, so it too can only be made after power-on.
    let mut rng = HashDRBG_SHA512::new_from_os();
    let mut key_material = KeyMaterial::<16>::from_rng(&mut rng).expect("RNG");
    key_material.set_key_type(KeyType::SymmetricCipherKey).expect("random bytes may become a key");
    let key = AES128Key::<GCM>::from_key_material(&key_material).expect("AES is available");
    let mut sealed = [0u8; 13 + 16];
    let (n, nonce) = key
        .encrypt_with_aad_out(&mut rng, b"header", b"hello, world!", &mut sealed)
        .expect("encryption");
    println!("  AES-GCM: sealed {n} bytes");

    let mut hash = SHA256::new();
    hash.do_update(b"hello, ");

    // --- Step 4: re-run on demand, with services in use. -----------------------------------
    run_self_tests().expect("the self-tests pass again");
    print_statuses("after an on-demand re-run");

    let mut opened = [0u8; 13];
    key.decrypt_with_aad_out(&nonce, b"header", &sealed, &mut opened).expect("decryption");
    assert_eq!(&opened, b"hello, world!");
    hash.do_update(b"world!");
    let digest = hash.do_final();
    println!("  key and hash made before the re-run still work: SHA-256 = {}", hex(&digest));
}

fn print_statuses(when: &str) {
    println!("Self-test status {when}:");
    for algorithm in SELF_TESTED {
        let status: SelfTestStatus = self_test_status(*algorithm);
        println!("  {}: {status:?}", algorithm.name());
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
