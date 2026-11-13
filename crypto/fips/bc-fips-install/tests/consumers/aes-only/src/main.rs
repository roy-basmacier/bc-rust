//! One of the two programs of `two_consumers_tests.rs`: powers on bouncycastle-fips, with the
//! software integrity test, prints the module info, and uses AES-GCM and nothing else of the
//! module. Exits 0 only if all of that succeeds.

use std::process::ExitCode;

use bouncycastle_aes::AES128Key;
use bouncycastle_cipher::modes::GCM;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{AeadDecryptionKey, AeadEncryptionKey, FromKeyMaterial};
use bouncycastle_fips::{module_info, power_on_self_tests};

/// Printed after power-on passes. The test flips one of its bytes in the file: it is data the
/// program reads only after the integrity test has run.
const PASSED: &str = "aes-only consumer: power-on passed";

fn main() -> ExitCode {
    if let Err(e) = power_on_self_tests() {
        eprintln!("aes-only consumer: power-on failed: {e:?}");
        return ExitCode::FAILURE;
    }
    println!("{PASSED}");
    print!("{}", module_info().expect("HMAC-SHA-512 passed at power-on"));

    // A round trip under a fixed key and nonce: a test program, never a pattern to copy.
    let material = KeyMaterial::<16>::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
        .expect("16 bytes fit");
    let key = AES128Key::<GCM>::from_key_material(&material).expect("AES has passed");
    let nonce = [7u8; 12];
    let mut sealed = [0u8; 5 + 16];
    key.encrypt_with_aad_nonce_out(&nonce, b"aad", b"hello", &mut sealed).expect("encrypt");
    let mut opened = [0u8; 5];
    key.decrypt_with_aad_out(&nonce, b"aad", &sealed, &mut opened).expect("decrypt");
    assert_eq!(&opened, b"hello");
    println!("aes-gcm round trip ok");
    ExitCode::SUCCESS
}
