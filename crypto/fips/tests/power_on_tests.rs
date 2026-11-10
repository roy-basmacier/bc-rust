//! After [`power_on_self_tests`] has passed, the gated services can be created, a second call and
//! [`run_self_tests`] pass too, and services stay usable while a re-run is in progress. One test,
//! in a binary of its own, because the status table is process-wide.

use bouncycastle_fips::{
    SELF_TESTED, SelfTestStatus, power_on_self_tests, run_self_tests, self_test_status,
};
use std::sync::atomic::{AtomicBool, Ordering};

fn all_passed() -> bool {
    SELF_TESTED.iter().all(|&a| self_test_status(a) == SelfTestStatus::Passed)
}

/// Creates and uses one service of each self-tested algorithm; panics if any refuses.
fn use_services() {
    #[cfg(feature = "aes")]
    {
        use bouncycastle_aes::{AES128Key, AES256Key};
        use bouncycastle_cipher::modes::{Blocks, CBC, GCM};
        use bouncycastle_core::key_material::{KeyMaterial, KeyType};
        use bouncycastle_core::symmetric_key::{
            AeadDecryptionKey, AeadEncryptionKey, BlockDecryptionKey, BlockEncryptionKey,
            FromKeyMaterial,
        };

        let k16 = KeyMaterial::<16>::from_bytes_as_type(&[7; 16], KeyType::SymmetricCipherKey).unwrap();
        let gcm = AES128Key::<GCM>::from_key_material(&k16).expect("AES-128 GCM key");
        let mut data = *b"sixteen byte msg";
        let tag = gcm.encrypt_detached_in_place_nonce(&[1; 12], b"aad", &mut data).unwrap();
        gcm.decrypt_detached_in_place(&[1; 12], b"aad", &mut data, &tag).unwrap();
        assert_eq!(&data, b"sixteen byte msg");

        let k32 = KeyMaterial::<32>::from_bytes_as_type(&[9; 32], KeyType::SymmetricCipherKey).unwrap();
        let cbc = AES256Key::<CBC<Blocks>>::from_key_material(&k32).expect("AES-256 CBC key");
        let mut block = [0x5a; 16];
        cbc.encrypt_inplace_nonce(&[2; 16], &mut block).unwrap();
        cbc.decrypt_inplace(&[2; 16], &mut block).unwrap();
        assert_eq!(block, [0x5a; 16]);
    }
    #[cfg(feature = "sha2")]
    {
        use bouncycastle_core::traits::HashOneShot;
        use bouncycastle_sha2::{SHA224, SHA256, SHA384, SHA512, SHA512_256};

        assert_eq!(SHA256::hash_out(b"abc", &mut [0; 32]), 32);
        assert_eq!(SHA224::hash_out(b"abc", &mut [0; 28]), 28);
        assert_eq!(SHA512::hash_out(b"abc", &mut [0; 64]), 64);
        assert_eq!(SHA384::hash_out(b"abc", &mut [0; 48]), 48);
        assert_eq!(SHA512_256::hash_out(b"abc", &mut [0; 32]), 32);
    }
}

#[test]
fn power_on_then_rerun_keeps_services_usable() {
    assert_eq!(power_on_self_tests(), Ok(()));
    assert!(all_passed());
    use_services();

    // A second power-on call is a no-op that reports the stored result.
    assert_eq!(power_on_self_tests(), Ok(()));
    assert!(all_passed());

    // On-demand re-runs, while another thread keeps creating and using services: none of them
    // may be refused (the status passes through `Running`, which the gates admit).
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        let user = s.spawn(|| {
            let mut uses = 0u32;
            while !stop.load(Ordering::Relaxed) || uses == 0 {
                use_services();
                uses += 1;
            }
            uses
        });
        for _ in 0..50 {
            assert_eq!(run_self_tests(), Ok(()));
        }
        stop.store(true, Ordering::Relaxed);
        assert!(user.join().expect("no service was refused during the re-runs") > 0);
    });
    assert!(all_passed());
    use_services();
}
