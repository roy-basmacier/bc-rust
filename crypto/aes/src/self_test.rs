//! The FIPS 140-3 cryptographic algorithm self-test (CAST) for AES, and the status that gates
//! every AES key on it. Only compiled with the `fips` cargo feature.
//!
//! The requirements and the choice of vectors, with their sources, are in the `bouncycastle-fips`
//! crate docs ("Requirements", "Known-answer vectors"); this module implements the AES rows of
//! that table and nothing else:
//!
//! * AES-GCM-128 encryption and decryption of CAVP `gcmEncryptExtIV128.rsp`
//!   `[Keylen = 128] [IVlen = 96] [PTlen = 128] [AADlen = 128] [Taglen = 128]`, `Count = 0`
//!   (FIPS 140-3 IG 10.3.A Resolution 1.a, 1.b, 1.d(i), and the forward cipher of 1.c);
//! * AES-CBC-128 decryption of SP 800-38A Appendix F.2.2 "CBC-AES128.Decrypt" (the inverse
//!   cipher of 1.c).
//!
//! The KAT drives the same public API an application would (`AES128Key<GCM>`,
//! `AES128Key<CBC<Blocks>>`, `FromKeyMaterial`, the `_nonce` and `_out` one-shots), so the keys it
//! builds pass through the same gate as every other key.
//!
//! # The status
//!
//! [`STATUS`] is private to this crate: only [`self_test`] can move it to `Passed`, and only by
//! producing the known answers. A failure puts the whole module in the error state through
//! `bouncycastle_core::fips::enter_error_state`, which every self-tested crate's gate reads, so
//! that one algorithm's failure stops all of them at once. The error state is permanent for the
//! life of the process (the decision recorded in the `bouncycastle-fips` docs).
//!
//! While a run is in progress the status is `Running`, and the gate admits `Running` as it admits
//! `Passed`, because the KAT's own keys go through it and `no_std` gives no way to tell the
//! KAT's thread from any other. So for the length of a run *every* thread may create AES keys:
//! during a re-run that is the background periodic self-test IG 10.3.E Resolution 5 allows;
//! during the first run it is a key made before the self-test has passed, which the
//! `bouncycastle-fips` docs rule out by telling the application to run the power-on self-tests
//! before creating any service.

use bouncycastle_cipher::modes::{Blocks, CBC, GCM};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::fips::{
    SelfTestError, SelfTestStatus, SelfTestStatusCell, SelfTestedAlgorithm,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{
    AeadDecryptionKey, AeadEncryptionKey, BlockDecryptionKey, FromKeyMaterial,
};

use crate::AES128Key;

/// The AES self-test status. Only [`run`] runs it, so only the AES KAT can make it `Passed`.
static STATUS: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::AES);

/// One set of the AES known-answer values; see the module docs for their sources.
#[derive(Clone, Copy)]
struct Kat {
    gcm_key: [u8; 16],
    gcm_iv: [u8; 12],
    gcm_pt: [u8; 16],
    gcm_aad: [u8; 16],
    gcm_ct: [u8; 16],
    gcm_tag: [u8; 16],
    cbc_key: [u8; 16],
    cbc_iv: [u8; 16],
    cbc_ct: [u8; 64],
    cbc_pt: [u8; 64],
}

/// The known answers [`self_test`] checks.
const KAT: Kat = Kat {
    // CAVP gcmEncryptExtIV128.rsp, [Keylen = 128] [IVlen = 96] [PTlen = 128] [AADlen = 128]
    // [Taglen = 128], Count = 0: Key, IV, PT, AAD, CT, Tag.
    gcm_key: [
        0xc9, 0x39, 0xcc, 0x13, 0x39, 0x7c, 0x1d, 0x37, //
        0xde, 0x6a, 0xe0, 0xe1, 0xcb, 0x7c, 0x42, 0x3c,
    ],
    gcm_iv: [
        0xb3, 0xd8, 0xcc, 0x01, 0x7c, 0xbb, 0x89, 0xb3, //
        0x9e, 0x0f, 0x67, 0xe2,
    ],
    gcm_pt: [
        0xc3, 0xb3, 0xc4, 0x1f, 0x11, 0x3a, 0x31, 0xb7, //
        0x3d, 0x9a, 0x5c, 0xd4, 0x32, 0x10, 0x30, 0x69,
    ],
    gcm_aad: [
        0x24, 0x82, 0x56, 0x02, 0xbd, 0x12, 0xa9, 0x84, //
        0xe0, 0x09, 0x2d, 0x3e, 0x44, 0x8e, 0xda, 0x5f,
    ],
    gcm_ct: [
        0x93, 0xfe, 0x7d, 0x9e, 0x9b, 0xfd, 0x10, 0x34, //
        0x8a, 0x56, 0x06, 0xe5, 0xca, 0xfa, 0x73, 0x54,
    ],
    gcm_tag: [
        0x00, 0x32, 0xa1, 0xdc, 0x85, 0xf1, 0xc9, 0x78, //
        0x69, 0x25, 0xa2, 0xe7, 0x1d, 0x82, 0x72, 0xdd,
    ],
    // SP 800-38A Appendix F.2.2, CBC-AES128.Decrypt: Key, IV, Ciphertext blocks 1-4,
    // Plaintext blocks 1-4.
    cbc_key: [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, //
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ],
    cbc_iv: [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, //
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ],
    cbc_ct: [
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, //
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d, //
        0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, //
        0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2, //
        0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, //
        0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16, //
        0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, //
        0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7,
    ],
    cbc_pt: [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, //
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, //
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, //
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, //
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, //
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, //
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, //
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    ],
};

/// Runs the AES self-test: AES-GCM-128 encryption and decryption and AES-CBC-128 decryption
/// against compiled-in known answers. Until it has passed, every AES key constructor returns
/// [`SymmetricCipherError::SelfTestNotPassed`]. It may be run again at any time; keys stay
/// available while it runs.
///
/// An application normally calls this through `bouncycastle_fips::power_on_self_tests()`, which
/// also runs the other algorithms' self-tests and puts all of them in the error state if any
/// fails.
///
/// # Errors
/// * [`SelfTestError::KnownAnswerMismatch`] if any answer differs. The module is then in the
///   error state, and AES in [`SelfTestStatus::Failed`], until the program restarts.
/// * [`SelfTestError::NotPassed`] with [`SelfTestStatus::Failed`], without running anything, if
///   the module is already in the error state.
///
/// A call made while another thread is running the AES self-test waits for that run and
/// reports its result.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_aes::{self_test, self_test_status, AES128Key};
/// use bouncycastle_cipher::modes::GCM;
/// use bouncycastle_core::fips::SelfTestStatus;
/// use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
/// use bouncycastle_core::symmetric_key::FromKeyMaterial;
///
/// self_test().expect("the AES self-test passes");
/// assert_eq!(self_test_status(), SelfTestStatus::Passed);
///
/// let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
///     .expect("a 16-byte symmetric cipher key");
/// let key = AES128Key::<GCM>::from_key_material(&material).expect("AES is available");
/// ```
pub fn self_test() -> Result<(), SelfTestError> {
    run(&KAT)
}

/// Where the AES self-test stands. AES keys can be created in [`SelfTestStatus::Passed`] and,
/// while a run is in progress, [`SelfTestStatus::Running`]. [`SelfTestStatus::Failed`] once any
/// self-tested algorithm has failed, not only AES.
pub fn self_test_status() -> SelfTestStatus {
    STATUS.get()
}

/// The gate every AES key constructor passes through, from the key checks in
/// `AESInternal::validate`.
pub(crate) fn require_passed() -> Result<(), SymmetricCipherError> {
    match STATUS.get() {
        // Running: the KAT's own keys come through here (see the module docs).
        SelfTestStatus::Passed | SelfTestStatus::Running => Ok(()),
        other => Err(SymmetricCipherError::SelfTestNotPassed(other)),
    }
}

/// [`self_test`] over the given answers, so that the unit test can check a wrong answer fails.
fn run(kat: &Kat) -> Result<(), SelfTestError> {
    // The three CASTs in the order of the bouncycastle-fips table; `&&` stops at the first
    // failure, which is all the result reports.
    STATUS.run(|| gcm_encrypt_matches(kat) && gcm_decrypt_matches(kat) && cbc_decrypt_matches(kat))
}

/// A key (an `AES128Key<M>`) from 16 bytes of the KAT, through the public constructor; `None`
/// if it is refused, which fails the KAT.
fn key<K: FromKeyMaterial<16>>(bytes: &[u8; 16]) -> Option<K> {
    let material =
        KeyMaterial::<16>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey).ok()?;
    K::from_key_material(&material).ok()
}

/// IG 10.3.A 1.a: authenticated encryption, which gives both the ciphertext and the tag.
fn gcm_encrypt_matches(kat: &Kat) -> bool {
    let Some(key) = key::<AES128Key<GCM>>(&kat.gcm_key) else { return false };
    let mut ct = [0u8; 16];
    match key.encrypt_detached_nonce_out(&kat.gcm_iv, &kat.gcm_aad, &kat.gcm_pt, &mut ct) {
        Ok((written, tag)) => written == ct.len() && ct == kat.gcm_ct && tag == kat.gcm_tag,
        Err(_) => false,
    }
}

/// IG 10.3.A 1.b: authenticated decryption of the same vector, the tag accepted and the
/// plaintext recovered.
fn gcm_decrypt_matches(kat: &Kat) -> bool {
    let Some(key) = key::<AES128Key<GCM>>(&kat.gcm_key) else { return false };
    let mut pt = [0u8; 16];
    match key.decrypt_detached_out(&kat.gcm_iv, &kat.gcm_aad, &kat.gcm_ct, &kat.gcm_tag, &mut pt) {
        Ok(written) => written == pt.len() && pt == kat.gcm_pt,
        Err(_) => false,
    }
}

/// IG 10.3.A 1.c: the inverse cipher, which GCM never uses.
fn cbc_decrypt_matches(kat: &Kat) -> bool {
    let Some(key) = key::<AES128Key<CBC<Blocks>>>(&kat.cbc_key) else { return false };
    let mut data = kat.cbc_ct;
    match key.decrypt_inplace(&kat.cbc_iv, &mut data) {
        Ok(written) => written == data.len() && data == kat.cbc_pt,
        Err(_) => false,
    }
}

// One test, because STATUS is process-global and every unit test of the crate shares the process:
// it walks NotRun -> Passed -> (each wrong answer detected) -> Failed, which is permanent. No
// other unit test in the crate creates an AES key.
#[cfg(test)]
mod tests {
    use super::*;

    fn gcm_key_result() -> Result<AES128Key<GCM>, SymmetricCipherError> {
        let material =
            KeyMaterial::<16>::from_bytes_as_type(&KAT.gcm_key, KeyType::SymmetricCipherKey)
                .unwrap();
        AES128Key::<GCM>::from_key_material(&material)
    }

    #[test]
    fn passes_then_a_wrong_answer_fails_for_good() {
        assert_eq!(self_test_status(), SelfTestStatus::NotRun);
        assert_eq!(
            gcm_key_result().err(),
            Some(SymmetricCipherError::SelfTestNotPassed(SelfTestStatus::NotRun))
        );

        assert_eq!(self_test(), Ok(()));
        assert_eq!(self_test_status(), SelfTestStatus::Passed);
        assert!(gcm_key_result().is_ok());
        // A re-run from Passed runs again and passes.
        assert_eq!(self_test(), Ok(()));
        assert_eq!(self_test_status(), SelfTestStatus::Passed);

        // Each check rejects a single flipped bit in each value it compares or consumes.
        let flips: [fn(&mut Kat); 10] = [
            |k| k.gcm_key[0] ^= 1,
            |k| k.gcm_iv[0] ^= 1,
            |k| k.gcm_pt[0] ^= 1,
            |k| k.gcm_aad[0] ^= 1,
            |k| k.gcm_ct[15] ^= 1,
            |k| k.gcm_tag[15] ^= 1,
            |k| k.cbc_key[0] ^= 1,
            |k| k.cbc_iv[0] ^= 1,
            |k| k.cbc_ct[63] ^= 1,
            |k| k.cbc_pt[63] ^= 1,
        ];
        for (i, flip) in flips.iter().enumerate() {
            let mut bad = KAT;
            flip(&mut bad);
            let results =
                [gcm_encrypt_matches(&bad), gcm_decrypt_matches(&bad), cbc_decrypt_matches(&bad)];
            // Every GCM value is consumed or compared by both GCM checks.
            let expected = if i < 6 { [false, false, true] } else { [true, true, false] };
            assert_eq!(results, expected, "flip {i}");
        }
        assert!(
            gcm_encrypt_matches(&KAT) && gcm_decrypt_matches(&KAT) && cbc_decrypt_matches(&KAT)
        );

        // A run with a wrong answer fails and leaves AES in the error state for good.
        // Only the last of the three CASTs is wrong, so the run must not stop at the first.
        let mut bad = KAT;
        bad.cbc_pt[0] ^= 0x80;
        assert_eq!(run(&bad), Err(SelfTestError::KnownAnswerMismatch(SelfTestedAlgorithm::AES)));
        assert_eq!(self_test_status(), SelfTestStatus::Failed);
        assert_eq!(
            gcm_key_result().err(),
            Some(SymmetricCipherError::SelfTestNotPassed(SelfTestStatus::Failed))
        );
        assert_eq!(
            self_test(),
            Err(SelfTestError::NotPassed(SelfTestedAlgorithm::AES, SelfTestStatus::Failed))
        );
        assert_eq!(self_test_status(), SelfTestStatus::Failed);
    }
}
