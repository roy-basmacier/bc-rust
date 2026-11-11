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
//! The KAT drives the same key API an application would (`FromKeyMaterial`, the `_nonce` and
//! `_out` one-shots), the same mode code (`bouncycastle-cipher`'s GCM and CBC) and the same AES
//! rounds, but over [`KatAES128`], a private permutation that forwards to [`AES128Internal`]
//! without the gates. So no key of the public types exists before the self-test has passed, and a
//! gate that refuses (the module entering the error state mid-run) fails the KAT's answer rather
//! than panicking out of it.
//!
//! # The status
//!
//! [`STATUS`] is private to this crate: only [`self_test`] can move it to `Passed`, and only by
//! producing the known answers. A failure puts the whole module in the error state through
//! `bouncycastle_core::fips::enter_error_state`, which every self-tested crate's gate reads, so
//! that one algorithm's failure stops all of them at once. The error state is permanent for the
//! life of the process (the decision recorded in the `bouncycastle-fips` docs).
//!
//! AES keys can be created only while the status reads `Passed`: not during the first run, and
//! not after a failure. A re-run reads `Passed` while it runs (IG 10.3.E Resolution 5 lets a
//! repeated CAST run in the background), so keys stay available through one.

use bouncycastle_cipher::BlockCipherKey;
use bouncycastle_cipher::modes::ModeNames;
use bouncycastle_cipher::modes::{Blocks, CBC, GCM};
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::fips::{
    SelfTestError, SelfTestStatus, SelfTestStatusCell, SelfTestedAlgorithm,
};
use bouncycastle_core::hazmat::{BlockPermutation, KeyExpansion};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::{
    AeadDecryptionKey, AeadEncryptionKey, BlockDecryptionKey, FromKeyMaterial,
};
use bouncycastle_core::traits::Algorithm;

use crate::bitslice::Block;
use crate::hazmat::AES128Internal;

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
/// [`SymmetricCipherError::SelfTestNotPassed`]. It may be run again at any time; once it has
/// passed, keys stay available while it runs again.
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

/// Where the AES self-test stands. AES keys can be created only in [`SelfTestStatus::Passed`],
/// which a re-run of a passed self-test keeps reading while it runs. [`SelfTestStatus::Failed`]
/// once any self-tested algorithm has failed, not only AES.
pub fn self_test_status() -> SelfTestStatus {
    STATUS.get()
}

/// The gate every AES key constructor passes through (the `KeyExpansion` impls in
/// `hazmat::ecb`): `Passed` only.
pub(crate) fn require_passed() -> Result<(), SymmetricCipherError> {
    match STATUS.get() {
        SelfTestStatus::Passed => Ok(()),
        other => Err(SymmetricCipherError::SelfTestNotPassed(other)),
    }
}

/// [`self_test`] over the given answers, so that the unit test can check a wrong answer fails.
fn run(kat: &Kat) -> Result<(), SelfTestError> {
    // The three CASTs in the order of the bouncycastle-fips table; `&&` stops at the first
    // failure, which is all the result reports.
    STATUS.run(|| gcm_encrypt_matches(kat) && gcm_decrypt_matches(kat) && cbc_decrypt_matches(kat))
}

/// AES-128 for the KAT's keys only: [`AES128Internal`] without the gates in its `KeyExpansion`
/// impl, so that the self-test can build keys before AES is available. Each method forwards to
/// the same AES-128 code every `AES128Key` runs.
#[derive(Clone)]
struct KatAES128(AES128Internal);

impl Algorithm for KatAES128 {
    const ALG_NAME: &'static str = AES128Internal::ALG_NAME;
    const MAX_SECURITY_STRENGTH: SecurityStrength = AES128Internal::MAX_SECURITY_STRENGTH;
}

impl ModeNames for KatAES128 {
    const CBC_ALG_NAME: &'static str = AES128Internal::CBC_ALG_NAME;
    const CCM_ALG_NAME: &'static str = AES128Internal::CCM_ALG_NAME;
    const CFB_ALG_NAME: &'static str = AES128Internal::CFB_ALG_NAME;
    const CFB8_ALG_NAME: &'static str = AES128Internal::CFB8_ALG_NAME;
    const CMAC_ALG_NAME: &'static str = AES128Internal::CMAC_ALG_NAME;
    const CTR_ALG_NAME: &'static str = AES128Internal::CTR_ALG_NAME;
    const ECB_ALG_NAME: &'static str = AES128Internal::ECB_ALG_NAME;
    const GCM_ALG_NAME: &'static str = AES128Internal::GCM_ALG_NAME;
    const GMAC_ALG_NAME: &'static str = AES128Internal::GMAC_ALG_NAME;
    const KW_ALG_NAME: &'static str = AES128Internal::KW_ALG_NAME;
    const KWP_ALG_NAME: &'static str = AES128Internal::KWP_ALG_NAME;
}

impl KeyExpansion<16> for KatAES128 {
    fn new(key: &KeyMaterial<16>) -> Result<Self, SymmetricCipherError> {
        // The key checks and expansion, without `require_passed`.
        AES128Internal::new(key).map(Self)
    }
}

impl BlockPermutation<16> for KatAES128 {
    fn encrypt_block(&self, block: &mut Block) {
        self.0.encrypt_block(block)
    }
    fn decrypt_block(&self, block: &mut Block) {
        self.0.decrypt_block(block)
    }
    fn encrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        self.0.encrypt_2blocks(blocks)
    }
    fn decrypt_2blocks(&self, blocks: &mut [Block; 2]) {
        self.0.decrypt_2blocks(blocks)
    }
    fn encrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        self.0.encrypt_4blocks(blocks)
    }
    fn decrypt_4blocks(&self, blocks: &mut [Block; 4]) {
        self.0.decrypt_4blocks(blocks)
    }
}

/// A KAT key for the mode `M` from 16 bytes of the KAT, through the same `FromKeyMaterial`
/// checks as an `AES128Key<M>`; `None` if it is refused, which fails the KAT.
fn key<M>(bytes: &[u8; 16]) -> Option<BlockCipherKey<KatAES128, M>>
where
    M: bouncycastle_core::hazmat::Mode<KatAES128>,
{
    let material =
        KeyMaterial::<16>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey).ok()?;
    BlockCipherKey::<KatAES128, M>::from_key_material(&material).ok()
}

/// IG 10.3.A 1.a: authenticated encryption, which gives both the ciphertext and the tag.
fn gcm_encrypt_matches(kat: &Kat) -> bool {
    let Some(key) = key::<GCM>(&kat.gcm_key) else { return false };
    let mut ct = [0u8; 16];
    match key.encrypt_detached_nonce_out(&kat.gcm_iv, &kat.gcm_aad, &kat.gcm_pt, &mut ct) {
        Ok((written, tag)) => written == ct.len() && ct == kat.gcm_ct && tag == kat.gcm_tag,
        Err(_) => false,
    }
}

/// IG 10.3.A 1.b: authenticated decryption of the same vector, the tag accepted and the
/// plaintext recovered.
fn gcm_decrypt_matches(kat: &Kat) -> bool {
    let Some(key) = key::<GCM>(&kat.gcm_key) else { return false };
    let mut pt = [0u8; 16];
    match key.decrypt_detached_out(&kat.gcm_iv, &kat.gcm_aad, &kat.gcm_ct, &kat.gcm_tag, &mut pt) {
        Ok(written) => written == pt.len() && pt == kat.gcm_pt,
        Err(_) => false,
    }
}

/// IG 10.3.A 1.c: the inverse cipher, which GCM never uses.
fn cbc_decrypt_matches(kat: &Kat) -> bool {
    let Some(key) = key::<CBC<Blocks>>(&kat.cbc_key) else { return false };
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
    extern crate std;

    use super::*;
    use crate::AES128Key;
    use bouncycastle_core::traits::SymmetricCipherEncryptor;
    use std::panic::{AssertUnwindSafe, catch_unwind};

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

        // During the first run no AES key can be made, while the KAT's own keys can.
        assert_eq!(
            STATUS.run(|| {
                gcm_key_result().err()
                    == Some(SymmetricCipherError::SelfTestNotPassed(SelfTestStatus::Running))
                    && gcm_encrypt_matches(&KAT)
                    && gcm_decrypt_matches(&KAT)
                    && cbc_decrypt_matches(&KAT)
            }),
            Ok(())
        );
        assert_eq!(self_test_status(), SelfTestStatus::Passed);
        assert!(gcm_key_result().is_ok());
        // A re-run from Passed runs again and passes, and keys stay available while it runs.
        assert_eq!(STATUS.run(|| gcm_key_result().is_ok()), Ok(()));
        assert_eq!(self_test(), Ok(()));
        assert_eq!(self_test_status(), SelfTestStatus::Passed);

        // Each check rejects a flipped bit in every byte of every value it compares or consumes,
        // so no byte of a vector is dead weight.
        let fields: [(&str, fn(&mut Kat) -> &mut [u8]); 10] = [
            ("gcm_key", |k| &mut k.gcm_key),
            ("gcm_iv", |k| &mut k.gcm_iv),
            ("gcm_pt", |k| &mut k.gcm_pt),
            ("gcm_aad", |k| &mut k.gcm_aad),
            ("gcm_ct", |k| &mut k.gcm_ct),
            ("gcm_tag", |k| &mut k.gcm_tag),
            ("cbc_key", |k| &mut k.cbc_key),
            ("cbc_iv", |k| &mut k.cbc_iv),
            ("cbc_ct", |k| &mut k.cbc_ct),
            ("cbc_pt", |k| &mut k.cbc_pt),
        ];
        for (name, field) in fields {
            for i in 0..field(&mut KAT.clone()).len() {
                let mut bad = KAT;
                field(&mut bad)[i] ^= 1;
                let results = [
                    gcm_encrypt_matches(&bad),
                    gcm_decrypt_matches(&bad),
                    cbc_decrypt_matches(&bad),
                ];
                // Every GCM value is consumed or compared by both GCM checks.
                let expected = if name.starts_with("gcm") {
                    [false, false, true]
                } else {
                    [true, true, false]
                };
                assert_eq!(results, expected, "{name}[{i}]");
            }
        }
        assert!(
            gcm_encrypt_matches(&KAT) && gcm_decrypt_matches(&KAT) && cbc_decrypt_matches(&KAT)
        );

        // A key, and a worker from it, made while AES was available.
        let held = gcm_key_result().unwrap();
        let mut worker = held.create_encryptor_nonce(&KAT.gcm_iv);
        let mut out = [0u8; 16];
        assert!(worker.do_encrypt_out(&KAT.gcm_pt, &mut out).is_ok());

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

        // The key and worker that already existed produce nothing more (decision 5 of
        // APPROACHES.md): every block call panics.
        let encrypt = catch_unwind(AssertUnwindSafe(|| {
            held.encrypt_detached_nonce_out(&KAT.gcm_iv, &KAT.gcm_aad, &KAT.gcm_pt, &mut out)
        }));
        assert!(encrypt.is_err());
        assert!(
            catch_unwind(AssertUnwindSafe(|| worker.do_encrypt_out(&KAT.gcm_pt, &mut out)))
                .is_err()
        );
        // The KAT's own keys are not gated, so a KAT run in the error state reports its answer
        // rather than panicking.
        assert!(
            gcm_encrypt_matches(&KAT) && gcm_decrypt_matches(&KAT) && cbc_decrypt_matches(&KAT)
        );
    }
}
