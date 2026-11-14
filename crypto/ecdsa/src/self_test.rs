//! The FIPS 140-3 cryptographic algorithm self-test (CAST) for ECDSA, the status that gates every
//! ECDSA key pair, signer and verifier on it, and the pair-wise consistency test on every
//! generated key pair. Only compiled with the `fips` cargo feature.
//!
//! The requirements and the choice of vectors, with their sources, are in the `bouncycastle-fips`
//! crate docs ("Requirements", "Known-answer vectors"); this module implements the ECDSA rows of
//! that table and nothing else. FIPS 140-3 IG 10.3.A Resolution 10 asks for a CAST of signature
//! generation and of verification, with the per-message secret `k` fixed for a KAT ("For a KAT,
//! this requires the randomization parameter be fixed"), and Note10 for a separate CAST of
//! deterministic signature generation, since both are offered. So three known answers, all
//! ECDSA-P256-SHA256 from the NIST ACVP-Server `gen-val/json-files` (FIPS 186-5 revision):
//!
//! * signature generation with a random `k`: `ECDSA-SigGen-FIPS186-5`, `tgId` 14, `tcId` 131,
//!   with its `k` from `internalProjection.json`;
//! * deterministic signature generation: `DetECDSA-SigGen-FIPS186-5`, `tgId` 12, `tcId` 111;
//! * verification: `ECDSA-SigVer-FIPS186-5`, `tgId` 8, `tcId` 54, `testPassed: true`.
//!
//! One curve covers all seven: Note16 ("a CAST shall be performed at a minimum on any one approved
//! modulus or curve size that is supported by the module") and Note17 ("on any one of the
//! implemented NIST-recommended curves ... in each of the implemented two types of fields"; every
//! curve here is over a prime field). P-256 is the smallest the module supports ([10.29]).
//!
//! The KAT drives the same signer and verifier types an application gets, through their
//! `SignatureSigner` and `SignatureVerifier` impls, but creates them with crate-private
//! constructors that skip the creation gate, and gives the random-`k` signer its `k` directly
//! rather than from an RNG. So no signer or verifier of the public API exists before the
//! self-test has passed. The messages are hashed with SHA-256, whose own gate refuses until the
//! SHA-256 self-test has passed: [`self_test`] checks that first.
//!
//! # The status
//!
//! [`STATUS`] is private to this crate: only [`self_test`] can move it to `Passed`, and only by
//! producing the known answers. A failure, of the self-test or of a pair-wise consistency test,
//! puts the whole module in the error state through `bouncycastle_core::fips::enter_error_state`.
//!
//! Key pairs, signers and verifiers can be created only while the status reads `Passed`; a signer
//! or verifier that already exists refuses to finish once the module is in the error state.
//!
//! # The pair-wise consistency test
//!
//! ISO/IEC 19790:2012 7.10.3.3 [10.35], as IG 10.3.A Additional Comment 1 quotes it: "a pair-wise
//! consistency test shall be performed for every generated public and private key pair", and the
//! IG asks it be "consistent with the intended use of the keys" when that is known. A key pair
//! from [`crate::keys::keygen`] is an ECDSA pair, so the test signs a fixed message with the new
//! private key (deterministic `k`, so no RNG is drawn from) and verifies the signature with the
//! new public key, before `keygen` returns the pair.

use bouncycastle_core::errors::SignatureError;
use bouncycastle_core::fips::{
    SelfTestError, SelfTestStatus, SelfTestStatusCell, SelfTestedAlgorithm, enter_error_state,
    error_state,
};
use bouncycastle_core::traits::{
    SignaturePrivateKey, SignaturePublicKey, SignatureSigner, SignatureVerifier,
};
use bouncycastle_ec::P256;
use bouncycastle_ec::curve::{Curve, private_scalar_from_be_bytes};
use bouncycastle_sha2::SHA256;

use crate::ecdsa::{
    ECDSASigner, ECDSAVerifier, ECDetDSASigner, EcdsaHash, check_hash_fits, e_from_hash,
    finish_hash, sign_with_k, verify_final,
};
use crate::keys::{ECDSAPrivateKey, ECDSAPublicKey};
use crate::rfc6979;

/// The ECDSA self-test status. Only [`run`] runs it, so only the ECDSA KAT can make it `Passed`.
static STATUS: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::ECDSA);

/// A signature generated with a given `k`.
#[derive(Clone, Copy)]
struct SigGenKat {
    d: [u8; 32],
    k: [u8; 32],
    msg: [u8; 128],
    sig: [u8; 64],
}

/// A deterministic signature.
#[derive(Clone, Copy)]
struct DetSigGenKat {
    d: [u8; 32],
    msg: [u8; 128],
    sig: [u8; 64],
}

/// A signature that verifies.
#[derive(Clone, Copy)]
struct SigVerKat {
    qx: [u8; 32],
    qy: [u8; 32],
    msg: [u8; 128],
    sig: [u8; 64],
}

/// ACVP `ECDSA-SigGen-FIPS186-5`, `tgId` 14 (P-256, SHA2-256), `tcId` 131: `d`, `k`, `message`,
/// `r || s`.
const SIGGEN: SigGenKat = SigGenKat {
    d: [
        0xa8, 0x8c, 0x7a, 0x12, 0xe6, 0xcd, 0x3e, 0xc1, //
        0x46, 0x7e, 0x96, 0xdf, 0xd2, 0x30, 0xd6, 0x54, //
        0xf7, 0x86, 0xfa, 0x72, 0xef, 0xa4, 0x3c, 0xa9, //
        0x63, 0x2b, 0x8d, 0xe5, 0xbd, 0x24, 0x5c, 0xc3,
    ],
    k: [
        0x48, 0xfa, 0x4b, 0x5e, 0x8b, 0xb9, 0x17, 0x97, //
        0x3c, 0x25, 0xa0, 0xad, 0xa4, 0x1f, 0x33, 0x82, //
        0x1f, 0x68, 0xb6, 0x50, 0x56, 0x8e, 0xb1, 0x44, //
        0xbe, 0x59, 0x60, 0xda, 0x1c, 0x75, 0x6a, 0xba,
    ],
    msg: [
        0x4f, 0x1b, 0x2a, 0xba, 0x5d, 0x95, 0x2e, 0x43, //
        0x4d, 0x26, 0xb9, 0x01, 0x5c, 0xb1, 0x7f, 0xb4, //
        0xff, 0xeb, 0xd0, 0xcc, 0x7a, 0x94, 0x20, 0xf1, //
        0x91, 0x5d, 0xb0, 0xa2, 0x98, 0xfd, 0x92, 0x50, //
        0x92, 0xcd, 0x66, 0xc3, 0xd6, 0x55, 0x6b, 0x30, //
        0xdc, 0xa4, 0xc1, 0x55, 0x92, 0x47, 0xdc, 0xb2, //
        0x2d, 0xbf, 0xd7, 0x8f, 0xc9, 0xff, 0xb4, 0xb5, //
        0xdf, 0x01, 0x10, 0xc8, 0xc5, 0x0b, 0xe7, 0x0f, //
        0x7b, 0x4c, 0x48, 0x39, 0x64, 0xad, 0x74, 0xd6, //
        0x7b, 0x99, 0xcc, 0x2f, 0x4a, 0x00, 0xf2, 0xa1, //
        0x25, 0x75, 0xae, 0x80, 0x0c, 0x0e, 0x9c, 0xda, //
        0x06, 0xcb, 0x71, 0x4a, 0x2c, 0xe6, 0xca, 0xa9, //
        0xd3, 0x0b, 0x55, 0x85, 0xe8, 0x02, 0x28, 0xdc, //
        0x3f, 0xe3, 0x9d, 0x66, 0xda, 0xbb, 0x80, 0x50, //
        0x4b, 0x3c, 0xaf, 0x90, 0xb4, 0xbb, 0x1b, 0xd1, //
        0xd2, 0x30, 0x3b, 0x8d, 0x89, 0xb3, 0xba, 0x18,
    ],
    sig: [
        0x64, 0x2a, 0x2f, 0xea, 0x3f, 0xe1, 0xea, 0x23, //
        0xab, 0x69, 0x9e, 0x5e, 0xd5, 0x56, 0x8d, 0x08, //
        0x33, 0xb4, 0xce, 0xf5, 0x96, 0x76, 0x46, 0x28, //
        0xaf, 0x9c, 0x47, 0xe2, 0x3c, 0x0b, 0x40, 0x0b, //
        0x3b, 0xe6, 0x82, 0xf2, 0x65, 0xae, 0x3d, 0xb0, //
        0xd5, 0x95, 0x12, 0x8f, 0x35, 0xaf, 0x41, 0xbc, //
        0x63, 0xcb, 0x0f, 0xc4, 0xd0, 0x67, 0xce, 0xfd, //
        0xec, 0x95, 0x68, 0x7a, 0xc2, 0xb3, 0xb5, 0xaf,
    ],
};

/// ACVP `DetECDSA-SigGen-FIPS186-5`, `tgId` 12 (P-256, SHA2-256), `tcId` 111: `d`, `message`,
/// `r || s`.
const DET_SIGGEN: DetSigGenKat = DetSigGenKat {
    d: [
        0xf6, 0x9a, 0x77, 0xb5, 0x6c, 0xaf, 0x23, 0x43, //
        0x68, 0xdf, 0x0d, 0x69, 0xf9, 0x6c, 0xf0, 0x4f, //
        0x43, 0x5f, 0x96, 0x7f, 0xf3, 0x9e, 0x28, 0x37, //
        0x1c, 0x6f, 0xe7, 0xa8, 0x14, 0x6b, 0x86, 0x5d,
    ],
    msg: [
        0x0c, 0xce, 0x12, 0xcc, 0xf2, 0xf1, 0x7b, 0xda, //
        0x8c, 0x11, 0x92, 0xf4, 0x55, 0x7a, 0x84, 0x10, //
        0xfd, 0x65, 0xfa, 0x8d, 0xca, 0x17, 0x4b, 0xb5, //
        0x7c, 0x9b, 0x2a, 0x1e, 0x29, 0x59, 0x7b, 0x6a, //
        0x44, 0xad, 0x05, 0x5d, 0x23, 0xab, 0xa4, 0x92, //
        0x8b, 0x72, 0xc6, 0x7a, 0x3e, 0x00, 0x93, 0xbc, //
        0x36, 0x86, 0xf6, 0x8d, 0xe6, 0xce, 0xe2, 0x12, //
        0x2c, 0x35, 0x77, 0x96, 0x84, 0x07, 0x4c, 0x53, //
        0x8c, 0xd1, 0xf5, 0xe8, 0x36, 0xba, 0x96, 0xf4, //
        0xf3, 0xe0, 0x5c, 0xac, 0x29, 0x77, 0xeb, 0xf3, //
        0x32, 0xae, 0x25, 0x76, 0xac, 0x08, 0x3c, 0x3a, //
        0x96, 0x3c, 0x18, 0xba, 0x9f, 0x98, 0x72, 0xe7, //
        0x1e, 0xf0, 0xf2, 0x29, 0xf4, 0xc6, 0x6a, 0x5c, //
        0xfc, 0xa3, 0x95, 0x22, 0x08, 0x78, 0x4e, 0x44, //
        0xef, 0x17, 0x2f, 0xf7, 0xee, 0x6b, 0x43, 0x7e, //
        0xfb, 0xe9, 0xaf, 0xa1, 0x16, 0x93, 0x97, 0x89,
    ],
    sig: [
        0x46, 0xae, 0xb4, 0x00, 0x43, 0xea, 0xf1, 0x6d, //
        0xf4, 0x63, 0x89, 0x4f, 0xc8, 0xd3, 0x16, 0x18, //
        0x37, 0x93, 0x0a, 0xfb, 0xd6, 0x21, 0x51, 0x9f, //
        0x51, 0xd0, 0x2d, 0x5a, 0x28, 0x01, 0x2d, 0xf6, //
        0x62, 0x55, 0xbe, 0x75, 0x5f, 0xcf, 0x2e, 0x6d, //
        0xd4, 0xb7, 0x18, 0x71, 0x58, 0xdc, 0x62, 0x53, //
        0xdd, 0xe3, 0x6e, 0x81, 0xdc, 0x11, 0x4e, 0x09, //
        0xe6, 0xf6, 0xed, 0x77, 0x8a, 0xcb, 0x21, 0x28,
    ],
};

/// ACVP `ECDSA-SigVer-FIPS186-5`, `tgId` 8 (P-256, SHA2-256), `tcId` 54 (`testPassed: true`):
/// `qx`, `qy`, `message`, `r || s`.
const SIGVER: SigVerKat = SigVerKat {
    qx: [
        0x93, 0x16, 0x7a, 0x15, 0x67, 0xdf, 0xa2, 0x11, //
        0xc1, 0x08, 0x29, 0x91, 0x91, 0x13, 0xea, 0xb9, //
        0x25, 0x91, 0xce, 0x6d, 0x01, 0xca, 0x9d, 0x75, //
        0x28, 0x3a, 0x66, 0x20, 0x6c, 0xd5, 0xca, 0x0d,
    ],
    qy: [
        0xd6, 0x47, 0xda, 0x83, 0xc2, 0x55, 0x92, 0xc0, //
        0x33, 0x32, 0xdc, 0x2a, 0x05, 0x7e, 0x1e, 0xf6, //
        0x1e, 0xae, 0xd7, 0x7f, 0xa4, 0x13, 0x27, 0x5b, //
        0xee, 0xe0, 0x34, 0x51, 0x2f, 0x31, 0xc9, 0x7d,
    ],
    msg: [
        0xcf, 0x98, 0x38, 0xb2, 0xe0, 0xe9, 0x45, 0x84, //
        0xcf, 0xb7, 0xed, 0xb8, 0x6a, 0xf4, 0xea, 0x09, //
        0x45, 0x8f, 0xfd, 0xd8, 0x1c, 0x02, 0x4e, 0x54, //
        0xfe, 0x78, 0x99, 0xba, 0xbb, 0x52, 0x97, 0x77, //
        0x23, 0xfc, 0x7f, 0x04, 0x11, 0x85, 0x28, 0xa7, //
        0xfb, 0x83, 0x0a, 0xf2, 0x05, 0x78, 0x61, 0x68, //
        0x45, 0x8d, 0x85, 0xba, 0xcc, 0x0d, 0xf7, 0x4f, //
        0x9d, 0x49, 0x38, 0x09, 0x90, 0x41, 0x07, 0xd9, //
        0xaa, 0xf2, 0x30, 0xcc, 0x5c, 0x2f, 0x97, 0xca, //
        0x49, 0xc9, 0xe5, 0x14, 0x51, 0xeb, 0x9d, 0x36, //
        0x81, 0x29, 0xfb, 0xc3, 0x2c, 0x41, 0x6a, 0x53, //
        0xc9, 0xdc, 0x33, 0xa8, 0x50, 0x71, 0x70, 0xe1, //
        0x97, 0x5c, 0xde, 0xa2, 0xae, 0xe3, 0x92, 0x40, //
        0x51, 0xb2, 0xfb, 0x36, 0x60, 0xc0, 0x2b, 0xd1, //
        0xf1, 0x88, 0x7a, 0x01, 0x22, 0x9f, 0x36, 0x88, //
        0x95, 0xdf, 0xb0, 0xef, 0x6f, 0xe8, 0x7d, 0x44,
    ],
    sig: [
        0x8f, 0x3c, 0x09, 0x1e, 0xec, 0x05, 0xde, 0xec, //
        0xa8, 0x1c, 0xd5, 0xe4, 0x2a, 0xa7, 0x36, 0x57, //
        0x36, 0x01, 0x1c, 0x41, 0xfd, 0xda, 0x8b, 0x4c, //
        0x99, 0x73, 0x96, 0x26, 0x45, 0xae, 0x59, 0xbf, //
        0x59, 0x7b, 0x95, 0x06, 0x8c, 0x79, 0xb5, 0xc6, //
        0xef, 0x76, 0x3e, 0xea, 0x19, 0x83, 0x6a, 0x3a, //
        0x64, 0x78, 0x10, 0x1b, 0x3f, 0xea, 0x1c, 0x08, //
        0x11, 0x84, 0x5f, 0x73, 0x66, 0x38, 0x7d, 0x65,
    ],
};

/// The message the pair-wise consistency test signs; any message would do.
const PCT_MESSAGE: &[u8] = b"bouncycastle-ecdsa pair-wise consistency test";

/// Runs the ECDSA self-test: P-256 with SHA-256, signature generation with a fixed `k`,
/// deterministic signature generation, and verification, each against a compiled-in known
/// answer. Until it has passed, key generation, `create_signer`, `create_signer_deterministic` and
/// `create_verifier` return `SignatureError::SelfTestNotPassed`, on every curve and hash, and
/// `derive_pk` panics. It may be run again at any time; once it has passed, ECDSA stays available
/// while it runs again.
///
/// An application normally calls this through `bouncycastle_fips::power_on_self_tests()`, which
/// runs the SHA-2 self-tests first.
///
/// # Errors
/// * [`SelfTestError::NotPassed`] naming [`SelfTestedAlgorithm::SHA256`], without running
///   anything or changing any status, if the SHA-256 self-test has not passed yet: the KAT hashes
///   with SHA-256.
/// * [`SelfTestError::KnownAnswerMismatch`] if a signature differs or does not verify. The module
///   is then in the error state until the program restarts.
/// * [`SelfTestError::NotPassed`] with [`SelfTestStatus::Failed`], without running anything, if
///   the module is already in the error state.
///
/// A call made while another thread is running this self-test waits for that run and reports its
/// result.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_core::fips::SelfTestStatus;
/// use bouncycastle_ecdsa::{self_test, self_test_status};
///
/// bouncycastle_sha2::self_test().expect("the SHA-2 self-tests pass");
/// self_test().expect("the ECDSA self-test passes");
/// assert_eq!(self_test_status(), SelfTestStatus::Passed);
/// ```
pub fn self_test() -> Result<(), SelfTestError> {
    run(&SIGGEN, &DET_SIGGEN, &SIGVER)
}

/// Where the ECDSA self-test stands. ECDSA can be used only in [`SelfTestStatus::Passed`], which
/// a re-run keeps reading while it runs; [`SelfTestStatus::Failed`] once any self-tested
/// algorithm has failed.
pub fn self_test_status() -> SelfTestStatus {
    STATUS.get()
}

/// The gate in `keygen`, `create_signer`, `create_signer_deterministic` and `create_verifier`.
pub(crate) fn require_passed() -> Result<(), SignatureError> {
    match STATUS.get() {
        SelfTestStatus::Passed => Ok(()),
        other => Err(SignatureError::SelfTestNotPassed(other)),
    }
}

/// The gate in `derive_pk`, which returns no `Result`. Panics unless the self-test has passed.
pub(crate) fn assert_passed() {
    if let Err(e) = require_passed() {
        panic!("ECDSA cannot be used: {e:?} (run bouncycastle_fips::power_on_self_tests() first)");
    }
}

/// The gate in the signers' `do_final` and the verifier's `do_verify_final`, so that signers and
/// verifiers that exist when the module enters the error state produce nothing more. The
/// self-test's own signers and verifier pass through it too, which is harmless: the module error
/// state already stops the self-test from running.
pub(crate) fn require_operational() -> Result<(), SignatureError> {
    match error_state() {
        None => Ok(()),
        Some(_) => Err(SignatureError::SelfTestNotPassed(SelfTestStatus::Failed)),
    }
}

/// The pair-wise consistency test on a key pair `keygen` has just generated: `Ok` if a
/// deterministic signature of [`PCT_MESSAGE`] under `sk` verifies under `pk`. Otherwise the
/// module enters the error state, naming ECDSA, and the pair must not be used.
pub(crate) fn pairwise_consistency_test<C: Curve, H: EcdsaHash>(
    pk: &ECDSAPublicKey<C, H>,
    sk: &ECDSAPrivateKey<C, H>,
) -> Result<(), SignatureError> {
    if signs_and_verifies(pk, sk, PCT_MESSAGE) {
        Ok(())
    } else {
        enter_error_state(SelfTestedAlgorithm::ECDSA);
        Err(SignatureError::ConsistencyCheckFailed)
    }
}

/// Whether a deterministic signature of `msg` under `sk` verifies under `pk`. Through the same
/// steps the signers and the verifier take, but without their gates, so that a failure of the
/// module elsewhere does not read as an inconsistent pair.
fn signs_and_verifies<C: Curve, H: EcdsaHash>(
    pk: &ECDSAPublicKey<C, H>,
    sk: &ECDSAPrivateKey<C, H>,
    msg: &[u8],
) -> bool {
    const { check_hash_fits::<C, H>() };
    let mut hash = H::default();
    hash.do_update(msg);
    let h = finish_hash(hash);
    let h = &h[..H::OUTPUT_LEN];
    let k = rfc6979::generate_k::<C, H>(sk.scalar(), h);
    let Some(sig) = sign_with_k::<C, H>(sk, &e_from_hash::<C, H>(h), k) else {
        return false;
    };
    let mut hash = H::default();
    hash.do_update(msg);
    verify_final::<C, H>(hash, pk, sig.as_ref()).is_ok()
}

/// [`self_test`] over the given answers, so that the unit test can check a wrong answer fails.
fn run(siggen: &SigGenKat, det: &DetSigGenKat, sigver: &SigVerKat) -> Result<(), SelfTestError> {
    // In the error state the cell refuses by itself; otherwise SHA-256 must have passed, or the
    // KAT's hashes would panic inside the run and enter the error state for a test never run.
    if error_state().is_none() {
        let sha256 = bouncycastle_sha2::sha256_self_test_status();
        if sha256 != SelfTestStatus::Passed {
            return Err(SelfTestError::NotPassed(SelfTestedAlgorithm::SHA256, sha256));
        }
    }
    STATUS.run(|| siggen_matches(siggen) && det_siggen_matches(det) && sigver_accepts(sigver))
}

type P256Sk = ECDSAPrivateKey<P256, SHA256>;
type P256Pk = ECDSAPublicKey<P256, SHA256>;

/// FIPS 186-5 Section 6.4.1 with the given `k`: the signature of `kat.msg` is `kat.sig`.
fn siggen_matches(kat: &SigGenKat) -> bool {
    let Ok(sk) = P256Sk::from_bytes(&kat.d) else {
        return false;
    };
    let Some(k) = private_scalar_from_be_bytes::<P256>(&kat.k) else {
        return false;
    };
    let mut signer = ECDSASigner::with_k(&sk, k);
    signer.do_update(&kat.msg);
    matches!(signer.do_final(), Ok(sig) if sig == kat.sig)
}

/// FIPS 186-5 Section 6.4.1 with `k` from Appendix A.3.3: the signature of `kat.msg` is
/// `kat.sig`.
fn det_siggen_matches(kat: &DetSigGenKat) -> bool {
    let Ok(sk) = P256Sk::from_bytes(&kat.d) else {
        return false;
    };
    let mut signer = ECDetDSASigner::new_ungated(&sk);
    signer.do_update(&kat.msg);
    matches!(signer.do_final(), Ok(sig) if sig == kat.sig)
}

/// FIPS 186-5 Section 6.4.2: `kat.sig` verifies over `kat.msg` under the uncompressed public key
/// `04 || qx || qy`.
fn sigver_accepts(kat: &SigVerKat) -> bool {
    let mut encoded = [0x04u8; 65];
    encoded[1..33].copy_from_slice(&kat.qx);
    encoded[33..].copy_from_slice(&kat.qy);
    let Ok(pk) = P256Pk::from_bytes(&encoded) else {
        return false;
    };
    let mut verifier = ECDSAVerifier::new_ungated(&pk);
    verifier.do_update(&kat.msg);
    verifier.do_verify_final(&kat.sig).is_ok()
}

// The status and the error state are process-global, and every unit test of the crate shares the
// process, so the self-test is walked in one test: NotRun -> Passed -> (each wrong answer
// detected) -> a wrong answer -> Failed, which is permanent. A failed pair-wise consistency test
// also enters the error state, so it runs in a process of its own: the first test re-runs this
// test binary for the second, which is `#[ignore]`d so that it runs only that way. No other unit
// test of the crate makes a key pair, a signer or a verifier.
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::keys::keygen;
    use bouncycastle_core::signature_key::{DeterministicSigningKey, SigningKey, VerifyingKey};
    use bouncycastle_ec::P384;
    use bouncycastle_rng::HashDRBG_SHA512;
    use bouncycastle_sha2::SHA384;
    use std::panic::catch_unwind;
    use std::string::String;

    /// What [`services`] gives when every service is refused with `status`.
    fn refused(status: SelfTestStatus) -> [Result<(), SignatureError>; 3] {
        core::array::from_fn(|_| Err(SignatureError::SelfTestNotPassed(status)))
    }

    /// What [`services`] gives when every service is available.
    fn available() -> [Result<(), SignatureError>; 3] {
        core::array::from_fn(|_| Ok(()))
    }

    /// Whether each ECDSA service of `sk` / `pk` can be created: `[create_signer,
    /// create_signer_deterministic, create_verifier]`, or the error each gave.
    fn services(
        sk: &P256Sk,
        pk: &P256Pk,
        rng: &mut HashDRBG_SHA512,
    ) -> [Result<(), SignatureError>; 3] {
        [
            sk.create_signer(rng, None).map(|_| ()),
            sk.create_signer_deterministic(None).map(|_| ()),
            pk.create_verifier(None).map(|_| ()),
        ]
    }

    #[test]
    fn passes_then_a_wrong_answer_fails_for_good() {
        let sk = P256Sk::from_bytes(&SIGGEN.d).unwrap();
        let pk = P256Pk::from_bytes(&{
            let mut q = [0x04u8; 65];
            q[1..33].copy_from_slice(&SIGVER.qx);
            q[33..].copy_from_slice(&SIGVER.qy);
            q
        })
        .unwrap();
        let not_run = Some(SignatureError::SelfTestNotPassed(SelfTestStatus::NotRun));

        // SHA-256 first: until it has passed, the self-test runs nothing and changes nothing.
        assert_eq!(
            self_test(),
            Err(SelfTestError::NotPassed(SelfTestedAlgorithm::SHA256, SelfTestStatus::NotRun))
        );
        assert_eq!(self_test_status(), SelfTestStatus::NotRun);
        assert_eq!(error_state(), None);
        bouncycastle_sha2::self_test().unwrap();
        // The DRBG hashes with SHA-512, so it can be made only now.
        let mut drbg = HashDRBG_SHA512::new_from_os();
        let drbg = &mut drbg;

        // Before ECDSA's own self-test, nothing of ECDSA can be made, on any curve.
        assert_eq!(services(&sk, &pk, drbg), refused(SelfTestStatus::NotRun));
        assert_eq!(keygen::<P256, SHA256>(drbg).err(), not_run);
        assert_eq!(keygen::<P384, SHA384>(drbg).err(), not_run);
        assert!(catch_unwind(|| crate::keys_common::DerivePublicKey::derive_pk(&sk)).is_err());

        // During the first run nothing can be made either, while the KAT's own signers can.
        assert_eq!(
            STATUS.run(|| {
                services(&sk, &pk, drbg) == refused(SelfTestStatus::Running)
                    && siggen_matches(&SIGGEN)
                    && det_siggen_matches(&DET_SIGGEN)
                    && sigver_accepts(&SIGVER)
            }),
            Ok(())
        );
        assert_eq!(self_test_status(), SelfTestStatus::Passed);
        assert_eq!(services(&sk, &pk, drbg), available());
        // A re-run from Passed runs again, passes, and keeps ECDSA available while it runs.
        assert_eq!(STATUS.run(|| services(&sk, &pk, drbg) == available()), Ok(()));
        assert_eq!(self_test(), Ok(()));

        // Key generation works on every curve, through the pair-wise consistency test, and the
        // test accepts the pairs it is given and rejects a mismatched one.
        let (pk1, sk1) = keygen::<P256, SHA256>(drbg).unwrap();
        let (pk2, sk2) = keygen::<P384, SHA384>(drbg).unwrap();
        assert!(signs_and_verifies(&pk1, &sk1, PCT_MESSAGE));
        assert!(signs_and_verifies(&pk2, &sk2, PCT_MESSAGE));
        assert!(!signs_and_verifies(&pk, &sk1, PCT_MESSAGE));
        assert_eq!(crate::keys_common::DerivePublicKey::derive_pk(&sk1), pk1);

        // Each check rejects a flipped bit in every byte of its vector, so no byte is dead weight.
        for i in 0..32 + 32 + 128 + 64 {
            let mut bad = SIGGEN;
            flip(&mut [&mut bad.d, &mut bad.k, &mut bad.msg, &mut bad.sig], i);
            assert!(!siggen_matches(&bad), "SigGen byte {i}");
        }
        for i in 0..32 + 128 + 64 {
            let mut bad = DET_SIGGEN;
            flip(&mut [&mut bad.d, &mut bad.msg, &mut bad.sig], i);
            assert!(!det_siggen_matches(&bad), "DetSigGen byte {i}");
        }
        for i in 0..32 + 32 + 128 + 64 {
            let mut bad = SIGVER;
            flip(&mut [&mut bad.qx, &mut bad.qy, &mut bad.msg, &mut bad.sig], i);
            assert!(!sigver_accepts(&bad), "SigVer byte {i}");
        }
        assert!(siggen_matches(&SIGGEN) && det_siggen_matches(&DET_SIGGEN));
        assert!(sigver_accepts(&SIGVER));

        // Signers and a verifier made while ECDSA was available.
        let held_signer = sk.create_signer(drbg, None).unwrap();
        let held_det = sk.create_signer_deterministic(None).unwrap();
        let held_verifier = pk.create_verifier(None).unwrap();

        // A wrong verification answer fails the run and puts the module in the error state.
        let mut bad = SIGVER;
        bad.sig[0] ^= 0x80;
        assert_eq!(
            run(&SIGGEN, &DET_SIGGEN, &bad),
            Err(SelfTestError::KnownAnswerMismatch(SelfTestedAlgorithm::ECDSA))
        );
        assert_eq!(error_state(), Some(SelfTestedAlgorithm::ECDSA));
        assert_eq!(self_test_status(), SelfTestStatus::Failed);
        let failed = Some(SignatureError::SelfTestNotPassed(SelfTestStatus::Failed));
        assert_eq!(services(&sk, &pk, drbg), refused(SelfTestStatus::Failed));
        assert_eq!(keygen::<P256, SHA256>(drbg).err(), failed);
        assert_eq!(
            self_test(),
            Err(SelfTestError::NotPassed(SelfTestedAlgorithm::ECDSA, SelfTestStatus::Failed))
        );
        // Those that already existed produce nothing more (decision 5 of APPROACHES.md): the
        // hash panics on its update, and the finals refuse.
        assert_eq!(held_signer.do_final().err(), failed);
        assert_eq!(held_det.do_final().err(), failed);
        assert_eq!(held_verifier.do_verify_final(&SIGVER.sig).err(), failed);
        assert!(catch_unwind(|| crate::keys_common::DerivePublicKey::derive_pk(&sk)).is_err());

        // The failed pair-wise consistency test, in a process of its own.
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args(["--ignored", "--exact", "self_test::tests::a_failed_pct_enters_the_error_state"])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "{stdout}{}", String::from_utf8_lossy(&out.stderr));
        assert!(stdout.contains("1 passed"), "{stdout}");
    }

    /// Run by [`passes_then_a_wrong_answer_fails_for_good`] in a process of its own.
    #[test]
    #[ignore = "enters the process-wide error state; run in its own process by the test above"]
    fn a_failed_pct_enters_the_error_state() {
        bouncycastle_sha2::self_test().unwrap();
        self_test().unwrap();
        let drbg = &mut HashDRBG_SHA512::new_from_os();
        let (pk, _) = keygen::<P256, SHA256>(drbg).unwrap();
        let other = P256Sk::from_bytes(&SIGGEN.d).unwrap();
        assert_eq!(
            pairwise_consistency_test(&pk, &other),
            Err(SignatureError::ConsistencyCheckFailed)
        );
        assert_eq!(error_state(), Some(SelfTestedAlgorithm::ECDSA));
        assert_eq!(self_test_status(), SelfTestStatus::Failed);
        assert_eq!(
            keygen::<P256, SHA256>(drbg).err(),
            Some(SignatureError::SelfTestNotPassed(SelfTestStatus::Failed))
        );
    }

    /// Flips the low bit of byte `i` of the fields taken end to end.
    fn flip(fields: &mut [&mut [u8]], mut i: usize) {
        for field in fields {
            if i < field.len() {
                field[i] ^= 1;
                return;
            }
            i -= field.len();
        }
        panic!("byte {i} past the end");
    }
}
