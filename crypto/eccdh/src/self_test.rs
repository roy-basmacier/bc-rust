//! The FIPS 140-3 cryptographic algorithm self-test (CAST) for the ECC CDH primitive, the status
//! that gates every ECC CDH key pair and agreement on it, and the pair-wise consistency test on
//! every generated key pair. Only compiled with the `fips` cargo feature.
//!
//! The requirements and the choice of vector, with its source, are in the `bouncycastle-fips`
//! crate docs ("Requirements", "Known-answer vectors"); this module implements the ECC CDH row of
//! that table and nothing else. FIPS 140-3 IG 10.3.A Resolution 11 defers to IG D.F, whose CAST
//! for the shared secret computation is: "it is sufficient to choose any NIST-recommended curve
//! supported by one the module's ECC-based key shared secret computation schemes, select any point
//! Q in the subgroup of size n of points on that curve and verify the correct computation of the
//! x-coordinate of point P = hdQ, with 2 <= d <= n-2". One curve covers all seven; P-256 is the
//! smallest the module supports ([10.29]). The vector is NIST CAVP `ecccdhtestvectors.zip`
//! (CAVS 14.1), `KAS_ECC_CDH_PrimitiveTest.txt`, `[P-256]`, `COUNT = 0`: `QCAVSx`, `QCAVSy`,
//! `dIUT`, `ZIUT`.
//!
//! The KAT decodes the peer key through the same full public-key validation an application's key
//! goes through, and computes `Z` with the same crate-private primitive both agreement workers
//! call, so it needs no worker of the public API: none can exist before the self-test has passed.
//! The KDF variants run the same primitive and then a KDF, whose own self-test is not this one's.
//!
//! # The status
//!
//! [`STATUS`] is private to this crate: only [`self_test`] can move it to `Passed`, and only by
//! producing the known answer. A failure, of the self-test or of a pair-wise consistency test,
//! puts the whole module in the error state through `bouncycastle_core::fips::enter_error_state`.
//!
//! Key pairs and agreement workers can be created only while the status reads `Passed`; a worker
//! that already exists refuses to agree once the module is in the error state.
//!
//! # The pair-wise consistency test
//!
//! ISO/IEC 19790:2012 7.10.3.3, as the Background of IG 10.3.A quotes it: "a pair-wise
//! consistency test shall [10.35] be performed for every generated public and private key pair",
//! at minimum (Additional Comment 1) "the PCT that is required by the underlying algorithm standard (e.g., SP 800-56Arev3
//! Section 5.6.2.1.4 option 'b' ...)". That option, for an ECC key pair `(d, Q)`: "Use the private
//! key, d, along with the generator G and other domain parameters associated with the key pair,
//! to compute dG ... Compare the result to the public key, Q. If dG is not equal to Q, then the
//! pair-wise consistency test fails." [`crate::keys::keygen`] runs it before returning the pair.

use bouncycastle_core::errors::KeyAgreementError;
use bouncycastle_core::fips::{
    SelfTestError, SelfTestStatus, SelfTestStatusCell, SelfTestedAlgorithm, enter_error_state,
    error_state,
};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait};
use bouncycastle_core::traits::{KeyAgreementPrivateKey, KeyAgreementPublicKey};
use bouncycastle_ec::P256;
use bouncycastle_ec::curve::Curve;

use crate::eccdh::agree_out;
use crate::keys::{ECCDHPrivateKey, ECCDHPublicKey};

/// The ECC CDH self-test status. Only [`run`] runs it, so only the ECC CDH KAT can make it
/// `Passed`.
static STATUS: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::ECC_CDH);

/// The own private key, the peer's public key and the shared secret they give.
#[derive(Clone, Copy)]
struct CdhKat {
    d: [u8; 32],
    qx: [u8; 32],
    qy: [u8; 32],
    z: [u8; 32],
}

/// CAVP `KAS_ECC_CDH_PrimitiveTest.txt`, `[P-256]`, `COUNT = 0`: `dIUT`, `QCAVSx`, `QCAVSy`,
/// `ZIUT`.
const KAT: CdhKat = CdhKat {
    d: [
        0x7d, 0x7d, 0xc5, 0xf7, 0x1e, 0xb2, 0x9d, 0xda, //
        0xf8, 0x0d, 0x62, 0x14, 0x63, 0x2e, 0xea, 0xe0, //
        0x3d, 0x90, 0x58, 0xaf, 0x1f, 0xb6, 0xd2, 0x2e, //
        0xd8, 0x0b, 0xad, 0xb6, 0x2b, 0xc1, 0xa5, 0x34,
    ],
    qx: [
        0x70, 0x0c, 0x48, 0xf7, 0x7f, 0x56, 0x58, 0x4c, //
        0x5c, 0xc6, 0x32, 0xca, 0x65, 0x64, 0x0d, 0xb9, //
        0x1b, 0x6b, 0xac, 0xce, 0x3a, 0x4d, 0xf6, 0xb4, //
        0x2c, 0xe7, 0xcc, 0x83, 0x88, 0x33, 0xd2, 0x87,
    ],
    qy: [
        0xdb, 0x71, 0xe5, 0x09, 0xe3, 0xfd, 0x9b, 0x06, //
        0x0d, 0xdb, 0x20, 0xba, 0x5c, 0x51, 0xdc, 0xc5, //
        0x94, 0x8d, 0x46, 0xfb, 0xf6, 0x40, 0xdf, 0xe0, //
        0x44, 0x17, 0x82, 0xca, 0xb8, 0x5f, 0xa4, 0xac,
    ],
    z: [
        0x46, 0xfc, 0x62, 0x10, 0x64, 0x20, 0xff, 0x01, //
        0x2e, 0x54, 0xa4, 0x34, 0xfb, 0xdd, 0x2d, 0x25, //
        0xcc, 0xc5, 0x85, 0x20, 0x60, 0x56, 0x1e, 0x68, //
        0x04, 0x0d, 0xd7, 0x77, 0x89, 0x97, 0xbd, 0x7b,
    ],
};

/// Runs the ECC CDH self-test: the P-256 primitive against a compiled-in known answer. Until it
/// has passed, key generation and `create_agreement` return
/// `KeyAgreementError::SelfTestNotPassed`, on every curve and with every KDF, and `derive_pk`
/// panics. It may be run again at any time; once it has passed, ECC CDH stays available while it
/// runs again.
///
/// An application normally calls this through `bouncycastle_fips::power_on_self_tests()`.
///
/// # Errors
/// * [`SelfTestError::KnownAnswerMismatch`] if the shared secret differs. The module is then in
///   the error state until the program restarts.
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
/// use bouncycastle_eccdh::{self_test, self_test_status};
///
/// self_test().expect("the ECC CDH self-test passes");
/// assert_eq!(self_test_status(), SelfTestStatus::Passed);
/// ```
pub fn self_test() -> Result<(), SelfTestError> {
    run(&KAT)
}

/// Where the ECC CDH self-test stands. ECC CDH can be used only in [`SelfTestStatus::Passed`],
/// which a re-run keeps reading while it runs; [`SelfTestStatus::Failed`] once any self-tested
/// algorithm has failed.
pub fn self_test_status() -> SelfTestStatus {
    STATUS.get()
}

/// The gate in `keygen` and both `create_agreement`s.
pub(crate) fn require_passed() -> Result<(), KeyAgreementError> {
    match STATUS.get() {
        SelfTestStatus::Passed => Ok(()),
        other => Err(KeyAgreementError::SelfTestNotPassed(other)),
    }
}

/// The gate in `derive_pk`, which returns no `Result`. Panics unless the self-test has passed.
pub(crate) fn assert_passed() {
    if let Err(e) = require_passed() {
        panic!(
            "ECC CDH cannot be used: {e:?} (run bouncycastle_fips::power_on_self_tests() first)"
        );
    }
}

/// The gate in the primitive both workers call, so that workers that exist when the module
/// enters the error state produce nothing more. The self-test's own computation passes through
/// it too, which is harmless: the module error state already stops the self-test from running.
pub(crate) fn require_operational() -> Result<(), KeyAgreementError> {
    match error_state() {
        None => Ok(()),
        Some(_) => Err(KeyAgreementError::SelfTestNotPassed(SelfTestStatus::Failed)),
    }
}

/// SP 800-56A Rev. 3 Section 5.6.2.1.4 method b on a key pair `keygen` has just generated: `Ok`
/// if `[d]G` is the public key. Otherwise the module enters the error state, naming ECC CDH, and
/// the pair must not be used.
pub(crate) fn pairwise_consistency_test<C: Curve>(
    pk: &ECCDHPublicKey<C>,
    sk: &ECCDHPrivateKey<C>,
) -> Result<(), KeyAgreementError> {
    if C::public_point(sk.scalar()) == (pk.x, pk.y) {
        Ok(())
    } else {
        enter_error_state(SelfTestedAlgorithm::ECC_CDH);
        Err(KeyAgreementError::ConsistencyCheckFailed)
    }
}

/// [`self_test`] over the given answer, so that the unit test can check a wrong answer fails.
fn run(kat: &CdhKat) -> Result<(), SelfTestError> {
    STATUS.run(|| cdh_matches(kat))
}

/// SP 800-56A Rev. 3 Section 5.7.1.2: `Z` from `kat.d` and the uncompressed peer key
/// `04 || qx || qy` is `kat.z`.
fn cdh_matches(kat: &CdhKat) -> bool {
    let mut encoded = [0x04u8; 65];
    encoded[1..33].copy_from_slice(&kat.qx);
    encoded[33..].copy_from_slice(&kat.qy);
    let Ok(peer) = ECCDHPublicKey::<P256>::from_bytes(&encoded) else {
        return false;
    };
    let Ok(sk) = ECCDHPrivateKey::<P256>::from_bytes(&kat.d) else {
        return false;
    };
    let mut z = KeyMaterial::<32>::new();
    agree_out::<P256, 32>(&sk, &peer, &mut z).is_ok() && z.ref_to_bytes() == kat.z
}

// The status and the error state are process-global, and every unit test of the crate shares the
// process, so the self-test is walked in one test: NotRun -> Passed -> (each wrong answer
// detected) -> a wrong answer -> Failed, which is permanent. A failed pair-wise consistency test
// also enters the error state, so it runs in a process of its own: the first test re-runs this
// test binary for the second, which is `#[ignore]`d so that it runs only that way. No other unit
// test of the crate makes a key pair or an agreement worker.
#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::keys::{key_pair_from_generated, keygen};
    use crate::keys_common::DerivePublicKey;
    use bouncycastle_core::agreement_key::AgreementKey;
    use bouncycastle_core::traits::KeyAgreement;
    use bouncycastle_ec::P384;
    use bouncycastle_rng::FixedSeedRNG;
    use std::panic::catch_unwind;
    use std::string::String;

    fn rng() -> FixedSeedRNG<[u8; 64]> {
        let mut rng = FixedSeedRNG::new([0x5a; 64]);
        rng.set_security_strength(bouncycastle_core::security_strength::SecurityStrength::_256bit);
        rng
    }

    fn peer() -> ECCDHPublicKey<P256> {
        let mut encoded = [0x04u8; 65];
        encoded[1..33].copy_from_slice(&KAT.qx);
        encoded[33..].copy_from_slice(&KAT.qy);
        ECCDHPublicKey::<P256>::from_bytes(&encoded).unwrap()
    }

    #[test]
    fn passes_then_a_wrong_answer_fails_for_good() {
        let sk = ECCDHPrivateKey::<P256>::from_bytes(&KAT.d).unwrap();
        let not_run = Some(KeyAgreementError::SelfTestNotPassed(SelfTestStatus::NotRun));

        // Before the self-test, nothing of ECC CDH can be made, on any curve.
        assert_eq!(AgreementKey::<(), 32>::create_agreement(&sk, ()).err(), not_run);
        assert_eq!(keygen::<P256>(&mut rng()).err(), not_run);
        assert_eq!(keygen::<P384>(&mut rng()).err(), not_run);
        assert!(catch_unwind(|| sk.derive_pk()).is_err());

        // During the first run nothing can be made either, while the KAT computes.
        assert_eq!(
            STATUS.run(|| {
                AgreementKey::<(), 32>::create_agreement(&sk, ()).err()
                    == Some(KeyAgreementError::SelfTestNotPassed(SelfTestStatus::Running))
                    && cdh_matches(&KAT)
            }),
            Ok(())
        );
        assert_eq!(self_test_status(), SelfTestStatus::Passed);
        let worker = AgreementKey::<(), 32>::create_agreement(&sk, ()).unwrap();
        let mut z = KeyMaterial::<32>::new();
        assert_eq!(worker.agree_out(&peer(), &mut z), Ok(32));
        assert_eq!(z.ref_to_bytes(), KAT.z);
        // A re-run from Passed runs again, passes, and keeps ECC CDH available while it runs.
        assert_eq!(
            STATUS.run(|| AgreementKey::<(), 32>::create_agreement(&sk, ()).is_ok()),
            Ok(())
        );
        assert_eq!(self_test(), Ok(()));

        // Key generation works on every curve, through the pair-wise consistency test, which
        // rejects a mismatched pair.
        let (pk1, sk1) = keygen::<P256>(&mut rng()).unwrap();
        let (pk2, sk2) = keygen::<P384>(&mut rng()).unwrap();
        assert_eq!(sk1.derive_pk(), pk1);
        assert_eq!(sk2.derive_pk(), pk2);
        assert_ne!(P256::public_point(sk.scalar()), (pk1.x, pk1.y), "the mismatched pair below");

        // The check rejects a flipped bit in every byte of the vector, so no byte is dead weight.
        for i in 0..4 * 32 {
            let mut bad = KAT;
            let field = match i / 32 {
                0 => &mut bad.d,
                1 => &mut bad.qx,
                2 => &mut bad.qy,
                _ => &mut bad.z,
            };
            field[i % 32] ^= 1;
            assert!(!cdh_matches(&bad), "byte {i}");
        }
        assert!(cdh_matches(&KAT));

        // A wrong answer fails the run and puts the module in the error state.
        let mut bad = KAT;
        bad.z[31] ^= 0x80;
        assert_eq!(
            run(&bad),
            Err(SelfTestError::KnownAnswerMismatch(SelfTestedAlgorithm::ECC_CDH))
        );
        assert_eq!(error_state(), Some(SelfTestedAlgorithm::ECC_CDH));
        assert_eq!(self_test_status(), SelfTestStatus::Failed);
        let failed = Some(KeyAgreementError::SelfTestNotPassed(SelfTestStatus::Failed));
        assert_eq!(AgreementKey::<(), 32>::create_agreement(&sk, ()).err(), failed);
        assert_eq!(keygen::<P256>(&mut rng()).err(), failed);
        assert_eq!(
            self_test(),
            Err(SelfTestError::NotPassed(SelfTestedAlgorithm::ECC_CDH, SelfTestStatus::Failed))
        );
        // A worker that already existed produces nothing more (decision 5 of APPROACHES.md), and
        // leaves the buffer zeroized.
        assert_eq!(worker.agree_out(&peer(), &mut z).err(), failed);
        assert_ne!(z.ref_to_bytes(), KAT.z);
        assert!(catch_unwind(|| sk.derive_pk()).is_err());

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
        self_test().unwrap();
        let (pk, _) = keygen::<P256>(&mut rng()).unwrap();
        let other = ECCDHPrivateKey::<P256>::from_bytes(&KAT.d).unwrap();
        // `keygen`'s own second half, handed the new public point with another key's scalar:
        // it fails only if it runs the pair-wise consistency test.
        assert_eq!(
            key_pair_from_generated::<P256>((other.scalar().clone(), (pk.x, pk.y))).err(),
            Some(KeyAgreementError::ConsistencyCheckFailed)
        );
        assert_eq!(error_state(), Some(SelfTestedAlgorithm::ECC_CDH));
        assert_eq!(self_test_status(), SelfTestStatus::Failed);
        assert_eq!(
            keygen::<P256>(&mut rng()).err(),
            Some(KeyAgreementError::SelfTestNotPassed(SelfTestStatus::Failed))
        );
    }
}
