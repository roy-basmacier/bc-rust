//! The FIPS 140-3 cryptographic algorithm self-tests (CASTs) for SHA-256 and SHA-512, and the
//! statuses that gate every SHA-2 hash on them. Only compiled with the `fips` cargo feature.
//!
//! The requirements and the choice of vectors, with their sources, are in the `bouncycastle-fips`
//! crate docs ("Requirements", "Known-answer vectors"); this module implements the SHA-2 rows of
//! that table and nothing else: CAVP SHAVS byte-oriented `SHA256ShortMsg.rsp` `[L = 32]` and
//! `SHA512ShortMsg.rsp` `[L = 64]`, both `Len = 24`. FIPS 140-3 IG 10.3.A Resolution 2: the
//! SHA-256 CAST covers SHA-224, and the SHA-512 CAST covers SHA-384, SHA-512/224 and SHA-512/256,
//! so SHA-224 is gated on the SHA-256 status and the other three on the SHA-512 status.
//!
//! The KATs drive the same `Hash` API an application would (`do_update`, `do_final_out`) on the
//! same SHA-256 and SHA-512 types, but create their hashes with the crate-private
//! `new_ungated()`, which skips the gate. So no hash exists before its self-test has passed, and
//! a gate that refuses (the module entering the error state mid-run) cannot panic out of a KAT.
//!
//! # The statuses
//!
//! [`SHA256_STATUS`] and [`SHA512_STATUS`] are private to this crate: only [`self_test`] can move
//! them to `Passed`, and only by producing the known answers. A failure of either KAT puts the
//! whole module in the error state through `bouncycastle_core::fips::enter_error_state`, which
//! every self-tested crate's gate reads, and which is permanent for the life of the process (the
//! error-state decision recorded in the `bouncycastle-fips` docs).
//!
//! A hash can be created only while its status reads `Passed`: not during the first run, and not
//! after a failure. A re-run reads `Passed` while it runs (IG 10.3.E Resolution 5 lets a repeated
//! CAST run in the background), so hashes stay available through one.

use bouncycastle_core::errors::SuspendableError;
use bouncycastle_core::fips::{
    SelfTestError, SelfTestStatus, SelfTestStatusCell, SelfTestedAlgorithm,
};
use bouncycastle_core::traits::Hash;

use crate::{SHA256, SHA512};

/// The SHA-256 self-test status, gating SHA-224 and SHA-256. Only [`run`] runs it.
static SHA256_STATUS: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::SHA256);
/// The SHA-512 self-test status, gating SHA-384, SHA-512 and SHA-512/t. Only [`run`] runs it.
static SHA512_STATUS: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::SHA512);

/// A message and its digest.
#[derive(Clone, Copy)]
struct HashKat<const MD_LEN: usize> {
    msg: [u8; 3],
    md: [u8; MD_LEN],
}

/// SHAVS SHA256ShortMsg.rsp, [L = 32], Len = 24: Msg, MD.
const SHA256_KAT: HashKat<32> = HashKat {
    msg: [0xb4, 0x19, 0x0e],
    md: [
        0xdf, 0xf2, 0xe7, 0x30, 0x91, 0xf6, 0xc0, 0x5e, //
        0x52, 0x88, 0x96, 0xc4, 0xc8, 0x31, 0xb9, 0x44, //
        0x86, 0x53, 0xdc, 0x2f, 0xf0, 0x43, 0x52, 0x8f, //
        0x67, 0x69, 0x43, 0x7b, 0xc7, 0xb9, 0x75, 0xc2,
    ],
};

/// SHAVS SHA512ShortMsg.rsp, [L = 64], Len = 24: Msg, MD.
const SHA512_KAT: HashKat<64> = HashKat {
    msg: [0x0a, 0x55, 0xdb],
    md: [
        0x79, 0x52, 0x58, 0x5e, 0x53, 0x30, 0xcb, 0x24, //
        0x7d, 0x72, 0xba, 0xe6, 0x96, 0xfc, 0x8a, 0x6b, //
        0x0f, 0x7d, 0x08, 0x04, 0x57, 0x7e, 0x34, 0x7d, //
        0x99, 0xbc, 0x1b, 0x11, 0xe5, 0x2f, 0x38, 0x49, //
        0x85, 0xa4, 0x28, 0x44, 0x93, 0x82, 0x30, 0x6a, //
        0x89, 0x26, 0x1a, 0xe1, 0x43, 0xc2, 0xf3, 0xfb, //
        0x61, 0x38, 0x04, 0xab, 0x20, 0xb4, 0x2d, 0xc0, //
        0x97, 0xe5, 0xbf, 0x4a, 0x96, 0xef, 0x91, 0x9b,
    ],
};

/// Runs the SHA-256 and then the SHA-512 self-test against compiled-in known answers. Until the
/// SHA-256 one has passed, creating a SHA-224 or SHA-256 hash panics; until the SHA-512 one has
/// passed, creating a SHA-384, SHA-512 or SHA-512/t hash panics. That covers every way of making
/// one: `new()`, `Default`, the one-shots, and the HMAC and HKDF over them; `from_suspended`
/// returns [`SuspendableError::SelfTestNotPassed`] instead. It
/// may be run again at any time; once it has passed, the hashes stay available while it runs
/// again.
///
/// An application normally calls this through `bouncycastle_fips::power_on_self_tests()`, which
/// also runs the other algorithms' self-tests and puts all of them in the error state if any
/// fails.
///
/// # Errors
/// * [`SelfTestError::KnownAnswerMismatch`] if a digest differs. The module is then in the error
///   state, and both SHA-256 and SHA-512 in [`SelfTestStatus::Failed`], until the program
///   restarts.
/// * [`SelfTestError::NotPassed`] with [`SelfTestStatus::Failed`], without running anything, if
///   the module is already in the error state.
///
/// A call made while another thread is running one of these self-tests waits for that run and
/// reports its result.
///
/// # Usage Examples
///
/// ```
/// use bouncycastle_core::fips::SelfTestStatus;
/// use bouncycastle_core::traits::HashOneShot;
/// use bouncycastle_sha2::{self_test, sha256_self_test_status, SHA256};
///
/// self_test().expect("the SHA-2 self-tests pass");
/// assert_eq!(sha256_self_test_status(), SelfTestStatus::Passed);
/// let digest = SHA256::hash(b"abc");
/// ```
pub fn self_test() -> Result<(), SelfTestError> {
    run(&SHA256_KAT, &SHA512_KAT)
}

/// Where the SHA-256 self-test, which gates SHA-224 and SHA-256, stands. The hashes can be
/// created only in [`SelfTestStatus::Passed`], which a re-run keeps reading while it runs. [`SelfTestStatus::Failed`] once any self-tested algorithm has
/// failed.
pub fn sha256_self_test_status() -> SelfTestStatus {
    SHA256_STATUS.get()
}

/// Where the SHA-512 self-test, which gates SHA-384, SHA-512, SHA-512/224 and SHA-512/256, stands.
/// The hashes can be created only in [`SelfTestStatus::Passed`], which a re-run keeps reading
/// while it runs. [`SelfTestStatus::Failed`] once any self-tested algorithm has
/// failed.
pub fn sha512_self_test_status() -> SelfTestStatus {
    SHA512_STATUS.get()
}

/// The gate in every SHA-224 / SHA-256 constructor (`SHA256Internal::new`, which `Default` and
/// the one-shots call). Panics, because the constructor is infallible.
pub(crate) fn require_sha256_passed() {
    require_passed(&SHA256_STATUS, SelfTestedAlgorithm::SHA256);
}

/// The gate in every SHA-384 / SHA-512 / SHA-512/t constructor (`SHA512Internal::new`). Panics,
/// as [`require_sha256_passed`] does.
pub(crate) fn require_sha512_passed() {
    require_passed(&SHA512_STATUS, SelfTestedAlgorithm::SHA512);
}

/// The gate in `SHA256Internal::from_suspended`: `Err` until the SHA-256 self-test has passed.
pub(crate) fn sha256_resumable() -> Result<(), SuspendableError> {
    resumable(&SHA256_STATUS)
}

/// The gate in `SHA512Internal::from_suspended`: `Err` until the SHA-512 self-test has passed.
pub(crate) fn sha512_resumable() -> Result<(), SuspendableError> {
    resumable(&SHA512_STATUS)
}

fn resumable(cell: &SelfTestStatusCell) -> Result<(), SuspendableError> {
    match cell.get() {
        SelfTestStatus::Passed => Ok(()),
        _ => Err(SuspendableError::SelfTestNotPassed),
    }
}

fn require_passed(cell: &SelfTestStatusCell, algorithm: SelfTestedAlgorithm) {
    match cell.get() {
        SelfTestStatus::Passed => {}
        other => panic!(
            "{} cannot be used: its FIPS 140-3 self-test is {other:?} \
             (run bouncycastle_fips::power_on_self_tests() first)",
            algorithm.name()
        ),
    }
}

/// [`self_test`] over the given answers, so that the unit test can check a wrong answer fails.
/// SHA-256 first, the order of [`SelfTestedAlgorithm::ALL`].
fn run(sha256: &HashKat<32>, sha512: &HashKat<64>) -> Result<(), SelfTestError> {
    SHA256_STATUS.run(|| sha256_matches(sha256))?;
    SHA512_STATUS.run(|| sha512_matches(sha512))
}

fn sha256_matches(kat: &HashKat<32>) -> bool {
    let mut hash = SHA256::new_ungated();
    hash.do_update(&kat.msg);
    let mut md = [0u8; 32];
    hash.do_final_out(&mut md) == md.len() && md == kat.md
}

fn sha512_matches(kat: &HashKat<64>) -> bool {
    let mut hash = SHA512::new_ungated();
    hash.do_update(&kat.msg);
    let mut md = [0u8; 64];
    hash.do_final_out(&mut md) == md.len() && md == kat.md
}

// One test, because the statuses are process-global and every unit test of the crate shares the
// process: it walks NotRun -> Passed -> (each wrong answer detected) -> Failed, which is
// permanent. No other unit test in the crate creates a hash.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SHA224, SHA384, SHA512_256};
    use bouncycastle_core::traits::{HashOneShot, Suspendable};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[test]
    fn passes_then_a_wrong_answer_fails_for_good() {
        assert_eq!(sha256_self_test_status(), SelfTestStatus::NotRun);
        assert_eq!(sha512_self_test_status(), SelfTestStatus::NotRun);
        assert!(catch_unwind(SHA256::new).is_err());
        assert!(catch_unwind(SHA224::default).is_err());
        assert!(catch_unwind(SHA512::new).is_err());
        assert!(catch_unwind(SHA512_256::new).is_err());
        assert!(catch_unwind(|| SHA384::hash(b"")).is_err());

        // During the first run no hash can be made, while the KAT's own hashes can.
        assert_eq!(
            SHA256_STATUS.run(|| {
                catch_unwind(SHA256::new).is_err()
                    && catch_unwind(SHA224::new).is_err()
                    && sha256_matches(&SHA256_KAT)
            }),
            Ok(())
        );
        assert_eq!(
            SHA512_STATUS.run(|| {
                catch_unwind(SHA512::new).is_err()
                    && catch_unwind(SHA384::new).is_err()
                    && sha512_matches(&SHA512_KAT)
            }),
            Ok(())
        );
        assert_eq!(sha256_self_test_status(), SelfTestStatus::Passed);
        assert_eq!(sha512_self_test_status(), SelfTestStatus::Passed);
        let _ = (SHA224::new(), SHA256::new(), SHA384::new(), SHA512::new(), SHA512_256::new());
        // A re-run keeps the hashes available while it runs.
        assert_eq!(SHA256_STATUS.run(|| catch_unwind(SHA256::new).is_ok()), Ok(()));
        assert_eq!(SHA512_STATUS.run(|| catch_unwind(SHA512::new).is_ok()), Ok(()));
        // A re-run from Passed runs again and passes.
        assert_eq!(self_test(), Ok(()));
        assert_eq!(sha256_self_test_status(), SelfTestStatus::Passed);

        // Each check rejects a flipped bit in every byte of its message and its digest, so no
        // byte of a vector is dead weight.
        for i in 0..SHA256_KAT.msg.len() + SHA256_KAT.md.len() {
            let mut bad = SHA256_KAT;
            match i.checked_sub(bad.msg.len()) {
                None => bad.msg[i] ^= 1,
                Some(j) => bad.md[j] ^= 1,
            }
            assert!(!sha256_matches(&bad), "SHA-256 byte {i}");
        }
        for i in 0..SHA512_KAT.msg.len() + SHA512_KAT.md.len() {
            let mut bad = SHA512_KAT;
            match i.checked_sub(bad.msg.len()) {
                None => bad.msg[i] ^= 1,
                Some(j) => bad.md[j] ^= 1,
            }
            assert!(!sha512_matches(&bad), "SHA-512 byte {i}");
        }
        assert!(sha256_matches(&SHA256_KAT) && sha512_matches(&SHA512_KAT));

        // States suspended, and hashes in progress, while the hashes were available.
        let suspended256 = SHA256::new().suspend();
        let suspended512 = SHA512::new().suspend();
        let mut held256 = SHA224::new();
        held256.do_update(b"ab");
        let mut held512 = SHA384::new();
        held512.do_update(b"ab");
        let (copy256, copy512) = (held256.clone(), held512.clone());

        // A wrong SHA-512 answer fails the run and puts both hashes in the error state for good.
        let mut bad512 = SHA512_KAT;
        bad512.md[0] ^= 0x80;
        assert_eq!(
            run(&SHA256_KAT, &bad512),
            Err(SelfTestError::KnownAnswerMismatch(SelfTestedAlgorithm::SHA512))
        );
        assert_eq!(sha256_self_test_status(), SelfTestStatus::Failed);
        assert_eq!(sha512_self_test_status(), SelfTestStatus::Failed);
        assert!(catch_unwind(SHA256::new).is_err());
        assert!(catch_unwind(SHA512::new).is_err());
        assert_eq!(
            SHA256::from_suspended(suspended256).err(),
            Some(SuspendableError::SelfTestNotPassed)
        );
        assert_eq!(
            SHA512::from_suspended(suspended512).err(),
            Some(SuspendableError::SelfTestNotPassed)
        );
        assert_eq!(
            self_test(),
            Err(SelfTestError::NotPassed(SelfTestedAlgorithm::SHA256, SelfTestStatus::Failed))
        );
        assert_eq!(sha512_self_test_status(), SelfTestStatus::Failed);

        // Hashes that already existed produce nothing more (decision 5 of APPROACHES.md): an
        // update, a final and a suspend each panic.
        assert!(catch_unwind(AssertUnwindSafe(|| held256.do_update(b"c"))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| held512.do_update(b"c"))).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| copy256.clone().do_final())).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| copy512.clone().do_final())).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| copy256.suspend())).is_err());
        assert!(catch_unwind(AssertUnwindSafe(|| copy512.suspend())).is_err());
        // The KATs' own hashes are not gated, so a KAT run in the error state reports its answer
        // rather than panicking.
        assert!(sha256_matches(&SHA256_KAT) && sha512_matches(&SHA512_KAT));
    }
}
