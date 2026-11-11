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
//! The KATs drive the same public API an application would (`SHA256::new()`, `do_update`,
//! `do_final_out`), so they pass through the same gate as every other hash.
//!
//! # The statuses
//!
//! [`SHA256_STATUS`] and [`SHA512_STATUS`] are private to this crate: only [`self_test`] can move
//! them to `Passed`, and only by producing the known answers. A failure of either KAT puts the
//! whole module in the error state through `bouncycastle_core::fips::enter_error_state`, which
//! every self-tested crate's gate reads, and which is permanent for the life of the process (the
//! error-state decision recorded in the `bouncycastle-fips` docs).
//!
//! While a run is in progress its status is `Running`, and the gate admits `Running` as it admits
//! `Passed`, because the KAT's own hashes go through it and nothing tells the KAT's thread from
//! any other. So for the length of a run *every* thread may create that hash: during a re-run that
//! is the background periodic self-test IG 10.3.E Resolution 5 allows; during the first run it is
//! a hash made before the self-test has passed, which the `bouncycastle-fips` docs rule out by
//! telling the application to run the power-on self-tests before creating any service.

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
/// one: `new()`, `Default`, the one-shots, `from_suspended`, and the HMAC and HKDF over them. It
/// may be run again at any time; the hashes stay available while it runs.
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
/// created in [`SelfTestStatus::Passed`] and, while a run is in progress,
/// [`SelfTestStatus::Running`]. [`SelfTestStatus::Failed`] once any self-tested algorithm has
/// failed.
pub fn sha256_self_test_status() -> SelfTestStatus {
    SHA256_STATUS.get()
}

/// Where the SHA-512 self-test, which gates SHA-384, SHA-512, SHA-512/224 and SHA-512/256, stands.
/// The hashes can be created in [`SelfTestStatus::Passed`] and, while a run is in progress,
/// [`SelfTestStatus::Running`]. [`SelfTestStatus::Failed`] once any self-tested algorithm has
/// failed.
pub fn sha512_self_test_status() -> SelfTestStatus {
    SHA512_STATUS.get()
}

/// The gate in every SHA-224 / SHA-256 constructor (`SHA256Internal::new` and `from_suspended`).
/// Panics, because those constructors are infallible or, for `from_suspended`, have no error for it.
pub(crate) fn require_sha256_passed() {
    require_passed(&SHA256_STATUS, SelfTestedAlgorithm::SHA256);
}

/// The gate in every SHA-384 / SHA-512 / SHA-512/t constructor (`SHA512Internal::new` and
/// `from_suspended`). Panics, as [`require_sha256_passed`] does.
pub(crate) fn require_sha512_passed() {
    require_passed(&SHA512_STATUS, SelfTestedAlgorithm::SHA512);
}

fn require_passed(cell: &SelfTestStatusCell, algorithm: SelfTestedAlgorithm) {
    match cell.get() {
        // Running: the KAT's own hashes come through here (see the module docs).
        SelfTestStatus::Passed | SelfTestStatus::Running => {}
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
    let mut hash = SHA256::new();
    hash.do_update(&kat.msg);
    let mut md = [0u8; 32];
    hash.do_final_out(&mut md) == md.len() && md == kat.md
}

fn sha512_matches(kat: &HashKat<64>) -> bool {
    let mut hash = SHA512::new();
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
    use std::panic::catch_unwind;

    #[test]
    fn passes_then_a_wrong_answer_fails_for_good() {
        assert_eq!(sha256_self_test_status(), SelfTestStatus::NotRun);
        assert_eq!(sha512_self_test_status(), SelfTestStatus::NotRun);
        assert!(catch_unwind(SHA256::new).is_err());
        assert!(catch_unwind(SHA224::default).is_err());
        assert!(catch_unwind(SHA512::new).is_err());
        assert!(catch_unwind(SHA512_256::new).is_err());
        assert!(catch_unwind(|| SHA384::hash(b"")).is_err());

        assert_eq!(self_test(), Ok(()));
        assert_eq!(sha256_self_test_status(), SelfTestStatus::Passed);
        assert_eq!(sha512_self_test_status(), SelfTestStatus::Passed);
        let _ = (SHA224::new(), SHA256::new(), SHA384::new(), SHA512::new(), SHA512_256::new());
        // A re-run from Passed runs again and passes.
        assert_eq!(self_test(), Ok(()));
        assert_eq!(sha256_self_test_status(), SelfTestStatus::Passed);

        // Each check rejects a flipped bit in its message or its digest.
        let mut bad256 = SHA256_KAT;
        bad256.msg[2] ^= 1;
        assert!(!sha256_matches(&bad256));
        bad256 = SHA256_KAT;
        bad256.md[31] ^= 1;
        assert!(!sha256_matches(&bad256));
        let mut bad512 = SHA512_KAT;
        bad512.msg[2] ^= 1;
        assert!(!sha512_matches(&bad512));
        bad512 = SHA512_KAT;
        bad512.md[63] ^= 1;
        assert!(!sha512_matches(&bad512));
        assert!(sha256_matches(&SHA256_KAT) && sha512_matches(&SHA512_KAT));

        // States suspended while the hashes were available.
        let suspended256 = SHA256::new().suspend();
        let suspended512 = SHA512::new().suspend();

        // A wrong SHA-512 answer fails the run and puts both hashes in the error state for good.
        bad512.md[0] ^= 0x80;
        assert_eq!(
            run(&SHA256_KAT, &bad512),
            Err(SelfTestError::KnownAnswerMismatch(SelfTestedAlgorithm::SHA512))
        );
        assert_eq!(sha256_self_test_status(), SelfTestStatus::Failed);
        assert_eq!(sha512_self_test_status(), SelfTestStatus::Failed);
        assert!(catch_unwind(SHA256::new).is_err());
        assert!(catch_unwind(SHA512::new).is_err());
        assert!(catch_unwind(|| SHA256::from_suspended(suspended256)).is_err());
        assert!(catch_unwind(|| SHA512::from_suspended(suspended512)).is_err());
        assert_eq!(
            self_test(),
            Err(SelfTestError::NotPassed(SelfTestedAlgorithm::SHA256, SelfTestStatus::Failed))
        );
        assert_eq!(sha512_self_test_status(), SelfTestStatus::Failed);
    }
}
