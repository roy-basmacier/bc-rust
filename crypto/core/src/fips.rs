//! Types shared by the FIPS 140-3 cryptographic algorithm self-tests (CASTs).
//!
//! Only present with the `fips` cargo feature. The status of one self-tested algorithm and the
//! cell that runs its known-answer test and records the result ([`SelfTestStatusCell`]), which
//! algorithm it is, and the errors a self-test or a gated service reports. Each algorithm crate
//! keeps its cell in a private `static`, so only that crate can run its self-test;
//! `bouncycastle-fips` documents the requirements they implement.
//!
//! The one piece of state kept here is the module error state ([`enter_error_state`],
//! [`error_state`]): a failure of any self-test stops every algorithm, so every crate's gate reads
//! the same flag, and it can be set but never cleared.

use core::sync::atomic::{AtomicU8, Ordering};

/// Where one algorithm's self-test stands.
///
/// A service of the algorithm may be used only in [`SelfTestStatus::Passed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SelfTestStatus {
    /// The self-test has not been run since the program started.
    NotRun = 0,
    /// The self-test is being run.
    Running = 1,
    /// The last run of the self-test produced its known answer.
    Passed = 2,
    /// The last run of the self-test did not produce its known answer.
    Failed = 3,
}

impl SelfTestStatus {
    /// The status as a `u8`, the form [`SelfTestStatusCell`] stores it in.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The status a `u8` from [`SelfTestStatus::as_u8`] encodes, or `None` for any other value.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NotRun),
            1 => Some(Self::Running),
            2 => Some(Self::Passed),
            3 => Some(Self::Failed),
            _ => None,
        }
    }
}

/// One algorithm's self-test status, for a private `static` in the crate that implements the
/// algorithm: the only way to `Passed` is a [`SelfTestStatusCell::run`] whose known-answer test
/// returned `true`, so the crate that owns the `static` decides what passing means.
///
/// Starts as [`SelfTestStatus::NotRun`]. The first run reads [`SelfTestStatus::Running`]; a
/// re-run of a self-test that has passed keeps reading [`SelfTestStatus::Passed`] until it
/// finishes, so the algorithm stays available while its periodic self-test runs (FIPS 140-3 IG
/// 10.3.E Resolution 5: a repeated CAST "may be run in the background without the need for
/// inhibiting data output"; that covers a CAST, not the software integrity test, whose status is
/// a cell too: see the `bouncycastle-fips` crate docs, "Requirements"). Once the module is in the error state ([`error_state`]) every cell
/// reads [`SelfTestStatus::Failed`], whichever algorithm failed.
#[derive(Debug)]
pub struct SelfTestStatusCell {
    status: AtomicU8,
    algorithm: SelfTestedAlgorithm,
}

impl SelfTestStatusCell {
    /// A cell for `algorithm`'s self-test, holding [`SelfTestStatus::NotRun`].
    pub const fn new(algorithm: SelfTestedAlgorithm) -> Self {
        Self { status: AtomicU8::new(SelfTestStatus::NotRun.as_u8()), algorithm }
    }

    /// The current status: [`SelfTestStatus::Failed`] in the module error state, otherwise where
    /// this algorithm's self-test stands. A status written by a run on one thread is seen by
    /// every later `get` on any thread.
    pub fn get(&self) -> SelfTestStatus {
        if error_state().is_some() {
            return SelfTestStatus::Failed;
        }
        match self.status.load(Ordering::Acquire) {
            RERUNNING => SelfTestStatus::Passed,
            // Only this type writes `status`, and only `as_u8` values or RERUNNING, so `from_u8`
            // cannot fail; `Failed` is the safe reading should that ever stop being true.
            stored => SelfTestStatus::from_u8(stored).unwrap_or(SelfTestStatus::Failed),
        }
    }

    /// Runs `kat`, the algorithm's known-answer test, and records the result: `true` moves the
    /// status to [`SelfTestStatus::Passed`]; `false`, or a panic out of `kat`, moves it to
    /// [`SelfTestStatus::Failed`] and puts the whole module in the error state
    /// ([`enter_error_state`]) naming this cell's algorithm. Only one thread runs it at a time: a
    /// call made while another thread's run is in progress waits for that run to finish and
    /// reports its result, without running `kat` itself.
    ///
    /// # Errors
    /// * [`SelfTestError::KnownAnswerMismatch`] if `kat` returned `false`.
    /// * [`SelfTestError::NotPassed`] with [`SelfTestStatus::Failed`], without running `kat`, if
    ///   the module is in the error state, or if it entered the error state while `kat` (or the
    ///   run waited for) ran, whichever algorithm failed.
    pub fn run(&self, kat: impl FnOnce() -> bool) -> Result<(), SelfTestError> {
        if !self.claim()? {
            // Another thread's run finished while this call waited: its result is this call's.
            return self.result();
        }
        // Until `forget` disarms it, dropping the guard -- which only happens if `kat` unwinds --
        // records a failure, so a panicking KAT cannot leave the status at Running, which no
        // later run could claim.
        let guard = FailOnUnwind(self);
        let passed = kat();
        core::mem::forget(guard);
        if !passed {
            self.fail();
            return Err(SelfTestError::KnownAnswerMismatch(self.algorithm));
        }
        self.status.store(SelfTestStatus::Passed.as_u8(), Ordering::Release);
        self.result()
    }

    /// `Ok` if the status is [`SelfTestStatus::Passed`], else the status as an error.
    fn result(&self) -> Result<(), SelfTestError> {
        match self.get() {
            SelfTestStatus::Passed => Ok(()),
            other => Err(SelfTestError::NotPassed(self.algorithm, other)),
        }
    }

    /// Claims the run, atomically, so that two threads calling [`Self::run`] at once do not both
    /// run the KAT: NotRun becomes Running, Passed becomes RERUNNING. `Ok(true)` once claimed;
    /// `Ok(false)` if another thread's run was in progress, after waiting for it to finish.
    /// Failed, and the module error state, refuse.
    fn claim(&self) -> Result<bool, SelfTestError> {
        const NOT_RUN: u8 = SelfTestStatus::NotRun.as_u8();
        const RUNNING: u8 = SelfTestStatus::Running.as_u8();
        const PASSED: u8 = SelfTestStatus::Passed.as_u8();
        loop {
            if error_state().is_some() {
                return Err(SelfTestError::NotPassed(self.algorithm, SelfTestStatus::Failed));
            }
            let current = self.status.load(Ordering::Acquire);
            let claimed = match current {
                NOT_RUN => RUNNING,
                PASSED => RERUNNING,
                RUNNING | RERUNNING => {
                    // A KAT takes microseconds, and the guard in `run` ends the run even if it
                    // panics, so this spins briefly; no_std has no way to block instead.
                    while matches!(self.status.load(Ordering::Acquire), RUNNING | RERUNNING) {
                        core::hint::spin_loop();
                    }
                    return Ok(false);
                }
                _ => return Err(SelfTestError::NotPassed(self.algorithm, SelfTestStatus::Failed)),
            };
            if self
                .status
                .compare_exchange_weak(current, claimed, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(true);
            }
        }
    }

    /// Records a failure of this algorithm: its own status, and the module error state.
    fn fail(&self) {
        self.status.store(SelfTestStatus::Failed.as_u8(), Ordering::Release);
        enter_error_state(self.algorithm);
    }
}

/// The stored value of a re-run of a self-test that had passed, which [`SelfTestStatusCell::get`]
/// reports as [`SelfTestStatus::Passed`]. Outside the range of [`SelfTestStatus::as_u8`].
const RERUNNING: u8 = 4;

/// Records a failure if dropped; see [`SelfTestStatusCell::run`].
struct FailOnUnwind<'a>(&'a SelfTestStatusCell);

impl Drop for FailOnUnwind<'_> {
    fn drop(&mut self) {
        self.0.fail();
    }
}

/// An algorithm that has its own self-test, named as FIPS 140-3 IG 10.3.A names the CASTs, or
/// the software integrity test.
///
/// One algorithm's self-test covers every variant of it the library offers: [`Self::AES`] covers
/// all AES modes and key sizes, [`Self::SHA256`] covers SHA-224 and SHA-256, [`Self::SHA512`]
/// covers SHA-384, SHA-512, SHA-512/224 and SHA-512/256, and [`Self::ECDSA`] and
/// [`Self::ECC_CDH`] cover every curve. The pair-wise consistency test on a key pair those two
/// generate is a conditional self-test of the same algorithm, so its failure names it too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SelfTestedAlgorithm {
    /// AES (FIPS 197), in every mode.
    AES,
    /// SHA-256 (FIPS 180-4), also covering SHA-224.
    SHA256,
    /// SHA-512 (FIPS 180-4), also covering SHA-384, SHA-512/224 and SHA-512/256.
    SHA512,
    /// HMAC-SHA-512 (FIPS 198-1), the algorithm of the software integrity test.
    #[allow(non_camel_case_types)]
    HMAC_SHA512,
    /// Not an algorithm: the pre-operational software integrity test (ISO/IEC 19790:2012
    /// 7.10.2.2), an HMAC-SHA-512 over the program's read-only loaded segments.
    SoftwareIntegrity,
    /// Not an algorithm: the check that the module HMAC recomputed from the source table embedded
    /// in the program equals the published constant of a validated version of the module.
    ModuleIntegrity,
    /// ECDSA (FIPS 186-5): signature generation with a random and with a deterministic `k`, and
    /// verification, on every curve.
    ECDSA,
    /// The ECC CDH primitive (SP 800-56A Rev. 3 Section 5.7.1.2), on every curve.
    #[allow(non_camel_case_types)]
    ECC_CDH,
}

impl SelfTestedAlgorithm {
    /// Every self-tested algorithm, in the order the self-tests run.
    ///
    /// The hashes come first so that a known-answer test compared through a hash (FIPS 140-3 IG
    /// 10.3.A, GeneralNote7) only ever uses a hash that has already passed. HMAC-SHA-512 follows
    /// SHA-512, and the software integrity test follows HMAC-SHA-512, the algorithm it uses
    /// (ISO/IEC 19790:2012 7.10.1 [10.20], as FIPS 140-3 IG 10.2.A quotes it). The module
    /// integrity check, also an HMAC-SHA-512, follows the software integrity test. ECDSA hashes
    /// its messages with SHA-256 and keys its deterministic `k` with HMAC-SHA-256, so it follows
    /// the hashes too.
    pub const ALL: [Self; 8] = [
        Self::SHA256,
        Self::SHA512,
        Self::HMAC_SHA512,
        Self::SoftwareIntegrity,
        Self::ModuleIntegrity,
        Self::AES,
        Self::ECDSA,
        Self::ECC_CDH,
    ];

    /// The algorithm's position in [`Self::ALL`].
    const fn index(self) -> u8 {
        match self {
            Self::SHA256 => 0,
            Self::SHA512 => 1,
            Self::HMAC_SHA512 => 2,
            Self::SoftwareIntegrity => 3,
            Self::ModuleIntegrity => 4,
            Self::AES => 5,
            Self::ECDSA => 6,
            Self::ECC_CDH => 7,
        }
    }

    /// The algorithm's name as the self-test reports it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::AES => "AES",
            Self::SHA256 => "SHA-256",
            Self::SHA512 => "SHA-512",
            Self::HMAC_SHA512 => "HMAC-SHA-512",
            Self::SoftwareIntegrity => "software integrity",
            Self::ModuleIntegrity => "module integrity",
            Self::ECDSA => "ECDSA",
            Self::ECC_CDH => "ECC CDH",
        }
    }
}

/// Why a self-test, or a service waiting on one, could not go ahead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SelfTestError {
    /// The algorithm's self-test computed a value other than its known answer.
    KnownAnswerMismatch(SelfTestedAlgorithm),
    /// The algorithm's self-test has not passed: it is in the given status, which is never
    /// [`SelfTestStatus::Passed`].
    NotPassed(SelfTestedAlgorithm, SelfTestStatus),
}

/// The module error state: `NO_ERROR`, or the index in [`SelfTestedAlgorithm::ALL`] of the
/// algorithm whose failure entered it. Private, and written only by [`enter_error_state`], which
/// never clears it.
static ERROR_STATE: AtomicU8 = AtomicU8::new(NO_ERROR);
const NO_ERROR: u8 = u8::MAX;

/// Puts the whole module in the error state for the rest of the life of the process, naming
/// `cause` as the algorithm whose self-test failed. From then on every self-tested algorithm
/// reports [`SelfTestStatus::Failed`], refuses to create services, and refuses to run its
/// self-test again; only a restart of the program leaves the error state.
///
/// Only the first cause is kept: once the module is in the error state, a later call changes
/// nothing. Nothing can take the module out of the error state, so any code may call this to stop
/// the module, and none can use it to start one.
pub fn enter_error_state(cause: SelfTestedAlgorithm) {
    // Losing the exchange means an earlier failure is already recorded, which is the one kept.
    let _ =
        ERROR_STATE.compare_exchange(NO_ERROR, cause.index(), Ordering::AcqRel, Ordering::Acquire);
}

/// The check a gated operation of a self-tested algorithm makes before it produces output, so that
/// keys, workers and hashes that already exist stop when the module enters the error state (data
/// output is inhibited in it: AS03.07, quoted in the `bouncycastle-fips` crate docs,
/// "Requirements").
///
/// # Panics
/// If the module is in the error state, naming `algorithm` and the algorithm whose failure
/// entered it. The operations this guards return no error for it, so a panic is the only refusal
/// they can give.
pub fn assert_operational(algorithm: SelfTestedAlgorithm) {
    if let Some(cause) = error_state() {
        panic!(
            "{} cannot be used: the module is in the FIPS 140-3 error state since the {} \
             self-test failed",
            algorithm.name(),
            cause.name()
        );
    }
}

/// The algorithm whose failure put the module in the error state, or `None` if it is not in it.
pub fn error_state() -> Option<SelfTestedAlgorithm> {
    // Only `enter_error_state` writes ERROR_STATE, and only NO_ERROR (which `ALL.get` maps to None)
    // or an index into ALL.
    SelfTestedAlgorithm::ALL.get(usize::from(ERROR_STATE.load(Ordering::Acquire))).copied()
}

// The error state stores a cause as its index, and a process can enter the error state only once,
// so the integration tests can round-trip one cause each; this checks every index at once.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_is_the_position_in_all() {
        for (i, algorithm) in SelfTestedAlgorithm::ALL.iter().enumerate() {
            assert_eq!(usize::from(algorithm.index()), i, "{}", algorithm.name());
        }
    }
}
