//! Types shared by the FIPS 140-3 cryptographic algorithm self-tests (CASTs).
//!
//! Only present with the `fips` cargo feature. The vocabulary types (the status of one
//! self-tested algorithm, which algorithm it is, the errors a self-test or a gated service
//! reports), and the process-wide status table:
//!
//! * the algorithm crates' gated constructors read it, through [`check_self_test`] where they
//!   return a `Result` and [`assert_self_test`] where they cannot;
//! * `bouncycastle-fips`, which holds the self-tests, writes it through
//!   [`set_self_test_status`], which accepts writes from one [`SelfTestStatusWriter`] only.
//!
//! `bouncycastle-fips` documents the requirements they implement.

use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};

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
    /// The status as the `u8` that [`SelfTestStatusCell`] stores.
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

/// A [`SelfTestStatus`] that can be read and written from several threads, for use in a
/// `static`. Starts as [`SelfTestStatus::NotRun`].
///
/// A write made with [`SelfTestStatusCell::set`] is seen by every later
/// [`SelfTestStatusCell::get`] on any thread, together with everything the writing thread did
/// before it.
#[derive(Debug)]
pub struct SelfTestStatusCell(AtomicU8);

impl SelfTestStatusCell {
    /// A cell holding [`SelfTestStatus::NotRun`].
    pub const fn new() -> Self {
        Self(AtomicU8::new(SelfTestStatus::NotRun.as_u8()))
    }

    /// The current status.
    pub fn get(&self) -> SelfTestStatus {
        // Only `set` writes the cell, and it writes only `as_u8` values, so `from_u8` cannot
        // fail; `Failed` is the safe reading should that ever stop being true.
        SelfTestStatus::from_u8(self.0.load(Ordering::Acquire)).unwrap_or(SelfTestStatus::Failed)
    }

    /// Replaces the status.
    pub fn set(&self, status: SelfTestStatus) {
        self.0.store(status.as_u8(), Ordering::Release);
    }
}

impl Default for SelfTestStatusCell {
    fn default() -> Self {
        Self::new()
    }
}

/// An algorithm that has its own self-test, named as FIPS 140-3 IG 10.3.A names the CASTs.
///
/// One algorithm's self-test covers every variant of it the library offers: [`Self::AES`] covers
/// all AES modes and key sizes, [`Self::SHA256`] covers SHA-224 and SHA-256, and [`Self::SHA512`]
/// covers SHA-384, SHA-512, SHA-512/224 and SHA-512/256.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SelfTestedAlgorithm {
    /// AES (FIPS 197), in every mode.
    AES,
    /// SHA-256 (FIPS 180-4), also covering SHA-224.
    SHA256,
    /// SHA-512 (FIPS 180-4), also covering SHA-384, SHA-512/224 and SHA-512/256.
    SHA512,
}

impl SelfTestedAlgorithm {
    /// Every self-tested algorithm, in the order the self-tests run.
    ///
    /// The hashes come first so that a known-answer test compared through a hash (FIPS 140-3 IG
    /// 10.3.A, GeneralNote7) only ever uses a hash that has already passed.
    pub const ALL: [Self; 3] = [Self::SHA256, Self::SHA512, Self::AES];

    /// The algorithm's name as the self-test reports it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::AES => "AES",
            Self::SHA256 => "SHA-256",
            Self::SHA512 => "SHA-512",
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
    /// The status table already has a different writer (see [`set_self_test_status`]), so this
    /// self-test run cannot record its results.
    StatusWriterTaken,
}

impl SelfTestedAlgorithm {
    /// This algorithm's entry in the status table.
    fn status_cell(self) -> &'static SelfTestStatusCell {
        match self {
            Self::AES => &AES_STATUS,
            Self::SHA256 => &SHA256_STATUS,
            Self::SHA512 => &SHA512_STATUS,
        }
    }
}

// The status table: one cell per self-tested algorithm, private to this module. Reads go through
// `self_test_status` and the two gate functions; writes only through `set_self_test_status`.
static AES_STATUS: SelfTestStatusCell = SelfTestStatusCell::new();
static SHA256_STATUS: SelfTestStatusCell = SelfTestStatusCell::new();
static SHA512_STATUS: SelfTestStatusCell = SelfTestStatusCell::new();

/// The current status of `algorithm`'s self-test.
pub fn self_test_status(algorithm: SelfTestedAlgorithm) -> SelfTestStatus {
    algorithm.status_cell().get()
}

/// The gate for a constructor that returns a `Result`: `Ok` if a service of `algorithm` may be
/// created now.
///
/// A service may be created while the algorithm's self-test is [`SelfTestStatus::Passed`] or
/// [`SelfTestStatus::Running`], and while no self-tested algorithm is
/// [`SelfTestStatus::Failed`].
///
/// # Errors
/// The status that refuses: [`SelfTestStatus::Failed`] if any self-test has failed (the whole
/// module is then in the error state), otherwise the algorithm's own status, which is
/// [`SelfTestStatus::NotRun`].
pub fn check_self_test(algorithm: SelfTestedAlgorithm) -> Result<(), SelfTestStatus> {
    // FIPS 140-3 IG 1.B, as `bouncycastle-fips` records it: a failure of any self-test puts the
    // entire module in the error state, so a failed SHA-256 blocks AES too.
    for other in SelfTestedAlgorithm::ALL {
        if other.status_cell().get() == SelfTestStatus::Failed {
            return Err(SelfTestStatus::Failed);
        }
    }
    // `Running` is admitted so that the self-test can create the services it tests through the
    // same gated constructors as everyone else. It admits every other thread too: see
    // `bouncycastle-fips`'s "Self-test in progress".
    match algorithm.status_cell().get() {
        SelfTestStatus::Passed | SelfTestStatus::Running => Ok(()),
        refused => Err(refused),
    }
}

/// The gate for a constructor that cannot return an error: [`check_self_test`], panicking where it
/// would refuse.
///
/// # Panics
/// Where [`check_self_test`] returns `Err`: if `algorithm`'s self-test has not been run, or any
/// self-test has failed.
#[track_caller]
pub fn assert_self_test(algorithm: SelfTestedAlgorithm) {
    if let Err(status) = check_self_test(algorithm) {
        panic!("the {} FIPS self-test has not passed: {:?}", algorithm.name(), status);
    }
}

/// The identity of the one piece of code allowed to write the status table, by the address of a
/// `static` of this type.
///
/// The first call to [`set_self_test_status`] in the program records the address of the writer it
/// was given; every later call must give the same `static`, and is refused otherwise.
/// `bouncycastle-fips` keeps its writer in a private `static`, so once it has written a status no
/// other code can. Nothing stops other code from writing first: see
/// [`set_self_test_status`].
#[derive(Debug)]
pub struct SelfTestStatusWriter {
    // Never read; it is here for its address. An atomic, rather than a plain `u8`, makes the type
    // interior-mutable, which keeps a `&SelfTestStatusWriter::new()` from being promoted to a
    // constant that the compiler or linker could merge with another writer of the same value.
    _identity: AtomicU8,
}

impl SelfTestStatusWriter {
    /// A writer, for a `static`.
    pub const fn new() -> Self {
        Self { _identity: AtomicU8::new(0) }
    }
}

impl Default for SelfTestStatusWriter {
    fn default() -> Self {
        Self::new()
    }
}

/// The writer every status write must come from: null until the first write claims it.
static STATUS_WRITER: AtomicPtr<SelfTestStatusWriter> = AtomicPtr::new(ptr::null_mut());

/// Records `status` as `algorithm`'s self-test status, on behalf of `writer`.
///
/// The first call in the program makes `writer` the only one this function accepts from then on.
/// [`SelfTestStatus::Failed`] is final: a failed algorithm keeps that status until the program
/// restarts, and a write of any other status to it is refused.
///
/// # 🚨 Security Considerations 🚨
///
/// Any crate can call this. The calls `bouncycastle-fips` makes cannot be undone or overwritten
/// by other code once its first write has happened, but code that writes before it -- before
/// `bouncycastle_fips::power_on_self_tests` is first called -- becomes the writer, can record
/// [`SelfTestStatus::Passed`] for an algorithm that was never tested, and makes every
/// `bouncycastle-fips` run fail with [`SelfTestError::StatusWriterTaken`].
///
/// # Errors
/// * [`SelfTestError::StatusWriterTaken`] if a different writer made the first write; nothing is
///   recorded.
/// * [`SelfTestError::NotPassed`] with [`SelfTestStatus::Failed`] if `algorithm` has failed and
///   `status` is not `Failed`; the failure stays recorded.
pub fn set_self_test_status(
    writer: &'static SelfTestStatusWriter,
    algorithm: SelfTestedAlgorithm,
    status: SelfTestStatus,
) -> Result<(), SelfTestError> {
    // Compared by address only; the pointer is never dereferenced.
    let claimant = ptr::from_ref(writer).cast_mut();
    match STATUS_WRITER.compare_exchange(
        ptr::null_mut(),
        claimant,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {}
        Err(current) if current == claimant => {}
        Err(_) => return Err(SelfTestError::StatusWriterTaken),
    }

    // A compare-and-swap loop rather than a load and a store, so that a `Failed` written by one
    // thread cannot be overwritten by another thread's `Passed` that read the old value first.
    let cell = &algorithm.status_cell().0;
    let mut current = cell.load(Ordering::Acquire);
    loop {
        if current == SelfTestStatus::Failed.as_u8() {
            // Writing `Failed` again is not an error; anything else would clear the failure.
            return match status {
                SelfTestStatus::Failed => Ok(()),
                _ => Err(SelfTestError::NotPassed(algorithm, SelfTestStatus::Failed)),
            };
        }
        match cell.compare_exchange_weak(
            current,
            status.as_u8(),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(()),
            Err(seen) => current = seen,
        }
    }
}
