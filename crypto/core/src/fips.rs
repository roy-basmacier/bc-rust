//! Types shared by the FIPS 140-3 cryptographic algorithm self-tests (CASTs).
//!
//! Only present with the `fips` cargo feature. These are vocabulary types: the status of one
//! self-tested algorithm, which algorithm it is, and the errors a self-test or a gated service
//! reports. Where a status is stored and which code may change it are left to the crate that
//! runs the self-tests; `bouncycastle-fips` documents the requirements they implement.

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
}
