//! FIPS 140-3 cryptographic algorithm self-tests (CASTs) for bc-rust's AES and SHA-2.
//!
//! **This is a self-test prototype, not a validated module.** It implements the known-answer
//! self-tests FIPS 140-3 requires for AES and SHA-2, the gates that keep those algorithms unusable
//! until the self-tests pass, and the error state a failure enters. It is not a FIPS 140-3
//! validated cryptographic module, and using it does not make an application one: a validation
//! also needs, at least, a software integrity test that is on in every build (here it is the
//! `integrity` feature, with its post-link tool `bc-fips-install`), an approved service
//! indicator, a defined cryptographic boundary, self-tests for every other approved algorithm
//! offered (the DRBG, SHA-3, ML-KEM, ML-DSA, ...) and a CMVP certificate. `APPROACHES.md`
//! beside this crate lists what is still missing.
//!
//! Each algorithm crate carries its own self-test and status behind its `fips` cargo feature
//! (`bouncycastle_aes::self_test`, `bouncycastle_sha2::self_test`); this crate turns those features
//! on and runs the self-tests in order. The status of each algorithm lives in, and can only be set
//! to passed by, the crate that implements it. A failure of any of them puts the whole module in
//! the error state (`bouncycastle_core::fips::error_state`), which every gate reads.
//!
//! An application that needs the self-tests depends on this crate, calls
//! [`power_on_self_tests`] once at startup, and may call [`run_self_tests`] again at any time.
//! Until an algorithm's self-test has passed, its services refuse to be created: where the
//! constructor already returns a `Result` (an AES key from key material) it returns
//! [`bouncycastle_core::errors::SymmetricCipherError::SelfTestNotPassed`]; where it is
//! infallible (`SHA256::new()`, a one-shot `hash()`) it panics, and `from_suspended` returns
//! `SuspendableError::SelfTestNotPassed`. Once any self-test has failed, the module is in the
//! error state until the program restarts: no service can be created, and every service that
//! already exists -- a key, a worker, a hash in progress -- panics on its next operation, since
//! none of those operations returns an error for it. No self-test runs before `main`.
//!
//! The cargo features select which algorithms are self-tested and gated:
//!
//! | Feature | Self-tested algorithm | Services gated |
//! |---|---|---|
//! | `aes` | [`SelfTestedAlgorithm::AES`] | every AES mode and key size |
//! | `sha2` | [`SelfTestedAlgorithm::SHA256`], [`SelfTestedAlgorithm::SHA512`], [`SelfTestedAlgorithm::HMAC_SHA512`] | SHA-224, SHA-256; SHA-384, SHA-512, SHA-512/224, SHA-512/256; none for HMAC-SHA-512 |
//! | `integrity` (implies `sha2`; off by default; ELF only) | [`SelfTestedAlgorithm::SoftwareIntegrity`] | every service of the module, through the error state |
//!
//! The self-tests run in this order: SHA-256 and SHA-512, HMAC-SHA-512, the software integrity
//! test, AES. HMAC-SHA-512 needs SHA-512, whose gate refuses until its own self-test has passed;
//! the integrity test uses HMAC-SHA-512, which must pass first (ISO/IEC 19790:2012 7.10.1 [10.20]).
//!
//! # The software integrity test
//!
//! With the `integrity` feature, power-on also runs the pre-operational software integrity test
//! (ISO/IEC 19790:2012 7.10.2.2): an HMAC-SHA-512 over the program's own read-only loaded
//! segments, compared with a value the post-link tool `bc-fips-install` (beside this crate)
//! writes into a slot in the finished binary.
//! It covers the whole program, not only this module's code, because cross-crate inlining and
//! LTO put module code inside the application's functions. [`binary_hmac`] has the format, which
//! is a contract with that tool. **Until the tool has run on a binary, its slot is empty and
//! power-on fails**, so the feature is off by default; the tests of this crate run with it as
//! `cargo test --manifest-path crypto/fips/Cargo.toml --features integrity --tests` (the doc
//! examples power on, so they fail under it).
//!
//! # Usage Examples
//!
//! Power on once, first thing in `main`, and stop if it fails:
//!
//! ```
//! use bouncycastle_fips::{power_on_self_tests, self_test_status, SelfTestStatus, SelfTestedAlgorithm};
//!
//! if let Err(e) = power_on_self_tests() {
//!     eprintln!("FIPS 140-3 self-tests failed: {e:?}");
//!     std::process::exit(1);
//! }
//! assert_eq!(self_test_status(SelfTestedAlgorithm::AES), SelfTestStatus::Passed);
//! ```
//!
//! Then use the algorithms as usual. Re-run the self-tests on demand -- the periodic self-test of
//! IG 10.3.E -- and report each algorithm's status; services stay usable while it runs:
//!
//! ```
//! use bouncycastle_fips::{power_on_self_tests, run_self_tests, self_test_status, SELF_TESTED};
//!
//! power_on_self_tests().expect("self-tests pass");
//! let result = run_self_tests();
//! for algorithm in SELF_TESTED {
//!     println!("{}: {:?}", algorithm.name(), self_test_status(*algorithm));
//! }
//! result.expect("self-tests pass again");
//! ```
//!
//! What an application sees in the error state (here entered by hand, as a failing self-test
//! enters it): the self-tests do not run again, and every AES key is refused.
//!
//! ```no_run
//! use bouncycastle_aes::AES128Key;
//! use bouncycastle_cipher::modes::GCM;
//! use bouncycastle_core::errors::SymmetricCipherError;
//! use bouncycastle_core::fips::enter_error_state;
//! use bouncycastle_core::key_material::{KeyMaterial128, KeyType};
//! use bouncycastle_core::symmetric_key::FromKeyMaterial;
//! use bouncycastle_fips::{power_on_self_tests, SelfTestError, SelfTestStatus, SelfTestedAlgorithm};
//!
//! power_on_self_tests().expect("self-tests pass");
//! enter_error_state(SelfTestedAlgorithm::SHA256);
//! assert_eq!(
//!     power_on_self_tests(),
//!     Err(SelfTestError::NotPassed(SelfTestedAlgorithm::SHA256, SelfTestStatus::Failed))
//! );
//! let material = KeyMaterial128::from_bytes_as_type(&[0x42; 16], KeyType::SymmetricCipherKey)
//!     .unwrap();
//! assert_eq!(
//!     AES128Key::<GCM>::from_key_material(&material).err(),
//!     Some(SymmetricCipherError::SelfTestNotPassed(SelfTestStatus::Failed))
//! );
//! ```
//!
//! To self-test and gate only one of the algorithms, turn the default features off:
//!
//! ```toml
//! bouncycastle-fips = { version = "0.1.4", default-features = false, features = ["aes"] }
//! ```
//!
//! `examples/crypto_officer.rs` runs the whole flow, including what an application that skips
//! power-on sees; the `bc-rust` CLI's `fips` feature does the same for every command.
//!
//! # Requirements
//!
//! Read from *Implementation Guidance for FIPS 140-3 and the Cryptographic Module Validation
//! Program* (NIST CMVP), last update 2026-08-19, downloaded 2026-11-10 from
//! <https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf>.
//! The self-test section is **IG 10.3.A, "Cryptographic Algorithm Self-Test Requirements"**
//! (last modified 2026-08-19); bracketed numbers are the ISO/IEC 19790:2012 shall-statements
//! the IG quotes.
//!
//! When:
//! * A CAST is performed "prior to the first operational use of the cryptographic algorithm"
//!   (§7.10.3.2 [10.27]), and pass or fail is decided by the module "without external controls,
//!   externally provided input [test] text vectors, expected output results, or operator
//!   intervention" (§7.10.1 [10.01], [10.02]): vectors and answers are compiled in.
//! * The CAST of an algorithm must have run before *any* of its services is used, even when it
//!   exercises a different mode or key size (GeneralNote4: one AES GCM CAST covering GCM and ECB
//!   "shall be performed prior to the first use of either"). Different functions of one algorithm
//!   may be self-tested at different times, each before its own first use (GeneralNote4, second
//!   paragraph).
//! * Re-running is a periodic self-test (IG 10.3.E). At Security Levels 1 and 2 "a provided
//!   service, resetting, rebooting or power cycling" are acceptable triggers; Levels 3 and 4
//!   must re-run automatically on a defined period [10.54]. A repeated CAST "may be run in the
//!   background without the need for inhibiting data output" (IG 10.3.E Resolution 5).
//! * A service that performs on-demand self-tests needs an approved service indicator; re-running
//!   by restart does not (IG 2.4.C).
//!
//! What, for AES (IG 10.3.A Resolution 1):
//! * The smallest approved key length the module supports [10.29], and one the module offers as
//!   a service (GeneralNote5): AES-128.
//! * One authenticated mode from GCM, CCM, CMAC or GMAC (1.d(i)), self-tested in both directions
//!   as separate CASTs (1.a, 1.b). That covers KW/KWP (1.d(ii)) and the confidentiality-only
//!   modes ECB, CBC, CFB, CTR (1.d(iii)).
//! * The forward cipher at least once and the inverse cipher at least once (1.c). GCM uses only the
//!   forward cipher, so a decryption CAST on a mode whose decryption uses the inverse cipher
//!   ("ECB, CBC, XTS, KW, KWP") is also needed. Encrypt and decrypt "do not need to be performed
//!   for each mode(s) that is selected to meet this cipher function requirement".
//! * 1.d asks for the authenticated-mode CAST "for each underlying algorithm implementation (i.e.
//!   AES and Triple-DES)"; `bouncycastle-aes` has a single (bit-sliced, software) AES.
//!
//! What, for SHA-2 (IG 10.3.A Resolution 2): "a CAST for SHA-256 is required" and "a CAST for
//! SHA-512 is required". SHA-224 needs its own only "if SHA-224 is implemented without SHA-256",
//! SHA-384 only "if SHA-384 is implemented without SHA-512", SHA-512/224 or /256 only "if the
//! SHA-512 CAST is not performed". A SHA-1 CAST is required if SHA-1 is implemented; bc-rust
//! has none.
//!
//! What, for HMAC (IG 10.3.A Resolution 4): "a CAST for HMAC is required and shall be performed
//! with the HMAC function using at least one of the implemented underlying SHA-1, SHA-2, or SHA-3
//! algorithms". HMAC-SHA-512, since it is the algorithm of the software integrity test.
//!
//! On failure:
//! * A known-answer test whose output differs from the known answer "shall fail" (§7.10.3.2
//!   [10.28]). An answer may be compared through a hash only if that hash has itself been
//!   self-tested first (GeneralNote7).
//! * The module goes into an error state and inhibits data output (AS03.07, as IG 1.B and IG
//!   10.3.E Resolution 5 cite it; GeneralNote6 says the same for comparison tests). Per AS10.07
//!   as IG 1.B applies it, a failed self-test puts the *entire* module in the error state, not
//!   just the failed algorithm.
//! * **Not in the IG:** the text of AS10.07 to AS10.11 (ISO/IEC 19790:2012 §7.10.1 and ISO/IEC
//!   24759), which state the error-state behaviour, the error indicator and how a module leaves
//!   the error state. Those documents are not freely available. Project decision (2026-11-10), in
//!   their absence: a failure of any self-test blocks every gated algorithm, and only a restart
//!   of the program leaves the error state; a later run of the self-tests does not clear it.
//!
//! # Known-answer vectors
//!
//! The minimal set the requirements above call for. All values hex; every one was checked
//! against the source named.
//!
//! | CAST | Covers | Source | Inputs | Expected |
//! |---|---|---|---|---|
//! | SHA-256 | SHA-256, SHA-224 | CAVP SHAVS byte-oriented (CAVS 11.0), `bc-test-data/crypto/sha2/byte-oriented/SHA256ShortMsg.rsp`, `[L = 32]`, `Len = 24` | Msg `b4190e` | `dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2` |
//! | SHA-512 | SHA-512, SHA-384, SHA-512/224, SHA-512/256 | same suite, `SHA512ShortMsg.rsp`, `[L = 64]`, `Len = 24` | Msg `0a55db` | `7952585e5330cb247d72bae696fc8a6b0f7d0804577e347d99bc1b11e52f384985a428449382306a89261ae143c2f3fb613804ab20b42dc097e5bf4a96ef919b` |
//! | HMAC-SHA-512 | HMAC (Resolution 4) | RFC 4231 Section 4.2, "Test Case 1" | Key `0b` x 20, Data `4869205468657265` ("Hi There") | `87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854` |
//! | AES-GCM-128 encrypt | 1.a, 1.d(i), forward cipher (1.c) | CAVP `gcmtestvectors.zip` (CAVS 14.0), `bc-test-data/crypto/aes_tdes_vectors/GCM/cavp/gcmEncryptExtIV128.rsp`, `[Keylen = 128] [IVlen = 96] [PTlen = 128] [AADlen = 128] [Taglen = 128]`, `Count = 0` | Key `c939cc13397c1d37de6ae0e1cb7c423c`, IV `b3d8cc017cbb89b39e0f67e2`, PT `c3b3c41f113a31b73d9a5cd432103069`, AAD `24825602bd12a984e0092d3e448eda5f` | CT `93fe7d9e9bfd10348a5606e5cafa7354`, Tag `0032a1dc85f1c9786925a2e71d8272dd` |
//! | AES-GCM-128 decrypt | 1.b | the same vector, decrypting CT and Tag (1.b: "the data could be the encrypted value computed during the encryption test") | Key, IV, AAD, CT, Tag as above | PT as above, tag accepted |
//! | AES-CBC-128 decrypt | inverse cipher (1.c) | NIST SP 800-38A (2001), Appendix F.2.2 "CBC-AES128.Decrypt" | Key `2b7e151628aed2a6abf7158809cf4f3c`, IV `000102030405060708090a0b0c0d0e0f`, CT `7649abac8119b246cee98e9b12e9197d` `5086cb9b507219ee95db113a917678b2` `73bed6b8e3c1743b7116e69e22229516` `3ff1caa1681fac09120eca307586e1a7` | PT `6bc1bee22e409f96e93d7e117393172a` `ae2d8a571e03ac9c9eb76fac45af8e51` `30c81c46a35ce411e5fbc1191a0a52ef` `f69f2445df4f9b17ad2b417be66c3710` |
//!
//! Not needed: a CBC encryption CAST (the forward cipher is covered by GCM encryption, 1.c), and
//! CASTs for AES-192/256, other modes, SHA-224, SHA-384 or SHA-512/t (covered above).
//!
//! # Feature unification
//!
//! Cargo unifies the features of a package across everything built together, so if any
//! workspace member turned on `bouncycastle-aes/fips`, every AES test in `cargo test --workspace`
//! would run gated, find no self-test run, and fail. This crate is therefore **excluded from the
//! root workspace** (`exclude = ["crypto/fips"]`) and is its own workspace root, the way
//! `dev_scripts/aes_ct_harness` is:
//!
//! * `cargo build --workspace` / `cargo test --workspace` never build it and see no `fips`
//!   feature. Build and test it with `cargo test --manifest-path crypto/fips/Cargo.toml`
//!   (add `--no-default-features --features aes` and so on for one algorithm). It has its own
//!   `target/` and `Cargo.lock`, both ignored by git.
//! * No workspace member may depend on it, or on an algorithm crate's `fips` feature, except
//!   behind an off-by-default feature of its own, as the CLI's `fips` feature does. CI's
//!   `cargo build --workspace --all-features` still compiles such a feature, which is harmless;
//!   its tests run on their own, never under `--all-features` across the workspace.
//! * `cargo mutants` no longer passes `--all-features` (`.cargo/mutants.toml`), which would turn
//!   on a crate's own `fips` feature under `-p`. The `fips` code is mutated with an explicit
//!   `--features fips` on the crate that owns it.
//!
//! # Memory Usage
//!
//! Peak stack, measured on x86-64 in a release build by painting the stack below the call
//! (includes return addresses; an empty call measures 8 B):
//!
//! | Call | Peak stack |
//! |---|---|
//! | [`power_on_self_tests`], first call / [`run_self_tests`] | 1964 B |
//! | [`power_on_self_tests`] after it has passed | 40 B |
//! | `bouncycastle_aes::self_test` | 1948 B |
//! | `bouncycastle_sha2::self_test` | 1320 B |
//!
//! The state is a byte per algorithm and one for the module error state, all in `static`s. With
//! the `fips` feature each SHA-2 hash is 8 bytes larger (whether its output is gated).
//!
//! # 🚨 Security Considerations 🚨
//!
//! * **Not a validated module.** See the top of this page for what a validation needs beyond
//!   these self-tests. HKDF and the Hash_DRBG become usable as soon as SHA-2 passes, but have no
//!   self-test of their own here (FIPS 140-3 IG 10.3.A Resolution 6 requires them): they cannot
//!   be claimed as approved services of a build using this crate. HMAC has its CAST, but HMAC
//!   services are gated only on SHA-2, not on it.
//! * **The gates are build-wide.** Cargo turns a feature on for the whole build if any one
//!   dependency asks for it, so once anything in a program depends on this crate, every AES key
//!   and SHA-2 hash in that program, in every library, is refused until [`power_on_self_tests`]
//!   has passed. Call it first, before starting threads or initialising libraries that hash or
//!   encrypt at startup.
//! * **One module per process, and per copy of `bouncycastle-core`.** The statuses and the error
//!   state are process-global `static`s. A program that links two versions of
//!   `bouncycastle-core` (or of an algorithm crate) has two independent sets, and a failure in one
//!   does not stop the other.
//! * **The error state is permanent and panics.** After a failure, every existing key, worker and
//!   hash panics on its next operation, including in code that does not expect a panic. Under
//!   `panic = "abort"` that ends the process; under unwinding, code that catches the panic must not
//!   treat the operation as having produced output.
//! * **Anyone can stop the module.** `bouncycastle_core::fips::enter_error_state` is public so
//!   that any crate can report a failure (a pairwise consistency test, later). Nothing can clear
//!   it or record a pass, but any code in the process can stop every gated algorithm with it.
//! * **The integrity test detects corruption, not an attacker.** Its key is public and its value
//!   sits in the binary it checks, so whoever can rewrite a segment can rewrite the value. It
//!   does not cover writable segments. Without the `integrity` feature there is none.
//! * **`unsafe` code.** The integrity test reads the program's own headers and segments at the
//!   addresses the loader mapped them to, and the slot with a volatile read; that is the crate's
//!   only `unsafe` code, and only with the `integrity` feature.
//! * **The self-tests detect a faulty implementation**, not misuse: they say nothing about how
//!   keys, nonces or IVs are chosen.

#![no_std]
#![deny(unsafe_code)]
#![forbid(missing_docs)]

pub use bouncycastle_core::fips::{SelfTestError, SelfTestStatus, SelfTestedAlgorithm};

use bouncycastle_core::fips::error_state;

#[cfg(feature = "aes")]
use bouncycastle_aes as aes;
#[cfg(feature = "sha2")]
use bouncycastle_sha2 as sha2;

#[cfg(feature = "sha2")]
pub mod binary_hmac;
#[cfg(feature = "sha2")]
mod hmac_self_test;
#[cfg(feature = "integrity")]
mod integrity;

/// The algorithms whose self-tests this build runs, in the order they run: those of the
/// enabled cargo features, hashes first, then HMAC-SHA-512, then the software integrity test.
pub const SELF_TESTED: &[SelfTestedAlgorithm] = &[
    #[cfg(feature = "sha2")]
    SelfTestedAlgorithm::SHA256,
    #[cfg(feature = "sha2")]
    SelfTestedAlgorithm::SHA512,
    #[cfg(feature = "sha2")]
    SelfTestedAlgorithm::HMAC_SHA512,
    #[cfg(feature = "integrity")]
    SelfTestedAlgorithm::SoftwareIntegrity,
    #[cfg(feature = "aes")]
    SelfTestedAlgorithm::AES,
];

/// One self-test entry point: an algorithm crate's, or one of this crate's own.
struct Crate {
    /// The algorithms its one `self_test` covers.
    algorithms: &'static [SelfTestedAlgorithm],
    self_test: fn() -> Result<(), SelfTestError>,
}

/// The enabled crates, in the order of [`SELF_TESTED`].
const CRATES: &[Crate] = &[
    #[cfg(feature = "sha2")]
    Crate {
        algorithms: &[SelfTestedAlgorithm::SHA256, SelfTestedAlgorithm::SHA512],
        self_test: sha2::self_test,
    },
    #[cfg(feature = "sha2")]
    Crate { algorithms: &[SelfTestedAlgorithm::HMAC_SHA512], self_test: hmac_self_test::self_test },
    // The integrity test uses HMAC-SHA-512, which must pass first (ISO/IEC 19790:2012 7.10.1
    // [10.20]); it runs before the remaining self-tests. The module HMAC goes after it.
    #[cfg(feature = "integrity")]
    Crate {
        algorithms: &[SelfTestedAlgorithm::SoftwareIntegrity],
        self_test: integrity::self_test,
    },
    #[cfg(feature = "aes")]
    Crate { algorithms: &[SelfTestedAlgorithm::AES], self_test: aes::self_test },
];

/// Runs the self-test of every algorithm in [`SELF_TESTED`] that has not passed yet. Call once at
/// startup, before creating any service of those algorithms; calling it again after it succeeded
/// does nothing.
///
/// # Errors
///
/// [`SelfTestError::KnownAnswerMismatch`] for the first algorithm whose self-test fails; every
/// gated service then refuses to be created until the program restarts. After such a failure,
/// [`SelfTestError::NotPassed`] with [`SelfTestStatus::Failed`] for the failed algorithm, without
/// running anything. A call made while another thread is running a self-test waits for that run
/// and reports its result, so concurrent calls all succeed or all fail.
pub fn power_on_self_tests() -> Result<(), SelfTestError> {
    run(true)
}

/// Runs the self-test of every algorithm in [`SELF_TESTED`] again, whether or not it passed
/// before: the on-demand periodic self-test (FIPS 140-3 IG 10.3.E). Services stay available
/// while it runs. It cannot clear a failure; only a restart does.
///
/// # Errors
///
/// As [`power_on_self_tests`].
pub fn run_self_tests() -> Result<(), SelfTestError> {
    run(false)
}

/// The current status of `algorithm`'s self-test. An algorithm this build does not self-test
/// (not in [`SELF_TESTED`]) is always [`SelfTestStatus::NotRun`]. Once any self-test has failed,
/// every algorithm in [`SELF_TESTED`] reports [`SelfTestStatus::Failed`].
pub fn self_test_status(algorithm: SelfTestedAlgorithm) -> SelfTestStatus {
    match algorithm {
        #[cfg(feature = "sha2")]
        SelfTestedAlgorithm::SHA256 => sha2::sha256_self_test_status(),
        #[cfg(feature = "sha2")]
        SelfTestedAlgorithm::SHA512 => sha2::sha512_self_test_status(),
        #[cfg(feature = "sha2")]
        SelfTestedAlgorithm::HMAC_SHA512 => hmac_self_test::status(),
        #[cfg(feature = "integrity")]
        SelfTestedAlgorithm::SoftwareIntegrity => integrity::status(),
        #[cfg(feature = "aes")]
        SelfTestedAlgorithm::AES => aes::self_test_status(),
        _ => SelfTestStatus::NotRun,
    }
}

/// [`power_on_self_tests`] (`skip_passed`) and [`run_self_tests`].
fn run(skip_passed: bool) -> Result<(), SelfTestError> {
    // The module error state, whoever entered it: report the algorithm that failed first.
    if let Some(failed) = error_state() {
        return Err(SelfTestError::NotPassed(failed, SelfTestStatus::Failed));
    }
    for c in CRATES {
        if skip_passed
            && c.algorithms.iter().all(|a| self_test_status(*a) == SelfTestStatus::Passed)
        {
            continue;
        }
        // A failing self-test enters the module error state itself, which stops every crate.
        (c.self_test)()?;
    }
    Ok(())
}
