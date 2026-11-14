//! FIPS 140-3 cryptographic algorithm self-tests (CASTs) for bc-rust's AES, SHA-2, HMAC-SHA-512,
//! ECDSA and ECC CDH, and pair-wise consistency tests on generated EC key pairs.
//!
//! **This is a self-test prototype, not a validated module.** It implements the known-answer
//! self-tests FIPS 140-3 requires for those algorithms, the gates that keep them unusable until
//! the self-tests pass, the pair-wise consistency test on every ECDSA and ECC CDH key pair
//! generated, and the error state a failure enters. It is not a FIPS 140-3
//! validated cryptographic module, and using it does not make an application one: a validation
//! also needs, at least, a software integrity test that is on in every build (here it is the
//! `integrity` feature, with its post-link tool `bc-fips-install`), an approved service
//! indicator, a defined cryptographic boundary, self-tests for every other approved algorithm
//! offered (the DRBG, SHA-3, the KDFs, ...) and a CMVP certificate. `APPROACHES.md`
//! beside this crate lists what is still missing.
//!
//! Each algorithm crate carries its own self-test and status behind its `fips` cargo feature
//! (`bouncycastle_aes::self_test`, `bouncycastle_sha2::self_test`, `bouncycastle_ecdsa::self_test`,
//! `bouncycastle_eccdh::self_test`); this crate turns those features
//! on and runs the self-tests in order. The status of each algorithm lives in, and can only be set
//! to passed by, the crate that implements it. A failure of any of them puts the whole module in
//! the error state (`bouncycastle_core::fips::error_state`), which every gate reads.
//!
//! An application that needs the self-tests depends on this crate, calls
//! [`power_on_self_tests`] once at startup, and may call [`run_self_tests`] again at any time.
//! Until an algorithm's self-test has passed, its services refuse to be created: where the
//! constructor already returns a `Result` (an AES key from key material) it returns
//! [`bouncycastle_core::errors::SymmetricCipherError::SelfTestNotPassed`], and an EC key pair,
//! signer, verifier or agreement `SignatureError::SelfTestNotPassed` or
//! `KeyAgreementError::SelfTestNotPassed`; where it is
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
//! | `ecdsa` (implies `sha2`) | [`SelfTestedAlgorithm::ECDSA`] | ECDSA key generation (with a pair-wise consistency test), signing with a random and a deterministic `k`, and verification, on every curve and hash |
//! | `eccdh` | [`SelfTestedAlgorithm::ECC_CDH`] | ECC CDH key generation (with a pair-wise consistency test) and agreement, raw and with every KDF, on every curve |
//! | `integrity` (implies `sha2`; off by default; ELF only) | [`SelfTestedAlgorithm::SoftwareIntegrity`] | every service of the module, through the error state |
//! | `fips-validated` (implies `sha2`; off by default) | [`SelfTestedAlgorithm::ModuleIntegrity`] | every service of the module, through the error state |
//! | `approved-only` (off by default) | none | none; the build refuses non-approved features of the module crates, and the `approved` module offers the approved services as concrete types |
//!
//! The self-tests run in this order: SHA-256 and SHA-512, HMAC-SHA-512, the software integrity
//! test, the module integrity check, AES, ECDSA, ECC CDH. HMAC-SHA-512 needs SHA-512, whose gate refuses until its own self-test has passed;
//! the integrity test uses HMAC-SHA-512, which must pass first (ISO/IEC 19790:2012 7.10.1 [10.20]);
//! ECDSA hashes with SHA-256, and `bouncycastle_ecdsa::self_test` refuses to start until SHA-256
//! has passed.
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
//! power-on fails**, so the feature is off by default. The tests of this crate run with it as
//! `cargo test --manifest-path crypto/fips/Cargo.toml --features integrity`: they check the
//! failure, and the doc examples that power on return early under it.
//!
//! # The module source pin
//!
//! Every build embeds the module table: each crate inside the module boundary
//! ([`module_table`]), with the HMAC-SHA-512 of its sources under the public key
//! [`MODULE_HMAC_KEY`], and the record of the toolchain that built it ([`toolchain`]). The module
//! HMAC ([`module_hmac`]) is derived from the table at run time. It depends only on the sources,
//! not on the program that links the module or on how it was built, so it is the value a
//! validated version publishes in its Security Policy, and anyone can recompute it from a
//! checkout with `dev_scripts/fips_module_hmac.py`.
//!
//! The table also has a row for each crate from crates.io inside the boundary (`getrandom`,
//! `cfg-if`, `libc`, `r-efi`), made from its pinned name, version and registry checksum
//! ([`external_crates`]). This crate's `Cargo.toml` asks for those versions with `=`, so a
//! program that uses the module resolves to exactly them or does not build. A `[patch]` or a
//! replaced source can keep the version and change the contents, and only the program's
//! `Cargo.lock` shows that. The independent script checks the lock (`--lock`); see
//! crypto/fips/EXTERNAL_CRATES.md.
//!
//! With the `fips-validated` feature, the build fails unless the module HMAC equals the published
//! constant compiled into this crate, and power-on checks it again (the module integrity check).
//! Without it, nothing is compared. **No version is validated yet**: the constant is the module
//! HMAC of the current sources, so any change to a module crate fails a `fips-validated` build
//! until it is updated; the failing build prints the new value.
//!
//! The build fails, whatever the features, if a module crate gains a dependency outside the
//! module, or if the module's crates are not exactly the dependencies this crate lists.
//!
//! The toolchain record also lists each module crate's enabled cargo features as Cargo unified
//! them ([`ToolchainRecord::crate_features`]). The features select only what is compiled and
//! change no source file, so they never change the table. With the `approved-only` feature, the
//! build fails if a module crate has a feature on that adds a non-approved service, naming the
//! crate and the feature: today that is `bouncycastle-ec`'s `sm2`, which any dependency on
//! `bouncycastle-ec` with default features, or on `bouncycastle-sm2`, turns on.
//!
//! # Usage Examples
//!
//! Power on once, first thing in `main`, and stop if it fails:
//!
//! ```
//! use bouncycastle_fips::{power_on_self_tests, self_test_status, SelfTestStatus, SelfTestedAlgorithm};
//!
//! # // Under `integrity` power-on fails until `bc-fips-install` has written the slot, which a
//! # // doctest binary never gets.
//! # if cfg!(feature = "integrity") { return; }
//! if let Err(e) = power_on_self_tests() {
//!     eprintln!("FIPS 140-3 self-tests failed: {e:?}");
//!     std::process::exit(1);
//! }
//! # // Without the `aes` feature AES is not compiled in, and its status is `NotRun`.
//! # #[cfg(feature = "aes")]
//! assert_eq!(self_test_status(SelfTestedAlgorithm::AES), SelfTestStatus::Passed);
//! ```
//!
//! Then use the algorithms as usual. Re-run the self-tests on demand -- the periodic self-test of
//! IG 10.3.E -- and report each algorithm's status; services stay usable while it runs:
//!
//! ```
//! use bouncycastle_fips::{power_on_self_tests, run_self_tests, self_test_status, SELF_TESTED};
//!
//! # // Under `integrity` power-on fails until `bc-fips-install` has written the slot, which a
//! # // doctest binary never gets.
//! # if cfg!(feature = "integrity") { return; }
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
//! Print the module table, the toolchain record and the module HMAC, for comparison with the
//! Security Policy:
//!
//! ```
//! use bouncycastle_fips::{module_info, module_table, power_on_self_tests};
//!
//! # // Under `integrity` power-on fails until `bc-fips-install` has written the slot, which a
//! # // doctest binary never gets.
//! # if cfg!(feature = "integrity") { return; }
//! power_on_self_tests().expect("self-tests pass");
//! // In the format of `bc-rust fips-info` and `dev_scripts/fips_module_hmac.py`; see ModuleInfo.
//! let info = module_info().expect("HMAC-SHA-512 has passed its self-test");
//! print!("{info}");
//! // Or field by field.
//! assert_eq!(info.table, module_table());
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
//! What, for ECDSA (IG 10.3.A Resolution 10): "for algorithms whose output vary for a given set of
//! inputs such as DSA, ECDSA, and RSA PSS, they shall be self-tested as a CAST for signature
//! generation and verification (as supported by the module). For a KAT, this requires the
//! randomization parameter be fixed", and "for deterministic ECDSA signature generation, the
//! module shall have a deterministic ECDSA digital signature generation CAST"; Note10: "the ECDSA
//! signature generation and deterministic ECDSA signature generation methods shall each have
//! their own CAST if both are implemented in the approved mode". Both are, so three CASTs, run as
//! one self-test. How many curves:
//! * Note16: "a CAST shall be performed at a minimum on any one approved modulus or curve size
//!   that is supported by the module". Note17: "an ECDSA CAST shall be performed at a minimum, on
//!   any one of the implemented NIST-recommended curves (and for which the CAVP certificate
//!   includes the curve) in each of the implemented two types of fields (i.e., prime field where
//!   GF(p), and binary field where GF(2m))". All seven curves here (P-256/384/521,
//!   brainpoolP256r1/384r1/512r1, secp256k1) are over prime fields, so one curve, and [10.29]
//!   makes it the smallest: P-256.
//! * Against one CAST per curve family: GeneralNote1 asks a separate CAST for "different
//!   implementations (e.g., separate libraries, or two instances on the same or different
//!   hardware) of a single algorithm". Each curve has its own field arithmetic in
//!   `bouncycastle-ec`, but ECDSA is one implementation generic over the curve, and Note17 is the
//!   specific rule for how many curves; per-curve arithmetic is how every ECDSA implementation
//!   works, and Note17 still asks for one per field type. A test lab that read GeneralNote1 the
//!   other way would want a CAST on one brainpool curve and on secp256k1 as well: two more
//!   vectors through the same code.
//!
//! What, for ECC CDH (IG 10.3.A Resolution 11, which defers to IG D.F): "For the ECC
//! Diffie-Hellman CAST, it is sufficient to choose any NIST-recommended curve supported by one
//! the module's ECC-based key shared secret computation schemes, select any point Q in the
//! subgroup of size n of points on that curve and verify the correct computation of the
//! x-coordinate of point P = hdQ, with 2 <= d <= n-2". One curve, P-256, by the same reasoning.
//! The KDFs over `Z` (X9.63, concatenation, HKDF) are not covered by it ("All key derivation
//! functions not included in the SP 800-56Arev3 CASTs shall have their own self-test").
//!
//! Pair-wise consistency tests (IG 10.3.A Additional Comment 1, quoting ISO/IEC 19790:2012
//! 7.10.3.3 [10.35]): "a pairwise consistency test (PCT) shall be conducted for every generated
//! public and private key pair for the applicable approved algorithm". At minimum the one "required
//! by the underlying algorithm standard (e.g., SP 800-56Arev3 Section 5.6.2.1.4 option 'b' ...)",
//! and, when the keys' use is known, "consistent with the intended use of the keys". It must be
//! done "either prior to the first exportation or prior to the first operational use"; it is
//! not required for imported keys. Here:
//! * an ECDSA key pair from `bouncycastle_ecdsa::keys::keygen` is a signature pair: a
//!   deterministic signature of a fixed message under the new private key, verified under the new
//!   public key, before `keygen` returns;
//! * an ECC CDH key pair from `bouncycastle_eccdh::keys::keygen` is a key-agreement pair: SP
//!   800-56A Rev. 3 Section 5.6.2.1.4 method b, "compute dG ... Compare the result to the public
//!   key, Q. If dG is not equal to Q, then the pair-wise consistency test fails", before `keygen`
//!   returns.
//!
//! A failed pair-wise consistency test drops the pair (method b: "the tested key pair shall not be
//! used") and enters the module error state, naming the algorithm.
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
//! | ECDSA SigGen | Resolution 10 (generation, `k` fixed), every curve (Notes 16, 17) | NIST ACVP-Server `gen-val/json-files/ECDSA-SigGen-FIPS186-5/internalProjection.json`, `tgId` 14 (P-256, SHA2-256), `tcId` 131 | d `a88c7a12e6cd3ec1467e96dfd230d654f786fa72efa43ca9632b8de5bd245cc3`, k `48fa4b5e8bb917973c25a0ada41f33821f68b650568eb144be5960da1c756aba`, Msg `4f1b2aba5d952e434d26b9015cb17fb4ffebd0cc7a9420f1915db0a298fd925092cd66c3d6556b30dca4c1559247dcb22dbfd78fc9ffb4b5df0110c8c50be70f7b4c483964ad74d67b99cc2f4a00f2a12575ae800c0e9cda06cb714a2ce6caa9d30b5585e80228dc3fe39d66dabb80504b3caf90b4bb1bd1d2303b8d89b3ba18` | r `642a2fea3fe1ea23ab699e5ed5568d0833b4cef596764628af9c47e23c0b400b`, s `3be682f265ae3db0d595128f35af41bc63cb0fc4d067cefdec95687ac2b3b5af` |
//! | Deterministic ECDSA SigGen | Resolution 10, Note10 | `DetECDSA-SigGen-FIPS186-5/internalProjection.json`, `tgId` 12 (P-256, SHA2-256), `tcId` 111 | d `f69a77b56caf234368df0d69f96cf04f435f967ff39e28371c6fe7a8146b865d`, Msg `0cce12ccf2f17bda8c1192f4557a8410fd65fa8dca174bb57c9b2a1e29597b6a44ad055d23aba4928b72c67a3e0093bc3686f68de6cee2122c35779684074c538cd1f5e836ba96f4f3e05cac2977ebf332ae2576ac083c3a963c18ba9f9872e71ef0f229f4c66a5cfca3952208784e44ef172ff7ee6b437efbe9afa116939789` | r `46aeb40043eaf16df463894fc8d3161837930afbd621519f51d02d5a28012df6`, s `6255be755fcf2e6dd4b7187158dc6253dde36e81dc114e09e6f6ed778acb2128` |
//! | ECDSA SigVer | Resolution 10 (verification), also deterministic ECDSA's (Note9) | `ECDSA-SigVer-FIPS186-5/internalProjection.json`, `tgId` 8 (P-256, SHA2-256), `tcId` 54 | Qx `93167a1567dfa211c10829919113eab92591ce6d01ca9d75283a66206cd5ca0d`, Qy `d647da83c25592c03332dc2a057e1ef61eaed77fa413275beee034512f31c97d`, Msg `cf9838b2e0e94584cfb7edb86af4ea09458ffdd81c024e54fe7899babb52977723fc7f04118528a7fb830af205786168458d85bacc0df74f9d493809904107d9aaf230cc5c2f97ca49c9e51451eb9d368129fbc32c416a53c9dc33a8507170e1975cdea2aee3924051b2fb3660c02bd1f1887a01229f368895dfb0ef6fe87d44`, r `8f3c091eec05deeca81cd5e42aa7365736011c41fdda8b4c9973962645ae59bf`, s `597b95068c79b5c6ef763eea19836a3a6478101b3fea1c0811845f7366387d65` | accepted (`testPassed: true`) |
//! | ECC CDH | IG D.F (shared secret computation), every curve | CAVP `ecccdhtestvectors.zip` (CAVS 14.1), `KAS_ECC_CDH_PrimitiveTest.txt`, `[P-256]`, `COUNT = 0` | QCAVSx `700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287`, QCAVSy `db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac`, dIUT `7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534` | ZIUT `46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b` |
//!
//! Not needed: a CBC encryption CAST (the forward cipher is covered by GCM encryption, 1.c), and
//! CASTs for AES-192/256, other modes, SHA-224, SHA-384 or SHA-512/t (covered above), and ECDSA
//! or ECC CDH CASTs on curves other than P-256 (Notes 16 and 17, IG D.F).
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
//! | [`module_hmac`] | 3608 B |
//!
//! The module table is a `static` of 15 package names and 15 x 64 hash bytes. The state is a
//! byte per algorithm and one for the module error state, all in `static`s. With the `fips`
//! feature each SHA-2 hash is 8 bytes larger (whether its output is gated).
//!
//! # 🚨 Security Considerations 🚨
//!
//! * **Not a validated module.** See the top of this page for what a validation needs beyond
//!   these self-tests. HKDF and the Hash_DRBG become usable as soon as SHA-2 passes, but have no
//!   self-test of their own here (FIPS 140-3 IG 10.3.A Resolution 6 requires them): they cannot
//!   be claimed as approved services of a build using this crate. HMAC has its CAST, but HMAC
//!   services are gated only on SHA-2, not on it. Likewise the X9.63 and concatenation KDFs that
//!   ECC CDH can derive through: the ECC CDH CAST covers the shared secret `Z` only.
//! * **The pair-wise consistency tests cover key generation only.** A key pair decoded from bytes
//!   is imported, which [10.35] does not cover, and is not checked; the CLI's `check-consistency`
//!   is there for that.
//! * **The gates are build-wide.** Cargo turns a feature on for the whole build if any one
//!   dependency asks for it, so once anything in a program depends on this crate, every AES key,
//!   SHA-2 hash and ECDSA or ECC CDH key pair, signer, verifier and agreement in that program, in
//!   every library, is refused until [`power_on_self_tests`]
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
//!   that any crate can report a failure (the ECDSA and ECC CDH pair-wise consistency tests do).
//!   Nothing can clear
//!   it or record a pass, but any code in the process can stop every gated algorithm with it.
//! * **The integrity test detects corruption, not an attacker.** Its key is public and its value
//!   sits in the binary it checks, so whoever can rewrite a segment can rewrite the value. It
//!   does not cover writable segments. Without the `integrity` feature there is none.
//! * **The module HMAC pins sources, not this program.** It says which sources the build saw,
//!   if the build was honest; it is not computed over the compiled code, and its key is public.
//!   The integrity test is what checks the program itself.
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
#[cfg(feature = "eccdh")]
use bouncycastle_eccdh as eccdh;
#[cfg(feature = "ecdsa")]
use bouncycastle_ecdsa as ecdsa;
#[cfg(feature = "sha2")]
use bouncycastle_sha2 as sha2;

#[cfg(feature = "approved-only")]
pub mod approved;
#[cfg(feature = "sha2")]
pub mod binary_hmac;
#[cfg(feature = "fips-validated")]
mod expected_module_hmac;
#[cfg(feature = "sha2")]
mod hmac_self_test;
#[cfg(feature = "integrity")]
mod integrity;
mod module_table;

pub use module_table::{
    CHECKSUM_LEN, CrateFeatures, ExternalCrate, MODULE_HMAC_KEY, MODULE_HMAC_LEN, ModuleInfo,
    ModuleTableEntry, ToolchainRecord, external_crates, module_hmac, module_info, module_table,
    toolchain,
};

// The boundary crates this crate does not call. They are dependencies so that build.rs receives
// their source directories and pins them in the module table; see `Cargo.toml`.
use bouncycastle_ascon as _;
use bouncycastle_cipher as _;
use bouncycastle_concatkdf as _;
use bouncycastle_ec as _;
#[cfg(not(feature = "eccdh"))]
use bouncycastle_eccdh as _;
#[cfg(not(feature = "ecdsa"))]
use bouncycastle_ecdsa as _;
use bouncycastle_hkdf as _;
use bouncycastle_rng as _;
use bouncycastle_sha3 as _;
use bouncycastle_utils as _;
use bouncycastle_x963kdf as _;

/// The algorithms whose self-tests this build runs, in the order they run: those of the
/// enabled cargo features, hashes first, then HMAC-SHA-512, then the software integrity test and
/// the module integrity check, then AES, ECDSA and ECC CDH.
pub const SELF_TESTED: &[SelfTestedAlgorithm] = &[
    #[cfg(feature = "sha2")]
    SelfTestedAlgorithm::SHA256,
    #[cfg(feature = "sha2")]
    SelfTestedAlgorithm::SHA512,
    #[cfg(feature = "sha2")]
    SelfTestedAlgorithm::HMAC_SHA512,
    #[cfg(feature = "integrity")]
    SelfTestedAlgorithm::SoftwareIntegrity,
    #[cfg(feature = "fips-validated")]
    SelfTestedAlgorithm::ModuleIntegrity,
    #[cfg(feature = "aes")]
    SelfTestedAlgorithm::AES,
    #[cfg(feature = "ecdsa")]
    SelfTestedAlgorithm::ECDSA,
    #[cfg(feature = "eccdh")]
    SelfTestedAlgorithm::ECC_CDH,
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
    #[cfg(feature = "fips-validated")]
    Crate {
        algorithms: &[SelfTestedAlgorithm::ModuleIntegrity],
        self_test: module_table::validated::self_test,
    },
    #[cfg(feature = "aes")]
    Crate { algorithms: &[SelfTestedAlgorithm::AES], self_test: aes::self_test },
    // ECDSA hashes with SHA-256, which has passed by now.
    #[cfg(feature = "ecdsa")]
    Crate { algorithms: &[SelfTestedAlgorithm::ECDSA], self_test: ecdsa::self_test },
    #[cfg(feature = "eccdh")]
    Crate { algorithms: &[SelfTestedAlgorithm::ECC_CDH], self_test: eccdh::self_test },
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
        #[cfg(feature = "fips-validated")]
        SelfTestedAlgorithm::ModuleIntegrity => module_table::validated::status(),
        #[cfg(feature = "aes")]
        SelfTestedAlgorithm::AES => aes::self_test_status(),
        #[cfg(feature = "ecdsa")]
        SelfTestedAlgorithm::ECDSA => ecdsa::self_test_status(),
        #[cfg(feature = "eccdh")]
        SelfTestedAlgorithm::ECC_CDH => eccdh::self_test_status(),
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
