# FIPS 140-3 self-test layouts: the two prototypes compared

Reviewed 2026-11-10. Two prototypes fill in the `bouncycastle-fips` skeleton on this branch
(`feature/fips-kats-base`, `649981b4`):

* **Variant A**, `feature/fips-kats-separate-crate` at `68dc8c88`: every known-answer test (KAT) in
  `bouncycastle-fips`; the status of each algorithm in a table in `bouncycastle-core`; the AES and
  SHA-2 constructors read that table.
* **Variant B**, `feature/fips-kats-embedded` at `7cb362ed`: each algorithm crate carries its own
  KAT and its own private status behind its `fips` feature; `bouncycastle-fips` runs them in order.

This document changes no code. Everything below was checked against those commits or against a
source downloaded on the review date; where it was not, it says **unverified**. "IG" is
*Implementation Guidance for FIPS 140-3 and the Cryptographic Module Validation Program*, last
update 2026-08-19 (the URL is in the crate docs). The IG quotes ISO/IEC 19790:2012 and ISO/IEC
24759:2017 in part; neither standard is freely available, so a requirement the IG does not quote
is marked unverified. (Found since: NIST SP 800-140 gives AS03.07 and AS10.07; the crate docs
now quote them from it.) [How each figure was obtained](#how-this-was-checked) is at the end.

## Short version

**Recommendation: converge on variant B's ownership model** (the KAT and the "passed" status live
in the crate that implements the algorithm), **with three changes** taken from what variant A does
better and from the findings below: one shared status type in `core` (with an unwind guard)
instead of a copy of the state machine per crate, a one-way module error latch in `core`, and a
power-on call that does not report an overlapping run as an error. A fourth, a gate that admits
only `Passed`, was put as a decision and approved. [Details](#recommendation).

The deciding fact: in A, any crate that writes to the status table before `bouncycastle-fips`
does can record `Passed` for an algorithm that was never tested (finding [A-1](#findings)). That
is a consequence of the layout, not of the implementation: the status is in `core`, the code
allowed to set it is in another crate, and Rust has no way to make a `pub` function callable from
one crate only. In B nothing outside the algorithm crate can produce `Passed`.

Neither is ready as it stands: A and B have five findings each, and share six more.

The [decisions](#decisions-needed-before-convergence) at the end were answered on 2026-11-10:
B, with all four changes, and a failure must also stop keys and hashes that already exist.

## What the two variants have in common

Both implement the same three functions (`power_on_self_tests`, `run_self_tests`,
`self_test_status`), run the same five KATs through the algorithm crates' public API, and put the
same gates in the same places:

* AES: one check at the top of `AESInternal::validate`, which every AES key of every mode and
  size passes through. It returns `SymmetricCipherError::SelfTestNotPassed`.
* SHA-2: a check in `SHA256Internal::new`, `SHA512Internal::new` and both `from_suspended`. It
  panics, because those constructors return no `Result` (`from_suspended` returns one, but
  `SuspendableError` has no variant for it).

The embedded vectors are byte-for-byte the cited ones in both variants: CAVP
`gcmEncryptExtIV128.rsp` (CAVS 14.0) `Count = 0` of the `[Keylen = 128] [IVlen = 96]
[PTlen = 128] [AADlen = 128] [Taglen = 128]` group, CAVP `SHA256ShortMsg.rsp` and
`SHA512ShortMsg.rsp` (CAVS 11.0) `Len = 24`, and SP 800-38A Appendix F.2.2 (all four blocks). The
IG sections the crate docs cite exist and say what the docs say, with two caveats:

* The docs' wording at the review, "per AS10.07 as IG 1.B applies it, a failed self-test puts the *entire* module in the
  error state" rests on a sentence about hybrid modules: "if any self-test implemented in any
  disjoint component of a hybrid module fails, the entire hybrid module shall [IG1.B.10.01] enter
  an error state". The IG does not quote AS10.07 itself, so that it says the same of a software
  module was **unverified** at the review. Since verified: NIST SP 800-140 (March 2020) Section
  6.10 gives AS10.07, which says it of every module, and the crate docs now cite that.
* IG 10.3.A Resolution 2 lists "a CAST for SHA-1 is required" without the "if implemented" the
  docs add. Note2 of the same IG supports the docs' reading ("separate CASTs are needed for SHA-1,
  SHA-256 and SHA-512, if the module is designed to use these hash functions"). The docs now quote both.

## Measured comparison

| | Variant A (separate crate) | Variant B (embedded) |
|---|---|---|
| Lines added, `src/` | aes 15, sha2 42, core 186, fips 370 | aes 371, sha2 329, core 0, fips 123 |
| Lines added, `tests/` | core 84, fips 398 | fips 202 (plus the unit tests inside the two `self_test.rs`) |
| Lines added, whole diff | 1120 (25 removed) | 1051 (18 removed) |
| New `pub` items in algorithm crates | none | 7 functions: aes `self_test`, `self_test_status`, `self_test_enter_error_state`; sha2 `self_test`, `sha256_self_test_status`, `sha512_self_test_status`, `self_test_enter_error_state` |
| New `pub` items in `core` | 6: `self_test_status`, `check_self_test`, `assert_self_test`, `SelfTestStatusWriter`, `claim_self_test_status_writer`, `set_self_test_status`; and the variant `SelfTestError::StatusWriterTaken` | none |
| Who can set `Passed` | whichever code writes to the table first in the process; `bouncycastle-fips` only if it is first | only the algorithm crate's own `self_test()`, by producing the known answers |
| Who can set `Failed` | the table's writer only | any code, through `self_test_enter_error_state()` |
| Other threads during the first run | can create services of the algorithm under test (status `Running`) | the same |
| Two threads calling `power_on_self_tests` at once | both run the KATs; both get `Ok` (by inspection of `driver::run`; no test) | one runs; the other can get `Err(NotPassed(_, Running))` |
| A KAT that panics | recorded as `Failed` by a drop guard | status stays `Running`, which the gate admits |
| After one failure | every gate refuses at once (each gate reads all three statuses) | a failure found by a `bouncycastle-fips` run stops every crate at once; one a crate records on its own stops the others only at the next call into `bouncycastle-fips` (B-1) |
| `self_test_status` after a failure | `Failed` for the failed algorithm only; the others still read `Passed` though they are refused | `Failed` for all, once `bouncycastle-fips` has been called |
| AES CASTs in one run | all three always run (`&`) | stop at the first failure (`&&`) |
| How a failing KAT is injected | test recompiles `src/driver.rs`, `kats.rs`, `vectors.rs` with `#[path]` and writes through its own writer, which works because of A-1 | unit test in `self_test.rs` calls the private `run(&corrupted)`; the fips crate's tests start from the public error-state hook instead |
| Tests of `bouncycastle-fips` with one feature only | 10 (`aes`), 8 (`sha2`) | 2 each: every scenario file is `#![cfg(all(feature = "aes", feature = "sha2"))]` |
| `cargo mutants` | `core` `fips.rs`: 30 mutants, 21 caught, 9 unviable, 0 missed; `bouncycastle-fips`: 52 mutants, 38 caught, 7 unviable, 7 missed (A-5) | aes `self_test.rs`: 40 mutants, 27 caught, 13 unviable, 0 missed; sha2 `self_test.rs`: 30 mutants, 19 caught, 11 unviable, 0 missed; `bouncycastle-fips`: 20 mutants, 12 caught, 8 unviable, 0 missed |
| `.cargo/mutants.toml` | unchanged | `**/src/self_test.rs` excluded; mutating it needs a copy of the config, `--features fips` and `-- --lib` |
| Normal dependencies of `bouncycastle-fips` | direct: core, aes, cipher, sha2. Closure identical to B's | direct: core, aes, sha2 |
| Release binary (below) | 426,000 bytes | 424,872 bytes |
| Peak stack of a run | not measured (docs say "Not yet measured") | 1700 B, as its docs state; not re-measured here |

Binary size: one program that makes an AES-128-GCM key, encrypts 16 bytes and hashes with SHA-256
and SHA-512, built `--release` with `strip = true`, `panic = "abort"`, stable rustc 1.98.1,
x86-64 Linux. Without `bouncycastle-fips`: 369,440 bytes. With it and a `power_on_self_tests()`
call first: A +56,560, B +55,432. `text + data + bss` differs by 4 bytes between A and B. How
much of the increase is the GCM-decrypt and CBC code the KATs link and the program did not use
was not measured.

Both: `cargo test --workspace` with the features off passes (2672 tests passed, 0 failed, 8
ignored, in each), and `cargo tree --workspace -e features` shows no `fips` feature, so excluding
the crate from the workspace does what the crate docs say. Neither variant adds an external
dependency; `cfg-if`, `getrandom` and `libc` are in the closure already, through
`bouncycastle-rng`.

## Variant A: KATs in `bouncycastle-fips`, status in `core`

Ups:

* The algorithm crates barely change: 15 and 42 source lines, no new `pub` item, no vectors.
* "Public API only" is enforced by the compiler. The KATs are in another crate, so they cannot
  reach anything private. In B it is a convention.
* One file holds every vector and one holds every KAT, next to the table in the crate docs that
  justifies them. A reviewer, or a test lab, reads one crate.
* One status table, so the module-wide error state is immediate: every gate refuses as soon as
  any algorithm is `Failed`.
* Any crate can gate on any algorithm through `core`, which is what `bouncycastle-factory`,
  `bouncycastle-hmac` and `bouncycastle-hkdf` will need ([scaling](#beyond-aes-and-sha-2)).
* A KAT that panics is recorded as a failure, and concurrent power-on calls both succeed.

Downs:

* A pass can be forged (A-1), and no revision of this layout removes that while the status is
  writable from outside `core`.
* `core`, the spine every crate depends on, gains process-wide mutable state and six `pub` items,
  one of them a write function with a Security Considerations section of its own.
* An algorithm crate built with `fips` cannot be used without `bouncycastle-fips`: nothing else
  can make its status `Passed` (short of A-1).
* The failure-path test only works because of A-1, and tests a second compilation of the driver,
  not the library's own `WRITER` and `run_kat` (A-2).
* A status and its gate can disagree (A-3).
* Only the table's writer can record a failure, so an algorithm crate has no way to put the
  module in the error state when a test of its own fails. ML-KEM and ML-DSA need that for the
  pairwise consistency test.

## Variant B: KATs and status in the algorithm crates

Ups:

* `Passed` cannot be forged: the status is a private `static`, and the only path to `Passed` is a
  run that produced the known answers. The public hook can only stop the algorithm.
* `core` is untouched beyond the vocabulary types already on this branch.
* Each crate is self-contained: `bouncycastle_aes::self_test()` works without
  `bouncycastle-fips`, and its doctest is a complete usage example.
* The gate is one line that names nothing outside the crate.
* The failure path is tested on the library's own code: the unit test corrupts each KAT value in
  turn and checks which CAST notices.
* `bouncycastle-fips` shrinks to an ordered list of function pointers (123 lines).

Downs:

* Each algorithm crate's reviewed source grows by about 300 lines (vectors, a state machine, a
  unit test), against QUALITY_AND_STYLE.md's preference for a short `src/` and for integration
  tests. The unit test does meet that document's three conditions for an exception.
* The claim/finish state machine is written twice, near-identically, in `aes` and `sha2`, and
  would be written again in every crate that follows. Neither copy uses `core`'s
  `SelfTestStatusCell`, which exists on this branch for that purpose (B-3).
* The module-wide error state is assembled by `bouncycastle-fips` after the fact (B-1).
* Seven new `pub` functions across two crates, and three more per crate that follows.
* The vectors are in the algorithm crates while the table that justifies them is in the
  `bouncycastle-fips` docs, so the two can drift.
* "Public API only" is by convention.
* `cargo mutants` needs a special invocation per crate, and the config now carries an exclusion.

## Findings

Defects in the prototypes, for whoever converges them. None was fixed on the variant branches.
"Shared" findings are in both.

| Id | Finding | Evidence |
|---|---|---|
| A-1 | Any code that calls `bouncycastle_core::fips::set_self_test_status` before the first `power_on_self_tests` becomes the table's only writer and can record `Passed` for an untested algorithm. `bouncycastle-fips` then returns `StatusWriterTaken`, which helps only an application that calls it and checks the result. | Documented in the variant; demonstrated by its `status_writer_taken_tests.rs`. |
| A-2 | The failing-KAT test depends on A-1 (its own writer must win) and compiles `driver.rs`, `kats.rs` and `vectors.rs` a second time with `#[path]`. The library's `WRITER`, `run_kat` dispatch and `power_on_self_tests` are never run against a failing KAT. Closing A-1 breaks the test. | `tests/kat_failure_tests.rs`; the surviving mutant `replace run_kat -> bool with true` in `src/lib.rs`: the shipped `power_on_self_tests` would pass every test if it checked nothing. |
| A-3 | After a failure `self_test_status` still reports `Passed` for the algorithms that did not fail, although their gates refuse. | `core` `fips_status_table_tests.rs`: "the others keep their own status". |
| A-4 | The crate docs' Memory Usage section says "Not yet measured". | `crypto/fips/src/lib.rs`. |
| A-5 | The KAT tests check the three AES CASTs only as one result, so each GCM CAST can be made vacuous unnoticed, and nothing tests the unwind guard or the skip-if-passed condition. (B had the first of these and fixed it in `7cb362ed`.) | Surviving mutants: `aes_gcm_128_encrypt -> true`, `aes_gcm_128_decrypt -> true`, `&&` to `\|\|` in each, `FailOnUnwind::drop -> ()`, `delete !` at `driver.rs:40`. |
| B-1 | A crate that fails on its own (its `self_test()` called directly, or its error hook) stops only itself. The other crates keep working until something next calls `power_on_self_tests` or `run_self_tests`. The doc line "once any self-test has failed, every algorithm reports `Failed`" is true only after that call. | `aes::self_test_enter_error_state` writes the AES status only; the SHA-2 gates read only the SHA-2 statuses. `tests/failure_tests.rs` checks that SHA-2 is stopped only once `run_self_tests()` has been called. |
| B-2 | No unwind guard: if a KAT panics, the status stays `Running`. The gate admits `Running`, so other threads (or the same one, after `catch_unwind`) can use the algorithm indefinitely, and every later `self_test()` returns `NotPassed(_, Running)`. A panic is a plausible way for a faulty implementation to show itself. | `run()` in both `self_test.rs`: nothing between `begin()` and `finish()` handles unwinding. By inspection, not reproduced. |
| B-3 | The state machine is duplicated in `aes` and `sha2` and bypasses `core`'s `SelfTestStatusCell`, which no code in either variant outside `core`'s own tests uses. | `begin`, `finish`, `status` in both files. |
| B-4 | The second of two overlapping `power_on_self_tests` calls returns an error (`NotPassed(_, Running)`) although nothing is wrong; a caller that treats any error as fatal aborts a healthy program. The crate's own test works around it with `while power_on_self_tests().is_err() {}`. And with one feature only, `bouncycastle-fips` runs 2 tests: no scenario is checked in an AES-only or SHA-2-only build. | `tests/concurrent_run_tests.rs`; the `#![cfg(all(...))]` line in each scenario file. |
| B-5 | The `KnownAnswerMismatch` arm of `bouncycastle-fips`'s `run` is never reached by a test: the fips tests enter the error state through the hook. | `tests/failure_tests.rs`. By inspection; `cargo mutants` generates no mutant for a match arm, so its clean run says nothing here. |
| S-1 | During the first run the gate admits `Running`, so every thread can create services of an algorithm whose KAT has not finished. IG 10.3.A: "The conditional test shall [10.27] be performed prior to the first operational use of the cryptographic algorithm." Both variants document it and tell the application to finish power-on before starting threads. It exists because the KATs go through the gated public constructors. | Both gates; A's "Self-test in progress" docs; B's module docs. |
| S-2 | Only creation is gated. A key or hash that exists when a self-test fails keeps producing output. The crate docs' own requirement is that the module inhibits data output in the error state (AS03.07). | A documents it ("the gates are on creation only"); in B the gate is likewise only in the constructors. |
| S-3 | If a failure is recorded while another thread's KAT is running, that KAT's `SHA256::new()` panics, so `power_on_self_tests` panics instead of returning `Err`. | `assert_self_test` (A) and `require_passed` (B) are called from inside the KAT. By inspection. |
| S-4 | The algorithm crates' own test suites never run against the gated build: `cargo test -p bouncycastle-aes --features fips` fails in both variants (first at `tests/alg_name_tests.rs`), as documented. The gate lines are covered only by `bouncycastle-fips`'s tests (A) or by those and one unit test (B). | Run in both; exit 101. |
| S-5 | HMAC-SHA-2 becomes usable as soon as SHA-2 passes, but has no CAST. IG 10.3.A Resolution 4: "if the module implements a HMAC function (FIPS 198-1), a CAST for HMAC is required". Out of the prototype's stated scope (AES and SHA-2), but the HMAC and HKDF instantiations ship in `bouncycastle-sha2`, and the Hash_DRBG in `bouncycastle-rng` is in the dependency closure of `bouncycastle-aes` (through `bouncycastle-cipher`); Resolution 6 requires CASTs for it. | `crypto/sha2/src/hmac.rs`, `hkdf.rs`; `cargo tree`. |
| S-6 | `cargo mutants` cannot run on `bouncycastle-fips` with the repository's config. The crate is its own workspace, so the copy `cargo mutants` makes of it loses its `../` path dependencies ("failed to read `/tmp/hmac/Cargo.toml`" in A, `/tmp/cipher/Cargo.toml` in B), and `.cargo/mutants.toml` names `profile = "mutants"`, which only the root manifest defines ("profile `mutants` is not defined"). The figures in the table needed `--in-place` and a config without that line. | Run in both. |

## Options considered and not prototyped

None of these was built; the ups and downs are reasoned from the code and the IG, not measured.

**A wrapper-only `bouncycastle-fips`** that re-exports gated wrappers and leaves the algorithm
crates untouched.

* Ups: no change to any algorithm crate; no feature that changes behaviour, so the workspace
  exclusion and the feature-unification problem disappear.
* Downs: it gates nothing. An application, or any of its dependencies, that uses
  `bouncycastle-aes` directly bypasses it, so "prior to the first operational use" holds only by
  the application's discipline. Every algorithm type needs a wrapper type, and generic code
  written against `bouncycastle-aes` types does not accept them.

**Lazy self-test on first use**, instead of the explicit call: the first constructor of an
algorithm runs its KAT.

* Ups: nothing for the application to forget. It is what the standard describes: FIPS 140-3
  CASTs are *conditional* self-tests, "performed when an applicable security function or process
  is invoked" ([10.04]), and IG 10.3.A GeneralNote4 lets different functions be self-tested at
  different times. An unused algorithm costs nothing at startup.
* Downs: the first use of each algorithm pays for the KAT, at a point the application did not
  choose; for an infallible constructor a failure is a panic at that point. Two threads making
  their first use together need the claim logic both variants already have, plus an answer for
  the loser (wait, or run the KAT again). In A the algorithm crates cannot call the KATs, which
  are in `bouncycastle-fips`, except through a callback registered in `core`. In B it is a small
  change: the gate calls `self_test()` when the status is `NotRun`. It can sit beside the
  explicit call rather than replace it.

**An automatic pre-`main` constructor** (a function pointer placed in `.init_array`).

* Ups: self-tests always run, with no call and before any thread exists, which also removes S-1.
* Downs: it needs `#[link_section]` on a `static`, which is `unsafe` in the 2024 edition, so it
  conflicts with `#![forbid(unsafe_code)]` in every crate; the portable way to get it is an
  external crate, which conflicts with the zero-dependency rule in QUALITY_AND_STYLE.md. It is
  platform-specific (ELF, with different mechanisms on Mach-O and Windows, none on bare metal),
  and cannot report a failure except by aborting. Checked: on stable 1.98.1, edition 2024,
  `#[link_section]` without `unsafe(...)` is an error and `#[unsafe(link_section = ...)]` is
  rejected under `#![forbid(unsafe_code)]`. The portability points are **unverified**.

**How a refused service reports it.**

* *`Err` everywhere*: uniform, and the caller decides. But `Hash::new()`, `Default`, the
  one-shots and everything generic over them would have to become fallible, in every build or
  only under `fips`. The first is the kind of `Result` QUALITY_AND_STYLE.md's Fallibility section
  argues against ("programmer didn't read the docs" errors); the second makes the feature change
  signatures, which no dependent crate could then compile against in both configurations.
* *Panic everywhere*: no signature changes, and it cannot be ignored. But the AES constructors
  already return `Result` for bad key material, so panicking there throws away a channel that
  exists, and under `panic = "abort"` a late self-test failure takes the process down with no
  chance to report it.
* *The mix both prototypes chose* (`Err` where a `Result` already exists, panic where it does
  not): no signature changes and no new unwraps for callers. The cost is two behaviours to
  document, and `from_suspended`, which returns a `Result` and still panics because
  `SuspendableError` has no variant for it; adding one would be a small, defensible exception.

## Beyond AES and SHA-2

Layout facts used here: `bouncycastle-hmac` and `bouncycastle-hkdf` are generic over the hash and
have no hash of their own; `bouncycastle-sha2` depends on both and publishes the instantiations
(`sha2::hmac`, `sha2::hkdf`). `bouncycastle-rng` (Hash_DRBG) depends on `bouncycastle-sha2`.
`bouncycastle-cipher` holds the modes and `BlockCipherKey` and depends on `bouncycastle-rng`; AES,
ARIA, Camellia and SM4 each build their keys on it. `bouncycastle-mlkem` and `bouncycastle-mldsa`
depend on `bouncycastle-sha3` and `bouncycastle-rng`. `bouncycastle-factory` depends on sha2,
sha3, sm3, ascon, hmac and rng.

| | Variant A | Variant B |
|---|---|---|
| Adding an algorithm | a `SelfTestedAlgorithm` variant and a `static` in `core`, a gate line in the crate, vectors and a KAT in `bouncycastle-fips` | a `SelfTestedAlgorithm` variant in `core`, a `self_test.rs` in the crate, an entry in `bouncycastle-fips` |
| HMAC, HKDF (IG 10.3.A Resolution 4; Resolution 8 if HKDF is claimed as an SP 800-56C KDA) | The gate goes in the generic crate, which can read `core`'s table. Simple. | The generic crate has no hash, so it cannot hold its own KAT. The KAT and status go in `bouncycastle-sha2` beside the instantiation, and the generic constructor needs a hook to reach them (through `HMACParams`, say). Workable, but one more thing per hash crate. |
| DRBG (Resolution 6: instantiate, generate, reseed) | KAT in `bouncycastle-fips`, gate in `bouncycastle-rng`. | KAT, status and gate in `bouncycastle-rng`. |
| Ordering (SHA-2 before the DRBG, SHA-3 before ML-KEM) | One list in `core` (`SelfTestedAlgorithm::ALL`). | The list in `bouncycastle-fips`. A crate's `self_test()` called directly can run before its dependencies' and hit their gates; each `self_test()` would have to call its dependencies' first. |
| ML-KEM, ML-DSA KATs (Resolutions 14, 15: key generation, encapsulation, decapsulation with both the rejection and non-rejection paths; signing, verification) | Large vectors (keys, ciphertexts, signatures) all land in `bouncycastle-fips`, for both the standard and the low-memory crates (GeneralNote1: each implementation is self-tested separately). | The vectors land in the four crates; each is self-contained. |
| Pairwise consistency test (IG 10.3.A Additional Comment 1: "for every generated public and private key pair"; for ML-KEM, encapsulate with `ek` and decapsulate with `dk`) | It runs inside key generation, so it is code in the algorithm crate in either layout. Its failure must enter the error state, and only the table's writer can write `Failed`: A needs a second, public way to fail. | The crate sets its own status. Stopping the other crates has the B-1 gap. |
| Other block ciphers on `BlockCipherKey` | Unaffected in both: the gate is in AES's key expansion, below the shared key type. IG 10.3.A lists no CAST for ARIA, Camellia or SM4; if they are offered as non-approved services they need none (GeneralNote8) but must be told apart by the service indicator. | the same |
| `bouncycastle-factory` | `HashFactory::new(name)` returns a `Result` but calls `SHA256::new()`, so in a `fips` build it panics before power-on in both variants (by inspection). To return `Err` instead it needs its own `fips` feature and a status to read: `core`'s table. | It reads the algorithm crate's `pub` status function. Equally easy. |
| Process-wide state | 3 statics in `core` today; one per algorithm, all in one file. | One or two per crate. |

Neither layout scales cleanly as it stands: A has no way for an algorithm crate to fail, B has no
immediate module-wide failure and no home for generic crates' KATs. A one-way error latch in
`core`, readable and settable-to-failed by every crate, fixes the first two in either layout.

## What a FIPS 140-3 module still needs

The prototypes are CASTs for two algorithm families. A validated module needs at least the
following as well; none of it is addressed.

| Need | Reference | Status |
|---|---|---|
| Pre-operational software integrity test over everything inside the boundary, with an approved integrity technique | ISO/IEC 19790:2012 §7.10.2.2: "All software and firmware components within the cryptographic boundary shall [10.17] be verified using an approved integrity technique" (quoted in IG 5.A); [05.05] (quoted in IG 1.A) | Verified. How it is done for a Rust library that is linked statically into the application is **unverified** and is the hardest open design question here. |
| The integrity technique's own algorithm self-tested first | IG 10.2.A, [10.20] | Verified. Fits both layouts: the HMAC or signature CAST runs before the integrity check. |
| Approved security service indicator | IG 2.4.C, AS02.24: "All services shall [02.24] provide an indicator when the service utilizes an approved cryptographic algorithm". It also says a service that provides on-demand self-tests needs one, which covers `run_self_tests`. | Verified. bc-rust ships algorithms IG 10.3.A has CASTs for beside ones it does not mention (SM3, SM4, ARIA, Camellia). If a module "can provide an approved and non-approved security service concurrently", a global indicator that cannot tell them apart "does not meet the requirement". |
| A defined cryptographic boundary | [05.05] speaks of "the module's defined cryptographic boundary"; IG 1.A covers bound and embedded modules | The requirement is verified. What the boundary would be when each algorithm is a separately published crate, compiled from source by the application's build, is **unverified**; neither prototype defines one. |
| Error state: inhibit all data output, an error indicator, how the module leaves it | AS03.07 and AS10.07 are in NIST SP 800-140 (Sections 6.3 and 6.10; quoted in the crate docs); IG 2.4.C mentions the indicators "required in AS10.08 and AS10.11" | The text of AS10.08 to AS10.11 is in neither the IG nor SP 800-140: **unverified**, as the crate docs say. Finding S-2 is against AS03.07. |
| CASTs for every other approved algorithm offered | IG 10.3.A Resolutions 3 (SHA-3), 4 (HMAC), 6 (DRBG), 8 (KDFs), 14 (ML-KEM), 15 (ML-DSA) | Verified. |
| Pairwise consistency test on every generated key pair | IG 10.3.A Additional Comment 1; ISO/IEC 19790:2012 §7.10.3.3 [10.35] | Verified. |
| Entropy source health tests | IG 10.3.A Resolution 7 (SP 800-90B Section 4.2); IG 9.3.A, D.J, D.K exist on the subject | Resolution 7 verified; the other three were not read. Where bc-rust's seed comes from (`getrandom`) and whether that is inside the boundary is **unverified**. |
| AES-GCM IV rules | IG C.H lists the acceptable ways to generate a GCM IV | Verified that it exists and constrains IV generation; not read in full. The `_nonce` one-shots take the IV from the caller. |
| Periodic self-test | IG 10.3.E (Levels 3 and 4: automatic, on a defined period [10.54]; Levels 1 and 2: "a provided service, resetting, rebooting or power cycling") | Verified. `run_self_tests` covers Levels 1 and 2. |
| Error log | IG 10.3.D, Levels 3 and 4 only | Verified. |
| CAVP algorithm certificates, a security policy (SP 800-140Br1), zeroisation indicator (IG 9.7.B), roles and services | named in the IG's contents | **Unverified**: not read. |

## Recommendation

Converge on **variant B's ownership model**, with the four changes below (the fourth was
decision 3, since answered yes). Each answers a finding.

1. **One status type in `core`, one instance per algorithm crate.** Move the claim/finish state
   machine into `SelfTestStatusCell` (`begin`, `finish`, a guard that records `Failed` if dropped
   during unwinding). Each algorithm crate keeps a private `static` of that type, so the pass
   still cannot be forged and the logic exists once. Fixes B-2 and B-3; takes A's drop guard.
2. **A one-way module error latch in `core`**: a private `static`, a `pub` function that sets it
   and one that reads it, nothing that clears it. Every gate reads it; every failure (a KAT, and
   later a pairwise consistency test) sets it. Fixes B-1 and the A-3 disagreement, and gives
   ML-KEM and ML-DSA their way to fail. It replaces the per-crate
   `self_test_enter_error_state` functions (two fewer `pub` items per crate). Any code can stop
   the module through it; nothing can start it.
3. **`power_on_self_tests` does not return an error for an overlapping run** (B-4): it waits for
   the other run, or re-runs, and reports that run's result. Scenario tests run in the
   single-feature builds too.
4. **Close the first-run window** (S-1), which only an embedded KAT can do: let the KAT use a
   crate-private entry that skips the gate, and have the gate admit `Passed` only. This is the
   one change that departs from "the KAT uses the public API only", so it was
   put as [decision 3](#decisions-needed-before-convergence); the answer is yes.

Keep from A: the `bouncycastle-fips` test that checks every byte of every vector matters, and the
single vector table in the `bouncycastle-fips` docs as the one place that justifies the choices.

Why not A: A-1 is inherent to it, and the pairwise consistency tests need algorithm crates to
record failures, which A's single writer forbids. A's real advantages (tiny algorithm-crate
diffs, compiler-enforced public-API-only KATs, one place for vectors) are about review cost; B's
are about what the gate can be trusted to mean.

## Decisions needed before convergence

All nine were answered on 2026-11-10; each answer follows its question.

1. **May an algorithm crate export `self_test()` and a status function?** The parent task says
   "Dont use anything internal in crates (no pub for kats)". If that means "KATs must not need
   internals made public", both variants comply and the recommendation stands. If it means "no
   self-test items in an algorithm crate's public API", only A complies. *Recommended: the first
   reading; choose B.*
   **Decided:** The first reading: KATs must not need internals made public.
2. **Layout: B as amended, or A?** *Recommended: B with changes 1 to 3.*
   **Decided:** B.
3. **May an embedded KAT bypass the gate through a crate-private entry**, so that the gate admits
   only `Passed` and S-1 goes away? The alternative is to keep S-1 as a documented rule ("finish
   power-on before starting threads"). *Recommended: yes.*
   **Decided:** Yes.
4. **Explicit call, lazy, or both?** *Recommended: keep the explicit `power_on_self_tests`, and
   decide on lazy-on-first-use after change 1, since it then costs a few lines per gate.*
   **Decided:** As recommended: keep the explicit call; decide on lazy once the shared status
   type exists.
5. **Does a failure stop existing keys and hashes, or only new ones** (S-2)? Stopping existing
   ones means a check on every `do_update` / encrypt call, or a process abort on failure.
   *Recommended: abort-on-failure as an opt-in, and document creation-only gating otherwise;
   confirm against ISO/IEC 19790 before a validation.*
   **Decided:** Not as recommended. A failure of any self-test must stop the use of all keys and
   hashes, existing and new, across the whole module.
6. **`SHA256::new()` before power-on: keep the panic?** *Recommended: yes, plus a
   `SuspendableError` variant so `from_suspended` returns it instead of panicking.*
   **Decided:** Yes, with the `SuspendableError` variant.
7. **A `fips` cargo feature, or a build-wide `--cfg`?** A feature is switched on for the whole
   build by any one dependency, which is why this crate sits outside the workspace. A `cfg` set
   through `RUSTFLAGS` is chosen by whoever builds the final binary and by nobody else. Not
   prototyped. *Recommended: keep the feature for now; revisit with the module boundary.*
   **Decided:** Keep the feature for now.
8. **Scope of step 5/5**: AES and SHA-2 only, or also the HMAC CAST (S-5), without which
   HMAC-SHA-2 is usable unvalidated in a `fips` build? *Recommended: add the HMAC CAST; it is one
   vector and settles where generic crates' KATs live.*
   **Decided:** Not as recommended. AES and SHA-2 only for now.
9. **Is a FIPS 140-3 validation an actual goal, and at which security level?** It decides whether
   the integrity test, the service indicator and the boundary question above are next, or whether
   the self-tests are a robustness feature and stop here.
   **Decided:** Yes, a validation is the goal, at Security Level 1.

What the answers add to the recommendation:

* **Decision 5 moves the gate from creation to use.** Finding S-2 becomes a requirement: every
  operation on an existing key, worker or hash must read the module error latch, not only the
  constructors. Two things follow that convergence has to settle. The AES workers are in
  `bouncycastle-cipher`, which is generic over the permutation, so the check goes either in the
  AES block calls or in the mode workers under a `fips` feature of that crate. And most of those
  operations (`do_update`, a hash's `do_final`) return no `Result`, so there a refusal can only
  be a panic. The cost of a check per call was not measured.
* **Decision 8 leaves S-5 open.** Until HMAC has its CAST, HMAC-SHA-2 (and HKDF, and the DRBG)
  cannot be listed as approved services of a `fips` build, although nothing stops their use.
* **Decision 9, Level 1.** `run_self_tests` or a restart is an acceptable periodic self-test (IG
  10.3.E: "At security levels 1 and 2, acceptable means for initiating the periodic self-tests
  include a provided service, resetting, rebooting or power cycling"), and the error log of IG
  10.3.D does not apply (Levels 3 and 4). The integrity test, the service indicator and the
  module boundary in [the table above](#what-a-fips-140-3-module-still-needs) are what a
  validation needs next.

## How this was checked

* Diffs: `git diff --numstat` of each variant against `649981b4`, summed per crate and per
  `src/`, `tests/`.
* Tests, per variant, rustc 1.101.0-nightly (the machine's default) unless noted:
  `cargo test --workspace`; `cargo test --manifest-path crypto/fips/Cargo.toml` with default
  features, `--no-default-features --features aes`, `--features sha2`, and no features (all
  pass); `cargo +stable check --all-targets` on the fips manifest (passes); A:
  `cargo test -p bouncycastle-core --features fips` (passes); B:
  `cargo test -p bouncycastle-aes --features fips --lib`, likewise sha2 (pass);
  `cargo test -p bouncycastle-aes --features fips` (fails in both, S-4).
* Vectors: a script extracted every byte array from A's `vectors.rs` and B's two `self_test.rs`
  and compared them with `gcmtestvectors.zip`, `shabytetestvectors.zip` (csrc.nist.gov, CAVP)
  and the text of SP 800-38A (nvlpubs.nist.gov), all downloaded on the review date. All equal.
* IG: the PDF downloaded on the review date (249 pages, "Last Update: August 19, 2026"); sections
  1.A, 1.B (the error-state passages), 2.4.C, 5.A (Background), 10.2.A, 10.3.A, 10.3.B, 10.3.D
  and 10.3.E read in full or as stated.
* Mutation testing: `cargo mutants` with a copy of `.cargo/mutants.toml` without `examine_globs`
  (and, for B, without the `self_test.rs` exclusion); `-p bouncycastle-core --features fips -f
  '**/fips.rs'` (A), `-p bouncycastle-aes|sha2 --features fips -f '**/self_test.rs' -- --lib`
  (B). For `bouncycastle-fips` itself (S-6): `cargo mutants --in-place` inside `crypto/fips` of
  a scratch copy of each tree, with the `profile` line also removed from the config.
* Dependencies: `cargo tree --manifest-path crypto/fips/Cargo.toml -e normal`, and
  `cargo tree --workspace -e features`.
* Not checked: stack usage (B's figure is its own), behaviour on any target but x86-64 Linux,
  and anything marked unverified above.
