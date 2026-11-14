# FIPS 140-3 self-tests and module integrity: summary of the work

**Status: a prototype, not a validated module.** It implements the known-answer self-tests
(CASTs) FIPS 140-3 requires for AES, SHA-2, HMAC-SHA-512, ECDSA and ECC CDH, the gates that keep
AES, SHA-2, ECDSA and ECC CDH unusable until the self-tests pass, the pair-wise consistency tests
on generated ECDSA and ECC CDH key pairs, and the error state a failure enters; and the module's
integrity: a source pin (per-crate source HMACs and a module HMAC over them) and a software
integrity test over the compiled program (the binary HMAC), with an approved-mode build that
leaves SM2 out. A FIPS 140-3 validation needs more (see
[What is still missing](#what-is-still-missing)).

Based on `release/0.1.4alpha`. The sections up to [Verification](#verification) describe the self-test
work as first done (AES and SHA-2); [Module integrity](#module-integrity) describes what was
added after it.

This file is the overview. The detail lives in:

| For | Read |
|---|---|
| The two layouts explored, measured, with every finding and the nine decisions | [`APPROACHES.md`](APPROACHES.md) |
| The final design: usage, requirements (IG quotes), vectors, memory, security considerations | the crate docs, [`src/lib.rs`](src/lib.rs) (`cargo doc --manifest-path crypto/fips/Cargo.toml --open`) |
| The application flow, runnable | [`examples/crypto_officer.rs`](examples/crypto_officer.rs) |

## The task

Prototype FIPS 140-3 known-answer tests for AES and SHA-2 only, to find out how the API should
work: each algorithm has a self-test; a "crypto officer" builds the application with a `fips`
crate that runs the self-tests once at startup and can run them again on demand (or by
restarting); creating a key or service must check the self-test has passed; and no crate
internals may be made public just for the KATs. Explain the approaches, with ups and downs.

## How the work was done

1. **Base** (`feature/fips-kats-base`): shared vocabulary types in `bouncycastle-core` behind a
   `fips` feature, a `bouncycastle-fips` skeleton kept out of the workspace, and the choice of
   vectors, each checked against its NIST source.
2. **Two prototypes**, built independently:
   * **Variant A** (`feature/fips-kats-separate-crate`): every KAT in `bouncycastle-fips`; the
     status of each algorithm in a table in `core`; the AES and SHA-2 constructors read it.
   * **Variant B** (`feature/fips-kats-embedded`): each algorithm crate carries its own KAT and
     status behind its `fips` feature; `bouncycastle-fips` runs them in order.
3. **Review and comparison**: [`APPROACHES.md`](APPROACHES.md). Measured both (diff size, public
   items, mutants, binary size), listed 16 findings, considered three layouts not prototyped, and
   put nine decisions to the project, all answered on 2026-11-10.
4. **Convergence** (`feature/fips-kats`): variant B with the recommended changes, the CLI, the
   example, the docs and the quality gates. This is what the PR contains.

## The approaches in brief

| | Variant A: separate crate | Variant B: embedded (chosen) |
|---|---|---|
| Where the KATs live | `bouncycastle-fips` | the algorithm crate (`aes`, `sha2`) |
| Where the status lives | a table in `core` | a private `static` in the algorithm crate |
| Can a pass be forged? | **Yes** (A-1): any code that writes the table first can record `Passed` for an untested algorithm | No: only the crate's own KAT run can produce `Passed` |
| Changes to algorithm crates | tiny (15 and 42 lines) | about 300 lines each |
| "KATs use the public API only" | enforced by the compiler | by convention |
| An algorithm crate can report its own failure (needed for ML-KEM/ML-DSA pairwise tests) | no | yes |

Also considered and not built: a wrapper-only crate (gates nothing a dependency bypasses), lazy
self-tests on first use (possible later on top of B), and an automatic pre-`main` constructor
(needs `unsafe`, platform-specific). Details and trade-offs in
[`APPROACHES.md`](APPROACHES.md#options-considered-and-not-prototyped).

**Why B:** A's forgeable pass is inherent to putting a writable status in `core`, and A cannot
let an algorithm crate record a failure. A's advantages are about review cost; B's are about what
the gate can be trusted to mean.

## Decisions taken (2026-11-10)

1. "No pub for KATs" means KATs must not need internals made public; an algorithm crate may
   export `self_test()` and a status function.
2. Layout: variant B.
3. The KATs may bypass the gate through a crate-private entry, so the gate admits only `Passed`.
4. Keep the explicit `power_on_self_tests()` call; decide on lazy-on-first-use later.
5. A failure of any self-test stops **all** keys and hashes, existing and new, module-wide.
6. `SHA256::new()` keeps panicking before power-on; `from_suspended` gets an error variant.
7. Keep a cargo feature (not a `--cfg`) for now.
8. Scope stays AES and SHA-2 only (no HMAC CAST yet). Since then HMAC-SHA-512 got a CAST with
   the integrity work, and ECDSA and ECC CDH theirs; HKDF and the DRBG still have none.
9. A FIPS 140-3 validation at Security Level 1 is the goal.

## The final design

* **`bouncycastle-core`** (`fips` feature): the status types; `SelfTestStatusCell`, which runs a
  KAT, guards against concurrent runs and panics, and records the result; and the module error
  state (`enter_error_state` / `error_state` / `assert_operational`): one process-wide flag,
  set by any failure, never cleared.
* **`bouncycastle-aes`, `bouncycastle-sha2`** (`fips` feature): each holds its KAT vectors and a
  private status cell. `self_test()` runs the KAT; the gates refuse creation until `Passed`
  (AES: `SymmetricCipherError::SelfTestNotPassed`; SHA-2: a panic in the infallible `new()`,
  `SuspendableError::SelfTestNotPassed` from `from_suspended`), and after a failure the gated
  operations of an existing key, worker or hash panic. For AES those are the block operations
  only, which leaves a gap (see [What is still missing](#what-is-still-missing)).
* **`bouncycastle-fips`**: turns the features on and offers `power_on_self_tests()`,
  `run_self_tests()` and `self_test_status()`. It is excluded from the root workspace so that
  `cargo test --workspace` never runs gated.
* **`bc-rust` CLI** (`fips` feature): every invocation that reaches a subcommand runs the
  power-on self-tests first and exits with status 3 if they fail (`--help`, `--version` and
  usage errors exit from argument parsing, before power-on and before any cryptographic
  service); `bc-rust fips-self-test` re-runs them and prints each algorithm's status, and
  `bc-rust fips-info` prints the module table. Without the feature the CLI is unchanged. The
  approved-mode build is a separate binary, `cli-fips/`.

Application flow, as in the example:

```rust
use bouncycastle_fips::{power_on_self_tests, run_self_tests};

fn main() {
    if let Err(e) = power_on_self_tests() {       // first thing, before any AES or SHA-2 use
        eprintln!("FIPS self-tests failed: {e:?}");
        std::process::exit(1);
    }
    // ... create AES keys and SHA-2 hashes as usual ...
    run_self_tests().expect("periodic self-test"); // on demand; services stay usable
}
```

Vectors (all checked against the NIST sources): AES-GCM-128 encrypt and decrypt, CAVP
`gcmEncryptExtIV128.rsp` Count 0; AES-CBC-128 decrypt, SP 800-38A F.2.2; SHA-256 and SHA-512,
CAVP `ShortMsg` `Len = 24`. One AES CAST covers every mode and key size, the SHA-256 CAST covers
SHA-224, and the SHA-512 CAST covers SHA-384 and SHA-512/t (IG 10.3.A).

## Findings: what convergence did with each

Finding ids are those of [`APPROACHES.md`](APPROACHES.md#findings). The commit hashes are those
of the PR branch before the squash merge.

| Finding | Problem | Outcome | Commit |
|---|---|---|---|
| A-1 … A-5 | variant A's defects (forgeable pass, etc.) | not applicable: variant A not chosen | — |
| B-1 | a crate's own failure stopped only that crate | **fixed**: one module error state in `core` | `b3f5ebf4` |
| B-2 | a panicking KAT left the status `Running` | **fixed**: unwind guard records a failure | `3dc64e79` |
| B-3 | state machine duplicated per crate | **fixed**: one in `core` (`SelfTestStatusCell::run`) | `3dc64e79` |
| B-4 | an overlapping power-on call returned an error; single-feature builds untested | **fixed**: waits and reports; scenarios run per feature | `f1375b29` |
| B-5 | a match arm in `bouncycastle-fips` never tested | **gone**: the arm no longer exists | `b3f5ebf4` |
| S-1 | services could be created during the first run | **fixed**: gate admits only `Passed`; KATs run ungated (decision 3) | `65860d9f` |
| S-2 | only creation was gated | **mostly fixed**: existing keys, workers, hashes stop at their next gated operation (decision 5); an AES worker's operations that need no new block do not | `278f8eb7` |
| S-3 | a failure mid-run made a KAT panic | **fixed**: KATs never pass through a gate | `65860d9f` |
| S-4 | algorithm crates' own test suites fail with `fips` on | **open**, documented | — |
| S-5 | HMAC, HKDF, DRBG usable with no CAST | **partly done**: HMAC-SHA-512 has a CAST (added with the integrity work); HKDF and the DRBG have none, documented | — |
| S-6 | `cargo mutants` could not run on `bouncycastle-fips` | **fixed**: profile added, `--in-place` documented | `438b8ac9` |
| decision 6 | `from_suspended` panicked | **fixed**: `SuspendableError::SelfTestNotPassed` | `ece224f7` |
| from A | every byte of every vector must matter | **adopted** in the unit tests | `68cbdacd` |

The rest of the branch: the CLI (`fc2f4456`), the crypto officer example (`b11863a9`) and the
docs (`c10dfe8b`).

## Verification

* Figures in this section are for the self-test work alone; the integrity work's are in its
  commit messages.
* `cargo test --workspace` (features off): 2673 passed, 0 failed, 8 ignored.
* `bouncycastle-fips` tests with each feature combination (both, `aes` only, `sha2` only, none);
  `aes` and `sha2` `--features fips --lib`; `core --features fips`; `cargo test -p cli` with and
  without `--features fips`; the example run by hand.
* `cargo build --workspace --all-targets --all-features`; `cargo fmt --all --check`.
* `cargo mutants` on `bouncycastle-fips` (self-tests only, before the integrity work): 9 mutants, 8 caught, 1 unviable, 0 missed. Not yet run
  on the self-test code in `core`, `aes` and `sha2`.
* `quality_stats.sh` against variant B: code +180 lines, docstrings +171; `Err()` in core code
  607 → 597; `unwrap` in core code 1003 → 1005, both in test code under `src/`.
* Peak stack: first power-on 1964 B, power-on once passed 40 B, AES self-test 1948 B, SHA-2
  self-test 1320 B. With `fips`, each SHA-2 hash is 8 B larger.

## Module integrity

Added to this branch after the self-tests; designed in the module-integrity issue ("per-crate
source HMACs, a module HMAC over their table, and a binary HMAC").

* **Boundary.** The module is the normal-dependency closure of aes, ascon, hmac, hkdf, sha3, ec,
  ecdsa and eccdh: 15 crates (`aes`, `ascon`, `cipher`, `concatkdf`, `core`, `ec`, `eccdh`,
  `ecdsa`, `hkdf`, `hmac`, `rng`, `sha2`, `sha3`, `utils`, `x963kdf`). Each has a `links` key and a
  `build.rs` that reports its source directory and enabled features. `bouncycastle-fips` depends
  on all of them, and its build fails if the closure and its list disagree.
* **Source pin (module HMAC).** `build.rs` with `build-support/` HMACs each crate's sources
  (HMAC-SHA-512, public key, CRLF normalised) into a table ordered by package name, and the table
  into the module HMAC. Every program embeds the same table, whatever it uses.
  `bc-rust fips-info` prints it; `dev_scripts/fips_module_hmac.py` recomputes it independently.
  With the `fips-validated` feature the build and power-on hold it to
  `src/expected_module_hmac.rs`.
* **External crates.** `getrandom`, `cfg-if`, `libc` and `r-efi`, which `bouncycastle-rng` brings
  in, are table rows of their name, version and crates.io checksum. `=` requirements in
  `Cargo.toml` fix the versions, and the script checks the checksums against a build's
  `Cargo.lock`. Rule and reasoning: [`EXTERNAL_CRATES.md`](EXTERNAL_CRATES.md).
* **Software integrity test (binary HMAC).** With the `integrity` feature, power-on HMACs the
  program's own read-only ELF segments and compares the result with a slot that
  `bc-fips-install/` writes after linking (after `strip`, before signing). An unwritten slot fails.
* **Power-on order.** SHA-2 CASTs, HMAC-SHA-512 CAST, binary HMAC, module HMAC
  (`fips-validated`), then the AES, ECDSA and ECC CDH CASTs.
* **Approved mode.** `bouncycastle-ec`'s `sm2` feature is the one non-approved switch;
  `approved-only` fails the build if it is on and offers the approved services as concrete types
  in `bouncycastle_fips::approved`. Design and decisions: [`APPROVED_MODE.md`](APPROVED_MODE.md).

## ECDSA and ECC CDH

Added to this branch after the module integrity work, in the same layout (variant B):
`bouncycastle-ecdsa` and `bouncycastle-eccdh` each gained a `fips` feature with a `self_test()`,
a private status, gates, and a pair-wise consistency test (PCT) in `keygen`; `bouncycastle-fips`
runs them after AES (features `ecdsa` and `eccdh`, both default).

* **CASTs.** ECDSA: signature generation with `k` fixed, deterministic signature generation, and
  verification (IG 10.3.A Resolution 10 and Note10), on ECDSA-P256-SHA256, from NIST ACVP-Server
  (RELEASE/v1.1.0.39)
  `ECDSA-SigGen-FIPS186-5` tcId 131, `DetECDSA-SigGen-FIPS186-5` tcId 111 and
  `ECDSA-SigVer-FIPS186-5` tcId 54. ECC CDH: the P-256 primitive, CAVP
  `KAS_ECC_CDH_PrimitiveTest.txt` `[P-256]` `COUNT = 0` (IG D.F).
* **One curve per algorithm, not one per curve family.** Note16 asks for any one curve size and
  Note17 for one curve per field type, and every curve here is prime-field; IG D.F asks for "any NIST-recommended curve".
  P-256 is the smallest supported ([10.29]). The case for more (GeneralNote1, per-curve field
  arithmetic) is in the crate docs' Requirements section.
* **PCTs.** ECDSA: a deterministic signature under the new key, verified (the signature use the
  IG asks a PCT to match). ECC CDH: SP 800-56A Rev. 3 Section 5.6.2.1.4 method b, `[d]G == Q`.
  A failure drops the pair and enters the error state.
* **Gates.** Key generation, signer, verifier and agreement creation refuse until the self-test
  has passed (`SignatureError` / `KeyAgreementError::SelfTestNotPassed`); `derive_pk` panics;
  existing signers, verifiers and agreement workers refuse in the error state. Decoding keys is
  not gated.

## What is still missing

Before a Security Level 1 validation (decision 9), at least:

* a software integrity test on non-ELF targets (Mach-O, PE);
* an approved **service indicator**, since bc-rust also ships non-approved algorithms (SM3, SM4,
  ARIA, Camellia);
* **CASTs for every other approved algorithm** in the boundary: ascon, SHA-3 and SHAKE, HKDF,
  the X9.63 and concatenation KDFs, the Hash DRBG (ECDSA, ECC CDH and their pair-wise
  consistency tests are done; see [ECDSA and ECC CDH](#ecdsa-and-ecc-cdh));
* entropy source health tests, the GCM IV rules (IG C.H), the security policy and CAVP
  certificates;
* **stopping an existing AES worker completely**: the error-state check is in the AES block
  operations only, so a GCM or GMAC worker can still absorb data and produce or check its tag
  (`CIPH_K(J0)` and `H` are computed at creation), and a CTR, CFB or GCM worker can use up to 15
  bytes of keystream it has already buffered;
* **gating `bouncycastle-ec`**: it is inside the boundary, and its public `Curve` trait methods
  (`keygen_extra_bits`, `multiply_point`, `multiply_base_point`, `public_point`,
  `shamir_multiply`) reach key generation and the ECC CDH primitive with no CAST and no PCT;
* inhibiting output while `run_self_tests` re-runs the software integrity test (IG 10.3.E
  Resolution 5 exempts only the CAST re-runs; see the crate docs' Requirements section);
* a module HMAC for the crates as published: `cargo package` rewrites `Cargo.toml`, which the
  per-crate source HMAC covers, so a crates.io package gives a different value from a checkout.

Costs of the design to know about: the `links` keys mean two semver-incompatible versions of a
boundary crate cannot be in one build graph, and every user of the 15 crates compiles a small
build script for each; and `cli`'s optional `bouncycastle-fips` dependency brings the four `=`
pins into the root workspace's lock resolution even with `fips` off.

Smaller follow-ups: decide on lazy self-tests on first use (decision 4); let the algorithm crates'
own test suites run with `fips` on (S-4); revisit the cargo feature against a build-wide `--cfg`
(decision 7).

Full list and references: [`APPROACHES.md`](APPROACHES.md#what-a-fips-140-3-module-still-needs).

## Trying it

```sh
cargo test --manifest-path crypto/fips/Cargo.toml                    # the fips crate
cargo run --example crypto_officer --manifest-path crypto/fips/Cargo.toml
cargo build --release -p cli --features fips                         # CLI; exits 3 until installed:
cargo build --release --manifest-path crypto/fips/Cargo.toml -p bc-fips-install
crypto/fips/target/release/bc-fips-install target/release/bc-rust    # writes the binary HMAC
target/release/bc-rust fips-self-test                                # prints each status
cargo test -p bouncycastle-aes --features fips --lib                 # AES KAT unit test
```
