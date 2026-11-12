# Approved-mode builds: leaving non-approved curves and KDF pairings out

Proposal, 2026-11-12, against `feature/fips-integrity` at `d54a9687`. It changes no code. It
answers the question left open in the module-integrity issue ("Not everything in the EC crates
is FIPS approved"): one source tree has to produce both a FIPS-approved build and a full build,
so how is the switch between them made?

The constraints the answer has to meet:

1. The switch only selects what is compiled. It never rewrites, generates or deletes a file that
   the per-crate source HMAC covers (`src/`, `Cargo.toml`, `build.rs`), so every crate's table
   entry, and so the module HMAC, is the same whichever way the switch is set.
2. The setting is in the toolchain record that `bouncycastle-fips` embeds beside the table.
3. It survives Cargo's feature unification, which is why `crypto/fips` is already its own
   workspace (see "Feature unification" in `crypto/fips/src/lib.rs`).

It also has to fit two earlier decisions: PR #133 ruled out per-algorithm and per-crate *FIPS
gates* pending a workspace-wide `fips_mode` design, and decision 7 in `APPROACHES.md` kept a
cargo feature rather than a `--cfg` "for now; revisit with the module boundary". This is that
revisit.

Every spec statement below was checked against a copy downloaded on 2026-11-12: NIST SP 800-186
(February 2023), FIPS 186-5 (February 2023), NIST SP 800-56C Rev. 2 (August 2020) and NIST
SP 800-108r1-upd1 (August 2022). The two Cargo behaviours the design depends on were checked by
a throwaway probe on cargo 1.98.1 stable ([How this was checked](#how-this-was-checked)).

## Short version

**Recommendation: additive cargo features on the crates that carry non-approved items, checked
and recorded by `bouncycastle-fips`, whose own public API offers only approved services.**

* `bouncycastle-ec` and `bouncycastle-ecdsa` put each non-approved curve behind its own cargo
  feature (as decided, that is SM2 alone, in `ec`). Those features are on by default, so `cargo build --workspace` and every existing
  consumer are unchanged. A feature only adds a curve; none removes one, so they unify safely.
* Each crate's build script (already present since sub-issue 1) also exports its enabled feature
  set as `links` metadata. The combining build script in `bouncycastle-fips` reads it, writes it
  into the toolchain record, and, with `bouncycastle-fips`'s `approved-only` feature on, **fails
  the build** if any non-approved feature has been switched on anywhere in the graph. That turns
  feature unification from a silent leak into a build error.
* `bouncycastle-fips` re-exports the approved services as concrete types, so the generic doors
  that compile-time switches cannot shut (an unsealed `HMACParams`, signers that accept any `RNG`)
  are not part of the module's service interface.

Nothing in this rewrites a source file, so the table is the same for both builds by
construction; [the last section](#proving-the-same-table-acceptance-criterion) describes the test
that proves it.

## Decisions (2026-11-12)

The four [open decisions](#open-decisions) were put to the project owner the same day:

1. **Mechanism: A + C, as recommended.**
2. **Curves: P-256, P-384, P-521, brainpoolP256r1/384r1/512r1 and secp256k1 are all in the
   approved build; only SM2 is left out.** Not the recommendation (P-curves only). The rule is to
   follow BC-FJA. In the 3.0.X line (`bc-fips-3.0.X-java`, `main` at `90ad7196`),
   `org.bouncycastle.crypto.fips.FipsEC.approvedKeySet` is built from every `DomainParameterID`
   except the binary B-/K- curves (those only with the `org.bouncycastle.ec.enable_f2m`
   override). That set includes P-224 to P-521, brainpoolP224r1 to P512r1 and their `t1` twists,
   and secp256k1, with field size of at least 224 bits enforced by `validateCurveSize`. SM2 and
   SM3 are in the non-approved general provider (`core-gprov`, `crypto/general/SM2*.java`,
   `SM3Digest.java`), which is registered only outside approved-only mode. (The older 2.0.X line,
   `bc-fips-java` on `2.0.X`, approves only the NIST curves; 3.0.X is the line followed here.)
   The purpose conditions in SP 800-186 Appendix H belong in the Security Policy, as they do for
   BC-FJA. One consequence: **`bouncycastle-ecdsa` has no curve to gate.** The only feature
   needed is `bouncycastle-ec/sm2`. The "Options" section below is left as written before the
   decision, and "What changes" is narrowed to match it.
3. **Generic doors: facade types only, as recommended.** `HMACParams` stays unsealed and the
   algorithm crates keep `&mut dyn RNG`. In an approved build `bouncycastle-fips` offers the
   concrete approved HKDF/HMAC aliases and ECDSA wrappers that take a `HashDRBG_*`. BC-FJA draws
   the same HKDF line: `FipsKDF.AgreementKDFPRF` lists SHA-1, SHA-2 and SHA-3 (as hashes, HMACs,
   and KMAC128/256), which matches SP 800-56Cr2 Table 4. SM3 is not among them.
4. **CLI: a separate build later, as recommended.** `cli`'s `fips` feature stays "a full build
   with the self-tests and integrity checks". An approved-mode `bc-rust` will be built from its
   own workspace in a later task.

## What is not approved, as of `d54a9687`

### `bouncycastle-ec`: eight curves, not seven

The issue says seven; the crate has eight. `ecdsa` has seven, and SM2's arithmetic lives in
`ec` too (`hazmat::sm2*`, used by `bouncycastle-sm2`).

| Curve (modules in `ec::hazmat`) | Status | Source |
|---|---|---|
| P-256 (`p256*`) | Approved for ECDSA and EC key establishment | SP 800-186 §3.1.2, Table 2 "Allowed Usage of the Specified Curves": P-224, P-256, P-384, P-521 → "ECDSA, EC key establishment (see [SP_800-56A])"; curve in §3.2.1.3 |
| P-384 (`p384*`) | Approved, as above | Table 2; §3.2.1.4 |
| P-521 (`p521*`) | Approved, as above | Table 2; §3.2.1.5 |
| brainpoolP256r1, P384r1, P512r1 (`bp256r1*`, `bp384r1*`, `bp512r1*`) | **Allowed with a condition**: not in Table 2 | SP 800-186 Appendix H.1: "This standard also allows the curves specified in … [RFC_5639] for ECDSA signatures as well as EC key establishment … These curves were pseudorandomly generated and are allowed to be used for interoperability reasons." The Executive Summary glosses this as "(i.e., to accommodate inclusion in FIPS-validated products)". |
| secp256k1 (`p256k1*`) | **Allowed with a condition**: not in Table 2 | SP 800-186 Appendix H.2: "The curve secp256k1 is allowed to be used for blockchain-related applications." |
| SM2 (`sm2*`) | **Not approved**: SP 800-186 does not mention it | SP 800-186 Table 2 and Appendix H (searched for "SM2": no match) |

The shared arithmetic (`nat`, `barrett`, `montgomery`, `inverse_vartime`) serves every curve and
stays in both builds.

The two conditional curves are the real decision (see [Open decisions](#open-decisions)). Their
conditions are about the *caller's purpose* ("interoperability", "blockchain-related
applications"), which nothing in a library can check; a module that offers them as approved
services can only state the condition in its Security Policy. Whether a testing lab and the CMVP
accept that for this module, and whether ACVP has test coverage for them, was **not checked**
here.

### `bouncycastle-ecdsa`

| Item | Status | Source |
|---|---|---|
| ECDSA over P-256/SHA-256, P-384/SHA-384, P-521/SHA-512 (`ecdsa_p256`, `_p384`, `_p521`, `keys_*`) | Approved | FIPS 186-5 §6 ("domain parameters … are included in SP 800-186"), §6.4 ("An approved hash function or XOF … shall be used"); each curve is fixed to one SHA-2 hash whose strength matches `len(n)` (§6.1: "A hash function that provides a lower security strength than is associated with the bit length of n shall not be used") |
| Deterministic ECDSA on the same three (`ECDetDSA*Signer`, `rfc6979_p*`) | Approved | FIPS 186-5 Explanation item (2) ("known as deterministic ECDSA is also approved"), §6.3.2, Appendix A.3.3: "HMAC_DRBG shall be used with the same hash function as the one used to process the message M". The `rfc6979_*` modules key HMAC with the curve's own hash, as required. |
| ECDSA and deterministic ECDSA over brainpoolP256r1/384r1/512r1 (`*_bp*r1`) | Conditional, follows the curve | SP 800-186 Appendix H.1, as above |
| ECDSA and deterministic ECDSA over secp256k1 (`*_p256k1`) | Conditional, follows the curve | SP 800-186 Appendix H.2, as above |
| `keygen(rng: &mut dyn RNG)`, `create_signer(rng, …)`, `sign(rng, …)` | **Open door, not an algorithm**: any `RNG` is accepted, including one that is not an approved DRBG | FIPS 186-5 §6.4, item 5: "An approved random bit generator (not needed for deterministic ECDSA)". A compile switch cannot close this; the module's service interface has to (only `HashDRBG_*` from `bouncycastle-rng`). |
| `der` (signature encoding) | Not a cryptographic algorithm; no status needed | — |

### `bouncycastle-hkdf`, and the KDF pairings that reach it from `sha2`, `sha3` and `sm3`

HKDF is `HKDF<H: HMACParams>`, generic over the hash. SP 800-56Cr2 §5.1 names it: "[RFC 5869]
specifies a version of the above extraction-then-expansion key-derivation procedure using HMAC
for both the extraction and expansion steps", and requires that "If HMAC-hash is used in the
randomness-extraction step, then the same HMAC-hash (i.e., using the same hash function, hash)
shall be used as the PRF in the key-expansion step", which `HKDF<H>` does by construction. So
the question is only which `H` are approved. SP 800-56Cr2 §5.2, Table 4 ("MAC( salt, Z, …) =
HMAC-hash( salt, Z ) (For Randomness Extraction)") lists SHA-1, SHA-224, SHA-256, SHA-512/224,
SHA-512/256, SHA-384, SHA-512 and SHA3-224/256/384/512.

| Pairing (where the `HMACParams` impl lives) | Reachable how | Status |
|---|---|---|
| HKDF-SHA256, -SHA384, -SHA512 (`sha2`) | Aliases `bouncycastle_sha2::hkdf::HKDF_*`; `KDFFactory` | Approved (Table 4) |
| HKDF-SHA224, -SHA512/224, -SHA512/256 (`sha2`) | `HKDF<SHA224>` etc.: the `HMACParams` impls exist, no alias | Approved (Table 4) |
| HKDF-SHA3-224/256/384/512 (`sha3::hmac`) | `HKDF<SHA3_256>` etc.: impls and `HKDF_SHA3_*_NAME` exist, no alias, not in the factory | Approved (Table 4) |
| **HKDF-SM3** (`sm3::hkdf::HKDF_SM3`) | Alias; registered in `KDFFactory` as `"HKDF-SM3"` | **Not approved**: SM3 is not in Table 4. `bouncycastle-sm3` is outside the boundary, but the HKDF code that runs is the module's. |
| **HKDF over any downstream hash** | `HMACParams` is "deliberately **not** sealed" (`crypto/hmac/src/lib.rs`), so any crate can implement it | **Not approved** unless the hash is in Table 4. A compile switch on the module cannot remove a generic; only the service interface can. |

`bouncycastle-hkdf` itself has nothing to compile out: the non-approved pairings are made
*outside* it. The same holds for HMAC (`bouncycastle-hmac`, also generic over `HMACParams`).

### `bouncycastle-sha3`

Nothing to compile out. Every public algorithm is in an approved standard: SHA3-224/256/384/512
and SHAKE128/256 (FIPS 202), cSHAKE, KMAC, TupleHash and ParallelHash (SP 800-185), HMAC-SHA3
(FIPS 198-1 over FIPS 202). The raw permutation is not public (`mod keccak` is private; only `KeccakSize` and a
state-length constant are re-exported from it). HKDF-SHA3,
the "pairing" the task asked about, is approved (Table 4, above). KMAC used as a KDF
(SP 800-56Cr2 Option 3 / SP 800-108r1 §4.4) is not implemented, so it is not a question yet.

Two usage-level items are out of scope for a compile switch and belong to the Security Policy
and service indicator instead: `from_key_material_allow_weak` (HMAC keyed below the hash's
strength), and HKDF called with no salt (handled per SP 800-56Cr2 §5.1 already, see the `hkdf`
crate docs).

### Not on this base

`eccdh`, `concatkdf` and `x963kdf` are not on `feature/fips-integrity`; their curve and
hash pairings are for sub-task 7 (#uvonkv), which should apply the same features to `eccdh` that
this proposal gives `ecdsa`. SM2 signing and encryption (`bouncycastle-sm2`) are outside the
boundary and stay there.

## The options

### A. A cargo feature on each crate that carries non-approved items

`ec` gets one feature per non-approved curve (`brainpool`, `secp256k1`, `sm2`), `ecdsa` gets
`brainpool` and `secp256k1` forwarding to `ec`'s, `sm2` turns on `bouncycastle-ec/sm2`. All are
in `default`. The modules and their re-exports are wrapped in `#[cfg(feature = "…")]`. An
approved build depends on them with `default-features = false`.

* **Up:** stable Cargo, already the mechanism decision 7 chose. Features only add code, so they
  unify safely: `bouncycastle-sm2` and an approved-mode crate can sit in one workspace and both
  compile. The workspace build is unchanged.
* **Up:** the setting is recordable. The crate's own build script sees its unified features as
  `CARGO_FEATURE_*` and can export them through `links` metadata; a dependent's build script
  then reads them as `DEP_BOUNCYCASTLE_EC_FEATURES`. The probe confirmed that this shows the
  *unified* set, including a feature turned on by a sibling dependency that the reader itself
  did not ask for.
* **Down:** unification means anything else in the program can turn a non-approved curve back on
  (any dependency that takes `bouncycastle-ec` with default features). Without a check that
  happens silently. Hence the check in the recommendation.
* **Down:** "approved" is the absence of features, so the approved build is the one that has to
  opt out at every edge: each boundary crate's dependency on `ec`/`ecdsa` needs
  `default-features = false`, and tests, benches and examples that use a gated curve need
  `required-features`. More `cfg` lines than B.
* **Not** a per-crate FIPS gate in the sense of PR #133: the features select curves for every
  build, approved or not, and nothing in them refers to FIPS.

A subtractive variant (a `fips` feature that *removes* the curves) is ruled out: it is not
additive, so `bouncycastle-sm2` and anything enabling `ec/fips` could not be built together, and
`cargo build --workspace` would break.

### B. A single build-wide `--cfg` (`RUSTFLAGS="--cfg bc_fips_approved"`)

Every crate checks `#[cfg(not(bc_fips_approved))]` around its non-approved items.

* **Up:** chosen by whoever builds the final binary and by nobody else, so there is nothing to
  unify; one switch for every crate, including sub-task 7's. Subtractive is fine here because it
  is global.
* **Up:** recordable. The probe confirmed that a build script sees a `RUSTFLAGS` cfg as
  `CARGO_CFG_BC_FIPS_APPROVED` and the whole flag string as `CARGO_ENCODED_RUSTFLAGS`, so the
  combining script can write it into the toolchain record directly.
* **Down:** it is outside the manifest. `cargo build` without the flag silently produces a full
  build; the approved-only check then has to be "the cfg is set", which is only as good as the
  person typing the command. `RUSTFLAGS` also replaces any `build.rustflags` a consumer has
  configured, rebuilds every crate (including third-party ones), and is easy to lose in IDEs,
  `cargo doc` and docs.rs.
* **Down:** with the flag set, `bouncycastle-sm2` (and the CLI, the umbrella crate and the
  factory, which name the gated types) no longer compile, so the approved build cannot be a
  `--workspace` build; it has to be `-p`-scoped or a separate workspace anyway. Every crate also
  needs `[lints.rust] unexpected_cfgs = { check-cfg = ['cfg(bc_fips_approved)'] }`, or the
  stable compiler warns on each use (the probe hit this warning).
* **Down:** reverses decision 7 before there is a reason the feature cannot meet.

### C. `bouncycastle-fips` exposes only approved types, algorithm crates untouched

* **Up:** no `cfg` anywhere, so the table is trivially identical; the module's services are
  exactly what the facade names, which is what a Security Policy lists. It is the only option
  that closes the generic doors (`HMACParams`, `&mut dyn RNG`), by offering concrete types.
* **Down:** it leaves nothing out. The non-approved curves are still compiled, and an application
  (or any of its dependencies) can call `bouncycastle_ec::hazmat::p256k1` directly, which is the
  objection `APPROACHES.md` already raised against a wrapper-only crate ("it gates nothing").
  Dead-code elimination will usually drop unused curves from the binary, but "usually, depending
  on the optimiser" is not the "leave the non-approved algorithms out" the issue asks for.

### Compared

| | A. per-crate features | B. global `--cfg` | C. facade only |
|---|---|---|---|
| Non-approved code absent from the build | Yes, if nothing re-enables it; the check makes that a build error | Yes | No |
| Source files identical, so same table | Yes | Yes | Yes |
| In the toolchain record | Via `links` metadata (needs a line in each build script) | Via `CARGO_CFG_*` / `CARGO_ENCODED_RUSTFLAGS` | Nothing to record |
| Feature unification | Unifies *on*; detectable, so enforceable | Not affected | Not affected |
| `cargo build --workspace` | Unchanged | Unchanged without the flag; fails with it | Unchanged |
| Closes generic doors | No | No | Yes |
| Fits decision 7 | Yes | Reverses it | Yes |

## Recommendation: A for compilation, C for the service interface, B kept in reserve

1. **Features (A)** in `ec` and `ecdsa` (and `eccdh` in sub-task 7), default-on, additive, one
   per non-approved curve family. As decided, that is `sm2` in `ec` only.
2. **Export the feature set.** Each boundary crate's existing `build.rs` adds one line,
   `cargo:features=<its CARGO_FEATURE_* list>`, beside `cargo:src_dir`. That is a change to
   `build.rs`, so it changes those crates' table entries once, when it lands, and never again
   with the setting.
3. **Record and enforce in `bouncycastle-fips`.** The combining build script (sub-issue 2) writes
   every boundary crate's feature set into the toolchain record. Note what this corrects in the
   issue: the record's "enabled `CARGO_FEATURE_*`" as written there are `bouncycastle-fips`'s
   *own* features only; a build script never sees its dependencies' features except through
   `links` metadata. With `bouncycastle-fips`'s `approved-only` feature on, the script fails the
   build if any boundary crate reports a non-approved feature, naming the crate and feature.
   `approved-only` is itself recorded, so `fips-info` prints which kind of build it is.
4. **Facade (C)** for what compilation cannot remove. In an `approved-only` build,
   `bouncycastle-fips` re-exports the approved services as concrete types: the `HKDF_SHA*`
   aliases rather than `HKDF<H>`, and ECDSA key generation and random-`k` signing wrapped to take
   a `HashDRBG_*` rather than `&mut dyn RNG`. As decided, the generic doors are not also shut at
   the type level.
5. **B in reserve.** If the feature turns out to be unmanageable (most likely cause: a third-party
   crate that pulls `bouncycastle-ec` with default features into an approved program), switching
   to a `--cfg` touches the same `#[cfg(...)]` sites and the same build-script line; nothing in A
   has to be undone first.

The approved build itself stays where the self-test build already is: `crypto/fips` as its own
workspace root, with its own `Cargo.lock`. The root workspace keeps building everything, on.

### What changes, for the implementing sub-task

Not part of this proposal; listed so the size is visible.

As decided (only SM2 is gated):

* `crypto/ec`: a default-on `sm2` feature; `#[cfg(feature = "sm2")]` on the `sm2*` module
  declarations in `hazmat/mod.rs`, and on SM2's tests, benches and doctests.
* `crypto/ecdsa`: nothing to gate. It takes `bouncycastle-ec` with `default-features = false`,
  so that an approved build which pulls in `ecdsa` does not turn `sm2` back on.
* `crypto/sm2`: `bouncycastle-ec` with `features = ["sm2"]`.
* `crypto/ec`'s `build.rs` (and every boundary crate's, for uniformity): the `cargo:features=`
  line.
* `crypto/fips`: the `approved-only` feature; the check and the record in the combining script
  (sub-issue 2); the facade types.
* `cli`, umbrella `bouncycastle`, `factory`, `mem_usage_benches`: no change needed, because they
  take default features. `KDFFactory`'s `HKDF-SM3` is outside the module and stays.
* Sub-task 7 (`eccdh`, `concatkdf`, `x963kdf`): the same treatment. Gate SM2 if `eccdh` gains
  it, and offer only SHA-1/SHA-2/SHA-3 KDF hashes through the facade.

## Proving the "same table" acceptance criterion

The issue's first criterion includes "a FIPS-approved-mode build and a full build of the same
sources … embed the same table". The argument, and the test that backs it:

* **By construction.** A per-crate value hashes the canonicalised bytes of `src/**`,
  `Cargo.toml` and `build.rs` read from the crate's manifest directory. Under A the setting
  changes only the `--cfg feature="…"` arguments Cargo passes to `rustc`; under B only
  `RUSTFLAGS`. Neither writes to the crate directory, and every build script writes only to
  `OUT_DIR`. So none of the hashed bytes depend on the setting. The one rule to keep: **no build
  script may generate into `src/`**, and the per-crate hasher should reject a file that changes
  between two reads in one run.
* **By test** (sub-task 5's end-to-end test, or sub-issue 2's): build `crypto/fips` twice, once
  with default features plus a dependent that turns `bouncycastle-ec/sm2` on, once with
  `--features approved-only`; print the table and module HMAC from each (`fips-info`, or the
  library call) and assert they are equal, and assert that the two toolchain records differ in
  exactly the feature lines. A third build with `approved-only` *and* the dependent that turns a
  non-approved feature on must fail to compile with the check's message.

## Open decisions

All four were decided on 2026-11-12; see [Decisions](#decisions-2026-11-12). Kept as they were
asked:

1. **Mechanism.** A + C as recommended, or B (reverses decision 7), or C alone (accepts that
   non-approved code is compiled).
2. **Which curves an approved build carries.** P-256/384/521 only (recommended: the conditions on
   the other two are about caller purpose, which the module cannot check and would have to push
   into the Security Policy), or also Brainpool (Appendix H.1, "for interoperability reasons"),
   or also Brainpool and secp256k1 (Appendix H.2, "blockchain-related applications"). SM2 is out
   in every option. The answer sets the feature names: one feature per *excluded* family.
3. **The generic doors in an approved build.** Re-export concrete approved types from
   `bouncycastle-fips` and leave `HMACParams` and `&mut dyn RNG` open in the algorithm crates
   (recommended: no API change for anyone else), or also seal them under `approved-only` (a
   feature that narrows a public trait, which is subtractive and so carries the unification
   problem option A avoids).
4. **The CLI.** `cli`'s `fips` feature lives in the root workspace, where every curve feature is
   unified on, so it cannot also turn on `approved-only`. Keep `bc-rust --features fips` as "a
   full build with the self-tests and integrity checks", and make an approved-mode `bc-rust` a
   separate build from its own workspace (recommended), or not offer an approved-mode CLI yet.

## How this was checked

* **Specs**, downloaded 2026-11-12 from `nvlpubs.nist.gov` into a scratch directory outside the
  repo, converted with `pdftotext` and searched: `NIST.SP.800-186.pdf` (Executive Summary;
  §3.1.2 Table 2; §3.2.1.3-5; Appendix H.1, H.2; no match for "SM2"),
  `NIST.FIPS.186-5.pdf` (§6, §6.1, §6.3.2, §6.4; Appendix A.3.3), `NIST.SP.800-56Cr2.pdf`
  (§5.1, §5.2 Table 4), `NIST.SP.800-108r1-upd1.pdf` (§4 for the iteration modes). Not
  consulted: the FIPS 140-3 IG and ACVP's coverage of Brainpool and secp256k1; the decision to
  approve them rests on BC-FJA 3.0.X's precedent.
* **BC-FJA**, local checkouts: `bc-fips-3.0.X-java` `main` at `90ad7196`
  (`core/.../crypto/fips/FipsEC.java`, `DomainParameterID`, `approvedKeySet`,
  `validateDomainParameters`, `validateCurveSize`; `FipsKDF.AgreementKDFPRF`;
  `core-gprov/.../crypto/general/SM2*.java`, `SM3Digest.java`), and `bc-fips-java` `2.0.X` at
  `e56d3412` (`FipsEC.DomainParameterID`: NIST curves only).
* **Code**, at `d54a9687`: `crypto/ec/src/hazmat/mod.rs` (module list), `crypto/ecdsa/src/lib.rs`
  (Status section, module list), `ecdsa_p256.rs` and `keys_p256.rs` (`&mut dyn RNG`),
  `rfc6979_p256k1.rs` (HMAC keyed per curve hash), `crypto/hkdf/src/lib.rs`,
  `crypto/hmac/src/lib.rs` (`HMACParams` unsealed), `HMACParams` impls in `sha2`, `sha3`, `sm3`,
  `crypto/factory/src/kdf_factory.rs`, `crypto/sha3/src/{lib,keccak}.rs`.
* **Cargo**, by a throwaway probe (two path crates, cargo 1.98.1 stable, outside the repo):
  a dependency with `links` that prints `cargo:features=` from its `CARGO_FEATURE_*`; the
  dependent's build script read `DEP_<LINKS>_FEATURES` as empty with `default-features = false`,
  and as `CARGO_FEATURE_DEFAULT,CARGO_FEATURE_EXTRA` once a second dependency took the same crate
  with default features (unification is visible). With `RUSTFLAGS="--cfg bc_probe"` the
  dependent's build script saw `CARGO_CFG_BC_PROBE` set and `CARGO_ENCODED_RUSTFLAGS` =
  `--cfg\x1fbc_probe`, and the compiler warned `unexpected cfg condition name: bc_probe`.
