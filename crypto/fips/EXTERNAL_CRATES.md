# The external crates inside the module boundary

Decided 2026-11-13, against `feature/fips-kats` at `cf27fbca`. This is the rule the
module-integrity issue deferred ("a rule for them, name, version and the registry checksum from
`Cargo.lock` being the obvious one, is a later issue").

## The crates

The boundary's normal-dependency closure reaches outside the project through `bouncycastle-rng`,
which depends on `getrandom`. In `crypto/fips/Cargo.lock`, the closure of the 15 boundary crates
over the lock's dependency lists holds four external crates:

| Crate | Version | Why it is there |
|---|---|---|
| `getrandom` | 0.4.3 | `bouncycastle-rng`'s seed source |
| `cfg-if` | 1.0.5 | a dependency of `getrandom` on every target |
| `libc` | 0.2.191 | a dependency of `getrandom` on Linux, macOS and most other Unix targets |
| `r-efi` | 6.0.0 | a dependency of `getrandom` on UEFI only |

`cargo tree -e normal` for an x86-64 Linux host shows the first three; `--target all` adds `r-efi`.
A lock file is resolved for every target at once, so `r-efi` is in every lock that has `getrandom`.
It is pinned with the rest so that the table is the same on every target.

None of these crates can carry a `links` key or a build script of ours, so the per-crate source
HMAC cannot reach them. The registry checksum stands in for it: it is the SHA-256 of the `.crate`
file that crates.io serves for that version, which is immutable once published.

## What made this hard

* **Two lock files.** `crypto/fips` is its own workspace with its own `Cargo.lock`. A program
  using the module is built against *its* lock file, which Cargo resolves afresh.
* **`build.rs` cannot see the lock.** Cargo gives a build script `CARGO_MANIFEST_DIR` and
  `CARGO_MANIFEST_PATH`, but no workspace root or lock path (checked with a probe build script
  on cargo 1.98.1 stable). For a consumer that takes `bouncycastle-fips` from a registry, the
  manifest directory is under `~/.cargo/registry/src`, nowhere near the consumer's lock.
* **No `DEP_*` metadata.** That needs a `links` key on the external crate.

## The rule

1. **The pin is name, version and crates.io checksum** of each external crate in the boundary's
   closure, kept as `EXTERNAL_PINS` in `build-support/src/lib.rs`.
2. **It goes into the table, as extra rows.** Each external crate has one row, named by its
   package name. The row's value is HMAC-SHA-512, with the module key, over the name, a zero byte,
   the version, a zero byte and the 32 checksum bytes. The rows sort bytewise with the boundary
   crates (so `bouncycastle-*`, then `cfg-if`, `getrandom`, `libc`, `r-efi`). The module HMAC then
   covers them, so a new version of any of them gives a new published constant, as a new version
   of a boundary crate does. The toolchain record is not covered by the module HMAC and so was not
   chosen.
3. **Cargo enforces the version.** `bouncycastle-fips`'s `Cargo.toml` asks for each pinned crate
   with an `=` requirement, under `[target.'cfg(any())'.dependencies]`. `cfg(any())` matches no
   target, so the four are never compiled as dependencies of `bouncycastle-fips`, but resolution
   still honours the requirements: a lock file is resolved for every target. Cargo allows one
   version per semver-compatible range in a graph. A program using the module therefore resolves
   to exactly these versions or fails to resolve. Only users of `bouncycastle-fips` are
   constrained; `bouncycastle-rng` keeps its loose requirement. `build.rs` reads
   `bouncycastle-fips`'s own `Cargo.toml` and fails the build unless each of those requirements is
   `=` the pinned version. A bump made in one place and not the other therefore fails the build.
4. **What happens when the consumer's resolver wants another version:** resolution fails, naming
   `bouncycastle-fips`'s `=` requirement. The consumer has to align with the module's versions.
   Moving the pin is a change to the module, which needs a new constant.
5. **The checksum is checked by the independent script, against the build's own lock file.**
   Cargo itself refuses a downloaded `.crate` whose SHA-256 differs from the registry index, so
   an `=` version from crates.io implies the checksum. Three cases break that: `[patch]`, source
   replacement, and another registry. All of them show only in the build's `Cargo.lock`, as a
   different `source`, a missing `checksum` or a different one. `dev_scripts/fips_module_hmac.py`
   takes that lock with `--lock`. It derives the external rows from the lock, not from the pins:
   it walks the closure of the boundary crates over the lock's dependency lists, and refuses any
   package in it that is neither a boundary crate nor a crates.io package with a checksum. Its
   module HMAC then equals the published one only if the program was built from the pinned
   versions and checksums. The script stays independent of the Rust code: nothing in it comes
   from `EXTERNAL_PINS`.
6. **`crypto/fips/Cargo.lock` is committed** (the repository ignores `Cargo.lock` everywhere
   else). It is the reference lock for the pins, and the fips tests check that the script reads
   the same four crates out of it.

`bc-rust fips-info` (and `ModuleInfo`'s `Display`) prints one `external <name> <version>
<checksum>` line per pinned crate after `module-hmac`, and the script prints the same lines. An
operator can then read the versions and checksums off the program as well as off the lock.

## What it does not cover

* **A program whose lock is not checked.** Nothing at build time sees the lock, so a `[patch]`
  that keeps the version and changes the contents builds. The program then embeds the pinned rows
  and so the published constant. Only the script run against that program's `Cargo.lock` catches
  it. The Security Policy's build procedure has to include that run.
* **The external crates' compiled form** is covered, as all code is, by the binary HMAC of each
  program.
