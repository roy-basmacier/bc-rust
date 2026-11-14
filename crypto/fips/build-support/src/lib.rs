//! The build-time half of `bouncycastle-fips`'s module source pin: the per-crate source HMACs,
//! the closure check, the table, the module HMAC, and the generated file that embeds them.
//!
//! Used only by the build script of `bouncycastle-fips`, which supplies the I/O (environment,
//! files, `rustc -vV`); every function here other than [`read_crate`] is a function of its
//! arguments, so the tests can feed it inputs directly. It is a crate of its own, and uses the
//! standard library, because it runs only at build time; `Cargo.toml` says why it cannot be part
//! of the build script.
//!
//! The definitions are those of the FIPS module integrity issue, sections "Per-crate source HMAC"
//! and "The table and the module HMAC"; `dev_scripts/fips_module_hmac.py` implements them
//! independently, and `bouncycastle-fips` recomputes the module HMAC at run time with its own
//! copy of [`module_hmac`].
//!
//! # Usage Examples
//!
//! Not run as a doctest: a test build unifies features with `bouncycastle-fips`, whose
//! `bouncycastle-sha2/fips` gates SHA-512 until a self-test that this crate cannot run. The tests
//! of `bouncycastle-fips` (`tests/source_pin_tests.rs`) cover this crate and power on first.
//!
//! ```no_run
//! use bouncycastle_fips_build::{crate_hmac, SourceFile};
//!
//! let files = [
//!     SourceFile { path: "src/lib.rs".into(), bytes: b"//! A crate.\r\n".to_vec() },
//!     SourceFile { path: "Cargo.toml".into(), bytes: b"[package]\n".to_vec() },
//! ];
//! let mut reversed = files.clone();
//! reversed.reverse();
//! // The order of the files does not matter, nor does CRLF against LF.
//! assert_eq!(crate_hmac(&files), crate_hmac(&reversed));
//! ```
//!
//! # Memory Usage
//!
//! Build time only: it holds every file of the crate it hashes in memory at once.
//!
//! # 🚨 Security Considerations 🚨
//!
//! * The key is public. The values are a fingerprint of the sources that anyone can recompute,
//!   and pin nothing against someone who can change both the sources and the published constant.
//! * [`parse_manifest`] reads the subset of TOML that Cargo manifests use, and refuses what it
//!   does not understand (multi-line strings, renamed dependencies) rather than miss a dependency.

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle_core::traits::MACGenerator;
use bouncycastle_hmac::HmacKey;
use bouncycastle_sha2::SHA512;

/// The HMAC key of every per-crate source HMAC and of the module HMAC. Public, by design.
pub const MODULE_HMAC_KEY: &[u8; 41] = b"Legion of the Bouncy Castle FIPS Rust API";

/// The length of a per-crate source HMAC and of the module HMAC: HMAC-SHA-512's output.
pub const HMAC_LEN: usize = 64;

/// [`MODULE_HMAC_KEY`] as an HMAC-SHA-512 key.
fn hmac_key() -> HmacKey<SHA512> {
    // 41 bytes fit a 64-byte KeyMaterial, so this cannot fail.
    let material = KeyMaterial::<64>::from_bytes_as_type(MODULE_HMAC_KEY, KeyType::MACKey)
        .expect("a 41-byte key fits 64 bytes");
    // The key is a public string, so the strength check a key normally gets is beside the
    // point; with it skipped, a MACKey-tagged key cannot be refused.
    HmacKey::<SHA512>::from_key_material_allow_weak(&material)
        .expect("a MACKey-tagged key is accepted without the strength check")
}

/// The module HMAC of `table`: HMAC-SHA-512 under [`MODULE_HMAC_KEY`] over the rows in the order
/// given, each encoded as the package name, a zero byte, and the 64 hash bytes. [`build_table`]
/// gives the rows in the canonical order, bytewise by package name.
pub fn module_hmac(table: &[TableRow]) -> [u8; HMAC_LEN] {
    let key = hmac_key();
    let mut mac = key.create_generator();
    for (package, hmac) in table {
        mac.do_update(package.as_bytes());
        mac.do_update(&[0]);
        mac.do_update(hmac);
    }
    mac.do_final()
}

/// The module boundary: the normal-dependency closure of aes, ascon, hmac, hkdf, sha3, ec,
/// ecdsa and eccdh (`cargo tree -e normal`), in table order. Every one is a direct dependency of
/// `bouncycastle-fips`, in its `Cargo.toml`, and has a `links` key; [`check_closure`] holds the
/// two lists and the closure to each other.
pub const BOUNDARY: [&str; 15] = [
    "bouncycastle-aes", "bouncycastle-ascon", "bouncycastle-cipher", "bouncycastle-concatkdf",
    "bouncycastle-core", "bouncycastle-ec", "bouncycastle-eccdh", "bouncycastle-ecdsa",
    "bouncycastle-hkdf", "bouncycastle-hmac", "bouncycastle-rng", "bouncycastle-sha2",
    "bouncycastle-sha3", "bouncycastle-utils", "bouncycastle-x963kdf",
];

/// One crate from crates.io inside the module boundary, pinned by version and registry checksum
/// (crypto/fips/EXTERNAL_CRATES.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalPin {
    /// The package name.
    pub name: &'static str,
    /// The exact version. `bouncycastle-fips`'s `Cargo.toml` asks for it with `=`, which
    /// [`check_pins`] holds to this value.
    pub version: &'static str,
    /// The `checksum` of the package in `Cargo.lock`: the SHA-256 of the `.crate` file, as 64
    /// lowercase hex digits.
    pub checksum: &'static str,
}

/// The crates from outside this project in the boundary's normal-dependency closure, in table
/// order: the closure of [`BOUNDARY`] over `crypto/fips/Cargo.lock`, every target included.
/// `bouncycastle-rng` depends on `getrandom`, which brings the other three (`r-efi` on UEFI
/// only). They carry no `links` key or build script of ours, so the table holds their name,
/// version and checksum instead of a source HMAC; see [`external_hmac`]. A boundary crate may
/// depend directly on any of them.
pub const EXTERNAL_PINS: [ExternalPin; 4] = [
    ExternalPin {
        name: "cfg-if",
        version: "1.0.5",
        checksum: "4e7648175b45a9a48536d676f68d918270699102aa8dab5496df06904c914600",
    },
    ExternalPin {
        name: "getrandom",
        version: "0.4.3",
        checksum: "300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099",
    },
    ExternalPin {
        name: "libc",
        version: "0.2.191",
        checksum: "65cd87c9a6d60536580b316ad985726104730a5151c99845f2490428ef91240a",
    },
    ExternalPin {
        name: "r-efi",
        version: "6.0.0",
        checksum: "f8dcc9c7d52a811697d2151c701e0d08956f92b0e24136cf4cf27b57a6a0d9bf",
    },
];

/// The length of a registry checksum: SHA-256's output.
pub const CHECKSUM_LEN: usize = 32;

/// The table value of an external crate: HMAC-SHA-512 under [`MODULE_HMAC_KEY`] over the package
/// name, a zero byte, the version, a zero byte and the 32 checksum bytes.
pub fn external_hmac(name: &str, version: &str, checksum: &[u8; CHECKSUM_LEN]) -> [u8; HMAC_LEN] {
    let key = hmac_key();
    let mut mac = key.create_generator();
    mac.do_update(name.as_bytes());
    mac.do_update(&[0]);
    mac.do_update(version.as_bytes());
    mac.do_update(&[0]);
    mac.do_update(checksum);
    mac.do_final()
}

/// A checksum as `Cargo.lock` writes it, 64 lowercase hex digits, as bytes.
///
/// # Errors
/// If `hex` is not 64 lowercase hex digits.
pub fn parse_checksum(hex: &str) -> Result<[u8; CHECKSUM_LEN], String> {
    let digits = hex.as_bytes();
    let valid = |c: &u8| c.is_ascii_digit() || (b'a'..=b'f').contains(c);
    if digits.len() != 2 * CHECKSUM_LEN || !digits.iter().all(valid) {
        return Err(format!("`{hex}` is not 64 lowercase hex digits"));
    }
    let nibble = |c: u8| if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 };
    let mut out = [0u8; CHECKSUM_LEN];
    for (byte, pair) in out.iter_mut().zip(digits.chunks(2)) {
        *byte = nibble(pair[0]) << 4 | nibble(pair[1]);
    }
    Ok(out)
}

/// The table rows of [`EXTERNAL_PINS`], in their order.
pub fn external_rows() -> Vec<TableRow> {
    EXTERNAL_PINS
        .iter()
        .map(|p| {
            let checksum = parse_checksum(p.checksum).expect("EXTERNAL_PINS checksums are valid");
            (p.name.to_string(), external_hmac(p.name, p.version, &checksum))
        })
        .collect()
}

/// Checks that `bouncycastle-fips`'s own manifest asks for every crate of [`EXTERNAL_PINS`] with
/// the requirement `=<version>`, so that Cargo resolves exactly the pinned versions; and that it
/// asks for no other version of them.
///
/// # Errors
/// Every disagreement found, one per line.
pub fn check_pins(fips_manifest: &Manifest) -> Result<(), String> {
    let mut errors = Vec::new();
    for pin in EXTERNAL_PINS {
        let wanted = format!("={}", pin.version);
        let reqs: Vec<&str> = fips_manifest
            .requirements
            .iter()
            .filter(|(name, _)| name == pin.name)
            .map(|(_, req)| req.as_str())
            .collect();
        if reqs.is_empty() {
            errors.push(format!(
                "`{}` is pinned to {} (EXTERNAL_PINS in crypto/fips/build-support/src/lib.rs), \
                 but bouncycastle-fips's Cargo.toml does not ask for it: add `{} = \"{wanted}\"` \
                 under [target.'cfg(any())'.dependencies]",
                pin.name, pin.version, pin.name
            ));
        }
        for req in reqs.into_iter().filter(|r| *r != wanted) {
            errors.push(format!(
                "bouncycastle-fips's Cargo.toml asks for `{} = \"{req}\"`, but it is pinned to \
                 `{wanted}` (EXTERNAL_PINS in crypto/fips/build-support/src/lib.rs); a new \
                 version needs both changed, and its checksum from Cargo.lock",
                pin.name
            ));
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("\n")) }
}

/// The cargo features of boundary crates that add a service which is not approved, as
/// (package, feature). With `approved-only`, [`check_approved_only`] refuses a build in which any
/// of them is on. SM2 is not in SP 800-186 (crypto/fips/APPROVED_MODE.md).
pub const NON_APPROVED: [(&str, &str); 1] = [("bouncycastle-ec", "sm2")];

/// What the closure check needs from a boundary crate's `Cargo.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// `[package] name`.
    pub name: String,
    /// `[package] links`, if any.
    pub links: Option<String>,
    /// The names of its normal dependencies, target-specific ones included, in manifest order.
    /// Dev- and build-dependencies are not part of the module.
    pub normal_deps: Vec<String>,
    /// The version requirements of those normal dependencies that give one, as (name,
    /// requirement), in manifest order.
    pub requirements: Vec<(String, String)>,
}

/// One hashed file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    /// Its path relative to the crate directory, `/`-separated.
    pub path: String,
    /// Its bytes as on disk, before CRLF is turned into LF.
    pub bytes: Vec<u8>,
}

/// One boundary crate as the build script found it.
#[derive(Debug, Clone)]
pub struct BoundaryCrate {
    /// The `<LINKS>` of the `DEP_<LINKS>_SRC_DIR` variable that named its directory.
    pub dep_links: String,
    /// What its `Cargo.toml` says.
    pub manifest: Manifest,
    /// Every file under `src/`, plus `Cargo.toml` and `build.rs`, in any order.
    pub files: Vec<SourceFile>,
}

/// One row of the table: a package name and its per-crate source HMAC.
pub type TableRow = (String, [u8; HMAC_LEN]);

/// What the build records of the toolchain beside the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toolchain {
    /// The first line of `rustc -vV`, e.g. `rustc 1.91.0 (f8297e351 2025-10-28)`.
    pub rustc: String,
    /// The `host:` line of `rustc -vV`.
    pub host: String,
    /// Cargo's `TARGET`.
    pub target: String,
    /// Cargo's `OPT_LEVEL`.
    pub opt_level: String,
    /// Cargo's `PROFILE`: `debug` or `release`.
    pub profile: String,
    /// The enabled cargo features of `bouncycastle-fips`, lower case with `-`, sorted.
    pub features: Vec<String>,
    /// Each boundary crate's enabled cargo features, as its build script reported them, with
    /// the crates in table order.
    pub crate_features: Vec<CrateFeatures>,
}

/// One boundary crate's enabled cargo features: its package name, and the features lower case
/// with `-`, sorted.
pub type CrateFeatures = (String, Vec<String>);

/// The features in a boundary crate's `cargo:features=` value: comma-separated, as its build
/// script writes them. Sorted, and an empty value is no features.
pub fn parse_features(value: &str) -> Vec<String> {
    let mut features: Vec<String> =
        value.split(',').filter(|f| !f.is_empty()).map(str::to_string).collect();
    features.sort();
    features
}

/// The `approved-only` check: none of the [`NON_APPROVED`] features is on in `crate_features`.
///
/// # Errors
/// Every non-approved feature that is on, one per line, naming the crate and the feature.
pub fn check_approved_only(crate_features: &[CrateFeatures]) -> Result<(), String> {
    let mut errors = Vec::new();
    for (package, features) in crate_features {
        for (bad_package, bad_feature) in NON_APPROVED {
            if package == bad_package && features.iter().any(|f| f == bad_feature) {
                errors.push(format!(
                    "`approved-only` is on, but `{package}` has the non-approved feature \
                     `{bad_feature}` on. Something else in the build turns it on (a dependency \
                     on `{package}` with default features, or with `features = [\"{bad_feature}\"]`); \
                     remove that, or build without `approved-only`"
                ));
            }
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("\n")) }
}

/// Reads the hashed files and the manifest of the crate in `dir`.
///
/// # Errors
/// If `Cargo.toml`, `build.rs` or `src/` cannot be read, a path is not UTF-8, or the manifest is
/// not one [`parse_manifest`] reads.
pub fn read_crate(dir: &Path) -> Result<(Manifest, Vec<SourceFile>), String> {
    let mut files = Vec::new();
    for name in ["Cargo.toml", "build.rs"] {
        let bytes =
            fs::read(dir.join(name)).map_err(|e| format!("{}: {name}: {e}", dir.display()))?;
        files.push(SourceFile { path: name.to_string(), bytes });
    }
    read_tree(&dir.join("src"), "src", &mut files)?;
    let manifest = parse_manifest(&String::from_utf8_lossy(&files[0].bytes))
        .map_err(|e| format!("{}: Cargo.toml: {e}", dir.display()))?;
    Ok((manifest, files))
}

/// Appends every file under `dir`, recursively, with its path prefixed by `rel`.
fn read_tree(dir: &Path, rel: &str, files: &mut Vec<SourceFile>) -> Result<(), String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let name = entry.file_name();
        let name =
            name.to_str().ok_or_else(|| format!("{}: a file name is not UTF-8", dir.display()))?;
        let path = entry.path();
        // `metadata` follows a symlink, so a linked file is hashed as its target's contents.
        let meta = fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let child = format!("{rel}/{name}");
        if meta.is_dir() {
            read_tree(&path, &child, files)?;
        } else {
            let bytes = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            files.push(SourceFile { path: child, bytes });
        }
    }
    Ok(())
}

/// The per-crate source HMAC: HMAC-SHA-512 under the module key over the files in bytewise order
/// of their relative paths, each encoded as the path, a zero byte, the length of its canonical
/// bytes as 8 big-endian bytes, then those bytes. The canonical form turns every CRLF into LF, so
/// that a Windows checkout (`.gitattributes` has `* text=auto`) hashes as a Unix one does. The
/// order of `files` does not matter.
pub fn crate_hmac(files: &[SourceFile]) -> [u8; HMAC_LEN] {
    let mut sorted: Vec<&SourceFile> = files.iter().collect();
    sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let key = hmac_key();
    let mut mac = key.create_generator();
    for file in sorted {
        let canonical = crlf_to_lf(&file.bytes);
        mac.do_update(file.path.as_bytes());
        mac.do_update(&[0]);
        mac.do_update(&(canonical.len() as u64).to_be_bytes());
        mac.do_update(&canonical);
    }
    mac.do_final()
}

/// `bytes` with every CR LF pair replaced by LF. A CR not followed by LF stays.
pub fn crlf_to_lf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
            i += 1;
        }
        out.push(bytes[i]);
        i += 1;
    }
    out
}

/// The `links` value Cargo expects of a boundary package: its name with `-` as `_`.
fn links_of(package: &str) -> String {
    package.replace('-', "_")
}

/// The `<LINKS>` part of the `DEP_<LINKS>_SRC_DIR` variable Cargo sets for a `links` value.
pub fn dep_var_links(links: &str) -> String {
    links.to_ascii_uppercase().replace('-', "_")
}

/// Checks that the crates found are exactly [`BOUNDARY`], each with its `links` key, and that the
/// boundary is closed: every normal dependency of a boundary crate is in [`BOUNDARY`] or
/// [`EXTERNAL_PINS`].
///
/// # Errors
/// Every disagreement found, one per line.
pub fn check_closure(crates: &[BoundaryCrate]) -> Result<(), String> {
    let mut errors = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for c in crates {
        let name = c.manifest.name.as_str();
        if seen.contains(&name) {
            errors.push(format!("`{name}` was found twice"));
        }
        seen.push(name);
        if !BOUNDARY.contains(&name) {
            errors.push(format!(
                "`{name}` (DEP_{}_SRC_DIR) is not in the module boundary list, BOUNDARY in \
                 crypto/fips/build-support/src/lib.rs",
                c.dep_links
            ));
        }
        let links = links_of(name);
        if c.manifest.links.as_deref() != Some(links.as_str()) {
            errors.push(format!("`{name}` must have `links = \"{links}\"` in its Cargo.toml"));
        }
        if c.dep_links != dep_var_links(&links) {
            errors.push(format!("`{name}` was named by DEP_{}_SRC_DIR", c.dep_links));
        }
        for dep in &c.manifest.normal_deps {
            let external = EXTERNAL_PINS.iter().any(|p| p.name == dep);
            if !BOUNDARY.contains(&dep.as_str()) && !external {
                errors.push(format!(
                    "`{name}` depends on `{dep}`, which is not in the module boundary: add it \
                     to BOUNDARY in crypto/fips/build-support/src/lib.rs and to the dependencies \
                     of bouncycastle-fips, or, for a crate from crates.io, to EXTERNAL_PINS and \
                     the `=` requirements of bouncycastle-fips (crypto/fips/EXTERNAL_CRATES.md); \
                     or drop the dependency"
                ));
            }
        }
    }
    for name in BOUNDARY {
        if !seen.contains(&name) {
            errors.push(format!(
                "`{name}` is in the module boundary but no DEP_{}_SRC_DIR reached the build \
                 script: it must be a direct dependency of bouncycastle-fips and have `links = \
                 \"{}\"` and a build script that emits `cargo:src_dir`",
                dep_var_links(&links_of(name)),
                links_of(name)
            ));
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("\n")) }
}

/// The table: one row per boundary crate, its package name and per-crate source HMAC, and one
/// per crate of [`EXTERNAL_PINS`], its package name and [`external_hmac`]; ordered bytewise by
/// package name. The order of `crates` does not matter.
///
/// # Errors
/// As [`check_closure`].
pub fn build_table(crates: &[BoundaryCrate]) -> Result<Vec<TableRow>, String> {
    check_closure(crates)?;
    let mut table: Vec<TableRow> =
        crates.iter().map(|c| (c.manifest.name.clone(), crate_hmac(&c.files))).collect();
    table.extend(external_rows());
    table.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Ok(table)
}

/// The `fips-validated` gate: `expected` is the published constant when the feature is on, and
/// `None` when it is off, in which case nothing is compared.
///
/// # Errors
/// If `expected` is given and differs from `module`, with both values and the line to paste
/// into `src/expected_module_hmac.rs` should the sources be the ones meant.
pub fn check_expected(
    module: &[u8; HMAC_LEN],
    expected: Option<&[u8; HMAC_LEN]>,
) -> Result<(), String> {
    match expected {
        Some(expected) if expected != module => Err(format!(
            "the module HMAC of these sources is\n  {}\nbut the `fips-validated` feature expects \
             the published constant\n  {}\nfrom src/expected_module_hmac.rs. The boundary crates \
             are not the validated sources. If they are the ones meant, the constant is\n{}",
            hex(module),
            hex(expected),
            rust_bytes(module, "    ")
        )),
        _ => Ok(()),
    }
}

/// The Rust source of the generated file: the table, the toolchain record, the module HMAC in a
/// comment, and [`EXTERNAL_PINS`] as `EXTERNAL`. The module HMAC is not a constant the code reads, since it is derived from the
/// table, never stored on its own.
pub fn render(table: &[TableRow], toolchain: &Toolchain) -> String {
    let mut s = String::new();
    s.push_str("// @generated by the build script of bouncycastle-fips. Do not edit.\n");
    let _ = writeln!(s, "// Module HMAC, derived from TABLE: {}", hex(&module_hmac(table)));
    let _ = writeln!(s, "pub(crate) const TABLE: [ModuleTableEntry; {}] = [", table.len());
    for (name, hmac) in table {
        let _ = writeln!(s, "    ModuleTableEntry {{\n        package: {name:?},\n        hmac: [");
        s.push_str(&rust_bytes(hmac, "            "));
        s.push_str("        ],\n    },\n");
    }
    s.push_str("];\n");
    let _ = writeln!(
        s,
        "pub(crate) const TOOLCHAIN: ToolchainRecord = ToolchainRecord {{\n    rustc: {:?},\n    \
         host: {:?},\n    target: {:?},\n    opt_level: {:?},\n    profile: {:?},\n    \
         features: &{:?},\n    crate_features: &[",
        toolchain.rustc,
        toolchain.host,
        toolchain.target,
        toolchain.opt_level,
        toolchain.profile,
        toolchain.features
    );
    for (package, features) in &toolchain.crate_features {
        let _ = writeln!(
            s,
            "        CrateFeatures {{ package: {package:?}, features: &{features:?} }},"
        );
    }
    s.push_str("    ],\n};\n");
    let _ = writeln!(s, "pub(crate) const EXTERNAL: [ExternalCrate; {}] = [", EXTERNAL_PINS.len());
    for pin in EXTERNAL_PINS {
        let checksum = parse_checksum(pin.checksum).expect("EXTERNAL_PINS checksums are valid");
        let _ = writeln!(
            s,
            "    ExternalCrate {{\n        package: {:?},\n        version: {:?},\n        \
             checksum: [",
            pin.name, pin.version
        );
        s.push_str(&rust_bytes(&checksum, "            "));
        s.push_str("        ],\n    },\n");
    }
    s.push_str("];\n");
    s
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `bytes` as `0x..,` literals, 8 to a line, each line starting with `indent`.
fn rust_bytes(bytes: &[u8], indent: &str) -> String {
    let mut s = String::new();
    for line in bytes.chunks(8) {
        s.push_str(indent);
        let items: Vec<String> = line.iter().map(|b| format!("0x{b:02x},")).collect();
        s.push_str(&items.join(" "));
        s.push('\n');
    }
    s
}

/// Reads `[package] name` and `links`, and the names and version requirements of the normal
/// dependencies, from a `Cargo.toml`: `[dependencies]` and `[target.<cfg>.dependencies]` tables, with `name = ...` or
/// `name.key = ...` entries, and `[dependencies.<name>]` tables, the form `cargo package` writes.
/// This is not a TOML parser: it reads the subset Cargo manifests use, and refuses what it cannot
/// read rather than miss a dependency.
///
/// # Errors
/// No `[package] name`; a multi-line string; a renamed dependency (`package = ...`), since the
/// closure is checked by package name.
pub fn parse_manifest(text: &str) -> Result<Manifest, String> {
    #[derive(PartialEq)]
    enum Table {
        Package,
        DepList,
        OneDep,
        Other,
    }
    let mut table = Table::Other;
    let mut name = None;
    let mut links = None;
    let mut deps = Vec::new();
    let mut requirements = Vec::new();
    // Open brackets and braces of a value that continues on the next lines (a multi-line array).
    let mut depth: i32 = 0;
    for (n, raw) in text.lines().enumerate() {
        let n = n + 1;
        if raw.contains("\"\"\"") || raw.contains("'''") {
            return Err(format!("line {n}: multi-line strings are not supported"));
        }
        let line = strip_comment(raw).trim();
        if depth > 0 {
            depth += bracket_balance(line);
            if table != Table::Other && has_key(line, "package") {
                return Err(format!("line {n}: renamed dependencies are not supported"));
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if line.starts_with("[[") {
            table = Table::Other;
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            let header = header
                .strip_suffix(']')
                .ok_or_else(|| format!("line {n}: unterminated table header"))?;
            let seg = key_segments(header);
            let seg: Vec<&str> = seg.iter().map(String::as_str).collect();
            table = match seg.as_slice() {
                ["package"] => Table::Package,
                ["dependencies"] | ["target", _, "dependencies"] => Table::DepList,
                ["dependencies", dep] | ["target", _, "dependencies", dep] => {
                    deps.push(dep.to_string());
                    Table::OneDep
                }
                _ => Table::Other,
            };
            continue;
        }
        let Some(eq) = find_outside_quotes(line, '=') else {
            continue;
        };
        let key = key_segments(&line[..eq]);
        let value = line[eq + 1..].trim();
        depth = bracket_balance(value);
        match table {
            Table::Package if key == ["name"] => name = Some(unquote(value)),
            Table::Package if key == ["links"] => links = Some(unquote(value)),
            Table::DepList => {
                if key.get(1).map(String::as_str) == Some("package") || has_key(value, "package") {
                    return Err(format!("line {n}: renamed dependencies are not supported"));
                }
                if let Some(dep) = key.first() {
                    deps.push(dep.clone());
                    // `dep = "req"`, `dep = { version = "req", .. }` or `dep.version = "req"`.
                    let req = match key.get(1).map(String::as_str) {
                        None if value.starts_with(['"', '\'']) => Some(unquote(value)),
                        None => inline_value(value, "version"),
                        Some("version") => Some(unquote(value)),
                        Some(_) => None,
                    };
                    if let Some(req) = req {
                        requirements.push((dep.clone(), req));
                    }
                }
            }
            Table::OneDep if key == ["package"] => {
                return Err(format!("line {n}: renamed dependencies are not supported"));
            }
            Table::OneDep if key == ["version"] => {
                // The table's dependency is the one its header pushed last.
                if let Some(dep) = deps.last() {
                    requirements.push((dep.clone(), unquote(value)));
                }
            }
            _ => {}
        }
    }
    let name = name.ok_or_else(|| "no [package] name".to_string())?;
    Ok(Manifest { name, links, normal_deps: deps, requirements })
}

/// The value of `key` in the inline table `value` (`{ version = "1", features = [..] }`),
/// unquoted, if it has one.
fn inline_value(value: &str, key: &str) -> Option<String> {
    let mut rest = value.trim().strip_prefix('{')?.trim_end().strip_suffix('}')?;
    loop {
        let (part, tail) = match find_outside_quotes(rest, ',') {
            Some(i) => (&rest[..i], Some(&rest[i + 1..])),
            None => (rest, None),
        };
        if let Some(eq) = find_outside_quotes(part, '=')
            && key_segments(&part[..eq]) == [key]
        {
            return Some(unquote(&part[eq + 1..]));
        }
        rest = tail?;
    }
}

/// `line` up to the first `#` outside a string.
fn strip_comment(line: &str) -> &str {
    match find_outside_quotes(line, '#') {
        Some(i) => &line[..i],
        None => line,
    }
}

/// The byte index of the first `wanted` outside a `"..."` or `'...'` string.
fn find_outside_quotes(s: &str, wanted: char) -> Option<usize> {
    let mut quote = None;
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match quote {
            Some('"') if escaped => escaped = false,
            Some('"') if c == '\\' => escaped = true,
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == wanted => return Some(i),
            None if c == '"' || c == '\'' => quote = Some(c),
            None => {}
        }
    }
    None
}

/// `s` with its strings removed, so that their contents are not read as syntax.
fn without_strings(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find(['"', '\'']) {
        out.push_str(&rest[..i]);
        let quote = rest[i..].chars().next().unwrap_or('"');
        let tail = &rest[i + 1..];
        // The closing quote: the first unescaped one, for a basic string.
        let mut end = None;
        let mut escaped = false;
        for (j, c) in tail.char_indices() {
            if quote == '"' && escaped {
                escaped = false;
            } else if quote == '"' && c == '\\' {
                escaped = true;
            } else if c == quote {
                end = Some(j);
                break;
            }
        }
        match end {
            Some(j) => rest = &tail[j + 1..],
            None => return out,
        }
    }
    out.push_str(rest);
    out
}

/// Open minus closed brackets and braces outside strings.
fn bracket_balance(s: &str) -> i32 {
    without_strings(s)
        .chars()
        .map(|c| match c {
            '[' | '{' => 1,
            ']' | '}' => -1,
            _ => 0,
        })
        .sum()
}

/// Whether `value` contains `key = ` as a key of an inline table, outside strings.
fn has_key(value: &str, key: &str) -> bool {
    without_strings(value)
        .split(['{', ',', '}'])
        .any(|part| part.split('=').next().map(str::trim) == Some(key) && part.contains('='))
}

/// The segments of a TOML dotted key, unquoted and trimmed: `target.'cfg(unix)'.dependencies`
/// is `target`, `cfg(unix)`, `dependencies`.
fn key_segments(key: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut rest = key.trim();
    loop {
        match find_outside_quotes(rest, '.') {
            Some(i) => {
                segments.push(unquote(rest[..i].trim()));
                rest = rest[i + 1..].trim();
            }
            None => {
                segments.push(unquote(rest.trim()));
                return segments;
            }
        }
    }
}

/// `s` without one pair of surrounding `"` or `'`, if it has them.
fn unquote(s: &str) -> String {
    let s = s.trim();
    for q in ['"', '\''] {
        if let Some(inner) = s.strip_prefix(q).and_then(|t| t.strip_suffix(q)) {
            return inner.to_string();
        }
    }
    s.to_string()
}
