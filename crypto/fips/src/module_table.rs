//! The module's source pin, as the build embedded it: the table of per-crate source HMACs, the
//! toolchain record, and the module HMAC recomputed from the table.
//!
//! The build script (`build.rs`, with `bouncycastle-fips-build`) writes the table and the record;
//! [`module_hmac`] recomputes the module HMAC here with its own copy of the encoding, so a table
//! changed after the build gives a different value. With the `fips-validated` feature, the
//! power-on self-tests compare that value with the published constant.

use bouncycastle_core::fips::SelfTestError;
#[cfg(feature = "sha2")]
use bouncycastle_core::fips::{SelfTestStatus, SelfTestedAlgorithm};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle_core::traits::MACGenerator;
use bouncycastle_hmac::HmacKey;
use bouncycastle_sha2::SHA512;

/// The length of a per-crate source HMAC and of the module HMAC: HMAC-SHA-512's output.
pub const MODULE_HMAC_LEN: usize = 64;

/// The HMAC key of every per-crate source HMAC and of the module HMAC. It is public: the values
/// are a fingerprint of the sources that anyone can recompute.
pub const MODULE_HMAC_KEY: &[u8; 41] = b"Legion of the Bouncy Castle FIPS Rust API";

/// One entry of the module table: a crate inside the module boundary and the HMAC-SHA-512 of its
/// sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleTableEntry {
    /// The crate's full package name, e.g. `bouncycastle-aes`.
    pub package: &'static str,
    /// HMAC-SHA-512 under [`MODULE_HMAC_KEY`] of the crate's `src/`, `Cargo.toml` and `build.rs`.
    pub hmac: [u8; MODULE_HMAC_LEN],
}

/// The toolchain and settings that built this copy of the module, recorded beside the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolchainRecord {
    /// The first line of `rustc -vV`: the compiler's version, commit and date.
    pub rustc: &'static str,
    /// The compiler's host triple.
    pub host: &'static str,
    /// The target triple the module was built for.
    pub target: &'static str,
    /// The optimisation level: `0` to `3`, `s` or `z`.
    pub opt_level: &'static str,
    /// The Cargo profile family: `debug` or `release`.
    pub profile: &'static str,
    /// The enabled cargo features of `bouncycastle-fips`, sorted.
    pub features: &'static [&'static str],
    /// The enabled cargo features of each crate inside the module boundary, in table order.
    pub crate_features: &'static [CrateFeatures],
}

impl ToolchainRecord {
    /// Whether this is a FIPS-approved build: one with the `approved-only` feature, which builds
    /// only if no crate inside the module boundary has a non-approved feature on.
    pub fn approved_only(&self) -> bool {
        self.features.contains(&"approved-only")
    }
}

/// The enabled cargo features of one crate inside the module boundary, as Cargo unified them for
/// the build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrateFeatures {
    /// The crate's full package name, e.g. `bouncycastle-ec`.
    pub package: &'static str,
    /// Its enabled cargo features, sorted.
    pub features: &'static [&'static str],
}

// TABLE and TOOLCHAIN, written by build.rs.
include!(concat!(env!("OUT_DIR"), "/module_table.rs"));

/// The module table: every crate inside the module boundary with its source HMAC, ordered
/// bytewise by package name. The same in every program built from the same sources, whatever
/// else the program links.
pub fn module_table() -> &'static [ModuleTableEntry] {
    &TABLE
}

/// The toolchain and settings that built this copy of the module.
pub fn toolchain() -> &'static ToolchainRecord {
    &TOOLCHAIN
}

/// The module HMAC, recomputed from [`module_table`]: HMAC-SHA-512 under [`MODULE_HMAC_KEY`] over
/// the entries in table order, each as the package name, a zero byte and the 64 hash bytes. A
/// validated version of the module publishes it in its Security Policy.
///
/// # Errors
/// With the `sha2` feature, [`SelfTestError::NotPassed`] for HMAC-SHA-512 until its self-test
/// has passed: call [`crate::power_on_self_tests`] first.
pub fn module_hmac() -> Result<[u8; MODULE_HMAC_LEN], SelfTestError> {
    #[cfg(feature = "sha2")]
    {
        let status = crate::self_test_status(SelfTestedAlgorithm::HMAC_SHA512);
        if status != SelfTestStatus::Passed {
            return Err(SelfTestError::NotPassed(SelfTestedAlgorithm::HMAC_SHA512, status));
        }
    }
    Ok(module_hmac_of(&TABLE))
}

/// What an operator compares with the Security Policy: the module table, the module HMAC and the
/// toolchain record, from [`module_info`].
///
/// Its [`Display`](core::fmt::Display) form is what `bc-rust fips-info` prints, one item per
/// line, hex in lowercase:
///
/// ```text
/// <package name> <128 hex digits>        one line per table entry, in table order
/// module-hmac <128 hex digits>
/// toolchain.rustc <rustc>
/// toolchain.host <host>
/// toolchain.target <target>
/// toolchain.opt-level <opt-level>
/// toolchain.profile <profile>
/// toolchain.features[ <feature>]...
/// ```
///
/// The lines up to and including `module-hmac` are exactly what `dev_scripts/fips_module_hmac.py`
/// prints over the same sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModuleInfo {
    /// [`module_table`].
    pub table: &'static [ModuleTableEntry],
    /// [`module_hmac`], recomputed from [`ModuleInfo::table`].
    pub module_hmac: [u8; MODULE_HMAC_LEN],
    /// [`toolchain`].
    pub toolchain: &'static ToolchainRecord,
}

/// The module table, the module HMAC and the toolchain record together, to print.
///
/// # Errors
/// As [`module_hmac`].
pub fn module_info() -> Result<ModuleInfo, SelfTestError> {
    Ok(ModuleInfo { table: module_table(), module_hmac: module_hmac()?, toolchain: toolchain() })
}

impl core::fmt::Display for ModuleInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        /// `bytes` as lowercase hex, then the end of the line.
        fn hex_line(f: &mut core::fmt::Formatter<'_>, bytes: &[u8]) -> core::fmt::Result {
            for b in bytes {
                write!(f, "{b:02x}")?;
            }
            writeln!(f)
        }
        for entry in self.table {
            write!(f, "{} ", entry.package)?;
            hex_line(f, &entry.hmac)?;
        }
        f.write_str("module-hmac ")?;
        hex_line(f, &self.module_hmac)?;
        let t = self.toolchain;
        writeln!(f, "toolchain.rustc {}", t.rustc)?;
        writeln!(f, "toolchain.host {}", t.host)?;
        writeln!(f, "toolchain.target {}", t.target)?;
        writeln!(f, "toolchain.opt-level {}", t.opt_level)?;
        writeln!(f, "toolchain.profile {}", t.profile)?;
        f.write_str("toolchain.features")?;
        for feature in t.features {
            write!(f, " {feature}")?;
        }
        writeln!(f)
    }
}

/// The module HMAC of `table`, in the order given.
fn module_hmac_of(table: &[ModuleTableEntry]) -> [u8; MODULE_HMAC_LEN] {
    // 41 bytes fit a 64-byte KeyMaterial, and a MACKey-tagged key is accepted when the strength
    // check is skipped, so neither call can fail; the key is a public string, so the strength
    // check is beside the point.
    let material = KeyMaterial::<64>::from_bytes_as_type(MODULE_HMAC_KEY, KeyType::MACKey)
        .expect("a 41-byte key fits 64 bytes");
    let key = HmacKey::<SHA512>::from_key_material_allow_weak(&material)
        .expect("a MACKey-tagged key is accepted without the strength check");
    let mut mac = key.create_generator();
    for entry in table {
        mac.do_update(entry.package.as_bytes());
        mac.do_update(&[0]);
        mac.do_update(&entry.hmac);
    }
    mac.do_final()
}

/// The module integrity check of a validated build: the module HMAC recomputed from the embedded
/// table against the published constant. The build has already refused sources that do not
/// match, so a failure here means the table in the program is not the one built.
#[cfg(feature = "fips-validated")]
pub(crate) mod validated {
    use bouncycastle_core::fips::{
        SelfTestError, SelfTestStatus, SelfTestStatusCell, SelfTestedAlgorithm,
    };

    use super::{MODULE_HMAC_LEN, ModuleTableEntry, TABLE, module_hmac_of};
    use crate::expected_module_hmac::EXPECTED_MODULE_HMAC;

    /// The module integrity check's status. Only [`self_test`] runs it.
    static STATUS: SelfTestStatusCell =
        SelfTestStatusCell::new(SelfTestedAlgorithm::ModuleIntegrity);

    /// Runs the module integrity check. HMAC-SHA-512's self-test must have passed first.
    pub(crate) fn self_test() -> Result<(), SelfTestError> {
        STATUS.run(|| matches(&TABLE, &EXPECTED_MODULE_HMAC))
    }

    /// Where the module integrity check stands.
    pub(crate) fn status() -> SelfTestStatus {
        STATUS.get()
    }

    /// Whether the module HMAC of `table` is `expected`.
    fn matches(table: &[ModuleTableEntry], expected: &[u8; MODULE_HMAC_LEN]) -> bool {
        module_hmac_of(table) == *expected
    }

    // `matches` against tables other than the embedded one, which no public API can reach: the
    // build guarantees the embedded table matches. Uses SHA-512, so it runs SHA-2's self-test
    // first; not the full power-on, which fails under the `integrity` feature and would put every
    // other unit test of the crate in the error state.
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn a_changed_table_does_not_match() {
            bouncycastle_sha2::self_test().expect("SHA-2 self-tests pass");
            assert!(matches(&TABLE, &EXPECTED_MODULE_HMAC));
            let mut expected = EXPECTED_MODULE_HMAC;
            expected[63] ^= 1;
            assert!(!matches(&TABLE, &expected));
            let mut table = TABLE;
            table[0].hmac[0] ^= 1;
            assert!(!matches(&table, &EXPECTED_MODULE_HMAC));
            let mut table = TABLE;
            table.swap(0, 1);
            assert!(!matches(&table, &EXPECTED_MODULE_HMAC));
        }
    }
}
