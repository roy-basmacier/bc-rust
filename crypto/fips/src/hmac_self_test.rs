//! The FIPS 140-3 cryptographic algorithm self-test (CAST) for HMAC-SHA-512.
//!
//! FIPS 140-3 IG 10.3.A Resolution 4: "if the module implements a HMAC function (FIPS 198-1), a
//! CAST for HMAC is required and shall be performed with the HMAC function using at least one of
//! the implemented underlying SHA-1, SHA-2, or SHA-3 algorithms". SHA-512 is the one picked,
//! because HMAC-SHA-512 is also the algorithm of the software integrity test, which ISO/IEC
//! 19790:2012 7.10.1 [10.20] requires to "first pass the cryptographic algorithm self-test".
//!
//! The status lives here rather than in `bouncycastle-hmac`, and gates no HMAC service: it is the
//! precondition of the integrity test. HMAC-SHA-512 needs SHA-512, whose own gate refuses until the
//! SHA-512 CAST has passed, so this one runs after it.

use bouncycastle_core::fips::{SelfTestError, SelfTestStatus, SelfTestStatusCell, SelfTestedAlgorithm};
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle_core::traits::MACGenerator;
use bouncycastle_hmac::HmacKey;
use bouncycastle_sha2::SHA512;

/// The HMAC-SHA-512 self-test status. Only [`self_test`] runs it.
static STATUS: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::HMAC_SHA512);

/// A key, a message and its MAC.
#[derive(Clone, Copy)]
struct HmacKat {
    key: [u8; 20],
    data: [u8; 8],
    mac: [u8; 64],
}

/// RFC 4231 Section 4.2, "Test Case 1": Key, Data ("Hi There"), HMAC-SHA-512.
const KAT: HmacKat = HmacKat {
    key: [0x0b; 20],
    data: *b"Hi There",
    mac: [
        0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, //
        0x4f, 0xf0, 0xb4, 0x24, 0x1a, 0x1d, 0x6c, 0xb0, //
        0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78, //
        0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde, //
        0xda, 0xa8, 0x33, 0xb7, 0xd6, 0xb8, 0xa7, 0x02, //
        0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4, //
        0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, //
        0x2e, 0x69, 0x6c, 0x20, 0x3a, 0x12, 0x68, 0x54,
    ],
};

/// Runs the HMAC-SHA-512 self-test. The SHA-512 self-test must have passed first.
pub(crate) fn self_test() -> Result<(), SelfTestError> {
    STATUS.run(|| matches(&KAT))
}

/// Where the HMAC-SHA-512 self-test stands.
pub(crate) fn status() -> SelfTestStatus {
    STATUS.get()
}

/// Whether HMAC-SHA-512 of `kat.data` under `kat.key` is `kat.mac`.
fn matches(kat: &HmacKat) -> bool {
    // The 20-byte key is below HMAC-SHA-512's strength, so the strength check is skipped; the
    // vector is what RFC 4231 gives. Neither call can fail on these inputs (a 20-byte key fits
    // 64 bytes, and it is tagged a MAC key), but a failure would be a failed self-test.
    let Ok(material) = KeyMaterial::<64>::from_bytes_as_type(&kat.key, KeyType::MACKey) else {
        return false;
    };
    let Ok(key) = HmacKey::<SHA512>::from_key_material_allow_weak(&material) else {
        return false;
    };
    let mut generator = key.create_generator();
    generator.do_update(&kat.data);
    let mut mac = [0u8; 64];
    generator.do_final_out(&mut mac) == mac.len() && mac == kat.mac
}

// One test, because the status is process-global and shared by every unit test of the crate.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_and_rejects_a_flipped_byte_anywhere() {
        assert_eq!(status(), SelfTestStatus::NotRun);
        bouncycastle_sha2::self_test().expect("SHA-512, which HMAC-SHA-512 needs, passes");
        assert_eq!(self_test(), Ok(()));
        assert_eq!(status(), SelfTestStatus::Passed);

        // Each byte of the key, the data and the MAC matters.
        for i in 0..KAT.key.len() + KAT.data.len() + KAT.mac.len() {
            let mut bad = KAT;
            if i < bad.key.len() {
                bad.key[i] ^= 1;
            } else if i < bad.key.len() + bad.data.len() {
                bad.data[i - bad.key.len()] ^= 1;
            } else {
                bad.mac[i - bad.key.len() - bad.data.len()] ^= 1;
            }
            assert!(!matches(&bad), "byte {i}");
        }
        assert!(matches(&KAT));
    }
}
