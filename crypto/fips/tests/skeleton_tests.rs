//! The parts of the skeleton that are not stubs.

use bouncycastle_fips::{SELF_TESTED, SelfTestedAlgorithm};

#[test]
fn self_tested_follows_the_features_hashes_first() {
    let mut expected = Vec::new();
    if cfg!(feature = "sha2") {
        expected.extend([
            SelfTestedAlgorithm::SHA256,
            SelfTestedAlgorithm::SHA512,
            SelfTestedAlgorithm::HMAC_SHA512,
        ]);
    }
    if cfg!(feature = "aes") {
        expected.push(SelfTestedAlgorithm::AES);
    }
    assert_eq!(SELF_TESTED, expected.as_slice());
}
