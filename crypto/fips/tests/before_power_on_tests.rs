//! Before the power-on self-tests: nothing has run and every gated service refuses.
#![cfg(any(feature = "aes", feature = "sha2"))]

mod common;

use bouncycastle_fips::{SELF_TESTED, SelfTestStatus, self_test_status};

#[test]
fn services_refuse_before_power_on() {
    for algorithm in SELF_TESTED {
        assert_eq!(self_test_status(*algorithm), SelfTestStatus::NotRun, "{algorithm:?}");
    }
    common::assert_services(Some(SelfTestStatus::NotRun));
    // Refusing changes nothing.
    for algorithm in SELF_TESTED {
        assert_eq!(self_test_status(*algorithm), SelfTestStatus::NotRun, "{algorithm:?}");
    }
}

#[cfg(feature = "sha2")]
#[test]
#[should_panic(expected = "SHA-256 cannot be used: its FIPS 140-3 self-test is NotRun")]
fn sha256_new_panics_before_power_on() {
    let _ = bouncycastle_sha2::SHA256::new();
}
