//! Each KAT fails if any byte of its vector differs: the library's KAT code is compiled into this
//! binary (as in `kat_failure_tests.rs`) and run directly, after the real power-on self-tests have
//! opened the gates, so nothing here writes a status. A binary of its own, because it calls
//! `power_on_self_tests`.

#[allow(dead_code)]
#[path = "../src/kats.rs"]
mod kats;
#[allow(dead_code)]
#[path = "../src/vectors.rs"]
mod vectors;

#[cfg(any(feature = "aes", feature = "sha2"))]
/// Calls `check` with each single-byte change of `bytes`, which it must reject.
fn each_flip<const N: usize>(bytes: [u8; N], mut check: impl FnMut([u8; N]) -> bool) {
    for i in 0..N {
        let mut flipped = bytes;
        flipped[i] ^= 0x80;
        assert!(!check(flipped), "byte {i} not checked");
    }
}

#[test]
fn every_vector_byte_matters() {
    assert_eq!(bouncycastle_fips::power_on_self_tests(), Ok(()));

    #[cfg(feature = "sha2")]
    {
        let v = vectors::SHA256_KAT;
        assert!(kats::sha256(&v));
        each_flip(v.msg, |msg| kats::sha256(&vectors::HashKat { msg, ..v }));
        each_flip(v.md, |md| kats::sha256(&vectors::HashKat { md, ..v }));

        let v = vectors::SHA512_KAT;
        assert!(kats::sha512(&v));
        each_flip(v.msg, |msg| kats::sha512(&vectors::HashKat { msg, ..v }));
        each_flip(v.md, |md| kats::sha512(&vectors::HashKat { md, ..v }));
    }

    #[cfg(feature = "aes")]
    {
        let g = vectors::AES_GCM_128_KAT;
        let c = vectors::AES_CBC_128_DECRYPT_KAT;
        assert!(kats::aes(&g, &c));
        let gcm = |g: vectors::GcmKat| kats::aes(&g, &c);
        each_flip(g.key, |key| gcm(vectors::GcmKat { key, ..g }));
        each_flip(g.iv, |iv| gcm(vectors::GcmKat { iv, ..g }));
        each_flip(g.pt, |pt| gcm(vectors::GcmKat { pt, ..g }));
        each_flip(g.aad, |aad| gcm(vectors::GcmKat { aad, ..g }));
        each_flip(g.ct, |ct| gcm(vectors::GcmKat { ct, ..g }));
        each_flip(g.tag, |tag| gcm(vectors::GcmKat { tag, ..g }));
        let cbc = |c: vectors::CbcKat| kats::aes(&g, &c);
        each_flip(c.key, |key| cbc(vectors::CbcKat { key, ..c }));
        each_flip(c.iv, |iv| cbc(vectors::CbcKat { iv, ..c }));
        each_flip(c.ct, |ct| cbc(vectors::CbcKat { ct, ..c }));
        each_flip(c.pt, |pt| cbc(vectors::CbcKat { pt, ..c }));
    }
}
