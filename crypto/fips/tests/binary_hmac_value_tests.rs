//! The binary HMAC of hand-built ELF images: which bytes it covers, the slot left out, and the
//! check. One test, because it must see the HMAC-SHA-512 self-test not yet run, then run it.
//! Not under `integrity`, whose power-on fails on this test binary's own empty slot.

#![cfg(all(feature = "sha2", not(feature = "integrity")))]

mod elf_image;

use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey};
use bouncycastle_core::traits::MACGenerator;
use bouncycastle_fips::binary_hmac::{BinaryHmacError, KEY, SLOT_LEN, image_hmac, verify_image};
use bouncycastle_fips::power_on_self_tests;
use bouncycastle_hmac::HmacKey;
use bouncycastle_sha2::SHA512;
use elf_image::*;

/// HMAC-SHA-512 under KEY of the concatenation of `ranges` of `image`, computed independently of
/// the walk.
fn expected(image: &[u8], ranges: &[(usize, usize)]) -> [u8; 64] {
    let material = KeyMaterial::<64>::from_bytes_as_type(KEY, KeyType::MACKey).unwrap();
    let key = HmacKey::<SHA512>::from_key_material_allow_weak(&material).unwrap();
    let mut generator = key.create_generator();
    for &(start, end) in ranges {
        generator.do_update(&image[start..end]);
    }
    generator.do_final()
}

#[test]
fn covers_the_read_only_segments_without_the_slot() {
    let mut image = image(true, false, &usual_phdrs(), USUAL_LEN);
    put_magic(&mut image, 0x420);

    // ISO/IEC 19790 7.10.1 [10.20]: no hashing before the HMAC self-test has passed.
    assert_eq!(image_hmac(&image, 0x420), Err(BinaryHmacError::SelfTestNotPassed));
    assert!(!verify_image(&image, 0x420, &[1; 64]));
    power_on_self_tests().unwrap();

    // Header segment, then rodata, then text around the slot (0x420..0x470), in file order.
    let ranges = [(0, 0x200), (0x300, 0x380), (0x400, 0x420), (0x470, 0x500)];
    let value = image_hmac(&image, 0x420).unwrap();
    assert_eq!(value, expected(&image, &ranges));

    // Every hashed byte changes the value; the slot's bytes, the gaps between segments, the
    // writable segment and the bytes after the last segment do not.
    for at in 0..image.len() {
        let mut changed = image.clone();
        changed[at] ^= 1;
        let hashed = ranges.iter().any(|&(s, e)| (s..e).contains(&at));
        match image_hmac(&changed, 0x420) {
            Ok(v) => assert_eq!(v == value, !hashed, "byte {at:#x}"),
            // A changed program header can make the file unparseable; that is a change too.
            Err(_) => assert!(hashed, "byte {at:#x}"),
        }
    }

    // The slot at the start, and at the end, of a segment.
    assert_eq!(
        image_hmac(&image, 0x400).unwrap(),
        expected(&image, &[(0, 0x200), (0x300, 0x380), (0x450, 0x500)])
    );
    assert_eq!(
        image_hmac(&image, 0x500 - SLOT_LEN as u64).unwrap(),
        expected(&image, &[(0, 0x200), (0x300, 0x380), (0x400, 0x4b0)])
    );

    // The slot must lie wholly inside a read-only segment.
    for outside in [0x4b1, 0x3f0, 0x510, 0x5f0, 0x2000, u64::MAX - 10] {
        assert_eq!(
            image_hmac(&image, outside),
            Err(BinaryHmacError::SlotOutsideSegments),
            "{outside:#x}"
        );
    }

    // Two read-only segments that overlap in the file both leave the slot out.
    let phdrs = [load(PF_R, 0, 0, 0x200), load(PF_R | PF_X, 0x100, 0x1100, 0x200)];
    let overlapping = elf_image::image(true, false, &phdrs, 0x300);
    assert_eq!(
        image_hmac(&overlapping, 0x1c0).unwrap(),
        expected(&overlapping, &[(0, 0x1c0), (0x100, 0x1c0), (0x210, 0x300)])
    );

    // A segment past the end of the file.
    assert_eq!(image_hmac(&image[..0x4ff], 0x420), Err(BinaryHmacError::Truncated));
    assert_eq!(image_hmac(b"not elf", 0), Err(BinaryHmacError::NotElf));

    // The check: the right value passes; an all-zero slot, any wrong bit, a wrong slot offset and
    // an unparseable file fail.
    assert!(verify_image(&image, 0x420, &value));
    assert!(!verify_image(&image, 0x420, &[0; 64]));
    for i in 0..64 {
        let mut wrong = value;
        wrong[i] ^= 0x80;
        assert!(!verify_image(&image, 0x420, &wrong), "value byte {i}");
    }
    assert!(!verify_image(&image, 0x421, &value));
    assert!(!verify_image(&image, 0x2000, &value));
    assert!(!verify_image(&image[..0x4ff], 0x420, &value));
    assert!(!verify_image(b"not elf", 0x420, &value));
}
