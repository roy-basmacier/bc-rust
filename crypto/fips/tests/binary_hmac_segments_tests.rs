//! The ELF program-header walk and the slot search of `binary_hmac`, against hand-built images.
//! Nothing here hashes, so no self-test is needed.

#![cfg(feature = "sha2")]

mod elf_image;

use bouncycastle_fips::binary_hmac::{
    BinaryHmacError, MAX_SEGMENTS, SLOT_MAGIC, Segment, find_slot, read_only_segments,
};
use elf_image::*;

fn seg(offset: u64, vaddr: u64, filesz: u64) -> Segment {
    Segment { offset, vaddr, filesz }
}

#[test]
fn the_read_only_loads_in_file_order_for_every_class_and_byte_order() {
    for (elf64, big_endian) in [(true, false), (true, true), (false, false), (false, true)] {
        let image = image(elf64, big_endian, &usual_phdrs(), USUAL_LEN);
        let segments = read_only_segments(&image).unwrap();
        // No PT_PHDR, no PT_GNU_STACK, no RW; the rodata listed last comes second.
        assert_eq!(
            segments.as_slice(),
            [seg(0, 0, 0x200), seg(0x300, 0x300, 0x80), seg(0x400, 0x1400, 0x100)],
            "elf64 {elf64}, big-endian {big_endian}"
        );
        assert_eq!(segments.header_vaddr(), Some(0));
        // Only the headers are needed: the image cut after the table parses the same.
        assert_eq!(read_only_segments(&image[..64 + 6 * 56]).unwrap(), segments);
    }
}

#[test]
fn equal_offsets_keep_the_table_order() {
    let phdrs =
        [load(PF_R, 0x300, 0x5300, 0x10), load(PF_R, 0x300, 0x6300, 0x20), load(PF_R, 0, 0x100, 8)];
    let segments = read_only_segments(&image(true, false, &phdrs, 0x400)).unwrap();
    assert_eq!(
        segments.as_slice(),
        [seg(0, 0x100, 8), seg(0x300, 0x5300, 0x10), seg(0x300, 0x6300, 0x20)]
    );
}

#[test]
fn the_header_vaddr_is_the_first_load_at_offset_zero_writable_or_not() {
    let phdrs = [load(PF_R | PF_W, 0, 0x7000, 0x100), load(PF_R, 0, 0x8000, 0x100)];
    let segments = read_only_segments(&image(true, false, &phdrs, 0x200)).unwrap();
    assert_eq!(segments.header_vaddr(), Some(0x7000));
    assert_eq!(segments.as_slice(), [seg(0, 0x8000, 0x100)]);

    // A non-load at offset 0 does not count.
    let phdrs = [
        Phdr { p_type: PT_GNU_STACK, flags: PF_R, offset: 0, vaddr: 0x9000, filesz: 0 },
        load(PF_R, 0x100, 0x100, 0x10),
    ];
    assert_eq!(
        read_only_segments(&image(true, false, &phdrs, 0x200)).unwrap().header_vaddr(),
        None
    );
}

#[test]
fn file_offset_of_maps_a_vaddr_inside_a_read_only_segment() {
    let segments = read_only_segments(&image(true, false, &usual_phdrs(), USUAL_LEN)).unwrap();
    assert_eq!(segments.file_offset_of(0x1400), Some(0x400));
    assert_eq!(segments.file_offset_of(0x14ff), Some(0x4ff));
    assert_eq!(segments.file_offset_of(0x1500), None); // one past the end
    assert_eq!(segments.file_offset_of(0x13ff), None); // one before the start
    assert_eq!(segments.file_offset_of(0x310), Some(0x310));
    assert_eq!(segments.file_offset_of(0x2510), None); // the writable segment
}

#[test]
fn malformed_headers_are_refused() {
    let good = image(true, false, &usual_phdrs(), USUAL_LEN);
    let refused = |edit: &dyn Fn(&mut Vec<u8>)| {
        let mut image = good.clone();
        edit(&mut image);
        read_only_segments(&image).unwrap_err()
    };
    assert_eq!(refused(&|i| i[0] = 0x7e), BinaryHmacError::NotElf);
    assert_eq!(refused(&|i| i.truncate(3)), BinaryHmacError::NotElf);
    assert_eq!(refused(&|i| i[4] = 3), BinaryHmacError::Unsupported); // EI_CLASS
    assert_eq!(refused(&|i| i[4] = 0), BinaryHmacError::Unsupported);
    assert_eq!(refused(&|i| i[5] = 0), BinaryHmacError::Unsupported); // EI_DATA
    assert_eq!(refused(&|i| i[5] = 3), BinaryHmacError::Unsupported);
    assert_eq!(refused(&|i| i.truncate(4)), BinaryHmacError::Unsupported);
    assert_eq!(refused(&|i| i.truncate(5)), BinaryHmacError::Unsupported);
    assert_eq!(refused(&|i| i[0x36] = 55), BinaryHmacError::Unsupported); // e_phentsize < 56
    assert_eq!(
        refused(&|i| i[0x38..0x3a].copy_from_slice(&[0xff, 0xff])),
        BinaryHmacError::Unsupported
    ); // PN_XNUM
    // The header, or the table, cut short.
    assert_eq!(refused(&|i| i.truncate(0x39)), BinaryHmacError::Truncated);
    assert_eq!(refused(&|i| i.truncate(64 + 6 * 56 - 1)), BinaryHmacError::Truncated);
    assert_eq!(refused(&|i| i[0x20..0x28].fill(0xff)), BinaryHmacError::Truncated); // e_phoff
    // A larger e_phentsize is accepted, and moves every entry after the first.
    let mut wider = good.clone();
    wider[0x36] = 57;
    assert_ne!(read_only_segments(&wider).map(|_| ()), Err(BinaryHmacError::Unsupported));

    // A read-only load without PF_R, and one whose file range overflows.
    let unreadable = image(true, false, &[load(PF_X, 0x100, 0x100, 0x10)], 0x200);
    assert_eq!(read_only_segments(&unreadable), Err(BinaryHmacError::UnreadableSegment));
    let writable_unreadable = image(true, false, &[load(PF_W, 0x100, 0x100, 0x10)], 0x200);
    assert_eq!(read_only_segments(&writable_unreadable).unwrap().as_slice(), []);
    let overflow = image(true, false, &[load(PF_R, u64::MAX, 0, 1)], 0x200);
    assert_eq!(read_only_segments(&overflow), Err(BinaryHmacError::Truncated));
    let at_the_limit = image(true, false, &[load(PF_R, u64::MAX - 1, 0, 1)], 0x200);
    assert_eq!(read_only_segments(&at_the_limit).unwrap().as_slice(), [seg(u64::MAX - 1, 0, 1)]);
}

#[test]
fn at_most_max_segments() {
    let phdrs: Vec<Phdr> = (0..MAX_SEGMENTS as u64).map(|i| load(PF_R, i, i, 1)).collect();
    let len = 64 + (MAX_SEGMENTS + 1) * 56;
    assert_eq!(
        read_only_segments(&image(true, false, &phdrs, len)).unwrap().as_slice().len(),
        MAX_SEGMENTS
    );
    let mut more = phdrs.clone();
    more.push(load(PF_R | PF_W, 0x40, 0x40, 1)); // writable ones do not count
    assert_eq!(
        read_only_segments(&image(true, false, &more, len)).unwrap().as_slice().len(),
        MAX_SEGMENTS
    );
    more.pop();
    more.push(load(PF_R, 0x40, 0x40, 1));
    assert_eq!(
        read_only_segments(&image(true, false, &more, len)),
        Err(BinaryHmacError::TooManySegments)
    );
}

#[test]
fn find_slot_wants_exactly_one_magic() {
    let mut image = image(true, false, &usual_phdrs(), USUAL_LEN);
    assert_eq!(find_slot(&image), Err(BinaryHmacError::NoSlot));
    put_magic(&mut image, 0x420);
    assert_eq!(find_slot(&image), Ok(0x420));
    // At the very end of the file.
    let end = image.len() - SLOT_MAGIC.len();
    put_magic(&mut image, end);
    assert_eq!(find_slot(&image), Err(BinaryHmacError::MultipleSlots));
    image[0x420] ^= 1;
    assert_eq!(find_slot(&image), Ok(end as u64));
    assert_eq!(find_slot(&[]), Err(BinaryHmacError::NoSlot));
}
