//! Hand-built ELF images for the binary-HMAC tests: an ELF header, a program header table right
//! after it, and filler bytes that differ from their neighbours, so that a test can tell which
//! bytes were hashed. Field offsets as in `/usr/include/elf.h`.

#![allow(dead_code)]

pub const PT_LOAD: u32 = 1;
pub const PT_PHDR: u32 = 6;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// One program header.
#[derive(Clone, Copy)]
pub struct Phdr {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
}

/// A `PT_LOAD` header.
pub fn load(flags: u32, offset: u64, vaddr: u64, filesz: u64) -> Phdr {
    Phdr { p_type: PT_LOAD, flags, offset, vaddr, filesz }
}

/// An ELF file of `len` bytes, 64- or 32-bit, little- or big-endian, with `phdrs` as its program
/// header table.
pub fn image(elf64: bool, big_endian: bool, phdrs: &[Phdr], len: usize) -> Vec<u8> {
    // Filler first, so that no byte of the image is left zero by accident.
    let mut image: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
    let put = |image: &mut Vec<u8>, at: usize, width: usize, value: u64| {
        for i in 0..width {
            let shift = 8 * if big_endian { width - 1 - i } else { i };
            image[at + i] = (value >> shift) as u8;
        }
    };
    image[..4].copy_from_slice(b"\x7fELF");
    image[4] = if elf64 { 2 } else { 1 };
    image[5] = if big_endian { 2 } else { 1 };
    // (e_phoff, its width, e_phentsize, e_phnum), then the Phdr layout.
    let (phoff, phentsize) = if elf64 { (64, 56) } else { (52, 32) };
    if elf64 {
        put(&mut image, 0x20, 8, phoff as u64);
        put(&mut image, 0x36, 2, phentsize as u64);
        put(&mut image, 0x38, 2, phdrs.len() as u64);
    } else {
        put(&mut image, 0x1c, 4, phoff as u64);
        put(&mut image, 0x2a, 2, phentsize as u64);
        put(&mut image, 0x2c, 2, phdrs.len() as u64);
    }
    for (i, p) in phdrs.iter().enumerate() {
        let at = phoff + i * phentsize;
        put(&mut image, at, 4, p.p_type.into());
        if elf64 {
            put(&mut image, at + 4, 4, p.flags.into());
            put(&mut image, at + 8, 8, p.offset);
            put(&mut image, at + 16, 8, p.vaddr);
            put(&mut image, at + 32, 8, p.filesz);
        } else {
            put(&mut image, at + 4, 4, p.offset);
            put(&mut image, at + 8, 4, p.vaddr);
            put(&mut image, at + 16, 4, p.filesz);
            put(&mut image, at + 24, 4, p.flags.into());
        }
    }
    image
}

/// The usual layout, with the table out of file order: header segment R at 0..0x200, text RX at
/// 0x400..0x500 (vaddr 0x1400), data RW at 0x500..0x580, rodata R at 0x300..0x380 listed last,
/// plus a PT_PHDR and a PT_GNU_STACK that are not loads. 0x600 bytes.
pub fn usual_phdrs() -> Vec<Phdr> {
    vec![
        Phdr { p_type: PT_PHDR, flags: PF_R, offset: 0x40, vaddr: 0x40, filesz: 0x100 },
        load(PF_R, 0, 0, 0x200),
        load(PF_R | PF_X, 0x400, 0x1400, 0x100),
        load(PF_R | PF_W, 0x500, 0x2500, 0x80),
        load(PF_R, 0x300, 0x300, 0x80),
        Phdr { p_type: PT_GNU_STACK, flags: PF_R | PF_W, offset: 0, vaddr: 0, filesz: 0 },
    ]
}

pub const USUAL_LEN: usize = 0x600;

/// Writes the slot magic at `at`.
pub fn put_magic(image: &mut [u8], at: usize) {
    image[at..at + 16].copy_from_slice(&bouncycastle_fips::binary_hmac::SLOT_MAGIC);
}
