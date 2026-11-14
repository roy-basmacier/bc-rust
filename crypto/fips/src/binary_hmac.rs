//! The binary HMAC: the format shared by the software integrity test and the post-link tool that
//! writes its expected value.
//!
//! The integrity test (the `integrity` cargo feature) HMACs the program's own read-only loaded
//! segments at startup and compares the result with the value in a slot compiled into the
//! program. Nothing at build time can know that value, so a post-link tool computes it over the
//! finished ELF file, with the functions here, and writes it into the slot. Both sides use this
//! module so that they cannot drift apart.
//!
//! # The format
//!
//! **This is a contract with the post-link tool: the slot magic, the slot layout, the key and the
//! hashed ranges must not change without changing the tool, and a published release fixes them.**
//!
//! * **The slot** is [`SLOT_LEN`] bytes: [`SLOT_MAGIC`], then the [`VALUE_LEN`]-byte value, in a
//!   read-only segment. The tool finds it by its magic ([`find_slot`]), not by a symbol, so it
//!   survives a `strip`. An all-zero value means the tool never ran, and the test fails. The
//!   magic's 16 bytes must occur nowhere else in the program: [`find_slot`] itself does not
//!   contain them, and a program must not copy [`SLOT_MAGIC`] into other data of its own.
//! * **The ranges** are the file bytes (`p_offset`, `p_filesz`) of every `PT_LOAD` segment that
//!   is not writable (no `PF_W`), in ascending `p_offset` order, with the slot's [`SLOT_LEN`]
//!   bytes left out wherever a segment contains them ([`read_only_segments`]). Writable segments
//!   are left out because the loader rewrites them (`.data.rel.ro` under PIE relocations, `.got`,
//!   `.data`). A non-writable segment is mapped from the file unchanged, so the bytes hashed in
//!   memory at startup are the bytes the tool hashed in the file.
//! * **The value** is HMAC-SHA-512, keyed with [`KEY`], of those ranges' bytes concatenated, with
//!   nothing between them ([`image_hmac`]).
//!
//! The tool must run after anything that changes the read-only segments and before any code
//! signing that rewrites them. That includes `strip`: the first segment holds the ELF header,
//! whose `e_shoff`, `e_shnum` and `e_shstrndx` a `strip` rewrites. ELF only:
//! 32- and 64-bit, either byte order.
//!
//! # 🚨 Security Considerations 🚨
//!
//! * **The value is not a secret, and the key is public.** The test detects corruption and casual
//!   tampering of the program file. Anyone who can rewrite a segment can rewrite the slot as well.
//! * **Writable segments are not covered**, nor is anything outside a loaded segment (section
//!   headers, symbols, debug info).

use bouncycastle_core::fips::SelfTestStatus;
use bouncycastle_core::key_material::{KeyMaterial, KeyType};
use bouncycastle_core::symmetric_key::{FromAnyKeyMaterial, MacGenerationKey, MacVerificationKey};
use bouncycastle_core::traits::{MACGenerator, MACVerifier};
use bouncycastle_hmac::HmacKey;
use bouncycastle_sha2::SHA512;

use crate::hmac_self_test;

/// The first 16 bytes of the slot, by which the tool finds it in the file.
pub const SLOT_MAGIC: [u8; 16] = *b"BC-RUST FIPS HM\x01";

/// The length of the HMAC-SHA-512 value in the slot.
pub const VALUE_LEN: usize = 64;

/// The length of [`SLOT_MAGIC`], and so the offset of the value in the slot. Code that only needs
/// the length uses this rather than `SLOT_MAGIC.len()`, which in an unoptimised build puts a copy
/// of the magic's bytes into the program.
pub const SLOT_MAGIC_LEN: usize = SLOT_MAGIC.len();

/// The length of the slot: [`SLOT_MAGIC`] then the value.
pub const SLOT_LEN: usize = SLOT_MAGIC_LEN + VALUE_LEN;

/// The HMAC key: the public string the module HMAC is keyed with too.
pub const KEY: &[u8] = b"Legion of the Bouncy Castle FIPS Rust API";

/// The most read-only `PT_LOAD` segments a file may have. Linkers emit two to four.
pub const MAX_SEGMENTS: usize = 16;

/// Why a file could not be hashed or checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BinaryHmacError {
    /// The bytes do not start with the ELF magic.
    NotElf,
    /// An ELF class or byte order other than 32/64-bit and little/big-endian, a program header
    /// table entry smaller than the class's `Phdr`, or more than 65534 program headers
    /// (`PN_XNUM`).
    Unsupported,
    /// A header, the program header table, or a segment's file bytes reach past the end of the
    /// bytes given, or a segment's file range overflows.
    Truncated,
    /// More than [`MAX_SEGMENTS`] read-only `PT_LOAD` segments.
    TooManySegments,
    /// A read-only `PT_LOAD` segment that is not readable (no `PF_R`), which the program could
    /// not hash at startup.
    UnreadableSegment,
    /// No [`SLOT_MAGIC`] in the file.
    NoSlot,
    /// More than one [`SLOT_MAGIC`] in the file.
    MultipleSlots,
    /// The slot is not wholly inside one read-only `PT_LOAD` segment.
    SlotOutsideSegments,
    /// The HMAC-SHA-512 self-test has not passed: run
    /// [`power_on_self_tests`](crate::power_on_self_tests) first.
    SelfTestNotPassed,
}

/// One read-only `PT_LOAD` segment: its program header's `p_offset`, `p_vaddr` and `p_filesz`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Segment {
    /// Where its bytes start in the file.
    pub offset: u64,
    /// Where its bytes start in memory, before the load bias.
    pub vaddr: u64,
    /// How many bytes it has in the file.
    pub filesz: u64,
}

/// The read-only `PT_LOAD` segments of an ELF file, in ascending file offset, from
/// [`read_only_segments`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segments {
    list: [Segment; MAX_SEGMENTS],
    len: usize,
    header_vaddr: Option<u64>,
}

impl Segments {
    /// The segments, in ascending file offset.
    pub fn as_slice(&self) -> &[Segment] {
        &self.list[..self.len]
    }

    /// The `p_vaddr` of the `PT_LOAD` segment, writable or not, that starts at file offset 0 and
    /// so holds the ELF header; `None` if there is none.
    pub fn header_vaddr(&self) -> Option<u64> {
        self.header_vaddr
    }

    /// The file offset of the byte at `vaddr`, if one of the segments holds it.
    pub fn file_offset_of(&self, vaddr: u64) -> Option<u64> {
        self.as_slice()
            .iter()
            .find(|s| s.vaddr <= vaddr && vaddr - s.vaddr < s.filesz)
            .map(|s| s.offset + (vaddr - s.vaddr))
    }

    /// Inserts `segment` after every segment with a file offset at or below its own.
    fn insert(&mut self, segment: Segment) -> Result<(), BinaryHmacError> {
        if self.len == MAX_SEGMENTS {
            return Err(BinaryHmacError::TooManySegments);
        }
        let at = self.as_slice().iter().take_while(|s| s.offset <= segment.offset).count();
        self.list.copy_within(at..self.len, at + 1);
        self.list[at] = segment;
        self.len += 1;
        Ok(())
    }
}

/// Where the fields this module reads sit in one ELF class. Offsets from `/usr/include/elf.h`
/// (`Elf32_Ehdr`, `Elf64_Ehdr`, `Elf32_Phdr`, `Elf64_Phdr`), checked against the System V gABI
/// chapters "ELF Header" and "Program Header".
struct Layout {
    /// `e_phoff` and its width.
    e_phoff: (usize, usize),
    e_phentsize: usize,
    e_phnum: usize,
    /// `sizeof(ElfN_Phdr)`.
    phdr_len: usize,
    p_flags: usize,
    /// `p_offset`, `p_vaddr` and `p_filesz` are each this wide.
    p_word: usize,
    p_offset: usize,
    p_vaddr: usize,
    p_filesz: usize,
}

const ELF32: Layout = Layout {
    e_phoff: (0x1c, 4),
    e_phentsize: 0x2a,
    e_phnum: 0x2c,
    phdr_len: 32,
    p_flags: 24,
    p_word: 4,
    p_offset: 4,
    p_vaddr: 8,
    p_filesz: 16,
};

const ELF64: Layout = Layout {
    e_phoff: (0x20, 8),
    e_phentsize: 0x36,
    e_phnum: 0x38,
    phdr_len: 56,
    p_flags: 4,
    p_word: 8,
    p_offset: 8,
    p_vaddr: 16,
    p_filesz: 32,
};

/// `e_ident[EI_CLASS]` and `e_ident[EI_DATA]` values (`elf.h`).
const EI_CLASS: usize = 4;
const EI_DATA: usize = 5;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;
/// `p_type` and `p_flags` values (`elf.h`).
const PT_LOAD: u64 = 1;
const PF_W: u64 = 1 << 1;
const PF_R: u64 = 1 << 2;
/// The `e_phnum` that means the real count is elsewhere (`elf.h`), which this module refuses.
const PN_XNUM: u64 = 0xffff;

/// The `width`-byte unsigned field at `at`, or `None` if it is not all inside `bytes`.
fn field(bytes: &[u8], at: usize, width: usize, big_endian: bool) -> Option<u64> {
    let raw = bytes.get(at..at.checked_add(width)?)?;
    let mut value = 0u64;
    for i in 0..width {
        let byte = if big_endian { raw[i] } else { raw[width - 1 - i] };
        value = (value << 8) | u64::from(byte);
    }
    Some(value)
}

/// The read-only `PT_LOAD` segments of the ELF file whose first bytes are `headers`, which must
/// hold the ELF header and the whole program header table. Every `PT_LOAD` without `PF_W` is
/// listed, in ascending `p_offset` (the order of the table where two are equal).
///
/// # Errors
/// [`BinaryHmacError::NotElf`], [`BinaryHmacError::Unsupported`],
/// [`BinaryHmacError::Truncated`] if the table does not fit in `headers` or a segment's file range
/// overflows, [`BinaryHmacError::TooManySegments`], and [`BinaryHmacError::UnreadableSegment`].
pub fn read_only_segments(headers: &[u8]) -> Result<Segments, BinaryHmacError> {
    if !headers.starts_with(b"\x7fELF") {
        return Err(BinaryHmacError::NotElf);
    }
    let layout = match headers.get(EI_CLASS) {
        Some(&ELFCLASS32) => &ELF32,
        Some(&ELFCLASS64) => &ELF64,
        _ => return Err(BinaryHmacError::Unsupported),
    };
    let big_endian = match headers.get(EI_DATA) {
        Some(&ELFDATA2LSB) => false,
        Some(&ELFDATA2MSB) => true,
        _ => return Err(BinaryHmacError::Unsupported),
    };
    let read = |at: usize, width: usize| {
        field(headers, at, width, big_endian).ok_or(BinaryHmacError::Truncated)
    };
    let to_usize = |v: u64| usize::try_from(v).map_err(|_| BinaryHmacError::Truncated);

    let phoff = to_usize(read(layout.e_phoff.0, layout.e_phoff.1)?)?;
    let phentsize = to_usize(read(layout.e_phentsize, 2)?)?;
    let phnum = read(layout.e_phnum, 2)?;
    if phentsize < layout.phdr_len || phnum == PN_XNUM {
        return Err(BinaryHmacError::Unsupported);
    }
    let table_len = phentsize * to_usize(phnum)?;
    let table = phoff
        .checked_add(table_len)
        .and_then(|end| headers.get(phoff..end))
        .ok_or(BinaryHmacError::Truncated)?;

    let mut segments =
        Segments { list: [Segment::default(); MAX_SEGMENTS], len: 0, header_vaddr: None };
    for phdr in table.chunks_exact(phentsize) {
        let read = |at: usize, width: usize| {
            field(phdr, at, width, big_endian).ok_or(BinaryHmacError::Truncated)
        };
        if read(0, 4)? != PT_LOAD {
            continue;
        }
        let segment = Segment {
            offset: read(layout.p_offset, layout.p_word)?,
            vaddr: read(layout.p_vaddr, layout.p_word)?,
            filesz: read(layout.p_filesz, layout.p_word)?,
        };
        if segment.offset == 0 && segments.header_vaddr.is_none() {
            segments.header_vaddr = Some(segment.vaddr);
        }
        let flags = read(layout.p_flags, 4)?;
        if flags & PF_W != 0 {
            continue;
        }
        if flags & PF_R == 0 {
            return Err(BinaryHmacError::UnreadableSegment);
        }
        if segment.offset.checked_add(segment.filesz).is_none() {
            return Err(BinaryHmacError::Truncated);
        }
        segments.insert(segment)?;
    }
    Ok(segments)
}

/// The file offset of the slot: the one place [`SLOT_MAGIC`] occurs in `image`.
///
/// # Errors
/// [`BinaryHmacError::NoSlot`] or [`BinaryHmacError::MultipleSlots`].
pub fn find_slot(image: &[u8]) -> Result<u64, BinaryHmacError> {
    let mut found = image
        .windows(SLOT_MAGIC_LEN)
        .enumerate()
        .filter(|(_, w)| w[0] == SLOT_MAGIC_FIRST && magic_tag(w) == SLOT_MAGIC_TAG);
    match (found.next(), found.next()) {
        (Some((at, _)), None) => Ok(at as u64),
        (None, _) => Err(BinaryHmacError::NoSlot),
        (Some(_), Some(_)) => Err(BinaryHmacError::MultipleSlots),
    }
}

/// A 64-bit tag of `bytes`: each byte added in, then a multiplication by an arbitrary odd constant
/// and a fold of the high half into the low. Not a cryptographic hash, and it need not be:
/// [`find_slot`] uses it only to tell [`SLOT_MAGIC`] from other bytes of a file, where a chance
/// match of 64 bits is not a practical concern.
///
/// It exists so that the code that searches for the magic does not contain the magic. A plain
/// comparison with [`SLOT_MAGIC`] compiles to a 16-byte constant in the read-only data of every
/// program that calls [`find_slot`]; the post-link tool is such a program, and it found that
/// constant in itself, or in any program built without the `integrity` feature that searches for
/// a slot, took it for a slot, and wrote 64 bytes over whatever followed it. With the tag, the
/// only place the magic's bytes occur in a program is its slot.
const fn magic_tag(bytes: &[u8]) -> u64 {
    let mut tag = 0u64;
    let mut i = 0;
    while i < bytes.len() {
        tag = (tag ^ bytes[i] as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        tag ^= tag >> 32;
        i += 1;
    }
    tag
}

/// The first byte of [`SLOT_MAGIC`], which [`find_slot`] looks for before it computes a tag. A
/// constant of its own for the reason [`SLOT_MAGIC_LEN`] is.
const SLOT_MAGIC_FIRST: u8 = SLOT_MAGIC[0];

/// [`magic_tag`] of [`SLOT_MAGIC`], evaluated at compile time.
const SLOT_MAGIC_TAG: u64 = magic_tag(&SLOT_MAGIC);

/// The binary HMAC of the ELF file `image` whose slot starts at file offset `slot_offset`: the
/// value the post-link tool writes into the slot.
///
/// # Errors
/// Those of [`read_only_segments`]; [`BinaryHmacError::Truncated`] if a segment's bytes reach
/// past the end of `image`; [`BinaryHmacError::SlotOutsideSegments`]; and
/// [`BinaryHmacError::SelfTestNotPassed`].
pub fn image_hmac(image: &[u8], slot_offset: u64) -> Result<[u8; VALUE_LEN], BinaryHmacError> {
    let segments = read_only_segments(image)?;
    let key = key()?;
    let mut generator = key.create_generator();
    absorb(&segments, slot_offset, |s| file_bytes(image, s), |bytes| generator.do_update(bytes))?;
    Ok(generator.do_final())
}

/// Whether `expected` is the binary HMAC of the ELF file `image` whose slot starts at file offset
/// `slot_offset`, compared in constant time. `false` for an all-zero `expected`, and wherever
/// [`image_hmac`] would return an error.
pub fn verify_image(image: &[u8], slot_offset: u64, expected: &[u8; VALUE_LEN]) -> bool {
    match read_only_segments(image) {
        Ok(segments) => verify(&segments, slot_offset, |s| file_bytes(image, s), expected),
        Err(_) => false,
    }
}

/// `segment`'s bytes in the file `image`, if they are all inside it.
fn file_bytes<'a>(image: &'a [u8], segment: &Segment) -> Option<&'a [u8]> {
    let start = usize::try_from(segment.offset).ok()?;
    let len = usize::try_from(segment.filesz).ok()?;
    image.get(start..start.checked_add(len)?)
}

/// Whether `expected` is the binary HMAC of `segments`, whose bytes `bytes` gives, with the slot
/// at file offset `slot_offset`: the check shared by [`verify_image`] and the startup test.
pub(crate) fn verify<'a>(
    segments: &Segments,
    slot_offset: u64,
    bytes: impl FnMut(&Segment) -> Option<&'a [u8]>,
    expected: &[u8; VALUE_LEN],
) -> bool {
    // Fail closed on the slot as compiled, before the post-link tool has written it. The HMAC
    // below cannot come out all-zero in practice; this makes the rule explicit.
    if expected.iter().all(|&b| b == 0) {
        return false;
    }
    let Ok(key) = key() else { return false };
    let mut verifier = key.create_verifier();
    absorb(segments, slot_offset, bytes, |b| verifier.do_update(b)).is_ok()
        && verifier.do_verify_final(expected).is_ok()
}

/// The HMAC key from [`KEY`], once the HMAC-SHA-512 self-test has passed (ISO/IEC 19790:2012
/// 7.10.1 [10.20]: the integrity technique's algorithm "shall first pass" its self-test).
fn key() -> Result<HmacKey<SHA512>, BinaryHmacError> {
    if hmac_self_test::status() != SelfTestStatus::Passed {
        return Err(BinaryHmacError::SelfTestNotPassed);
    }
    // A public, fixed key: the strength check a key normally gets does not apply. Neither call can
    // fail on it (41 bytes fit 64, and it is tagged a MAC key); a failure fails the check.
    KeyMaterial::<64>::from_bytes_as_type(KEY, KeyType::MACKey)
        .ok()
        .and_then(|material| HmacKey::<SHA512>::from_key_material_allow_weak(&material).ok())
        .ok_or(BinaryHmacError::SelfTestNotPassed)
}

/// Feeds `update` the bytes the binary HMAC covers: each segment's bytes, from `bytes`, in the
/// order of `segments`, without the [`SLOT_LEN`] bytes at file offset `slot_offset`.
///
/// # Errors
/// [`BinaryHmacError::SlotOutsideSegments`] if no segment holds the whole slot, before anything
/// is fed; [`BinaryHmacError::Truncated`] if `bytes` has no bytes, or a different number than
/// `filesz`, for a segment.
fn absorb<'a>(
    segments: &Segments,
    slot_offset: u64,
    mut bytes: impl FnMut(&Segment) -> Option<&'a [u8]>,
    mut update: impl FnMut(&[u8]),
) -> Result<(), BinaryHmacError> {
    let slot_end =
        slot_offset.checked_add(SLOT_LEN as u64).ok_or(BinaryHmacError::SlotOutsideSegments)?;
    // `read_only_segments` checked that `offset + filesz` does not overflow.
    if !segments
        .as_slice()
        .iter()
        .any(|s| s.offset <= slot_offset && slot_end <= s.offset + s.filesz)
    {
        return Err(BinaryHmacError::SlotOutsideSegments);
    }
    for segment in segments.as_slice() {
        let data = bytes(segment).ok_or(BinaryHmacError::Truncated)?;
        if data.len() as u64 != segment.filesz {
            return Err(BinaryHmacError::Truncated);
        }
        let (start, end) = (segment.offset, segment.offset + segment.filesz);
        if slot_end <= start || end <= slot_offset {
            update(data);
            continue;
        }
        // The slot overlaps this segment: hash what is before it and what is after it. Both
        // bounds are at most `filesz`, which is `data.len()`, so the casts are lossless.
        let before = slot_offset.saturating_sub(start) as usize;
        let after = (slot_end - start).min(segment.filesz) as usize;
        update(&data[..before]);
        update(&data[after..]);
    }
    Ok(())
}
