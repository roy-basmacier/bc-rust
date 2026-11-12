//! The software integrity test (ISO/IEC 19790:2012 7.10.2.2): at power-on, the binary HMAC of
//! this program's own read-only segments, as mapped, against the slot the post-link tool wrote.
//! The format is [`crate::binary_hmac`]'s. Only with the `integrity` cargo feature, on ELF.
//!
//! The only `unsafe` code in the crate is here, in two places: [`mapped`], which reads the
//! program's own headers and segments where the loader mapped them, and [`slot_value`], the
//! volatile read of the slot.

use bouncycastle_core::fips::{
    SelfTestError, SelfTestStatus, SelfTestStatusCell, SelfTestedAlgorithm,
};

use crate::binary_hmac::{self, SLOT_MAGIC, VALUE_LEN};

#[cfg(not(any(target_os = "linux", target_os = "android")))]
compile_error!(
    "the `integrity` feature of bouncycastle-fips supports ELF targets only (Linux, Android)"
);

/// The slot: the magic the post-link tool finds it by, then the value it writes. All-zero as
/// compiled. `repr(C)` keeps the two fields in this order with nothing between them.
#[repr(C)]
struct Slot {
    magic: [u8; SLOT_MAGIC.len()],
    value: [u8; VALUE_LEN],
}

// An immutable static with no interior mutability is placed in a read-only section, and so in a
// read-only PT_LOAD segment; `check` fails if it is not in one of the hashed segments.
static SLOT: Slot = Slot { magic: SLOT_MAGIC, value: [0; VALUE_LEN] };

/// The integrity test's status. Only [`self_test`] runs it.
static STATUS: SelfTestStatusCell = SelfTestStatusCell::new(SelfTestedAlgorithm::SoftwareIntegrity);

/// Runs the software integrity test. The HMAC-SHA-512 self-test must have passed first, or it
/// fails.
pub(crate) fn self_test() -> Result<(), SelfTestError> {
    STATUS.run(check)
}

/// Where the software integrity test stands.
pub(crate) fn status() -> SelfTestStatus {
    STATUS.get()
}

/// Whether the binary HMAC of the mapped program matches the slot. Fails closed: an empty slot,
/// headers it cannot read, a slot outside the hashed segments, all fail.
fn check() -> bool {
    let expected = slot_value();
    match mapped::Image::of_this_program() {
        Some(image) => {
            binary_hmac::verify(&image.segments, image.slot_offset, |s| image.bytes(s), &expected)
        }
        None => false,
    }
}

/// The value in the slot, as the file holds it.
#[allow(unsafe_code)]
fn slot_value() -> [u8; VALUE_LEN] {
    // SAFETY: the pointer comes from a reference to a field of a `static`, so it is non-null,
    // aligned (a byte array has alignment 1) and points to initialised memory that lives for the
    // whole program and is never written through Rust. The read is volatile because the compiler
    // knows the static's initialiser and would otherwise fold the read, and the comparison with
    // it, to the all-zero constant; the post-link tool changes the bytes behind its back.
    unsafe { core::ptr::read_volatile(&raw const SLOT.value) }
}

/// The program's headers and read-only segments, where the loader mapped them.
#[allow(unsafe_code)]
mod mapped {
    use crate::binary_hmac::{Segment, Segments, read_only_segments};

    // Defined by the linker (GNU ld, gold, lld) at the ELF header when the header is in a loaded
    // segment, as it is in an executable or shared object; the link fails if it is not.
    unsafe extern "C" {
        static __ehdr_start: u8;
    }

    /// How much of the program's start [`Image::of_this_program`] reads as its headers: the
    /// smallest page size of the supported targets.
    const HEADER_LEN: usize = 4096;

    /// This program's read-only segments as mapped, and the slot's file offset.
    pub(super) struct Image {
        pub(super) segments: Segments,
        pub(super) slot_offset: u64,
        /// The address the segments' `p_vaddr` are relative to: `__ehdr_start` less
        /// [`Segments::header_vaddr`], the load bias.
        bias: usize,
    }

    impl Image {
        /// Walks the program headers from `__ehdr_start`. `None` if they cannot be parsed or
        /// have no segment at file offset 0, or the slot is not in a read-only segment.
        pub(super) fn of_this_program() -> Option<Self> {
            let ehdr = &raw const __ehdr_start;
            // SAFETY: `__ehdr_start` is the ELF header at the start of the segment that maps
            // file offset 0, so it is at a page boundary (p_vaddr and p_offset are congruent
            // modulo p_align, which is at least a page) and the whole first page is mapped and
            // readable for the life of the process: the loader maps whole pages, the segment is
            // read-only, and it holds at least the header. HEADER_LEN is not more than a page.
            let headers = unsafe { core::slice::from_raw_parts(ehdr, HEADER_LEN) };
            let segments = read_only_segments(headers).ok()?;
            let bias = ehdr.addr().wrapping_sub(usize::try_from(segments.header_vaddr()?).ok()?);
            let slot_vaddr = (&raw const super::SLOT).addr().wrapping_sub(bias);
            let slot_offset = segments.file_offset_of(u64::try_from(slot_vaddr).ok()?)?;
            Some(Self { segments, slot_offset, bias })
        }

        /// `segment`'s bytes in memory: `p_filesz` bytes at the load bias plus `p_vaddr`.
        pub(super) fn bytes(&self, segment: &Segment) -> Option<&'static [u8]> {
            let addr = self.bias.wrapping_add(usize::try_from(segment.vaddr).ok()?);
            let len = usize::try_from(segment.filesz).ok()?;
            let ptr = core::ptr::with_exposed_provenance::<u8>(addr);
            // SAFETY: `segment` is a PT_LOAD of this program from its own program header table,
            // without PF_W and with PF_R (`read_only_segments` refuses one without). The loader
            // maps every PT_LOAD at the load bias plus its p_vaddr, with p_memsz >= p_filesz bytes
            // (gABI, "Program Header"), readable, and never writable since PF_W is clear, for the
            // life of the process; the bias is the one the ELF header itself was mapped with.
            // `len` fits the address space because the segment is mapped.
            Some(unsafe { core::slice::from_raw_parts(ptr, len) })
        }
    }
}

// The startup check cannot pass in a test binary, whose slot the post-link tool never wrote. So
// this checks the walk against the file instead (the same segments and the same bytes, from memory
// and from /proc/self/exe), and that the value computed over the file, as the tool computes it,
// verifies against the mapped segments. One test, because the self-test statuses are
// process-global.
#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::binary_hmac::{image_hmac, read_only_segments};

    #[test]
    fn memory_matches_the_file_and_the_empty_slot_fails() {
        let file = std::fs::read("/proc/self/exe").unwrap();
        let image = mapped::Image::of_this_program().expect("the program's headers parse");
        assert_eq!(image.segments, read_only_segments(&file).unwrap());
        // More than the header segment: the code is covered.
        assert!(image.segments.as_slice().len() >= 2);
        for s in image.segments.as_slice() {
            let start = usize::try_from(s.offset).unwrap();
            let end = start + usize::try_from(s.filesz).unwrap();
            assert!(image.bytes(s).unwrap() == &file[start..end], "segment at {start:#x}");
        }
        let slot = usize::try_from(image.slot_offset).unwrap();
        assert_eq!(file[slot..slot + 16], SLOT_MAGIC);
        assert_eq!(file[slot + 16..slot + 80], [0; 64]);
        assert_eq!(slot_value(), [0; 64]);

        // Before the HMAC-SHA-512 self-test nothing verifies, not even the right value.
        crate::sha2::self_test().unwrap();
        assert!(!check());
        crate::hmac_self_test::self_test().unwrap();
        // The empty slot fails.
        assert!(!check());
        // The value the tool would write verifies against memory; one wrong bit does not.
        let value = image_hmac(&file, image.slot_offset).unwrap();
        let bytes = |s: &crate::binary_hmac::Segment| image.bytes(s);
        assert!(binary_hmac::verify(&image.segments, image.slot_offset, bytes, &value));
        let mut wrong = value;
        wrong[63] ^= 1;
        assert!(!binary_hmac::verify(&image.segments, image.slot_offset, bytes, &wrong));
        // The power-on entry fails on the empty slot and enters the error state.
        assert_eq!(
            self_test(),
            Err(SelfTestError::KnownAnswerMismatch(SelfTestedAlgorithm::SoftwareIntegrity))
        );
        assert_eq!(status(), SelfTestStatus::Failed);
    }
}
