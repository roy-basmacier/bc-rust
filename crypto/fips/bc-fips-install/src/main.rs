//! `bc-fips-install`: the post-link tool that writes a program's binary HMAC into its slot, so
//! that the software integrity test of `bouncycastle-fips` (its `integrity` feature) passes.
//!
//! ```text
//! bc-fips-install <ELF file>
//! ```
//!
//! It reads the file, finds the slot by its magic, HMACs the file's read-only `PT_LOAD` segments
//! without the slot, and writes the 64-byte value into the slot, in place: nothing else in the
//! file changes. It prints the slot's file offset and the value. The format, and the code that
//! parses the file and computes the value, are `bouncycastle_fips::binary_hmac`'s, which the
//! startup test uses too.
//!
//! It refuses, and leaves the file as it was, when the file is not a 32- or 64-bit ELF file, has
//! no slot (it was not built with the `integrity` feature) or more than one, or has its slot
//! outside the read-only segments. Running it again on an installed file writes the same value.
//!
//! Exit status: 0 when the value was written, 1 when it was refused or the file could not be
//! read or written, 2 for a usage error.
//!
//! # Ordering
//!
//! **Run it after `strip` and before any code signing**: after the last step that changes the
//! file's read-only segments. Those segments start with the ELF header, so a `strip` after the
//! tool, which moves the section headers and rewrites the header's `e_shoff`, makes the startup
//! test fail; so does signing that rewrites headers. Run the tool again after such a step.
//!
//! # 🚨 Security Considerations 🚨
//!
//! * **The value detects corruption, not an attacker.** The key is public and the value is in
//!   the file it covers, so anyone who can change the file can run this tool again.
//! * **Writable segments, and everything outside a loaded segment, are not covered.**

#![forbid(unsafe_code)]
#![forbid(missing_docs)]

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::ExitCode;

use bouncycastle_fips::binary_hmac::{
    BinaryHmacError, SLOT_MAGIC, VALUE_LEN, find_slot, image_hmac, read_only_segments,
};
use bouncycastle_fips::{SelfTestError, power_on_self_tests};

const USAGE: &str = "\
usage: bc-fips-install <ELF file>

Writes the binary HMAC of <ELF file> into its bouncycastle-fips integrity slot, in place.
Run it after strip and before any code signing.
";

/// Why the value was not written.
enum Error {
    /// The tool's own HMAC-SHA-512 self-test failed: it computes nothing.
    SelfTest(SelfTestError),
    /// The file could not be opened, read or written.
    Io(io::Error),
    /// The file has no usable slot or cannot be hashed.
    Format(BinaryHmacError),
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let path = match args.as_slice() {
        [flag] if flag == "-h" || flag == "--help" => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        // Anything else that looks like an option is a usage error, not a file name.
        [path] if !path.to_string_lossy().starts_with('-') => Path::new(path),
        _ => {
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match install(path) {
        Ok((slot_offset, value)) => {
            let hex: String = value.iter().map(|b| format!("{b:02x}")).collect();
            println!("{}: slot at file offset {slot_offset:#x}: {hex}", path.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("bc-fips-install: {}: {}", path.display(), message(&e));
            ExitCode::FAILURE
        }
    }
}

/// Writes the binary HMAC of the ELF file at `path` into its slot, and returns the slot's file
/// offset and the value. The file is written only once everything has been checked.
fn install(path: &Path) -> Result<(u64, [u8; VALUE_LEN]), Error> {
    // The HMAC-SHA-512 self-test, which `image_hmac` requires before it computes anything.
    power_on_self_tests().map_err(Error::SelfTest)?;

    let mut file = OpenOptions::new().read(true).write(true).open(path).map_err(Error::Io)?;
    let mut image = Vec::new();
    file.read_to_end(&mut image).map_err(Error::Io)?;

    // Parse the headers first, so that a file that is not ELF says so rather than "no slot".
    read_only_segments(&image).map_err(Error::Format)?;
    // By content, not by symbol, so a stripped file works; exactly one, or which to write is
    // ambiguous.
    let slot_offset = find_slot(&image).map_err(Error::Format)?;
    let value = image_hmac(&image, slot_offset).map_err(Error::Format)?;

    // The value goes right after the magic. `image_hmac` checked that the whole slot is inside a
    // segment of the file, so this writes over existing bytes and never extends the file.
    file.seek(SeekFrom::Start(slot_offset + SLOT_MAGIC.len() as u64)).map_err(Error::Io)?;
    file.write_all(&value).map_err(Error::Io)?;
    file.sync_all().map_err(Error::Io)?;
    Ok((slot_offset, value))
}

/// What to tell the user about `e`.
fn message(e: &Error) -> String {
    match e {
        Error::SelfTest(e) => format!("the tool's own HMAC-SHA-512 self-test failed: {e:?}"),
        Error::Io(e) => e.to_string(),
        Error::Format(e) => match e {
            BinaryHmacError::NotElf => "not an ELF file".into(),
            BinaryHmacError::NoSlot => {
                "no integrity slot: was it built with bouncycastle-fips's `integrity` feature?"
                    .into()
            }
            BinaryHmacError::MultipleSlots => {
                "more than one integrity slot magic in the file; refusing to choose".into()
            }
            BinaryHmacError::SlotOutsideSegments => {
                "the integrity slot is not inside a read-only loaded segment".into()
            }
            other => format!("cannot hash the file: {other:?}"),
        },
    }
}
