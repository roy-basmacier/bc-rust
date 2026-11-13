//! The test program for `tests/approved_mode_tests.rs`: powers on bouncycastle-fips and prints,
//! one item per line, the module table, the module HMAC and every field of the toolchain record.
//! The lines that come from cargo features start with `features` or `crate-features`.

use std::process::ExitCode;

use bouncycastle_fips::{module_hmac, module_table, power_on_self_tests, toolchain};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> ExitCode {
    if let Err(e) = power_on_self_tests() {
        eprintln!("power-on failed: {e:?}");
        return ExitCode::FAILURE;
    }
    for entry in module_table() {
        println!("table {} {}", entry.package, hex(&entry.hmac));
    }
    match module_hmac() {
        Ok(hmac) => println!("module-hmac {}", hex(&hmac)),
        Err(e) => {
            eprintln!("module HMAC: {e:?}");
            return ExitCode::FAILURE;
        }
    }
    let t = toolchain();
    println!("rustc {}", t.rustc);
    println!("host {}", t.host);
    println!("target {}", t.target);
    println!("opt-level {}", t.opt_level);
    println!("profile {}", t.profile);
    println!("features {}", t.features.join(","));
    for c in t.crate_features {
        println!("crate-features {} {}", c.package, c.features.join(","));
    }
    ExitCode::SUCCESS
}
