//! Sets `bc_approved_only`, which the `cli/src` modules that this crate compiles in check to
//! leave out the algorithms outside the module boundary (SM3, Poly1305, ARIA, Camellia, SM4).

fn main() {
    println!("cargo:rustc-check-cfg=cfg(bc_approved_only)");
    println!("cargo:rustc-cfg=bc_approved_only");
}
