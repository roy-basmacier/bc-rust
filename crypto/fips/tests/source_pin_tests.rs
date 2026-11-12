//! The build script's logic (`bouncycastle-fips-build`), fed its inputs directly: the per-crate
//! and module HMACs against values from the independent `dev_scripts/fips_module_hmac.py`, their
//! independence from input order, what a one-byte edit changes, the closure check, the
//! `fips-validated` gate and the manifest reader.
//!
//! In a test build the helper's SHA-512 is the gated one (`bouncycastle-sha2/fips` unifies), so
//! every test that hashes runs SHA-2's self-test first. Not the whole power-on, which fails under
//! the `integrity` feature.

use bouncycastle_fips_build::{
    BOUNDARY, BoundaryCrate, HMAC_LEN, Manifest, SourceFile, Toolchain, build_table, check_closure,
    check_expected, crate_hmac, crlf_to_lf, dep_var_links, hex, module_hmac, parse_manifest,
    render,
};

fn power_on() {
    #[cfg(feature = "sha2")]
    bouncycastle_sha2::self_test().expect("SHA-2 self-tests pass");
}

fn file(path: &str, bytes: &[u8]) -> SourceFile {
    SourceFile { path: path.to_string(), bytes: bytes.to_vec() }
}

fn unhex(s: &str) -> [u8; HMAC_LEN] {
    let mut out = [0u8; HMAC_LEN];
    assert_eq!(s.len(), 2 * HMAC_LEN);
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// Fixture crate `a`: CRLF and LF files, a nested directory, and `src/B.rs`, which sorts before
/// `src/lib.rs` bytewise (upper case first) but not case-insensitively.
fn kat_crate_a() -> Vec<SourceFile> {
    vec![
        file("Cargo.toml", b"[package]\nname = \"bouncycastle-kat-a\"\n"),
        file("build.rs", b"fn main() {}\r\n"),
        file("src/lib.rs", b"//! A.\r\n//! Two lines.\r\n"),
        file("src/z/mod.rs", b"pub fn z() {}\n"),
        file("src/B.rs", b"B"),
    ]
}

/// Fixture crate `b`: an empty file, and a lone CR before a CRLF.
fn kat_crate_b() -> Vec<SourceFile> {
    vec![
        file("Cargo.toml", b"[package]\nname = \"bouncycastle-kat-b\"\n"),
        file("build.rs", b""),
        file("src/lib.rs", b"\r\r\n"),
    ]
}

// Computed by dev_scripts/fips_module_hmac.py over the fixture crates above, written to disk.
const KAT_A: &str = "166c390b5412d9426e4e369fd2aafc4c1c79bdb0aa6db0fd6cbd884310bc2181\
                     7fa37ce803eea409d8965d11179d884a0cda9cd3d31dd7c68b4cc72e5ef2044c";
const KAT_B: &str = "d5ca2cfc8deaa789fb3496b83ec53696bea8d4772e6ee47f7a76368140cafa77\
                     6c98b97594f60b61244ed7655bfda7fb4322cc637e195245b81b63e9968995b4";
const KAT_MODULE: &str = "9f8fc3c1a342d2dd9072567d898877bbc2de6ea03db36d065ff5aef0dd8e945f\
                          f6904448589f8fd491bab743ac5d5f1058108c95d766529518a013670eaaaf68";

#[test]
fn hmacs_match_the_independent_script() {
    power_on();
    let a = crate_hmac(&kat_crate_a());
    let b = crate_hmac(&kat_crate_b());
    assert_eq!(a, unhex(KAT_A));
    assert_eq!(b, unhex(KAT_B));
    let table = vec![("bouncycastle-kat-a".to_string(), a), ("bouncycastle-kat-b".to_string(), b)];
    assert_eq!(module_hmac(&table), unhex(KAT_MODULE));
    assert_eq!(hex(&module_hmac(&table)), KAT_MODULE.replace(char::is_whitespace, ""));
}

#[test]
fn crlf_becomes_lf_and_nothing_else_changes() {
    assert_eq!(crlf_to_lf(b"a\r\nb\rc\n\r\n\r"), b"a\nb\rc\n\n\r");
    assert_eq!(crlf_to_lf(b"\r\r\n"), b"\r\n");
    assert_eq!(crlf_to_lf(b""), b"");
    power_on();
    let lf: Vec<SourceFile> = kat_crate_a()
        .into_iter()
        .map(|f| SourceFile { bytes: crlf_to_lf(&f.bytes), ..f })
        .collect();
    assert_eq!(crate_hmac(&lf), unhex(KAT_A));
}

/// The boundary as fake crates, one file each, in table order.
fn boundary() -> Vec<BoundaryCrate> {
    BOUNDARY
        .iter()
        .map(|name| BoundaryCrate {
            dep_links: dep_var_links(&name.replace('-', "_")),
            manifest: Manifest {
                name: name.to_string(),
                links: Some(name.replace('-', "_")),
                normal_deps: vec!["bouncycastle-core".to_string(), "getrandom".to_string()],
            },
            files: vec![
                file("Cargo.toml", name.as_bytes()),
                file("build.rs", b"fn main() {}\n"),
                file("src/lib.rs", b"//! lib\n"),
                file("src/a.rs", b"//! a\n"),
            ],
        })
        .collect()
}

/// A fixed shuffle of `v`, different from reversal, for `seed` > 0.
fn shuffled<T: Clone>(v: &[T], seed: usize) -> Vec<T> {
    let mut out = v.to_vec();
    let n = out.len();
    for i in (1..n).rev() {
        out.swap(i, (i * 7 + seed * 13) % (i + 1));
    }
    out
}

#[test]
fn shuffled_inputs_give_the_same_table_and_module_hmac() {
    power_on();
    let crates = boundary();
    let table = build_table(&crates).unwrap();
    let names: Vec<&str> = table.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, BOUNDARY, "the table is in BOUNDARY's order");
    let mut sorted = names.clone();
    sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    assert_eq!(names, sorted, "BOUNDARY is bytewise sorted");
    let module = module_hmac(&table);

    for seed in 1..6 {
        let mut input = shuffled(&crates, seed);
        assert_ne!(
            input.iter().map(|c| c.manifest.name.clone()).collect::<Vec<_>>(),
            BOUNDARY,
            "seed {seed} shuffles"
        );
        for c in &mut input {
            c.files = shuffled(&c.files, seed);
        }
        let t = build_table(&input).unwrap();
        assert_eq!(t, table, "seed {seed}");
        assert_eq!(module_hmac(&t), module, "seed {seed}");
    }
    let mut reversed = crates.clone();
    reversed.reverse();
    for c in &mut reversed {
        c.files.reverse();
    }
    assert_eq!(build_table(&reversed).unwrap(), table);
}

#[test]
fn table_order_is_part_of_the_module_hmac() {
    power_on();
    let table = build_table(&boundary()).unwrap();
    let mut swapped = table.clone();
    swapped.swap(0, 1);
    assert_ne!(module_hmac(&swapped), module_hmac(&table));
}

#[test]
fn one_byte_edit_changes_only_its_entry_and_the_module_hmac() {
    power_on();
    let crates = boundary();
    let table = build_table(&crates).unwrap();
    let module = module_hmac(&table);
    for (c, f) in [(0, 0), (4, 1), (11, 3)] {
        let mut edited = crates.clone();
        edited[c].files[f].bytes[0] ^= 1;
        let t = build_table(&edited).unwrap();
        for (i, (row, original)) in t.iter().zip(&table).enumerate() {
            assert_eq!(row.0, original.0);
            assert_eq!(row.1 == original.1, i != c, "crate {i} after editing crate {c}");
        }
        assert_ne!(module_hmac(&t), module);
    }
    // A file's path and its length are hashed too, not only its bytes.
    let mut renamed = crates.clone();
    renamed[2].files[3].path = "src/b.rs".to_string();
    assert_ne!(build_table(&renamed).unwrap()[2].1, table[2].1);
    let mut moved = crates.clone();
    moved[2].files[2].bytes = b"//! lib\n//! a\n".to_vec();
    moved[2].files[3].bytes = Vec::new();
    assert_ne!(build_table(&moved).unwrap()[2].1, table[2].1);
    let mut added = crates;
    added[5].files.push(file("src/new.rs", b""));
    assert_ne!(build_table(&added).unwrap()[5].1, table[5].1);
}

fn closure_errors(crates: &[BoundaryCrate]) -> String {
    let e = check_closure(crates).unwrap_err();
    assert_eq!(build_table(crates).unwrap_err(), e);
    e
}

#[test]
fn closure_check_accepts_the_boundary() {
    assert_eq!(check_closure(&boundary()), Ok(()));
}

#[test]
fn an_unlisted_dependency_fails() {
    let mut crates = boundary();
    crates[4].manifest.normal_deps.push("bouncycastle-hex".to_string());
    let e = closure_errors(&crates);
    assert!(e.contains("`bouncycastle-ec` depends on `bouncycastle-hex`"), "{e}");
    // An external crate other than getrandom is as unlisted as an internal one.
    let mut crates = boundary();
    crates[8].manifest.normal_deps.push("libc".to_string());
    assert!(closure_errors(&crates).contains("depends on `libc`"));
}

#[test]
fn a_missing_crate_fails() {
    // What a boundary crate without a `links` key looks like here: Cargo sets no DEP_ variable.
    let mut crates = boundary();
    crates.remove(6);
    let e = closure_errors(&crates);
    assert!(
        e.contains(
            "`bouncycastle-hkdf` is in the module boundary but no DEP_BOUNCYCASTLE_HKDF_SRC_DIR"
        ),
        "{e}"
    );
}

#[test]
fn an_unlisted_crate_fails() {
    let mut crates = boundary();
    let mut extra = crates[0].clone();
    extra.manifest.name = "bouncycastle-hex".to_string();
    extra.manifest.links = Some("bouncycastle_hex".to_string());
    extra.dep_links = "BOUNCYCASTLE_HEX".to_string();
    crates.push(extra);
    assert!(closure_errors(&crates).contains(
        "`bouncycastle-hex` (DEP_BOUNCYCASTLE_HEX_SRC_DIR) is not in the module boundary"
    ));
}

#[test]
fn a_crate_found_twice_fails() {
    let mut crates = boundary();
    crates.push(crates[3].clone());
    assert!(closure_errors(&crates).contains("`bouncycastle-core` was found twice"));
}

#[test]
fn a_wrong_or_missing_links_key_fails() {
    let mut crates = boundary();
    crates[1].manifest.links = None;
    assert!(
        closure_errors(&crates)
            .contains("`bouncycastle-ascon` must have `links = \"bouncycastle_ascon\"`")
    );
    let mut crates = boundary();
    crates[1].manifest.links = Some("bouncycastle_ascon2".to_string());
    assert!(closure_errors(&crates).contains("must have `links"));
    let mut crates = boundary();
    crates[1].dep_links = "BOUNCYCASTLE_ASCON2".to_string();
    assert!(
        closure_errors(&crates)
            .contains("`bouncycastle-ascon` was named by DEP_BOUNCYCASTLE_ASCON2_SRC_DIR")
    );
}

#[test]
fn every_problem_is_reported() {
    let mut crates = boundary();
    crates[0].manifest.normal_deps.push("x".to_string());
    crates[0].manifest.normal_deps.push("y".to_string());
    crates.remove(1);
    let e = closure_errors(&crates);
    assert_eq!(e.lines().count(), 3, "{e}");
}

#[test]
fn dep_var_names_follow_cargo() {
    assert_eq!(dep_var_links("bouncycastle_aes"), "BOUNCYCASTLE_AES");
    assert_eq!(dep_var_links("a-b_c"), "A_B_C");
}

#[test]
fn the_validated_gate() {
    let module = [7u8; HMAC_LEN];
    // Off: nothing is compared.
    assert_eq!(check_expected(&module, None), Ok(()));
    // On: the published constant must match.
    assert_eq!(check_expected(&module, Some(&module)), Ok(()));
    let mut other = module;
    other[HMAC_LEN - 1] ^= 1;
    let e = check_expected(&module, Some(&other)).unwrap_err();
    assert!(e.contains(&hex(&module)) && e.contains(&hex(&other)), "{e}");
    assert!(e.contains("0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,"), "{e}");
}

#[test]
fn the_generated_file() {
    power_on();
    let table = build_table(&boundary()).unwrap();
    let toolchain = Toolchain {
        rustc: "rustc 1.0.0 (abc 2015-05-15)".to_string(),
        host: "h".to_string(),
        target: "t".to_string(),
        opt_level: "3".to_string(),
        profile: "release".to_string(),
        features: vec!["aes".to_string(), "fips-validated".to_string()],
    };
    let s = render(&table, &toolchain);
    assert!(
        s.contains(&format!("// Module HMAC, derived from TABLE: {}\n", hex(&module_hmac(&table))))
    );
    assert!(s.contains("pub(crate) const TABLE: [ModuleTableEntry; 12] = [\n"));
    assert!(s.contains("        package: \"bouncycastle-aes\",\n        hmac: [\n            0x"));
    let first = &table[0].1;
    let line = first[..8].iter().map(|b| format!("0x{b:02x},")).collect::<Vec<_>>().join(" ");
    assert!(s.contains(&format!("            {line}\n")), "{s}");
    assert!(s.contains(
        "pub(crate) const TOOLCHAIN: ToolchainRecord = ToolchainRecord {\n    rustc: \"rustc 1.0.0 \
         (abc 2015-05-15)\",\n    host: \"h\",\n    target: \"t\",\n    opt_level: \"3\",\n    \
         profile: \"release\",\n    features: &[\"aes\", \"fips-validated\"],\n};\n"
    ), "{s}");
    assert_eq!(s.matches("ModuleTableEntry {").count(), 12);
    assert_eq!(s.matches("0x").count(), 12 * HMAC_LEN);
}

#[test]
fn manifests_in_the_workspace_form() {
    let m = parse_manifest(
        r#"
[package]
name = "bouncycastle-rng"   # a comment
links = "bouncycastle_rng"
version.workspace = true

[features]
fips = ["bouncycastle-core/fips"]

[dependencies]
bouncycastle-core.workspace = true
"bouncycastle-sha2" = { workspace = true, features = [
    "a", # package = "not a rename, a comment"
] }
getrandom = "0.4.0-rc.1"

[target.'cfg(target_os = "linux")'.dependencies]
bouncycastle-utils = { path = "../utils", features = ["x = y"] }

[dev-dependencies]
bouncycastle-hex.workspace = true

[build-dependencies]
cc = "1"

[[bench]]
name = "not-a-package"
"#,
    )
    .unwrap();
    assert_eq!(
        m,
        Manifest {
            name: "bouncycastle-rng".to_string(),
            links: Some("bouncycastle_rng".to_string()),
            normal_deps: [
                "bouncycastle-core", "bouncycastle-sha2", "getrandom", "bouncycastle-utils"
            ]
            .map(String::from)
            .to_vec(),
        }
    );
}

#[test]
fn manifests_in_the_packaged_form() {
    // What `cargo package` writes: one table per dependency.
    let m = parse_manifest(
        "[package]\nedition = \"2024\"\nname = \"bouncycastle-aes\"\nlinks = 'bouncycastle_aes'\n\n\
         [dependencies.bouncycastle-cipher]\nversion = \"0.1.4\"\n\n\
         [target.\"cfg(unix)\".dependencies.bouncycastle-core]\nversion = \"0.1.4\"\n\n\
         [dev-dependencies.bouncycastle-hex]\nversion = \"0.1.4\"\n",
    )
    .unwrap();
    assert_eq!(m.name, "bouncycastle-aes");
    assert_eq!(m.links.as_deref(), Some("bouncycastle_aes"));
    assert_eq!(m.normal_deps, ["bouncycastle-cipher", "bouncycastle-core"]);
}

#[test]
fn manifests_it_cannot_read_are_refused() {
    assert_eq!(parse_manifest("[package]\nlinks = \"x\"\n").unwrap_err(), "no [package] name");
    assert_eq!(parse_manifest("[lib]\nname = \"x\"\n").unwrap_err(), "no [package] name");
    let rename = "renamed dependencies are not supported";
    for text in [
        "[package]\nname = \"x\"\n[dependencies]\ny = { package = \"z\", path = \"..\" }\n",
        "[package]\nname = \"x\"\n[dependencies]\ny.package = \"z\"\n",
        "[package]\nname = \"x\"\n[dependencies.y]\npackage = \"z\"\n",
        "[package]\nname = \"x\"\n[dependencies]\ny = { features = [\n\"a\"], package = \"z\" }\n",
    ] {
        let e = parse_manifest(text).unwrap_err();
        assert!(e.ends_with(rename), "{text}: {e}");
    }
    assert_eq!(
        parse_manifest("[package]\nname = \"x\"\ndescription = \"\"\"\nmulti\n\"\"\"\n")
            .unwrap_err(),
        "line 3: multi-line strings are not supported"
    );
    assert_eq!(
        parse_manifest("[package\nname = \"x\"\n").unwrap_err(),
        "line 1: unterminated table header"
    );
    // `package` as an ordinary word, or in a string, is no rename.
    let m = parse_manifest(
        "[package]\nname = \"x\"\n[dependencies]\ny = { path = \"../package\", features = [\"package = 1\"] }\n",
    )
    .unwrap();
    assert_eq!(m.normal_deps, ["y"]);
}

#[test]
fn strings_hide_syntax() {
    // A `#` in a string is no comment, also after an escaped quote.
    assert_eq!(parse_manifest("[package]\nname = \"x#y\"\n").unwrap().name, "x#y");
    assert_eq!(parse_manifest("[package]\nname = 'x#y'\n").unwrap().name, "x#y");
    assert_eq!(parse_manifest("[package]\nname = \"a\\\"#b\"\n").unwrap().name, "a\\\"#b");
    // Nor is a `package = ` key in a string, whatever surrounds it.
    for value in [r#"["x, package = 1"]"#, r#"["a\", package = 1"]"#, r#"['x, package = 1']"#] {
        let text = format!("[package]\nname = \"x\"\n[dependencies]\ny = {{ features = {value} }}\n");
        assert_eq!(parse_manifest(&text).unwrap().normal_deps, ["y"], "{value}");
    }
}

#[test]
fn a_multi_line_value_is_read_to_its_end() {
    // The array closes on a line that also has an `=`, which must not be read as a new key.
    let m = parse_manifest(
        "[package]\nname = \"x\"\n[dependencies]\ny = { features = [\n\"a\",\n], path = \"p\" }\nz = \"1\"\n",
    )
    .unwrap();
    assert_eq!(m.normal_deps, ["y", "z"]);
}
