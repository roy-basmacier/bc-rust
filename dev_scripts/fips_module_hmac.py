#!/usr/bin/env python3
"""Independently recompute the FIPS module's per-crate source HMACs and the module HMAC.

Standard library only, and it shares no code with the Rust build script of `bouncycastle-fips`:
the point is that an operator or lab can check the published constant without trusting the
program that produced it.

Usage:
    dev_scripts/fips_module_hmac.py CRATE_DIR [CRATE_DIR ...]
    dev_scripts/fips_module_hmac.py --list FILE

CRATE_DIR is a boundary crate's directory (the one holding its Cargo.toml). `--list` reads one
directory per line (blank lines and `#` comments ignored; relative paths are relative to the
list file). The package name of each crate is read from its Cargo.toml.

Definitions (from the FIPS module integrity issue, "Per-crate source HMAC" and "The table and the
module HMAC"):
  key        = b"Legion of the Bouncy Castle FIPS Rust API"
  per crate  = HMAC-SHA-512(key, concat over files of
                 relpath || 0x00 || len(bytes) as 8 bytes big-endian || bytes)
               files = every file under src/, plus Cargo.toml and build.rs, in bytewise order of
               their '/'-separated path relative to the crate directory (so Cargo.toml, build.rs,
               then src/...); bytes = file contents with every CRLF turned into LF.
  table      = (package name, 64-byte HMAC) entries sorted bytewise by package name
  module     = HMAC-SHA-512(key, concat over table of name || 0x00 || 64 hash bytes)

Output (the format `bc-rust fips-info` is to print for the table and module HMAC):
  <package name> <128 lowercase hex digits>     one line per table entry, in table order
  module-hmac <128 lowercase hex digits>
"""
import hashlib
import hmac
import os
import re
import sys

KEY = b"Legion of the Bouncy Castle FIPS Rust API"


def package_name(cargo_toml: bytes) -> str:
    # Read the [package] table's `name` without a TOML library (tomllib needs Python 3.11).
    in_package = False
    for line in cargo_toml.decode("utf-8").splitlines():
        s = line.strip()
        if s.startswith("["):
            in_package = s == "[package]"
            continue
        if in_package:
            m = re.fullmatch(r'name\s*=\s*"([^"]+)"\s*(#.*)?', s)
            if m:
                return m.group(1)
    raise SystemExit("no [package] name in Cargo.toml")


def source_files(crate_dir: str):
    """Relative '/'-separated paths of the hashed files, sorted bytewise."""
    paths = ["Cargo.toml", "build.rs"]
    for root, _dirs, files in os.walk(os.path.join(crate_dir, "src")):
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), crate_dir)
            paths.append(rel.replace(os.sep, "/"))
    for p in paths:
        if not os.path.isfile(os.path.join(crate_dir, p)):
            raise SystemExit(f"{crate_dir}: missing {p}")
    return sorted(paths, key=lambda p: p.encode("utf-8"))


def crate_hmac(crate_dir: str) -> bytes:
    mac = hmac.new(KEY, digestmod=hashlib.sha512)
    for rel in source_files(crate_dir):
        with open(os.path.join(crate_dir, rel), "rb") as fh:
            data = fh.read().replace(b"\r\n", b"\n")
        mac.update(rel.encode("utf-8") + b"\x00" + len(data).to_bytes(8, "big") + data)
    return mac.digest()


def main(argv):
    if len(argv) >= 2 and argv[0] == "--list":
        base = os.path.dirname(os.path.abspath(argv[1]))
        dirs = []
        with open(argv[1], encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    dirs.append(os.path.join(base, line))
    else:
        dirs = argv
    if not dirs or any(d.startswith("-") for d in dirs):
        sys.stderr.write(__doc__)
        return 2

    table = {}
    for d in dirs:
        with open(os.path.join(d, "Cargo.toml"), "rb") as fh:
            name = package_name(fh.read())
        if name in table:
            raise SystemExit(f"duplicate package {name}")
        table[name] = crate_hmac(d)

    module = hmac.new(KEY, digestmod=hashlib.sha512)
    for name in sorted(table, key=lambda n: n.encode("utf-8")):
        print(f"{name} {table[name].hex()}")
        module.update(name.encode("utf-8") + b"\x00" + table[name])
    print(f"module-hmac {module.hexdigest()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
