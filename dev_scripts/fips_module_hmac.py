#!/usr/bin/env python3
"""Independently recompute the FIPS module's per-crate source HMACs and the module HMAC.

Standard library only, and it shares no code with the Rust build script of `bouncycastle-fips`:
the point is that an operator or lab can check the published constant without trusting the
program that produced it.

Usage:
    dev_scripts/fips_module_hmac.py --lock CARGO_LOCK CRATE_DIR [CRATE_DIR ...]
    dev_scripts/fips_module_hmac.py --lock CARGO_LOCK --list FILE

CRATE_DIR is a boundary crate's directory (the one holding its Cargo.toml). `--list` reads one
directory per line (blank lines and `#` comments ignored; relative paths are relative to the
list file). The package name of each crate is read from its Cargo.toml.

CARGO_LOCK is the `Cargo.lock` of the build to check: the program's own, or for the module's own
workspace crypto/fips/Cargo.lock. The external crates are read from it, not from any list in
the Rust code. They are the normal dependencies of the boundary crates (from each crate's
Cargo.toml, since a workspace member's lock entry lists its dev-dependencies too) that are not
boundary crates, resolved to versions through the lock, and then everything in the lock's
`dependencies` lists of those, recursively. Each must come from crates.io with a checksum;
anything else (a path or git package outside the boundary, `[patch]`, another registry, two
versions of one crate) is refused. See crypto/fips/EXTERNAL_CRATES.md.

Definitions (from the FIPS module integrity issue, "Per-crate source HMAC" and "The table and the
module HMAC"):
  key        = b"Legion of the Bouncy Castle FIPS Rust API"
  per crate  = HMAC-SHA-512(key, concat over files of
                 relpath || 0x00 || len(bytes) as 8 bytes big-endian || bytes)
               files = every file under src/, plus Cargo.toml and build.rs, in bytewise order of
               their '/'-separated path relative to the crate directory (so Cargo.toml, build.rs,
               then src/...); bytes = file contents with every CRLF turned into LF.
  external   = HMAC-SHA-512(key, name || 0x00 || version || 0x00 || 32 checksum bytes)
               for each external crate, name, version and checksum as in CARGO_LOCK
  table      = (package name, 64-byte HMAC) entries, per crate and external, sorted bytewise
               by package name
  module     = HMAC-SHA-512(key, concat over table of name || 0x00 || 64 hash bytes)

Output (the format `bc-rust fips-info` prints for the table, module HMAC and external crates):
  <package name> <128 lowercase hex digits>     one line per table entry, in table order
  module-hmac <128 lowercase hex digits>
  external <name> <version> <64 lowercase hex digits>   one line per external crate, in order
"""
import hashlib
import hmac
import os
import re
import sys

KEY = b"Legion of the Bouncy Castle FIPS Rust API"
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"


def strip_toml_comment(line: str) -> str:
    """`line` up to the first `#` outside a string."""
    quote = None
    escaped = False
    for i, c in enumerate(line):
        if quote == '"' and escaped:
            escaped = False
        elif quote == '"' and c == "\\":
            escaped = True
        elif quote is not None:
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == "#":
            return line[:i]
    return line


def dotted_key(key: str):
    """The segments of a TOML dotted key, unquoted: `target.'cfg(unix)'.dependencies`."""
    return [seg.strip().strip("\"'") for seg in re.findall(r"""(?:"[^"]*"|'[^']*'|[^.])+""", key)]


def normal_dependencies(cargo_toml: bytes):
    """The names of the normal dependencies in a Cargo.toml, target-specific ones included:
    `[dependencies]` and `[target.<cfg>.dependencies]` entries, and `[dependencies.<name>]` and
    `[target.<cfg>.dependencies.<name>]` tables."""
    deps = set()
    in_deps = False
    depth = 0  # open brackets of a value that continues onto the next lines
    for raw in cargo_toml.decode("utf-8").splitlines():
        line = strip_toml_comment(raw).strip()
        plain = re.sub(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'', "", line)
        if depth > 0:
            depth += plain.count("[") + plain.count("{") - plain.count("]") - plain.count("}")
            continue
        if line.startswith("[["):
            in_deps = False
        elif line.startswith("["):
            seg = dotted_key(line.strip("[]"))
            in_deps = False
            if seg == ["dependencies"] or (len(seg) == 3 and seg[0] == "target"
                                           and seg[2] == "dependencies"):
                in_deps = True
            elif (len(seg) == 2 and seg[0] == "dependencies") or (
                    len(seg) == 4 and seg[0] == "target" and seg[2] == "dependencies"):
                deps.add(seg[-1])
        elif "=" in plain:
            key = line[:line.index("=")] if "=" in line else ""
            value = plain[plain.index("=") + 1:]
            depth = value.count("[") + value.count("{") - value.count("]") - value.count("}")
            if in_deps:
                deps.add(dotted_key(key)[0])
    return deps


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


def read_lock(path: str):
    """The [[package]] entries of a Cargo.lock (format version 3 or 4), as dicts with `name`,
    `version`, optional `source` and `checksum`, and `dependencies` (a list of strings). Not a TOML
    parser: it reads the subset Cargo writes, without tomllib (which needs Python 3.11)."""
    packages = []
    current = None
    in_deps = False
    lock_version = None
    with open(path, encoding="utf-8") as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            if in_deps:
                if line == "]":
                    in_deps = False
                elif line:
                    m = re.fullmatch(r'"([^"]*)",?', line)
                    if not m:
                        raise SystemExit(f"{path}:{n}: unexpected dependency line")
                    current["dependencies"].append(m.group(1))
                continue
            if not line or line.startswith("#"):
                continue
            if line.startswith("["):
                current = None
                if line == "[[package]]":
                    current = {"dependencies": []}
                    packages.append(current)
                continue
            m = re.fullmatch(r'([A-Za-z_-]+)\s*=\s*(.*)', line)
            if not m:
                raise SystemExit(f"{path}:{n}: unexpected line")
            key, value = m.group(1), m.group(2)
            if current is None:
                if key == "version":
                    lock_version = value
                continue
            if key == "dependencies":
                if value == "[":
                    in_deps = True
                elif value == "[]":
                    pass
                else:
                    raise SystemExit(f"{path}:{n}: unexpected dependencies value")
                continue
            m = re.fullmatch(r'"([^"]*)"', value)
            if not m:
                raise SystemExit(f"{path}:{n}: unexpected value")
            current[key] = m.group(1)
    if lock_version not in ("3", "4"):
        raise SystemExit(f"{path}: lock file format version {lock_version} is not 3 or 4")
    for p in packages:
        if "name" not in p or "version" not in p:
            raise SystemExit(f"{path}: a [[package]] has no name or version")
    return packages


def lookup(packages, dep: str, path: str):
    """The one package a `dependencies` entry ("name", "name version" or
    "name version (source)") names."""
    m = re.fullmatch(r'(\S+)(?: (\S+))?(?: \((.*)\))?', dep)
    if not m:
        raise SystemExit(f"{path}: cannot read the dependency {dep!r}")
    name, version, source = m.groups()
    found = [p for p in packages
             if p["name"] == name
             and (version is None or p["version"] == version)
             and (source is None or p.get("source") == source)]
    if len(found) != 1:
        raise SystemExit(f"{path}: the dependency {dep!r} names {len(found)} packages, not one")
    return found[0]


def external_crates(lock_path: str, boundary):
    """The (name, version, checksum bytes) of every crate outside the boundary in its closure:
    `boundary` maps each boundary crate's name to the names of its normal dependencies. Sorted
    bytewise by name."""
    packages = read_lock(lock_path)
    todo = []
    for name, normal in boundary.items():
        # From a path in a checkout, or from a registry for a program that takes the module from
        # one; the sources are pinned by the per-crate HMACs either way.
        found = [p for p in packages if p["name"] == name]
        if len(found) != 1:
            raise SystemExit(f"{lock_path}: {len(found)} packages named {name}, not one")
        # The lock's entry names the version of each dependency where there are several, but it
        # also lists a workspace member's dev- and build-dependencies, so the kind comes from the
        # manifest.
        for dep in found[0]["dependencies"]:
            target = lookup(packages, dep, lock_path)
            if target["name"] in normal and target["name"] not in boundary:
                todo.append((name, target))
        resolved = {lookup(packages, d, lock_path)["name"] for d in found[0]["dependencies"]}
        for dep in normal - resolved:
            raise SystemExit(f"{lock_path}: {name}'s dependency {dep} is not in the lock")
    seen = set()
    external = {}
    while todo:
        parent, target = todo.pop()
        name = target["name"]
        if name in boundary:
            raise SystemExit(
                f"{lock_path}: {parent}, outside the boundary, depends on the boundary crate "
                f"{name}")
        if target.get("source") != CRATES_IO:
            raise SystemExit(
                f"{lock_path}: {name} {target['version']}, a dependency of {parent}, is not a "
                f"crates.io package (source {target.get('source', 'a path')}): it is outside "
                f"the module boundary")
        checksum = target.get("checksum", "")
        if not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise SystemExit(f"{lock_path}: {name} {target['version']} has no checksum")
        pin = (target["version"], bytes.fromhex(checksum))
        if external.setdefault(name, pin) != pin:
            raise SystemExit(f"{lock_path}: two versions of {name} in the module boundary")
        key = (name, target["version"])
        if key in seen:
            continue
        seen.add(key)
        # A crates.io package's lock entry lists its normal and build dependencies; a build
        # dependency would be an extra row, which fails the comparison rather than hiding a crate.
        for dep in target["dependencies"]:
            todo.append((name, lookup(packages, dep, lock_path)))
    return [(n, *external[n]) for n in sorted(external, key=lambda n: n.encode("utf-8"))]


def external_hmac(name: str, version: str, checksum: bytes) -> bytes:
    return hmac.new(KEY, name.encode("utf-8") + b"\x00" + version.encode("utf-8") + b"\x00"
                    + checksum, hashlib.sha512).digest()


def main(argv):
    if len(argv) < 2 or argv[0] != "--lock":
        sys.stderr.write(__doc__)
        return 2
    lock = argv[1]
    argv = argv[2:]
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
    normal = {}
    for d in dirs:
        with open(os.path.join(d, "Cargo.toml"), "rb") as fh:
            manifest = fh.read()
        name = package_name(manifest)
        if name in table:
            raise SystemExit(f"duplicate package {name}")
        table[name] = crate_hmac(d)
        normal[name] = normal_dependencies(manifest)

    external = external_crates(lock, normal)
    for name, version, checksum in external:
        if name in table:
            raise SystemExit(f"{name} is both a boundary crate and an external crate")
        table[name] = external_hmac(name, version, checksum)

    module = hmac.new(KEY, digestmod=hashlib.sha512)
    for name in sorted(table, key=lambda n: n.encode("utf-8")):
        print(f"{name} {table[name].hex()}")
        module.update(name.encode("utf-8") + b"\x00" + table[name])
    print(f"module-hmac {module.hexdigest()}")
    for name, version, checksum in external:
        print(f"external {name} {version} {checksum.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
