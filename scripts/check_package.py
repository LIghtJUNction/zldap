#!/usr/bin/env python3
"""Check the actual Cargo metadata and archive against the core's constraints."""

import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib


def run(*args):
    return subprocess.check_output(args, text=True)


def main():
    manifest = tomllib.loads(Path("Cargo.toml").read_text())
    package = manifest["package"]
    metadata = json.loads(run("cargo", "metadata", "--no-deps", "--locked", "--format-version", "1"))
    packages = metadata["packages"]
    if len(packages) != 1 or packages[0]["name"] != "zldap":
        sys.exit("the published workspace must contain only zldap")
    if packages[0]["dependencies"]:
        sys.exit("the core has a normal, dev, build, optional, or target-specific dependency")
    if Path("build.rs").exists() or any("custom-build" in item["kind"] for item in packages[0]["targets"]):
        sys.exit("build scripts are forbidden")
    if package.get("rust-version") != "1.74":
        sys.exit("update the MSRV matrix and policy together")
    source = Path("src/lib.rs").read_text()
    if not re.search(r"#!\s*\[\s*no_std\s*\]", source):
        sys.exit("zldap must be unconditionally no_std")
    if not re.search(r"#!\s*\[\s*forbid\s*\(\s*unsafe_code\s*\)\s*\]", source):
        sys.exit("the safe implementation must forbid unsafe_code")
    if tomllib.loads(Path("Cargo.lock").read_text())["version"] != 3:
        sys.exit("Cargo.lock must remain compatible with Cargo 1.74 (format 3)")
    # Listing is useful before a commit; the actual packaging/release gates
    # separately require a clean checkout and never pass --allow-dirty.
    contents = run("cargo", "package", "--list", "--locked", "--allow-dirty").splitlines()
    if any(name.startswith(("comparison/", "target/", ".github/")) for name in contents):
        sys.exit("comparison, target, and workflow files must stay out of the published crate")
    print(f"zldap {package['version']}: zero dependencies, no build script, no_std, no unsafe, MSRV 1.74; {len(contents)} packaged files")


if __name__ == "__main__":
    main()
