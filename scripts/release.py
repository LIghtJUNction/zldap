#!/usr/bin/env python3
"""Release version and registry checks; only the workflow receives credentials."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
import tomllib
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z")


def next_version(version, kind):
    match = SEMVER.fullmatch(version)
    if not match:
        raise ValueError("release versions must be three nonnegative integers without leading zeros")
    major, minor, patch = map(int, match.groups())
    if kind == "patch":
        patch += 1
    elif kind == "minor":
        minor, patch = minor + 1, 0
    elif kind == "major":
        major, minor, patch = major + 1, 0, 0
    elif kind != "current":
        raise ValueError("unknown bump; choose current, patch, minor, or major")
    return f"{major}.{minor}.{patch}"


def replace_manifest_version(text, old, new):
    """Change only [package].version; keep formatting and all other versions."""
    start = re.search(r"(?m)^\[package\]\s*$", text)
    if not start:
        raise ValueError("missing [package] table")
    rest = text[start.end():]
    end = re.search(r"(?m)^\[", rest)
    stop = start.end() + (end.start() if end else len(rest))
    section = text[start.end():stop]
    pattern = re.compile(r'(?m)^(version\s*=\s*)"' + re.escape(old) + r'"(\s*(?:#.*)?)$')
    updated, count = pattern.subn(lambda m: f'{m[1]}"{new}"{m[2]}', section)
    if count != 1:
        raise ValueError("expected one explicit [package].version")
    return text[:start.end()] + updated + text[stop:]


def replace_lock_version(text, name, old, new):
    data = tomllib.loads(text)
    if data.get("version") != 3:
        raise ValueError("release lockfile must use Cargo 1.74-compatible format 3")
    packages = data.get("package", [])
    if len(packages) != 1 or packages[0].get("name") != name or packages[0].get("version") != old:
        raise ValueError("zero-dependency release lockfile must contain only the current zldap version")
    pattern = re.compile(r'(?m)^version\s*=\s*"' + re.escape(old) + r'"\s*$')
    updated, count = pattern.subn(f'version = "{new}"', text)
    if count != 1:
        raise ValueError("cannot locate the root package lockfile version")
    return updated


def replace_comparison_lock_version(text, name, old, new):
    """Update only the local core package; retain every third-party pin byte for byte."""
    data = tomllib.loads(text)
    if data.get("version") not in (3, 4):
        raise ValueError("unsupported comparison lockfile format")
    packages = data.get("package", [])
    candidates = [(index, item) for index, item in enumerate(packages) if item.get("name") == name]
    if len(candidates) != 1:
        raise ValueError("comparison lockfile must contain exactly one zldap package")
    index, package = candidates[0]
    if package.get("version") != old or "source" in package or "checksum" in package:
        raise ValueError("comparison zldap entry must be the current local path dependency")
    sections = list(re.finditer(r"(?m)^\[\[package\]\][ \t]*$", text))
    if len(sections) != len(packages):
        raise ValueError("cannot locate comparison lockfile package sections")
    start = sections[index].end()
    end = sections[index + 1].start() if index + 1 < len(sections) else len(text)
    pattern = re.compile(r'(?m)^(version[ \t]*=[ \t]*)"' + re.escape(old) + r'"([ \t]*(?:#.*)?)$')
    updated, count = pattern.subn(lambda match: f'{match[1]}"{new}"{match[2]}', text[start:end])
    if count != 1:
        raise ValueError("cannot locate the comparison path dependency version")
    return text[:start] + updated + text[end:]


def output(name, value):
    print(f"{name}={value}")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as destination:
            destination.write(f"{name}={value}\n")


def package_info():
    package = tomllib.loads(Path("Cargo.toml").read_text())["package"]
    if package["name"] != "zldap":
        raise ValueError("this release script is scoped to zldap")
    next_version(package["version"], "current")
    return package["name"], package["version"]


def bump(kind):
    name, old = package_info()
    new = next_version(old, kind)
    # Validate all three files before changing any of them. The workflow commits
    # the synchronized set together; third-party comparison pins never resolve anew.
    original = {
        Path("Cargo.toml"): Path("Cargo.toml").read_text(),
        Path("Cargo.lock"): Path("Cargo.lock").read_text(),
        Path("comparison/Cargo.lock"): Path("comparison/Cargo.lock").read_text(),
    }
    updated = {
        Path("Cargo.toml"): replace_manifest_version(original[Path("Cargo.toml")], old, new),
        Path("Cargo.lock"): replace_lock_version(original[Path("Cargo.lock")], name, old, new),
        Path("comparison/Cargo.lock"): replace_comparison_lock_version(original[Path("comparison/Cargo.lock")], name, old, new),
    }
    if new != old:
        try:
            for path, contents in updated.items():
                path.write_text(contents)
        except OSError:
            # A failed write must not leave a partially bumped checkout.
            for path, contents in original.items():
                path.write_text(contents)
            raise
    output("version", new)
    output("tag", f"v{new}")


def registry_version(name, version):
    """404 is vacancy; all network, rate-limit, and server failures fail closed."""
    url = f"https://crates.io/api/v1/crates/{name}/{version}"
    request = Request(url, headers={"User-Agent": "zldap-release (https://github.com/LIghtJUNction/zldap)"})
    try:
        with urlopen(request, timeout=20) as response:
            data = json.load(response)
    except HTTPError as error:
        if error.code == 404:
            return None
        raise RuntimeError(f"registry check failed with HTTP {error.code}; publication is blocked") from None
    except (URLError, TimeoutError, json.JSONDecodeError):
        raise RuntimeError("registry response could not be verified; publication is blocked") from None
    published = data.get("version", {})
    if published.get("num") != version or published.get("crate") != name:
        raise RuntimeError("registry returned an unexpected package/version")
    checksum = published.get("checksum")
    if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise RuntimeError("registry returned no verifiable SHA-256 checksum")
    return checksum


def artifact_checksum(path, name, version):
    path = Path(path)
    if path.name != f"{name}-{version}.crate":
        raise ValueError("artifact filename must match the release version")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_registry(path, resume):
    name, version = package_info()
    expected = artifact_checksum(path, name, version)
    published = registry_version(name, version)
    if published is not None:
        if not resume:
            raise RuntimeError("version is already occupied; choose a bump, or explicitly resume this exact release")
        if expected != published:
            raise RuntimeError("occupied version has different archive bytes; refusing to tag or release it")
    output("published", "true" if published else "false")
    output("sha256", expected)


def confirm(path):
    name, version = package_info()
    expected = artifact_checksum(path, name, version)
    # Registry propagation may lag a successful cargo publish.
    for attempt in range(12):
        published = registry_version(name, version)
        if published is not None:
            if published != expected:
                raise RuntimeError("published archive checksum differs from the validated artifact")
            Path(path).with_name("SHA256SUMS").write_text(f"{expected}  {Path(path).name}\n")
            print("published registry archive matches the validated release artifact")
            return
        if attempt < 11:
            time.sleep(5)
    raise RuntimeError("registry version is not visible yet; dispatch current + resume after propagation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("bump").add_argument("kind", choices=["current", "patch", "minor", "major"])
    registry = commands.add_parser("registry")
    registry.add_argument("--artifact", required=True)
    registry.add_argument("--resume", choices=["true", "false"], default="false")
    commands.add_parser("confirm").add_argument("--artifact", required=True)
    args = parser.parse_args()
    try:
        if args.command == "bump":
            bump(args.kind)
        elif args.command == "registry":
            check_registry(args.artifact, args.resume == "true")
        else:
            confirm(args.artifact)
    except (OSError, ValueError, RuntimeError) as error:
        sys.exit(str(error))


if __name__ == "__main__":
    main()
