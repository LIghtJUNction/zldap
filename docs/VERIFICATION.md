# Verification: zldap 0.1.0

**All 72 core tests passed under Miri with strict provenance.** The six local cross-compilation checks, documentation build, example, package-policy checks, release-helper tests, package build, and publication dry run also passed. GitHub CI completed all 16 jobs successfully for the frozen implementation commit.

## Scope and environment

Verification completed on **2026-11-10 at 12:33 Asia/Taipei (UTC+08:00)**. The implementation is commit [`68f0bfeb762e3f6e84bea323771772d6b4808e98`](https://github.com/LIghtJUNction/zldap/commit/68f0bfeb762e3f6e84bea323771772d6b4808e98). A final `git diff` confirmed that `src/` matched this commit. The local Miri run additionally included three lines extending the existing BER BOOLEAN test to run generic validation for all 256 octet values; the number of tests remained 72.

| Tool or platform | Observed version |
| --- | --- |
| Host | Linux 6.18.57, x86_64 |
| Stable Rust | 1.99.1, `58cf8f9c3` |
| Minimum supported Rust | 1.74.0, `79e9716c9` |
| Nightly Rust | 1.102.0-nightly, `ac8310ba6` (2026-11-09) |
| Miri | 0.1.0, `ac8310ba64` (2026-11-09) |
| Python | 3.12.14 |
| Actionlint | 1.7.7 |

## Memory-safety and protocol tests

```sh
MIRIFLAGS=-Zmiri-strict-provenance cargo +nightly miri test --locked --lib --tests
```

| Test suite | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| BER primitives, bounds, and reverse writer | 16 | 0 | 0 |
| Typed encoding and transactional buffers | 15 | 0 | 0 |
| Fast-path equivalence and resource accounting | 10 | 0 | 0 |
| LDAP protocol and security regressions | 31 | 0 | 0 |
| **Total** | **72** | **0** | **0** |

The [raw Miri log](verification/miri.txt) records every executed test and result. Coverage includes integer and length boundaries, truncation, deterministic random inputs, nested resource limits, unchanged buffers after encoding errors, 128 KiB binary values, absent versus empty credentials, the empty SASL-mechanism abort case, and LDAP BOOLEAN validation inside unknown extensions. Randomized workload sizes are reduced under Miri; the regression tests remain enabled.

Miri checks the executed paths and is not a proof over every possible byte sequence. The crate independently forbids unsafe Rust and has no allocator dependency. Its successful compilation on the declared targets enforces that source restriction.

## Portability and engineering checks

| Target | Rust 1.74.0 | Stable 1.99.1 |
| --- | --- | --- |
| `wasm32-unknown-unknown` | Passed | Passed |
| `thumbv7em-none-eabi` | Passed | Passed |
| `aarch64-unknown-linux-gnu` | Passed | Passed |

Each combination used:

```sh
cargo +TOOLCHAIN check --locked --lib --no-default-features --target TARGET
```

These checks compile the library for the target; they do not execute on physical embedded hardware. Native Linux, macOS, and Windows tests on both Rust versions are covered by the GitHub CI matrix below.

The following local commands also completed successfully:

```sh
RUSTDOCFLAGS='-D warnings' cargo +stable doc --locked --no-deps
cargo +stable run --locked --example search
python3 scripts/check_package.py
python3 -m unittest discover -s scripts -p 'test_*.py'
actionlint
```

The example decoded message 2, a 66-byte SearchRequest, and returned its `cn` and `mail` attribute selections. Package policy confirmed zero dependencies, no build script, unconditional `no_std`, forbidden unsafe code, MSRV 1.74, and 19 packaged files. All ten release-helper tests passed, including synchronized version bumps, retained comparison dependency pins, and rollback after a failed write. The Python helpers require Python 3.11 or later; CI selects 3.12.

## Package and remote CI

In a separate clean, detached checkout of the frozen commit, both commands passed without `--allow-dirty`:

```sh
cargo +stable package --locked
cargo +stable publish --dry-run --locked
```

Cargo packaged and compiled 19 files: 188.9 KiB before compression and 41.9 KiB compressed. The dry run explicitly aborted before upload.

[GitHub CI run 42755915828](https://github.com/LIghtJUNction/zldap/actions/runs/42755915828) completed successfully for the exact frozen commit. The public Actions API reported **16 completed, successful jobs**, observed at 12:32 Asia/Taipei. These include the six operating-system/toolchain combinations, six target/toolchain combinations, Miri, quality checks, differential tests, and package checks.

## Publication status and evidence limits

**Version 0.1.0 was not published during this verification.** Its public crates.io version lookup returned HTTP 404. The current execution environment did not provide an authenticated publication or workflow-dispatch route. The repository's secret configuration was not inspected; absence of a local token does not establish absence of the GitHub `CARGO_REGISTRY_TOKEN` secret.

Release workflow syntax and helper behavior passed their checks. A live publish, tag, and GitHub Release remain unverified until the authenticated Release workflow runs. Performance measurements and their comparison scope are reported separately under `comparison/`; none of these verification results establishes a speed advantage for a complete Kanidm server request.
