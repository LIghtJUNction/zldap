# Protocol comparison

This is a separate, unpublished Cargo workspace. Its dependencies and allocation
instrumentation are excluded from the `zldap` crate and its package. The pinned
reference is Kanidm's [`ldap3_proto = 0.9.0`](https://docs.rs/ldap3_proto/0.9.0/),
using [`ldap3_lber = 0.9.0`](https://docs.rs/ldap3_lber/0.9.0/).
Both published packages identify source commit
[`f1ec51111756a6ea941a0685827283bb55bb94ac`](https://github.com/kanidm/ldap3/tree/f1ec51111756a6ea941a0685827283bb55bb94ac).
All transitive versions and registry checksums are fixed in `Cargo.lock`.

## Reproduce

Use a current stable Rust toolchain for the comparison workspace; the reference
crate itself requires Rust 1.85 or newer. The production crate's MSRV is separate.

```sh
cargo test --manifest-path comparison/Cargo.toml --locked
python3 comparison/run.py --output comparison/results/local --iterations 50000 --samples 7
```

The script runs differential tests, builds the timing binary with the system
allocator, runs the benchmark, then builds a separate allocator-instrumented
binary. It merges timing and allocation results by scenario and phase. It fails
if measured source files change between builds, if zldap allocates, or if the
allocator fails to observe the reference implementation's allocations. On Linux,
it pins the benchmark to the first permitted CPU; `--cpu N` selects another.

Each output directory contains:

- `results.csv`: merged latency, throughput, cost per byte, allocation calls, and
  peak live heap bytes.
- `timing.csv` and `allocations.csv`: separate raw observations. Instrumented
  builds report no timing, and normal builds report no allocation measurements.
- `errors.csv`: exact error categories and accepted inputs for both parsers.
- `metadata.json`: compiler, CPU, affinity, source hashes, reference versions,
  sample count, and iteration cap.
- `REPORT.md`: tables generated directly from the CSV values.
- `*-process.txt`: total harness process measurements when GNU `time` exists.

To inspect rejection classifications without running timing:

```sh
cargo run --release --manifest-path comparison/Cargo.toml --locked -- --report-errors
```

## Equivalent work

The corpus builder emits canonical BER independently of both encoders. The tests
compare complete decoded fields, Filter variants and operands, attribute bytes,
message IDs, and consumed frame boundaries. A second comparison checks every BER
tag, constructed flag, and primitive value. Independent encoding paths must
produce identical bytes, and generated valid inputs cover 512 deterministic
combinations. Truncation tests cover all short-frame prefixes and sampled offsets
through large binary values.

The timed protocol path in Kanidm is the BER `Parser` followed by
`LdapMsg::try_from`, matching the protocol work inside `LdapCodec`. Its pre-buffer
and encoded-frame size checks use the same order as `LdapCodec`; the harness does
not include network or `BytesMut` input-buffer copying. The reference depth value
is one greater because its parser decrements before testing for zero. Both permit
32 nested TLV levels for these runs. zldap also enforces its field-count and
primitive-size limits. All accepted benchmark cases fall within these limits.

The phases answer different questions:

| Phase | Measured work | Interpretation |
| --- | --- | --- |
| `decode` | Full protocol validation, typed output construction, and output destruction | Borrowed zldap result versus owned Kanidm result |
| `decode_and_scan` | Decode, then visit every field and hash every payload byte | Shows how a subsequent byte-reading workload reduces the copy-avoidance advantage |
| `encode_reuse` | Encode repeatedly from existing structured data into preallocated output | Includes the reference's required input clone because its native API consumes the message |
| `rejection_policy` | Parse malformed, unsupported, or oversized inputs | Acceptance policies differ; these rows are excluded from speedup claims |

The encoder benchmark reuses a prevalidated encoded zldap Filter, while the
reference consumes an owned Filter tree. This is an API-level comparison, and its
ratios must not be presented as a comparison of identical low-level encoder work.
The protocol decoder fully validates every supported field before returning;
iteration of its borrowed collections is not required for validation.

## Workloads and memory

The accepted workloads include small simple/SASL Bind messages, BindResponse,
simple Search, all ten Filter variants in a complex Search, 128 attributes,
a 128 KiB binary value, SearchResultDone, Unbind, 256-message Bind batches, and
128-message SearchResultEntry batches. Each timing sample processes up to the
requested number of messages or 64 MiB of wire data. Seven samples alternate
implementation order after warmup. The reported central value is the median;
minimum and maximum are variation across samples, not confidence intervals.

The allocation counter records successful `alloc`, `alloc_zeroed`, and `realloc`
calls. Peak heap is the maximum simultaneously live allocation size inside one
operation, excluding preexisting input and output buffers. Batch decoding drops
each message before reading the next, so peak memory is the peak of one live
message, while allocation calls are divided by message count. The counter checks
that live bytes return to zero. The caller also supplies 32 BER workspace frames;
on the measured 64-bit target this occupies 512 bytes. Zero heap usage does not
mean zero total memory. Whole-process RSS includes fixtures and both libraries,
and is reported separately without attribution to either parser.

## Rejection differences

Version 0.9.0 accepts several inputs zldap rejects: negative/zero/empty message IDs,
nonminimal INTEGER encodings, and an empty AND Filter. The empty AND extension is
outside zldap's RFC 4511 Filter subset. The reference also implements Delete,
which zldap intentionally reports as `UnsupportedOperation(10)`. Different
categories can describe the same rejection: truncated input becomes `Truncated`
or `Incomplete`, while invalid BER can surface at different parser layers.
`tests/differential.rs` records these differences explicitly rather than assuming
that every accepted reference input is valid for the shared subset.

## Claims supported by these experiments

Use the per-scenario tables and raw files in
[`results/20261110-baseline`](results/20261110-baseline/REPORT.md) for the initial
implementation. Later results should be reported separately, retaining the
baseline. This synthetic corpus on one CPU does not establish performance on all
architectures. It does not measure a Kanidm server, networking, TLS, password
verification, authorization, or database work. The allocator experiment and
differential tests complement the root crate's adversarial tests and Miri;
benchmark success is not a memory-safety proof.

Review checks: every performance claim must identify its phase and workload;
every policy mismatch remains visible; zero allocation excludes caller-provided
storage; byte-scanning and unsuccessful cases remain in the report; server-level
speedups are not inferred from protocol timings.
