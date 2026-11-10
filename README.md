# zldap

An allocation-free LDAP/BER protocol codec. The published crate is always
`#![no_std]`, uses only `core`, has no dependencies, and forbids unsafe code.
Minimum supported Rust: **1.74** (edition 2021).

## Bind example

```rust
use zldap::{Authentication, BindRequest, Message, MessageInput, Operation,
    OperationInput, ParseLimits, ber::Frame};

let request = MessageInput {
    id: 1,
    operation: OperationInput::BindRequest(BindRequest {
        version: 3,
        name: "cn=alice,dc=example,dc=org",
        authentication: Authentication::Simple(b"example-password"),
    }),
    controls: &[],
};
let mut output = [0u8; 256];
let n = request.encode(&mut output)?;
let mut workspace = [Frame::EMPTY; 32];
let message = Message::parse(&output[..n], ParseLimits::default(), &mut workspace)?;
assert_eq!(message.id, 1);
assert!(matches!(message.operation, Operation::BindRequest(_)));
# Ok::<(), zldap::Error>(())
```

Parsing returns protocol data. Authentication, authorization, filter evaluation,
transport security, connection state and request scheduling belong to the caller.
In particular, decoding a BindRequest or a success result code does not establish
an authenticated session. Debug output redacts Bind credentials.

## Supported wire types

BER identifiers (including high tags), definite lengths, signed INTEGER and
ENUMERATED, BOOLEAN, primitive OCTET STRING, SEQUENCE and SET are available in
`ber`. The LDAP layer supports simple and SASL Bind protocol data, BindResponse,
SearchRequest, SearchResultEntry, SearchResultDone, UnbindRequest, controls and
referrals. SASL credentials remain opaque bytes.

Filters cover AND, OR, NOT, equality, substrings, greater-or-equal,
less-or-equal, present, approximate match and extensible match. `Filter::children`
exposes immediate children; `Filter::events` traverses preorder with depth using
a caller-owned stack. No recursive parser or recursive destructor is used.

Other application operations return `ErrorKind::UnsupportedOperation(tag)`.
Unknown trailing SEQUENCE extensions are structurally validated and retained in
the original message bytes. Known duplicate fields, invalid field order, malformed
values and unknown filter choices are rejected. Metadata is checked as UTF-8;
passwords, assertions, control contents and attribute values stay binary.

## Resource bounds and buffers

`ParseLimits` defaults to a 1 MiB encoded frame, 32 TLV levels, 65,536 total TLVs,
and 1 MiB per primitive value. The outer message counts as depth one and one
field. Every nested TLV, including ignored extensions, consumes these budgets.
Limits apply before returning a message; callers need not iterate every view to
trigger validation. A short frame workspace returns `WorkspaceTooSmall`.

`Message::parse` requires exactly one complete frame. `parse_prefix` returns the
first frame and its consumed size for TCP buffers and batches; limits apply to
that individual frame. Truncation, malformed BER, overflow and resource-limit
failures have separate structured error kinds and byte offsets.

`MessageInput::encoded_len` validates fields and computes exact required capacity.
`encode` writes at the beginning of caller-provided storage and leaves it unchanged
on invalid fields or insufficient capacity. The low-level `ber::Writer` writes
backward: write siblings last-to-first, then wrap their parent using a checkpoint
from `Writer::len`. `Writer::finish` returns the encoded suffix without shifting
payload bytes. `Message::copy_encoded` explicitly copies an existing frame.

The BER layer accepts nonminimal definite length encodings, as BER permits them;
it rejects indefinite lengths. Integers must use minimal signed encodings and fit
in `i64`. LDAP INTEGER fields additionally obey their ASN.1 ranges. LDAP BOOLEAN
true must use `ff`, and default FALSE criticality/dnAttributes fields must be
absent; generic BER BOOLEAN accepts any nonzero octet. Constructed
OCTET STRING is outside the LDAP BER profile. Embedded ASN.1 in an OCTET STRING
is opaque and is not recursively decoded.

## Build and verification

```sh
cargo test --locked
cargo +1.74.0 test --locked
cargo clippy --all-targets -- -D warnings
cargo doc --no-deps
cargo check --target wasm32-unknown-unknown
cargo check --target thumbv7em-none-eabi
cargo +nightly miri test --locked --lib --tests
python3 scripts/check_package.py
```

The independent `comparison/` workspace pins Kanidm protocol and BER releases.
It is excluded from the published package and the core dependency graph. Its
README documents the corpus, semantic checks, timing and allocation accounting.
Performance conclusions apply only to measured equivalent protocol operations.

## Release

The GitHub **Release** workflow accepts `current`, `patch`, `minor` or `major`.
It validates the release commit, checks registry version availability, publishes
using the `CARGO_REGISTRY_TOKEN` repository secret, then creates the Git tag and
GitHub Release in the same run. PR jobs receive no publishing credentials.

## References

- [RFC 4511: LDAP protocol](https://www.rfc-editor.org/rfc/rfc4511)
- [RFC 4512: LDAP attribute descriptions](https://www.rfc-editor.org/rfc/rfc4512)
- [Kanidm LDAP protocol implementation](https://github.com/kanidm/ldap3)

License: MIT OR Apache-2.0.
