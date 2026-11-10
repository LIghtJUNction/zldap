//! Exercise the same protocol data through the flat-message fast path and the
//! general BER/schema path. A legal nonminimal MessageID length disables the
//! fast path without changing any decoded field or nesting relationship.
use zldap::ber::{Frame, Tlv};
use zldap::{Authentication, ErrorKind, Message, Operation, ParseLimits};

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if value.len() < 128 {
        output.push(value.len() as u8);
    } else {
        let length = value.len().to_be_bytes();
        let start = length.iter().position(|byte| *byte != 0).unwrap();
        output.push(0x80 | (length.len() - start) as u8);
        output.extend_from_slice(&length[start..]);
    }
    output.extend_from_slice(value);
    output
}

fn group(tag: u8, fields: &[Vec<u8>]) -> Vec<u8> {
    tlv(tag, &fields.concat())
}
fn integer_value(value: i64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let mut start = 0;
    while start < 7
        && ((bytes[start] == 0 && bytes[start + 1] < 128)
            || (bytes[start] == 255 && bytes[start + 1] >= 128))
    {
        start += 1;
    }
    bytes[start..].to_vec()
}
fn integer(tag: u8, value: i64) -> Vec<u8> {
    tlv(tag, &integer_value(value))
}
fn wire(id: i64, operation: Vec<u8>) -> Vec<u8> {
    group(0x30, &[integer(2, id), operation])
}

fn force_general(input: &[u8]) -> Vec<u8> {
    let outer = Tlv::parse(input, ParseLimits::default()).unwrap().0;
    assert_eq!(outer.value[0], 2);
    assert!(outer.value[1] < 128);
    let mut body = vec![2, 0x81, outer.value[1]];
    body.extend_from_slice(&outer.value[2..]);
    group(0x30, &[body])
}

#[derive(Clone, Copy, Debug)]
enum Shape {
    Simple,
    SaslAbsent,
    SaslEmpty,
    SaslBytes,
    BindAbsent,
    BindEmpty,
    BindBytes,
    Done,
    Unbind,
}
const SHAPES: [Shape; 9] = [
    Shape::Simple,
    Shape::SaslAbsent,
    Shape::SaslEmpty,
    Shape::SaslBytes,
    Shape::BindAbsent,
    Shape::BindEmpty,
    Shape::BindBytes,
    Shape::Done,
    Shape::Unbind,
];

struct Case {
    bytes: Vec<u8>,
    fields: usize,
    depth: usize,
    max_value: usize,
}

fn fixture(shape: Shape, id: i64, payload_len: usize) -> Case {
    let text = vec![b'a'; payload_len];
    let binary = (0..payload_len)
        .map(|i| (i.wrapping_mul(131) & 255) as u8)
        .collect::<Vec<_>>();
    let mut max_value = integer_value(id).len();
    let (operation, fields, depth) = match shape {
        Shape::Simple => {
            max_value = max_value.max(1).max(payload_len);
            (
                group(0x60, &[integer(2, 3), tlv(4, &text), tlv(0x80, &binary)]),
                6,
                3,
            )
        }
        Shape::SaslAbsent | Shape::SaslEmpty | Shape::SaslBytes => {
            let mut auth = vec![tlv(4, b"PLAIN")];
            let has_credentials = !matches!(shape, Shape::SaslAbsent);
            if has_credentials {
                auth.push(tlv(
                    4,
                    if matches!(shape, Shape::SaslEmpty) {
                        &[]
                    } else {
                        &binary
                    },
                ));
            }
            max_value = max_value.max(5).max(payload_len);
            (
                group(0x60, &[integer(2, 3), tlv(4, &text), group(0xa3, &auth)]),
                7 + usize::from(has_credentials),
                4,
            )
        }
        Shape::BindAbsent | Shape::BindEmpty | Shape::BindBytes | Shape::Done => {
            let mut fields = vec![integer(10, 49), tlv(4, &text), tlv(4, &text)];
            let has_credentials = matches!(shape, Shape::BindEmpty | Shape::BindBytes);
            if has_credentials {
                fields.push(tlv(
                    0x87,
                    if matches!(shape, Shape::BindEmpty) {
                        &[]
                    } else {
                        &binary
                    },
                ));
            }
            max_value = max_value.max(1).max(payload_len);
            (
                group(
                    if matches!(shape, Shape::Done) {
                        0x65
                    } else {
                        0x61
                    },
                    &fields,
                ),
                6 + usize::from(has_credentials),
                3,
            )
        }
        Shape::Unbind => (tlv(0x42, &[]), 3, 2),
    };
    Case {
        bytes: wire(id, operation),
        fields,
        depth,
        max_value,
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Decoded<'a> {
    Bind {
        id: u32,
        version: u8,
        name: &'a str,
        auth: Authentication<'a>,
    },
    BindResponse {
        id: u32,
        code: u32,
        matched: &'a str,
        diagnostic: &'a str,
        credentials: Option<&'a [u8]>,
    },
    Done {
        id: u32,
        code: u32,
        matched: &'a str,
        diagnostic: &'a str,
    },
    Unbind {
        id: u32,
    },
}

fn decoded(message: Message<'_>) -> Decoded<'_> {
    match message.operation {
        Operation::BindRequest(bind) => Decoded::Bind {
            id: message.id,
            version: bind.version,
            name: bind.name,
            auth: bind.authentication,
        },
        Operation::BindResponse(response) => {
            assert!(response.result.referrals.into_iter().next().is_none());
            Decoded::BindResponse {
                id: message.id,
                code: response.result.code,
                matched: response.result.matched_dn,
                diagnostic: response.result.diagnostic_message,
                credentials: response.server_sasl_credentials,
            }
        }
        Operation::SearchResultDone(result) => {
            assert!(result.referrals.into_iter().next().is_none());
            Decoded::Done {
                id: message.id,
                code: result.code,
                matched: result.matched_dn,
                diagnostic: result.diagnostic_message,
            }
        }
        Operation::UnbindRequest => Decoded::Unbind { id: message.id },
        _ => panic!("operation outside flat-message fixtures"),
    }
}

fn outcome(bytes: &[u8], limits: ParseLimits, slots: usize) -> Result<Decoded<'_>, ErrorKind> {
    let mut workspace = [Frame::EMPTY; 8];
    Message::parse(bytes, limits, &mut workspace[..slots])
        .map(|message| {
            assert!(message.controls.into_iter().next().is_none());
            assert!(message.extensions.is_empty());
            decoded(message)
        })
        .map_err(|error| error.kind)
}

fn equivalent<'a>(
    a: &'a [u8],
    b: &[u8],
    limits: ParseLimits,
    slots: usize,
) -> Result<Decoded<'a>, ErrorKind> {
    let result = outcome(a, limits, slots);
    assert_eq!(
        result,
        outcome(b, limits, slots),
        "limits={limits:?}, workspace={slots}, wire={a:?}"
    );
    result
}

#[test]
fn every_flat_shape_matches_general_across_sign_and_length_boundaries() {
    let ids = if cfg!(miri) {
        vec![1, 127, 128, i64::from(i32::MAX)]
    } else {
        vec![
            1,
            127,
            128,
            255,
            256,
            32767,
            32768,
            65535,
            65536,
            0x7fffff,
            0x800000,
            i64::from(i32::MAX),
        ]
    };
    let lengths = if cfg!(miri) {
        vec![0, 1, 31, 60, 127, 128, 129]
    } else {
        (0..=129).collect()
    };
    for id in ids {
        for &length in &lengths {
            for shape in SHAPES {
                let case = fixture(shape, id, length);
                let general = force_general(&case.bytes);
                equivalent(&case.bytes, &general, ParseLimits::default(), 8).unwrap();
            }
        }
    }
}

#[test]
fn resource_thresholds_match_independently_counted_trees() {
    let lengths = if cfg!(miri) {
        vec![0, 7, 129]
    } else {
        vec![0, 1, 7, 60, 113, 127, 128, 129]
    };
    for shape in SHAPES {
        for &length in &lengths {
            let case = fixture(shape, 128, length);
            let general = force_general(&case.bytes);
            let defaults = ParseLimits::default();
            for count in 0..=case.fields + 1 {
                let outcome = equivalent(
                    &case.bytes,
                    &general,
                    ParseLimits {
                        max_fields: count,
                        ..defaults
                    },
                    8,
                );
                if count < case.fields {
                    assert_eq!(outcome.unwrap_err(), ErrorKind::FieldLimit);
                } else {
                    outcome.unwrap();
                }
            }
            for depth in 0..=case.depth + 1 {
                let outcome = equivalent(
                    &case.bytes,
                    &general,
                    ParseLimits {
                        max_depth: depth,
                        ..defaults
                    },
                    8,
                );
                if depth < case.depth {
                    assert_eq!(outcome.unwrap_err(), ErrorKind::DepthLimit);
                } else {
                    outcome.unwrap();
                }
            }
            for slots in 0..=case.depth {
                let outcome = equivalent(&case.bytes, &general, defaults, slots);
                if slots < case.depth - 1 {
                    assert_eq!(outcome.unwrap_err(), ErrorKind::WorkspaceTooSmall);
                } else {
                    outcome.unwrap();
                }
            }
            for max_value in [0, case.max_value - 1, case.max_value, case.max_value + 1] {
                let outcome = equivalent(
                    &case.bytes,
                    &general,
                    ParseLimits {
                        max_string_len: max_value,
                        ..defaults
                    },
                    8,
                );
                if max_value < case.max_value {
                    assert_eq!(outcome.unwrap_err(), ErrorKind::StringTooLong);
                } else {
                    outcome.unwrap();
                }
            }
        }
    }
}

#[test]
fn simultaneous_budget_failures_keep_general_error_precedence() {
    for shape in SHAPES {
        let case = fixture(shape, 1, 7);
        let general = force_general(&case.bytes);
        for max_fields in [0, 1, 2, 3, 5, 8] {
            for max_depth in [0, 1, 2, 3, 4] {
                for slots in [0, 1, 2, 3] {
                    let limits = ParseLimits {
                        max_fields,
                        max_depth,
                        max_string_len: 2,
                        ..ParseLimits::default()
                    };
                    let _ = equivalent(&case.bytes, &general, limits, slots);
                }
            }
        }
    }
}

#[test]
fn frame_capacity_uses_each_encodings_actual_size() {
    for shape in SHAPES {
        for length in [0, 55, 60, 61, 113, 114, 127, 128, 129] {
            let case = fixture(shape, 32768, length);
            let general = force_general(&case.bytes);
            for bytes in [&case.bytes, &general] {
                assert_eq!(
                    outcome(
                        bytes,
                        ParseLimits {
                            max_message_len: bytes.len() - 1,
                            ..ParseLimits::default()
                        },
                        8
                    )
                    .unwrap_err(),
                    ErrorKind::MessageTooLong
                );
                outcome(
                    bytes,
                    ParseLimits {
                        max_message_len: bytes.len(),
                        ..ParseLimits::default()
                    },
                    8,
                )
                .unwrap();
            }
            assert_eq!(
                outcome(
                    &case.bytes,
                    ParseLimits {
                        max_message_len: case.bytes.len(),
                        ..ParseLimits::default()
                    },
                    8
                ),
                outcome(
                    &general,
                    ParseLimits {
                        max_message_len: general.len(),
                        ..ParseLimits::default()
                    },
                    8
                )
            );
        }
    }
}

#[test]
fn unsigned_integer_gate_matches_signed_general_validation() {
    for raw in [
        vec![],
        vec![0],
        vec![0xff],
        vec![0x80],
        vec![0, 1],
        vec![0xff, 0xff],
        vec![0, 0x80],
        vec![0x7f, 0xff, 0xff, 0xff],
        vec![0, 0x80, 0, 0, 0],
        vec![1, 0, 0, 0, 0],
        vec![0x7f; 8],
        vec![1; 9],
    ] {
        let encoded = group(0x30, &[tlv(2, &raw), tlv(0x42, &[])]);
        let general = force_general(&encoded);
        let _ = equivalent(&encoded, &general, ParseLimits::default(), 8);
    }
    for code in [
        -1,
        0,
        1,
        10,
        11,
        49,
        127,
        128,
        255,
        256,
        32767,
        32768,
        0x7fffff,
        0x800000,
        i64::from(i32::MAX),
        i64::from(i32::MAX) + 1,
    ] {
        for tag in [0x61, 0x65] {
            let encoded = wire(
                128,
                group(tag, &[integer(10, code), tlv(4, &[]), tlv(4, &[])]),
            );
            let general = force_general(&encoded);
            let result = equivalent(&encoded, &general, ParseLimits::default(), 8);
            if (0..=i64::from(i32::MAX)).contains(&code) && code != 10 {
                result.unwrap();
            } else {
                assert!(result.is_err());
            }
        }
    }
    for version in [-1, 0, 1, 2, 3, 127, 128, 255, 256] {
        let encoded = wire(
            1,
            group(0x60, &[integer(2, version), tlv(4, &[]), tlv(0x80, &[])]),
        );
        let general = force_general(&encoded);
        let result = equivalent(&encoded, &general, ParseLimits::default(), 8);
        if (1..=127).contains(&version) {
            result.unwrap();
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn absent_empty_and_binary_credentials_stay_distinct() {
    let absent = fixture(Shape::SaslAbsent, 1, 0);
    let empty = fixture(Shape::SaslEmpty, 1, 0);
    let binary = fixture(Shape::SaslBytes, 1, 7);
    assert!(matches!(
        outcome(&absent.bytes, ParseLimits::default(), 8).unwrap(),
        Decoded::Bind {
            auth: Authentication::Sasl {
                credentials: None,
                ..
            },
            ..
        }
    ));
    assert!(matches!(
        outcome(&empty.bytes, ParseLimits::default(), 8).unwrap(),
        Decoded::Bind {
            auth: Authentication::Sasl {
                credentials: Some([]),
                ..
            },
            ..
        }
    ));
    assert!(
        matches!(outcome(&binary.bytes, ParseLimits::default(), 8).unwrap(), Decoded::Bind { auth: Authentication::Sasl { credentials: Some(value), .. }, .. } if value.len() == 7)
    );
    for shape in SHAPES {
        let case = fixture(shape, 1, 7);
        equivalent(
            &case.bytes,
            &force_general(&case.bytes),
            ParseLimits::default(),
            8,
        )
        .unwrap();
    }
}

#[test]
fn empty_sasl_mechanism_matches_general_and_keeps_resource_counts() {
    for credentials in [None, Some(&[][..])] {
        let mut auth = vec![tlv(4, b"")];
        if let Some(bytes) = credentials {
            auth.push(tlv(4, bytes));
        }
        let encoded = wire(
            1,
            group(0x60, &[integer(2, 3), tlv(4, b""), group(0xa3, &auth)]),
        );
        let general = force_general(&encoded);
        let fields = 7 + usize::from(credentials.is_some());
        let exact = ParseLimits {
            max_fields: fields,
            max_depth: 4,
            max_string_len: 1,
            ..ParseLimits::default()
        };
        let result = equivalent(&encoded, &general, exact, 3).unwrap();
        assert_eq!(
            result,
            Decoded::Bind {
                id: 1,
                version: 3,
                name: "",
                auth: Authentication::Sasl {
                    mechanism: "",
                    credentials
                },
            }
        );
        assert_eq!(
            equivalent(
                &encoded,
                &general,
                ParseLimits {
                    max_fields: fields - 1,
                    ..exact
                },
                3
            )
            .unwrap_err(),
            ErrorKind::FieldLimit
        );
        assert_eq!(
            equivalent(
                &encoded,
                &general,
                ParseLimits {
                    max_depth: 3,
                    ..exact
                },
                3
            )
            .unwrap_err(),
            ErrorKind::DepthLimit
        );
        assert_eq!(
            equivalent(&encoded, &general, exact, 2).unwrap_err(),
            ErrorKind::WorkspaceTooSmall
        );
    }
}

#[test]
fn invalid_utf8_and_sasl_mechanisms_fall_back_with_identical_errors() {
    for text in [
        vec![0xff],
        vec![0xc0, 0x80],
        vec![0xe2, 0x82],
        vec![0xed, 0xa0, 0x80],
    ] {
        let operations = [
            group(0x60, &[integer(2, 3), tlv(4, &text), tlv(0x80, &[])]),
            group(
                0x60,
                &[integer(2, 3), tlv(4, &[]), group(0xa3, &[tlv(4, &text)])],
            ),
            group(0x61, &[integer(10, 0), tlv(4, &text), tlv(4, &[])]),
            group(0x65, &[integer(10, 0), tlv(4, &[]), tlv(4, &text)]),
        ];
        for operation in operations {
            let encoded = wire(1, operation);
            assert_eq!(
                equivalent(
                    &encoded,
                    &force_general(&encoded),
                    ParseLimits::default(),
                    8
                )
                .unwrap_err(),
                ErrorKind::InvalidUtf8
            );
        }
    }
    for mechanism in ["plain", "A B", "ABCDEFGHIJKLMNOPQRSTU"] {
        let encoded = wire(
            1,
            group(
                0x60,
                &[
                    integer(2, 3),
                    tlv(4, &[]),
                    group(0xa3, &[tlv(4, mechanism.as_bytes())]),
                ],
            ),
        );
        assert_eq!(
            equivalent(
                &encoded,
                &force_general(&encoded),
                ParseLimits::default(),
                8
            )
            .unwrap_err(),
            ErrorKind::InvalidValue
        );
    }
}

#[test]
fn malformed_flat_candidates_have_identical_general_outcomes() {
    for shape in SHAPES {
        let case = fixture(shape, 1, 7);
        let outer = Tlv::parse(&case.bytes, ParseLimits::default()).unwrap().0;
        let id_len = usize::from(outer.value[1]) + 2;
        let replacements = if cfg!(miri) {
            &[0, 0x80, 0xff][..]
        } else {
            &[0, 1, 2, 0x1f, 0x30, 0x42, 0x60, 0x61, 0x65, 0x80, 0xff][..]
        };
        for index in id_len..outer.value.len() {
            for &replacement in replacements {
                let mut body = outer.value.to_vec();
                body[index] = replacement;
                let encoded = tlv(0x30, &body);
                let general = force_general(&encoded);
                let a = Message::parse(&encoded, ParseLimits::default(), &mut [Frame::EMPTY; 8]);
                let b = Message::parse(&general, ParseLimits::default(), &mut [Frame::EMPTY; 8]);
                match (a, b) {
                    (Ok(a), Ok(b)) => {
                        assert_eq!(a.id, b.id);
                        // Mutation can create legal opaque extensions. Copying
                        // each frame remains exact, including those extensions.
                        assert_eq!(a.extensions, b.extensions);
                        let controls = |message: Message<'_>| {
                            message
                                .controls
                                .map(|control| {
                                    let control = control.unwrap();
                                    (
                                        control.oid.to_owned(),
                                        control.critical,
                                        control.value.map(<[u8]>::to_vec),
                                    )
                                })
                                .collect::<Vec<_>>()
                        };
                        assert_eq!(controls(a), controls(b));
                        assert_eq!(decoded(a), decoded(b));
                    }
                    (Err(a), Err(b)) => assert_eq!(a.kind, b.kind),
                    _ => panic!("fast/general acceptance diverged at byte {index}: {encoded:?}"),
                }
            }
        }
    }
}

#[test]
fn full_frame_truncations_and_batches_preserve_prefix_boundaries() {
    for shape in SHAPES {
        let case = fixture(shape, 128, 7);
        let general = force_general(&case.bytes);
        for bytes in [&case.bytes, &general] {
            for end in 0..bytes.len() {
                assert_eq!(
                    outcome(&bytes[..end], ParseLimits::default(), 8).unwrap_err(),
                    ErrorKind::Truncated
                );
            }
        }
        let batch = [
            case.bytes.as_slice(),
            general.as_slice(),
            case.bytes.as_slice(),
        ]
        .concat();
        let mut remaining = batch.as_slice();
        for expected in [&case.bytes, &general, &case.bytes] {
            let (message, used) =
                Message::parse_prefix(remaining, ParseLimits::default(), &mut [Frame::EMPTY; 8])
                    .unwrap();
            assert_eq!(used, expected.len());
            assert_eq!(message.encoded(), expected.as_slice());
            assert_eq!(
                decoded(message),
                outcome(&case.bytes, ParseLimits::default(), 8).unwrap()
            );
            remaining = &remaining[used..];
        }
        assert!(remaining.is_empty());
    }
}
