use zldap::ber::{validate, Class, Cursor, Frame, Tag, Tlv, Writer};
use zldap::{ErrorKind, ParseLimits};

fn limits() -> ParseLimits {
    ParseLimits::default()
}

fn kind(input: &[u8]) -> ErrorKind {
    Tlv::parse(input, limits()).unwrap_err().kind
}

#[test]
fn scalar_vectors_borrow_original_bytes() {
    let input = [2, 1, 127, 4, 0];
    let (integer, used) = Tlv::parse(&input, limits()).unwrap();
    assert_eq!(used, 3);
    assert_eq!(integer.tag, Tag::INTEGER);
    assert_eq!(integer.as_i64(), Ok(127));
    assert_eq!(integer.value.as_ptr(), input[2..].as_ptr());
    assert_eq!(integer.encoded.as_ptr(), input.as_ptr());
    assert_eq!(integer.value_offset(), 2);
    let mut cursor = Cursor::new(&input, 10, limits());
    assert_eq!(cursor.next().unwrap().unwrap().offset, 10);
    assert_eq!(cursor.offset(), 13);
    assert_eq!(cursor.next().unwrap().unwrap().as_octets(), Ok(&[][..]));
    assert!(cursor.next().unwrap().is_none());
    cursor.finish().unwrap();
}

#[test]
fn high_tag_identifiers_round_trip_all_classes() {
    for class in [
        Class::Universal,
        Class::Application,
        Class::Context,
        Class::Private,
    ] {
        for constructed in [false, true] {
            for number in [0, 1, 30, 31, 127, 128, 16383, 16384, u32::MAX] {
                let tag = Tag::new(class, constructed, number);
                let mut storage = [0; 32];
                let mut writer = Writer::new(&mut storage);
                writer.write_tlv(tag, b"abc").unwrap();
                let encoded = writer.finish();
                let (decoded, used) = Tlv::parse(encoded, limits()).unwrap();
                assert_eq!(decoded.tag, tag);
                assert_eq!(decoded.value, b"abc");
                assert_eq!(used, encoded.len());
            }
        }
    }
}

#[test]
fn invalid_identifiers_are_bounded() {
    assert_eq!(kind(&[0x1f]), ErrorKind::Truncated);
    assert_eq!(kind(&[0x1f, 0x80, 0]), ErrorKind::InvalidTag);
    assert_eq!(kind(&[0x1f, 0x1e, 0]), ErrorKind::InvalidTag);
    assert_eq!(
        kind(&[0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f, 0]),
        ErrorKind::TagOverflow
    );
    let mut continuation = [0x80; 4096];
    continuation[0] = 0x1f;
    continuation[1] = 0x81;
    assert_eq!(kind(&continuation), ErrorKind::TagOverflow);
}

#[test]
fn definite_lengths_accept_ber_long_form() {
    for encoded in [&[4, 0][..], &[4, 0x81, 0][..], &[4, 0x82, 0, 0][..]] {
        assert!(Tlv::parse(encoded, limits()).unwrap().0.value.is_empty());
    }
    for length in [0, 1, 127, 128, 255, 256, 65535, 65536] {
        let value = vec![0x5a; length];
        let mut storage = vec![0u8; length + 16];
        let mut writer = Writer::new(&mut storage);
        writer.write_octet_string(&value).unwrap();
        let encoded = writer.finish();
        let (decoded, used) = Tlv::parse(encoded, limits()).unwrap();
        assert_eq!(decoded.value, value);
        assert_eq!(used, encoded.len());
    }
}

#[test]
fn reserved_indefinite_overflow_and_truncated_lengths() {
    assert_eq!(kind(&[]), ErrorKind::Truncated);
    assert_eq!(kind(&[4]), ErrorKind::Truncated);
    assert_eq!(kind(&[4, 0x80]), ErrorKind::IndefiniteLength);
    assert_eq!(kind(&[4, 0xff]), ErrorKind::InvalidLength);
    assert_eq!(kind(&[4, 0x82, 1]), ErrorKind::Truncated);
    assert_eq!(kind(&[4, 2, 1]), ErrorKind::Truncated);
    let mut overflowing = vec![4, 0x80 | (core::mem::size_of::<usize>() as u8 + 1)];
    overflowing.push(1);
    overflowing.extend([0; core::mem::size_of::<usize>()]);
    assert_eq!(kind(&overflowing), ErrorKind::LengthOverflow);
    let mut impossible_total = vec![4, 0x80 | core::mem::size_of::<usize>() as u8];
    impossible_total.extend([0xff; core::mem::size_of::<usize>()]);
    assert_eq!(kind(&impossible_total), ErrorKind::LengthOverflow);
    let small = ParseLimits {
        max_message_len: 128,
        ..limits()
    };
    assert_eq!(
        Tlv::parse(&[4, 0x82, 1, 0], small).unwrap_err().kind,
        ErrorKind::MessageTooLong
    );
}

#[test]
fn excessive_length_of_length_is_bounded_and_zero_prefixes_work() {
    let mut input = [0u8; 128];
    input[0] = 4;
    input[1] = 0xfe;
    assert_eq!(Tlv::parse(&input, limits()).unwrap().1, 128);
    input[2] = 1;
    assert_eq!(kind(&input), ErrorKind::LengthOverflow);
}

#[test]
fn signed_integer_boundaries_and_minimality() {
    for value in [
        i64::MIN,
        -65537,
        -32769,
        -32768,
        -129,
        -128,
        -1,
        0,
        1,
        127,
        128,
        255,
        256,
        32767,
        32768,
        i64::MAX,
    ] {
        let mut buffer = [0; 16];
        let mut writer = Writer::new(&mut buffer);
        writer.write_integer(value).unwrap();
        let encoded = writer.finish();
        assert_eq!(Tlv::parse(encoded, limits()).unwrap().0.as_i64(), Ok(value));
        validate(encoded, limits(), &mut []).unwrap();
        let mut buffer = [0; 16];
        let mut writer = Writer::new(&mut buffer);
        writer.write_enumerated(value).unwrap();
        assert_eq!(
            Tlv::parse(writer.finish(), limits())
                .unwrap()
                .0
                .as_enumerated(),
            Ok(value)
        );
    }
    for encoded in [&[2, 0][..], &[2, 2, 0, 1][..], &[2, 2, 0xff, 0x80][..]] {
        let value = Tlv::parse(encoded, limits()).unwrap().0;
        assert_eq!(value.as_i64().unwrap_err().kind, ErrorKind::InvalidInteger);
    }
    let overflow = [2, 9, 0, 0x80, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(
        Tlv::parse(&overflow, limits())
            .unwrap()
            .0
            .as_i64()
            .unwrap_err()
            .kind,
        ErrorKind::IntegerOverflow
    );
}

#[test]
fn boolean_and_octet_string_semantics() {
    for value in 0..=255u8 {
        let encoded = [1, 1, value];
        assert_eq!(
            Tlv::parse(&encoded, limits()).unwrap().0.as_bool(),
            Ok(value != 0)
        );
    }
    for encoded in [&[1, 0][..], &[1, 2, 0, 0][..]] {
        assert_eq!(
            Tlv::parse(encoded, limits())
                .unwrap()
                .0
                .as_bool()
                .unwrap_err()
                .kind,
            ErrorKind::InvalidBoolean
        );
    }
    assert_eq!(
        Tlv::parse(&[4, 0], limits())
            .unwrap()
            .0
            .as_i64()
            .unwrap_err()
            .kind,
        ErrorKind::UnexpectedTag
    );
    let mut buffer = [0u8; 6];
    let mut writer = Writer::new(&mut buffer);
    writer.write_boolean(false).unwrap();
    writer.write_boolean(true).unwrap();
    assert_eq!(writer.finish(), [1, 1, 0xff, 1, 1, 0]);
}

#[test]
fn cursor_errors_are_transactional_and_offsets_saturate() {
    let bytes = [2, 1];
    let mut cursor = Cursor::new(&bytes, usize::MAX, limits());
    assert_eq!(cursor.next().unwrap_err().kind, ErrorKind::Truncated);
    assert_eq!(cursor.offset(), usize::MAX);
    assert_eq!(cursor.remaining(), bytes);
    assert_eq!(cursor.finish().unwrap_err().kind, ErrorKind::TrailingData);
    let manual = Tlv {
        tag: Tag::OCTET_STRING,
        encoded: &[],
        value: &[1],
        offset: usize::MAX,
    };
    assert_eq!(manual.value_offset(), usize::MAX);
}

#[test]
fn reverse_writer_container_checkpoints_preserve_siblings() {
    let mut buffer = [0u8; 64];
    let mut writer = Writer::new(&mut buffer);
    assert!(writer.is_empty());
    writer.write_octet_string(b"tail").unwrap();
    let checkpoint = writer.len();
    writer.write_octet_string(b"x").unwrap();
    writer.write_integer(7).unwrap();
    writer.wrap(Tag::SEQUENCE, checkpoint).unwrap();
    assert_eq!(
        writer.as_slice(),
        [0x30, 6, 2, 1, 7, 4, 1, b'x', 4, 4, b't', b'a', b'i', b'l']
    );
    let mut cursor = Cursor::new(writer.as_slice(), 0, limits());
    let sequence = cursor.next().unwrap().unwrap();
    assert_eq!(sequence.tag, Tag::SEQUENCE);
    assert_eq!(cursor.next().unwrap().unwrap().value, b"tail");
    cursor.finish().unwrap();
}

#[test]
fn writer_capacity_errors_do_not_modify_previous_output() {
    let mut storage = [0x5a; 3];
    let mut writer = Writer::new(&mut storage);
    assert_eq!(
        writer.write_octet_string(b"xx").unwrap_err().kind,
        ErrorKind::BufferTooSmall
    );
    assert!(writer.is_empty());
    writer.write_integer(1).unwrap();
    assert_eq!(
        writer.wrap(Tag::SEQUENCE, 0).unwrap_err().kind,
        ErrorKind::BufferTooSmall
    );
    assert_eq!(writer.as_slice(), [2, 1, 1]);
    assert_eq!(
        writer.wrap(Tag::SEQUENCE, usize::MAX).unwrap_err().kind,
        ErrorKind::InvalidValue
    );
    assert_eq!(writer.finish(), [2, 1, 1]);
    let mut empty = [];
    assert_eq!(
        Writer::new(&mut empty)
            .write_boolean(false)
            .unwrap_err()
            .kind,
        ErrorKind::BufferTooSmall
    );
}

#[test]
fn every_prefix_of_valid_values_is_truncated() {
    let values = [
        vec![2, 1, 1],
        vec![0xbf, 0x81, 0, 3, 2, 1, 0],
        vec![4, 0x82, 0, 3, 1, 2, 3],
    ];
    for value in values {
        for prefix in 0..value.len() {
            assert_eq!(
                Tlv::parse(&value[..prefix], limits()).unwrap_err().kind,
                ErrorKind::Truncated
            );
        }
        assert!(Tlv::parse(&value, limits()).is_ok());
    }
}

#[test]
fn validator_enforces_global_fields_depth_values_and_workspace() {
    // Three levels: sequence -> set -> integer, plus a sibling octet string.
    let bytes = [0x30, 10, 0x31, 3, 2, 1, 1, 4, 3, b'a', b'b', b'c'];
    let mut frames = [Frame::EMPTY; 2];
    validate(&bytes, limits(), &mut frames).unwrap();
    for (limit, expected) in [
        (
            ParseLimits {
                max_fields: 3,
                ..limits()
            },
            ErrorKind::FieldLimit,
        ),
        (
            ParseLimits {
                max_depth: 2,
                ..limits()
            },
            ErrorKind::DepthLimit,
        ),
        (
            ParseLimits {
                max_string_len: 2,
                ..limits()
            },
            ErrorKind::StringTooLong,
        ),
        (
            ParseLimits {
                max_message_len: 11,
                ..limits()
            },
            ErrorKind::MessageTooLong,
        ),
    ] {
        assert_eq!(
            validate(&bytes, limit, &mut frames).unwrap_err().kind,
            expected
        );
    }
    let exact = ParseLimits {
        max_fields: 4,
        max_depth: 3,
        max_string_len: 3,
        max_message_len: 12,
    };
    validate(&bytes, exact, &mut frames).unwrap();
    assert_eq!(
        validate(&bytes, limits(), &mut frames[..1])
            .unwrap_err()
            .kind,
        ErrorKind::WorkspaceTooSmall
    );
    assert_eq!(
        validate(
            &[4, 0],
            ParseLimits {
                max_depth: 0,
                ..limits()
            },
            &mut []
        )
        .unwrap_err()
        .kind,
        ErrorKind::DepthLimit
    );
    assert_eq!(
        validate(
            &[4, 0],
            ParseLimits {
                max_fields: 0,
                ..limits()
            },
            &mut []
        )
        .unwrap_err()
        .kind,
        ErrorKind::FieldLimit
    );
    validate(
        &[0x30, 0],
        ParseLimits {
            max_depth: 1,
            ..limits()
        },
        &mut [],
    )
    .unwrap();
    validate(
        &[4, 0],
        ParseLimits {
            max_string_len: 0,
            ..limits()
        },
        &mut [],
    )
    .unwrap();
}

#[test]
fn validator_rejects_malformed_nested_values_and_trailing_data() {
    let mut frames = [Frame::EMPTY; 8];
    for (input, expected) in [
        (&[0x30, 3, 4, 2, 1][..], ErrorKind::Truncated),
        (&[0x30, 2, 2, 0][..], ErrorKind::InvalidInteger),
        (&[0x30, 2, 0, 0][..], ErrorKind::InvalidTag),
        (&[0x30, 0, 4, 0][..], ErrorKind::TrailingData),
        (&[0x10, 0][..], ErrorKind::UnexpectedTag),
        (&[0x11, 0][..], ErrorKind::UnexpectedTag),
        (&[0x24, 0][..], ErrorKind::UnexpectedTag),
        (&[0x21, 0][..], ErrorKind::UnexpectedTag),
        (&[0x22, 0][..], ErrorKind::UnexpectedTag),
        (&[0x2a, 0][..], ErrorKind::UnexpectedTag),
    ] {
        assert_eq!(
            validate(input, limits(), &mut frames).unwrap_err().kind,
            expected
        );
    }
    // Unrecognized application/context/private tags still receive a full walk.
    validate(&[0x63, 4, 0x85, 2, 1, 2], limits(), &mut frames).unwrap();
    assert_eq!(
        validate(
            &[0x63, 4, 0x85, 2, 1, 2],
            ParseLimits {
                max_fields: 1,
                ..limits()
            },
            &mut frames
        )
        .unwrap_err()
        .kind,
        ErrorKind::FieldLimit
    );
}

#[test]
fn deeply_nested_input_uses_only_caller_stack() {
    let depth = if cfg!(miri) { 128 } else { 4096 };
    let mut buffer = vec![0u8; depth * 5 + 8];
    let mut writer = Writer::new(&mut buffer);
    writer.write_octet_string(b"x").unwrap();
    for _ in 1..depth {
        writer.wrap(Tag::SEQUENCE, 0).unwrap();
    }
    let bytes = writer.finish();
    let generous = ParseLimits {
        max_depth: depth,
        max_message_len: bytes.len(),
        max_fields: depth,
        ..limits()
    };
    let mut stack = vec![Frame::EMPTY; depth - 1];
    validate(bytes, generous, &mut stack).unwrap();
    assert_eq!(
        validate(bytes, limits(), &mut stack).unwrap_err().kind,
        ErrorKind::DepthLimit
    );
    assert_eq!(
        validate(bytes, generous, &mut []).unwrap_err().kind,
        ErrorKind::WorkspaceTooSmall
    );
}

#[test]
fn deterministic_random_inputs_terminate_without_panicking() {
    let iterations = if cfg!(miri) { 256 } else { 30_000 };
    let mut state = 0x1a24_b79c_239d_719fu64;
    let mut data = [0u8; 128];
    let mut frames = [Frame::EMPTY; 16];
    for _ in 0..iterations {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let len = state as usize % data.len();
        for byte in &mut data[..len] {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        let bounded = ParseLimits {
            max_message_len: 1024,
            max_depth: 16,
            max_fields: 64,
            max_string_len: 128,
        };
        let _ = validate(&data[..len], bounded, &mut frames);
        if let Ok((value, used)) = Tlv::parse(&data[..len], bounded) {
            assert!(used <= len);
            let _ = value.as_i64();
            let _ = value.as_enumerated();
            let _ = value.as_bool();
            let _ = value.as_octets();
        }
    }
}
