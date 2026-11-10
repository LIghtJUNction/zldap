use zldap::{ber::Frame, Message, ParseLimits};
use zldap_comparison::{
    corpus, encoding, oracle,
    semantics::{self, Fields},
};

fn equivalent(input: &[u8]) {
    let mut input = input;
    while !input.is_empty() {
        let (z, z_used) =
            Message::parse_prefix(input, ParseLimits::default(), &mut [Frame::EMPTY; 32]).unwrap();
        let (k, k_used) = oracle::parse_prefix(input, 33).unwrap();
        assert_eq!(z_used, k_used, "same frame boundary");
        let mut z_fields = Fields::default();
        let mut k_fields = Fields::default();
        semantics::zldap(&z, &mut z_fields);
        semantics::kanidm(&k, &mut k_fields);
        assert_eq!(z_fields, k_fields, "every decoded protocol field");
        input = &input[z_used..];
    }
}

#[test]
fn all_benchmark_messages_have_identical_fields() {
    for case in corpus::corpus() {
        equivalent(&case.wire);
    }
}

#[test]
fn independently_encoded_messages_have_identical_bytes_and_fields() {
    for case in corpus::corpus().into_iter().filter(|c| c.messages == 1) {
        let z =
            Message::parse(&case.wire, ParseLimits::default(), &mut [Frame::EMPTY; 32]).unwrap();
        let k = oracle::parse_exact(&case.wire, 33).unwrap();
        let mut oracle_bytes = bytes::BytesMut::new();
        oracle::encode(k, &mut oracle_bytes);
        encoding::with_input(z, |input| {
            let len = input.encoded_len().unwrap();
            let mut output = vec![0; len];
            assert_eq!(input.encode(&mut output).unwrap(), len);
            assert_eq!(
                output.as_slice(),
                oracle_bytes.as_ref(),
                "{} canonical encoding",
                case.name
            );
            equivalent(&output);
        });
    }
}

#[test]
fn deterministic_generated_valid_messages() {
    let mut seed = 0x5eed_1234_9876_abcd_u64;
    for id in 1..=512 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        match seed % 4 {
            0 => equivalent(&corpus::bind(id)),
            1 => equivalent(&corpus::entry(
                id,
                (seed as usize % 20) + 1,
                seed as usize % 1024,
            )),
            2 => equivalent(&corpus::search(
                id,
                corpus::assertion(0xa3, b"uid", format!("user{seed}").as_bytes()),
            )),
            _ => equivalent(&corpus::search(id, corpus::complex_filter())),
        }
    }
}

#[test]
fn all_truncations_are_rejected_by_both() {
    for case in corpus::corpus().into_iter().filter(|c| c.messages == 1) {
        // Sample long binary fields as well as every header byte; avoid quadratic
        // work copying every prefix of the large-value fixture in the oracle.
        let step = if case.wire.len() > 4096 { 257 } else { 1 };
        for length in (0..case.wire.len()).step_by(step) {
            let input = &case.wire[..length];
            assert!(
                Message::parse(input, ParseLimits::default(), &mut [Frame::EMPTY; 32]).is_err()
            );
            assert!(oracle::parse_exact(input, 33).is_err());
        }
    }
}

#[test]
fn ber_tree_fields_and_frame_lengths_match() {
    use ldap3_lber::structure::{StructureTag, PL};
    use zldap::ber::{Cursor, Tlv};
    use zldap_comparison::semantics::Sink;
    fn z_fields(tlv: Tlv<'_>, out: &mut Fields) {
        out.word(tlv.tag.class as u64);
        out.word(tlv.tag.number as u64);
        out.word(tlv.tag.constructed as u64);
        if tlv.tag.constructed {
            let mut cursor = Cursor::new(tlv.value, 0, ParseLimits::default());
            while let Some(child) = cursor.next().unwrap() {
                z_fields(child, out);
            }
        } else {
            out.bytes(tlv.value);
        }
        out.word(u64::MAX);
    }
    fn k_fields(tlv: &StructureTag, out: &mut Fields) {
        out.word(tlv.class as u64);
        out.word(tlv.id);
        out.word(matches!(&tlv.payload, PL::C(_)) as u64);
        match &tlv.payload {
            PL::C(children) => {
                for child in children {
                    k_fields(child, out);
                }
            }
            PL::P(bytes) => out.bytes(bytes),
        }
        out.word(u64::MAX);
    }
    for case in corpus::corpus().into_iter().filter(|c| c.messages == 1) {
        zldap::ber::validate(&case.wire, ParseLimits::default(), &mut [Frame::EMPTY; 32]).unwrap();
        let (z, used) = Tlv::parse(&case.wire, ParseLimits::default()).unwrap();
        let (remaining, k) = ldap3_lber::parse::Parser::new(33)
            .parse(&case.wire)
            .unwrap();
        assert_eq!(used, case.wire.len() - remaining.len());
        let (mut z_out, mut k_out) = (Fields::default(), Fields::default());
        z_fields(z, &mut z_out);
        k_fields(&k, &mut k_out);
        assert_eq!(
            z_out, k_out,
            "all BER tags, lengths, and bytes: {}",
            case.name
        );
    }
}

#[test]
fn malformed_error_classes_and_known_policy_differences_are_explicit() {
    let expected = [
        ("empty", "Truncated", "Incomplete"),
        ("truncated_tag", "Truncated", "Incomplete"),
        ("truncated_value", "Truncated", "Incomplete"),
        ("indefinite_length", "IndefiniteLength", "Protocol"),
        ("length_overflow", "LengthOverflow", "Protocol"),
        ("negative_message_id", "IntegerOverflow", "accepted"),
        ("zero_message_id", "InvalidMessageId", "accepted"),
        ("empty_message_id", "InvalidInteger", "accepted"),
        ("nonminimal_integer", "InvalidInteger", "accepted"),
        (
            "unsupported_operation",
            "UnsupportedOperation(10)",
            "accepted",
        ),
        ("unknown_outer_tag", "UnexpectedTag", "Protocol"),
        ("empty_and", "InvalidFilter", "accepted"),
        ("empty_not", "MissingField", "Protocol"),
        ("trailing_data", "TrailingData", "TrailingData"),
        ("invalid_utf8_dn", "InvalidUtf8", "Protocol"),
        ("oversized_value", "MessageTooLong", "ResourceLimit"),
    ];
    for (case, (name, z_expected, k_expected)) in corpus::malformed().into_iter().zip(expected) {
        assert_eq!(case.name, name);
        let mut limits = ParseLimits::default();
        if name == "oversized_value" {
            limits.max_message_len = 32_768;
        }
        let z = Message::parse(&case.wire, limits, &mut [Frame::EMPTY; 32])
            .map(|_| "accepted".to_owned())
            .unwrap_or_else(|e| format!("{:?}", e.kind));
        let k = oracle::parse_exact_limited(&case.wire, 33, limits.max_message_len)
            .map(|_| "accepted".to_owned())
            .unwrap_or_else(|e| format!("{e:?}"));
        assert_eq!(z, z_expected, "zldap error class: {name}");
        assert_eq!(k, k_expected, "oracle error class: {name}");
    }
}
