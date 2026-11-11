use zldap::{Message, ParseLimits, ber::Frame};
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
    use ldap3_lber::structure::{PL, StructureTag};
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
    let cases = corpus::malformed();
    assert_eq!(
        cases.len(),
        expected.len(),
        "every rejection case needs an explicit expectation"
    );
    for (case, (name, z_expected, k_expected)) in cases.into_iter().zip(expected) {
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

#[test]
fn binary_assertion_is_preserved_and_oracle_utf8_limitation_is_explicit() {
    let wire = corpus::search(
        1,
        corpus::assertion(0xa3, b"jpegphoto", &[0xff, 0x00, 0x80]),
    );
    let message = Message::parse(&wire, ParseLimits::default(), &mut [Frame::EMPTY; 32]).unwrap();
    let zldap::Operation::SearchRequest(search) = message.operation else {
        panic!("search fixture")
    };
    let zldap::FilterKind::Equality { attribute, value } = search.filter.kind().unwrap() else {
        panic!("equality fixture")
    };
    assert_eq!(attribute, "jpegphoto");
    assert_eq!(value, &[0xff, 0x00, 0x80]);
    // LDAP AssertionValue is OCTET STRING; the reference maps it to String.
    // This valid-wire difference is kept out of the shared timing corpus.
    assert_eq!(
        oracle::parse_exact(&wire, 33),
        Err(oracle::Rejection::Protocol)
    );
}

#[test]
fn optional_fields_match_and_oracle_referral_loss_is_explicit() {
    use corpus::{container, integer, message, tlv};
    let fixtures = [
        container(
            0x30,
            &[
                integer(2, 10),
                tlv(0x42, b""),
                container(
                    0xa0,
                    &[container(
                        0x30,
                        &[
                            tlv(4, b"1.2.3.4"),
                            tlv(1, &[0xff]),
                            tlv(4, &[0xff, 0x00, 0x80]),
                        ],
                    )],
                ),
            ],
        ),
        message(
            11,
            container(
                0x61,
                &[
                    integer(10, 10),
                    tlv(4, b"dc=example,dc=org"),
                    tlv(4, b"follow referral"),
                    container(
                        0xa3,
                        &[tlv(4, b"ldap://directory.example.org/dc=example,dc=org")],
                    ),
                ],
            ),
        ),
        message(
            12,
            container(
                0x61,
                &[
                    integer(10, 14),
                    tlv(4, b""),
                    tlv(4, b"continue SASL"),
                    tlv(0x87, &[0xff, 0, 0x80]),
                ],
            ),
        ),
        message(
            13,
            container(
                0x65,
                &[
                    integer(10, 10),
                    tlv(4, b""),
                    tlv(4, b"referrals"),
                    container(
                        0xa3,
                        &[
                            tlv(4, b"ldap://first.example.org"),
                            tlv(4, b"ldap://second.example.org"),
                        ],
                    ),
                ],
            ),
        ),
    ];
    for wire in fixtures {
        let z = Message::parse(&wire, ParseLimits::default(), &mut [Frame::EMPTY; 32]).unwrap();
        let k = oracle::parse_exact(&wire, 33).unwrap();
        if z.id == 11 || z.id == 13 {
            let expected: &[&str] = if z.id == 11 {
                &["ldap://directory.example.org/dc=example,dc=org"]
            } else {
                &["ldap://first.example.org", "ldap://second.example.org"]
            };
            let z_referrals = match z.operation {
                zldap::Operation::BindResponse(response) => response.result.referrals,
                zldap::Operation::SearchResultDone(result) => result.referrals,
                _ => panic!("referral fixture"),
            };
            assert_eq!(
                z_referrals.map(Result::unwrap).collect::<Vec<_>>(),
                expected
            );
            let k_referrals = match &k.op {
                ldap3_proto::proto::LdapOp::BindResponse(response) => &response.res.referral,
                ldap3_proto::proto::LdapOp::SearchResultDone(result) => &result.referral,
                _ => panic!("referral fixture"),
            };
            assert!(
                k_referrals.is_empty(),
                "pinned oracle currently drops referral URLs"
            );
            encoding::with_input(z, |input| {
                let mut output = vec![0; input.encoded_len().unwrap()];
                input.encode(&mut output).unwrap();
                assert_eq!(output, wire, "zldap preserves the referral field");
            });
            continue;
        }
        equivalent(&wire);
        let mut oracle_bytes = bytes::BytesMut::new();
        oracle::encode(k, &mut oracle_bytes);
        encoding::with_input(z, |input| {
            let mut output = vec![0; input.encoded_len().unwrap()];
            input.encode(&mut output).unwrap();
            assert_eq!(output.as_slice(), oracle_bytes.as_ref());
        });
    }
}

#[test]
fn sasl_absent_and_empty_are_normalized_only_at_reference_boundary() {
    use corpus::{container, integer, message, tlv};
    let absent = message(
        1,
        container(
            0x60,
            &[
                integer(2, 3),
                tlv(4, b""),
                container(0xa3, &[tlv(4, b"EXTERNAL")]),
            ],
        ),
    );
    let empty = message(
        1,
        container(
            0x60,
            &[
                integer(2, 3),
                tlv(4, b""),
                container(0xa3, &[tlv(4, b"EXTERNAL"), tlv(4, b"")]),
            ],
        ),
    );
    for (wire, expected) in [(&absent, None), (&empty, Some(&b""[..]))] {
        let z = Message::parse(wire, ParseLimits::default(), &mut [Frame::EMPTY; 32]).unwrap();
        let zldap::Operation::BindRequest(request) = z.operation else {
            panic!("Bind fixture")
        };
        let zldap::Authentication::Sasl { credentials, .. } = request.authentication else {
            panic!("SASL fixture")
        };
        assert_eq!(credentials, expected);
        equivalent(wire);
    }
    assert_eq!(
        oracle::parse_exact(&absent, 33).unwrap(),
        oracle::parse_exact(&empty, 33).unwrap()
    );
}

#[test]
fn empty_sasl_mechanism_is_protocol_data_for_abort_negotiation() {
    use corpus::{container, integer, message, tlv};
    for credentials in [None, Some(&b""[..])] {
        let mut sasl = vec![tlv(4, b"")];
        if let Some(credentials) = credentials {
            sasl.push(tlv(4, credentials));
        }
        let wire = message(
            1,
            container(0x60, &[integer(2, 3), tlv(4, b""), container(0xa3, &sasl)]),
        );
        equivalent(&wire);
        let decoded =
            Message::parse(&wire, ParseLimits::default(), &mut [Frame::EMPTY; 32]).unwrap();
        encoding::with_input(decoded, |input| {
            let mut output = vec![0; input.encoded_len().unwrap()];
            input.encode(&mut output).unwrap();
            assert_eq!(output, wire);
        });
    }
}
