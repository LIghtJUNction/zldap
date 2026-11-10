//! Independent wire vectors and transactional typed-encoding regressions.
use zldap::ber::Frame;
use zldap::{
    Attribute, Authentication, BindRequest, ControlInput, DerefAliases, ErrorKind, Filter,
    FilterKind, Message, MessageInput, Operation, OperationInput, ParseLimits, ResultInput, Scope,
    SearchInput,
};

fn parse(bytes: &[u8]) -> Message<'_> {
    Message::parse(bytes, ParseLimits::default(), &mut [Frame::EMPTY; 64]).unwrap()
}

fn filter(bytes: &[u8]) -> Filter<'_> {
    Filter::parse(bytes, ParseLimits::default(), &mut [Frame::EMPTY; 64]).unwrap()
}

fn success() -> ResultInput<'static> {
    ResultInput {
        code: 0,
        matched_dn: "",
        diagnostic_message: "",
        referrals: &[],
    }
}

fn input(operation: OperationInput<'_>) -> MessageInput<'_> {
    MessageInput {
        id: 1,
        operation,
        controls: &[],
    }
}

fn encode(message: &MessageInput<'_>) -> Vec<u8> {
    let length = message.encoded_len().unwrap();
    let mut storage = vec![0xa5; length + 7];
    assert_eq!(message.encode(&mut storage).unwrap(), length);
    assert_eq!(&storage[length..], &[0xa5; 7]);
    storage.truncate(length);
    storage
}

fn rejected(message: &MessageInput<'_>, expected: ErrorKind) {
    assert_eq!(message.encoded_len().unwrap_err().kind, expected);
    let mut output = [0xa5; 512];
    assert_eq!(message.encode(&mut output).unwrap_err().kind, expected);
    assert_eq!(output, [0xa5; 512]);
    // Protocol validation precedes capacity checking, even for no storage.
    assert_eq!(message.encode(&mut []).unwrap_err().kind, expected);
}

fn minimal_operations() -> [(OperationInput<'static>, &'static [u8]); 6] {
    [
        (
            OperationInput::BindRequest(BindRequest {
                version: 3,
                name: "",
                authentication: Authentication::Simple(b""),
            }),
            b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
        ),
        (
            OperationInput::BindResponse {
                result: success(),
                server_sasl_credentials: None,
            },
            b"\x30\x0c\x02\x01\x01\x61\x07\x0a\x01\x00\x04\x00\x04\x00",
        ),
        (
            OperationInput::SearchRequest(SearchInput {
                base_dn: "",
                scope: Scope::Base,
                deref_aliases: DerefAliases::Never,
                size_limit: 0,
                time_limit: 0,
                types_only: false,
                filter: filter(b"\x87\x02cn"),
                attributes: &[],
            }),
            b"\x30\x1c\x02\x01\x01\x63\x17\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x02cn\x30\x00",
        ),
        (
            OperationInput::SearchResultEntry {
                object_name: "",
                attributes: &[],
            },
            b"\x30\x09\x02\x01\x01\x64\x04\x04\x00\x30\x00",
        ),
        (
            OperationInput::SearchResultDone(success()),
            b"\x30\x0c\x02\x01\x01\x65\x07\x0a\x01\x00\x04\x00\x04\x00",
        ),
        (
            OperationInput::UnbindRequest,
            b"\x30\x05\x02\x01\x01\x42\x00",
        ),
    ]
}

#[test]
fn every_operation_matches_independent_minimal_wire_vectors() {
    for (operation, expected) in minimal_operations() {
        let message = input(operation);
        assert_eq!(message.encoded_len().unwrap(), expected.len());
        let bytes = encode(&message);
        assert_eq!(bytes, expected);
        let decoded = parse(&bytes);
        assert_eq!(decoded.id, 1);
        assert_eq!(decoded.encoded(), expected);
        assert_eq!(decoded.controls.count(), 0);
        assert!(decoded.extensions.is_empty());
    }
}

#[test]
fn every_insufficient_capacity_preserves_the_entire_buffer() {
    for (operation, expected) in minimal_operations() {
        let message = input(operation);
        for capacity in 0..expected.len() {
            let mut bytes = vec![0xa5; expected.len() + 8];
            let error = message.encode(&mut bytes[..capacity]).unwrap_err();
            assert_eq!(error.kind, ErrorKind::BufferTooSmall);
            assert!(bytes.iter().all(|byte| *byte == 0xa5));
        }
        let mut exact = vec![0xa5; expected.len()];
        assert_eq!(message.encode(&mut exact).unwrap(), expected.len());
        assert_eq!(exact, expected);
    }
}

#[test]
fn message_id_sign_boundaries_use_minimal_positive_integer_bytes() {
    let cases: &[(u32, &[u8])] = &[
        (1, &[1]),
        (127, &[127]),
        (128, &[0, 128]),
        (255, &[0, 255]),
        (256, &[1, 0]),
        (32767, &[127, 255]),
        (32768, &[0, 128, 0]),
        (65535, &[0, 255, 255]),
        (65536, &[1, 0, 0]),
        (8_388_607, &[127, 255, 255]),
        (8_388_608, &[0, 128, 0, 0]),
        (i32::MAX as u32, &[127, 255, 255, 255]),
    ];
    for &(id, integer) in cases {
        let message = MessageInput {
            id,
            ..input(OperationInput::UnbindRequest)
        };
        let bytes = encode(&message);
        let mut expected = vec![0x30, (integer.len() + 4) as u8, 2, integer.len() as u8];
        expected.extend_from_slice(integer);
        expected.extend_from_slice(&[0x42, 0]);
        assert_eq!(bytes, expected);
        assert_eq!(parse(&bytes).id, id);
    }
    for id in [0, (i32::MAX as u32) + 1, u32::MAX] {
        rejected(
            &MessageInput {
                id,
                ..input(OperationInput::UnbindRequest)
            },
            ErrorKind::InvalidMessageId,
        );
    }
}

#[test]
fn sasl_credentials_distinguish_absence_empty_and_binary_data() {
    let mut encodings = Vec::new();
    for credentials in [None, Some(&b""[..]), Some(&b"\0\xffcredential"[..])] {
        let authentication = Authentication::Sasl {
            mechanism: "SCRAM-SHA-256",
            credentials,
        };
        let bytes = encode(&input(OperationInput::BindRequest(BindRequest {
            version: 3,
            name: "cn=测试,dc=example",
            authentication,
        })));
        match parse(&bytes).operation {
            Operation::BindRequest(request) => {
                assert_eq!(request.version, 3);
                assert_eq!(request.name, "cn=测试,dc=example");
                assert_eq!(request.authentication, authentication);
            }
            other => panic!("unexpected operation: {other:?}"),
        }
        encodings.push(bytes);
    }
    assert_eq!(encodings[1].len(), encodings[0].len() + 2);
    assert_ne!(encodings[0], encodings[1]);
}

#[test]
fn bind_response_preserves_sasl_tokens_and_protocol_result_fields() {
    for credentials in [None, Some(&b""[..]), Some(&b"\xff\0challenge"[..])] {
        let bytes = encode(&input(OperationInput::BindResponse {
            result: ResultInput {
                code: 14,
                matched_dn: "cn=bind",
                diagnostic_message: "continue SASL",
                referrals: &[],
            },
            server_sasl_credentials: credentials,
        }));
        match parse(&bytes).operation {
            Operation::BindResponse(response) => {
                assert_eq!(response.result.code, 14);
                assert_eq!(response.result.matched_dn, "cn=bind");
                assert_eq!(response.result.diagnostic_message, "continue SASL");
                assert_eq!(response.server_sasl_credentials, credentials);
            }
            other => panic!("unexpected operation: {other:?}"),
        }
    }
}

#[test]
fn controls_preserve_order_defaults_and_optional_empty_values() {
    let controls = [
        ControlInput {
            oid: "1.2.3",
            critical: false,
            value: None,
        },
        ControlInput {
            oid: "1.2.4",
            critical: false,
            value: Some(b""),
        },
        ControlInput {
            oid: "1.2.5",
            critical: true,
            value: Some(b"\0\xff"),
        },
    ];
    let bytes = encode(&MessageInput {
        controls: &controls,
        ..input(OperationInput::UnbindRequest)
    });
    let decoded: Vec<_> = parse(&bytes).controls.map(Result::unwrap).collect();
    assert_eq!(decoded.len(), controls.len());
    for (actual, expected) in decoded.iter().zip(controls) {
        assert_eq!(actual.oid, expected.oid);
        assert_eq!(actual.critical, expected.critical);
        assert_eq!(actual.value, expected.value);
    }

    let single = [ControlInput {
        oid: "1.2",
        critical: false,
        value: None,
    }];
    let bytes = encode(&MessageInput {
        controls: &single,
        ..input(OperationInput::UnbindRequest)
    });
    // DEFAULT FALSE is absent, not encoded as an extra BOOLEAN.
    assert_eq!(
        bytes,
        b"\x30\x0e\x02\x01\x01\x42\x00\xa0\x07\x30\x05\x04\x031.2"
    );
}

#[test]
fn search_round_trips_enums_limits_boolean_attributes_and_filter() {
    let search_filter = filter(b"\xa3\x09\x04\x02cn\x04\x03a\0\xff");
    for scope in [Scope::Base, Scope::OneLevel, Scope::Subtree] {
        for deref in [
            DerefAliases::Never,
            DerefAliases::InSearching,
            DerefAliases::FindingBase,
            DerefAliases::Always,
        ] {
            for types_only in [false, true] {
                let bytes = encode(&input(OperationInput::SearchRequest(SearchInput {
                    base_dn: "dc=example,dc=org",
                    scope,
                    deref_aliases: deref,
                    size_limit: i32::MAX as u32,
                    time_limit: 128,
                    types_only,
                    filter: search_filter,
                    attributes: &["*", "+", "1.1", "cn;lang-en"],
                })));
                match parse(&bytes).operation {
                    Operation::SearchRequest(search) => {
                        assert_eq!(search.base_dn, "dc=example,dc=org");
                        assert_eq!(search.scope, scope);
                        assert_eq!(search.deref_aliases, deref);
                        assert_eq!(search.size_limit, i32::MAX as u32);
                        assert_eq!(search.time_limit, 128);
                        assert_eq!(search.types_only, types_only);
                        assert_eq!(
                            search
                                .attributes
                                .collect::<zldap::Result<Vec<_>>>()
                                .unwrap(),
                            ["*", "+", "1.1", "cn;lang-en"]
                        );
                        match search.filter.kind().unwrap() {
                            FilterKind::Equality { attribute, value } => {
                                assert_eq!(attribute, "cn");
                                assert_eq!(value, b"a\0\xff");
                            }
                            other => panic!("unexpected filter: {other:?}"),
                        }
                    }
                    other => panic!("unexpected operation: {other:?}"),
                }
            }
        }
    }
}

#[test]
fn entries_keep_empty_sets_binary_values_and_attribute_order() {
    let attributes = [
        Attribute {
            description: "cn",
            values: &[b"Alice", b"", b"A"],
        },
        Attribute {
            description: "jpegPhoto;binary",
            values: &[b"\0\xff\x80"],
        },
        Attribute {
            description: "description",
            values: &[],
        },
    ];
    let bytes = encode(&input(OperationInput::SearchResultEntry {
        object_name: "cn=Alice,dc=example",
        attributes: &attributes,
    }));
    let Operation::SearchResultEntry(entry) = parse(&bytes).operation else {
        panic!("expected entry")
    };
    assert_eq!(entry.object_name, "cn=Alice,dc=example");
    let decoded: Vec<_> = entry.attributes.map(Result::unwrap).collect();
    assert_eq!(decoded.len(), attributes.len());
    for (actual, expected) in decoded.iter().zip(attributes) {
        assert_eq!(actual.description, expected.description);
        assert_eq!(
            actual.values.collect::<zldap::Result<Vec<_>>>().unwrap(),
            expected.values
        );
    }
}

#[test]
fn large_attribute_values_round_trip_with_exact_capacity_and_limits() {
    let mut value = vec![0xff; 128 * 1024];
    value[0] = 0;
    value[128] = 0x80;
    let attributes = [Attribute {
        description: "jpegPhoto",
        values: &[&value],
    }];
    let message = input(OperationInput::SearchResultEntry {
        object_name: "cn=large",
        attributes: &attributes,
    });
    let size = message.encoded_len().unwrap();
    let mut short = vec![0xa5; size - 1];
    assert_eq!(
        message.encode(&mut short).unwrap_err().kind,
        ErrorKind::BufferTooSmall
    );
    assert!(short.iter().all(|byte| *byte == 0xa5));
    let bytes = encode(&message);
    assert_eq!(&bytes[..2], &[0x30, 0x83]);
    let Operation::SearchResultEntry(entry) = parse(&bytes).operation else {
        panic!("expected entry")
    };
    let actual = entry
        .attributes
        .into_iter()
        .next()
        .unwrap()
        .unwrap()
        .values
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(actual, value);
    let limits = ParseLimits {
        max_string_len: value.len() - 1,
        ..ParseLimits::default()
    };
    assert_eq!(
        Message::parse(&bytes, limits, &mut [Frame::EMPTY; 64])
            .unwrap_err()
            .kind,
        ErrorKind::StringTooLong
    );
}

#[test]
fn results_preserve_referrals_for_bind_and_search_done() {
    let result = ResultInput {
        code: 10,
        matched_dn: "dc=example",
        diagnostic_message: "referral",
        referrals: &["ldap://one.example/dc=example", "ldap:///dc=other"],
    };
    for operation in [
        OperationInput::BindResponse {
            result,
            server_sasl_credentials: Some(b""),
        },
        OperationInput::SearchResultDone(result),
    ] {
        let bytes = encode(&input(operation));
        let decoded = match parse(&bytes).operation {
            Operation::BindResponse(bind) => bind.result,
            Operation::SearchResultDone(done) => done,
            other => panic!("unexpected operation: {other:?}"),
        };
        assert_eq!(decoded.code, result.code);
        assert_eq!(decoded.matched_dn, result.matched_dn);
        assert_eq!(decoded.diagnostic_message, result.diagnostic_message);
        assert_eq!(
            decoded
                .referrals
                .collect::<zldap::Result<Vec<_>>>()
                .unwrap(),
            result.referrals
        );
    }
}

#[test]
fn invalid_bind_versions_and_sasl_mechanisms_are_transactional() {
    for version in [0, 128, 255] {
        rejected(
            &input(OperationInput::BindRequest(BindRequest {
                version,
                name: "",
                authentication: Authentication::Simple(b"secret"),
            })),
            ErrorKind::InvalidVersion,
        );
    }
    for mechanism in ["", "plain", "PLAIN ", "A!", "AAAAAAAAAAAAAAAAAAAAA"] {
        rejected(
            &input(OperationInput::BindRequest(BindRequest {
                version: 3,
                name: "",
                authentication: Authentication::Sasl {
                    mechanism,
                    credentials: Some(b"secret"),
                },
            })),
            ErrorKind::InvalidValue,
        );
    }
}

#[test]
fn invalid_controls_attributes_referrals_and_integers_are_transactional() {
    for oid in ["", "cn", ".1", "1.", "1..2", "1.02", "01.2"] {
        rejected(
            &MessageInput {
                controls: &[ControlInput {
                    oid,
                    critical: true,
                    value: Some(b"private"),
                }],
                ..input(OperationInput::UnbindRequest)
            },
            ErrorKind::InvalidOid,
        );
    }
    for description in ["", "123", "*", "cn;", "cn;;binary", "cn@x", "-cn"] {
        rejected(
            &input(OperationInput::SearchResultEntry {
                object_name: "cn=x",
                attributes: &[Attribute {
                    description,
                    values: &[b"value"],
                }],
            }),
            ErrorKind::InvalidAttribute,
        );
    }
    let search = SearchInput {
        base_dn: "",
        scope: Scope::Base,
        deref_aliases: DerefAliases::Never,
        size_limit: 0,
        time_limit: 0,
        types_only: false,
        filter: filter(b"\x87\x02cn"),
        attributes: &[],
    };
    rejected(
        &input(OperationInput::SearchRequest(SearchInput {
            attributes: &["cn", "bad!"],
            ..search
        })),
        ErrorKind::InvalidAttribute,
    );
    rejected(
        &input(OperationInput::SearchRequest(SearchInput {
            size_limit: u32::MAX,
            ..search
        })),
        ErrorKind::IntegerOverflow,
    );
    rejected(
        &input(OperationInput::SearchRequest(SearchInput {
            time_limit: (i32::MAX as u32) + 1,
            ..search
        })),
        ErrorKind::IntegerOverflow,
    );
    rejected(
        &input(OperationInput::SearchResultDone(ResultInput {
            code: u32::MAX,
            ..success()
        })),
        ErrorKind::IntegerOverflow,
    );
    rejected(
        &input(OperationInput::SearchResultDone(ResultInput {
            referrals: &[""],
            ..success()
        })),
        ErrorKind::InvalidValue,
    );
}

#[test]
fn validated_filter_extension_and_ber_length_bytes_are_preserved() {
    // The nested assertion uses a legal nonminimal BER length and an unknown
    // trailing extension. Neither field may silently disappear in a new Search.
    let wire = b"\xa0\x11\xa3\x81\x0e\x04\x81\x02cn\x04\x03a\0\xff\x89\x02xy";
    let original = filter(wire);
    let bytes = encode(&input(OperationInput::SearchRequest(SearchInput {
        base_dn: "",
        scope: Scope::Subtree,
        deref_aliases: DerefAliases::Never,
        size_limit: 0,
        time_limit: 0,
        types_only: false,
        filter: original,
        attributes: &[],
    })));
    let Operation::SearchRequest(search) = parse(&bytes).operation else {
        panic!("expected search")
    };
    assert_eq!(search.filter.encoded(), wire);
}

#[test]
fn raw_copy_keeps_extensions_and_is_transactional_at_every_capacity() {
    let original = b"\x30\x08\x02\x01\x01\x42\x00\x89\x01\xff";
    let message = parse(original);
    for capacity in 0..original.len() {
        let mut bytes = [0xa5; 32];
        assert_eq!(
            message
                .copy_encoded(&mut bytes[..capacity])
                .unwrap_err()
                .kind,
            ErrorKind::BufferTooSmall
        );
        assert_eq!(bytes, [0xa5; 32]);
    }
    let mut output = [0xa5; 32];
    assert_eq!(message.copy_encoded(&mut output).unwrap(), original.len());
    assert_eq!(&output[..original.len()], original);
    assert!(output[original.len()..].iter().all(|byte| *byte == 0xa5));
}
