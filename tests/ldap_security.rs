//! Wire-level security regressions. Fixture construction deliberately bypasses
//! the typed encoder so malformed messages reach the decoder unchanged.
use zldap::ber::{Class, Frame, Tag, Writer};
use zldap::{
    Authentication, ErrorKind, Filter, FilterKind, Message, Operation, ParseLimits, Substring,
};

fn tlv(identifier: u8, bytes: &[u8]) -> Vec<u8> {
    let class = match identifier >> 6 {
        0 => Class::Universal,
        1 => Class::Application,
        2 => Class::Context,
        _ => Class::Private,
    };
    let tag = Tag::new(class, identifier & 0x20 != 0, u32::from(identifier & 31));
    let mut storage = vec![0; bytes.len() + 16];
    let mut writer = Writer::new(&mut storage);
    writer.write_tlv(tag, bytes).unwrap();
    writer.finish().to_vec()
}

fn group(identifier: u8, fields: &[Vec<u8>]) -> Vec<u8> {
    tlv(identifier, &fields.concat())
}

fn integer(value: i64) -> Vec<u8> {
    let mut storage = [0; 16];
    let mut writer = Writer::new(&mut storage);
    writer.write_integer(value).unwrap();
    writer.finish().to_vec()
}

fn enumerated(value: i64) -> Vec<u8> {
    let mut bytes = integer(value);
    bytes[0] = 10;
    bytes
}

fn octets(value: &[u8]) -> Vec<u8> {
    tlv(4, value)
}
fn sequence(fields: &[Vec<u8>]) -> Vec<u8> {
    group(0x30, fields)
}
fn present(name: &[u8]) -> Vec<u8> {
    tlv(0x87, name)
}
fn assertion(identifier: u8, name: &[u8], value: &[u8]) -> Vec<u8> {
    group(identifier, &[octets(name), octets(value)])
}
fn message(id: i64, operation: Vec<u8>) -> Vec<u8> {
    sequence(&[integer(id), operation])
}
fn bind_operation(version: i64, name: &[u8], auth: Vec<u8>) -> Vec<u8> {
    group(0x60, &[integer(version), octets(name), auth])
}
fn bind(password: &[u8]) -> Vec<u8> {
    message(1, bind_operation(3, b"", tlv(0x80, password)))
}
fn search_fields(filter: Vec<u8>) -> Vec<Vec<u8>> {
    vec![
        octets(b"dc=example,dc=org"),
        enumerated(2),
        enumerated(0),
        integer(0),
        integer(0),
        tlv(1, &[0]),
        filter,
        sequence(&[]),
    ]
}
fn search(filter: Vec<u8>) -> Vec<u8> {
    message(2, group(0x63, &search_fields(filter)))
}
fn attribute(name: &[u8], values: &[Vec<u8>]) -> Vec<u8> {
    sequence(&[octets(name), group(0x31, values)])
}
fn entry(attributes: &[Vec<u8>]) -> Vec<u8> {
    message(3, group(0x64, &[octets(b"cn=alice"), sequence(attributes)]))
}
fn result_fields(code: i64) -> Vec<Vec<u8>> {
    vec![enumerated(code), octets(b""), octets(b"")]
}
fn parse(bytes: &[u8]) -> zldap::Result<Message<'_>> {
    Message::parse(bytes, ParseLimits::default(), &mut [Frame::EMPTY; 128])
}
fn error(bytes: &[u8]) -> ErrorKind {
    parse(bytes).unwrap_err().kind
}
fn filter_error(bytes: &[u8]) -> ErrorKind {
    Filter::parse(bytes, ParseLimits::default(), &mut [Frame::EMPTY; 128])
        .unwrap_err()
        .kind
}

#[test]
fn empty_and_binary_credentials_are_protocol_data() {
    for password in [&[][..], &[0, 0xff, 0x80, b'p'][..]] {
        let encoded = bind(password);
        let parsed = parse(&encoded).unwrap();
        let Operation::BindRequest(request) = parsed.operation else {
            panic!("wrong operation")
        };
        assert_eq!(request.version, 3);
        assert_eq!(request.name, "");
        assert_eq!(request.authentication, Authentication::Simple(password));
        assert_eq!(parsed.encoded().as_ptr(), encoded.as_ptr());
        let Authentication::Simple(borrowed) = request.authentication else {
            unreachable!()
        };
        assert!(borrowed.as_ptr() >= encoded.as_ptr());
        assert!(borrowed.as_ptr() <= encoded.as_ptr().wrapping_add(encoded.len()));
    }
}

#[test]
fn sasl_distinguishes_absent_empty_and_binary_credentials() {
    for credentials in [None, Some(&[][..]), Some(&[0xff, 0, 0x80][..])] {
        let mut fields = vec![octets(b"PLAIN")];
        if let Some(value) = credentials {
            fields.push(octets(value));
        }
        let encoded = message(1, bind_operation(3, b"", group(0xa3, &fields)));
        let Operation::BindRequest(request) = parse(&encoded).unwrap().operation else {
            panic!("wrong operation")
        };
        assert_eq!(
            request.authentication,
            Authentication::Sasl {
                mechanism: "PLAIN",
                credentials
            }
        );
    }
    for mechanism in [
        &[][..],
        &b"plain"[..],
        &b"A B"[..],
        &b"ABCDEFGHIJKLMNOPQRSTU"[..],
    ] {
        let encoded = message(1, bind_operation(3, b"", group(0xa3, &[octets(mechanism)])));
        assert_eq!(error(&encoded), ErrorKind::InvalidValue);
    }
    let bad_utf8 = message(1, bind_operation(3, b"", group(0xa3, &[octets(&[0xff])])));
    assert_eq!(error(&bad_utf8), ErrorKind::InvalidUtf8);
    let duplicate = message(
        1,
        bind_operation(
            3,
            b"",
            group(0xa3, &[octets(b"PLAIN"), octets(b"one"), octets(b"two")]),
        ),
    );
    assert_eq!(error(&duplicate), ErrorKind::UnexpectedTag);
}

#[test]
fn ids_versions_and_application_tags_are_checked() {
    assert_eq!(
        error(&message(0, tlv(0x42, &[]))),
        ErrorKind::InvalidMessageId
    );
    for id in [-1, i64::from(i32::MAX) + 1, i64::MAX] {
        assert_eq!(
            error(&message(id, tlv(0x42, &[]))),
            ErrorKind::IntegerOverflow
        );
    }
    parse(&message(i64::from(i32::MAX), tlv(0x42, &[]))).unwrap();
    for version in [0, 128] {
        assert_eq!(
            error(&message(1, bind_operation(version, b"", tlv(0x80, &[])))),
            ErrorKind::InvalidVersion
        );
    }
    assert_eq!(
        error(&message(1, bind_operation(-1, b"", tlv(0x80, &[])))),
        ErrorKind::IntegerOverflow
    );
    // Versions are protocol data; the codec does not decide server support.
    for version in [1, 2, 3, 127] {
        parse(&message(1, bind_operation(version, b"", tlv(0x80, &[])))).unwrap();
    }
    for op in [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 19, 23, 24, 25] {
        assert_eq!(
            error(&message(1, tlv(0x60 | op, &[]))),
            ErrorKind::UnsupportedOperation(u32::from(op))
        );
    }
    assert_eq!(error(&message(1, sequence(&[]))), ErrorKind::UnexpectedTag);
    assert_eq!(error(&message(1, tlv(0x40, &[]))), ErrorKind::UnexpectedTag);
    assert_eq!(
        error(&message(1, bind_operation(3, b"", tlv(0x81, &[])))),
        ErrorKind::UnsupportedAuthentication(1)
    );
}

#[test]
fn unbind_is_exactly_primitive_empty_protocol_data() {
    assert!(matches!(
        parse(&message(1, tlv(0x42, &[]))).unwrap().operation,
        Operation::UnbindRequest
    ));
    assert_eq!(error(&message(1, tlv(0x42, &[0]))), ErrorKind::InvalidValue);
    assert_eq!(error(&message(1, tlv(0x62, &[]))), ErrorKind::UnexpectedTag);
}

#[test]
fn metadata_utf8_and_binary_values_have_distinct_rules() {
    assert_eq!(
        error(&message(1, bind_operation(3, &[0xff], tlv(0x80, &[])))),
        ErrorKind::InvalidUtf8
    );
    let mut fields = search_fields(present(b"cn"));
    fields[0] = octets(&[0xf0, 0x80, 0x80, 0x80]);
    assert_eq!(
        error(&message(1, group(0x63, &fields))),
        ErrorKind::InvalidUtf8
    );
    let binary = [0, 0xff, 0xc0, 0x80];
    let encoded = entry(&[attribute(
        b"jpegPhoto;binary",
        &[octets(&binary), octets(&[])],
    )]);
    let Operation::SearchResultEntry(entry) = parse(&encoded).unwrap().operation else {
        panic!("wrong operation")
    };
    let attr = entry.attributes.into_iter().next().unwrap().unwrap();
    assert_eq!(attr.description, "jpegPhoto;binary");
    assert_eq!(
        attr.values.collect::<zldap::Result<Vec<_>>>().unwrap(),
        [&binary[..], &[][..]]
    );
    let encoded = search(assertion(0xa3, b"userPassword", &binary));
    let Operation::SearchRequest(request) = parse(&encoded).unwrap().operation else {
        panic!("wrong operation")
    };
    assert!(
        matches!(request.filter.kind().unwrap(), FilterKind::Equality { value, .. } if value == binary)
    );
}

#[test]
fn every_prefix_of_representative_frames_is_truncated() {
    let corpus = [
        bind(b"secret"),
        message(
            1,
            bind_operation(3, b"", group(0xa3, &[octets(b"EXTERNAL")])),
        ),
        search(group(
            0xa0,
            &[present(b"cn"), assertion(0xa3, b"uid", b"alice")],
        )),
        entry(&[attribute(b"photo", &[octets(&vec![0x42; 260])])]),
        message(1, group(0x65, &result_fields(0))),
    ];
    for encoded in corpus {
        parse(&encoded).unwrap();
        for len in 0..encoded.len() {
            assert_eq!(
                error(&encoded[..len]),
                ErrorKind::Truncated,
                "prefix {len} of {}",
                encoded.len()
            );
        }
    }
}

#[test]
fn search_enumerations_limits_and_boolean_encodings_are_checked() {
    for (index, field, expected) in [
        (1, enumerated(3), ErrorKind::InvalidEnumeration),
        (2, enumerated(4), ErrorKind::InvalidEnumeration),
        (1, enumerated(-1), ErrorKind::IntegerOverflow),
        (2, enumerated(-1), ErrorKind::IntegerOverflow),
        (3, integer(-1), ErrorKind::IntegerOverflow),
        (
            4,
            integer(i64::from(i32::MAX) + 1),
            ErrorKind::IntegerOverflow,
        ),
        (1, integer(1), ErrorKind::UnexpectedTag),
        (3, enumerated(1), ErrorKind::UnexpectedTag),
        (5, octets(&[0]), ErrorKind::UnexpectedTag),
    ] {
        let mut fields = search_fields(present(b"cn"));
        fields[index] = field;
        assert_eq!(error(&message(1, group(0x63, &fields))), expected);
    }
    for value in [0, 1, 0x7f, 0x80, 0xff] {
        let mut fields = search_fields(present(b"cn"));
        fields[5] = tlv(1, &[value]);
        let encoded = message(1, group(0x63, &fields));
        if value == 0 || value == 0xff {
            parse(&encoded).unwrap();
        } else {
            assert_eq!(error(&encoded), ErrorKind::InvalidBoolean);
        }
    }
}

#[test]
fn attribute_selections_validate_every_name_before_returning() {
    let mut fields = search_fields(present(b"cn"));
    fields[7] = sequence(&[
        octets(b"*"),
        octets(b"+"),
        octets(b"1.1"),
        octets(b"cn;lang-en"),
        octets(b"1.2.3"),
    ]);
    parse(&message(1, group(0x63, &fields))).unwrap();
    for name in [
        &[][..],
        &b"cn;"[..],
        &b"cn_"[..],
        &b"01.2"[..],
        &b"cn;;binary"[..],
    ] {
        fields[7] = sequence(&[octets(b"cn"), octets(name)]);
        assert_eq!(
            error(&message(1, group(0x63, &fields))),
            ErrorKind::InvalidAttribute
        );
    }
    fields[7] = sequence(&[octets(b"cn"), octets(&[0xff])]);
    assert_eq!(
        error(&message(1, group(0x63, &fields))),
        ErrorKind::InvalidUtf8
    );
}

#[test]
fn late_result_attributes_and_values_are_eagerly_validated() {
    let good = attribute(b"cn", &[octets(b"Alice")]);
    let bad_name = attribute(b"", &[octets(b"late")]);
    assert_eq!(
        error(&entry(&[good.clone(), bad_name])),
        ErrorKind::InvalidAttribute
    );
    let bad_value = attribute(b"sn", &[octets(b"valid"), integer(1)]);
    assert_eq!(
        error(&entry(&[good.clone(), bad_value])),
        ErrorKind::UnexpectedTag
    );
    let bad_utf8 = attribute(&[0xff], &[octets(b"late")]);
    assert_eq!(error(&entry(&[good, bad_utf8])), ErrorKind::InvalidUtf8);
    parse(&entry(&[])).unwrap();
    parse(&entry(&[attribute(b"cn", &[])])).unwrap();
}

#[test]
fn logical_filters_reject_missing_children_and_validate_all_branches() {
    assert_eq!(filter_error(&group(0xa0, &[])), ErrorKind::InvalidFilter);
    assert_eq!(filter_error(&group(0xa1, &[])), ErrorKind::InvalidFilter);
    assert_eq!(filter_error(&group(0xa2, &[])), ErrorKind::MissingField);
    assert_eq!(
        filter_error(&group(0xa2, &[present(b"cn"), present(b"sn")])),
        ErrorKind::TrailingData
    );
    assert_eq!(
        filter_error(&group(0xa2, &[tlv(1, &[0])])),
        ErrorKind::InvalidFilter
    );
    assert_eq!(
        error(&search(group(0xa0, &[present(b"cn"), present(b"")]))),
        ErrorKind::InvalidAttribute
    );
    assert_eq!(
        error(&search(group(
            0xa0,
            &[
                present(b"cn"),
                group(0xa1, &[present(b"sn"), tlv(0xaa, &[])])
            ]
        ))),
        ErrorKind::InvalidFilter
    );
}

#[test]
fn nested_filter_events_have_correct_depth_and_bounded_workspace() {
    let encoded = group(
        0xa0,
        &[
            present(b"cn"),
            group(
                0xa1,
                &[
                    assertion(0xa3, b"sn", b"Smith"),
                    group(0xa2, &[present(b"uid")]),
                ],
            ),
            assertion(0xa5, b"age", b"18"),
        ],
    );
    let filter = Filter::parse(&encoded, ParseLimits::default(), &mut [Frame::EMPTY; 32]).unwrap();
    let mut slots = [0; 8];
    let depths = filter
        .events(&mut slots)
        .map(|event| event.unwrap().depth)
        .collect::<Vec<_>>();
    assert_eq!(depths, [0, 1, 1, 2, 2, 3, 1]);
    assert_eq!(filter.children().unwrap().count(), 3);
    let mut none = [];
    let mut events = filter.events(&mut none);
    assert_eq!(
        events.next().unwrap().unwrap_err().kind,
        ErrorKind::WorkspaceTooSmall
    );
    assert!(events.next().is_none());
    let encoded = present(b"cn");
    let leaf = Filter::parse(&encoded, ParseLimits::default(), &mut []).unwrap();
    assert_eq!(leaf.events(&mut []).next().unwrap().unwrap().depth, 0);
    assert_eq!(leaf.children().unwrap().count(), 0);
}

#[test]
fn substring_order_cardinality_and_binary_parts_are_checked() {
    let valid = group(
        0xa4,
        &[
            octets(b"cn"),
            sequence(&[tlv(0x80, &[0xff]), tlv(0x81, &[]), tlv(0x82, &[0])]),
        ],
    );
    let filter = Filter::parse(&valid, ParseLimits::default(), &mut [Frame::EMPTY; 8]).unwrap();
    let FilterKind::Substrings {
        attribute,
        components,
    } = filter.kind().unwrap()
    else {
        panic!("wrong kind")
    };
    assert_eq!(attribute, "cn");
    assert_eq!(
        components.collect::<zldap::Result<Vec<_>>>().unwrap(),
        [
            Substring::Initial(&[0xff]),
            Substring::Any(&[]),
            Substring::Final(&[0])
        ]
    );
    for parts in [
        vec![],
        vec![tlv(0x80, b"a"), tlv(0x80, b"b")],
        vec![tlv(0x81, b"a"), tlv(0x80, b"b")],
        vec![tlv(0x82, b"a"), tlv(0x81, b"b")],
        vec![tlv(0x82, b"a"), tlv(0x82, b"b")],
        vec![tlv(0x83, b"a")],
    ] {
        assert_eq!(
            filter_error(&group(0xa4, &[octets(b"cn"), sequence(&parts)])),
            ErrorKind::InvalidFilter
        );
    }
}

#[test]
fn extensible_filter_optional_fields_are_ordered_and_distinct() {
    let encoded = group(
        0xa9,
        &[
            tlv(0x81, b"caseIgnoreMatch"),
            tlv(0x82, b"cn"),
            tlv(0x83, &[0xff]),
            tlv(0x84, &[0xff]),
        ],
    );
    let filter = Filter::parse(&encoded, ParseLimits::default(), &mut [Frame::EMPTY; 8]).unwrap();
    assert!(matches!(
        filter.kind().unwrap(),
        FilterKind::ExtensibleMatch {
            matching_rule: Some("caseIgnoreMatch"),
            attribute: Some("cn"),
            value: [0xff],
            dn_attributes: true
        }
    ));
    for fields in [
        vec![tlv(0x83, b"x")],
        vec![tlv(0x82, b"cn"), tlv(0x82, b"sn"), tlv(0x83, b"x")],
        vec![tlv(0x82, b"cn"), tlv(0x81, b"1.2.3"), tlv(0x83, b"x")],
        vec![tlv(0x82, b"cn"), tlv(0x83, b"x"), tlv(0x83, b"y")],
    ] {
        assert_eq!(
            filter_error(&group(0xa9, &fields)),
            ErrorKind::InvalidFilter
        );
    }
    assert_eq!(
        filter_error(&group(0xa9, &[tlv(0x82, b"cn")])),
        ErrorKind::MissingField
    );
    assert_eq!(
        filter_error(&group(0xa9, &[tlv(0x81, b"01.2"), tlv(0x83, b"x")])),
        ErrorKind::InvalidOid
    );
    assert_eq!(
        filter_error(&group(
            0xa9,
            &[tlv(0x82, b"cn"), tlv(0x83, b"x"), tlv(0x84, &[1])]
        )),
        ErrorKind::InvalidBoolean
    );
}

#[test]
fn controls_preserve_criticality_and_absent_vs_empty_values() {
    let controls = group(
        0xa0,
        &[
            sequence(&[octets(b"1.2.3")]),
            sequence(&[octets(b"1.2.4"), tlv(1, &[0xff]), octets(&[])]),
            sequence(&[octets(b"1.2.5"), octets(&[0xff, 0])]),
        ],
    );
    let encoded = sequence(&[integer(1), tlv(0x42, &[]), controls]);
    let parsed = parse(&encoded).unwrap();
    let values = parsed.controls.collect::<zldap::Result<Vec<_>>>().unwrap();
    assert_eq!(values.len(), 3);
    assert_eq!(
        (values[0].oid, values[0].critical, values[0].value),
        ("1.2.3", false, None)
    );
    assert_eq!(
        (values[1].oid, values[1].critical, values[1].value),
        ("1.2.4", true, Some(&[][..]))
    );
    assert_eq!(values[2].value, Some(&[0xff, 0][..]));
}

#[test]
fn malformed_late_controls_cannot_hide_behind_unconsumed_iterators() {
    for (control, expected) in [
        (sequence(&[]), ErrorKind::MissingField),
        (sequence(&[octets(b"not-an-oid")]), ErrorKind::InvalidOid),
        (sequence(&[octets(b"1.02")]), ErrorKind::InvalidOid),
        (
            sequence(&[octets(b"1.2"), tlv(1, &[1])]),
            ErrorKind::InvalidBoolean,
        ),
        (
            sequence(&[octets(b"1.2"), octets(b"x"), tlv(1, &[0])]),
            ErrorKind::UnexpectedTag,
        ),
        (
            sequence(&[octets(b"1.2"), octets(b"x"), octets(b"y")]),
            ErrorKind::UnexpectedTag,
        ),
    ] {
        let controls = group(0xa0, &[sequence(&[octets(b"1.2.3")]), control]);
        assert_eq!(
            error(&sequence(&[integer(1), tlv(0x42, &[]), controls])),
            expected
        );
    }
    assert_eq!(
        error(&sequence(&[integer(1), tlv(0x42, &[]), group(0xa0, &[])])),
        ErrorKind::InvalidValue
    );
}

#[test]
fn result_referrals_and_sasl_response_bytes_are_eagerly_validated() {
    let mut fields = result_fields(10);
    fields.push(group(
        0xa3,
        &[
            octets(b"ldap://one.example/"),
            octets(b"ldap://two.example/"),
        ],
    ));
    fields.push(tlv(0x87, &[0xff, 0]));
    let encoded = message(1, group(0x61, &fields));
    let Operation::BindResponse(response) = parse(&encoded).unwrap().operation else {
        panic!("wrong operation")
    };
    assert_eq!(response.result.code, 10);
    assert_eq!(
        response
            .result
            .referrals
            .collect::<zldap::Result<Vec<_>>>()
            .unwrap(),
        ["ldap://one.example/", "ldap://two.example/"]
    );
    assert_eq!(response.server_sasl_credentials, Some(&[0xff, 0][..]));
    for (refs, expected) in [
        (vec![], ErrorKind::InvalidValue),
        (vec![octets(b"")], ErrorKind::InvalidValue),
        (
            vec![octets(b"ldap://one.example/"), octets(&[0xff])],
            ErrorKind::InvalidUtf8,
        ),
        (vec![integer(1)], ErrorKind::UnexpectedTag),
    ] {
        let mut fields = result_fields(10);
        fields.push(group(0xa3, &refs));
        assert_eq!(error(&message(1, group(0x65, &fields))), expected);
    }
    // Unknown result codes are retained for protocol extension handling.
    parse(&message(1, group(0x65, &result_fields(999)))).unwrap();
}

#[test]
fn duplicate_fields_and_out_of_order_optionals_are_rejected() {
    let mut fields = result_fields(10);
    fields.push(group(0xa3, &[octets(b"ldap://one.example/")]));
    fields.push(group(0xa3, &[octets(b"ldap://two.example/")]));
    assert_eq!(
        error(&message(1, group(0x65, &fields))),
        ErrorKind::UnexpectedTag
    );
    let mut fields = result_fields(0);
    fields.push(tlv(0x87, b"credentials"));
    fields.push(group(0xa3, &[octets(b"ldap://one.example/")]));
    assert_eq!(
        error(&message(1, group(0x61, &fields))),
        ErrorKind::UnexpectedTag
    );
    let extra_id = sequence(&[integer(1), tlv(0x42, &[]), integer(2)]);
    assert_eq!(error(&extra_id), ErrorKind::UnexpectedTag);
    let controls = group(0xa0, &[sequence(&[octets(b"1.2")])]);
    let repeated_controls = sequence(&[integer(1), tlv(0x42, &[]), controls.clone(), controls]);
    assert_eq!(error(&repeated_controls), ErrorKind::UnexpectedTag);
}

#[test]
fn default_false_fields_must_be_omitted_from_ldap_encoding() {
    let control = sequence(&[octets(b"1.2.3"), tlv(1, &[0])]);
    let encoded = sequence(&[integer(1), tlv(0x42, &[]), group(0xa0, &[control])]);
    assert_eq!(error(&encoded), ErrorKind::InvalidValue);
    let filter = group(
        0xa9,
        &[tlv(0x82, b"cn"), tlv(0x83, b"Alice"), tlv(0x84, &[0])],
    );
    assert_eq!(filter_error(&filter), ErrorKind::InvalidValue);
    // Search typesOnly has no DEFAULT: explicitly encoded false is required.
    parse(&search(present(b"cn"))).unwrap();
}

#[test]
fn referral_presence_is_tied_to_its_result_code() {
    assert_eq!(
        error(&message(1, group(0x65, &result_fields(10)))),
        ErrorKind::InvalidValue
    );
    for code in [0, 49, 999] {
        let mut fields = result_fields(code);
        fields.push(group(0xa3, &[octets(b"ldap://one.example/")]));
        assert_eq!(
            error(&message(1, group(0x65, &fields))),
            ErrorKind::InvalidValue
        );
    }
}

#[test]
fn trailing_integer_is_unknown_in_result_and_entry_schemas() {
    for identifier in [0x61, 0x65] {
        let mut fields = result_fields(0);
        fields.push(integer(7));
        parse(&message(1, group(identifier, &fields))).unwrap();
    }
    let fields = [octets(b"cn=alice"), sequence(&[]), integer(7)];
    parse(&message(1, group(0x64, &fields))).unwrap();
}

#[test]
fn known_choice_alternatives_are_not_unknown_trailing_extensions() {
    let duplicate_op = sequence(&[
        integer(1),
        bind_operation(3, b"", tlv(0x80, &[])),
        tlv(0x42, &[]),
    ]);
    assert_eq!(error(&duplicate_op), ErrorKind::UnexpectedTag);
    let mut fields = search_fields(assertion(0xa3, b"cn", b"Alice"));
    fields.push(present(b"sn"));
    assert_eq!(
        error(&message(1, group(0x63, &fields))),
        ErrorKind::UnexpectedTag
    );
}

#[test]
fn wrong_constructed_bit_cannot_disguise_duplicate_known_tag() {
    let encoded = sequence(&[
        integer(1),
        bind_operation(3, b"", tlv(0x80, &[])),
        tlv(0x80, &[]),
    ]);
    assert_eq!(error(&encoded), ErrorKind::UnexpectedTag);
    let operation = group(
        0x60,
        &[integer(3), octets(b""), tlv(0x80, &[]), group(0xa0, &[])],
    );
    assert_eq!(error(&message(1, operation)), ErrorKind::UnexpectedTag);
    let filter = group(0xa9, &[tlv(0x82, b"cn"), tlv(0x83, b"x"), group(0xa4, &[])]);
    assert!(Filter::parse(&filter, ParseLimits::default(), &mut [Frame::EMPTY; 16]).is_err());
}

#[test]
fn unknown_trailing_extensions_are_validated_and_preserved() {
    let extension = group(0xb8, &[octets(b"opaque"), tlv(0x89, &[0xff])]);
    let encoded = sequence(&[integer(1), tlv(0x42, &[]), extension.clone()]);
    let parsed = parse(&encoded).unwrap();
    assert_eq!(parsed.extensions, extension);
    let mut output = vec![0xa5; encoded.len()];
    assert_eq!(parsed.copy_encoded(&mut output).unwrap(), encoded.len());
    assert_eq!(output, encoded);
    let mut short = vec![0xa5; encoded.len() - 1];
    assert_eq!(
        parsed.copy_encoded(&mut short).unwrap_err().kind,
        ErrorKind::BufferTooSmall
    );
    assert!(short.iter().all(|b| *b == 0xa5));
    let bad_extension = tlv(0xb8, &[4, 2, 0]);
    assert_eq!(
        error(&sequence(&[integer(1), tlv(0x42, &[]), bad_extension])),
        ErrorKind::Truncated
    );
}

#[test]
fn global_message_budgets_include_all_containers_and_primitive_fields() {
    let encoded = bind(b"abcd");
    let exact = ParseLimits {
        max_message_len: encoded.len(),
        max_depth: 3,
        max_fields: 6,
        max_string_len: 4,
    };
    Message::parse(&encoded, exact, &mut [Frame::EMPTY; 2]).unwrap();
    for (limits, expected) in [
        (
            ParseLimits {
                max_message_len: encoded.len() - 1,
                ..exact
            },
            ErrorKind::MessageTooLong,
        ),
        (
            ParseLimits {
                max_depth: 2,
                ..exact
            },
            ErrorKind::DepthLimit,
        ),
        (
            ParseLimits {
                max_fields: 5,
                ..exact
            },
            ErrorKind::FieldLimit,
        ),
        (
            ParseLimits {
                max_string_len: 3,
                ..exact
            },
            ErrorKind::StringTooLong,
        ),
        (
            ParseLimits {
                max_fields: 0,
                ..exact
            },
            ErrorKind::FieldLimit,
        ),
        (
            ParseLimits {
                max_depth: 0,
                ..exact
            },
            ErrorKind::DepthLimit,
        ),
    ] {
        assert_eq!(
            Message::parse(&encoded, limits, &mut [Frame::EMPTY; 8])
                .unwrap_err()
                .kind,
            expected
        );
    }
    assert_eq!(
        Message::parse(&encoded, exact, &mut [Frame::EMPTY; 1])
            .unwrap_err()
            .kind,
        ErrorKind::WorkspaceTooSmall
    );
}

#[test]
fn empty_constructed_extensions_still_consume_depth_and_fields() {
    let encoded = sequence(&[integer(1), tlv(0x42, &[]), group(0xb8, &[group(0xb9, &[])])]);
    let exact = ParseLimits {
        max_depth: 3,
        max_fields: 5,
        ..ParseLimits::default()
    };
    Message::parse(&encoded, exact, &mut [Frame::EMPTY; 2]).unwrap();
    assert_eq!(
        Message::parse(
            &encoded,
            ParseLimits {
                max_depth: 2,
                ..exact
            },
            &mut [Frame::EMPTY; 2]
        )
        .unwrap_err()
        .kind,
        ErrorKind::DepthLimit
    );
    assert_eq!(
        Message::parse(
            &encoded,
            ParseLimits {
                max_fields: 4,
                ..exact
            },
            &mut [Frame::EMPTY; 2]
        )
        .unwrap_err()
        .kind,
        ErrorKind::FieldLimit
    );
}

#[test]
fn deep_and_wide_filters_fail_with_explicit_resource_errors() {
    let mut nested = present(b"cn");
    for _ in 0..96 {
        nested = group(0xa2, &[nested]);
    }
    let encoded = search(nested);
    assert_eq!(error(&encoded), ErrorKind::DepthLimit);
    let limits = ParseLimits {
        max_depth: 128,
        ..ParseLimits::default()
    };
    Message::parse(&encoded, limits, &mut [Frame::EMPTY; 128]).unwrap();
    assert_eq!(
        Message::parse(&encoded, limits, &mut [Frame::EMPTY; 8])
            .unwrap_err()
            .kind,
        ErrorKind::WorkspaceTooSmall
    );
    let wide = search(group(0xa0, &vec![present(b"cn"); 128]));
    assert_eq!(
        Message::parse(
            &wide,
            ParseLimits {
                max_fields: 32,
                ..limits
            },
            &mut [Frame::EMPTY; 128]
        )
        .unwrap_err()
        .kind,
        ErrorKind::FieldLimit
    );
}

#[test]
fn giant_announced_lengths_are_rejected_before_body_arrives() {
    assert_eq!(
        error(&[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff]),
        ErrorKind::MessageTooLong
    );
    let encoded = bind(&vec![0x41; 256]);
    assert_eq!(
        Message::parse(
            &encoded,
            ParseLimits {
                max_message_len: 128,
                ..ParseLimits::default()
            },
            &mut [Frame::EMPTY; 4]
        )
        .unwrap_err()
        .kind,
        ErrorKind::MessageTooLong
    );
}

#[test]
fn prefix_framing_applies_limits_per_message_in_a_batch() {
    let one = bind(b"one");
    let two = bind(b"two");
    let batch = [one.clone(), two.clone()].concat();
    let limits = ParseLimits {
        max_message_len: one.len(),
        ..ParseLimits::default()
    };
    let (first, used) = Message::parse_prefix(&batch, limits, &mut [Frame::EMPTY; 4]).unwrap();
    assert_eq!(used, one.len());
    assert_eq!(first.encoded(), one);
    let (second, second_used) =
        Message::parse_prefix(&batch[used..], limits, &mut [Frame::EMPTY; 4]).unwrap();
    assert_eq!(second.encoded(), two);
    assert_eq!(second_used, two.len());
    assert_eq!(
        Message::parse(&batch, limits, &mut [Frame::EMPTY; 4])
            .unwrap_err()
            .kind,
        ErrorKind::TrailingData
    );
}

#[test]
fn deterministic_random_and_mutated_messages_terminate() {
    let mut state = 0xe37a_f531_008d_6c49u64;
    let mut bytes = [0u8; 160];
    let limits = ParseLimits {
        max_message_len: 4096,
        max_depth: 16,
        max_fields: 128,
        max_string_len: 256,
    };
    let rounds = if cfg!(miri) { 128 } else { 30_000 };
    for _ in 0..rounds {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let len = state as usize % bytes.len();
        for byte in &mut bytes[..len] {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
        if let Err(error) = Message::parse(&bytes[..len], limits, &mut [Frame::EMPTY; 16]) {
            assert!(error.offset <= len);
        }
        if let Err(error) = Filter::parse(&bytes[..len], limits, &mut [Frame::EMPTY; 16]) {
            assert!(error.offset <= len);
        }
    }
    let corpus = [
        bind(b"secret"),
        search(group(
            0xa0,
            &[present(b"cn"), assertion(0xa3, b"uid", b"alice")],
        )),
        entry(&[attribute(b"cn", &[octets(b"Alice")])]),
    ];
    for original in corpus {
        for index in 0..original.len() {
            for replacement in [0, 1, 0x1f, 0x30, 0x80, 0xff] {
                let mut mutated = original.clone();
                mutated[index] = replacement;
                if let Ok(parsed) = Message::parse(&mutated, limits, &mut [Frame::EMPTY; 16]) {
                    assert_eq!(parsed.encoded(), mutated);
                    for control in parsed.controls {
                        control.unwrap();
                    }
                    match parsed.operation {
                        Operation::SearchRequest(request) => {
                            for name in request.attributes {
                                name.unwrap();
                            }
                            for event in request.filter.events(&mut [0; 16]) {
                                event.unwrap();
                            }
                        }
                        Operation::SearchResultEntry(entry) => {
                            for attribute in entry.attributes {
                                for value in attribute.unwrap().values {
                                    value.unwrap();
                                }
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
    }
}
