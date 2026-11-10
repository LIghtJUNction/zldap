//! Deterministic wire fixtures generated independently of either encoder.

#[derive(Clone)]
pub struct Case {
    pub name: &'static str,
    pub wire: Vec<u8>,
    pub messages: usize,
}

pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        let bytes = value.len().to_be_bytes();
        let first = bytes.iter().position(|b| *b != 0).unwrap();
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(value);
    out
}

pub fn container(tag: u8, children: &[Vec<u8>]) -> Vec<u8> {
    tlv(tag, &children.concat())
}

pub fn integer(tag: u8, value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(3);
    let mut out = Vec::new();
    if bytes[first] & 0x80 != 0 {
        out.push(0);
    }
    out.extend_from_slice(&bytes[first..]);
    tlv(tag, &out)
}

pub fn message(id: u32, operation: Vec<u8>) -> Vec<u8> {
    container(0x30, &[integer(2, id), operation])
}

pub fn bind(id: u32) -> Vec<u8> {
    message(
        id,
        container(
            0x60,
            &[
                integer(2, 3),
                tlv(4, b"cn=alice,dc=example,dc=org"),
                tlv(0x80, b"example-password"),
            ],
        ),
    )
}

pub fn search(id: u32, filter: Vec<u8>) -> Vec<u8> {
    message(
        id,
        container(
            0x63,
            &[
                tlv(4, b"dc=example,dc=org"),
                integer(10, 2),
                integer(10, 0),
                integer(2, 100),
                integer(2, 30),
                tlv(1, &[0]),
                filter,
                container(0x30, &[tlv(4, b"cn"), tlv(4, b"mail")]),
            ],
        ),
    )
}

pub fn assertion(tag: u8, attribute: &[u8], value: &[u8]) -> Vec<u8> {
    container(tag, &[tlv(4, attribute), tlv(4, value)])
}

pub fn complex_filter() -> Vec<u8> {
    container(
        0xa0,
        &[
            assertion(0xa3, b"objectclass", b"person"),
            container(
                0xa1,
                &[
                    assertion(0xa3, b"uid", b"alice"),
                    assertion(0xa3, b"uid", b"bob"),
                    container(0xa2, &[tlv(0x87, b"disabled")]),
                ],
            ),
            container(
                0xa4,
                &[
                    tlv(4, b"cn"),
                    container(0x30, &[tlv(0x80, b"Al"), tlv(0x81, b"ic"), tlv(0x82, b"e")]),
                ],
            ),
            assertion(0xa5, b"uidnumber", b"1000"),
            assertion(0xa6, b"uidnumber", b"9999"),
            assertion(0xa8, b"displayname", b"Alice"),
            container(
                0xa9,
                &[
                    tlv(0x81, b"2.5.13.2"),
                    tlv(0x82, b"cn"),
                    tlv(0x83, b"alice"),
                    tlv(0x84, &[0xff]),
                ],
            ),
        ],
    )
}

pub fn entry(id: u32, count: usize, value_len: usize) -> Vec<u8> {
    let attrs = (0..count)
        .map(|index| {
            let name = format!("attribute{index}");
            let value: Vec<u8> = (0..value_len)
                .map(|byte| ((byte * 31 + index * 17) % 256) as u8)
                .collect();
            container(
                0x30,
                &[tlv(4, name.as_bytes()), container(0x31, &[tlv(4, &value)])],
            )
        })
        .collect::<Vec<_>>();
    message(
        id,
        container(
            0x64,
            &[
                tlv(4, b"cn=alice,dc=example,dc=org"),
                container(0x30, &attrs),
            ],
        ),
    )
}

pub fn corpus() -> Vec<Case> {
    let mut cases = vec![
        Case {
            name: "bind_small",
            wire: bind(1),
            messages: 1,
        },
        Case {
            name: "bind_sasl",
            wire: message(
                2,
                container(
                    0x60,
                    &[
                        integer(2, 3),
                        tlv(4, b""),
                        container(0xa3, &[tlv(4, b"PLAIN"), tlv(4, b"\0alice\0secret")]),
                    ],
                ),
            ),
            messages: 1,
        },
        Case {
            name: "bind_response",
            wire: message(
                3,
                container(0x61, &[integer(10, 0), tlv(4, b""), tlv(4, b"bound")]),
            ),
            messages: 1,
        },
        Case {
            name: "search_simple",
            wire: search(4, tlv(0x87, b"objectclass")),
            messages: 1,
        },
        Case {
            name: "search_complex",
            wire: search(5, complex_filter()),
            messages: 1,
        },
        Case {
            name: "entry_many_attributes",
            wire: entry(6, 128, 32),
            messages: 1,
        },
        Case {
            name: "entry_large_value",
            wire: entry(7, 1, 131_072),
            messages: 1,
        },
        Case {
            name: "search_done",
            wire: message(
                8,
                container(0x65, &[integer(10, 0), tlv(4, b""), tlv(4, b"complete")]),
            ),
            messages: 1,
        },
        Case {
            name: "unbind",
            wire: message(9, tlv(0x42, b"")),
            messages: 1,
        },
    ];
    cases.push(Case {
        name: "batch_256_binds",
        wire: (1..=256).flat_map(bind).collect(),
        messages: 256,
    });
    cases.push(Case {
        name: "batch_128_entries",
        wire: (1..=128).flat_map(|id| entry(id, 8, 64)).collect(),
        messages: 128,
    });
    cases
}

pub fn malformed() -> Vec<Case> {
    let good = bind(1);
    let mut trailing = good.clone();
    trailing.push(0);
    vec![
        Case {
            name: "empty",
            wire: vec![],
            messages: 1,
        },
        Case {
            name: "truncated_tag",
            wire: vec![0x30],
            messages: 1,
        },
        Case {
            name: "truncated_value",
            wire: good[..good.len() - 1].to_vec(),
            messages: 1,
        },
        Case {
            name: "indefinite_length",
            wire: vec![0x30, 0x80, 0, 0],
            messages: 1,
        },
        Case {
            name: "length_overflow",
            wire: vec![0x30, 0x89, 1, 0, 0, 0, 0, 0, 0, 0, 0],
            messages: 1,
        },
        Case {
            name: "negative_message_id",
            wire: container(0x30, &[tlv(2, &[0xff]), tlv(0x42, b"")]),
            messages: 1,
        },
        Case {
            name: "zero_message_id",
            wire: message(0, tlv(0x42, b"")),
            messages: 1,
        },
        Case {
            name: "empty_message_id",
            wire: container(0x30, &[tlv(2, b""), tlv(0x42, b"")]),
            messages: 1,
        },
        Case {
            name: "nonminimal_integer",
            wire: container(0x30, &[tlv(2, &[0, 1]), tlv(0x42, b"")]),
            messages: 1,
        },
        Case {
            name: "unsupported_operation",
            wire: message(1, tlv(0x4a, b"cn=a")),
            messages: 1,
        },
        Case {
            name: "unknown_outer_tag",
            wire: container(0x31, &[integer(2, 1), tlv(0x42, b"")]),
            messages: 1,
        },
        Case {
            name: "empty_and",
            wire: search(1, tlv(0xa0, b"")),
            messages: 1,
        },
        Case {
            name: "empty_not",
            wire: search(1, tlv(0xa2, b"")),
            messages: 1,
        },
        Case {
            name: "trailing_data",
            wire: trailing,
            messages: 1,
        },
        Case {
            name: "invalid_utf8_dn",
            wire: message(
                1,
                container(0x60, &[integer(2, 3), tlv(4, &[0xff]), tlv(0x80, b"")]),
            ),
            messages: 1,
        },
        Case {
            name: "oversized_value",
            wire: entry(1, 1, 131_072),
            messages: 1,
        },
    ]
}
