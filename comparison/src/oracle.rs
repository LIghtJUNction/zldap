use bytes::BytesMut;
use ldap3_lber::{parse::Parser, structure::StructureTag};
use ldap3_proto::proto::LdapMsg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    Incomplete,
    MalformedBer,
    Protocol,
    TrailingData,
    ResourceLimit,
}

/// The protocol path inside LdapCodec, without BytesMut/network-buffer copying.
pub fn parse_prefix(input: &[u8], max_depth: usize) -> Result<(LdapMsg, usize), Rejection> {
    parse_prefix_limited(input, max_depth, 1_048_576)
}

/// Preserve LdapCodec's ordering: buffer cap, BER parse, encoded-frame cap,
/// then protocol conversion. No pre-copy into BytesMut is included.
pub fn parse_prefix_limited(
    input: &[u8],
    max_depth: usize,
    max_message: usize,
) -> Result<(LdapMsg, usize), Rejection> {
    if input.len() > max_message.saturating_mul(2) {
        return Err(Rejection::ResourceLimit);
    }
    let (remaining, tag) = Parser::new(max_depth)
        .parse(input)
        .map_err(|error| match error {
            nom::Err::Incomplete(_) => Rejection::Incomplete,
            _ => Rejection::MalformedBer,
        })?;
    let used = input.len() - remaining.len();
    if used > max_message {
        return Err(Rejection::ResourceLimit);
    }
    let message = LdapMsg::try_from(tag).map_err(|_| Rejection::Protocol)?;
    Ok((message, used))
}

pub fn parse_exact_limited(
    input: &[u8],
    max_depth: usize,
    max_message: usize,
) -> Result<LdapMsg, Rejection> {
    let (message, used) = parse_prefix_limited(input, max_depth, max_message)?;
    if used == input.len() {
        Ok(message)
    } else {
        Err(Rejection::TrailingData)
    }
}

pub fn parse_exact(input: &[u8], max_depth: usize) -> Result<LdapMsg, Rejection> {
    let (message, used) = parse_prefix(input, max_depth)?;
    if used == input.len() {
        Ok(message)
    } else {
        Err(Rejection::TrailingData)
    }
}

/// Same owned message -> BER tree -> bytes path as LdapCodec::encode.
pub fn encode(message: LdapMsg, out: &mut BytesMut) {
    let tree: StructureTag = message.into();
    ldap3_lber::write::encode_into(out, tree).expect("in-memory oracle encoding");
}
