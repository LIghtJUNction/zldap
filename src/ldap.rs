use crate::ber::{self, Class, Cursor, Frame, Tag, Tlv};
use crate::{Error, ErrorKind, Filter, ParseLimits, Result};

pub(crate) const fn context(number: u32, constructed: bool) -> Tag {
    Tag::new(Class::Context, constructed, number)
}

pub(crate) const fn application(number: u32, constructed: bool) -> Tag {
    Tag::new(Class::Application, constructed, number)
}

pub(crate) fn contents(tlv: Tlv<'_>, limits: ParseLimits) -> Cursor<'_> {
    Cursor::new(tlv.value, value_offset(tlv), limits)
}

pub(crate) fn value_offset(tlv: Tlv<'_>) -> usize {
    tlv.offset + tlv.encoded.len() - tlv.value.len()
}

pub(crate) fn expect(tlv: Tlv<'_>, tag: Tag) -> Result<Tlv<'_>> {
    if tlv.tag == tag {
        Ok(tlv)
    } else {
        Err(Error::new(ErrorKind::UnexpectedTag, tlv.offset))
    }
}

pub(crate) fn required<'a>(cursor: &mut Cursor<'a>) -> Result<Tlv<'a>> {
    cursor
        .next()?
        .ok_or_else(|| Error::new(ErrorKind::MissingField, cursor.offset()))
}

pub(crate) fn text(tlv: Tlv<'_>) -> Result<&str> {
    core::str::from_utf8(tlv.value)
        .map_err(|e| Error::new(ErrorKind::InvalidUtf8, value_offset(tlv) + e.valid_up_to()))
}

pub(crate) fn string<'a>(cursor: &mut Cursor<'a>) -> Result<&'a str> {
    text(expect(required(cursor)?, Tag::OCTET_STRING)?)
}

pub(crate) fn positive(tlv: Tlv<'_>, enumeration: bool) -> Result<u32> {
    let value = if enumeration {
        tlv.as_enumerated()?
    } else {
        tlv.as_i64()?
    };
    if !(0..=i32::MAX as i64).contains(&value) {
        return Err(Error::new(ErrorKind::IntegerOverflow, tlv.offset));
    }
    Ok(value as u32)
}

pub(crate) fn ldap_boolean(tlv: Tlv<'_>) -> Result<bool> {
    match tlv.value {
        [0] => Ok(false),
        [255] => Ok(true),
        _ => Err(Error::new(ErrorKind::InvalidBoolean, value_offset(tlv))),
    }
}

/// Validate a numericoid without converting arbitrarily large decimal arcs.
pub(crate) fn valid_oid(value: &str) -> bool {
    let mut arcs = value.split('.');
    let mut count = 0;
    for arc in &mut arcs {
        if arc.is_empty()
            || (arc.len() > 1 && arc.as_bytes()[0] == b'0')
            || !arc.bytes().all(|b| b.is_ascii_digit())
        {
            return false;
        }
        count += 1;
    }
    count >= 2
}

pub(crate) fn valid_descriptor(value: &str) -> bool {
    matches!(value.as_bytes().first(), Some(b) if b.is_ascii_alphabetic())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

pub(crate) fn valid_attribute(value: &str) -> bool {
    let mut fields = value.split(';');
    let first = fields.next().unwrap_or("");
    (valid_descriptor(first) || valid_oid(first))
        && fields
            .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

pub(crate) fn attribute(tlv: Tlv<'_>) -> Result<&str> {
    let value = text(tlv)?;
    if valid_attribute(value) {
        Ok(value)
    } else {
        Err(Error::new(ErrorKind::InvalidAttribute, value_offset(tlv)))
    }
}

/// Check unknown trailing SEQUENCE extensions while rejecting duplicate known fields.
pub(crate) fn extensions<'a>(cursor: &mut Cursor<'a>, known: &[Tag]) -> Result<&'a [u8]> {
    let bytes = cursor.remaining();
    while let Some(tlv) = cursor.next()? {
        if known
            .iter()
            .any(|tag| tag.class == tlv.tag.class && tag.number == tlv.tag.number)
        {
            return Err(Error::new(ErrorKind::UnexpectedTag, tlv.offset));
        }
    }
    Ok(bytes)
}

/// Borrowed authentication protocol data. This type performs no authentication.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Authentication<'a> {
    Simple(&'a [u8]),
    Sasl {
        mechanism: &'a str,
        credentials: Option<&'a [u8]>,
    },
}

impl core::fmt::Debug for Authentication<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Simple(_) => f.write_str("Simple([redacted])"),
            Self::Sasl {
                mechanism,
                credentials,
            } => f
                .debug_struct("Sasl")
                .field("mechanism", mechanism)
                .field("credentials_present", &credentials.is_some())
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BindRequest<'a> {
    pub version: u8,
    pub name: &'a str,
    pub authentication: Authentication<'a>,
}

#[derive(Clone, Copy)]
pub struct BindResponse<'a> {
    pub result: LdapResult<'a>,
    pub server_sasl_credentials: Option<&'a [u8]>,
}

impl core::fmt::Debug for BindResponse<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BindResponse")
            .field("result", &self.result)
            .field(
                "server_sasl_credentials_present",
                &self.server_sasl_credentials.is_some(),
            )
            .finish()
    }
}

/// Result codes are protocol data, including unknown extension values.
#[derive(Clone, Copy, Debug)]
pub struct LdapResult<'a> {
    pub code: u32,
    pub matched_dn: &'a str,
    pub diagnostic_message: &'a str,
    pub referrals: Strings<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Scope {
    Base = 0,
    OneLevel = 1,
    Subtree = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DerefAliases {
    Never = 0,
    InSearching = 1,
    FindingBase = 2,
    Always = 3,
}

#[derive(Clone, Copy, Debug)]
pub struct SearchRequest<'a> {
    pub base_dn: &'a str,
    pub scope: Scope,
    pub deref_aliases: DerefAliases,
    /// Requested server limit; separate from parser resource limits.
    pub size_limit: u32,
    pub time_limit: u32,
    pub types_only: bool,
    pub filter: Filter<'a>,
    pub attributes: Strings<'a>,
}

#[derive(Clone, Copy, Debug)]
pub struct SearchResultEntry<'a> {
    pub object_name: &'a str,
    pub attributes: Attributes<'a>,
}

#[derive(Clone, Copy, Debug)]
pub enum Operation<'a> {
    BindRequest(BindRequest<'a>),
    BindResponse(BindResponse<'a>),
    SearchRequest(SearchRequest<'a>),
    SearchResultEntry(SearchResultEntry<'a>),
    SearchResultDone(LdapResult<'a>),
    UnbindRequest,
}

/// A complete, eagerly validated message with borrowed values.
/// Iterating a collection is optional: parsing has already checked every member.
#[derive(Clone, Copy)]
pub struct Message<'a> {
    pub id: u32,
    pub operation: Operation<'a>,
    pub controls: Controls<'a>,
    pub extensions: &'a [u8],
    encoded: &'a [u8],
}

impl core::fmt::Debug for Message<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Message")
            .field("id", &self.id)
            .field("operation", &self.operation)
            .field("encoded_len", &self.encoded.len())
            .finish_non_exhaustive()
    }
}

impl<'a> Message<'a> {
    pub fn parse(input: &'a [u8], limits: ParseLimits, workspace: &mut [Frame]) -> Result<Self> {
        let (message, used) = Self::parse_prefix(input, limits, workspace)?;
        if used != input.len() {
            return Err(Error::new(ErrorKind::TrailingData, used));
        }
        Ok(message)
    }

    /// Decode one frame at the start of a batch. Limits apply to that frame.
    pub fn parse_prefix(
        input: &'a [u8],
        limits: ParseLimits,
        workspace: &mut [Frame],
    ) -> Result<(Self, usize)> {
        let (outer, used) = Tlv::parse(input, limits)?;
        expect(outer, Tag::SEQUENCE)?;
        ber::validate(outer.encoded, limits, workspace)?;
        let mut cursor = contents(outer, limits);
        let id_tlv = required(&mut cursor)?;
        let id = positive(id_tlv, false)?;
        if id == 0 {
            return Err(Error::new(ErrorKind::InvalidMessageId, id_tlv.offset));
        }
        let op = required(&mut cursor)?;
        if op.tag.class != Class::Application {
            return Err(Error::new(ErrorKind::UnexpectedTag, op.offset));
        }
        let operation = parse_operation(op, limits)?;
        let mut controls = Controls::empty(limits);
        if let Some(next) = peek(cursor)? {
            if next.tag == context(0, true) {
                let field = required(&mut cursor)?;
                if field.value.is_empty() {
                    return Err(Error::new(ErrorKind::InvalidValue, value_offset(field)));
                }
                controls = Controls {
                    cursor: contents(field, limits),
                    limits,
                };
                for item in controls {
                    item?;
                }
            }
        }
        let extension_offset = cursor.offset();
        let extensions = extensions(&mut cursor, &[Tag::INTEGER, op.tag, context(0, true)])?;
        let mut extra = Cursor::new(extensions, extension_offset, limits);
        while let Some(field) = extra.next()? {
            if field.tag.class == Class::Application
                && matches!(field.tag.number, 0..=16 | 19 | 23..=25)
            {
                return Err(Error::new(ErrorKind::UnexpectedTag, field.offset));
            }
        }
        Ok((
            Self {
                id,
                operation,
                controls,
                extensions,
                encoded: outer.encoded,
            },
            used,
        ))
    }

    pub fn encoded(&self) -> &'a [u8] {
        self.encoded
    }

    /// Copy the original encoding, including unknown extensions, into `output`.
    /// Use [`crate::MessageInput`] to construct and encode new protocol data.
    pub fn copy_encoded(&self, output: &mut [u8]) -> Result<usize> {
        let target = output
            .get_mut(..self.encoded.len())
            .ok_or_else(|| Error::new(ErrorKind::BufferTooSmall, 0))?;
        target.copy_from_slice(self.encoded);
        Ok(self.encoded.len())
    }
}

fn peek(mut cursor: Cursor<'_>) -> Result<Option<Tlv<'_>>> {
    cursor.next()
}

fn parse_operation(tlv: Tlv<'_>, limits: ParseLimits) -> Result<Operation<'_>> {
    let mut cursor = contents(tlv, limits);
    let mut known = [Tag::INTEGER; 16];
    let known_len;
    let operation = match tlv.tag.number {
        0 => {
            known_len = 4;
            expect(tlv, application(0, true))?;
            let v = required(&mut cursor)?;
            let version = positive(v, false)?;
            if !(1..=127).contains(&version) {
                return Err(Error::new(ErrorKind::InvalidVersion, v.offset));
            }
            let name = string(&mut cursor)?;
            let auth = required(&mut cursor)?;
            let authentication = match auth.tag {
                t if t == context(0, false) => Authentication::Simple(auth.value),
                t if t == context(3, true) => {
                    let mut fields = contents(auth, limits);
                    let mechanism = string(&mut fields)?;
                    if mechanism.is_empty()
                        || mechanism.len() > 20
                        || !mechanism.bytes().all(|b| {
                            b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
                        })
                    {
                        return Err(Error::new(ErrorKind::InvalidValue, value_offset(auth)));
                    }
                    let credentials = match peek(fields)? {
                        Some(t) if t.tag == Tag::OCTET_STRING => Some(required(&mut fields)?.value),
                        _ => None,
                    };
                    extensions(&mut fields, &[Tag::OCTET_STRING])?;
                    Authentication::Sasl {
                        mechanism,
                        credentials,
                    }
                }
                t if t.class == Class::Context => {
                    return Err(Error::new(
                        ErrorKind::UnsupportedAuthentication(t.number),
                        auth.offset,
                    ))
                }
                _ => return Err(Error::new(ErrorKind::UnexpectedTag, auth.offset)),
            };
            known[..4].copy_from_slice(&[
                Tag::INTEGER,
                Tag::OCTET_STRING,
                context(0, false),
                context(3, true),
            ]);
            Operation::BindRequest(BindRequest {
                version: version as u8,
                name,
                authentication,
            })
        }
        1 => {
            known_len = 4;
            expect(tlv, application(1, true))?;
            let result = parse_result(&mut cursor, limits)?;
            let server_sasl_credentials = match peek(cursor)? {
                Some(t) if t.tag == context(7, false) => Some(required(&mut cursor)?.value),
                _ => None,
            };
            known[..4].copy_from_slice(&[
                Tag::ENUMERATED,
                Tag::OCTET_STRING,
                context(3, true),
                context(7, false),
            ]);
            Operation::BindResponse(BindResponse {
                result,
                server_sasl_credentials,
            })
        }
        2 => {
            known_len = 0;
            expect(tlv, application(2, false))?;
            if !tlv.value.is_empty() {
                return Err(Error::new(ErrorKind::InvalidValue, value_offset(tlv)));
            }
            Operation::UnbindRequest
        }
        3 => {
            known_len = 16;
            expect(tlv, application(3, true))?;
            let base_dn = string(&mut cursor)?;
            let s = required(&mut cursor)?;
            let scope = match positive(s, true)? {
                0 => Scope::Base,
                1 => Scope::OneLevel,
                2 => Scope::Subtree,
                _ => return Err(Error::new(ErrorKind::InvalidEnumeration, s.offset)),
            };
            let d = required(&mut cursor)?;
            let deref_aliases = match positive(d, true)? {
                0 => DerefAliases::Never,
                1 => DerefAliases::InSearching,
                2 => DerefAliases::FindingBase,
                3 => DerefAliases::Always,
                _ => return Err(Error::new(ErrorKind::InvalidEnumeration, d.offset)),
            };
            let size_limit = positive(required(&mut cursor)?, false)?;
            let time_limit = positive(required(&mut cursor)?, false)?;
            let types_only = ldap_boolean(expect(required(&mut cursor)?, Tag::BOOLEAN)?)?;
            let filter = Filter::from_tlv(required(&mut cursor)?, limits)?;
            let attrs = expect(required(&mut cursor)?, Tag::SEQUENCE)?;
            let attributes = Strings {
                cursor: contents(attrs, limits),
            };
            for item in attributes {
                let name = item?;
                if name != "*" && name != "+" && !valid_attribute(name) {
                    return Err(Error::new(ErrorKind::InvalidAttribute, value_offset(attrs)));
                }
            }
            known[..6].copy_from_slice(&[
                Tag::OCTET_STRING,
                Tag::ENUMERATED,
                Tag::INTEGER,
                Tag::BOOLEAN,
                filter.tag(),
                Tag::SEQUENCE,
            ]);
            for (number, tag) in known[6..].iter_mut().enumerate() {
                *tag = context(number as u32, true);
            }
            Operation::SearchRequest(SearchRequest {
                base_dn,
                scope,
                deref_aliases,
                size_limit,
                time_limit,
                types_only,
                filter,
                attributes,
            })
        }
        4 => {
            known_len = 2;
            expect(tlv, application(4, true))?;
            let object_name = string(&mut cursor)?;
            let attrs = expect(required(&mut cursor)?, Tag::SEQUENCE)?;
            let attributes = Attributes {
                cursor: contents(attrs, limits),
                limits,
            };
            for item in attributes {
                for value in item?.values {
                    value?;
                }
            }
            known[..2].copy_from_slice(&[Tag::OCTET_STRING, Tag::SEQUENCE]);
            Operation::SearchResultEntry(SearchResultEntry {
                object_name,
                attributes,
            })
        }
        5 => {
            known_len = 3;
            expect(tlv, application(5, true))?;
            let result = parse_result(&mut cursor, limits)?;
            known[..3].copy_from_slice(&[Tag::ENUMERATED, Tag::OCTET_STRING, context(3, true)]);
            Operation::SearchResultDone(result)
        }
        number => {
            return Err(Error::new(
                ErrorKind::UnsupportedOperation(number),
                tlv.offset,
            ))
        }
    };
    extensions(&mut cursor, &known[..known_len])?;
    Ok(operation)
}

fn parse_result<'a>(cursor: &mut Cursor<'a>, limits: ParseLimits) -> Result<LdapResult<'a>> {
    let code = positive(required(cursor)?, true)?;
    let matched_dn = string(cursor)?;
    let diagnostic_message = string(cursor)?;
    let mut referrals = Strings::empty(limits);
    if let Some(t) = peek(*cursor)? {
        if t.tag == context(3, true) {
            let field = required(cursor)?;
            if field.value.is_empty() {
                return Err(Error::new(ErrorKind::InvalidValue, value_offset(field)));
            }
            referrals = Strings {
                cursor: contents(field, limits),
            };
            for value in referrals {
                if value?.is_empty() {
                    return Err(Error::new(ErrorKind::InvalidValue, value_offset(field)));
                }
            }
        }
    }
    if (code == 10) == referrals.cursor.remaining().is_empty() {
        return Err(Error::new(ErrorKind::InvalidValue, cursor.offset()));
    }
    Ok(LdapResult {
        code,
        matched_dn,
        diagnostic_message,
        referrals,
    })
}

/// Reusable iterator over validated LDAP strings. Errors remain explicit in generic access.
#[derive(Clone, Copy, Debug)]
pub struct Strings<'a> {
    pub(crate) cursor: Cursor<'a>,
}

impl<'a> Strings<'a> {
    fn empty(limits: ParseLimits) -> Self {
        Self {
            cursor: Cursor::new(&[], 0, limits),
        }
    }
}

impl<'a> Iterator for Strings<'a> {
    type Item = Result<&'a str>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.cursor.next() {
            Ok(Some(t)) => Some(expect(t, Tag::OCTET_STRING).and_then(text)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PartialAttribute<'a> {
    pub description: &'a str,
    pub values: AttributeValues<'a>,
}

#[derive(Clone, Copy, Debug)]
pub struct Attributes<'a> {
    cursor: Cursor<'a>,
    limits: ParseLimits,
}

impl<'a> Iterator for Attributes<'a> {
    type Item = Result<PartialAttribute<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        let tlv = match self.cursor.next() {
            Ok(Some(t)) => t,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        Some((|| {
            let mut fields = contents(expect(tlv, Tag::SEQUENCE)?, self.limits);
            let description = attribute(expect(required(&mut fields)?, Tag::OCTET_STRING)?)?;
            let set = expect(required(&mut fields)?, Tag::SET)?;
            let values = AttributeValues {
                cursor: contents(set, self.limits),
            };
            extensions(&mut fields, &[Tag::OCTET_STRING, Tag::SET])?;
            Ok(PartialAttribute {
                description,
                values,
            })
        })())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AttributeValues<'a> {
    cursor: Cursor<'a>,
}

impl<'a> Iterator for AttributeValues<'a> {
    type Item = Result<&'a [u8]>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.cursor.next() {
            Ok(Some(t)) => Some(expect(t, Tag::OCTET_STRING).map(|t| t.value)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

/// A control is exposed to the caller, including its criticality. The codec
/// never applies or silently ignores critical controls on an application's behalf.
#[derive(Clone, Copy, Debug)]
pub struct Control<'a> {
    pub oid: &'a str,
    pub critical: bool,
    pub value: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug)]
pub struct Controls<'a> {
    cursor: Cursor<'a>,
    limits: ParseLimits,
}

impl Controls<'_> {
    fn empty(limits: ParseLimits) -> Self {
        Self {
            cursor: Cursor::new(&[], 0, limits),
            limits,
        }
    }
}

impl<'a> Iterator for Controls<'a> {
    type Item = Result<Control<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        let tlv = match self.cursor.next() {
            Ok(Some(t)) => t,
            Ok(None) => return None,
            Err(e) => return Some(Err(e)),
        };
        Some((|| {
            let mut fields = contents(expect(tlv, Tag::SEQUENCE)?, self.limits);
            let oid = string(&mut fields)?;
            if !valid_oid(oid) {
                return Err(Error::new(ErrorKind::InvalidOid, value_offset(tlv)));
            }
            let critical = match peek(fields)? {
                Some(t) if t.tag == Tag::BOOLEAN => {
                    let critical = ldap_boolean(required(&mut fields)?)?;
                    if !critical {
                        return Err(Error::new(ErrorKind::InvalidValue, t.offset));
                    }
                    critical
                }
                _ => false,
            };
            let value = match peek(fields)? {
                Some(t) if t.tag == Tag::OCTET_STRING => Some(required(&mut fields)?.value),
                _ => None,
            };
            extensions(&mut fields, &[Tag::OCTET_STRING, Tag::BOOLEAN])?;
            Ok(Control {
                oid,
                critical,
                value,
            })
        })())
    }
}
