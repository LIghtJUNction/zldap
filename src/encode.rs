use crate::ber::{Tag, Tlv, Writer};
use crate::ldap::{application, context, valid_attribute, valid_oid};
use crate::{
    Authentication, BindRequest, DerefAliases, Error, ErrorKind, Filter, ParseLimits, Result, Scope,
};

#[derive(Clone, Copy, Debug)]
pub struct Attribute<'a> {
    pub description: &'a str,
    pub values: &'a [&'a [u8]],
}

#[derive(Clone, Copy, Debug)]
pub struct ControlInput<'a> {
    pub oid: &'a str,
    pub critical: bool,
    pub value: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug)]
pub struct ResultInput<'a> {
    pub code: u32,
    pub matched_dn: &'a str,
    pub diagnostic_message: &'a str,
    /// Empty means that the optional referral field is absent.
    pub referrals: &'a [&'a str],
}

#[derive(Clone, Copy, Debug)]
pub struct SearchInput<'a> {
    pub base_dn: &'a str,
    pub scope: Scope,
    pub deref_aliases: DerefAliases,
    pub size_limit: u32,
    pub time_limit: u32,
    pub types_only: bool,
    pub filter: Filter<'a>,
    pub attributes: &'a [&'a str],
}

#[derive(Clone, Copy)]
pub enum OperationInput<'a> {
    BindRequest(BindRequest<'a>),
    BindResponse {
        result: ResultInput<'a>,
        server_sasl_credentials: Option<&'a [u8]>,
    },
    SearchRequest(SearchInput<'a>),
    SearchResultEntry {
        object_name: &'a str,
        attributes: &'a [Attribute<'a>],
    },
    SearchResultDone(ResultInput<'a>),
    UnbindRequest,
}

/// Borrowed input for constructing a definite-length LDAP message.
/// Newly emitted headers use minimal lengths; validated filter contents retain
/// their original BER representation.
#[derive(Clone, Copy)]
pub struct MessageInput<'a> {
    pub id: u32,
    pub operation: OperationInput<'a>,
    pub controls: &'a [ControlInput<'a>],
}

impl MessageInput<'_> {
    /// Validate protocol fields and compute exact capacity without allocation.
    pub fn encoded_len(&self) -> Result<usize> {
        let mut size = Sizer(0);
        emit(self, &mut size)?;
        Ok(size.len())
    }

    /// Write a complete message into the start of the output buffer.
    /// Invalid fields or insufficient capacity leave the output unchanged.
    /// Bytes after the returned length are untouched.
    pub fn encode(&self, output: &mut [u8]) -> Result<usize> {
        let length = self.encoded_len()?;
        let target = output
            .get_mut(..length)
            .ok_or_else(|| Error::new(ErrorKind::BufferTooSmall, 0))?;
        let mut writer = Writer::new(target);
        emit(self, &mut writer)?;
        Ok(length)
    }
}

trait Sink {
    fn len(&self) -> usize;
    fn tlv(&mut self, tag: Tag, value: &[u8]) -> Result<()>;
    fn wrap(&mut self, tag: Tag, checkpoint: usize) -> Result<()>;
    fn integer(&mut self, tag: Tag, value: u32) -> Result<()> {
        if value > i32::MAX as u32 {
            return Err(Error::new(ErrorKind::IntegerOverflow, 0));
        }
        let bytes = value.to_be_bytes();
        let mut start = 0;
        while start < 3 && bytes[start] == 0 && bytes[start + 1] < 128 {
            start += 1;
        }
        self.tlv(tag, &bytes[start..])
    }
    fn octets(&mut self, bytes: &[u8]) -> Result<()> {
        self.tlv(Tag::OCTET_STRING, bytes)
    }
    fn boolean(&mut self, value: bool) -> Result<()> {
        self.tlv(Tag::BOOLEAN, &[if value { 255 } else { 0 }])
    }
}

impl Sink for Writer<'_> {
    fn len(&self) -> usize {
        Writer::len(self)
    }
    fn tlv(&mut self, tag: Tag, value: &[u8]) -> Result<()> {
        self.write_tlv(tag, value)
    }
    fn wrap(&mut self, tag: Tag, checkpoint: usize) -> Result<()> {
        Writer::wrap(self, tag, checkpoint)
    }
}

struct Sizer(usize);

impl Sizer {
    fn add(&mut self, value: usize) -> Result<()> {
        self.0 = self
            .0
            .checked_add(value)
            .ok_or_else(|| Error::new(ErrorKind::LengthOverflow, 0))?;
        Ok(())
    }
    fn header(&mut self, tag: Tag, length: usize) -> Result<()> {
        let tag_len = if tag.number < 31 {
            1
        } else {
            1 + (32 - tag.number.leading_zeros()).div_ceil(7) as usize
        };
        let len_len = if length < 128 {
            1
        } else {
            1 + (usize::BITS - length.leading_zeros()).div_ceil(8) as usize
        };
        self.add(tag_len + len_len)
    }
}

impl Sink for Sizer {
    fn len(&self) -> usize {
        self.0
    }
    fn tlv(&mut self, tag: Tag, value: &[u8]) -> Result<()> {
        self.header(tag, value.len())?;
        self.add(value.len())
    }
    fn wrap(&mut self, tag: Tag, checkpoint: usize) -> Result<()> {
        self.header(
            tag,
            self.0
                .checked_sub(checkpoint)
                .ok_or_else(|| Error::new(ErrorKind::InvalidValue, 0))?,
        )
    }
}

fn emit(message: &MessageInput<'_>, sink: &mut impl Sink) -> Result<()> {
    if message.id == 0 || message.id > i32::MAX as u32 {
        return Err(Error::new(ErrorKind::InvalidMessageId, 0));
    }
    let root = sink.len();
    if !message.controls.is_empty() {
        let controls = sink.len();
        for control in message.controls.iter().rev() {
            if !valid_oid(control.oid) {
                return Err(Error::new(ErrorKind::InvalidOid, 0));
            }
            let checkpoint = sink.len();
            if let Some(value) = control.value {
                sink.octets(value)?;
            }
            if control.critical {
                sink.boolean(true)?;
            }
            sink.octets(control.oid.as_bytes())?;
            sink.wrap(Tag::SEQUENCE, checkpoint)?;
        }
        sink.wrap(context(0, true), controls)?;
    }
    let checkpoint = sink.len();
    let tag = match message.operation {
        OperationInput::BindRequest(bind) => {
            if !(1..=127).contains(&bind.version) {
                return Err(Error::new(ErrorKind::InvalidVersion, 0));
            }
            match bind.authentication {
                Authentication::Simple(password) => sink.tlv(context(0, false), password)?,
                Authentication::Sasl {
                    mechanism,
                    credentials,
                } => {
                    if mechanism.is_empty()
                        || mechanism.len() > 20
                        || !mechanism.bytes().all(|b| {
                            b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
                        })
                    {
                        return Err(Error::new(ErrorKind::InvalidValue, 0));
                    }
                    let sasl = sink.len();
                    if let Some(value) = credentials {
                        sink.octets(value)?;
                    }
                    sink.octets(mechanism.as_bytes())?;
                    sink.wrap(context(3, true), sasl)?;
                }
            }
            sink.octets(bind.name.as_bytes())?;
            sink.integer(Tag::INTEGER, u32::from(bind.version))?;
            application(0, true)
        }
        OperationInput::BindResponse {
            result,
            server_sasl_credentials,
        } => {
            if let Some(value) = server_sasl_credentials {
                sink.tlv(context(7, false), value)?;
            }
            emit_result(result, sink)?;
            application(1, true)
        }
        OperationInput::SearchRequest(search) => {
            let attrs = sink.len();
            for attr in search.attributes.iter().rev() {
                if *attr != "*" && *attr != "+" && !valid_attribute(attr) {
                    return Err(Error::new(ErrorKind::InvalidAttribute, 0));
                }
                sink.octets(attr.as_bytes())?;
            }
            sink.wrap(Tag::SEQUENCE, attrs)?;
            let (filter, _) = Tlv::parse(
                search.filter.encoded(),
                ParseLimits {
                    max_message_len: usize::MAX,
                    ..ParseLimits::default()
                },
            )?;
            sink.tlv(filter.tag, filter.value)?;
            sink.boolean(search.types_only)?;
            sink.integer(Tag::INTEGER, search.time_limit)?;
            sink.integer(Tag::INTEGER, search.size_limit)?;
            sink.integer(Tag::ENUMERATED, search.deref_aliases as u32)?;
            sink.integer(Tag::ENUMERATED, search.scope as u32)?;
            sink.octets(search.base_dn.as_bytes())?;
            application(3, true)
        }
        OperationInput::SearchResultEntry {
            object_name,
            attributes,
        } => {
            let attrs = sink.len();
            for attribute in attributes.iter().rev() {
                if !valid_attribute(attribute.description) {
                    return Err(Error::new(ErrorKind::InvalidAttribute, 0));
                }
                let attr = sink.len();
                let values = sink.len();
                for value in attribute.values.iter().rev() {
                    sink.octets(value)?;
                }
                sink.wrap(Tag::SET, values)?;
                sink.octets(attribute.description.as_bytes())?;
                sink.wrap(Tag::SEQUENCE, attr)?;
            }
            sink.wrap(Tag::SEQUENCE, attrs)?;
            sink.octets(object_name.as_bytes())?;
            application(4, true)
        }
        OperationInput::SearchResultDone(result) => {
            emit_result(result, sink)?;
            application(5, true)
        }
        OperationInput::UnbindRequest => application(2, false),
    };
    sink.wrap(tag, checkpoint)?;
    sink.integer(Tag::INTEGER, message.id)?;
    sink.wrap(Tag::SEQUENCE, root)
}

fn emit_result(result: ResultInput<'_>, sink: &mut impl Sink) -> Result<()> {
    if (result.code == 10) == result.referrals.is_empty() {
        return Err(Error::new(ErrorKind::InvalidValue, 0));
    }
    if !result.referrals.is_empty() {
        let referrals = sink.len();
        for referral in result.referrals.iter().rev() {
            if referral.is_empty() {
                return Err(Error::new(ErrorKind::InvalidValue, 0));
            }
            sink.octets(referral.as_bytes())?;
        }
        sink.wrap(context(3, true), referrals)?;
    }
    sink.octets(result.diagnostic_message.as_bytes())?;
    sink.octets(result.matched_dn.as_bytes())?;
    sink.integer(Tag::ENUMERATED, result.code)
}
