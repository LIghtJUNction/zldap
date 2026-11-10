//! Borrowed definite-length BER views and a bounded reverse writer.
//!
//! [`Tlv::parse`] frames one value. [`validate`] additionally walks every field
//! with an explicit caller-owned stack and checks the LDAP BER profile. BER
//! long-form lengths need not be minimal; integer encodings must be minimal.

use crate::{Error, ErrorKind, ParseLimits, Result};

/// ASN.1 tag class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    /// Types defined by ASN.1.
    Universal,
    /// Types assigned by an application protocol.
    Application,
    /// Types interpreted in their enclosing schema.
    Context,
    /// Privately assigned types.
    Private,
}

/// A BER identifier, including high-tag-number identifiers up to `u32::MAX`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tag {
    /// Identifier class.
    pub class: Class,
    /// Whether the value contains child TLVs.
    pub constructed: bool,
    /// Tag number, independent of the class and constructed bit.
    pub number: u32,
}

impl Tag {
    /// Universal primitive BOOLEAN.
    pub const BOOLEAN: Self = Self::new(Class::Universal, false, 1);
    /// Universal primitive INTEGER.
    pub const INTEGER: Self = Self::new(Class::Universal, false, 2);
    /// Universal primitive OCTET STRING.
    pub const OCTET_STRING: Self = Self::new(Class::Universal, false, 4);
    /// Universal primitive ENUMERATED.
    pub const ENUMERATED: Self = Self::new(Class::Universal, false, 10);
    /// Universal constructed SEQUENCE.
    pub const SEQUENCE: Self = Self::new(Class::Universal, true, 16);
    /// Universal constructed SET.
    pub const SET: Self = Self::new(Class::Universal, true, 17);

    /// Construct an identifier. This does not validate an application schema.
    pub const fn new(class: Class, constructed: bool, number: u32) -> Self {
        Self {
            class,
            constructed,
            number,
        }
    }
}

/// One complete BER value borrowing its encoded representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tlv<'a> {
    /// Decoded identifier.
    pub tag: Tag,
    /// Value bytes, without the identifier and length.
    pub value: &'a [u8],
    /// Identifier, length, and value bytes.
    pub encoded: &'a [u8],
    /// Byte position of the identifier relative to the caller's input.
    pub offset: usize,
}

impl<'a> Tlv<'a> {
    /// Frame the first value, returning its total encoded size.
    ///
    /// Bytes following the first value are permitted. Indefinite lengths,
    /// invalid identifiers, overflows, and frames exceeding the configured
    /// message limit are rejected before attempting to access their contents.
    pub fn parse(input: &'a [u8], limits: ParseLimits) -> Result<(Self, usize)> {
        Self::parse_at(input, 0, limits)
    }

    pub(crate) fn parse_at(
        input: &'a [u8],
        base_offset: usize,
        limits: ParseLimits,
    ) -> Result<(Self, usize)> {
        let first = *input
            .first()
            .ok_or_else(|| Error::new(ErrorKind::Truncated, base_offset))?;
        let class = match first >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::Context,
            _ => Class::Private,
        };
        let mut pos = 1usize;
        let mut number = u32::from(first & 0x1f);
        if number == 0x1f {
            number = 0;
            loop {
                let byte = *input.get(pos).ok_or_else(|| {
                    Error::new(ErrorKind::Truncated, base_offset.saturating_add(pos))
                })?;
                if pos == 1 && byte & 0x7f == 0 {
                    return Err(Error::new(ErrorKind::InvalidTag, base_offset));
                }
                number = number
                    .checked_mul(128)
                    .and_then(|n| n.checked_add(u32::from(byte & 0x7f)))
                    .ok_or_else(|| Error::new(ErrorKind::TagOverflow, base_offset))?;
                pos += 1;
                if byte & 0x80 == 0 {
                    break;
                }
            }
            if number < 31 {
                return Err(Error::new(ErrorKind::InvalidTag, base_offset));
            }
        }
        let length_offset = base_offset.saturating_add(pos);
        let first_length = *input
            .get(pos)
            .ok_or_else(|| Error::new(ErrorKind::Truncated, length_offset))?;
        pos += 1;
        let length = if first_length < 0x80 {
            usize::from(first_length)
        } else {
            if first_length == 0x80 {
                return Err(Error::new(ErrorKind::IndefiniteLength, length_offset));
            }
            if first_length == 0xff {
                return Err(Error::new(ErrorKind::InvalidLength, length_offset));
            }
            let octets = usize::from(first_length & 0x7f);
            // The prefix has at most 126 length octets. Checking its entire
            // extent first makes the accumulation below independent of the
            // attacker-supplied length value.
            let length_end = pos
                .checked_add(octets)
                .ok_or_else(|| Error::new(ErrorKind::LengthOverflow, length_offset))?;
            let bytes = input
                .get(pos..length_end)
                .ok_or_else(|| Error::new(ErrorKind::Truncated, length_offset))?;
            let mut length = 0usize;
            for &byte in bytes {
                length = length
                    .checked_mul(256)
                    .and_then(|n| n.checked_add(usize::from(byte)))
                    .ok_or_else(|| Error::new(ErrorKind::LengthOverflow, length_offset))?;
            }
            pos = length_end;
            length
        };
        let end = pos
            .checked_add(length)
            .ok_or_else(|| Error::new(ErrorKind::LengthOverflow, length_offset))?;
        if end > limits.max_message_len {
            return Err(Error::new(ErrorKind::MessageTooLong, base_offset));
        }
        let encoded = input
            .get(..end)
            .ok_or_else(|| Error::new(ErrorKind::Truncated, base_offset.saturating_add(pos)))?;
        Ok((
            Self {
                tag: Tag::new(class, first & 0x20 != 0, number),
                value: &encoded[pos..],
                encoded,
                offset: base_offset,
            },
            end,
        ))
    }

    /// Decode a minimally encoded signed 64-bit INTEGER.
    pub fn as_i64(self) -> Result<i64> {
        self.expect(Tag::INTEGER)?;
        signed(self.value, self.offset)
    }

    /// Decode a minimally encoded signed 64-bit ENUMERATED value.
    pub fn as_enumerated(self) -> Result<i64> {
        self.expect(Tag::ENUMERATED)?;
        signed(self.value, self.offset)
    }

    /// Decode BER BOOLEAN: zero is false; any nonzero byte is true.
    ///
    /// LDAP's stricter requirement that true is encoded as `0xff` is enforced
    /// by the LDAP schema parser.
    pub fn as_bool(self) -> Result<bool> {
        self.expect(Tag::BOOLEAN)?;
        match self.value {
            [value] => Ok(*value != 0),
            _ => Err(Error::new(ErrorKind::InvalidBoolean, self.offset)),
        }
    }

    /// Borrow a primitive OCTET STRING.
    pub fn as_octets(self) -> Result<&'a [u8]> {
        self.expect(Tag::OCTET_STRING)?;
        Ok(self.value)
    }

    /// Absolute offset of the first value byte.
    ///
    /// Parsed views always have a valid header extent. Saturation also keeps
    /// this helper safe for manually constructed public views and offsets.
    pub fn value_offset(self) -> usize {
        self.offset
            .saturating_add(self.encoded.len().saturating_sub(self.value.len()))
    }

    fn expect(self, expected: Tag) -> Result<()> {
        if self.tag == expected {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::UnexpectedTag, self.offset))
        }
    }
}

fn signed(bytes: &[u8], offset: usize) -> Result<i64> {
    if bytes.is_empty() {
        return Err(Error::new(ErrorKind::InvalidInteger, offset));
    }
    if bytes.len() > 1
        && ((bytes[0] == 0 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xff && bytes[1] & 0x80 != 0))
    {
        return Err(Error::new(ErrorKind::InvalidInteger, offset));
    }
    if bytes.len() > 8 {
        return Err(Error::new(ErrorKind::IntegerOverflow, offset));
    }
    let mut value = if bytes[0] & 0x80 == 0 { 0i64 } else { -1i64 };
    for &byte in bytes {
        value = (value << 8) | i64::from(byte);
    }
    Ok(value)
}

/// Cursor over sibling values. A failed read leaves the cursor unchanged.
#[derive(Clone, Copy, Debug)]
pub struct Cursor<'a> {
    input: &'a [u8],
    base_offset: usize,
    position: usize,
    limits: ParseLimits,
}

impl<'a> Cursor<'a> {
    /// Read fields within an already bounded container.
    pub const fn new(input: &'a [u8], base_offset: usize, limits: ParseLimits) -> Self {
        Self {
            input,
            base_offset,
            position: 0,
            limits,
        }
    }

    /// Read the next complete sibling, or `None` at the end of the container.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Option<Tlv<'a>>> {
        if self.position == self.input.len() {
            return Ok(None);
        }
        let (value, size) = Tlv::parse_at(self.remaining(), self.offset(), self.limits)?;
        // The parser returned a subslice of remaining(), so this cannot exceed
        // input.len() or overflow usize.
        self.position += size;
        Ok(Some(value))
    }

    /// Require that the enclosing schema consumed every byte.
    pub fn finish(self) -> Result<()> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::TrailingData, self.offset()))
        }
    }

    /// Borrow the unconsumed bytes.
    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.position..]
    }

    /// Current absolute byte offset, saturated for arbitrary caller offsets.
    pub fn offset(&self) -> usize {
        self.base_offset.saturating_add(self.position)
    }
}

/// One slot in the explicit BER traversal stack.
///
/// Allocate at most `max_depth - 1` slots to accommodate every allowed tree.
/// Empty containers and primitive root values need no stack slots.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Frame {
    end: usize,
    resume: usize,
}

impl Frame {
    /// An unused stack slot, suitable for array initialization.
    pub const EMPTY: Self = Self { end: 0, resume: 0 };
}

/// Validate exactly one complete BER value using the LDAP BER profile.
///
/// Every TLV, including containers, consumes one field from the global budget.
/// The root has depth one. Every primitive value is subject to the string/value
/// length limit, including context-specific values. Known scalar types are
/// validated; unknown tags remain available for application-specific schemas.
/// The walk has no recursion, allocation, or stack size dependent on input.
pub fn validate(input: &[u8], limits: ParseLimits, frames: &mut [Frame]) -> Result<()> {
    if input.len() > limits.max_message_len {
        return Err(Error::new(ErrorKind::MessageTooLong, 0));
    }
    if limits.max_depth == 0 {
        return Err(Error::new(ErrorKind::DepthLimit, 0));
    }
    let (root, size) = Tlv::parse(input, limits)?;
    if size != input.len() {
        return Err(Error::new(ErrorKind::TrailingData, size));
    }
    let mut position = 0usize;
    let mut end = input.len();
    let mut stack_len = 0usize;
    let mut fields = 0usize;
    let mut first = Some(root);
    loop {
        if fields >= limits.max_fields {
            return Err(Error::new(ErrorKind::FieldLimit, position));
        }
        fields += 1;
        let node = match first.take() {
            Some(root) => root,
            None => Tlv::parse_at(&input[position..end], position, limits)?.0,
        };
        validate_scalar(node, limits)?;
        let next = position + node.encoded.len();
        if node.tag.constructed && !node.value.is_empty() {
            if stack_len + 1 >= limits.max_depth {
                return Err(Error::new(ErrorKind::DepthLimit, position));
            }
            let slot = frames
                .get_mut(stack_len)
                .ok_or_else(|| Error::new(ErrorKind::WorkspaceTooSmall, position))?;
            *slot = Frame { end, resume: next };
            stack_len += 1;
            position = next - node.value.len();
            end = next;
        } else {
            position = next;
            while position == end && stack_len != 0 {
                stack_len -= 1;
                let frame = frames[stack_len];
                position = frame.resume;
                end = frame.end;
            }
            if position == end {
                return Ok(());
            }
        }
    }
}

fn validate_scalar(node: Tlv<'_>, limits: ParseLimits) -> Result<()> {
    if !node.tag.constructed && node.value.len() > limits.max_string_len {
        return Err(Error::new(ErrorKind::StringTooLong, node.offset));
    }
    if node.tag.class != Class::Universal {
        return Ok(());
    }
    match node.tag.number {
        0 => Err(Error::new(ErrorKind::InvalidTag, node.offset)),
        1 => node.as_bool().map(|_| ()),
        2 => node.as_i64().map(|_| ()),
        4 => node.as_octets().map(|_| ()),
        10 => node.as_enumerated().map(|_| ()),
        16 | 17 if !node.tag.constructed => Err(Error::new(ErrorKind::UnexpectedTag, node.offset)),
        _ => Ok(()),
    }
}

/// A reverse writer: write siblings last-to-first, then wrap their container.
///
/// Values are copied once into caller-provided output storage. Header lengths
/// are known when prepended, so no shifting, backpatching, or heap allocation
/// is necessary. Each method checks capacity before modifying the buffer.
pub struct Writer<'a> {
    buffer: &'a mut [u8],
    start: usize,
}

impl<'a> Writer<'a> {
    /// Start with an empty encoded suffix in the output buffer.
    pub fn new(buffer: &'a mut [u8]) -> Self {
        let start = buffer.len();
        Self { buffer, start }
    }

    /// Number of encoded bytes currently stored.
    pub fn len(&self) -> usize {
        self.buffer.len() - self.start
    }

    /// Whether no bytes have been encoded.
    pub fn is_empty(&self) -> bool {
        self.start == self.buffer.len()
    }

    /// Borrow the encoded suffix.
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer[self.start..]
    }

    /// Return the encoded suffix with the output buffer's original lifetime.
    pub fn finish(self) -> &'a [u8] {
        &self.buffer[self.start..]
    }

    /// Prepend a complete value. The caller owns its application semantics.
    pub fn write_tlv(&mut self, tag: Tag, value: &[u8]) -> Result<()> {
        let mut header = [0u8; 7 + core::mem::size_of::<usize>()];
        let header_len = encode_header(tag, value.len(), &mut header);
        let total = header_len
            .checked_add(value.len())
            .ok_or_else(|| Error::new(ErrorKind::LengthOverflow, self.len()))?;
        if total > self.start {
            return Err(Error::new(ErrorKind::BufferTooSmall, self.len()));
        }
        let new_start = self.start - total;
        let value_start = new_start + header_len;
        self.buffer[new_start..value_start].copy_from_slice(&header[..header_len]);
        self.buffer[value_start..self.start].copy_from_slice(value);
        self.start = new_start;
        Ok(())
    }

    /// Prepend a canonical signed INTEGER.
    pub fn write_integer(&mut self, value: i64) -> Result<()> {
        self.write_signed(Tag::INTEGER, value)
    }

    /// Prepend a canonical signed ENUMERATED.
    pub fn write_enumerated(&mut self, value: i64) -> Result<()> {
        self.write_signed(Tag::ENUMERATED, value)
    }

    fn write_signed(&mut self, tag: Tag, value: i64) -> Result<()> {
        let bytes = value.to_be_bytes();
        let mut start = 0;
        while start < 7
            && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
                || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
        {
            start += 1;
        }
        self.write_tlv(tag, &bytes[start..])
    }

    /// Prepend BOOLEAN using the LDAP representation of true (`0xff`).
    pub fn write_boolean(&mut self, value: bool) -> Result<()> {
        self.write_tlv(Tag::BOOLEAN, &[if value { 0xff } else { 0 }])
    }

    /// Prepend a primitive OCTET STRING.
    pub fn write_octet_string(&mut self, value: &[u8]) -> Result<()> {
        self.write_tlv(Tag::OCTET_STRING, value)
    }

    /// Wrap bytes added after `checkpoint_len` in the supplied tag.
    ///
    /// Take the checkpoint with [`Self::len`] before writing a container's
    /// children. Existing bytes beyond that checkpoint remain sibling values.
    pub fn wrap(&mut self, tag: Tag, checkpoint_len: usize) -> Result<()> {
        let content_len = self
            .len()
            .checked_sub(checkpoint_len)
            .ok_or_else(|| Error::new(ErrorKind::InvalidValue, self.len()))?;
        let mut header = [0u8; 7 + core::mem::size_of::<usize>()];
        let header_len = encode_header(tag, content_len, &mut header);
        if header_len > self.start {
            return Err(Error::new(ErrorKind::BufferTooSmall, self.len()));
        }
        let new_start = self.start - header_len;
        self.buffer[new_start..self.start].copy_from_slice(&header[..header_len]);
        self.start = new_start;
        Ok(())
    }
}

fn encode_header(
    tag: Tag,
    length: usize,
    output: &mut [u8; 7 + core::mem::size_of::<usize>()],
) -> usize {
    let class = match tag.class {
        Class::Universal => 0,
        Class::Application => 0x40,
        Class::Context => 0x80,
        Class::Private => 0xc0,
    };
    let first = class | if tag.constructed { 0x20 } else { 0 };
    let mut pos = 1usize;
    if tag.number < 31 {
        output[0] = first | tag.number as u8;
    } else {
        output[0] = first | 0x1f;
        let groups = (32 - tag.number.leading_zeros()).div_ceil(7) as usize;
        for i in (0..groups).rev() {
            output[pos] = ((tag.number >> (i * 7)) & 0x7f) as u8 | if i == 0 { 0 } else { 0x80 };
            pos += 1;
        }
    }
    if length < 128 {
        output[pos] = length as u8;
        pos += 1;
    } else {
        let octets = (usize::BITS - length.leading_zeros()).div_ceil(8) as usize;
        output[pos] = 0x80 | octets as u8;
        pos += 1;
        for i in (0..octets).rev() {
            output[pos] = (length >> (i * 8)) as u8;
            pos += 1;
        }
    }
    pos
}
