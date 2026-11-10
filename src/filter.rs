use crate::ber::{self, Class, Cursor, Frame, Tag, Tlv};
use crate::ldap::{
    attribute, contents, context, expect, extensions, ldap_boolean, required, text,
    valid_descriptor, valid_oid, value_offset,
};
use crate::{Error, ErrorKind, ParseLimits, Result};

/// A validated filter subtree. Values retain their original binary representation.
#[derive(Clone, Copy, Debug)]
pub struct Filter<'a> {
    tlv: Tlv<'a>,
    max_message_len: usize,
}

#[derive(Clone, Copy, Debug)]
pub enum FilterKind<'a> {
    And,
    Or,
    Not,
    Equality {
        attribute: &'a str,
        value: &'a [u8],
    },
    Substrings {
        attribute: &'a str,
        components: Substrings<'a>,
    },
    GreaterOrEqual {
        attribute: &'a str,
        value: &'a [u8],
    },
    LessOrEqual {
        attribute: &'a str,
        value: &'a [u8],
    },
    Present(&'a str),
    ApproxMatch {
        attribute: &'a str,
        value: &'a [u8],
    },
    ExtensibleMatch {
        matching_rule: Option<&'a str>,
        attribute: Option<&'a str>,
        value: &'a [u8],
        dn_attributes: bool,
    },
}

impl<'a> Filter<'a> {
    pub fn parse(input: &'a [u8], limits: ParseLimits, workspace: &mut [Frame]) -> Result<Self> {
        ber::validate(input, limits, workspace)?;
        let (tlv, used) = Tlv::parse(input, limits)?;
        if used != input.len() {
            return Err(Error::new(ErrorKind::TrailingData, used));
        }
        Self::from_tlv(tlv, limits)
    }

    pub(crate) fn from_tlv(tlv: Tlv<'a>, limits: ParseLimits) -> Result<Self> {
        let filter = Self {
            tlv,
            max_message_len: limits.max_message_len,
        };
        // Walk the preorder wire layout. Descend only into logical filter
        // containers; assertion fields remain part of their owning leaf.
        // BER validation has already established every enclosing boundary.
        let mut offset = 0;
        while offset < tlv.encoded.len() {
            let (node, used) = Tlv::parse_at(&tlv.encoded[offset..], tlv.offset + offset, limits)?;
            let view = Self {
                tlv: node,
                max_message_len: limits.max_message_len,
            };
            let kind = view.kind()?;
            offset += if matches!(kind, FilterKind::And | FilterKind::Or | FilterKind::Not) {
                used - node.value.len()
            } else {
                used
            };
        }
        Ok(filter)
    }

    pub fn encoded(&self) -> &'a [u8] {
        self.tlv.encoded
    }
    pub(crate) fn tag(&self) -> Tag {
        self.tlv.tag
    }

    pub fn kind(&self) -> Result<FilterKind<'a>> {
        let t = self.tlv;
        if t.tag.class != Class::Context || t.tag.constructed != (t.tag.number != 7) {
            return Err(Error::new(ErrorKind::InvalidFilter, t.offset));
        }
        let mut fields = contents(t, ber::framing_limits(self.max_message_len));
        match t.tag.number {
            0 | 1 => {
                if t.value.is_empty() {
                    return Err(Error::new(ErrorKind::InvalidFilter, value_offset(t)));
                }
                Ok(if t.tag.number == 0 {
                    FilterKind::And
                } else {
                    FilterKind::Or
                })
            }
            2 => {
                required(&mut fields)?;
                fields.finish()?;
                Ok(FilterKind::Not)
            }
            3 | 5 | 6 | 8 => {
                let name = attribute(expect(required(&mut fields)?, Tag::OCTET_STRING)?)?;
                let value = expect(required(&mut fields)?, Tag::OCTET_STRING)?.value;
                extensions(&mut fields, &[Tag::OCTET_STRING])?;
                Ok(match t.tag.number {
                    3 => FilterKind::Equality {
                        attribute: name,
                        value,
                    },
                    5 => FilterKind::GreaterOrEqual {
                        attribute: name,
                        value,
                    },
                    6 => FilterKind::LessOrEqual {
                        attribute: name,
                        value,
                    },
                    _ => FilterKind::ApproxMatch {
                        attribute: name,
                        value,
                    },
                })
            }
            4 => {
                let name = attribute(expect(required(&mut fields)?, Tag::OCTET_STRING)?)?;
                let sequence = expect(required(&mut fields)?, Tag::SEQUENCE)?;
                if sequence.value.is_empty() {
                    return Err(Error::new(ErrorKind::InvalidFilter, value_offset(sequence)));
                }
                let components = Substrings {
                    cursor: contents(sequence, ber::framing_limits(self.max_message_len)),
                };
                let mut finished = false;
                for (count, component) in components.enumerate() {
                    if finished {
                        return Err(Error::new(ErrorKind::InvalidFilter, value_offset(sequence)));
                    }
                    match component? {
                        Substring::Initial(_) if count != 0 => {
                            return Err(Error::new(
                                ErrorKind::InvalidFilter,
                                value_offset(sequence),
                            ))
                        }
                        Substring::Final(_) => finished = true,
                        _ => (),
                    }
                }
                extensions(&mut fields, &[Tag::OCTET_STRING, Tag::SEQUENCE])?;
                Ok(FilterKind::Substrings {
                    attribute: name,
                    components,
                })
            }
            7 => Ok(FilterKind::Present(attribute(t)?)),
            9 => {
                let mut matching_rule = None;
                let mut name = None;
                let mut value = None;
                let mut dn_attributes = false;
                let mut previous = 0;
                while let Some(field) = fields.next()? {
                    if field.tag.class != Class::Context
                        || field.tag.constructed
                        || !(1..=4).contains(&field.tag.number)
                    {
                        // Implied extensibility permits trailing unknown fields.
                        if value.is_none()
                            || (field.tag.class == Class::Context
                                && (1..=4).contains(&field.tag.number))
                        {
                            return Err(Error::new(ErrorKind::InvalidFilter, field.offset));
                        }
                        extensions(
                            &mut fields,
                            &[
                                context(1, false),
                                context(2, false),
                                context(3, false),
                                context(4, false),
                            ],
                        )?;
                        break;
                    }
                    if field.tag.number <= previous {
                        return Err(Error::new(ErrorKind::InvalidFilter, field.offset));
                    }
                    previous = field.tag.number;
                    match field.tag.number {
                        1 => {
                            let rule = text(field)?;
                            if !valid_descriptor(rule) && !valid_oid(rule) {
                                return Err(Error::new(ErrorKind::InvalidOid, value_offset(field)));
                            }
                            matching_rule = Some(rule);
                        }
                        2 => name = Some(attribute(field)?),
                        3 => value = Some(field.value),
                        4 => {
                            dn_attributes = ldap_boolean(field)?;
                            if !dn_attributes {
                                return Err(Error::new(ErrorKind::InvalidValue, field.offset));
                            }
                        }
                        _ => (),
                    }
                }
                if matching_rule.is_none() && name.is_none() {
                    return Err(Error::new(ErrorKind::InvalidFilter, t.offset));
                }
                Ok(FilterKind::ExtensibleMatch {
                    matching_rule,
                    attribute: name,
                    value: value.ok_or_else(|| Error::new(ErrorKind::MissingField, t.offset))?,
                    dn_attributes,
                })
            }
            _ => Err(Error::new(ErrorKind::InvalidFilter, t.offset)),
        }
    }

    /// Iterate immediate children of AND, OR or NOT; leaves return an empty iterator.
    pub fn children(&self) -> Result<Filters<'a>> {
        let bytes = if matches!(
            self.kind()?,
            FilterKind::And | FilterKind::Or | FilterKind::Not
        ) {
            self.tlv.value
        } else {
            &[]
        };
        Ok(Filters {
            cursor: Cursor::new(
                bytes,
                value_offset(self.tlv),
                ber::framing_limits(self.max_message_len),
            ),
            max_message_len: self.max_message_len,
        })
    }

    /// Preorder traversal with depth, using one caller slot per logical ancestor.
    /// Workspace exhaustion returns an error and terminates the iterator.
    pub fn events<'w>(&self, workspace: &'w mut [usize]) -> FilterEvents<'a, 'w> {
        FilterEvents {
            input: self.tlv.encoded,
            base: self.tlv.offset,
            max_message_len: self.max_message_len,
            workspace,
            offset: 0,
            depth: 0,
            failed: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Filters<'a> {
    cursor: Cursor<'a>,
    max_message_len: usize,
}

impl<'a> Iterator for Filters<'a> {
    type Item = Result<Filter<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.cursor.next() {
            Ok(Some(tlv)) => Some(Ok(Filter {
                tlv,
                max_message_len: self.max_message_len,
            })),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Substring<'a> {
    Initial(&'a [u8]),
    Any(&'a [u8]),
    Final(&'a [u8]),
}

#[derive(Clone, Copy, Debug)]
pub struct Substrings<'a> {
    cursor: Cursor<'a>,
}

impl<'a> Iterator for Substrings<'a> {
    type Item = Result<Substring<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        match self.cursor.next() {
            Ok(Some(t)) => Some(match t.tag {
                tag if tag == context(0, false) => Ok(Substring::Initial(t.value)),
                tag if tag == context(1, false) => Ok(Substring::Any(t.value)),
                tag if tag == context(2, false) => Ok(Substring::Final(t.value)),
                _ => Err(Error::new(ErrorKind::InvalidFilter, t.offset)),
            }),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FilterEvent<'a> {
    pub depth: usize,
    pub filter: Filter<'a>,
}

pub struct FilterEvents<'a, 'w> {
    input: &'a [u8],
    base: usize,
    max_message_len: usize,
    workspace: &'w mut [usize],
    offset: usize,
    depth: usize,
    failed: bool,
}

impl<'a> Iterator for FilterEvents<'a, '_> {
    type Item = Result<FilterEvent<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.offset == self.input.len() {
            return None;
        }
        let result = (|| {
            while self.depth > 0 && self.offset >= self.workspace[self.depth - 1] {
                self.depth -= 1;
            }
            let (tlv, used) = Tlv::parse_at(
                &self.input[self.offset..],
                self.base + self.offset,
                ber::framing_limits(self.max_message_len),
            )?;
            let filter = Filter {
                tlv,
                max_message_len: self.max_message_len,
            };
            let depth = self.depth;
            if matches!(
                filter.kind()?,
                FilterKind::And | FilterKind::Or | FilterKind::Not
            ) {
                let slot = self.workspace.get_mut(self.depth).ok_or_else(|| {
                    Error::new(ErrorKind::WorkspaceTooSmall, self.base + self.offset)
                })?;
                *slot = self.offset + used;
                self.depth += 1;
                self.offset += used - tlv.value.len();
            } else {
                self.offset += used;
            }
            Ok(FilterEvent { depth, filter })
        })();
        if result.is_err() {
            self.failed = true;
        }
        Some(result)
    }
}
