#![no_std]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

//! The codec reads protocol data. It never authenticates a peer, evaluates an
//! access policy, or opens a network connection.

pub mod ber;
mod encode;
mod filter;
mod ldap;

pub use encode::{Attribute, ControlInput, MessageInput, OperationInput, ResultInput, SearchInput};
pub use filter::{Filter, FilterEvent, FilterEvents, FilterKind, Filters, Substring, Substrings};
pub use ldap::{
    AttributeValues, Attributes, Authentication, BindRequest, BindResponse, Control, Controls,
    DerefAliases, LdapResult, Message, Operation, PartialAttribute, Scope, SearchRequest,
    SearchResultEntry, Strings,
};

/// A fallible protocol operation.
pub type Result<T> = core::result::Result<T, Error>;

/// Limits apply to one complete BER/LDAP frame, including all nested fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    /// Maximum encoded frame size, including its tag and length.
    pub max_message_len: usize,
    /// Maximum TLV depth; the outer message is depth one.
    pub max_depth: usize,
    /// Maximum total TLV count, including containers.
    pub max_fields: usize,
    /// Maximum primitive value length, including binary attribute values.
    pub max_string_len: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_message_len: 1_048_576,
            max_depth: 32,
            max_fields: 65_536,
            max_string_len: 1_048_576,
        }
    }
}

/// Stable error categories. Offsets are relative to the supplied frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    Truncated,
    InvalidTag,
    TagOverflow,
    IndefiniteLength,
    InvalidLength,
    LengthOverflow,
    MessageTooLong,
    DepthLimit,
    FieldLimit,
    StringTooLong,
    WorkspaceTooSmall,
    UnexpectedTag,
    InvalidInteger,
    IntegerOverflow,
    InvalidBoolean,
    InvalidValue,
    TrailingData,
    BufferTooSmall,
    InvalidMessageId,
    InvalidUtf8,
    InvalidFilter,
    InvalidEnumeration,
    InvalidVersion,
    InvalidAttribute,
    InvalidOid,
    MissingField,
    UnsupportedOperation(u32),
    UnsupportedAuthentication(u32),
}

/// A structured failure without heap storage or borrowed error strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error {
    pub kind: ErrorKind,
    pub offset: usize,
}

impl Error {
    pub const fn new(kind: ErrorKind, offset: usize) -> Self {
        Self { kind, offset }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?} at byte {}", self.kind, self.offset)
    }
}
