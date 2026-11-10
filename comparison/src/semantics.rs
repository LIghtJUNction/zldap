//! One field walk for exact equality and for allocation-free payload scans.
//! Recursion here only visits already validated, depth-bounded fixtures; the
//! production zldap parser has no recursive traversal.
use ldap3_proto::{control::LdapControl, proto::*};
use zldap::{Authentication, Filter, FilterKind, Message, Operation, Substring};

pub trait Sink {
    fn word(&mut self, value: u64);
    fn bytes(&mut self, value: &[u8]);
    fn optional_bytes(&mut self, value: Option<&[u8]>) {
        self.word(value.is_some() as u64);
        if let Some(value) = value {
            self.bytes(value);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Field {
    Number(u64),
    Bytes(Vec<u8>),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Fields(pub Vec<Field>);
impl Sink for Fields {
    fn word(&mut self, value: u64) {
        self.0.push(Field::Number(value));
    }
    fn bytes(&mut self, value: &[u8]) {
        self.0.push(Field::Bytes(value.to_vec()));
    }
}

pub struct Digest(pub u64);
impl Default for Digest {
    fn default() -> Self {
        Self(0xcbf29ce484222325)
    }
}
impl Digest {
    fn feed(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ *byte as u64).wrapping_mul(0x100000001b3);
        }
    }
}
impl Sink for Digest {
    fn word(&mut self, value: u64) {
        self.feed(&value.to_le_bytes());
    }
    fn bytes(&mut self, value: &[u8]) {
        self.word(value.len() as u64);
        self.feed(value);
    }
}

fn end(sink: &mut impl Sink) {
    sink.word(u64::MAX);
}

pub fn zldap(message: &Message<'_>, sink: &mut impl Sink) {
    sink.word(message.id as u64);
    match message.operation {
        Operation::BindRequest(request) => {
            sink.word(0);
            sink.word(request.version as u64);
            sink.bytes(request.name.as_bytes());
            match request.authentication {
                Authentication::Simple(bytes) => {
                    sink.word(0);
                    sink.bytes(bytes);
                }
                Authentication::Sasl {
                    mechanism,
                    credentials,
                } => {
                    sink.word(3);
                    sink.bytes(mechanism.as_bytes());
                    // ldap3_proto normalizes omitted SASL credentials to empty.
                    sink.bytes(credentials.unwrap_or_default());
                }
            }
        }
        Operation::BindResponse(response) => {
            sink.word(1);
            result_z(response.result, sink);
            sink.optional_bytes(response.server_sasl_credentials);
        }
        Operation::UnbindRequest => sink.word(2),
        Operation::SearchRequest(request) => {
            sink.word(3);
            sink.bytes(request.base_dn.as_bytes());
            sink.word(request.scope as u64);
            sink.word(request.deref_aliases as u64);
            sink.word(request.size_limit as u64);
            sink.word(request.time_limit as u64);
            sink.word(request.types_only as u64);
            filter_z(request.filter, sink);
            for value in request.attributes {
                sink.bytes(value.unwrap().as_bytes());
            }
            end(sink);
        }
        Operation::SearchResultEntry(entry) => {
            sink.word(4);
            sink.bytes(entry.object_name.as_bytes());
            for attribute in entry.attributes {
                let attribute = attribute.unwrap();
                sink.bytes(attribute.description.as_bytes());
                for value in attribute.values {
                    sink.bytes(value.unwrap());
                }
                end(sink);
            }
            end(sink);
        }
        Operation::SearchResultDone(result) => {
            sink.word(5);
            result_z(result, sink);
        }
    }
    for control in message.controls {
        let control = control.unwrap();
        sink.bytes(control.oid.as_bytes());
        sink.word(control.critical as u64);
        sink.optional_bytes(control.value);
    }
    end(sink);
}

fn result_z(result: zldap::LdapResult<'_>, sink: &mut impl Sink) {
    sink.word(result.code as u64);
    sink.bytes(result.matched_dn.as_bytes());
    sink.bytes(result.diagnostic_message.as_bytes());
    for referral in result.referrals {
        sink.bytes(referral.unwrap().as_bytes());
    }
    end(sink);
}

fn filter_z(filter: Filter<'_>, sink: &mut impl Sink) {
    match filter.kind().unwrap() {
        FilterKind::And | FilterKind::Or | FilterKind::Not => {
            sink.word(match filter.kind().unwrap() {
                FilterKind::And => 0,
                FilterKind::Or => 1,
                _ => 2,
            });
            for child in filter.children().unwrap() {
                filter_z(child.unwrap(), sink);
            }
            end(sink);
        }
        FilterKind::Equality { attribute, value } => assertion(sink, 3, attribute, value),
        FilterKind::Substrings {
            attribute,
            components,
        } => {
            sink.word(4);
            sink.bytes(attribute.as_bytes());
            for component in components {
                let (kind, value) = match component.unwrap() {
                    Substring::Initial(v) => (0, v),
                    Substring::Any(v) => (1, v),
                    Substring::Final(v) => (2, v),
                };
                sink.word(kind);
                sink.bytes(value);
            }
            end(sink);
        }
        FilterKind::GreaterOrEqual { attribute, value } => assertion(sink, 5, attribute, value),
        FilterKind::LessOrEqual { attribute, value } => assertion(sink, 6, attribute, value),
        FilterKind::Present(attribute) => {
            sink.word(7);
            sink.bytes(attribute.as_bytes());
        }
        FilterKind::ApproxMatch { attribute, value } => assertion(sink, 8, attribute, value),
        FilterKind::ExtensibleMatch {
            matching_rule,
            attribute,
            value,
            dn_attributes,
        } => {
            sink.word(9);
            sink.optional_bytes(matching_rule.map(str::as_bytes));
            sink.optional_bytes(attribute.map(str::as_bytes));
            sink.bytes(value);
            sink.word(dn_attributes as u64);
        }
    }
}

fn assertion(sink: &mut impl Sink, kind: u64, attribute: &str, value: &[u8]) {
    sink.word(kind);
    sink.bytes(attribute.as_bytes());
    sink.bytes(value);
}

pub fn kanidm(message: &LdapMsg, sink: &mut impl Sink) {
    sink.word(message.msgid as u64);
    match &message.op {
        LdapOp::BindRequest(request) => {
            sink.word(0);
            sink.word(request.version as u64);
            sink.bytes(request.dn.as_bytes());
            match &request.cred {
                LdapBindCred::Simple(value) => {
                    sink.word(0);
                    sink.bytes(value.as_bytes());
                }
                LdapBindCred::SASL(credentials) => {
                    sink.word(3);
                    sink.bytes(credentials.mechanism.as_bytes());
                    sink.bytes(&credentials.credentials);
                }
                _ => panic!("oracle unsupported authentication outside corpus"),
            }
        }
        LdapOp::BindResponse(response) => {
            sink.word(1);
            result_k(&response.res, sink);
            sink.optional_bytes(response.saslcreds.as_deref());
        }
        LdapOp::UnbindRequest => sink.word(2),
        LdapOp::SearchRequest(request) => {
            sink.word(3);
            sink.bytes(request.base.as_bytes());
            sink.word(request.scope.clone() as u64);
            sink.word(request.aliases.clone() as u64);
            sink.word(request.sizelimit as u64);
            sink.word(request.timelimit as u64);
            sink.word(request.typesonly as u64);
            filter_k(&request.filter, sink);
            for value in &request.attrs {
                sink.bytes(value.as_bytes());
            }
            end(sink);
        }
        LdapOp::SearchResultEntry(entry) => {
            sink.word(4);
            sink.bytes(entry.dn.as_bytes());
            for attribute in &entry.attributes {
                sink.bytes(attribute.atype.as_bytes());
                for value in &attribute.vals {
                    sink.bytes(value);
                }
                end(sink);
            }
            end(sink);
        }
        LdapOp::SearchResultDone(result) => {
            sink.word(5);
            result_k(result, sink);
        }
        _ => panic!("oracle operation outside shared benchmark subset"),
    }
    for control in &message.ctrl {
        match control {
            LdapControl::Unknown {
                oid,
                criticality,
                value,
            } => {
                sink.bytes(oid.as_bytes());
                sink.word(*criticality as u64);
                sink.optional_bytes(value.as_deref());
            }
            _ => panic!("only opaque controls are in shared benchmark subset"),
        }
    }
    end(sink);
}

fn result_k(result: &LdapResult, sink: &mut impl Sink) {
    sink.word(result.code.clone() as u64);
    sink.bytes(result.matcheddn.as_bytes());
    sink.bytes(result.message.as_bytes());
    for referral in &result.referral {
        sink.bytes(referral.as_bytes());
    }
    end(sink);
}

fn filter_k(filter: &LdapFilter, sink: &mut impl Sink) {
    match filter {
        LdapFilter::And(children) | LdapFilter::Or(children) => {
            sink.word(if matches!(filter, LdapFilter::And(_)) {
                0
            } else {
                1
            });
            for child in children {
                filter_k(child, sink);
            }
            end(sink);
        }
        LdapFilter::Not(child) => {
            sink.word(2);
            filter_k(child, sink);
            end(sink);
        }
        LdapFilter::Equality(a, v) => assertion(sink, 3, a, v.as_bytes()),
        LdapFilter::Substring(attribute, filter) => {
            sink.word(4);
            sink.bytes(attribute.as_bytes());
            if let Some(initial) = &filter.initial {
                sink.word(0);
                sink.bytes(initial.as_bytes());
            }
            for any in &filter.any {
                sink.word(1);
                sink.bytes(any.as_bytes());
            }
            if let Some(final_) = &filter.final_ {
                sink.word(2);
                sink.bytes(final_.as_bytes());
            }
            end(sink);
        }
        LdapFilter::GreaterOrEqual(a, v) => assertion(sink, 5, a, v.as_bytes()),
        LdapFilter::LessOrEqual(a, v) => assertion(sink, 6, a, v.as_bytes()),
        LdapFilter::Present(attribute) => {
            sink.word(7);
            sink.bytes(attribute.as_bytes());
        }
        LdapFilter::Approx(a, v) => assertion(sink, 8, a, v.as_bytes()),
        LdapFilter::Extensible(filter) => {
            sink.word(9);
            sink.optional_bytes(filter.matching_rule.as_deref().map(str::as_bytes));
            sink.optional_bytes(filter.type_.as_deref().map(str::as_bytes));
            sink.bytes(filter.match_value.as_bytes());
            sink.word(filter.dn_attributes as u64);
        }
    }
}
