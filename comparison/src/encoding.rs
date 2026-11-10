use zldap::{
    Attribute, ControlInput, Message, MessageInput, Operation, OperationInput, ResultInput,
    SearchInput,
};

/// Build the borrowed encoder's lists outside the measured region. The source
/// message and all strings/values already exist, as does the oracle's owned
/// LdapMsg. Callers must not return references to these temporary lists.
pub fn with_input<R>(message: Message<'_>, f: impl FnOnce(MessageInput<'_>) -> R) -> R {
    let controls: Vec<_> = message
        .controls
        .map(|control| {
            let control = control.unwrap();
            ControlInput {
                oid: control.oid,
                critical: control.critical,
                value: control.value,
            }
        })
        .collect();
    let make = |operation| MessageInput {
        id: message.id,
        operation,
        controls: &controls,
    };
    match message.operation {
        Operation::BindRequest(request) => f(make(OperationInput::BindRequest(request))),
        Operation::BindResponse(response) => {
            let referrals: Vec<_> = response.result.referrals.map(Result::unwrap).collect();
            f(make(OperationInput::BindResponse {
                result: ResultInput {
                    code: response.result.code,
                    matched_dn: response.result.matched_dn,
                    diagnostic_message: response.result.diagnostic_message,
                    referrals: &referrals,
                },
                server_sasl_credentials: response.server_sasl_credentials,
            }))
        }
        Operation::SearchRequest(request) => {
            let attributes: Vec<_> = request.attributes.map(Result::unwrap).collect();
            f(make(OperationInput::SearchRequest(SearchInput {
                base_dn: request.base_dn,
                scope: request.scope,
                deref_aliases: request.deref_aliases,
                size_limit: request.size_limit,
                time_limit: request.time_limit,
                types_only: request.types_only,
                filter: request.filter,
                attributes: &attributes,
            })))
        }
        Operation::SearchResultEntry(entry) => {
            let decoded: Vec<_> = entry.attributes.map(Result::unwrap).collect();
            let values: Vec<Vec<_>> = decoded
                .iter()
                .map(|attr| attr.values.map(Result::unwrap).collect())
                .collect();
            let attributes: Vec<_> = decoded
                .iter()
                .zip(&values)
                .map(|(attr, values)| Attribute {
                    description: attr.description,
                    values,
                })
                .collect();
            f(make(OperationInput::SearchResultEntry {
                object_name: entry.object_name,
                attributes: &attributes,
            }))
        }
        Operation::SearchResultDone(result) => {
            let referrals: Vec<_> = result.referrals.map(Result::unwrap).collect();
            f(make(OperationInput::SearchResultDone(ResultInput {
                code: result.code,
                matched_dn: result.matched_dn,
                diagnostic_message: result.diagnostic_message,
                referrals: &referrals,
            })))
        }
        Operation::UnbindRequest => f(make(OperationInput::UnbindRequest)),
    }
}
