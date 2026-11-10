use zldap::ber::{Class, Frame, Tag, Writer};
use zldap::{
    DerefAliases, Filter, Message, MessageInput, Operation, OperationInput, ParseLimits, Scope,
    SearchInput,
};

fn main() -> Result<(), zldap::Error> {
    let limits = ParseLimits::default();
    let mut workspace = [Frame::EMPTY; 32];
    let mut filter_buffer = [0u8; 64];
    let mut writer = Writer::new(&mut filter_buffer);
    writer.write_tlv(Tag::new(Class::Context, false, 7), b"objectClass")?;
    let filter = Filter::parse(writer.finish(), limits, &mut workspace)?;
    let request = MessageInput {
        id: 2,
        operation: OperationInput::SearchRequest(SearchInput {
            base_dn: "dc=example,dc=org",
            scope: Scope::Subtree,
            deref_aliases: DerefAliases::Never,
            size_limit: 100,
            time_limit: 5,
            types_only: false,
            filter,
            attributes: &["cn", "mail"],
        }),
        controls: &[],
    };
    let mut output = [0u8; 512];
    let written = request.encode(&mut output)?;
    let decoded = Message::parse(&output[..written], limits, &mut workspace)?;
    if let Operation::SearchRequest(search) = decoded.operation {
        println!(
            "message {}, {} bytes, base {}",
            decoded.id, written, search.base_dn
        );
        for attribute in search.attributes {
            println!("requested attribute: {}", attribute?);
        }
    }
    Ok(())
}
