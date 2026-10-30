use asn1_rs::{Any, Class, Header, Length, Tag, ToDer};

use crate::errors::SnmpMessageError;

const TAG_OCTET_STRING: u32 = 4;
const TAG_SEQUENCE: u32 = 16;

/// Encodes a tag-length-value with an arbitrary class and tag number. SNMP needs
/// this for its application-wide types and its implicitly tagged PDUs.
pub(super) fn tlv(
    class: Class,
    constructed: bool,
    tag: u32,
    content: &[u8],
) -> Result<Vec<u8>, SnmpMessageError> {
    let header = Header::new(
        class,
        constructed,
        Tag(tag),
        Length::Definite(content.len()),
    );
    Ok(Any::new(header, content).to_der_vec()?)
}

pub(super) fn sequence(content: &[u8]) -> Result<Vec<u8>, SnmpMessageError> {
    tlv(Class::Universal, true, TAG_SEQUENCE, content)
}

pub(super) fn octet_string(content: &[u8]) -> Result<Vec<u8>, SnmpMessageError> {
    tlv(Class::Universal, false, TAG_OCTET_STRING, content)
}

pub(super) fn integer(value: i32) -> Result<Vec<u8>, SnmpMessageError> {
    Ok(value.to_der_vec()?)
}
