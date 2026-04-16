use simple_asn1::{ASN1Block, ASN1Class, BigInt, BigUint, FromASN1, ToASN1, OID};

use crate::message::obj_ident::{ObjectIdentifier, ObjectIdentifierError};
use std::net::Ipv4Addr;

use super::scoped_pdu::SNMPMessageError;
pub(crate) enum BindValue {
    Unspecified,
    Value(ObjectValue),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

pub(crate) enum ObjectValue {
    //Simple syntax
    Integer(i32),
    OctetString(Vec<u8>),
    ObjectIdentifier(ObjectIdentifier),
    //Application-wide syntax
    IpAddress(Ipv4Addr), // APPLICATION 0
    Counter32(u32),      // APPLICATION 1
    Gauge32(u32),        // APPLICATION 2
    TimeTicks(u64),      // APPLICATION 3  (range 0..4294967295)
    Opaque(Vec<u8>),     // APPLICATION 4
    Counter64(u64),      // APPLICATION 6
    Unsigned32(u32),     // APPLICATION 2  (same tag as Gauge32)
}

trait ToASN1Block {
    type Error: From<SNMPMessageError>;

    fn to_asn1_block(&self) -> Result<ASN1Block, Self::Error>;
}

// Encode an unsigned 32-bit value as minimal big-endian BER integer bytes.
// A leading 0x00 is prepended when the high bit of the first byte is set,
// preventing the value from being interpreted as negative.
fn encode_uint32(v: u32) -> Vec<u8> {
    if v == 0 {
        return vec![0x00];
    }
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let trimmed = &bytes[start..];
    if trimmed[0] & 0x80 != 0 {
        let mut out = vec![0x00];
        out.extend_from_slice(trimmed);
        out
    } else {
        trimmed.to_vec()
    }
}

// Same as encode_uint32 but for 64-bit values (Counter64).
fn encode_uint64(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0x00];
    }
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let trimmed = &bytes[start..];
    if trimmed[0] & 0x80 != 0 {
        let mut out = vec![0x00];
        out.extend_from_slice(trimmed);
        out
    } else {
        trimmed.to_vec()
    }
}

// Build an APPLICATION-tagged primitive block (RFC 2578 application-wide types).
fn app_block(tag: u8, content: Vec<u8>) -> ASN1Block {
    ASN1Block::Unknown(
        ASN1Class::Application,
        false,
        0,
        BigUint::from(tag),
        content,
    )
}

impl ToASN1Block for ObjectValue {
    type Error = SNMPMessageError;

    fn to_asn1_block(&self) -> Result<ASN1Block, Self::Error> {
        let asn_block = match self {
            ObjectValue::Integer(v) => ASN1Block::Integer(0, BigInt::from(*v)),
            ObjectValue::OctetString(v) => ASN1Block::OctetString(v.len(), v.clone()),
            ObjectValue::ObjectIdentifier(oid) => {
                let asn1_oid = OID::try_from(oid).map_err(|e: ObjectIdentifierError| {
                    SNMPMessageError::EncodeError(e.to_string())
                })?;
                ASN1Block::ObjectIdentifier(oid.length(), asn1_oid)
            }
            ObjectValue::IpAddress(ip) => app_block(0, ip.octets().to_vec()),
            ObjectValue::Counter32(v) => app_block(1, encode_uint32(*v)),
            ObjectValue::Gauge32(v) => app_block(2, encode_uint32(*v)),
            ObjectValue::TimeTicks(v) => app_block(3, encode_uint64(*v)),
            ObjectValue::Opaque(v) => app_block(4, v.clone()),
            ObjectValue::Counter64(v) => app_block(6, encode_uint64(*v)),
            ObjectValue::Unsigned32(v) => app_block(2, encode_uint32(*v)),
        };

        Ok(asn_block)
    }
}

// RFC 3416: exception values use implicit context-specific tags [0], [1], [2].
fn exception_block(tag: u8) -> ASN1Block {
    ASN1Block::Unknown(
        ASN1Class::ContextSpecific,
        false,
        0,
        BigUint::from(tag),
        vec![],
    )
}

impl ToASN1Block for BindValue {
    type Error = SNMPMessageError;

    fn to_asn1_block(&self) -> Result<ASN1Block, Self::Error> {
        let asn_block = match self {
            BindValue::Unspecified => ASN1Block::Null(0),
            BindValue::Value(ov) => ov.to_asn1_block()?,
            BindValue::NoSuchObject => exception_block(0),
            BindValue::NoSuchInstance => exception_block(1),
            BindValue::EndOfMibView => exception_block(2),
        };

        Ok(asn_block)
    }
}

impl TryFrom<&ObjectIdentifier> for OID {
    type Error = ObjectIdentifierError;

    fn try_from(value: &ObjectIdentifier) -> Result<Self, Self::Error> {
        if value.length() > crate::message::obj_ident::MAX_OBJECT_IDENTIFIER_LEN {
            return Err(ObjectIdentifierError::TooLong(value.length()));
        };

        let big_vec: Vec<BigUint> = value
            .get_value()
            .iter()
            .map(|&v| BigUint::from(v))
            .collect();

        Ok(OID::new(big_vec))
    }
}
// RFC 3416
pub(crate) struct VarBind {
    name: ObjectIdentifier,
    value: BindValue,
}

impl VarBind {
    pub(crate) fn new(name: ObjectIdentifier, value: BindValue) -> Self {
        Self { name, value }
    }
}

impl FromASN1 for VarBind {
    type Error = SNMPMessageError;

    fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
        todo!()
    }
}

impl ToASN1 for VarBind {
    type Error = SNMPMessageError;

    fn to_asn1_class(&self, _c: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let mut asn_vec: Vec<ASN1Block> = Vec::new();

        // encode ObjectIdentifier
        match OID::try_from(&self.name) {
            Ok(oid) => asn_vec.push(ASN1Block::ObjectIdentifier(self.name.length(), oid)),
            Err(_) => {
                return Err(SNMPMessageError::EncodeError(
                    "Error encoding OID".to_string(),
                ))
            }
        }

        let value_block = self.value.to_asn1_block()?;

        asn_vec.push(value_block);

        let asn_seq = ASN1Block::Sequence(0, asn_vec);

        Ok(vec![asn_seq])
    }
}

#[cfg(test)]
mod tests {
    use simple_asn1::oid;

    use super::*;

    #[test]
    fn test_create_var_bind() {
        let name = ObjectIdentifier::new(vec![1, 3, 5, 7, 9, 11, 13, 17]).unwrap();
        let value = BindValue::Unspecified;

        let var_bind = VarBind::new(name, value);
        let asn = var_bind.to_asn1().unwrap();

        assert_eq!(
            asn,
            vec![ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::ObjectIdentifier(8, oid!(1, 3, 5, 7, 9, 11, 13, 17)),
                    ASN1Block::Null(0),
                ]
            )]
        );
    }

    #[test]
    fn test_create_var_bind_with_int_value() {
        let name = ObjectIdentifier::new(vec![1, 3, 5, 7, 9, 11, 13, 17]).unwrap();
        let value = BindValue::Value(ObjectValue::Integer(42));

        let var_bind = VarBind::new(name, value);
        let asn = var_bind.to_asn1().unwrap();

        assert_eq!(
            asn,
            vec![ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::ObjectIdentifier(8, oid!(1, 3, 5, 7, 9, 11, 13, 17)),
                    ASN1Block::Integer(0, BigInt::from(42)),
                ]
            )]
        );
    }
    #[test]
    fn test_create_var_bind_with_string_value() {
        let name = ObjectIdentifier::new(vec![1, 3, 5, 7, 9, 11, 13, 17]).unwrap();
        let value = BindValue::Value(ObjectValue::OctetString(b"This is a test".to_vec()));

        let var_bind = VarBind::new(name, value);
        let asn = var_bind.to_asn1().unwrap();

        assert_eq!(
            asn,
            vec![ASN1Block::Sequence(
                0,
                vec![
                    ASN1Block::ObjectIdentifier(8, oid!(1, 3, 5, 7, 9, 11, 13, 17)),
                    ASN1Block::OctetString(14, b"This is a test".to_vec()),
                ]
            )]
        );
    }
}
