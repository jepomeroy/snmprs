use std::net::Ipv4Addr;

use super::ber;
use super::obj_ident::ObjectIdentifier;
use crate::errors::SnmpMessageError;
use crate::message::ber::Tag::{
    self, Counter32, Counter64, GaugeOrUnsigned32, IpAddress, Null, OctetString, Opaque, Sequence,
    TimeTicks,
};

/// The value half of a variable binding (RFC 3416).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindValue {
    /// No value, as sent in requests that only name variables. Encoded as NULL.
    Unspecified,
    /// A real value.
    Value(ObjectValue),
    /// The agent doesn't implement the object type.
    NoSuchObject,
    /// The object type exists but this instance doesn't.
    NoSuchInstance,
    /// A GetNext or GetBulk walk reached the end of the agent's MIB view.
    EndOfMibView,
}

impl BindValue {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, SnmpMessageError> {
        match self {
            BindValue::Unspecified => ObjectValue::Null.encode(),
            BindValue::Value(value) => value.encode(),
            BindValue::NoSuchObject => Ok(exception(Tag::NoSuchObject)),
            BindValue::NoSuchInstance => Ok(exception(Tag::NoSuchInstance)),
            BindValue::EndOfMibView => Ok(exception(Tag::EndOfMibView)),
        }
    }
}

// RFC 3416 exceptions replace the value in a response and have no content.
fn exception(tag: Tag) -> Vec<u8> {
    ber::write(tag, &[])
}

/// A value of one of the SMIv2 types (RFC 2578).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectValue {
    // Simple syntax
    /// A signed 32-bit INTEGER (Integer32).
    Integer(i32),
    /// An OCTET STRING, which can hold any bytes.
    OctetString(Vec<u8>),
    /// A NULL value.
    Null,
    /// An OBJECT IDENTIFIER.
    ObjectIdentifier(ObjectIdentifier),
    // Application-wide syntax
    /// An IPv4 address.
    IpAddress(Ipv4Addr),
    /// A 32-bit counter that wraps to zero.
    Counter32(u32),
    /// A 32-bit gauge that sticks at its maximum.
    Gauge32(u32),
    /// Time in hundredths of a second.
    TimeTicks(u32),
    /// Arbitrary BER-encoded data wrapped as an OCTET STRING.
    Opaque(Vec<u8>),
    /// A 64-bit counter that wraps to zero.
    Counter64(u64),
    /// An unsigned 32-bit integer. It shares Gauge32's tag on the wire.
    Unsigned32(u32),
}

impl ObjectValue {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, SnmpMessageError> {
        match self {
            ObjectValue::Integer(v) => Ok(ber::integer(*v)),
            ObjectValue::OctetString(v) => Ok(ber::write(OctetString, v)),
            ObjectValue::Null => Ok(ber::write(Null, &Vec::new())),
            ObjectValue::ObjectIdentifier(v) => Ok(ber::oid(v.value())),
            ObjectValue::IpAddress(v) => Ok(ber::write(IpAddress, &v.octets())),
            ObjectValue::Counter32(v) => Ok(ber::unsigned(Counter32, u64::from(*v))),
            ObjectValue::Gauge32(v) => Ok(ber::unsigned(GaugeOrUnsigned32, u64::from(*v))),
            ObjectValue::TimeTicks(v) => Ok(ber::unsigned(TimeTicks, u64::from(*v))),
            ObjectValue::Opaque(v) => Ok(ber::write(Opaque, v)),
            ObjectValue::Counter64(v) => Ok(ber::unsigned(Counter64, *v)),
            ObjectValue::Unsigned32(v) => Ok(ber::unsigned(GaugeOrUnsigned32, u64::from(*v))),
        }
    }
}

/// A variable binding (RFC 3416): an OID paired with its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarBind {
    name: ObjectIdentifier,
    value: BindValue,
}

impl VarBind {
    /// Pairs `name` with `value`.
    pub fn new(name: ObjectIdentifier, value: BindValue) -> Self {
        Self { name, value }
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, SnmpMessageError> {
        let mut content = ber::oid(self.name.value());
        content.extend(self.value.encode()?);
        Ok(ber::write(Sequence, &content))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn encode_value(value: ObjectValue) -> Vec<u8> {
        value.encode().unwrap()
    }

    #[test]
    fn test_encode_var_bind_unspecified() {
        let name = ObjectIdentifier::from_str("1.3.6.1.2.1.1.1.0").unwrap();
        let var_bind = VarBind::new(name, BindValue::Unspecified);

        assert_eq!(
            var_bind.encode().unwrap(),
            [0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00]
        );
    }

    #[test]
    fn test_encode_simple_values() {
        assert_eq!(encode_value(ObjectValue::Integer(42)), [0x02, 0x01, 0x2a]);
        assert_eq!(encode_value(ObjectValue::Integer(-1)), [0x02, 0x01, 0xff]);
        assert_eq!(
            encode_value(ObjectValue::OctetString(b"abc".to_vec())),
            [0x04, 0x03, 0x61, 0x62, 0x63]
        );
        assert_eq!(encode_value(ObjectValue::Null), [0x05, 0x00]);
        assert_eq!(
            encode_value(ObjectValue::ObjectIdentifier(
                ObjectIdentifier::from_str("1.3.6").unwrap()
            )),
            [0x06, 0x02, 0x2b, 0x06]
        );
    }

    #[test]
    fn test_encode_application_values() {
        assert_eq!(
            encode_value(ObjectValue::IpAddress(Ipv4Addr::new(192, 168, 0, 1))),
            [0x40, 0x04, 0xc0, 0xa8, 0x00, 0x01]
        );
        assert_eq!(encode_value(ObjectValue::Counter32(0)), [0x41, 0x01, 0x00]);
        assert_eq!(
            encode_value(ObjectValue::Counter32(u32::MAX)),
            [0x41, 0x05, 0x00, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            encode_value(ObjectValue::Gauge32(128)),
            [0x42, 0x02, 0x00, 0x80]
        );
        assert_eq!(
            encode_value(ObjectValue::Unsigned32(127)),
            [0x42, 0x01, 0x7f]
        );
        assert_eq!(
            encode_value(ObjectValue::TimeTicks(256)),
            [0x43, 0x02, 0x01, 0x00]
        );
        assert_eq!(
            encode_value(ObjectValue::Opaque(vec![0xde, 0xad])),
            [0x44, 0x02, 0xde, 0xad]
        );
        assert_eq!(
            encode_value(ObjectValue::Counter64(u64::MAX)),
            [0x46, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn test_encode_integer_limits() {
        assert_eq!(
            encode_value(ObjectValue::Integer(i32::MAX)),
            [0x02, 0x04, 0x7f, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            encode_value(ObjectValue::Integer(i32::MIN)),
            [0x02, 0x04, 0x80, 0x00, 0x00, 0x00]
        );
        assert_eq!(encode_value(ObjectValue::Integer(0)), [0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_unsigned_widths() {
        assert_eq!(encode_value(ObjectValue::Counter64(0)), [0x46, 0x01, 0x00]);
        assert_eq!(
            encode_value(ObjectValue::Counter64(255)),
            [0x46, 0x02, 0x00, 0xff]
        );
        assert_eq!(
            encode_value(ObjectValue::Counter64(1 << 32)),
            [0x46, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_encode_octet_string_length_forms() {
        let lengths: [(usize, &[u8]); 4] = [
            (127, &[0x04, 0x7f]),
            (128, &[0x04, 0x81, 0x80]),
            (255, &[0x04, 0x81, 0xff]),
            (256, &[0x04, 0x82, 0x01, 0x00]),
        ];
        for (len, header) in lengths {
            let encoded = encode_value(ObjectValue::OctetString(vec![0xab; len]));

            assert_eq!(&encoded[..header.len()], header, "length {}", len);
            assert_eq!(encoded.len(), header.len() + len);
            assert!(encoded[header.len()..].iter().all(|&b| b == 0xab));
        }
    }

    #[test]
    fn test_encode_octet_string_with_non_utf8_bytes() {
        assert_eq!(
            encode_value(ObjectValue::OctetString(vec![0xff, 0x00])),
            [0x04, 0x02, 0xff, 0x00]
        );
    }

    #[test]
    fn test_encode_multi_byte_oid_arcs() {
        // 2021 is net-snmp's enterprise number: 0x8f 0x65 in base 128.
        assert_eq!(
            encode_value(ObjectValue::ObjectIdentifier(
                ObjectIdentifier::from_str("1.3.6.1.4.1.2021").unwrap()
            )),
            [0x06, 0x07, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x8f, 0x65]
        );
        assert_eq!(
            encode_value(ObjectValue::ObjectIdentifier(
                ObjectIdentifier::from_str("1.3.4294967295").unwrap()
            )),
            [0x06, 0x06, 0x2b, 0x8f, 0xff, 0xff, 0xff, 0x7f]
        );
    }

    #[test]
    fn test_encode_var_bind_with_value() {
        let name = ObjectIdentifier::from_str("1.3.6").unwrap();
        let var_bind = VarBind::new(name, BindValue::Value(ObjectValue::Gauge32(5)));

        assert_eq!(
            var_bind.encode().unwrap(),
            [0x30, 0x07, 0x06, 0x02, 0x2b, 0x06, 0x42, 0x01, 0x05]
        );
    }

    #[test]
    fn test_encode_exceptions() {
        assert_eq!(BindValue::NoSuchObject.encode().unwrap(), [0x80, 0x00]);
        assert_eq!(BindValue::NoSuchInstance.encode().unwrap(), [0x81, 0x00]);
        assert_eq!(BindValue::EndOfMibView.encode().unwrap(), [0x82, 0x00]);
    }
}
