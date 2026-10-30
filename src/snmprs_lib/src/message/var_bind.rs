use asn1_rs::{Class, ToDer};

use std::net::Ipv4Addr;

use super::der;
use super::obj_ident::ObjectIdentifier;
use crate::errors::SnmpMessageError;

// RFC 2578 application-wide tags. Unsigned32 and Gauge32 share a tag on the wire.
const TAG_IP_ADDRESS: u32 = 0;
const TAG_COUNTER32: u32 = 1;
const TAG_GAUGE32: u32 = 2;
const TAG_TIME_TICKS: u32 = 3;
const TAG_OPAQUE: u32 = 4;
const TAG_COUNTER64: u32 = 6;

// RFC 3416 exception tags, used in place of a value in a response.
const TAG_NO_SUCH_OBJECT: u32 = 0;
const TAG_NO_SUCH_INSTANCE: u32 = 1;
const TAG_END_OF_MIB_VIEW: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindValue {
    Unspecified,
    Value(ObjectValue),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl BindValue {
    fn encode(&self) -> Result<Vec<u8>, SnmpMessageError> {
        match self {
            BindValue::Unspecified => ObjectValue::Null.encode(),
            BindValue::Value(value) => value.encode(),
            BindValue::NoSuchObject => exception(TAG_NO_SUCH_OBJECT),
            BindValue::NoSuchInstance => exception(TAG_NO_SUCH_INSTANCE),
            BindValue::EndOfMibView => exception(TAG_END_OF_MIB_VIEW),
        }
    }
}

fn exception(tag: u32) -> Result<Vec<u8>, SnmpMessageError> {
    der::tlv(Class::ContextSpecific, false, tag, &[])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectValue {
    //Simple syntax
    Integer(i32),
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(ObjectIdentifier),
    //Application-wide syntax
    IpAddress(Ipv4Addr),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
    Unsigned32(u32),
}

impl ObjectValue {
    fn encode(&self) -> Result<Vec<u8>, SnmpMessageError> {
        match self {
            ObjectValue::Integer(v) => der::integer(*v),
            ObjectValue::OctetString(v) => der::octet_string(v),
            ObjectValue::Null => Ok(asn1_rs::Null::new().to_der_vec()?),
            ObjectValue::ObjectIdentifier(v) => Ok(v.to_oid()?.to_der_vec()?),
            ObjectValue::IpAddress(v) => application(TAG_IP_ADDRESS, &v.octets()),
            ObjectValue::Counter32(v) => application_uint(TAG_COUNTER32, u64::from(*v)),
            ObjectValue::Gauge32(v) => application_uint(TAG_GAUGE32, u64::from(*v)),
            ObjectValue::TimeTicks(v) => application_uint(TAG_TIME_TICKS, u64::from(*v)),
            ObjectValue::Opaque(v) => application(TAG_OPAQUE, v),
            ObjectValue::Counter64(v) => application_uint(TAG_COUNTER64, *v),
            ObjectValue::Unsigned32(v) => application_uint(TAG_GAUGE32, u64::from(*v)),
        }
    }
}

fn application(tag: u32, content: &[u8]) -> Result<Vec<u8>, SnmpMessageError> {
    der::tlv(Class::Application, false, tag, content)
}

// Implicitly tagged unsigned INTEGER: minimal big-endian bytes, with a leading zero
// when the top bit is set so the value isn't read as negative.
fn application_uint(tag: u32, value: u64) -> Result<Vec<u8>, SnmpMessageError> {
    let bytes = value.to_be_bytes();
    let first = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);

    let mut content = Vec::with_capacity(bytes.len() - first + 1);
    if bytes[first] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(&bytes[first..]);

    application(tag, &content)
}

// RFC 3416
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarBind {
    name: ObjectIdentifier,
    value: BindValue,
}

impl VarBind {
    pub fn new(name: ObjectIdentifier, value: BindValue) -> Self {
        Self { name, value }
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, SnmpMessageError> {
        let mut content = self.name.to_oid()?.to_der_vec()?;
        content.extend(self.value.encode()?);
        der::sequence(&content)
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
