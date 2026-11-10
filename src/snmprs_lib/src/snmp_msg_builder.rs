use std::fmt::Debug;
use std::str::FromStr;

use crate::errors::SnmpMessageError;
use crate::message::obj_ident::ObjectIdentifier;
use crate::message::pdu::{BulkPdu, Pdu, PduType};
use crate::message::v2c_message::V2cMessage;
use crate::message::var_bind::{BindValue, ObjectValue, VarBind};

/// Builds single-varbind request messages from an OID string.
pub trait SnmpMessageBuilder {
    /// Builds a GetRequest for `oid`.
    fn get(&self, oid: &str) -> Result<V2cMessage, SnmpMessageError>;
    /// Builds a GetNextRequest for `oid`.
    fn get_next(&self, oid: &str) -> Result<V2cMessage, SnmpMessageError>;
    /// Builds a GetBulkRequest for `oid`. Both counts must be at most 2147483647.
    fn get_bulk(
        &self,
        oid: &str,
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Result<V2cMessage, SnmpMessageError>;
    /// Builds a SetRequest that writes `value` to `oid`.
    fn set(&self, oid: &str, value: ObjectValue) -> Result<V2cMessage, SnmpMessageError>;
}

/// Builds SNMPv2c messages that all use one community string.
pub struct SnmpV2MessageBuilder {
    community: Vec<u8>,
}

impl Debug for SnmpV2MessageBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnmpV2MessageBuilder")
            .field("community", &"[REDACTED]")
            .finish()
    }
}

impl SnmpV2MessageBuilder {
    /// Creates a builder for `community`. Communities are raw bytes on the wire, so
    /// any byte string is accepted, including a `String`, `&[u8]` or `Vec<u8>`.
    pub fn new(community: impl Into<Vec<u8>>) -> Self {
        Self {
            community: community.into(),
        }
    }

    fn request(
        &self,
        pdu_type: PduType,
        oid: &str,
        value: BindValue,
    ) -> Result<V2cMessage, SnmpMessageError> {
        let pdu = Pdu::new(pdu_type, vec![var_bind(oid, value)?]);
        Ok(V2cMessage::new(self.community.clone(), pdu.into()))
    }
}

fn var_bind(oid: &str, value: BindValue) -> Result<VarBind, SnmpMessageError> {
    Ok(VarBind::new(ObjectIdentifier::from_str(oid)?, value))
}

impl SnmpMessageBuilder for SnmpV2MessageBuilder {
    fn get(&self, oid: &str) -> Result<V2cMessage, SnmpMessageError> {
        self.request(PduType::GetRequest, oid, BindValue::Unspecified)
    }

    fn get_next(&self, oid: &str) -> Result<V2cMessage, SnmpMessageError> {
        self.request(PduType::GetNextRequest, oid, BindValue::Unspecified)
    }

    fn get_bulk(
        &self,
        oid: &str,
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Result<V2cMessage, SnmpMessageError> {
        let pdu = BulkPdu::new(
            non_repeaters,
            max_repetitions,
            vec![var_bind(oid, BindValue::Unspecified)?],
        )?;
        Ok(V2cMessage::new(self.community.clone(), pdu.into()))
    }

    fn set(&self, oid: &str, value: ObjectValue) -> Result<V2cMessage, SnmpMessageError> {
        self.request(PduType::SetRequest, oid, BindValue::Value(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";

    // Skips the SEQUENCE header, version and community ("public") to reach the PDU tag.
    const PDU_TAG_OFFSET: usize = 2 + 3 + 8;

    #[test]
    fn test_requests_use_the_right_pdu_tag() {
        let builder = SnmpV2MessageBuilder::new("public".to_string());

        let tag = |msg: V2cMessage| msg.encode().unwrap()[PDU_TAG_OFFSET];
        assert_eq!(tag(builder.get(SYS_DESCR).unwrap()), 0xa0);
        assert_eq!(tag(builder.get_next(SYS_DESCR).unwrap()), 0xa1);
        assert_eq!(
            tag(builder.set(SYS_DESCR, ObjectValue::Integer(1)).unwrap()),
            0xa3
        );
        assert_eq!(tag(builder.get_bulk(SYS_DESCR, 0, 10).unwrap()), 0xa5);
    }

    #[test]
    fn test_set_encodes_the_value() {
        let builder = SnmpV2MessageBuilder::new("public".to_string());

        let msg = builder
            .set("1.3.6", ObjectValue::Integer(42))
            .unwrap()
            .encode()
            .unwrap();

        // VarBindList { VarBind { 1.3.6, INTEGER 42 } }
        let var_binds = [
            0x30, 0x09, 0x30, 0x07, 0x06, 0x02, 0x2b, 0x06, 0x02, 0x01, 0x2a,
        ];
        assert!(msg.ends_with(&var_binds), "{:02x?}", msg);
    }

    #[test]
    fn test_get_requests_an_unspecified_value() {
        let builder = SnmpV2MessageBuilder::new("public".to_string());

        for msg in [builder.get("1.3.6"), builder.get_next("1.3.6")] {
            let msg = msg.unwrap().encode().unwrap();
            let var_binds = [0x30, 0x08, 0x30, 0x06, 0x06, 0x02, 0x2b, 0x06, 0x05, 0x00];
            assert!(msg.ends_with(&var_binds), "{:02x?}", msg);
        }
    }

    #[test]
    fn test_get_bulk_encodes_repeater_fields() {
        let builder = SnmpV2MessageBuilder::new("public".to_string());

        let msg = builder.get_bulk("1.3.6", 1, 10).unwrap().encode().unwrap();

        // non-repeaters, max-repetitions, then the VarBindList.
        let tail = [
            0x02, 0x01, 0x01, 0x02, 0x01, 0x0a, 0x30, 0x08, 0x30, 0x06, 0x06, 0x02, 0x2b, 0x06,
            0x05, 0x00,
        ];
        assert!(msg.ends_with(&tail), "{:02x?}", msg);
    }

    #[test]
    fn test_get_bulk_rejects_out_of_range_fields() {
        let builder = SnmpV2MessageBuilder::new("public".to_string());
        assert!(matches!(
            builder.get_bulk(SYS_DESCR, 0, u32::MAX),
            Err(SnmpMessageError::BulkFieldOutOfRange { .. })
        ));
    }

    #[test]
    fn test_community_accepts_non_utf8_bytes() {
        let builder = SnmpV2MessageBuilder::new(&[0xff, 0x00][..]);

        let msg = builder.get(SYS_DESCR).unwrap().encode().unwrap();

        // SEQUENCE header and version, then the community OCTET STRING.
        assert_eq!(&msg[5..9], [0x04, 0x02, 0xff, 0x00]);
    }

    #[test]
    fn test_debug_redacts_the_community() {
        let builder = SnmpV2MessageBuilder::new("s3cret");
        let msg = builder.get(SYS_DESCR).unwrap();

        for debug in [format!("{:?}", builder), format!("{:?}", msg)] {
            assert!(!debug.contains("s3cret"), "{}", debug);
            assert!(debug.contains("[REDACTED]"), "{}", debug);
        }
    }

    #[test]
    fn test_invalid_oid_is_an_error() {
        let builder = SnmpV2MessageBuilder::new("public".to_string());
        assert!(matches!(
            builder.get("not.an.oid"),
            Err(SnmpMessageError::InvalidOid(_))
        ));
    }

    #[test]
    fn test_request_id_matches_the_encoded_message() {
        let builder = SnmpV2MessageBuilder::new("public".to_string());

        for msg in [
            builder.get(SYS_DESCR).unwrap(),
            builder.get_bulk(SYS_DESCR, 0, 10).unwrap(),
        ] {
            let encoded = msg.encode().unwrap();
            // Skip the PDU tag and length to reach the request-id INTEGER.
            let start = PDU_TAG_OFFSET + 2;
            assert_eq!(encoded[start], 0x02);
            let len = encoded[start + 1] as usize;
            let bytes = &encoded[start + 2..start + 2 + len];
            // Sign-extend the big-endian two's-complement value.
            let id = bytes[1..]
                .iter()
                .fold(bytes[0] as i8 as i64, |acc, &b| (acc << 8) | b as i64);
            assert_eq!(id, msg.request_id() as i64);
        }
    }
}
