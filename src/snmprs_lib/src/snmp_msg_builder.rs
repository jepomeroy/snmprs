use std::str::FromStr;

use crate::errors::SnmpMessageError;
use crate::message::obj_ident::ObjectIdentifier;
use crate::message::pdu::{BulkPdu, Pdu, PduType};
use crate::message::v2c_message::V2cMessage;
use crate::message::var_bind::{BindValue, ObjectValue, VarBind};

pub trait SnmpMessageBuilder {
    fn get(&self, oid: &str) -> Result<Vec<u8>, SnmpMessageError>;
    fn get_next(&self, oid: &str) -> Result<Vec<u8>, SnmpMessageError>;
    fn get_bulk(
        &self,
        oid: &str,
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Result<Vec<u8>, SnmpMessageError>;
    fn set(&self, oid: &str, value: ObjectValue) -> Result<Vec<u8>, SnmpMessageError>;
}

#[derive(Debug)]
pub struct SnmpV2MessageBuilder {
    community: Vec<u8>,
}

impl SnmpV2MessageBuilder {
    pub fn new(community: String) -> Self {
        Self {
            community: community.into_bytes(),
        }
    }

    fn request(
        &self,
        pdu_type: PduType,
        oid: &str,
        value: BindValue,
    ) -> Result<Vec<u8>, SnmpMessageError> {
        let pdu = Pdu::new(pdu_type, vec![var_bind(oid, value)?]);
        V2cMessage::new(self.community.clone(), pdu.into()).encode()
    }
}

fn var_bind(oid: &str, value: BindValue) -> Result<VarBind, SnmpMessageError> {
    Ok(VarBind::new(ObjectIdentifier::from_str(oid)?, value))
}

impl SnmpMessageBuilder for SnmpV2MessageBuilder {
    fn get(&self, oid: &str) -> Result<Vec<u8>, SnmpMessageError> {
        self.request(PduType::GetRequest, oid, BindValue::Unspecified)
    }

    fn get_next(&self, oid: &str) -> Result<Vec<u8>, SnmpMessageError> {
        self.request(PduType::GetNextRequest, oid, BindValue::Unspecified)
    }

    fn get_bulk(
        &self,
        oid: &str,
        non_repeaters: u32,
        max_repetitions: u32,
    ) -> Result<Vec<u8>, SnmpMessageError> {
        let pdu = BulkPdu::new(
            non_repeaters,
            max_repetitions,
            vec![var_bind(oid, BindValue::Unspecified)?],
        );
        V2cMessage::new(self.community.clone(), pdu.into()).encode()
    }

    fn set(&self, oid: &str, value: ObjectValue) -> Result<Vec<u8>, SnmpMessageError> {
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

        let tag = |msg: Vec<u8>| msg[PDU_TAG_OFFSET];
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

        let msg = builder.set("1.3.6", ObjectValue::Integer(42)).unwrap();

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
            let msg = msg.unwrap();
            let var_binds = [0x30, 0x08, 0x30, 0x06, 0x06, 0x02, 0x2b, 0x06, 0x05, 0x00];
            assert!(msg.ends_with(&var_binds), "{:02x?}", msg);
        }
    }

    #[test]
    fn test_get_bulk_encodes_repeater_fields() {
        let builder = SnmpV2MessageBuilder::new("public".to_string());

        let msg = builder.get_bulk("1.3.6", 1, 10).unwrap();

        // non-repeaters, max-repetitions, then the VarBindList.
        let tail = [
            0x02, 0x01, 0x01, 0x02, 0x01, 0x0a, 0x30, 0x08, 0x30, 0x06, 0x06, 0x02, 0x2b, 0x06,
            0x05, 0x00,
        ];
        assert!(msg.ends_with(&tail), "{:02x?}", msg);
    }

    #[test]
    fn test_invalid_oid_is_an_error() {
        let builder = SnmpV2MessageBuilder::new("public".to_string());
        assert!(matches!(
            builder.get("not.an.oid"),
            Err(SnmpMessageError::InvalidOid(_))
        ));
    }
}
