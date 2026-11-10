// RFC 1901 — SNMPv2c community-based message wrapper.
//
// Message ::= SEQUENCE {
//   version   INTEGER { version-2c(1) },
//   community OCTET STRING,
//   data      PDUs
// }
use super::ber;
use super::pdu::PduData;
use crate::errors::SnmpMessageError;
use crate::message::ber::Tag::{OctetString, Sequence};

const SNMP_V2C_VERSION: i32 = 1;

/// A community-based SNMPv2c message, ready to encode and send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2cMessage {
    community: Vec<u8>,
    data: PduData,
}

impl V2cMessage {
    /// Wraps `data` with the given community string.
    pub fn new(community: Vec<u8>, data: PduData) -> Self {
        Self { community, data }
    }

    /// Encodes the message as BER bytes for sending on the wire.
    pub fn encode(&self) -> Result<Vec<u8>, SnmpMessageError> {
        let mut content = ber::integer(SNMP_V2C_VERSION);
        content.extend(ber::write(OctetString, &self.community));
        content.extend(self.data.encode()?);
        Ok(ber::write(Sequence, &content))
    }

    /// The request ID of the wrapped PDU, for matching the reply.
    pub fn request_id(&self) -> i32 {
        self.data.request_id()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::message::obj_ident::ObjectIdentifier;
    use crate::message::pdu::{Pdu, PduType};
    use crate::message::var_bind::{BindValue, VarBind};

    // A community long enough to push the community, and the message around it, into
    // the long length form.
    #[test]
    fn test_encode_long_message_uses_long_form_lengths() {
        let pdu = Pdu::new(PduType::GetRequest, vec![]).with_request_id(1);
        let msg = V2cMessage::new(vec![b'a'; 200], pdu.into());

        let encoded = msg.encode().unwrap();

        // 3 (version) + 3 + 200 (community) + 13 (PDU) = 219 bytes of content.
        assert_eq!(&encoded[..3], [0x30, 0x81, 219]);
        assert_eq!(encoded.len(), 3 + 219);
        assert_eq!(&encoded[6..9], [0x04, 0x81, 200]);
    }

    #[test]
    fn test_encode_empty_community() {
        let pdu = Pdu::new(PduType::GetRequest, vec![]).with_request_id(1);
        let encoded = V2cMessage::new(vec![], pdu.into()).encode().unwrap();

        assert_eq!(&encoded[..7], [0x30, 0x12, 0x02, 0x01, 0x01, 0x04, 0x00]);
    }

    #[test]
    fn test_encode_get_sys_descr() {
        let name = ObjectIdentifier::from_str("1.3.6.1.2.1.1.1.0").unwrap();
        let var_bind = VarBind::new(name, BindValue::Unspecified);
        let pdu = Pdu::new(PduType::GetRequest, vec![var_bind]).with_request_id(1);

        let msg = V2cMessage::new(b"public".to_vec(), pdu.into());

        assert_eq!(
            msg.encode().unwrap(),
            [
                0x30, 0x26, // Message
                0x02, 0x01, 0x01, // version-2c
                0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // "public"
                0xa0, 0x19, // GetRequest
                0x02, 0x01, 0x01, // request-id
                0x02, 0x01, 0x00, // error-status
                0x02, 0x01, 0x00, // error-index
                0x30, 0x0e, // VarBindList
                0x30, 0x0c, // VarBind
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // name
                0x05, 0x00, // unSpecified
            ]
        );
    }
}
