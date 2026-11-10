use super::ber;
use super::var_bind::VarBind;
use crate::{
    errors::{ErrorStatus, SnmpMessageError},
    message::ber::Tag::{self, OctetString, Sequence},
};

fn generate_request_id() -> i32 {
    rand::random::<i32>()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduType {
    GetRequest = 0,
    GetNextRequest = 1,
    Response = 2,
    SetRequest = 3,
    // 4 is obsolete (SNMPv1 Trap; not used in v2c/v3)
    // 5 is GetBulkRequest, which has its own layout: see BulkPdu
    InformRequest = 6,
    Trap = 7,
    Report = 8,
}

impl PduType {
    fn tag(self) -> Tag {
        match self {
            PduType::GetRequest => Tag::GetRequest,
            PduType::GetNextRequest => Tag::GetNextRequest,
            PduType::Response => Tag::Response,
            PduType::SetRequest => Tag::SetRequest,
            PduType::InformRequest => Tag::InformRequest,
            PduType::Trap => Tag::SnmpV2Trap,
            PduType::Report => Tag::Report,
        }
    }
}

// RFC 3416: PDU types are implicitly context-tagged (e.g. [0] IMPLICIT PDU), so the
// context-specific tag replaces the SEQUENCE tag around the four fields.
fn encode_pdu(
    tag: Tag,
    request_id: i32,
    second_field: i32,
    third_field: i32,
    var_bindings: &[VarBind],
) -> Result<Vec<u8>, SnmpMessageError> {
    let mut var_bind_list = Vec::new();
    for var_bind in var_bindings {
        var_bind_list.extend(var_bind.encode()?);
    }

    let mut content = ber::integer(request_id);
    content.extend(ber::integer(second_field));
    content.extend(ber::integer(third_field));
    content.extend(ber::write(Sequence, &var_bind_list));

    Ok(ber::write(tag, &content))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    pdu_type: PduType,
    request_id: i32,
    error_status: ErrorStatus,
    error_index: i32,
    var_bindings: Vec<VarBind>,
}

impl Pdu {
    pub fn new(pdu_type: PduType, v: Vec<VarBind>) -> Self {
        Self {
            pdu_type,
            request_id: generate_request_id(),
            error_status: ErrorStatus::NoError,
            error_index: 0,
            var_bindings: v,
        }
    }

    pub fn request_id(&self) -> i32 {
        self.request_id
    }

    pub fn with_request_id(mut self, request_id: i32) -> Self {
        self.request_id = request_id;
        self
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, SnmpMessageError> {
        encode_pdu(
            self.pdu_type.tag(),
            self.request_id,
            self.error_status.to_int(),
            self.error_index,
            &self.var_bindings,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkPdu {
    request_id: i32,
    non_repeaters: i32,
    max_repetitions: i32,
    var_bindings: Vec<VarBind>,
}

impl BulkPdu {
    pub fn new(non_repeaters: u32, max_repetitions: u32, v: Vec<VarBind>) -> Self {
        // RFC 3416 limits both fields to 0..2147483647.
        let clamp = |value: u32| i32::try_from(value).unwrap_or(i32::MAX);
        Self {
            request_id: generate_request_id(),
            non_repeaters: clamp(non_repeaters),
            max_repetitions: clamp(max_repetitions),
            var_bindings: v,
        }
    }

    pub fn request_id(&self) -> i32 {
        self.request_id
    }

    pub fn with_request_id(mut self, request_id: i32) -> Self {
        self.request_id = request_id;
        self
    }

    pub(super) fn encode(&self) -> Result<Vec<u8>, SnmpMessageError> {
        encode_pdu(
            Tag::GetBulkRequest,
            self.request_id,
            self.non_repeaters,
            self.max_repetitions,
            &self.var_bindings,
        )
    }
}

/// Any PDU that can be carried by a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PduData {
    Standard(Pdu),
    Bulk(BulkPdu),
}

impl PduData {
    pub fn encode(&self) -> Result<Vec<u8>, SnmpMessageError> {
        match self {
            PduData::Standard(pdu) => pdu.encode(),
            PduData::Bulk(pdu) => pdu.encode(),
        }
    }

    pub fn request_id(&self) -> i32 {
        match self {
            PduData::Standard(pdu) => pdu.request_id(),
            PduData::Bulk(pdu) => pdu.request_id(),
        }
    }
}

impl From<Pdu> for PduData {
    fn from(value: Pdu) -> Self {
        PduData::Standard(value)
    }
}

impl From<BulkPdu> for PduData {
    fn from(value: BulkPdu) -> Self {
        PduData::Bulk(value)
    }
}

// RFC 3412 — SNMPv3 scoped PDU: ties a PDU to a specific SNMP engine and context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedPdu {
    context_engine_id: Vec<u8>,
    context_name: Vec<u8>, // max 32 bytes per RFC 3412
    data: PduData,
}

impl ScopedPdu {
    pub fn new(context_engine_id: Vec<u8>, context_name: Vec<u8>, data: PduData) -> Self {
        Self {
            context_engine_id,
            context_name,
            data,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, SnmpMessageError> {
        let mut content = ber::write(OctetString, &self.context_engine_id);
        content.extend(ber::write(OctetString, &self.context_name));
        content.extend(self.data.encode()?);
        Ok(ber::write(Sequence, &content))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::message::obj_ident::ObjectIdentifier;
    use crate::message::var_bind::BindValue;

    fn var_bind() -> VarBind {
        let name = ObjectIdentifier::from_str("1.3.6").unwrap();
        VarBind::new(name, BindValue::Unspecified)
    }

    // SEQUENCE { SEQUENCE { OID 1.3.6, NULL } }
    const VAR_BIND_LIST: [u8; 10] = [0x30, 0x08, 0x30, 0x06, 0x06, 0x02, 0x2b, 0x06, 0x05, 0x00];

    fn expected(tag: u8, fields: [u8; 3]) -> Vec<u8> {
        let mut bytes = vec![
            tag, 0x13, 0x02, 0x01, fields[0], 0x02, 0x01, fields[1], 0x02, 0x01, fields[2],
        ];
        bytes.extend(VAR_BIND_LIST);
        bytes
    }

    #[test]
    fn test_encode_pdu() {
        let pdu = Pdu::new(PduType::GetNextRequest, vec![var_bind()]).with_request_id(7);
        assert_eq!(pdu.encode().unwrap(), expected(0xa1, [7, 0, 0]));
    }

    #[test]
    fn test_every_pdu_type_uses_its_tag() {
        let types = [
            (PduType::GetRequest, 0xa0),
            (PduType::GetNextRequest, 0xa1),
            (PduType::Response, 0xa2),
            (PduType::SetRequest, 0xa3),
            (PduType::InformRequest, 0xa6),
            (PduType::Trap, 0xa7),
            (PduType::Report, 0xa8),
        ];
        for (pdu_type, tag) in types {
            let pdu = Pdu::new(pdu_type, vec![var_bind()]).with_request_id(7);
            assert_eq!(pdu.encode().unwrap(), expected(tag, [7, 0, 0]));
        }
    }

    #[test]
    fn test_encode_error_status_and_index() {
        let mut pdu = Pdu::new(PduType::Response, vec![var_bind()]).with_request_id(7);
        pdu.error_status = ErrorStatus::NotWritable;
        pdu.error_index = 1;

        assert_eq!(pdu.encode().unwrap(), expected(0xa2, [7, 17, 1]));
    }

    #[test]
    fn test_encode_request_id_widths() {
        let ids: [(i32, &[u8]); 5] = [
            (-1, &[0x02, 0x01, 0xff]),
            (127, &[0x02, 0x01, 0x7f]),
            (128, &[0x02, 0x02, 0x00, 0x80]),
            (i32::MAX, &[0x02, 0x04, 0x7f, 0xff, 0xff, 0xff]),
            (i32::MIN, &[0x02, 0x04, 0x80, 0x00, 0x00, 0x00]),
        ];
        for (id, id_bytes) in ids {
            let pdu = Pdu::new(PduType::GetRequest, vec![]).with_request_id(id);
            let encoded = pdu.encode().unwrap();

            assert_eq!(pdu.request_id(), id);
            assert_eq!(&encoded[2..2 + id_bytes.len()], id_bytes);
        }
    }

    #[test]
    fn test_bulk_request_id_getter() {
        let pdu = BulkPdu::new(0, 0, vec![]).with_request_id(-5);
        assert_eq!(pdu.request_id(), -5);
    }

    #[test]
    fn test_encode_empty_var_bind_list() {
        let pdu = Pdu::new(PduType::GetRequest, vec![]).with_request_id(7);
        assert_eq!(
            pdu.encode().unwrap(),
            [0xa0, 0x0b, 0x02, 0x01, 0x07, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x00]
        );
    }

    #[test]
    fn test_encode_keeps_multiple_var_binds_in_order() {
        let first = VarBind::new(
            ObjectIdentifier::from_str("1.3.6").unwrap(),
            BindValue::Unspecified,
        );
        let second = VarBind::new(
            ObjectIdentifier::from_str("1.3.7").unwrap(),
            BindValue::NoSuchInstance,
        );
        let pdu = Pdu::new(PduType::Response, vec![first, second]).with_request_id(7);

        assert_eq!(
            pdu.encode().unwrap(),
            [
                0xa2, 0x1b, 0x02, 0x01, 0x07, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, // header
                0x30, 0x10, // VarBindList
                0x30, 0x06, 0x06, 0x02, 0x2b, 0x06, 0x05, 0x00, // 1.3.6 = NULL
                0x30, 0x06, 0x06, 0x02, 0x2b, 0x07, 0x81, 0x00, // 1.3.7 = noSuchInstance
            ]
        );
    }

    #[test]
    fn test_encode_bulk_pdu() {
        let pdu = BulkPdu::new(1, 10, vec![var_bind()]).with_request_id(7);
        assert_eq!(pdu.encode().unwrap(), expected(0xa5, [7, 1, 10]));
    }

    #[test]
    fn test_bulk_pdu_clamps_to_max_int() {
        let pdu = BulkPdu::new(0, u32::MAX, vec![]);
        assert_eq!(pdu.max_repetitions, i32::MAX);
    }

    #[test]
    fn test_encode_scoped_pdu() {
        let pdu = Pdu::new(PduType::GetRequest, vec![var_bind()]).with_request_id(7);
        let scoped = ScopedPdu::new(vec![0x80], b"ctx".to_vec(), pdu.into());

        let mut body = vec![0x04, 0x01, 0x80, 0x04, 0x03, 0x63, 0x74, 0x78];
        body.extend(expected(0xa0, [7, 0, 0]));
        let mut bytes = vec![0x30, body.len() as u8];
        bytes.extend(body);

        assert_eq!(scoped.encode().unwrap(), bytes);
    }
}
