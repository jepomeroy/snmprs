use super::ber;
use super::var_bind::VarBind;
use crate::{
    errors::SnmpMessageError,
    message::ber::Tag::{self, OctetString, Sequence},
};

fn generate_request_id() -> i32 {
    rand::random::<i32>()
}

/// Represents the possible error statuses in an SNMP PDU (RFC 3416).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ErrorStatus {
    /// No error occurred.
    NoError,
    /// The response would be too large to fit in a single message.
    TooBig,
    /// Proxy compatibility with SNMPv1: the variable does not exist.
    NoSuchName,
    /// Proxy compatibility with SNMPv1: the value is not valid for the variable.
    BadValue,
    /// Proxy compatibility with SNMPv1: the variable cannot be modified.
    ReadOnly,
    /// A general error not covered by any other status.
    GenErr,
    /// The variable is not accessible.
    NoAccess,
    /// The value has the wrong type for the variable.
    WrongType,
    /// The value has the wrong length for the variable.
    WrongLength,
    /// The value has the wrong encoding for the variable.
    WrongEncoding,
    /// The value is outside the range allowed for the variable.
    WrongValue,
    /// The variable does not exist and cannot be created.
    NoCreation,
    /// The value is inconsistent with other managed objects.
    InconsistentValue,
    /// A resource needed to assign the value is unavailable.
    ResourceUnavailable,
    /// The assignment failed and was rolled back.
    CommitFailed,
    /// The assignment failed and could not be rolled back.
    UndoFailed,
    /// The request was not authorized.
    AuthorizationError,
    /// The variable cannot be modified.
    NotWritable,
    /// The variable does not exist and its name is inconsistent with creating it.
    InconsistentName,
    /// A code that RFC 3416 doesn't define, kept as received.
    Unknown(i32),
}

impl ErrorStatus {
    /// Converts `ErrorStatus` to its integer representation.
    pub fn to_int(&self) -> i32 {
        match self {
            ErrorStatus::NoError => 0,
            ErrorStatus::TooBig => 1,
            ErrorStatus::NoSuchName => 2,
            ErrorStatus::BadValue => 3,
            ErrorStatus::ReadOnly => 4,
            ErrorStatus::GenErr => 5,
            ErrorStatus::NoAccess => 6,
            ErrorStatus::WrongType => 7,
            ErrorStatus::WrongLength => 8,
            ErrorStatus::WrongEncoding => 9,
            ErrorStatus::WrongValue => 10,
            ErrorStatus::NoCreation => 11,
            ErrorStatus::InconsistentValue => 12,
            ErrorStatus::ResourceUnavailable => 13,
            ErrorStatus::CommitFailed => 14,
            ErrorStatus::UndoFailed => 15,
            ErrorStatus::AuthorizationError => 16,
            ErrorStatus::NotWritable => 17,
            ErrorStatus::InconsistentName => 18,
            ErrorStatus::Unknown(code) => *code,
        }
    }

    /// Converts an integer to an `ErrorStatus`. Codes RFC 3416 doesn't define
    /// become [`ErrorStatus::Unknown`] with the original value.
    pub fn from_int(value: i32) -> Self {
        match value {
            0 => ErrorStatus::NoError,
            1 => ErrorStatus::TooBig,
            2 => ErrorStatus::NoSuchName,
            3 => ErrorStatus::BadValue,
            4 => ErrorStatus::ReadOnly,
            5 => ErrorStatus::GenErr,
            6 => ErrorStatus::NoAccess,
            7 => ErrorStatus::WrongType,
            8 => ErrorStatus::WrongLength,
            9 => ErrorStatus::WrongEncoding,
            10 => ErrorStatus::WrongValue,
            11 => ErrorStatus::NoCreation,
            12 => ErrorStatus::InconsistentValue,
            13 => ErrorStatus::ResourceUnavailable,
            14 => ErrorStatus::CommitFailed,
            15 => ErrorStatus::UndoFailed,
            16 => ErrorStatus::AuthorizationError,
            17 => ErrorStatus::NotWritable,
            18 => ErrorStatus::InconsistentName,
            other => ErrorStatus::Unknown(other),
        }
    }
}

/// The kind of a standard PDU (RFC 3416). GetBulkRequest isn't listed because it
/// has its own layout: see [`BulkPdu`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PduType {
    /// Reads the named variables.
    GetRequest = 0,
    /// Reads the variables that follow the named ones in the MIB.
    GetNextRequest = 1,
    /// An agent's reply to a request.
    Response = 2,
    /// Writes the given values.
    SetRequest = 3,
    // 4 is obsolete (SNMPv1 Trap; not used in v2c/v3)
    // 5 is GetBulkRequest, which has its own layout: see BulkPdu
    /// A notification that the receiver acknowledges.
    InformRequest = 6,
    /// An unacknowledged notification (SNMPv2-Trap-PDU).
    Trap = 7,
    /// An internal SNMPv3 report, such as a USM discovery or error reply.
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
) -> Vec<u8> {
    let mut var_bind_list = Vec::new();
    for var_bind in var_bindings {
        var_bind_list.extend(var_bind.encode());
    }

    let mut content = ber::integer(request_id);
    content.extend(ber::integer(second_field));
    content.extend(ber::integer(third_field));
    content.extend(ber::write(Sequence, &var_bind_list));

    ber::write(tag, &content)
}

/// A standard PDU: every type except GetBulkRequest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pdu {
    pdu_type: PduType,
    request_id: i32,
    error_status: ErrorStatus,
    error_index: i32,
    var_bindings: Vec<VarBind>,
}

impl Pdu {
    /// Builds a PDU with a random request ID and no error.
    pub fn new(pdu_type: PduType, v: Vec<VarBind>) -> Self {
        Self {
            pdu_type,
            request_id: generate_request_id(),
            error_status: ErrorStatus::NoError,
            error_index: 0,
            var_bindings: v,
        }
    }

    /// The ID that ties a response to this request.
    pub fn request_id(&self) -> i32 {
        self.request_id
    }

    /// Replaces the random request ID, for example to resend with the same ID.
    pub fn with_request_id(mut self, request_id: i32) -> Self {
        self.request_id = request_id;
        self
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        encode_pdu(
            self.pdu_type.tag(),
            self.request_id,
            self.error_status.to_int(),
            self.error_index,
            &self.var_bindings,
        )
    }
}

/// A GetBulkRequest PDU, which replaces the error fields with repetition counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BulkPdu {
    request_id: i32,
    non_repeaters: i32,
    max_repetitions: i32,
    var_bindings: Vec<VarBind>,
}

impl BulkPdu {
    /// Builds a GetBulkRequest PDU.
    ///
    /// RFC 3416 limits both fields to 0..2147483647; a larger value is an error
    /// rather than being clamped.
    pub fn new(
        non_repeaters: u32,
        max_repetitions: u32,
        v: Vec<VarBind>,
    ) -> Result<Self, SnmpMessageError> {
        let check = |field: &'static str, value: u32| {
            i32::try_from(value).map_err(|_| SnmpMessageError::BulkFieldOutOfRange { field, value })
        };
        Ok(Self {
            request_id: generate_request_id(),
            non_repeaters: check("non-repeaters", non_repeaters)?,
            max_repetitions: check("max-repetitions", max_repetitions)?,
            var_bindings: v,
        })
    }

    /// The ID that ties a response to this request.
    pub fn request_id(&self) -> i32 {
        self.request_id
    }

    /// Replaces the random request ID, for example to resend with the same ID.
    pub fn with_request_id(mut self, request_id: i32) -> Self {
        self.request_id = request_id;
        self
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
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
    /// Any PDU type except GetBulkRequest.
    Standard(Pdu),
    /// A GetBulkRequest.
    Bulk(BulkPdu),
}

impl PduData {
    pub(crate) fn encode(&self) -> Vec<u8> {
        match self {
            PduData::Standard(pdu) => pdu.encode(),
            PduData::Bulk(pdu) => pdu.encode(),
        }
    }

    /// The request ID of the wrapped PDU.
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

/// An SNMPv3 scoped PDU (RFC 3412): ties a PDU to a specific SNMP engine and context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedPdu {
    context_engine_id: Vec<u8>,
    context_name: Vec<u8>, // max 32 bytes per RFC 3412
    data: PduData,
}

impl ScopedPdu {
    /// Wraps `data` for the given context engine ID and context name.
    pub fn new(context_engine_id: Vec<u8>, context_name: Vec<u8>, data: PduData) -> Self {
        Self {
            context_engine_id,
            context_name,
            data,
        }
    }

    // Only the SNMPv3 message wrapper (Phase 3) will call this.
    #[allow(dead_code)]
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut content = ber::write(OctetString, &self.context_engine_id);
        content.extend(ber::write(OctetString, &self.context_name));
        content.extend(self.data.encode());
        ber::write(Sequence, &content)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::message::obj_ident::ObjectIdentifier;
    use crate::message::var_bind::BindValue;

    // RFC 3416 error-status values.
    const ERROR_STATUS_CODES: [(ErrorStatus, i32); 19] = [
        (ErrorStatus::NoError, 0),
        (ErrorStatus::TooBig, 1),
        (ErrorStatus::NoSuchName, 2),
        (ErrorStatus::BadValue, 3),
        (ErrorStatus::ReadOnly, 4),
        (ErrorStatus::GenErr, 5),
        (ErrorStatus::NoAccess, 6),
        (ErrorStatus::WrongType, 7),
        (ErrorStatus::WrongLength, 8),
        (ErrorStatus::WrongEncoding, 9),
        (ErrorStatus::WrongValue, 10),
        (ErrorStatus::NoCreation, 11),
        (ErrorStatus::InconsistentValue, 12),
        (ErrorStatus::ResourceUnavailable, 13),
        (ErrorStatus::CommitFailed, 14),
        (ErrorStatus::UndoFailed, 15),
        (ErrorStatus::AuthorizationError, 16),
        (ErrorStatus::NotWritable, 17),
        (ErrorStatus::InconsistentName, 18),
    ];

    #[test]
    fn test_error_status_to_int() {
        for (status, code) in ERROR_STATUS_CODES {
            assert_eq!(status.to_int(), code, "{:?}", status);
        }
    }

    #[test]
    fn test_error_status_from_int() {
        for (status, code) in ERROR_STATUS_CODES {
            assert_eq!(ErrorStatus::from_int(code), status, "code {}", code);
        }
    }

    #[test]
    fn test_error_status_keeps_unknown_codes() {
        for code in [-1, 19, i32::MAX, i32::MIN] {
            let status = ErrorStatus::from_int(code);
            assert_eq!(status, ErrorStatus::Unknown(code));
            assert_eq!(status.to_int(), code);
        }
    }

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
        assert_eq!(pdu.encode(), expected(0xa1, [7, 0, 0]));
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
            assert_eq!(pdu.encode(), expected(tag, [7, 0, 0]));
        }
    }

    #[test]
    fn test_encode_error_status_and_index() {
        let mut pdu = Pdu::new(PduType::Response, vec![var_bind()]).with_request_id(7);
        pdu.error_status = ErrorStatus::NotWritable;
        pdu.error_index = 1;

        assert_eq!(pdu.encode(), expected(0xa2, [7, 17, 1]));
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
            let encoded = pdu.encode();

            assert_eq!(pdu.request_id(), id);
            assert_eq!(&encoded[2..2 + id_bytes.len()], id_bytes);
        }
    }

    #[test]
    fn test_bulk_request_id_getter() {
        let pdu = BulkPdu::new(0, 0, vec![]).unwrap().with_request_id(-5);
        assert_eq!(pdu.request_id(), -5);
    }

    #[test]
    fn test_encode_empty_var_bind_list() {
        let pdu = Pdu::new(PduType::GetRequest, vec![]).with_request_id(7);
        assert_eq!(
            pdu.encode(),
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
            pdu.encode(),
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
        let pdu = BulkPdu::new(1, 10, vec![var_bind()])
            .unwrap()
            .with_request_id(7);
        assert_eq!(pdu.encode(), expected(0xa5, [7, 1, 10]));
    }

    #[test]
    fn test_bulk_pdu_accepts_max_int() {
        let max = i32::MAX as u32;
        let pdu = BulkPdu::new(max, max, vec![]).unwrap();
        assert_eq!(pdu.non_repeaters, i32::MAX);
        assert_eq!(pdu.max_repetitions, i32::MAX);
    }

    #[test]
    fn test_bulk_pdu_rejects_values_above_max_int() {
        let too_big = i32::MAX as u32 + 1;
        assert_eq!(
            BulkPdu::new(too_big, 0, vec![]),
            Err(SnmpMessageError::BulkFieldOutOfRange {
                field: "non-repeaters",
                value: too_big,
            })
        );
        assert_eq!(
            BulkPdu::new(0, u32::MAX, vec![]),
            Err(SnmpMessageError::BulkFieldOutOfRange {
                field: "max-repetitions",
                value: u32::MAX,
            })
        );
    }

    #[test]
    fn test_encode_scoped_pdu() {
        let pdu = Pdu::new(PduType::GetRequest, vec![var_bind()]).with_request_id(7);
        let scoped = ScopedPdu::new(vec![0x80], b"ctx".to_vec(), pdu.into());

        let mut body = vec![0x04, 0x01, 0x80, 0x04, 0x03, 0x63, 0x74, 0x78];
        body.extend(expected(0xa0, [7, 0, 0]));
        let mut bytes = vec![0x30, body.len() as u8];
        bytes.extend(body);

        assert_eq!(scoped.encode(), bytes);
    }
}
