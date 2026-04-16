use std::fmt::Display;
use simple_asn1::{ASN1Block, ASN1Class, ASN1DecodeErr, ASN1EncodeErr, BigInt, BigUint, FromASN1, ToASN1, to_der};

use crate::message::var_bind::VarBind;

#[derive(Debug)]
pub(crate) enum SNMPMessageError {
    DecodeError(String),
    EncodeError(String),
    ParseError(String),
    TooLong(usize),
}

impl Display for SNMPMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SNMPMessageError::DecodeError(e) => write!(f, "Decode error: {}", e),
            SNMPMessageError::EncodeError(e) => write!(f, "Encode error: {}", e),
            SNMPMessageError::ParseError(e) => write!(f, "Parse error: {}", e),
            SNMPMessageError::TooLong(n) => write!(f, "Message too long: {} bytes", n),
        }
    }
}

impl std::error::Error for SNMPMessageError {}

impl From<ASN1DecodeErr> for SNMPMessageError {
    fn from(value: ASN1DecodeErr) -> Self {
        SNMPMessageError::DecodeError(value.to_string())
    }
}

impl From<ASN1EncodeErr> for SNMPMessageError {
    fn from(value: ASN1EncodeErr) -> Self {
        SNMPMessageError::EncodeError(value.to_string())
    }
}

fn generate_request_id() -> i32 {
    rand::random::<i32>()
}

pub(crate) enum PDUError {
    NoError = 0,
    TooBig = 1,
    NoSuchName = 2, // for proxy compatibility
    BadValue = 3,   // for proxy compatibility
    ReadOnly = 4,   // for proxy compatibility
    GenErr = 5,
    NoAccess = 6,
    WrongType = 7,
    WrongLength = 8,
    WrongEncoding = 9,
    WrongValue = 10,
    NoCreation = 11,
    InconsistentValue = 12,
    ResourceUnavailable = 13,
    CommitFailed = 14,
    UndoFailed = 15,
    AuthorizationError = 16,
    NotWritable = 17,
    InconsistentName = 18,
}


#[derive(Clone, Copy)]
pub(crate) enum PDUType {
    GetRequest = 0,
    GetNextRequest = 1,
    Response = 2,
    SetRequest = 3,
    // 4 is obsolete (SNMPv1 Trap; not used in v2c/v3)
    GetBulkRequest = 5,
    InformRequest = 6,
    Trap = 7,
    Report = 8,
}

pub(crate) struct PDU {
    pdu_type: PDUType,
    request_id: i32,
    error_status: i32,
    error_index: u32,
    var_bindings: Vec<VarBind>,
}

impl PDU {
    pub(crate) fn new(pdu_type: PDUType, v: Vec<VarBind>) -> Self {
        Self {
            pdu_type,
            request_id: generate_request_id(),
            error_status: 0,
            error_index: 0,
            var_bindings: v,
        }
    }
}
impl FromASN1 for PDU {
    type Error = SNMPMessageError;

    fn from_asn1(
        v: &[simple_asn1::ASN1Block],
    ) -> Result<(Self, &[simple_asn1::ASN1Block]), Self::Error> {
        todo!()
    }
}

impl ToASN1 for PDU {
    type Error = SNMPMessageError;

    fn to_asn1_class(&self, _c: simple_asn1::ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let mut var_bind_list: Vec<ASN1Block> = Vec::new();
        for var_bind in &self.var_bindings {
            var_bind_list.append(&mut var_bind.to_asn1()?);
        }

        let inner_blocks = [
            ASN1Block::Integer(0, BigInt::from(self.request_id)),
            ASN1Block::Integer(0, BigInt::from(self.error_status)),
            ASN1Block::Integer(0, BigInt::from(self.error_index)),
            ASN1Block::Sequence(0, var_bind_list),
        ];

        // RFC 3416: PDU types are implicitly context-tagged (e.g. [0] IMPLICIT PDU).
        // Encode each inner element to DER and concatenate as the raw content of the
        // context-specific tag, replacing the outer SEQUENCE tag.
        let mut content_bytes: Vec<u8> = Vec::new();
        for block in &inner_blocks {
            content_bytes.extend(to_der(block)?);
        }

        let tag = BigUint::from(self.pdu_type as u8);
        Ok(vec![ASN1Block::Unknown(
            ASN1Class::ContextSpecific,
            true, // constructed
            0,
            tag,
            content_bytes,
        )])
    }
}

pub(crate) struct BulkPDU {
    request_id: i32,
    non_repeaters: u32,
    max_repetitions: u32,
    var_bindings: Vec<VarBind>,
}

impl BulkPDU {
    pub(crate) fn new(v: Vec<VarBind>) -> Self {
        Self {
            request_id: generate_request_id(),
            non_repeaters: 0,
            max_repetitions: 0,
            var_bindings: v,
        }
    }
}

impl FromASN1 for BulkPDU {
    type Error = SNMPMessageError;

    fn from_asn1(
        v: &[simple_asn1::ASN1Block],
    ) -> Result<(Self, &[simple_asn1::ASN1Block]), Self::Error> {
        todo!()
    }
}

impl ToASN1 for BulkPDU {
    type Error = SNMPMessageError;

    fn to_asn1_class(
        &self,
        _c: simple_asn1::ASN1Class,
    ) -> Result<Vec<simple_asn1::ASN1Block>, Self::Error> {
        todo!()
    }
}

// RFC 3412 — SNMPv3 scoped PDU: ties a PDU to a specific SNMP engine and context.
pub(crate) struct ScopedPDU {
    context_engine_id: Vec<u8>,
    context_name: Vec<u8>, // max 32 bytes per RFC 3412
    data: PDU,
}

impl ScopedPDU {
    pub(crate) fn new(context_engine_id: Vec<u8>, context_name: Vec<u8>, data: PDU) -> Self {
        Self {
            context_engine_id,
            context_name,
            data,
        }
    }
}

impl FromASN1 for ScopedPDU {
    type Error = SNMPMessageError;

    fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
        todo!()
    }
}

impl ToASN1 for ScopedPDU {
    type Error = SNMPMessageError;

    fn to_asn1_class(&self, _c: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let engine_id =
            ASN1Block::OctetString(self.context_engine_id.len(), self.context_engine_id.clone());
        let context_name =
            ASN1Block::OctetString(self.context_name.len(), self.context_name.clone());

        let mut inner = vec![engine_id, context_name];
        inner.append(&mut self.data.to_asn1()?);

        Ok(vec![ASN1Block::Sequence(0, inner)])
    }
}
