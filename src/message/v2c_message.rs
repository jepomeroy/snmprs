// RFC 1901 — SNMPv2c community-based message wrapper.
//
// Message ::= SEQUENCE {
//   version   INTEGER { version-2c(1) },
//   community OCTET STRING,
//   data      PDUs
// }
use simple_asn1::{ASN1Block, ASN1Class, ASN1DecodeErr, ASN1EncodeErr, BigInt, FromASN1, ToASN1};

use super::scoped_pdu::{PDU, SNMPMessageError};

pub(crate) struct Message {
    community: Vec<u8>,
    data: PDU,
}

impl Message {
    pub(crate) fn new(community: Vec<u8>, data: PDU) -> Self {
        Self { community, data }
    }
}

impl FromASN1 for Message {
    type Error = SNMPMessageError;

    fn from_asn1(_v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
        todo!()
    }
}

impl ToASN1 for Message {
    type Error = SNMPMessageError;

    fn to_asn1_class(&self, _c: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let version = ASN1Block::Integer(0, BigInt::from(1i32)); // 1 = version-2c
        let community = ASN1Block::OctetString(self.community.len(), self.community.clone());

        let mut inner = vec![version, community];
        inner.append(&mut self.data.to_asn1()?);

        Ok(vec![ASN1Block::Sequence(0, inner)])
    }
}
