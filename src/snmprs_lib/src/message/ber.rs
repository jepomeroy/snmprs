//! The subset of BER (X.690) that SNMP uses: single-byte tags, definite lengths,
//! and the INTEGER, OCTET STRING, NULL, OBJECT IDENTIFIER and SEQUENCE types plus
//! SNMP's application and context-specific tags.

use crate::errors::DecodeError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

pub(super) enum Class {
    Universal = 0b00,
    Application = 0b01,
    ContextSpecific = 0b10,
    Private = 0b11,
}

/// Every tag SNMP v2c and v3 use. Each value is the full tag byte as it appears on
/// the wire: class in bits 8–7, the constructed flag in bit 6, and the tag number
/// in bits 5–1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(super) enum Tag {
    // Universal
    Integer = 0x02,
    OctetString = 0x04,
    Null = 0x05,
    Oid = 0x06,
    Sequence = 0x30,
    // Application
    IpAddress = 0x40,
    Counter32 = 0x41,
    GaugeOrUnsigned32 = 0x42, // Either a Gauge32 or Unsigned32
    TimeTicks = 0x43,
    Opaque = 0x44,
    Counter64 = 0x46,
    // Context Specific
    NoSuchObject = 0x80,
    NoSuchInstance = 0x81,
    EndOfMibView = 0x82,
    GetRequest = 0xA0,
    GetNextRequest = 0xA1,
    Response = 0xA2,
    SetRequest = 0xA3,
    GetBulkRequest = 0xA5,
    InformRequest = 0xA6,
    SnmpV2Trap = 0xA7,
    Report = 0xA8,
}

impl Tag {
    fn class(&self) -> Class {
        match *self as u8 >> 6 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            _ => Class::Universal,
        }
    }

    fn is_constructed(&self) -> bool {
        *self as u8 & 0x20 != 0
    }
}

impl From<Tag> for u8 {
    fn from(value: Tag) -> Self {
        value as u8
    }
}

/// One decoded tag-length-value. All slices borrow from the input, so reading
/// doesn't allocate.
pub(super) struct Tlv<'a> {
    /// The raw tag byte. It's a `u8` rather than a `Tag` so that tags snmprs doesn't
    /// know can still be read and reported.
    pub tag: u8,
    /// The content bytes, without the header.
    pub value: &'a [u8],
    /// The whole TLV as received, header included. SNMPv3 needs the exact bytes to
    /// verify the message's HMAC.
    pub raw: &'a [u8],
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encodes `content` with the given tag and a definite length.
pub(super) fn write(tag: Tag, content: &[u8]) -> Vec<u8> {
    // Room for the tag, the longest length header and the content, so the vector
    // never has to grow.
    let mut out: Vec<u8> = Vec::with_capacity(content.len() + 6);

    out.push(tag.into());

    push_length(&mut out, content.len());
    out.extend_from_slice(content);

    out
}

/// Appends a BER definite length: one byte for 0–127, otherwise 0x80 | n
/// followed by the length in n big-endian bytes.
fn push_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }

    let bytes = len.to_be_bytes();
    // len >= 128, so at least one byte is non-zero.
    let first = bytes.iter().position(|&i| i != 0).unwrap();
    let significant = &bytes[first..];

    out.push(0x80 | significant.len() as u8);
    out.extend_from_slice(significant);
}

/// Encodes a signed INTEGER as the shortest two's-complement big-endian bytes.
pub(super) fn integer(value: i32) -> Vec<u8> {
    let bytes = value.to_be_bytes();

    // A leading byte is redundant when it only repeats the sign of the byte after it:
    // 0x00 before a byte whose top bit is 0, or 0xFF before a byte whose top bit is 1.
    // Always keep at least one byte.
    let mut start = 0;
    while start < bytes.len() - 1 {
        let next_is_negative = bytes[start + 1] & 0x80 != 0;
        let redundant =
            (bytes[start] == 0 && !next_is_negative) || (bytes[start] == 0xff && next_is_negative);
        if !redundant {
            break;
        }
        start += 1;
    }

    write(Tag::Integer, &bytes[start..])
}

/// Encodes an implicitly tagged unsigned INTEGER, such as Counter32 or TimeTicks:
/// minimal big-endian bytes, with a leading zero when the top bit is set so the
/// value isn't read as negative.
pub(super) fn unsigned(tag: Tag, value: u64) -> Vec<u8> {
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

    write(tag, &content)
}

/// Encodes an OBJECT IDENTIFIER. The caller must pass at least two arcs, which
/// `ObjectIdentifier::new` guarantees.
pub(super) fn oid(arcs: &[u32]) -> Vec<u8> {
    assert!(arcs.len() >= 2, "an OID needs at least two arcs");

    let mut content = Vec::with_capacity(arcs.len() + 4);

    // The first two arcs are merged into one number. It's computed as u64 because
    // 2.4294967295 overflows u32, and it can need more than one byte (2.999 -> 1079).
    push_base128(&mut content, 40 * u64::from(arcs[0]) + u64::from(arcs[1]));

    for &arc in &arcs[2..] {
        push_base128(&mut content, u64::from(arc));
    }

    write(Tag::Oid, &content)
}

/// Appends `n` in base 128, most significant digit first, with the top bit set on
/// every byte except the last.
fn push_base128(out: &mut Vec<u8>, mut n: u64) {
    // A u64 needs at most 10 seven-bit digits.
    let mut digits = [0u8; 10];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = (n & 0x7F) as u8;
        n >>= 7;
        if n == 0 {
            break;
        }
    }

    let last = digits.len() - 1;
    for digit in &mut digits[start..last] {
        *digit |= 0x80;
    }
    out.extend_from_slice(&digits[start..]);
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// The most length bytes accepted in the long form. Four bytes allows lengths up to
/// 4 GiB, far beyond any SNMP message, so a longer length field is malformed or hostile.
const MAX_LENGTH_OCTETS: usize = 4;

/// Reads one TLV from the front of `input` and returns it with the bytes after it.
///
/// Every length is checked against the input before slicing, so malformed or hostile
/// input returns an error and never panics.
pub(super) fn read(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), DecodeError> {
    let (&tag, after_tag) = input.split_first().ok_or(DecodeError::Truncated {
        needed: 1,
        available: 0,
    })?;

    // Low five bits of 11111 mean the tag number continues in the following bytes.
    // SNMP never uses multi-byte tags.
    if tag & 0x1F == 0x1F {
        return Err(DecodeError::UnknownTag { tag });
    }

    let (len, after_len) = read_length(after_tag)?;

    // The declared length comes from the sender, so check it before slicing.
    if after_len.len() < len {
        return Err(DecodeError::Truncated {
            needed: len,
            available: after_len.len(),
        });
    }

    let (value, rest) = after_len.split_at(len);

    // Everything consumed so far, header included. SNMPv3 verifies its HMAC over the
    // exact bytes that arrived, which re-encoding wouldn't reproduce if the sender
    // used a non-minimal length.
    let raw = &input[..input.len() - rest.len()];

    Ok((Tlv { tag, value, raw }, rest))
}

/// Reads a BER definite length from the front of `input` and returns it with the
/// bytes after it.
///
/// Quirk policy: non-minimal encodings, such as `81 05` for a length of 5, are
/// accepted. They're valid BER, and some agents send them. Indefinite lengths and
/// length fields longer than [`MAX_LENGTH_OCTETS`] are rejected.
fn read_length(input: &[u8]) -> Result<(usize, &[u8]), DecodeError> {
    let (&first, rest) = input.split_first().ok_or(DecodeError::Truncated {
        needed: 1,
        available: 0,
    })?;

    // Short form: the byte itself is the length, 0 to 127.
    if first & 0x80 == 0 {
        return Ok((usize::from(first), rest));
    }

    // Long form: the low seven bits say how many length bytes follow.
    let octets = usize::from(first & 0x7F);

    if octets == 0 {
        return Err(DecodeError::IndefiniteLength);
    }

    // Also stops the fold below from overflowing usize, and rejects 0xFF, which
    // BER reserves.
    if octets > MAX_LENGTH_OCTETS {
        return Err(DecodeError::LengthTooLong {
            octets,
            max: MAX_LENGTH_OCTETS,
        });
    }

    if rest.len() < octets {
        return Err(DecodeError::Truncated {
            needed: octets,
            available: rest.len(),
        });
    }

    let (len_bytes, rest) = rest.split_at(octets);

    // Big-endian: shift in one byte at a time.
    let len = len_bytes
        .iter()
        .fold(0, |acc, &b| (acc << 8) | usize::from(b));

    Ok((len, rest))
}

/// Reads one TLV and checks that it has the tag the message structure requires.
pub(super) fn expect(input: &[u8], tag: Tag) -> Result<(Tlv<'_>, &[u8]), DecodeError> {
    let (tlv, remainder) = read(input)?;

    if tlv.tag != u8::from(tag) {
        return Err(DecodeError::UnexpectedTag {
            expected: tag.into(),
            found: tlv.tag,
        });
    }

    Ok((tlv, remainder))
}

#[cfg(test)]
mod test {
    use super::*;

    // Encoding

    #[test]
    fn encodes_oids() {
        let cases: &[(&[u32], &[u8])] = &[
            (
                &[1, 3, 6, 1, 2, 1, 1, 1, 0],
                &[0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00],
            ),
            (&[2, 999, 1], &[0x06, 0x03, 0x88, 0x37, 0x01]),
            (
                &[1, 3, u32::MAX],
                &[0x06, 0x06, 0x2B, 0x8F, 0xFF, 0xFF, 0xFF, 0x7F],
            ),
        ];
        for (arcs, expected) in cases {
            assert_eq!(oid(arcs), *expected, "oid {arcs:?}");
        }
    }

    #[test]
    fn encodes_integers() {
        let cases: &[(i32, &[u8])] = &[
            (0, &[0x02, 0x01, 0x00]),
            (128, &[0x02, 0x02, 0x00, 0x80]),
            (-129, &[0x02, 0x02, 0xFF, 0x7F]),
        ];
        for (value, expected) in cases {
            assert_eq!(integer(*value), *expected, "integer {value}");
        }
    }

    #[test]
    fn encodes_unsigned() {
        assert_eq!(
            unsigned(Tag::Counter32, u64::from(u32::MAX)),
            [0x41, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
        );
    }

    #[test]
    fn writes_length_forms() {
        let cases: &[(usize, &[u8])] = &[
            (0, &[0x04, 0x00]),
            (127, &[0x04, 0x7F]),       // largest short form
            (128, &[0x04, 0x81, 0x80]), // smallest long form
            (200, &[0x04, 0x81, 0xC8]),
            (256, &[0x04, 0x82, 0x01, 0x00]),
        ];
        for (len, header) in cases {
            let content = vec![0xAA; *len];
            let out = write(Tag::OctetString, &content);
            assert_eq!(&out[..header.len()], *header, "length {len}");
            assert_eq!(&out[header.len()..], &content[..]);
        }
    }

    // Decoding

    #[test]
    fn reads_back_encoded_values() {
        let encoded: &[&[u8]] = &[
            &[0x06, 0x03, 0x88, 0x37, 0x01],
            &[0x02, 0x02, 0xFF, 0x7F],
            &[0x41, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF],
        ];
        for bytes in encoded {
            let (tlv, rest) = read(bytes).unwrap();
            assert_eq!(tlv.tag, bytes[0]);
            assert_eq!(tlv.value, &bytes[2..]);
            assert_eq!(tlv.raw, *bytes);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn accepts_non_minimal_lengths() {
        // 81 02 is a long-form length that would fit in the short form.
        let input = [0x04, 0x81, 0x02, 0xAA, 0xBB];

        let (tlv, rest) = read(&input).unwrap();

        assert_eq!(tlv.tag, 0x04);
        assert_eq!(tlv.value, [0xAA, 0xBB]);
        // `raw` keeps the bytes as sent, not a re-encoded `04 02 AA BB`.
        assert_eq!(tlv.raw, input);
        assert!(rest.is_empty());
    }

    #[test]
    fn returns_the_bytes_after_the_value() {
        // INTEGER 5 followed by NULL.
        let input = [0x02, 0x01, 0x05, 0x05, 0x00];

        let (first, rest) = read(&input).unwrap();
        assert_eq!(first.tag, 0x02);
        assert_eq!(first.value, [0x05]);
        assert_eq!(first.raw, [0x02, 0x01, 0x05]);
        assert_eq!(rest, [0x05, 0x00]);

        let (second, rest) = read(rest).unwrap();
        assert_eq!(second.tag, 0x05);
        assert!(second.value.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn rejects_malformed_headers() {
        let cases: &[(&[u8], DecodeError)] = &[
            (
                &[],
                DecodeError::Truncated {
                    needed: 1,
                    available: 0,
                },
            ),
            (
                &[0x04],
                DecodeError::Truncated {
                    needed: 1,
                    available: 0,
                },
            ),
            (&[0x04, 0x80], DecodeError::IndefiniteLength),
            (
                &[0x04, 0x85, 0, 0, 0, 0, 1],
                DecodeError::LengthTooLong { octets: 5, max: 4 },
            ),
            (
                &[0x04, 0x82, 0x01],
                DecodeError::Truncated {
                    needed: 2,
                    available: 1,
                },
            ),
            (
                &[0x04, 0x05, 0x01],
                DecodeError::Truncated {
                    needed: 5,
                    available: 1,
                },
            ),
            (&[0x1F, 0x01, 0x00], DecodeError::UnknownTag { tag: 0x1F }),
        ];
        for (input, expected) in cases {
            assert_eq!(
                read(input).err().as_ref(),
                Some(expected),
                "input {input:02x?}"
            );
        }
    }

    #[test]
    fn expect_reports_the_wrong_tag() {
        let input = [0x02, 0x01, 0x05];

        assert!(expect(&input, Tag::Integer).is_ok());
        assert_eq!(
            expect(&input, Tag::Sequence).err(),
            Some(DecodeError::UnexpectedTag {
                expected: 0x30,
                found: 0x02,
            })
        );
    }
}
