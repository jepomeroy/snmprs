use std::{
    io,
    net::{AddrParseError, SocketAddr},
    time::Duration,
};

use thiserror::Error;

/// An OID that can't be parsed or breaks the rules in RFC 2578.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ObjectIdentifierError {
    /// The text isn't a dot-separated list of numbers that each fit in a `u32`.
    #[error(
        "`{input}` is not a valid OID: expected numbers from 0 to 4294967295 separated by dots"
    )]
    Parse {
        /// The text that was given.
        input: String,
    },

    /// The first two arcs aren't a valid combination.
    #[error("OID cannot start with {first}.{second}")]
    InvalidPrefix {
        /// The first arc.
        first: u32,
        /// The second arc.
        second: u32,
    },

    /// The OID has fewer arcs than the minimum.
    #[error("OID length {len} is below the minimum of {min} arcs")]
    TooShort {
        /// The number of arcs given.
        len: usize,
        /// The minimum number of arcs.
        min: usize,
    },

    /// The OID has more arcs than the maximum.
    #[error("OID length {len} is above the maximum of {max} arcs")]
    TooLong {
        /// The number of arcs given.
        len: usize,
        /// The maximum number of arcs.
        max: usize,
    },
}

/// BER input that is malformed or breaks the limits snmprs enforces on untrusted data.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input ended before a complete header or value could be read.
    #[error("input ended early: needed {needed} bytes, but only {available} were left")]
    Truncated {
        /// The number of bytes the header or value needed.
        needed: usize,
        /// The number of bytes that were left.
        available: usize,
    },

    /// The length byte was `0x80`, which BER allows but SNMP doesn't.
    #[error("indefinite lengths are not allowed")]
    IndefiniteLength,

    /// The long-form length field uses more bytes than snmprs accepts.
    #[error("length field is {octets} bytes long, more than the maximum of {max}")]
    LengthTooLong {
        /// The number of bytes in the length field.
        octets: usize,
        /// The maximum number of bytes accepted.
        max: usize,
    },

    /// A value had a different tag from the one the message structure requires.
    #[error("expected tag {expected:#04x}, found {found:#04x}")]
    UnexpectedTag {
        /// The tag the structure requires.
        expected: u8,
        /// The tag that was read.
        found: u8,
    },

    /// A value had a tag snmprs doesn't recognize.
    #[error("unknown tag {tag:#04x}")]
    UnknownTag {
        /// The tag that was read.
        tag: u8,
    },

    /// An integer had more content bytes than its type can hold.
    #[error("integer with tag {tag:#04x} has {len} bytes, too many for its type")]
    IntegerOverflow {
        /// The integer's tag.
        tag: u8,
        /// The number of content bytes.
        len: usize,
    },

    /// Bytes were left over after a value that should have used all of its input.
    #[error("{len} unexpected bytes after the end of the value")]
    TrailingBytes {
        /// The number of leftover bytes.
        len: usize,
    },
}

/// A failure while building, encoding or decoding an SNMP message.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SnmpMessageError {
    /// An OID given to the message builder was invalid.
    #[error(transparent)]
    InvalidOid(#[from] ObjectIdentifierError),

    /// A received message couldn't be decoded.
    #[error("failed to decode SNMP message")]
    Decode(#[from] DecodeError),

    /// A GetBulkRequest field was above the RFC 3416 maximum of 2147483647.
    #[error("{field} is {value}, above the maximum of {}", i32::MAX)]
    BulkFieldOutOfRange {
        /// The field's RFC 3416 name: `non-repeaters` or `max-repetitions`.
        field: &'static str,
        /// The value that was given.
        value: u32,
    },
}

/// A failure in the UDP transport.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The agent address couldn't be parsed.
    #[error("`{input}` is not a valid IP address")]
    InvalidAddress {
        /// The text that was given.
        input: String,
        /// The parse failure.
        source: AddrParseError,
    },

    /// The local UDP socket couldn't be bound.
    #[error("failed to bind a UDP socket to {local}")]
    Bind {
        /// The local address the socket tried to bind to.
        local: SocketAddr,
        /// The OS error.
        source: io::Error,
    },

    /// A socket option, such as a timeout, couldn't be set.
    #[error("failed to configure the UDP socket")]
    Configure {
        /// The OS error.
        source: io::Error,
    },

    /// The socket couldn't be connected to the agent.
    #[error("failed to connect the UDP socket to {remote}")]
    Connect {
        /// The agent's address.
        remote: SocketAddr,
        /// The OS error.
        source: io::Error,
    },

    /// The host resolved successfully but yielded no addresses.
    #[error("no addresses found for host {input}")]
    NoResolvedAddresses {
        /// The host that was given.
        input: String,
    },

    /// The OS sent only part of the message.
    #[error("sent only {sent} of {len} bytes to {remote}")]
    PartialSend {
        /// The agent's address.
        remote: SocketAddr,
        /// The number of bytes sent.
        sent: usize,
        /// The message length.
        len: usize,
    },

    /// Receiving a message failed for a reason other than a timeout.
    #[error("failed to receive from {remote}")]
    Receive {
        /// The agent's address.
        remote: SocketAddr,
        /// The OS error.
        source: io::Error,
    },

    /// Resolving the host (IP literal or hostname) failed.
    #[error("failed to resolve host {input}")]
    Resolve {
        /// The host that was given.
        input: String,
        /// The OS error.
        source: io::Error,
    },

    /// Sending a message failed.
    #[error("failed to send to {remote}")]
    Send {
        /// The agent's address.
        remote: SocketAddr,
        /// The OS error.
        source: io::Error,
    },

    /// No reply arrived before the read timeout.
    #[error("no response from {remote} within {timeout:?}")]
    Timeout {
        /// The agent's address.
        remote: SocketAddr,
        /// The read timeout that expired.
        timeout: Duration,
    },
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

#[cfg(test)]
mod tests {
    use std::error::Error as _;

    use super::*;

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

    #[test]
    fn test_bulk_field_error_message() {
        let err = SnmpMessageError::BulkFieldOutOfRange {
            field: "max-repetitions",
            value: u32::MAX,
        };
        assert_eq!(
            err.to_string(),
            "max-repetitions is 4294967295, above the maximum of 2147483647"
        );
    }

    #[test]
    fn test_decode_error_messages_show_tags_in_hex() {
        let err = DecodeError::UnexpectedTag {
            expected: 0x30,
            found: 0xa2,
        };
        assert_eq!(err.to_string(), "expected tag 0x30, found 0xa2");
    }

    #[test]
    fn test_invalid_oid_message_is_passed_through() {
        let err = SnmpMessageError::from(ObjectIdentifierError::TooShort { len: 1, min: 2 });
        assert_eq!(
            err.to_string(),
            "OID length 1 is below the minimum of 2 arcs"
        );
    }

    #[test]
    fn test_decode_error_is_kept_as_the_source() {
        let err = SnmpMessageError::from(DecodeError::IndefiniteLength);
        assert_eq!(err.to_string(), "failed to decode SNMP message");
        assert_eq!(
            err.source().unwrap().to_string(),
            "indefinite lengths are not allowed"
        );
    }
}
