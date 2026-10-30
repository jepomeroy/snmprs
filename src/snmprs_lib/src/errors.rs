use std::{error::Error, fmt::Display};

use asn1_rs::SerializeError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectIdentifierError {
    ParseError(String),
    InvalidPrefix(u32, u32),
    TooShort(usize, usize),
    TooLong(usize, usize),
}

impl Display for ObjectIdentifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectIdentifierError::ParseError(e) => {
                write!(f, "Parse error: {} is not the right format", e)
            }
            ObjectIdentifierError::InvalidPrefix(first, second) => {
                write!(f, "OID cannot start with {}.{}", first, second)
            }
            ObjectIdentifierError::TooShort(size, min) => {
                write!(f, "OID of length {} is too short: minimum is {}", size, min)
            }
            ObjectIdentifierError::TooLong(size, max) => {
                write!(f, "OID of length {} exceeds the maximum: {}", size, max)
            }
        }
    }
}

impl Error for ObjectIdentifierError {}

#[derive(Debug)]
pub enum SnmpMessageError {
    InvalidOid(ObjectIdentifierError),
    EncodeError(String),
}

impl Display for SnmpMessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnmpMessageError::InvalidOid(e) => write!(f, "Invalid OID: {}", e),
            SnmpMessageError::EncodeError(e) => write!(f, "Encode error: {}", e),
        }
    }
}

impl Error for SnmpMessageError {}

impl From<ObjectIdentifierError> for SnmpMessageError {
    fn from(value: ObjectIdentifierError) -> Self {
        SnmpMessageError::InvalidOid(value)
    }
}

impl From<SerializeError> for SnmpMessageError {
    fn from(value: SerializeError) -> Self {
        SnmpMessageError::EncodeError(value.to_string())
    }
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
        }
    }

    /// Converts an integer to an `ErrorStatus`.
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
            _ => ErrorStatus::GenErr, // Default to GenErr for unknown values
        }
    }
}

#[cfg(test)]
mod tests {
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
    fn test_error_status_from_unknown_int_is_gen_err() {
        for code in [-1, 19, i32::MAX, i32::MIN] {
            assert_eq!(ErrorStatus::from_int(code), ErrorStatus::GenErr);
        }
    }
}
