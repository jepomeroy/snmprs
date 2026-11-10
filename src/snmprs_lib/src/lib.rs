//! SNMP v2c/v3 message encoding and a basic UDP client.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

/// SNMPv3 authentication and privacy protocols.
pub mod auth;
/// A blocking UDP transport to a single agent.
pub mod base_client;
/// Error types for every part of the crate.
pub mod errors;
/// SNMP message types and their BER encoding.
pub mod message;
/// Builders that turn an OID and a value into a ready-to-send message.
pub mod snmp_msg_builder;
