/// An SNMPv3 privacy (encryption) protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionProtocol {
    /// AES-256-CFB (non-standard key extension).
    Aes256,
    /// AES-192-CFB (non-standard key extension).
    Aes192,
    /// AES-128-CFB (RFC 3826).
    Aes128,
    /// DES-CBC (RFC 3414). Legacy and insecure.
    Des,
}

/// An SNMPv3 authentication protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    /// HMAC-SHA-512 (RFC 7860).
    Sha512,
    /// HMAC-SHA-384 (RFC 7860).
    Sha384,
    /// HMAC-SHA-256 (RFC 7860).
    Sha256,
    /// HMAC-SHA-224 (RFC 7860).
    Sha224,
    /// HMAC-SHA-96 (RFC 3414).
    Sha1,
    /// HMAC-MD5-96 (RFC 3414). Legacy and insecure.
    Md5,
}
