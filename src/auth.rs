pub(crate) enum EncryptionProtocol {
    AES256,
    AES192,
    AES, // AES128
    DES,
}

pub(crate) enum AuthProtocol {
    SHA512,
    SHA384,
    SHA256,
    SHA224,
    SHA, // SHA1
    MD5,
}
