#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionProtocol {
    Aes256,
    Aes192,
    Aes128,
    Des,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthProtocol {
    Sha512,
    Sha384,
    Sha256,
    Sha224,
    Sha1,
    Md5,
}
