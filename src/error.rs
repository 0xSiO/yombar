use std::io;

use scrypt::password_hash;

#[derive(Debug, thiserror::Error)]
pub enum KeyFromFileError {
    #[error("failed to read key file")]
    ReadKeyFile(#[from] io::Error),
    #[error("failed to parse key file")]
    KeyParse(#[from] serde_json::Error),
    #[error("failed to parse scrypt salt")]
    PasswordHash(#[from] password_hash::Error),
    #[error("failed to extract scrypt parameters")]
    InvalidScryptParams(#[from] scrypt::errors::InvalidParams),
    #[error("failed to decode base64 string")]
    Base64Decode(#[from] base64ct::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("failed to derive key-encryption key")]
pub struct KekDerivationError(#[from] password_hash::Error);

#[derive(Debug, thiserror::Error)]
pub enum VaultUnlockError {
    #[error("failed to read vault config file")]
    ReadConfigFile(#[from] io::Error),
    #[error("failed to decode/verify JWT")]
    JwtError(#[from] jsonwebtoken::errors::Error),
    #[error("JWT header is missing `kid` claim")]
    JwtMissingKeyId,
    #[error(transparent)]
    KeyFromFileError(#[from] KeyFromFileError),
    #[error(transparent)]
    KekDerivation(#[from] KekDerivationError),
    #[error("failed to unwrap master key")]
    KeyUnwrap(#[from] aes_kw::Error),
    #[error("unsupported key URI format: {0}")]
    UnsupportedKeyUri(String),
}
