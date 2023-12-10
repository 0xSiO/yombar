use std::io;

use scrypt::password_hash;

use crate::CipherCombo;

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
pub enum SivCtrMacCryptorError {
    #[error("invalid header length: {0}")]
    InvalidHeaderLen(usize),
    #[error("invalid chunk length: {0}")]
    InvalidChunkLen(usize),
    #[error("failed to verify MAC")]
    MacVerificationFailed { expected: Vec<u8>, actual: Vec<u8> },
    #[error("failed to generate random bytes")]
    RandError(#[from] rand_core::Error),
    #[error("failed to encrypt/decrypt using AES-CTR")]
    AesCtrError(#[from] aes::cipher::StreamCipherError),
    #[error("failed to encrypt/decrypt using AES-SIV")]
    AesSivError(#[from] aes_siv::Error),
    #[error("failed to decode base64 string")]
    Base64DecodeError(#[from] base64ct::Error),
    #[error("failed to convert to UTF-8 string")]
    InvalidUTF8(#[from] std::string::FromUtf8Error),
}

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
    #[error("unsupported vault format: {0}")]
    UnsupportedVaultFormat(u32),
    #[error("unsupported cipher combo: {0:?}")]
    UnsupportedCipherCombo(CipherCombo),
}
