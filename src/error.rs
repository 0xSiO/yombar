use std::io;

use scrypt::password_hash::{self, rand_core};

#[derive(Debug, thiserror::Error)]
#[error("failed to derive key-encryption key")]
pub struct KekDerivationError(#[from] password_hash::Error);

#[derive(Debug, thiserror::Error)]
pub enum KeyDerivationError {
    #[error(transparent)]
    KekDerivation(#[from] KekDerivationError),
    #[error("failed to generate random bytes")]
    RandomByteGen(#[from] rand_core::Error),
    #[error("failed to wrap key")]
    AesKeyWrap(#[from] aes_kw::Error),
    #[error("failed to create HMAC")]
    Hmac(#[from] hmac::digest::InvalidLength),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyFromFileError {
    #[error("failed to read key file")]
    ReadKeyFile(#[from] io::Error),
    #[error("failed to parse key file")]
    KeyParse(#[from] serde_json::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyDecryptionError {
    #[error("failed to decode key")]
    KeyDecode(#[from] base64ct::Error),
    #[error("failed to unwrap key")]
    AesKeyUnwrap(#[from] aes_kw::Error),
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
    // TODO: Get rid of this variant
    #[error("failed to hash password")]
    PasswordHash(#[from] password_hash::Error),
    #[error(transparent)]
    KekDerivation(#[from] KekDerivationError),
    #[error("failed to decrypt master key")]
    KeyDecryption(#[from] KeyDecryptionError),
}
