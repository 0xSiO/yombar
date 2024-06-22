#[derive(Debug, thiserror::Error)]
pub enum CryptorError {
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
    #[error("failed to encrypt/decrypt using AEAD cipher")]
    AeadError(#[from] aes_siv::Error), // This also covers AES-GCM errors
    #[error("failed to decode base64 string")]
    Base64DecodeError(#[from] base64ct::Error),
    #[error("failed to convert to UTF-8 string")]
    InvalidUTF8(#[from] std::string::FromUtf8Error),
}
