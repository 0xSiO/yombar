use std::{ffi::OsStr, path::PathBuf};

use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{error::CryptorError, key::SUBKEY_LEN};

pub mod siv_ctrmac;
pub mod siv_gcm;

const HEADER_RESERVED_LEN: usize = 8;

// TODO: If future cryptors require different header fields, you'll need to generalize
#[derive(Debug, PartialEq, Eq, Clone, Zeroize, ZeroizeOnDrop)]
pub struct FileHeader {
    nonce: Vec<u8>,
    payload: Vec<u8>,
}

impl FileHeader {
    pub fn new(nonce_len: usize, payload_len: usize) -> Result<Self, rand_core::Error> {
        let mut nonce = vec![0_u8; nonce_len];
        OsRng.try_fill_bytes(&mut nonce)?;

        let mut payload = vec![0_u8; payload_len];
        OsRng.try_fill_bytes(&mut payload)?;

        // Overwrite first portion with reserved bytes
        payload[..HEADER_RESERVED_LEN].copy_from_slice(&[0xff; HEADER_RESERVED_LEN]);

        Ok(Self { nonce, payload })
    }

    fn content_key(&self) -> [u8; SUBKEY_LEN] {
        // TODO: This will fail if payload len is too small
        debug_assert_eq!(self.payload.len() - HEADER_RESERVED_LEN, SUBKEY_LEN);
        self.payload[HEADER_RESERVED_LEN..].try_into().unwrap()
    }
}

pub trait FileCryptor {
    fn encrypted_header_len() -> usize;

    fn max_chunk_len() -> usize;

    fn max_encrypted_chunk_len() -> usize;

    fn encrypt_header(&self, header: &FileHeader) -> Result<Vec<u8>, CryptorError>;

    fn decrypt_header(
        &self,
        encrypted_header: impl AsRef<[u8]>,
    ) -> Result<FileHeader, CryptorError>;

    fn encrypt_chunk(
        &self,
        chunk: impl AsRef<[u8]>,
        header: &FileHeader,
        chunk_number: usize,
    ) -> Result<Vec<u8>, CryptorError>;

    fn decrypt_chunk(
        &self,
        encrypted_chunk: impl AsRef<[u8]>,
        header: &FileHeader,
        chunk_number: usize,
    ) -> Result<Vec<u8>, CryptorError>;

    fn hash_dir_id(&self, dir_id: impl AsRef<str>) -> Result<PathBuf, CryptorError>;

    fn encrypt_name(
        &self,
        name: impl AsRef<OsStr>,
        parent_dir_id: impl AsRef<str>,
    ) -> Result<String, CryptorError>;

    fn decrypt_name(
        &self,
        encrypted_name: impl AsRef<str>,
        parent_dir_id: impl AsRef<str>,
    ) -> Result<String, CryptorError>;
}
