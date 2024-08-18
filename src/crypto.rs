use std::{ffi::OsStr, path::PathBuf};

use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{key::SUBKEY_LEN, Result};

pub mod siv_ctrmac;
pub mod siv_gcm;

const HEADER_RESERVED_LEN: usize = 8;

#[derive(Debug, PartialEq, Eq, Clone, Zeroize, ZeroizeOnDrop)]
pub struct FileHeader {
    nonce: Vec<u8>,
    payload: Vec<u8>,
}

impl FileHeader {
    pub fn new(nonce_len: usize, payload_len: usize) -> Result<Self> {
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
    fn encrypted_header_len(&self) -> usize;

    fn max_chunk_len(&self) -> usize;

    fn max_encrypted_chunk_len(&self) -> usize;

    fn new_header(&self) -> Result<FileHeader>;

    fn encrypt_header(&self, header: &FileHeader) -> Result<Vec<u8>>;

    fn decrypt_header(&self, encrypted_header: impl AsRef<[u8]>) -> Result<FileHeader>;

    fn encrypt_chunk(
        &self,
        chunk: impl AsRef<[u8]>,
        header: &FileHeader,
        chunk_number: usize,
    ) -> Result<Vec<u8>>;

    fn decrypt_chunk(
        &self,
        encrypted_chunk: impl AsRef<[u8]>,
        header: &FileHeader,
        chunk_number: usize,
    ) -> Result<Vec<u8>>;

    fn hash_dir_id(&self, dir_id: impl AsRef<str>) -> Result<PathBuf>;

    fn encrypt_name(
        &self,
        name: impl AsRef<OsStr>,
        parent_dir_id: impl AsRef<str>,
    ) -> Result<String>;

    fn decrypt_name(
        &self,
        encrypted_name: impl AsRef<str>,
        parent_dir_id: impl AsRef<str>,
    ) -> Result<String>;
}

#[derive(Debug, Clone, Copy)]
pub enum Cryptor<'k> {
    SivCtrMac(siv_ctrmac::Cryptor<'k>),
    SivGcm(siv_gcm::Cryptor<'k>),
}

impl<'k> FileCryptor for Cryptor<'k> {
    fn encrypted_header_len(&self) -> usize {
        match self {
            Cryptor::SivCtrMac(c) => c.encrypted_header_len(),
            Cryptor::SivGcm(c) => c.encrypted_header_len(),
        }
    }

    fn max_chunk_len(&self) -> usize {
        match self {
            Cryptor::SivCtrMac(c) => c.max_chunk_len(),
            Cryptor::SivGcm(c) => c.max_chunk_len(),
        }
    }

    fn max_encrypted_chunk_len(&self) -> usize {
        match self {
            Cryptor::SivCtrMac(c) => c.max_encrypted_chunk_len(),
            Cryptor::SivGcm(c) => c.max_encrypted_chunk_len(),
        }
    }

    fn new_header(&self) -> Result<FileHeader> {
        match self {
            Cryptor::SivCtrMac(c) => c.new_header(),
            Cryptor::SivGcm(c) => c.new_header(),
        }
    }

    fn encrypt_header(&self, header: &FileHeader) -> Result<Vec<u8>> {
        match self {
            Cryptor::SivCtrMac(c) => c.encrypt_header(header),
            Cryptor::SivGcm(c) => c.encrypt_header(header),
        }
    }

    fn decrypt_header(&self, encrypted_header: impl AsRef<[u8]>) -> Result<FileHeader> {
        match self {
            Cryptor::SivCtrMac(c) => c.decrypt_header(encrypted_header),
            Cryptor::SivGcm(c) => c.decrypt_header(encrypted_header),
        }
    }

    fn encrypt_chunk(
        &self,
        chunk: impl AsRef<[u8]>,
        header: &FileHeader,
        chunk_number: usize,
    ) -> Result<Vec<u8>> {
        match self {
            Cryptor::SivCtrMac(c) => c.encrypt_chunk(chunk, header, chunk_number),
            Cryptor::SivGcm(c) => c.encrypt_chunk(chunk, header, chunk_number),
        }
    }

    fn decrypt_chunk(
        &self,
        encrypted_chunk: impl AsRef<[u8]>,
        header: &FileHeader,
        chunk_number: usize,
    ) -> Result<Vec<u8>> {
        match self {
            Cryptor::SivCtrMac(c) => c.decrypt_chunk(encrypted_chunk, header, chunk_number),
            Cryptor::SivGcm(c) => c.decrypt_chunk(encrypted_chunk, header, chunk_number),
        }
    }

    fn hash_dir_id(&self, dir_id: impl AsRef<str>) -> Result<PathBuf> {
        match self {
            Cryptor::SivCtrMac(c) => c.hash_dir_id(dir_id),
            Cryptor::SivGcm(c) => c.hash_dir_id(dir_id),
        }
    }

    fn encrypt_name(
        &self,
        name: impl AsRef<OsStr>,
        parent_dir_id: impl AsRef<str>,
    ) -> Result<String> {
        match self {
            Cryptor::SivCtrMac(c) => c.encrypt_name(name, parent_dir_id),
            Cryptor::SivGcm(c) => c.encrypt_name(name, parent_dir_id),
        }
    }

    fn decrypt_name(
        &self,
        encrypted_name: impl AsRef<str>,
        parent_dir_id: impl AsRef<str>,
    ) -> Result<String> {
        match self {
            Cryptor::SivCtrMac(c) => c.decrypt_name(encrypted_name, parent_dir_id),
            Cryptor::SivGcm(c) => c.decrypt_name(encrypted_name, parent_dir_id),
        }
    }
}
