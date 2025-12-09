use std::{ffi::OsStr, path::PathBuf};

use rand::Rng;
use secrets::{Secret, SecretBox};

use crate::{Result, key::SUBKEY_LEN};

pub mod siv_ctrmac;
pub mod siv_gcm;

const HEADER_RESERVED_LEN: usize = 8;
const HEADER_PAYLOAD_LEN: usize = HEADER_RESERVED_LEN + SUBKEY_LEN;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FileHeader {
    nonce: Vec<u8>,
    payload: SecretBox<[u8; HEADER_PAYLOAD_LEN]>,
}

impl FileHeader {
    fn new(nonce_len: usize) -> Result<Self> {
        let mut nonce = vec![0_u8; nonce_len];
        rand::thread_rng().try_fill(nonce.as_mut_slice())?;

        Secret::<[u8; HEADER_RESERVED_LEN + SUBKEY_LEN]>::random(|mut s| {
            s.first_chunk_mut::<HEADER_RESERVED_LEN>()
                .unwrap()
                .fill(0xff);

            Ok(Self {
                nonce,
                payload: SecretBox::from(&mut *s),
            })
        })
    }

    fn content_key(&self) -> [u8; SUBKEY_LEN] {
        *self.payload.borrow().last_chunk::<SUBKEY_LEN>().unwrap()
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

impl FileCryptor for Cryptor<'_> {
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
