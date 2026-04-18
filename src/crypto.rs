use std::{ffi::OsStr, path::PathBuf, sync::Mutex};

use enum_dispatch::enum_dispatch;
use secrets::{Secret, SecretBox};

use crate::{Result, key::SUBKEY_LEN};

pub mod siv_ctrmac;
pub mod siv_gcm;

const HEADER_RESERVED_LEN: usize = 8;
const HEADER_PAYLOAD_LEN: usize = HEADER_RESERVED_LEN + SUBKEY_LEN;

#[derive(Debug)]
pub struct FileHeader {
    nonce: Vec<u8>,
    payload: Mutex<SecretBox<[u8; HEADER_PAYLOAD_LEN]>>,
}

impl FileHeader {
    fn new(nonce_len: usize) -> Result<Self> {
        let mut nonce = vec![0_u8; nonce_len];
        rand::fill(nonce.as_mut_slice());

        Secret::<[u8; HEADER_RESERVED_LEN + SUBKEY_LEN]>::random(|mut s| {
            s.first_chunk_mut::<HEADER_RESERVED_LEN>()
                .unwrap()
                .fill(0xff);

            Ok(Self {
                nonce,
                payload: Mutex::new(SecretBox::from(&mut *s)),
            })
        })
    }

    fn from_parts(nonce: Vec<u8>, payload: &mut [u8; HEADER_PAYLOAD_LEN]) -> Self {
        Self {
            nonce,
            payload: Mutex::new(SecretBox::from(payload)),
        }
    }

    fn payload(&self) -> [u8; HEADER_PAYLOAD_LEN] {
        *self.payload.lock().unwrap().borrow()
    }

    fn content_key(&self) -> [u8; SUBKEY_LEN] {
        *self
            .payload
            .lock()
            .unwrap()
            .borrow()
            .last_chunk::<SUBKEY_LEN>()
            .unwrap()
    }
}

#[enum_dispatch]
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
#[enum_dispatch(FileCryptor)]
pub enum Cryptor<'k> {
    SivCtrMac(siv_ctrmac::Cryptor<'k>),
    SivGcm(siv_gcm::Cryptor<'k>),
}
