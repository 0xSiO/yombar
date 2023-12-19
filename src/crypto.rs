use std::{ffi::OsStr, path::PathBuf};

pub mod siv_ctrmac;

pub trait FileHeader {
    const ENCRYPTED_HEADER_LEN: usize;
}

pub trait FileCryptor {
    type Header: FileHeader;
    type Error: std::error::Error + Send + Sync + 'static;

    const MAX_CHUNK_LEN: usize;
    const MAX_ENCRYPTED_CHUNK_LEN: usize;

    fn encrypt_header(&self, header: &Self::Header) -> Result<Vec<u8>, Self::Error>;

    fn decrypt_header(
        &self,
        encrypted_header: impl AsRef<[u8]>,
    ) -> Result<Self::Header, Self::Error>;

    fn encrypt_chunk(
        &self,
        chunk: impl AsRef<[u8]>,
        header: &Self::Header,
        chunk_number: usize,
    ) -> Result<Vec<u8>, Self::Error>;

    fn decrypt_chunk(
        &self,
        encrypted_chunk: impl AsRef<[u8]>,
        header: &Self::Header,
        chunk_number: usize,
    ) -> Result<Vec<u8>, Self::Error>;

    fn hash_dir_id(&self, dir_id: impl AsRef<str>) -> Result<PathBuf, Self::Error>;

    fn encrypt_name(
        &self,
        name: impl AsRef<OsStr>,
        parent_dir_id: impl AsRef<str>,
    ) -> Result<String, Self::Error>;

    fn decrypt_name(
        &self,
        encrypted_name: impl AsRef<str>,
        parent_dir_id: impl AsRef<str>,
    ) -> Result<String, Self::Error>;
}
