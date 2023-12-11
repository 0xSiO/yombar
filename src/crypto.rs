pub mod siv_ctrmac;

pub trait FileHeader {}

pub trait FileCryptor {
    type Header: FileHeader;
    type Error: std::error::Error;

    fn encrypt_header(&self, header: &Self::Header) -> Result<Vec<u8>, Self::Error>;

    fn decrypt_header(&self, encrypted_header: &[u8]) -> Result<Self::Header, Self::Error>;

    fn encrypt_chunk(
        &self,
        chunk: &[u8],
        header: &Self::Header,
        chunk_number: usize,
    ) -> Result<Vec<u8>, Self::Error>;

    fn decrypt_chunk(
        &self,
        encrypted_chunk: &[u8],
        header: &Self::Header,
        chunk_number: usize,
    ) -> Result<Vec<u8>, Self::Error>;

    fn hash_dir_id(&self, dir_id: &str) -> Result<String, Self::Error>;

    fn encrypt_name(&self, name: &str, parent_dir_id: &str) -> Result<String, Self::Error>;

    fn decrypt_name(
        &self,
        encrypted_name: &str,
        parent_dir_id: &str,
    ) -> Result<String, Self::Error>;
}
