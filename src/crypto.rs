pub mod siv_ctrmac;

pub trait FileHeader {}

// TODO: Return result where needed
pub trait FileCryptor<H: FileHeader, E: std::error::Error> {
    fn encrypt_header(&self, header: &H) -> Result<Vec<u8>, E>;

    fn decrypt_header(&self, encrypted_header: &[u8]) -> Result<H, E>;

    fn encrypt_chunk(&self, chunk: &[u8], header: &H, chunk_number: usize) -> Result<Vec<u8>, E>;

    fn decrypt_chunk(
        &self,
        encrypted_chunk: &[u8],
        header: &H,
        chunk_number: usize,
    ) -> Result<Vec<u8>, E>;

    fn hash_dir_id(&self, dir_id: &str) -> Result<String, E>;

    fn encrypt_name(&self, name: &str, parent_dir_id: &str) -> Result<String, E>;

    fn decrypt_name(&self, encrypted_name: &str, parent_dir_id: &str) -> Result<String, E>;
}
