pub mod v1;

pub trait FileHeader {}

// TODO: Return result where needed
pub trait FileCryptor<H: FileHeader> {
    fn encrypt_header(&self, header: &H) -> Vec<u8>;

    fn decrypt_header(&self, encrypted_header: &[u8]) -> H;

    fn encrypt_chunk(&self, chunk: &[u8], header: &H, chunk_number: usize) -> Vec<u8>;

    fn decrypt_chunk(&self, encrypted_chunk: &[u8], header: &H, chunk_number: usize) -> Vec<u8>;

    fn hash_dir_id(&self, dir_id: &str) -> String;

    fn encrypt_name(&self, name: &str, parent_dir_id: &str) -> String;

    fn decrypt_name(&self, encrypted_name: &str, parent_dir_id: &str) -> String;
}
