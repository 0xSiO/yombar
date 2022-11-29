pub mod v1;

pub trait FileHeader
where
    Self: Sized,
{
    fn new() -> Result<Self, rand_core::Error>;
}

pub trait FileCryptor<H: FileHeader> {
    fn encrypt_header(&self, header: H) -> Vec<u8>;

    fn decrypt_header(ciphertext: Vec<u8>) -> H;

    fn encrypt_chunk(header: H, cleartext: Vec<u8>, chunk_number: usize) -> Vec<u8>;

    fn decrypt_chunk(header: H, ciphertext: Vec<u8>, chunk_number: usize) -> Vec<u8>;

    fn encrypt_name(cleartext_name: String, data: Vec<u8>) -> Vec<u8>;

    fn decrypt_name(ciphertext_name: String, data: Vec<u8>) -> String;
}
