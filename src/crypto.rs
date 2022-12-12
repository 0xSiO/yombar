pub mod v1;

pub trait FileHeader
where
    Self: Sized,
{
    fn new() -> Result<Self, rand_core::Error>;
}

pub trait FileCryptor<H: FileHeader> {
    fn encrypt_header(&self, header: H) -> Vec<u8>;

    // TODO: Return Result
    fn decrypt_header(&self, encrypted_header: Vec<u8>) -> H;

    fn encrypt_chunk(&self, chunk: Vec<u8>, header: &H, chunk_number: usize) -> Vec<u8>;

    fn decrypt_chunk(&self, encrypted_chunk: Vec<u8>, header: &H, chunk_number: usize) -> Vec<u8>;

    fn encrypt_name(name: String, data: Vec<u8>) -> Vec<u8>;

    fn decrypt_name(encrypted_name: String, data: Vec<u8>) -> String;
}
