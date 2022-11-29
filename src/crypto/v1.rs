use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes256,
};
use ctr::Ctr64LE;
use hmac::{Hmac, Mac};
use rand_core::{self, OsRng, RngCore};
use sha2::Sha256;

use crate::MasterKey;

use super::FileCryptor;

const NONCE_LEN: usize = 16;
const RESERVED_LEN: usize = 8;
const CONTENT_KEY_LEN: usize = 32;
const MAC_LEN: usize = 32;

struct FileHeader {
    nonce: [u8; NONCE_LEN],
    payload: [u8; RESERVED_LEN + CONTENT_KEY_LEN],
}

impl super::FileHeader for FileHeader {
    fn new() -> Result<Self, rand_core::Error> {
        let mut nonce = [0_u8; NONCE_LEN];
        OsRng.try_fill_bytes(&mut nonce)?;

        let mut payload = [0_u8; RESERVED_LEN + CONTENT_KEY_LEN];
        OsRng.try_fill_bytes(&mut payload)?;

        // Overwrite first portion with reserved bytes
        payload[..RESERVED_LEN].copy_from_slice(&[0xff; RESERVED_LEN]);

        Ok(Self { nonce, payload })
    }
}

struct Cryptor<'k> {
    key: &'k MasterKey,
}

impl<'k> FileCryptor<FileHeader> for Cryptor<'k> {
    fn encrypt_header(&self, mut header: FileHeader) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(header.nonce.len() + header.payload.len() + MAC_LEN);
        buffer.extend(header.nonce);

        // TODO: Confirm whether this the correct counter type and key size
        let mut cipher = Ctr64LE::<Aes256>::new(self.key.enc_key().into(), &header.nonce.into());
        cipher.apply_keystream(&mut header.payload);
        buffer.extend(header.payload);

        let mac = Hmac::<Sha256>::new_from_slice(self.key.mac_key())
            // Ok to unwrap, HMAC can take keys of any size
            .unwrap()
            .chain_update(&buffer)
            .finalize()
            .into_bytes();
        buffer.extend(mac);

        buffer
    }

    fn decrypt_header(ciphertext: Vec<u8>) -> FileHeader {
        todo!()
    }

    fn encrypt_chunk(header: FileHeader, cleartext: Vec<u8>, chunk_number: usize) -> Vec<u8> {
        todo!()
    }

    fn decrypt_chunk(header: FileHeader, ciphertext: Vec<u8>, chunk_number: usize) -> Vec<u8> {
        todo!()
    }

    fn encrypt_name(cleartext_name: String, data: Vec<u8>) -> Vec<u8> {
        todo!()
    }

    fn decrypt_name(ciphertext_name: String, data: Vec<u8>) -> String {
        todo!()
    }
}
