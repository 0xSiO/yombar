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
const PAYLOAD_LEN: usize = RESERVED_LEN + CONTENT_KEY_LEN;
const HEADER_LEN: usize = NONCE_LEN + PAYLOAD_LEN;
const ENCRYPTED_HEADER_LEN: usize = HEADER_LEN + MAC_LEN;

struct FileHeader {
    nonce: [u8; NONCE_LEN],
    payload: [u8; PAYLOAD_LEN],
}

impl super::FileHeader for FileHeader {
    fn new() -> Result<Self, rand_core::Error> {
        let mut nonce = [0_u8; NONCE_LEN];
        OsRng.try_fill_bytes(&mut nonce)?;

        let mut payload = [0_u8; PAYLOAD_LEN];
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
        let mut buffer = Vec::with_capacity(ENCRYPTED_HEADER_LEN);
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

        debug_assert_eq!(buffer.len(), ENCRYPTED_HEADER_LEN);

        buffer
    }

    fn decrypt_header(&self, encrypted_header: Vec<u8>) -> FileHeader {
        if encrypted_header.len() != ENCRYPTED_HEADER_LEN {
            // TODO: Error
        }

        // First, verify the HMAC

        let (nonce_and_payload, expected_mac) = encrypted_header.split_at(HEADER_LEN);

        let actual_mac = Hmac::<Sha256>::new_from_slice(self.key.mac_key())
            // Ok to unwrap, HMAC can take keys of any size
            .unwrap()
            .chain_update(nonce_and_payload)
            .finalize()
            .into_bytes()
            .to_vec();

        if actual_mac != expected_mac {
            // TODO: Error
        }

        // Next, decrypt the payload

        let (nonce, payload) = nonce_and_payload.split_at(NONCE_LEN);

        debug_assert_eq!(nonce.len(), NONCE_LEN);
        debug_assert_eq!(payload.len(), PAYLOAD_LEN);

        // Ok to convert these to sized arrays since we know the length at this point
        let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();
        let mut payload: [u8; PAYLOAD_LEN] = payload.try_into().unwrap();

        // TODO: Confirm whether this the correct counter type and key size
        let mut cipher = Ctr64LE::<Aes256>::new(self.key.enc_key().into(), &nonce.into());
        // TODO: Does this work for decrypting the ciphertext?
        cipher.apply_keystream(&mut payload);

        FileHeader { nonce, payload }
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
