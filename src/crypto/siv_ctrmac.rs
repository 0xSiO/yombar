use std::{ffi::OsStr, path::PathBuf};

use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes256,
};
use aes_siv::siv::Aes256Siv;
use base32ct::{Base32Upper, Encoding as Base32Encoding};
use base64ct::{Base64Url, Encoding as Base64Encoding};
use color_eyre::eyre::bail;
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use rand_core::{self, OsRng, RngCore};
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::{key::SUBKEY_LEN, util, MasterKey, Result};

use super::{FileCryptor, FileHeader, HEADER_RESERVED_LEN};

// General constants
const NONCE_LEN: usize = 16;
const MAC_LEN: usize = 32;

// File header constants
const CONTENT_KEY_LEN: usize = 32;
const PAYLOAD_LEN: usize = HEADER_RESERVED_LEN + CONTENT_KEY_LEN;
const ENCRYPTED_HEADER_LEN: usize = NONCE_LEN + PAYLOAD_LEN + MAC_LEN;

// File content constants
const MAX_CHUNK_LEN: usize = 32 * 1024;
const MAX_ENCRYPTED_CHUNK_LEN: usize = NONCE_LEN + MAX_CHUNK_LEN + MAC_LEN;

#[derive(Debug, Clone, Copy)]
pub struct Cryptor<'k> {
    key: &'k MasterKey,
}

impl<'k> Cryptor<'k> {
    pub fn new(key: &'k MasterKey) -> Self {
        Self { key }
    }

    fn aes_ctr(&self, message: &[u8], key: &[u8; SUBKEY_LEN], nonce: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = message.to_vec();
        Ctr128BE::<Aes256>::new(key.into(), nonce.into()).try_apply_keystream(&mut buffer)?;
        Ok(buffer)
    }

    fn aes_siv_encrypt(&self, plaintext: &[u8], associated_data: &[&[u8]]) -> Result<Vec<u8>> {
        use aes_siv::KeyInit;

        // AES-SIV takes both the encryption key and mac key, but in reverse order
        let key: [[u8; SUBKEY_LEN]; 2] = [*self.key.mac_key(), *self.key.enc_key()];

        Ok(Aes256Siv::new(key.as_flattened().into()).encrypt(associated_data, plaintext)?)
    }

    fn aes_siv_decrypt(&self, ciphertext: &[u8], associated_data: &[&[u8]]) -> Result<Vec<u8>> {
        use aes_siv::KeyInit;

        // AES-SIV takes both the encryption key and mac key, but in reverse order
        let key: [[u8; SUBKEY_LEN]; 2] = [*self.key.mac_key(), *self.key.enc_key()];

        Ok(Aes256Siv::new(key.as_flattened().into()).decrypt(associated_data, ciphertext)?)
    }

    fn chunk_hmac(&self, data: &[u8], header: &FileHeader, chunk_number: usize) -> Vec<u8> {
        Hmac::<Sha256>::new_from_slice(self.key.mac_key())
            // Ok to unwrap, HMAC can take keys of any size
            .unwrap()
            .chain_update(&header.nonce)
            .chain_update(chunk_number.to_be_bytes())
            .chain_update(data)
            .finalize()
            .into_bytes()
            .to_vec()
    }

    fn encrypt_chunk_with_nonce(
        &self,
        nonce: &[u8],
        chunk: &[u8],
        header: &FileHeader,
        chunk_number: usize,
    ) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(NONCE_LEN + chunk.len() + MAC_LEN);
        buffer.extend(nonce);
        buffer.extend(self.aes_ctr(chunk, &header.content_key(), nonce)?);
        buffer.extend(self.chunk_hmac(&buffer, header, chunk_number));

        debug_assert!(buffer.len() <= MAX_ENCRYPTED_CHUNK_LEN);

        Ok(buffer)
    }
}

impl<'k> FileCryptor for Cryptor<'k> {
    fn encrypted_header_len(&self) -> usize {
        ENCRYPTED_HEADER_LEN
    }

    fn max_chunk_len(&self) -> usize {
        MAX_CHUNK_LEN
    }

    fn max_encrypted_chunk_len(&self) -> usize {
        MAX_ENCRYPTED_CHUNK_LEN
    }

    fn new_header(&self) -> Result<FileHeader> {
        FileHeader::new(NONCE_LEN, PAYLOAD_LEN)
    }

    fn encrypt_header(&self, header: &FileHeader) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(ENCRYPTED_HEADER_LEN);
        buffer.extend(&header.nonce);
        buffer.extend(self.aes_ctr(&header.payload, self.key.enc_key(), &header.nonce)?);
        buffer.extend(util::hmac(&buffer, self.key));
        debug_assert_eq!(buffer.len(), ENCRYPTED_HEADER_LEN);
        Ok(buffer)
    }

    fn decrypt_header(&self, encrypted_header: impl AsRef<[u8]>) -> Result<FileHeader> {
        let encrypted_header = encrypted_header.as_ref();
        if encrypted_header.len() != ENCRYPTED_HEADER_LEN {
            bail!("invalid header length: {}", encrypted_header.len());
        }

        // Ok to start slicing, we've checked the length
        let expected_mac = encrypted_header[NONCE_LEN + PAYLOAD_LEN..].to_vec();

        // First, verify the HMAC
        let actual_mac = util::hmac(&encrypted_header[..NONCE_LEN + PAYLOAD_LEN], self.key);
        if actual_mac != expected_mac {
            bail!("failed to verify header MAC");
        }

        // Next, decrypt the payload
        let nonce = encrypted_header[..NONCE_LEN].to_vec();
        let encrypted_payload = &encrypted_header[NONCE_LEN..NONCE_LEN + PAYLOAD_LEN];
        let payload = self.aes_ctr(encrypted_payload, self.key.enc_key(), &nonce)?;

        Ok(FileHeader { nonce, payload })
    }

    fn encrypt_chunk(
        &self,
        chunk: impl AsRef<[u8]>,
        header: &FileHeader,
        chunk_number: usize,
    ) -> Result<Vec<u8>> {
        let chunk = chunk.as_ref();
        if chunk.is_empty() || chunk.len() > MAX_CHUNK_LEN {
            bail!("invalid cleartext chunk length: {}", chunk.len());
        }

        let mut nonce = [0_u8; NONCE_LEN];
        OsRng.try_fill_bytes(&mut nonce)?;
        self.encrypt_chunk_with_nonce(&nonce, chunk, header, chunk_number)
    }

    fn decrypt_chunk(
        &self,
        encrypted_chunk: impl AsRef<[u8]>,
        header: &FileHeader,
        chunk_number: usize,
    ) -> Result<Vec<u8>> {
        let encrypted_chunk = encrypted_chunk.as_ref();
        if encrypted_chunk.len() <= NONCE_LEN + MAC_LEN
            || encrypted_chunk.len() > MAX_ENCRYPTED_CHUNK_LEN
        {
            bail!("invalid ciphertext chunk length: {}", encrypted_chunk.len());
        }

        // First, verify the HMAC
        let (nonce_and_chunk, expected_mac) =
            encrypted_chunk.split_at(encrypted_chunk.len() - MAC_LEN);
        let actual_mac = self.chunk_hmac(nonce_and_chunk, header, chunk_number);
        if actual_mac != expected_mac {
            bail!("failed to verify chunk MAC");
        }

        // Next, decrypt the chunk
        let (nonce, chunk) = nonce_and_chunk.split_at(NONCE_LEN);
        // Ok to convert to sized arrays - we know the lengths at this point
        let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();

        self.aes_ctr(chunk, &header.content_key(), &nonce)
    }

    fn hash_dir_id(&self, dir_id: impl AsRef<str>) -> Result<PathBuf> {
        let ciphertext = self.aes_siv_encrypt(dir_id.as_ref().as_bytes(), &[])?;
        let hash = Sha1::new().chain_update(ciphertext).finalize();
        let base32 = Base32Upper::encode_string(&hash);
        let (first, second) = base32.split_at(2);
        Ok(PathBuf::from(first).join(second))
    }

    // TODO: "The cleartext name of a file gets encoded using UTF-8 in Normalization Form C to get
    // a unique binary representation." https://github.com/unicode-rs/unicode-normalization
    fn encrypt_name(
        &self,
        name: impl AsRef<OsStr>,
        parent_dir_id: impl AsRef<str>,
    ) -> Result<String> {
        Ok(Base64Url::encode_string(&self.aes_siv_encrypt(
            // TODO: Is it okay to use lossy UTF-8 conversion?
            name.as_ref().to_string_lossy().as_bytes(),
            &[parent_dir_id.as_ref().as_bytes()],
        )?))
    }

    fn decrypt_name(
        &self,
        encrypted_name: impl AsRef<str>,
        parent_dir_id: impl AsRef<str>,
    ) -> Result<String> {
        // TODO: Can we assume the decrypted bytes are valid UTF-8?
        Ok(String::from_utf8(self.aes_siv_decrypt(
            &Base64Url::decode_vec(encrypted_name.as_ref())?,
            &[parent_dir_id.as_ref().as_bytes()],
        )?)?)
    }
}

#[cfg(test)]
mod tests {
    use base64ct::Base64;

    use super::*;

    #[test]
    fn file_chunk_test() {
        // Safe, this is for test purposes only
        let key = unsafe { MasterKey::from_bytes([13_u8; SUBKEY_LEN * 2]) };
        let cryptor = Cryptor::new(&key);
        let header = FileHeader {
            nonce: vec![19; NONCE_LEN],
            payload: vec![23; PAYLOAD_LEN],
        };
        let chunk = b"the quick brown fox jumps over the lazy dog".to_vec();

        let ciphertext = cryptor
            .encrypt_chunk_with_nonce(&[0; NONCE_LEN], &chunk, &header, 2)
            .unwrap();
        assert_eq!(
            Base64::encode_string(&ciphertext),
            "AAAAAAAAAAAAAAAAAAAAAPEq/PjcykUIlDRazM36igCN1QKikATEKglKUEDWiEkMGujfnzOMHOLK+h1N4PnB891N+uiKvZVyNWgezJc2G4ejVvLko6B1/IMyrQ=="
        );
        assert_eq!(
            cryptor.decrypt_chunk(&ciphertext, &header, 2).unwrap(),
            chunk
        );
    }
}
