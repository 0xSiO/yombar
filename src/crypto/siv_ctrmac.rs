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
use hmac::digest::CtOutput;
use rand::Rng;
use secrets::{Secret, SecretBox};
use sha1_checked::{Digest, Sha1};
use unicode_normalization::UnicodeNormalization;

use crate::{
    key::{MasterKey, SUBKEY_LEN},
    util, Result,
};

use super::{FileCryptor, FileHeader, HEADER_PAYLOAD_LEN};

// General constants
const NONCE_LEN: usize = 16;
const MAC_LEN: usize = 32;

// File header constants
const ENCRYPTED_HEADER_LEN: usize = NONCE_LEN + HEADER_PAYLOAD_LEN + MAC_LEN;

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

    fn aes_ctr(
        &self,
        message: &[u8],
        key: &[u8; SUBKEY_LEN],
        nonce: &[u8; NONCE_LEN],
    ) -> Result<Vec<u8>> {
        let mut buffer = message.to_vec();
        Ctr128BE::<Aes256>::new(key.into(), nonce.into()).try_apply_keystream(&mut buffer)?;
        Ok(buffer)
    }

    fn aes_siv_encrypt(&self, plaintext: &[u8], associated_data: &[&[u8]]) -> Result<Vec<u8>> {
        use aes_siv::KeyInit;

        Secret::<[[u8; SUBKEY_LEN]; 2]>::new(|mut key| {
            // AES-SIV takes both the encryption key and mac key, but in reverse order
            *key = [self.key.mac_key(), self.key.enc_key()];
            Ok(Aes256Siv::new(key.as_flattened().into()).encrypt(associated_data, plaintext)?)
        })
    }

    fn aes_siv_decrypt(&self, ciphertext: &[u8], associated_data: &[&[u8]]) -> Result<Vec<u8>> {
        use aes_siv::KeyInit;

        Secret::<[[u8; SUBKEY_LEN]; 2]>::new(|mut key| {
            // AES-SIV takes both the encryption key and mac key, but in reverse order
            *key = [self.key.mac_key(), self.key.enc_key()];
            Ok(Aes256Siv::new(key.as_flattened().into()).decrypt(associated_data, ciphertext)?)
        })
    }

    fn encrypt_chunk_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        chunk: &[u8],
        header: &FileHeader,
        chunk_number: usize,
    ) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(NONCE_LEN + chunk.len() + MAC_LEN);
        buffer.extend(nonce);
        buffer.extend(self.aes_ctr(chunk, &header.content_key(), nonce)?);
        buffer.extend(
            util::hmac(
                self.key,
                &[&header.nonce, chunk_number.to_be_bytes().as_ref(), &buffer].concat(),
            )
            .into_bytes(),
        );

        debug_assert!(buffer.len() <= MAX_ENCRYPTED_CHUNK_LEN);

        Ok(buffer)
    }
}

impl FileCryptor for Cryptor<'_> {
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
        FileHeader::new(NONCE_LEN)
    }

    fn encrypt_header(&self, header: &FileHeader) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(ENCRYPTED_HEADER_LEN);
        if header.nonce.len() != NONCE_LEN {
            bail!("invalid nonce length: {}", header.nonce.len());
        }

        let nonce = header.nonce.first_chunk::<NONCE_LEN>().unwrap();
        buffer.extend(nonce);
        buffer.extend(self.aes_ctr(&*header.payload.borrow(), &self.key.enc_key(), nonce)?);
        buffer.extend(util::hmac(self.key, &buffer).into_bytes());

        debug_assert_eq!(buffer.len(), ENCRYPTED_HEADER_LEN);

        Ok(buffer)
    }

    fn decrypt_header(&self, encrypted_header: impl AsRef<[u8]>) -> Result<FileHeader> {
        let encrypted_header = encrypted_header.as_ref();
        if encrypted_header.len() != ENCRYPTED_HEADER_LEN {
            bail!("invalid header length: {}", encrypted_header.len());
        }

        // Ok to start slicing, we've checked the length
        let (nonce, rest) = encrypted_header.split_first_chunk::<NONCE_LEN>().unwrap();
        let (enc_payload, expected_mac) = rest.split_first_chunk::<HEADER_PAYLOAD_LEN>().unwrap();
        let expected_mac = expected_mac.first_chunk::<MAC_LEN>().unwrap();

        // First, verify the HMAC
        let expected_mac = CtOutput::new((*expected_mac).into());
        let actual_mac = util::hmac(
            self.key,
            &encrypted_header[..NONCE_LEN + HEADER_PAYLOAD_LEN],
        );
        if actual_mac != expected_mac {
            bail!("failed to verify header MAC");
        }

        // Next, decrypt the payload
        let mut payload = self.aes_ctr(enc_payload, &self.key.enc_key(), nonce)?;

        Ok(FileHeader {
            nonce: nonce.to_vec(),
            payload: SecretBox::from(payload.first_chunk_mut::<HEADER_PAYLOAD_LEN>().unwrap()),
        })
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
        rand::thread_rng().try_fill(&mut nonce)?;
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

        // Ok to convert to sized arrays - we know the lengths at this point
        let (nonce_and_chunk, expected_mac) =
            encrypted_chunk.split_last_chunk::<MAC_LEN>().unwrap();
        let (nonce, chunk) = nonce_and_chunk.split_first_chunk::<NONCE_LEN>().unwrap();

        // First, verify the HMAC
        let expected_mac = CtOutput::new((*expected_mac).into());
        let actual_mac = util::hmac(
            self.key,
            &[
                &header.nonce,
                chunk_number.to_be_bytes().as_ref(),
                nonce_and_chunk,
            ]
            .concat(),
        );
        if actual_mac != expected_mac {
            bail!("failed to verify chunk MAC");
        }

        self.aes_ctr(chunk, &header.content_key(), nonce)
    }

    fn hash_dir_id(&self, dir_id: impl AsRef<str>) -> Result<PathBuf> {
        let ciphertext = self.aes_siv_encrypt(dir_id.as_ref().as_bytes(), &[])?;
        let hash = Sha1::new().chain_update(ciphertext).finalize();
        let base32 = Base32Upper::encode_string(&hash);
        let (first, second) = base32.split_at(2);
        Ok(PathBuf::from(first).join(second))
    }

    fn encrypt_name(
        &self,
        name: impl AsRef<OsStr>,
        parent_dir_id: impl AsRef<str>,
    ) -> Result<String> {
        Ok(Base64Url::encode_string(
            &self.aes_siv_encrypt(
                name.as_ref()
                    .to_string_lossy()
                    .nfc()
                    .collect::<String>()
                    .as_bytes(),
                &[parent_dir_id.as_ref().as_bytes()],
            )?,
        ))
    }

    fn decrypt_name(
        &self,
        encrypted_name: impl AsRef<str>,
        parent_dir_id: impl AsRef<str>,
    ) -> Result<String> {
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
        let key = MasterKey::from_bytes([13_u8; SUBKEY_LEN * 2]);
        let cryptor = Cryptor::new(&key);
        let header = FileHeader {
            nonce: vec![19; NONCE_LEN],
            payload: SecretBox::from(&mut [23; HEADER_PAYLOAD_LEN]),
        };
        let chunk = b"the quick brown fox jumps over the lazy dog";

        let ciphertext = cryptor
            .encrypt_chunk_with_nonce(&[0; NONCE_LEN], chunk, &header, 2)
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
