use std::{ffi::OsStr, path::PathBuf};

use aes_siv::siv::Aes256Siv;
use base32ct::{Base32Upper, Encoding as Base32Encoding};
use base64ct::{Base64Url, Encoding as Base64Encoding};
use color_eyre::eyre::bail;
use rand::Rng;
use ring::aead::{Aad, LessSafeKey, Nonce, Tag, UnboundKey, AES_256_GCM};
use sha1_checked::{Digest, Sha1};
use unicode_normalization::UnicodeNormalization;

use crate::{
    key::{MasterKey, SUBKEY_LEN},
    Result,
};

use super::{FileCryptor, FileHeader, HEADER_PAYLOAD_LEN};

// General constants
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

// File header constants
const ENCRYPTED_HEADER_LEN: usize = NONCE_LEN + HEADER_PAYLOAD_LEN + TAG_LEN;

// File content constants
const MAX_CHUNK_LEN: usize = 32 * 1024;
const MAX_ENCRYPTED_CHUNK_LEN: usize = NONCE_LEN + MAX_CHUNK_LEN + TAG_LEN;

#[derive(Debug, Clone, Copy)]
pub struct Cryptor<'k> {
    key: &'k MasterKey,
}

impl<'k> Cryptor<'k> {
    pub fn new(key: &'k MasterKey) -> Self {
        Self { key }
    }

    // TODO: Use AES-GCM from ring until https://github.com/RustCrypto/AEADs/issues/74 is resolved
    fn aes_gcm_encrypt(
        &self,
        plaintext: &[u8],
        key: &[u8; SUBKEY_LEN],
        nonce: &[u8; NONCE_LEN],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, Tag)> {
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key)?);
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let aad = Aad::from(associated_data);
        let mut buffer = plaintext.to_vec();
        let tag = key.seal_in_place_separate_tag(nonce, aad, &mut buffer)?;

        Ok((buffer, tag))
    }

    // TODO: Use AES-GCM from ring until https://github.com/RustCrypto/AEADs/issues/74 is resolved
    fn aes_gcm_decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8; SUBKEY_LEN],
        nonce: &[u8; NONCE_LEN],
        associated_data: &[u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<Vec<u8>> {
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key)?);
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let aad = Aad::from(associated_data);
        let tag = Tag::from(*tag);
        let mut buffer = ciphertext.to_vec();
        key.open_in_place_separate_tag(nonce, aad, tag, &mut buffer, 0..)?;

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

    fn encrypt_chunk_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        chunk: &[u8],
        header: &FileHeader,
        chunk_number: usize,
    ) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(NONCE_LEN + chunk.len() + TAG_LEN);

        let mut associated_data = chunk_number.to_be_bytes().to_vec();
        associated_data.extend(&header.nonce);
        let (ciphertext, tag) =
            self.aes_gcm_encrypt(chunk, header.content_key(), nonce, &associated_data)?;

        buffer.extend(nonce);
        buffer.extend(ciphertext);
        buffer.extend(tag.as_ref());

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
        let (ciphertext, tag) =
            self.aes_gcm_encrypt(&header.payload, self.key.enc_key(), nonce, &[])?;

        buffer.extend(nonce);
        buffer.extend(ciphertext);
        buffer.extend(tag.as_ref());

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
        let (enc_payload, rest) = rest.split_first_chunk::<HEADER_PAYLOAD_LEN>().unwrap();
        let tag = rest.first_chunk::<TAG_LEN>().unwrap();

        let payload = self.aes_gcm_decrypt(enc_payload, self.key.enc_key(), nonce, &[], tag)?;

        Ok(FileHeader {
            nonce: nonce.to_vec(),
            payload: *payload.first_chunk::<HEADER_PAYLOAD_LEN>().unwrap(),
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
        if encrypted_chunk.len() <= NONCE_LEN + TAG_LEN
            || encrypted_chunk.len() > MAX_ENCRYPTED_CHUNK_LEN
        {
            bail!("invalid ciphertext chunk length: {}", encrypted_chunk.len());
        }

        // Ok to convert to sized arrays - we know the lengths at this point
        let (nonce_and_chunk, tag) = encrypted_chunk.split_last_chunk::<TAG_LEN>().unwrap();
        let (nonce, chunk) = nonce_and_chunk.split_first_chunk::<NONCE_LEN>().unwrap();

        let mut associated_data = chunk_number.to_be_bytes().to_vec();
        associated_data.extend(&header.nonce);

        self.aes_gcm_decrypt(chunk, header.content_key(), nonce, &associated_data, tag)
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
            payload: [23; HEADER_PAYLOAD_LEN],
        };
        let chunk = b"the quick brown fox jumps over the lazy dog";

        let ciphertext = cryptor
            .encrypt_chunk_with_nonce(&[0; NONCE_LEN], chunk, &header, 2)
            .unwrap();
        assert_eq!(
            Base64::encode_string(&ciphertext),
            "AAAAAAAAAAAAAAAABuWa0yODDKHFtRizEcmdCC+Lj4yIt17WEiaw4kNyO3sLHx+6HNwklpgcipEJ8lRmonOdo932Mmf5bTw="
        );
        assert_eq!(
            cryptor.decrypt_chunk(&ciphertext, &header, 2).unwrap(),
            chunk
        );
    }
}
