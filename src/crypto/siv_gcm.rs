use std::{ffi::OsStr, path::PathBuf};

use aes_gcm::{aead::AeadMutInPlace, Aes256Gcm, Tag};
use aes_siv::siv::Aes256Siv;
use base32ct::{Base32Upper, Encoding as Base32Encoding};
use base64ct::{Base64Url, Encoding as Base64Encoding};
use rand_core::{OsRng, RngCore};
use sha1::{Digest, Sha1};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{error::SivGcmCryptorError as Error, key::SUBKEY_LEN, MasterKey};

use super::{FileCryptor, FileHeader};

// General constants
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

// File header constants
const RESERVED_LEN: usize = 8;
const CONTENT_KEY_LEN: usize = 32;
const PAYLOAD_LEN: usize = RESERVED_LEN + CONTENT_KEY_LEN;
const ENCRYPTED_HEADER_LEN: usize = NONCE_LEN + PAYLOAD_LEN + TAG_LEN;

// File content constants
const MAX_CHUNK_LEN: usize = 32 * 1024;
const MAX_ENCRYPTED_CHUNK_LEN: usize = NONCE_LEN + MAX_CHUNK_LEN + TAG_LEN;

#[derive(Debug, PartialEq, Eq, Clone, Zeroize, ZeroizeOnDrop)]
pub struct Header {
    nonce: [u8; NONCE_LEN],
    payload: [u8; PAYLOAD_LEN],
}

impl Header {
    pub fn new() -> Result<Self, rand_core::Error> {
        let mut nonce = [0_u8; NONCE_LEN];
        OsRng.try_fill_bytes(&mut nonce)?;

        let mut payload = [0_u8; PAYLOAD_LEN];
        OsRng.try_fill_bytes(&mut payload)?;

        // Overwrite first portion with reserved bytes
        payload[..RESERVED_LEN].copy_from_slice(&[0xff; RESERVED_LEN]);

        Ok(Self { nonce, payload })
    }

    fn content_key(&self) -> [u8; SUBKEY_LEN] {
        debug_assert_eq!(self.payload.len() - RESERVED_LEN, SUBKEY_LEN);
        self.payload[RESERVED_LEN..].try_into().unwrap()
    }
}

impl FileHeader for Header {
    const ENCRYPTED_HEADER_LEN: usize = ENCRYPTED_HEADER_LEN;
}

#[derive(Clone, Copy)]
pub struct Cryptor<'k> {
    key: &'k MasterKey,
}

impl<'k> Cryptor<'k> {
    pub fn new(key: &'k MasterKey) -> Self {
        Self { key }
    }

    fn aes_gcm_encrypt(
        &self,
        message: &[u8],
        key: &[u8; SUBKEY_LEN],
        nonce: &[u8; NONCE_LEN],
        associated_data: &[u8],
    ) -> Result<(Vec<u8>, Tag), aes_gcm::Error> {
        use aes_gcm::KeyInit;

        let mut message = message.to_vec();
        let tag = Aes256Gcm::new(key.into()).encrypt_in_place_detached(
            nonce.into(),
            associated_data,
            &mut message,
        )?;
        Ok((message, tag))
    }

    fn aes_gcm_decrypt(
        &self,
        ciphertext: &[u8],
        key: &[u8; SUBKEY_LEN],
        nonce: &[u8; NONCE_LEN],
        associated_data: &[u8],
        tag: &[u8; TAG_LEN],
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        use aes_gcm::KeyInit;

        let mut message = ciphertext.to_vec();
        Aes256Gcm::new(key.into()).decrypt_in_place_detached(
            nonce.into(),
            associated_data,
            &mut message,
            tag.into(),
        )?;

        Ok(message)
    }

    fn aes_siv_encrypt(
        &self,
        plaintext: &[u8],
        associated_data: &[&[u8]],
    ) -> Result<Vec<u8>, aes_siv::Error> {
        use aes_siv::KeyInit;

        // AES-SIV takes both the encryption key and mac key, but in reverse order
        // TODO: Use slice flatten() method when stabilized
        let mut key = [0_u8; SUBKEY_LEN * 2];
        let (left, right) = key.split_at_mut(SUBKEY_LEN);
        left.copy_from_slice(self.key.mac_key());
        right.copy_from_slice(self.key.enc_key());

        Aes256Siv::new(&key.into()).encrypt(associated_data, plaintext)
    }

    fn aes_siv_decrypt(
        &self,
        ciphertext: &[u8],
        associated_data: &[&[u8]],
    ) -> Result<Vec<u8>, aes_siv::Error> {
        use aes_siv::KeyInit;

        // AES-SIV takes both the encryption key and mac key, but in reverse order
        // TODO: Use slice flatten() method when stabilized
        let mut key = [0_u8; SUBKEY_LEN * 2];
        let (left, right) = key.split_at_mut(SUBKEY_LEN);
        left.copy_from_slice(self.key.mac_key());
        right.copy_from_slice(self.key.enc_key());

        Aes256Siv::new(&key.into()).decrypt(associated_data, ciphertext)
    }

    fn encrypt_chunk_with_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        chunk: &[u8],
        header: &Header,
        chunk_number: usize,
    ) -> Result<Vec<u8>, aes_gcm::Error> {
        let mut buffer = Vec::with_capacity(NONCE_LEN + chunk.len() + TAG_LEN);

        let mut associated_data = chunk_number.to_be_bytes().to_vec();
        associated_data.extend(header.nonce);
        let (ciphertext, tag) =
            self.aes_gcm_encrypt(chunk, &header.content_key(), nonce, &associated_data)?;

        buffer.extend(nonce);
        buffer.extend(ciphertext);
        buffer.extend(tag);

        debug_assert!(buffer.len() <= MAX_ENCRYPTED_CHUNK_LEN);

        Ok(buffer)
    }
}

impl<'k> FileCryptor for Cryptor<'k> {
    type Header = Header;
    type Error = Error;

    const MAX_CHUNK_LEN: usize = MAX_CHUNK_LEN;
    const MAX_ENCRYPTED_CHUNK_LEN: usize = MAX_ENCRYPTED_CHUNK_LEN;

    fn encrypt_header(&self, header: &Self::Header) -> Result<Vec<u8>, Self::Error> {
        let mut buffer = Vec::with_capacity(ENCRYPTED_HEADER_LEN);
        let (ciphertext, tag) =
            self.aes_gcm_encrypt(&header.payload, self.key.enc_key(), &header.nonce, &[])?;

        buffer.extend(header.nonce);
        buffer.extend(ciphertext);
        buffer.extend(tag);

        debug_assert_eq!(buffer.len(), ENCRYPTED_HEADER_LEN);

        Ok(buffer)
    }

    fn decrypt_header(
        &self,
        encrypted_header: impl AsRef<[u8]>,
    ) -> Result<Self::Header, Self::Error> {
        let encrypted_header = encrypted_header.as_ref();
        if encrypted_header.len() != ENCRYPTED_HEADER_LEN {
            return Err(Error::InvalidHeaderLen(encrypted_header.len()));
        }

        let (nonce_and_payload, tag) = encrypted_header.split_at(NONCE_LEN + PAYLOAD_LEN);
        let (nonce, payload) = nonce_and_payload.split_at(NONCE_LEN);
        // Ok to convert to sized arrays - we know the lengths at this point
        let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();
        let tag: [u8; TAG_LEN] = tag.try_into().unwrap();
        let payload: [u8; PAYLOAD_LEN] = self
            .aes_gcm_decrypt(payload, self.key.enc_key(), &nonce, &[], &tag)?
            .try_into()
            .unwrap();

        Ok(Header { nonce, payload })
    }

    fn encrypt_chunk(
        &self,
        chunk: impl AsRef<[u8]>,
        header: &Self::Header,
        chunk_number: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        let chunk = chunk.as_ref();
        if chunk.is_empty() || chunk.len() > MAX_CHUNK_LEN {
            return Err(Error::InvalidChunkLen(chunk.len()));
        }

        let mut nonce = [0_u8; NONCE_LEN];
        OsRng.try_fill_bytes(&mut nonce)?;
        Ok(self.encrypt_chunk_with_nonce(&nonce, chunk, header, chunk_number)?)
    }

    fn decrypt_chunk(
        &self,
        encrypted_chunk: impl AsRef<[u8]>,
        header: &Self::Header,
        chunk_number: usize,
    ) -> Result<Vec<u8>, Self::Error> {
        let encrypted_chunk = encrypted_chunk.as_ref();
        if encrypted_chunk.len() <= NONCE_LEN + TAG_LEN
            || encrypted_chunk.len() > MAX_ENCRYPTED_CHUNK_LEN
        {
            return Err(Error::InvalidChunkLen(encrypted_chunk.len()));
        }

        let (nonce_and_chunk, tag) = encrypted_chunk.split_at(encrypted_chunk.len() - TAG_LEN);
        let (nonce, chunk) = nonce_and_chunk.split_at(NONCE_LEN);
        // Ok to convert to sized arrays - we know the lengths at this point
        let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();
        let tag: [u8; TAG_LEN] = tag.try_into().unwrap();

        let mut associated_data = chunk_number.to_be_bytes().to_vec();
        associated_data.extend(header.nonce);

        Ok(self.aes_gcm_decrypt(chunk, &header.content_key(), &nonce, &associated_data, &tag)?)
    }

    fn hash_dir_id(&self, dir_id: impl AsRef<str>) -> Result<std::path::PathBuf, Self::Error> {
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
    ) -> Result<String, Error> {
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
    ) -> Result<String, Error> {
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
        let header = Header {
            nonce: [19; NONCE_LEN],
            payload: [23; PAYLOAD_LEN],
        };
        let chunk = b"the quick brown fox jumps over the lazy dog".to_vec();

        let ciphertext = cryptor
            .encrypt_chunk_with_nonce(&[0; NONCE_LEN], &chunk, &header, 2)
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
