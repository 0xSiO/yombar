use aes::{
    cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher, StreamCipherError},
    Aes256,
};
use aes_siv::siv::Aes256Siv;
use base32ct::{Base32Upper, Encoding as Base32Encoding};
use base64ct::{Base64Url, Encoding as Base64Encoding};
use ctr::Ctr128BE;
use hmac::{Hmac, Mac};
use rand_core::{self, OsRng, RngCore};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{error::SivCtrMacCryptorError as Error, key::SUBKEY_LEN, util, MasterKey};

use super::{FileCryptor, FileHeader};

// General constants
const NONCE_LEN: usize = 16;
const MAC_LEN: usize = 32;

// File header constants
const RESERVED_LEN: usize = 8;
const CONTENT_KEY_LEN: usize = 32;
const PAYLOAD_LEN: usize = RESERVED_LEN + CONTENT_KEY_LEN;
const ENCRYPTED_HEADER_LEN: usize = NONCE_LEN + PAYLOAD_LEN + MAC_LEN;

// File content constants
const MAX_CHUNK_LEN: usize = 32 * 1024;
const MAX_ENCRYPTED_CHUNK_LEN: usize = NONCE_LEN + MAX_CHUNK_LEN + MAC_LEN;

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
    const HEADER_SIZE: usize = ENCRYPTED_HEADER_LEN;
}

#[derive(Clone, Copy)]
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
    ) -> Result<Vec<u8>, StreamCipherError> {
        let mut message = message.to_vec();
        Ctr128BE::<Aes256>::new(key.into(), nonce.into()).try_apply_keystream(&mut message)?;
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
        associated_data: &[u8],
    ) -> Result<Vec<u8>, aes_siv::Error> {
        use aes_siv::KeyInit;

        // AES-SIV takes both the encryption key and mac key, but in reverse order
        // TODO: Use slice flatten() method when stabilized
        let mut key = [0_u8; SUBKEY_LEN * 2];
        let (left, right) = key.split_at_mut(SUBKEY_LEN);
        left.copy_from_slice(self.key.mac_key());
        right.copy_from_slice(self.key.enc_key());

        debug_assert_eq!(key.len(), SUBKEY_LEN * 2);

        Aes256Siv::new(GenericArray::from_slice(&key)).decrypt([associated_data], ciphertext)
    }

    fn chunk_hmac(&self, data: &[u8], header: &Header, chunk_number: usize) -> Vec<u8> {
        Hmac::<Sha256>::new_from_slice(self.key.mac_key())
            // Ok to unwrap, HMAC can take keys of any size
            .unwrap()
            .chain_update(header.nonce)
            .chain_update(chunk_number.to_be_bytes())
            .chain_update(data)
            .finalize()
            .into_bytes()
            .to_vec()
    }

    fn encrypt_chunk_using_nonce(
        &self,
        nonce: &[u8; NONCE_LEN],
        chunk: &[u8],
        header: &Header,
        chunk_number: usize,
    ) -> Result<Vec<u8>, StreamCipherError> {
        let mut buffer = Vec::with_capacity(NONCE_LEN + chunk.len() + MAC_LEN);
        buffer.extend(nonce);
        buffer.extend(self.aes_ctr(chunk, &header.content_key(), nonce)?);
        buffer.extend(self.chunk_hmac(&buffer, header, chunk_number));

        debug_assert!(buffer.len() <= MAX_ENCRYPTED_CHUNK_LEN);

        Ok(buffer)
    }
}

impl<'k> FileCryptor for Cryptor<'k> {
    type Header = Header;
    type Error = Error;

    const CHUNK_SIZE: usize = MAX_ENCRYPTED_CHUNK_LEN;

    fn encrypt_header(&self, header: &Header) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::with_capacity(ENCRYPTED_HEADER_LEN);
        buffer.extend(header.nonce);
        buffer.extend(self.aes_ctr(&header.payload, self.key.enc_key(), &header.nonce)?);
        buffer.extend(util::hmac(&buffer, self.key));
        debug_assert_eq!(buffer.len(), ENCRYPTED_HEADER_LEN);
        Ok(buffer)
    }

    fn decrypt_header(&self, encrypted_header: &[u8]) -> Result<Header, Error> {
        if encrypted_header.len() != ENCRYPTED_HEADER_LEN {
            return Err(Error::InvalidHeaderLen(encrypted_header.len()));
        }

        // First, verify the HMAC
        let (nonce_and_payload, expected_mac) = encrypted_header.split_at(NONCE_LEN + PAYLOAD_LEN);
        let actual_mac = util::hmac(nonce_and_payload, self.key);
        if actual_mac != expected_mac {
            return Err(Error::MacVerificationFailed {
                expected: expected_mac.to_vec(),
                actual: actual_mac,
            });
        }

        // Next, decrypt the payload
        let (nonce, payload) = nonce_and_payload.split_at(NONCE_LEN);
        // Ok to convert to sized arrays - we know the lengths at this point
        let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();
        let payload: [u8; PAYLOAD_LEN] = self
            .aes_ctr(payload, self.key.enc_key(), &nonce)?
            .try_into()
            .unwrap();

        Ok(Header { nonce, payload })
    }

    fn encrypt_chunk(
        &self,
        chunk: &[u8],
        header: &Header,
        chunk_number: usize,
    ) -> Result<Vec<u8>, Error> {
        if chunk.is_empty() || chunk.len() > MAX_CHUNK_LEN {
            return Err(Error::InvalidChunkLen(chunk.len()));
        }

        let mut nonce = [0_u8; NONCE_LEN];
        OsRng.try_fill_bytes(&mut nonce)?;
        Ok(self.encrypt_chunk_using_nonce(&nonce, chunk, header, chunk_number)?)
    }

    fn decrypt_chunk(
        &self,
        encrypted_chunk: &[u8],
        header: &Header,
        chunk_number: usize,
    ) -> Result<Vec<u8>, Error> {
        if encrypted_chunk.len() <= NONCE_LEN + MAC_LEN
            || encrypted_chunk.len() > MAX_ENCRYPTED_CHUNK_LEN
        {
            return Err(Error::InvalidChunkLen(encrypted_chunk.len()));
        }

        // First, verify the HMAC
        let (nonce_and_chunk, expected_mac) =
            encrypted_chunk.split_at(encrypted_chunk.len() - MAC_LEN);
        let actual_mac = self.chunk_hmac(nonce_and_chunk, header, chunk_number);
        if actual_mac != expected_mac {
            return Err(Error::MacVerificationFailed {
                expected: expected_mac.to_vec(),
                actual: actual_mac,
            });
        }

        // Next, decrypt the chunk
        let (nonce, chunk) = nonce_and_chunk.split_at(NONCE_LEN);
        // Ok to unwrap - we know the length at this point
        let nonce: [u8; NONCE_LEN] = nonce.try_into().unwrap();

        Ok(self.aes_ctr(chunk, &header.content_key(), &nonce)?)
    }

    fn hash_dir_id(&self, dir_id: &str) -> Result<String, Error> {
        let ciphertext = self.aes_siv_encrypt(dir_id.as_bytes(), &[])?;
        let hash = Sha1::new().chain_update(ciphertext).finalize();
        Ok(Base32Upper::encode_string(&hash))
    }

    // TODO: "The cleartext name of a file gets encoded using UTF-8 in Normalization Form C to get
    // a unique binary representation." https://github.com/unicode-rs/unicode-normalization
    fn encrypt_name(&self, name: &str, parent_dir_id: &str) -> Result<String, Error> {
        Ok(Base64Url::encode_string(&self.aes_siv_encrypt(
            name.as_bytes(),
            &[parent_dir_id.as_bytes()],
        )?))
    }

    fn decrypt_name(&self, encrypted_name: &str, parent_dir_id: &str) -> Result<String, Error> {
        // TODO: Can we assume the decrypted bytes are valid UTF-8?
        Ok(String::from_utf8(self.aes_siv_decrypt(
            &Base64Url::decode_vec(encrypted_name)?,
            parent_dir_id.as_bytes(),
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
            .encrypt_chunk_using_nonce(&[0; NONCE_LEN], &chunk, &header, 2)
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
