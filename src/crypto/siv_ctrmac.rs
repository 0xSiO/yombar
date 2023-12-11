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

impl FileHeader for Header {}

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

impl<'k> FileCryptor<Header, Error> for Cryptor<'k> {
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
    use aes_siv::siv::Aes128Siv;
    use base64ct::Base64;

    use super::*;

    #[test]
    fn siv_encrypt_decrypt_test() {
        use aes_siv::KeyInit;

        // First half is MAC key, second half is encryption key
        let key = [
            0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2,
            0xf1, 0xf0, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
            0xfc, 0xfd, 0xfe, 0xff,
        ];

        let plaintext = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        ];

        let associated_data = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        ];

        let ciphertext = Aes128Siv::new(GenericArray::from_slice(&key))
            .encrypt([associated_data], &plaintext)
            .unwrap();

        assert_eq!(
            Base64::encode_string(&ciphertext),
            "hWMtB8bo83+VCs0yCi7Mk0DAK5aQxNwE2u9/av5c"
        );

        assert_eq!(
            Aes128Siv::new(GenericArray::from_slice(&key))
                .decrypt([associated_data], &ciphertext)
                .unwrap(),
            plaintext
        );
    }

    #[test]
    fn file_header_test() {
        // Safe, this is for test purposes only
        let key = unsafe { MasterKey::from_bytes([12_u8; SUBKEY_LEN * 2]) };
        let cryptor = Cryptor::new(&key);
        let header = Header {
            nonce: [9; NONCE_LEN],
            payload: [2; PAYLOAD_LEN],
        };

        let ciphertext = cryptor.encrypt_header(&header).unwrap();
        assert_eq!(Base64::encode_string(&ciphertext), "CQkJCQkJCQkJCQkJCQkJCbLKvhHVpdx6zpp+DCYeHQbzlREdVyMvQODun2plN9x6WRVW6IIIbrg4FwObxUUOzEgfvVvBAzIGOMXnFHGSjVP5fNWJYI+TVA==");
        assert_eq!(cryptor.decrypt_header(&ciphertext).unwrap(), header);
    }

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

    #[test]
    fn dir_id_hash_test() {
        // Safe, this is for test purposes only
        let key = unsafe { MasterKey::from_bytes([0_u8; SUBKEY_LEN * 2]) };
        let cryptor = Cryptor::new(&key);

        assert_eq!(
            cryptor
                .hash_dir_id("373067f5-71bd-48a8-ab1a-cd4dc1f62d03")
                .unwrap(),
            "6NCUUJAQ6BMB33DOEGUQZHX7ZBDIT76T"
        );
    }

    #[test]
    fn file_name_test() {
        // Safe, this is for test purposes only
        let key = unsafe { MasterKey::from_bytes([53_u8; SUBKEY_LEN * 2]) };
        let cryptor = Cryptor::new(&key);
        let name = "example_file_name.txt";
        let dir_id = "b77a03f6-d561-482e-95ff-97d01a9ea26b";

        let ciphertext = cryptor.encrypt_name(name, dir_id).unwrap();
        assert_eq!(
            ciphertext,
            "WpmIYies2GhYC3gYZHOaUd76c3gp6VHLmFWy-7xWmDEQK19fEw=="
        );
        assert_eq!(cryptor.decrypt_name(&ciphertext, dir_id).unwrap(), name);
    }
}
