use std::io::{self, Read};

use aes::Aes256;
use aes_kw::Kek;
use hmac::{Hmac, Mac, digest::CtOutput};
use scrypt::{
    Params, Scrypt,
    password_hash::{PasswordHasher, Salt},
};
use secrets::{Secret, SecretVec};
use sha2::Sha256;

use crate::{
    Result,
    crypto::{Cryptor, FileCryptor},
    key::{MasterKey, SUBKEY_LEN},
};

pub struct SecretString {
    bytes: SecretVec<u8>,
}

impl From<String> for SecretString {
    fn from(mut value: String) -> Self {
        Self {
            // Safety: The unprotected memory holding the string is immediately zeroed once
            // copied into the SecretVec and is not used afterward.
            bytes: SecretVec::from(unsafe { value.as_bytes_mut() }),
        }
    }
}

pub(crate) fn derive_kek(
    password: SecretString,
    params: Params,
    salt: Salt,
) -> Result<Kek<Aes256>> {
    let mut password_hash =
        Scrypt.hash_password_customized(&password.bytes.borrow(), None, None, params, salt)?;

    Secret::<[u8; SUBKEY_LEN]>::new(|mut s| {
        // Ok to unwrap, Scrypt.hash_password_customized should have set the hash
        s.copy_from_slice(password_hash.hash.take().unwrap().as_bytes());
        Ok(Kek::from(*s))
    })
}

pub(crate) fn hmac(key: &MasterKey, data: &[u8]) -> CtOutput<Hmac<Sha256>> {
    Hmac::<Sha256>::new_from_slice(&key.mac_key())
        .expect("HMAC can take keys of any size")
        .chain_update(data)
        .finalize()
}

/// A modified version of [`Read::read_exact`] that ignores an unexpected EOF, returning whether
/// the whole buffer could be filled and the number of bytes read.
pub(crate) fn try_read_exact(mut this: impl Read, mut buf: &mut [u8]) -> io::Result<(bool, usize)> {
    let mut bytes_read: usize = 0;
    while !buf.is_empty() {
        match this.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                buf = &mut buf[n..];
                bytes_read += n;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok((buf.is_empty(), bytes_read))
}

pub(crate) fn get_cleartext_size(cryptor: Cryptor<'_>, ciphertext_size: u64) -> u64 {
    let max_enc_chunk_len = cryptor.max_encrypted_chunk_len() as u64;
    let max_chunk_len = cryptor.max_chunk_len() as u64;
    let enc_chunks_len = ciphertext_size - cryptor.encrypted_header_len() as u64;
    let num_chunks = enc_chunks_len.div_ceil(max_enc_chunk_len);

    enc_chunks_len - (num_chunks * (max_enc_chunk_len - max_chunk_len))
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use scrypt::password_hash::SaltString;

    use super::*;

    #[test]
    fn password_hash_test() {
        let password = String::from("the_password");
        let salt_string = SaltString::encode_b64(b"salty").unwrap();
        let params = Params::new(4, 8, 1, SUBKEY_LEN).unwrap();
        let password_hash = Scrypt
            .hash_password_customized(password.as_bytes(), None, None, params, &salt_string)
            .unwrap();

        assert_eq!(
            Base64::encode_string(password_hash.hash.unwrap().as_bytes()),
            "VXfqskgJw4XfN0pWQYfD4UlSJsKJ/MqTZNyIh9Vu3v8="
        );
    }

    #[test]
    fn kek_derivation_test() {
        let password = SecretString::from(String::from("this is a test password"));
        let salt_string = SaltString::encode_b64(b"examplesalt").unwrap();
        let params = Params::new(6, 8, 1, SUBKEY_LEN).unwrap();
        let kek = derive_kek(password, params, salt_string.as_salt()).unwrap();
        let wrapped_data = kek.wrap_vec(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();

        assert_eq!(
            Base64::encode_string(&wrapped_data),
            "3km5Iw076jsx8sdzMv+QmA=="
        );
    }

    #[test]
    fn hmac_test() {
        let key = MasterKey::from_bytes([15_u8; SUBKEY_LEN * 2]);
        assert_eq!(
            Base64::encode_string(&hmac(&key, b"here is some data").into_bytes()),
            "CWTyTEOJ2pDGgMpGjHgQV8T+EjEJYliXRQL2XzgT1W0="
        );
    }
}
