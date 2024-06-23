use std::io::{self, Read};

use aes_kw::{Kek, KekAes256};
use hmac::{Hmac, Mac};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use scrypt::{
    password_hash::{PasswordHasher, Salt},
    Params, Scrypt,
};
use serde::{de::DeserializeOwned, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{
    crypto::{Cryptor, FileCryptor},
    key::SUBKEY_LEN,
    MasterKey, Result,
};

pub fn derive_kek(mut password: String, params: Params, salt: Salt) -> Result<KekAes256> {
    let password_hash =
        Scrypt.hash_password_customized(password.as_bytes(), None, None, params, salt)?;

    password.zeroize();
    debug_assert_eq!(password_hash.hash.unwrap().len(), SUBKEY_LEN);

    let mut kek_bytes = [0_u8; SUBKEY_LEN];
    kek_bytes.copy_from_slice(password_hash.hash.unwrap().as_bytes());
    Ok(Kek::from(kek_bytes))
}

pub fn hmac(data: &[u8], key: &MasterKey) -> Vec<u8> {
    Hmac::<Sha256>::new_from_slice(key.mac_key())
        // Ok to unwrap, HMAC can take keys of any size
        .unwrap()
        .chain_update(data)
        .finalize()
        .into_bytes()
        .to_vec()
}

pub fn sign_jwt(header: Header, claims: impl Serialize, key: &MasterKey) -> Result<String> {
    Ok(jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_secret(key.raw_key()),
    )?)
}

pub fn verify_jwt<T: DeserializeOwned>(
    token: String,
    validation: Validation,
    key: &MasterKey,
) -> Result<TokenData<T>> {
    Ok(jsonwebtoken::decode(
        &token,
        &DecodingKey::from_secret(key.raw_key()),
        &validation,
    )?)
}

/// A modified version of read_exact that ignores an unexpected EOF, returning whether the whole
/// buffer could be filled and the number of bytes read.
pub fn try_read_exact(mut this: impl Read, mut buf: &mut [u8]) -> io::Result<(bool, usize)> {
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

pub fn get_cleartext_size(cryptor: Cryptor<'_>, ciphertext_size: u64) -> u64 {
    let max_enc_chunk_len = cryptor.max_encrypted_chunk_len() as u64;
    let max_chunk_len = cryptor.max_chunk_len() as u64;
    let enc_chunks_len = ciphertext_size - cryptor.encrypted_header_len() as u64;
    let num_full_chunks = enc_chunks_len / max_enc_chunk_len;
    // Length of last partial cleartext chunk, or zero if there is no partial chunk
    let remainder = (enc_chunks_len % max_enc_chunk_len).max(max_enc_chunk_len - max_chunk_len)
        - (max_enc_chunk_len - max_chunk_len);

    num_full_chunks * max_chunk_len + remainder
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use jsonwebtoken::Algorithm;
    use scrypt::password_hash::SaltString;
    use serde::Deserialize;

    use super::*;

    #[test]
    #[ignore]
    fn password_hash_test() {
        let password = String::from("pleaseletmein");
        let salt_string = SaltString::encode_b64(b"SodiumChloride").unwrap();
        let params = Params::new(14, 8, 1, 64).unwrap();
        let password_hash = Scrypt
            .hash_password_customized(password.as_bytes(), None, None, params, &salt_string)
            .unwrap();

        assert_eq!(
            Base64::encode_string(password_hash.hash.unwrap().as_bytes()),
            "cCO9yzr9c0hGHAbNgf046/2o+7qQT44+qbVD9lRdofLVQylVYT8Pz2LUlwUkKpr55h6F3A1lHkDfzwF7RVdYhw=="
        );
    }

    #[test]
    #[ignore]
    fn kek_derivation_test() {
        let password = String::from("this is a test password");
        let salt_string = SaltString::encode_b64(b"examplesalt").unwrap();
        let params = Params::new(15, 8, 1, SUBKEY_LEN).unwrap();
        let kek = derive_kek(password, params, salt_string.as_salt()).unwrap();
        let wrapped_data = kek.wrap_vec(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();

        assert_eq!(
            Base64::encode_string(&wrapped_data),
            "Rf3TWtT0Rz9WDIMD3+26pA=="
        );
    }

    #[test]
    fn hmac_test() {
        // Safe, this is for test purposes only
        let key = unsafe { MasterKey::from_bytes([15_u8; SUBKEY_LEN * 2]) };
        assert_eq!(
            Base64::encode_string(&hmac(b"here is some data", &key)),
            "CWTyTEOJ2pDGgMpGjHgQV8T+EjEJYliXRQL2XzgT1W0="
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ExampleClaims {
        one: u32,
        two: bool,
        three: String,
    }

    #[test]
    fn sign_and_verify_jwt_test() {
        let key_bytes = [[30; SUBKEY_LEN], [40; SUBKEY_LEN]].concat();
        // Safe, this is for test purposes only
        let key = unsafe { MasterKey::from_bytes(key_bytes.try_into().unwrap()) };

        let header = Header::new(Algorithm::HS256);
        let claims = ExampleClaims {
            one: 10,
            two: false,
            three: String::from("test"),
        };

        let jwt = sign_jwt(header.clone(), claims.clone(), &key).unwrap();
        assert_eq!(
            jwt,
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvbmUiOjEwLCJ0d28iOmZhbHNlLCJ0aHJlZSI6InRlc3QifQ.RAy9PledsRNGbbxzAWdzWu6M-mEsz3RecHJiMM3FyTE"
        );

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        let verified: TokenData<ExampleClaims> = verify_jwt(jwt, validation, &key).unwrap();

        assert_eq!(verified.header, header);
        assert_eq!(verified.claims, claims);
    }
}
