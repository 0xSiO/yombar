use aes_kw::KekAes256;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use rand_core::{self, OsRng, RngCore};
use scrypt::{password_hash::SaltString, Params};
use serde::{de::DeserializeOwned, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{util, wrapped_key::WrappedKey};

pub const SUBKEY_LENGTH: usize = 32;

#[derive(Debug, PartialEq, Eq, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; SUBKEY_LENGTH * 2]);

impl MasterKey {
    pub fn new() -> Result<Self, rand_core::Error> {
        let mut key = Self([0_u8; SUBKEY_LENGTH * 2]);
        OsRng.try_fill_bytes(&mut key.0)?;
        Ok(key)
    }

    /// Create a [MasterKey] from the provided byte array.
    ///
    /// # Safety
    ///
    /// - `bytes` should contain secret, random bytes with sufficient entropy
    pub unsafe fn from_bytes(bytes: [u8; SUBKEY_LENGTH * 2]) -> Self {
        MasterKey(bytes)
    }

    pub(crate) fn enc_key(&self) -> &[u8] {
        &self.0[0..SUBKEY_LENGTH]
    }

    pub(crate) fn mac_key(&self) -> &[u8] {
        &self.0[SUBKEY_LENGTH..]
    }

    pub fn wrap(
        &self,
        key_encryption_key: &KekAes256,
        scrypt_params: Params,
        scrypt_salt: SaltString,
        format_version: u32,
    ) -> Result<WrappedKey, aes_kw::Error> {
        let mut wrapped_enc_master_key = [0_u8; SUBKEY_LENGTH + 8];
        let mut wrapped_mac_master_key = [0_u8; SUBKEY_LENGTH + 8];

        key_encryption_key.wrap(self.enc_key(), &mut wrapped_enc_master_key)?;
        key_encryption_key.wrap(self.mac_key(), &mut wrapped_mac_master_key)?;

        Ok(WrappedKey {
            scrypt_salt,
            scrypt_params,
            enc_key: wrapped_enc_master_key.to_vec(),
            mac_key: wrapped_mac_master_key.to_vec(),
            version_mac: util::hmac(&format_version.to_be_bytes(), self),
        })
    }

    pub fn unwrap(
        wrapped_key: &WrappedKey,
        key_encryption_key: &KekAes256,
    ) -> Result<Self, aes_kw::Error> {
        let mut buffer = [0_u8; SUBKEY_LENGTH * 2];
        key_encryption_key.unwrap(wrapped_key.enc_key(), &mut buffer[0..SUBKEY_LENGTH])?;
        key_encryption_key.unwrap(wrapped_key.mac_key(), &mut buffer[SUBKEY_LENGTH..])?;
        Ok(MasterKey(buffer))
    }

    pub fn sign_jwt(
        &self,
        header: Header,
        claims: impl Serialize,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(&self.0))
    }

    pub fn verify_jwt<T: DeserializeOwned>(
        &self,
        token: String,
        validation: Validation,
    ) -> Result<TokenData<T>, jsonwebtoken::errors::Error> {
        jsonwebtoken::decode(&token, &DecodingKey::from_secret(&self.0), &validation)
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use jsonwebtoken::Algorithm;
    use serde::Deserialize;

    use crate::util;

    use super::*;

    #[test]
    #[ignore]
    fn wrap_and_unwrap_test() {
        let key_bytes = [[10; SUBKEY_LENGTH], [20; SUBKEY_LENGTH]].concat();
        let key = MasterKey(key_bytes.try_into().unwrap());
        let password = String::from("this is a test password");
        let params = Params::recommended();
        let salt_string = SaltString::new("lDDHfk5Y+elVtPi5STJrKw").unwrap();
        let kek = util::derive_kek(password, params, salt_string.as_salt()).unwrap();
        let wrapped_key = key.wrap(&kek, params, salt_string.clone(), 8).unwrap();

        assert_eq!(wrapped_key.scrypt_salt, salt_string);
        assert_eq!(wrapped_key.scrypt_params.log_n(), params.log_n());
        assert_eq!(wrapped_key.scrypt_params.r(), params.r());
        assert_eq!(wrapped_key.scrypt_params.p(), params.p());
        assert_eq!(
            Base64::encode_string(wrapped_key.enc_key()),
            "SIUVZV/5Zq/o3M6o7TKVtUBBCnNS1gBw9vlEQxBzELT4JbjRNXHS2Q=="
        );
        assert_eq!(
            Base64::encode_string(wrapped_key.mac_key()),
            "QodpBW0JpLl9+oJHsRyz9+KGCerxetc9ddKkpI3efveRVZS85uMKRg=="
        );
        assert_eq!(
            Base64::encode_string(wrapped_key.version_mac()),
            "P7wUK1BElZEaHemyhC7j4WWdxOrwb6d+5SSdjVAICmA="
        );

        assert_eq!(MasterKey::unwrap(&wrapped_key, &kek).unwrap(), key);
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ExampleClaims {
        one: u32,
        two: bool,
        three: String,
    }

    #[test]
    fn sign_and_verify_jwt_test() {
        let key_bytes = [[30; SUBKEY_LENGTH], [40; SUBKEY_LENGTH]].concat();
        let key = MasterKey(key_bytes.try_into().unwrap());

        let header = Header::new(Algorithm::HS256);
        let claims = ExampleClaims {
            one: 10,
            two: false,
            three: String::from("test"),
        };

        let jwt = key.sign_jwt(header.clone(), claims.clone()).unwrap();
        assert_eq!(
            jwt,
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJvbmUiOjEwLCJ0d28iOmZhbHNlLCJ0aHJlZSI6InRlc3QifQ.RAy9PledsRNGbbxzAWdzWu6M-mEsz3RecHJiMM3FyTE"
        );

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        let verified: TokenData<ExampleClaims> = key.verify_jwt(jwt, validation).unwrap();

        assert_eq!(verified.header, header);
        assert_eq!(verified.claims, claims);
    }
}
