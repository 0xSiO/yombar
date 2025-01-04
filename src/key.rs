use std::{fmt::Debug, fs, path::Path};

use aes_kw::KekAes256;
use base64ct::{Base64, Encoding};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use rand::Rng;
use scrypt::{
    password_hash::{Salt, SaltString},
    Params,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{util, Result};

pub(crate) const SUBKEY_LEN: usize = 32;

#[derive(PartialEq, Eq, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; SUBKEY_LEN * 2]);

impl MasterKey {
    pub fn new() -> Result<Self> {
        let mut key = Self([0_u8; SUBKEY_LEN * 2]);
        rand::thread_rng().try_fill(&mut key.0)?;
        Ok(key)
    }

    /// Create a [`MasterKey`] from the provided byte array. For testing purposes only.
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; SUBKEY_LEN * 2]) -> Self {
        MasterKey(bytes)
    }

    pub(crate) fn enc_key(&self) -> &[u8; SUBKEY_LEN] {
        self.0.first_chunk::<SUBKEY_LEN>().unwrap()
    }

    pub(crate) fn mac_key(&self) -> &[u8; SUBKEY_LEN] {
        self.0.last_chunk::<SUBKEY_LEN>().unwrap()
    }

    pub(crate) fn wrap(
        &self,
        key_encryption_key: &KekAes256,
        scrypt_params: Params,
        scrypt_salt: SaltString,
        format_version: u32,
    ) -> Result<WrappedKey> {
        let mut wrapped_enc_master_key = [0_u8; SUBKEY_LEN + 8];
        let mut wrapped_mac_master_key = [0_u8; SUBKEY_LEN + 8];

        key_encryption_key.wrap(self.enc_key(), &mut wrapped_enc_master_key)?;
        key_encryption_key.wrap(self.mac_key(), &mut wrapped_mac_master_key)?;

        Ok(WrappedKey {
            scrypt_salt,
            scrypt_params,
            enc_key: wrapped_enc_master_key.to_vec(),
            mac_key: wrapped_mac_master_key.to_vec(),
            version_mac: util::hmac(self, &format_version.to_be_bytes()),
        })
    }

    pub(crate) fn from_wrapped(
        wrapped_key: &WrappedKey,
        key_encryption_key: &KekAes256,
    ) -> Result<Self> {
        let mut buffer = [0_u8; SUBKEY_LEN * 2];
        key_encryption_key.unwrap(wrapped_key.enc_key(), &mut buffer[0..SUBKEY_LEN])?;
        key_encryption_key.unwrap(wrapped_key.mac_key(), &mut buffer[SUBKEY_LEN..])?;
        Ok(MasterKey(buffer))
    }

    pub(crate) fn sign_jwt(&self, header: Header, claims: impl Serialize) -> Result<String> {
        Ok(jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_secret(&self.0),
        )?)
    }

    pub(crate) fn verify_jwt<T: DeserializeOwned>(
        &self,
        token: String,
        validation: Validation,
    ) -> Result<TokenData<T>> {
        Ok(jsonwebtoken::decode(
            &token,
            &DecodingKey::from_secret(&self.0),
            &validation,
        )?)
    }
}

impl Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawWrappedKey {
    version: u32,
    scrypt_salt: String,
    scrypt_cost_param: u32,
    scrypt_block_size: u32,
    primary_master_key: String,
    hmac_master_key: String,
    version_mac: String,
}

#[derive(Debug)]
pub(crate) struct WrappedKey {
    pub(crate) scrypt_salt: SaltString,
    pub(crate) scrypt_params: Params,
    pub(crate) enc_key: Vec<u8>,
    pub(crate) mac_key: Vec<u8>,
    pub(crate) version_mac: Vec<u8>,
}

impl WrappedKey {
    pub(crate) fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let json = fs::read_to_string(path)?;
        let raw: RawWrappedKey = serde_json::from_str(&json)?;
        let recommended_params = Params::recommended();
        let salt_no_padding = raw.scrypt_salt.replace('=', "");

        Ok(Self {
            scrypt_salt: SaltString::from_b64(&salt_no_padding)?,
            scrypt_params: Params::new(
                raw.scrypt_cost_param.ilog2() as u8,
                raw.scrypt_block_size,
                recommended_params.p(),
                SUBKEY_LEN,
            )?,
            enc_key: Base64::decode_vec(&raw.primary_master_key)?,
            mac_key: Base64::decode_vec(&raw.hmac_master_key)?,
            version_mac: Base64::decode_vec(&raw.version_mac)?,
        })
    }

    pub(crate) fn salt(&self) -> Salt {
        self.scrypt_salt.as_salt()
    }

    pub(crate) fn params(&self) -> Params {
        self.scrypt_params
    }

    pub(crate) fn enc_key(&self) -> &[u8] {
        &self.enc_key
    }

    pub(crate) fn mac_key(&self) -> &[u8] {
        &self.mac_key
    }

    #[cfg(test)]
    pub(crate) fn version_mac(&self) -> &[u8] {
        &self.version_mac
    }

    fn as_raw(&self) -> RawWrappedKey {
        RawWrappedKey {
            version: 999,
            scrypt_salt: self.scrypt_salt.to_string(),
            // TODO: Use Params::n from https://github.com/RustCrypto/password-hashes/pull/544
            scrypt_cost_param: 2_u32.pow(self.scrypt_params.log_n() as u32),
            scrypt_block_size: self.scrypt_params.r(),
            primary_master_key: Base64::encode_string(&self.enc_key),
            hmac_master_key: Base64::encode_string(&self.mac_key),
            version_mac: Base64::encode_string(&self.version_mac),
        }
    }
}

impl Serialize for WrappedKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_raw().serialize(serializer)
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
    fn wrap_and_unwrap_test() {
        let key_bytes = [[10; SUBKEY_LEN], [20; SUBKEY_LEN]].concat();
        let key = MasterKey(key_bytes.try_into().unwrap());
        let password = String::from("this is a test password");
        let params = Params::new(4, 8, 1, SUBKEY_LEN).unwrap();
        let salt_string = SaltString::encode_b64(b"test salt").unwrap();
        let kek = util::derive_kek(password, params, salt_string.as_salt()).unwrap();
        let wrapped_key = key.wrap(&kek, params, salt_string.clone(), 8).unwrap();

        assert_eq!(wrapped_key.scrypt_salt, salt_string);
        assert_eq!(wrapped_key.scrypt_params.log_n(), params.log_n());
        assert_eq!(wrapped_key.scrypt_params.r(), params.r());
        assert_eq!(wrapped_key.scrypt_params.p(), params.p());
        assert_eq!(
            Base64::encode_string(wrapped_key.enc_key()),
            "hVcTLMybIXICR26f5zpegiH/OpXnNv4lvytd6tATj87Di4lPhD5t0Q=="
        );
        assert_eq!(
            Base64::encode_string(wrapped_key.mac_key()),
            "LiBoVDJthshFhm1Q+T3de2Ynpfb5Yx63KrRyjqSGBNp3gyFznhjnNQ=="
        );
        assert_eq!(
            Base64::encode_string(wrapped_key.version_mac()),
            "P7wUK1BElZEaHemyhC7j4WWdxOrwb6d+5SSdjVAICmA="
        );

        assert_eq!(MasterKey::from_wrapped(&wrapped_key, &kek).unwrap(), key);
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
