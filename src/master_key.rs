use aes_kw::KekAes256;
use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use scrypt::{
    password_hash::{
        rand_core::{OsRng, RngCore},
        SaltString,
    },
    Params,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::util;

pub const SUBKEY_LENGTH: usize = 32;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedKeyInfo {
    pub version: u16,
    pub scrypt_salt: String,
    pub scrypt_cost_param: usize,
    pub scrypt_block_size: u32,
    pub primary_master_key: String,
    pub hmac_master_key: String,
    pub version_mac: String,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; 64]);

impl MasterKey {
    pub fn new_raw() -> Result<Self> {
        let mut key = Self([0_u8; SUBKEY_LENGTH * 2]);
        OsRng
            .try_fill_bytes(&mut key.0)
            .context("failed to generate random bytes")?;
        Ok(key)
    }

    pub fn new_wrapped(password: String, _version: u16) -> Result<WrappedKeyInfo> {
        let mut wrapped_enc_master_key = [0_u8; SUBKEY_LENGTH + 8];
        let mut wrapped_mac_master_key = [0_u8; SUBKEY_LENGTH + 8];
        let params = Params::recommended();
        let salt_string = SaltString::generate(OsRng);
        let key_encryption_key = util::derive_kek(password, params, salt_string.as_salt())
            .context("failed to derive key-encryption-key")?;
        let master_key = Self::new_raw().context("failed to generate master key")?;

        key_encryption_key
            .wrap(&master_key.0[0..SUBKEY_LENGTH], &mut wrapped_enc_master_key)
            .context("failed to wrap encryption master key")?;
        key_encryption_key
            .wrap(&master_key.0[SUBKEY_LENGTH..], &mut wrapped_mac_master_key)
            .context("failed to wrap MAC master key")?;

        Ok(WrappedKeyInfo {
            version: 999,
            scrypt_salt: salt_string.to_string(),
            scrypt_cost_param: 2_usize.pow(params.log_n() as u32),
            scrypt_block_size: params.r(),
            primary_master_key: Base64::encode_string(&wrapped_enc_master_key),
            hmac_master_key: Base64::encode_string(&wrapped_mac_master_key),
            // TODO: HMAC of vault format version
            version_mac: String::new(),
        })
    }

    pub fn from_wrapped(wrapped_key_info: &WrappedKeyInfo, kek: KekAes256) -> Result<Self> {
        let mut key = Self([0_u8; SUBKEY_LENGTH * 2]);

        let wrapped_enc_key = Base64::decode_vec(&wrapped_key_info.primary_master_key)
            .context("failed to decode wrapped encryption key")?;
        let wrapped_mac_key = Base64::decode_vec(&wrapped_key_info.hmac_master_key)
            .context("failed to decode wrapped MAC key")?;
        kek.unwrap(&wrapped_enc_key, &mut key.0[0..SUBKEY_LENGTH])
            .context("failed to unwrap encryption master key")?;
        kek.unwrap(&wrapped_mac_key, &mut key.0[SUBKEY_LENGTH..])
            .context("failed to unwrap MAC master key")?;

        Ok(key)
    }

    pub fn sign_jwt(&self, header: Header, claims: impl Serialize) -> Result<String> {
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(&self.0))
            .context("failed to sign JWT")
    }

    pub fn verify_jwt<T: DeserializeOwned>(
        &self,
        token: String,
        validation: Validation,
    ) -> Result<TokenData<T>> {
        jsonwebtoken::decode(&token, &DecodingKey::from_secret(&self.0), &validation)
            .context("failed to verify JWT")
    }
}
