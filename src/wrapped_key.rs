use std::{fs, path::Path};

use base64ct::{Base64, Encoding};
use scrypt::{
    password_hash::{Salt, SaltString},
    Params,
};
use serde::{Deserialize, Serialize};

use crate::error::*;

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
pub struct WrappedKey {
    pub(crate) scrypt_salt: SaltString,
    pub(crate) scrypt_params: Params,
    pub(crate) enc_key: Vec<u8>,
    pub(crate) mac_key: Vec<u8>,
    pub(crate) version_mac: Vec<u8>,
}

impl WrappedKey {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, KeyFromFileError> {
        let json = fs::read_to_string(path)?;
        let raw: RawWrappedKey = serde_json::from_str(&json)?;
        let recommended_params = Params::recommended();
        let salt_no_padding = raw.scrypt_salt.replace('=', "");

        Ok(Self {
            scrypt_salt: SaltString::new(&salt_no_padding)?,
            scrypt_params: Params::new(
                // TODO: Use integer log once that's stabilized
                (raw.scrypt_cost_param as f64).log2() as u8,
                raw.scrypt_block_size,
                recommended_params.p(),
            )?,
            enc_key: Base64::decode_vec(&raw.primary_master_key)?,
            mac_key: Base64::decode_vec(&raw.hmac_master_key)?,
            version_mac: Base64::decode_vec(&raw.version_mac)?,
        })
    }

    pub fn salt(&self) -> Salt {
        self.scrypt_salt.as_salt()
    }

    pub fn params(&self) -> Params {
        self.scrypt_params
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.enc_key
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.mac_key
    }

    pub fn version_mac(&self) -> &[u8] {
        &self.version_mac
    }
}
