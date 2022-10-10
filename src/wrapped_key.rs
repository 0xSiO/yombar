use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use scrypt::{password_hash::Salt, Params};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedKey {
    pub version: u16,
    pub scrypt_salt: String,
    pub scrypt_cost_param: usize,
    pub scrypt_block_size: u32,
    pub primary_master_key: String,
    pub hmac_master_key: String,
    pub version_mac: String,
}

impl WrappedKey {
    pub fn salt(&self) -> Result<Salt> {
        Salt::new(&self.scrypt_salt).context("failed to parse scrypt salt")
    }

    pub fn params(&self) -> Params {
        todo!()
    }

    pub fn enc_key(&self) -> Result<Vec<u8>> {
        Base64::decode_vec(&self.primary_master_key)
            .context("failed to decode wrapped encryption key")
    }

    pub fn mac_key(&self) -> Result<Vec<u8>> {
        Base64::decode_vec(&self.hmac_master_key).context("failed to decode wrapped MAC key")
    }

    pub fn version_mac(&self) -> Result<Vec<u8>> {
        Base64::decode_vec(&self.version_mac).context("failed to decode format version MAC")
    }
}
