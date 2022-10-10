use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use scrypt::{password_hash::Salt, Params};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WrappedKey {
    pub(crate) version: u32,
    pub(crate) scrypt_salt: String,
    pub(crate) scrypt_cost_param: u32,
    pub(crate) scrypt_block_size: u32,
    pub(crate) primary_master_key: String,
    pub(crate) hmac_master_key: String,
    pub(crate) version_mac: String,
}

impl WrappedKey {
    pub fn salt(&self) -> Result<Salt> {
        Salt::new(&self.scrypt_salt).context("failed to parse scrypt salt")
    }

    // TODO: Construct params from self
    pub fn params(&self) -> Result<Params> {
        Ok(Params::recommended())
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
