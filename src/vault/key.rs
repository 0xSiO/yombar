use anyhow::{Context, Result};
use scrypt::password_hash::rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyInfo {
    pub version: u16,
    pub scrypt_salt: String,
    pub scrypt_cost_param: usize,
    pub scrypt_block_size: u32,
    pub primary_master_key: String,
    pub hmac_master_key: String,
    pub version_mac: String,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey<const N: usize>([u8; N]);

impl<const N: usize> MasterKey<N> {
    pub fn new() -> Result<Self> {
        let mut key = Self([0_u8; N]);
        OsRng
            .try_fill_bytes(&mut key.0)
            .context("failed to generate random bytes")?;
        Ok(key)
    }
}

impl<const N: usize> AsRef<[u8]> for MasterKey<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
