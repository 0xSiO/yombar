use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use scrypt::{
    password_hash::{rand_core::OsRng, SaltString},
    Params,
};

mod config;
mod key;

use crate::util;

pub use self::config::*;
pub use self::key::*;

pub struct Vault {
    config: Config,
    master_key: KeyInfo,
}

impl Vault {
    pub fn derive_master_key(password: String) -> Result<KeyInfo> {
        let mut wrapped_enc_master_key = [0_u8; 40];
        let mut wrapped_mac_master_key = [0_u8; 40];
        let params = Params::recommended();
        let salt_string = SaltString::generate(OsRng);
        let key_encryption_key = util::derive_kek(password, params, salt_string.as_salt())?;

        key_encryption_key
            .wrap(
                MasterKey::<32>::new()?.as_ref(),
                &mut wrapped_enc_master_key,
            )
            .context("failed to wrap encryption master key")?;

        key_encryption_key
            .wrap(
                MasterKey::<32>::new()?.as_ref(),
                &mut wrapped_mac_master_key,
            )
            .context("failed to wrap MAC master key")?;

        Ok(KeyInfo {
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
}
