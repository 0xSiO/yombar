use aes_kw::Kek;
use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use scrypt::{
    password_hash::{
        rand_core::{OsRng, RngCore},
        PasswordHasher, SaltString,
    },
    Params, Scrypt,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MasterKeyInfo {
    pub version: u16,
    pub scrypt_salt: String,
    pub scrypt_cost_param: usize,
    pub scrypt_block_size: u32,
    pub primary_master_key: String,
    pub hmac_master_key: String,
    pub version_mac: String,
}

pub fn derive_master_key(password: &[u8]) -> Result<MasterKeyInfo> {
    let mut enc_master_key = [0_u8; 32];
    let mut mac_master_key = [0_u8; 32];

    OsRng
        .try_fill_bytes(&mut enc_master_key)
        .context("failed to generate random bytes")?;
    OsRng
        .try_fill_bytes(&mut mac_master_key)
        .context("failed to generate random bytes")?;

    let params = Params::recommended();
    let salt = SaltString::generate(OsRng);
    let key_encryption_key = Scrypt
        .hash_password_customized(password, None, None, params, &salt)
        .context("failed to generate key-encryption key")?;

    debug_assert_eq!(key_encryption_key.hash.unwrap().len(), 32);

    let mut kek_bytes = [0u8; 32];
    kek_bytes.copy_from_slice(key_encryption_key.hash.unwrap().as_bytes());
    let kek = Kek::from(kek_bytes);

    let mut wrapped_enc_master_key = [0_u8; 40];
    let mut wrapped_mac_master_key = [0_u8; 40];

    kek.wrap(&enc_master_key, &mut wrapped_enc_master_key)
        .context("failed to wrap encryption master key")?;
    kek.wrap(&mac_master_key, &mut wrapped_mac_master_key)
        .context("failed to wrap encryption master key")?;

    Ok(MasterKeyInfo {
        version: 999,
        scrypt_salt: salt.to_string(),
        scrypt_cost_param: 2_usize.pow(params.log_n() as u32),
        scrypt_block_size: params.r(),
        primary_master_key: Base64::encode_string(&wrapped_enc_master_key),
        hmac_master_key: Base64::encode_string(&wrapped_mac_master_key),
        // TODO: HMAC of vault format version
        version_mac: String::new(),
    })
}
