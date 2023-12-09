use std::{fs, path::Path};

use jsonwebtoken::{TokenData, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::*, master_key::MasterKey, util, wrapped_key::WrappedKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherCombo {
    /// AES-SIV for file name encryption, AES-CTR + HMAC for content encryption.
    #[serde(rename = "SIV_CTRMAC")]
    SivCtrMac,
    /// AES-SIV for file name encryption, AES-GCM for content encryption.
    #[serde(rename = "SIV_GCM")]
    SivGcm,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfig {
    pub jti: Uuid,
    pub format: u32,
    pub shortening_threshold: u32,
    pub cipher_combo: CipherCombo,
}

#[allow(dead_code)]
pub struct Vault {
    config: TokenData<VaultConfig>,
    master_key: MasterKey,
}

impl Vault {
    // TODO: New vaults require the following:
    // - name
    // - location
    // - password -> master key
    //
    // Optional: generate a recovery key
    //
    // pub fn create() -> Result<Self, VaultCreateError> {}

    // Unlock procedure is as follows:
    // 1. Decode the config JWT header to get the master key URI
    // 2. Load the wrapped master key and grab the scrypt parameters
    // 3. Derive a KEK with the password and scrypt parameters
    // 4. Use the KEK to unwrap the master key and decode/verify the config JWT
    pub fn open(config_path: impl AsRef<Path>, password: String) -> Result<Self, VaultUnlockError> {
        let jwt = fs::read_to_string(&config_path)?;
        let header = jsonwebtoken::decode_header(&jwt)?;
        let master_key_uri = header.kid.ok_or(VaultUnlockError::JwtMissingKeyId)?;

        if master_key_uri.starts_with("masterkeyfile:") {
            // TODO: Handle case with no parent?
            let config_dir = config_path.as_ref().parent().unwrap();
            let key_path = config_dir.join(master_key_uri.split_once("masterkeyfile:").unwrap().1);
            let wrapped_key = WrappedKey::from_file(key_path)?;
            let kek = util::derive_kek(password, wrapped_key.params(), wrapped_key.salt())?;
            let master_key = MasterKey::from_wrapped(&wrapped_key, &kek)?;

            let mut validation = Validation::new(header.alg);
            validation.validate_exp = false;
            validation.required_spec_claims.clear();

            let config: TokenData<VaultConfig> = util::verify_jwt(jwt, validation, &master_key)?;

            // TODO: Only version 8 is supported for now
            match config.claims.format {
                8 => {}
                other => return Err(VaultUnlockError::UnsupportedVaultFormat(other)),
            }

            // TODO: Only SIV+CTR+HMAC combo is supported for now
            match config.claims.cipher_combo {
                CipherCombo::SivCtrMac => {}
                other => return Err(VaultUnlockError::UnsupportedCipherCombo(other)),
            }

            Ok(Self { config, master_key })
        } else {
            Err(VaultUnlockError::UnsupportedKeyUri(master_key_uri))
        }
    }
}
