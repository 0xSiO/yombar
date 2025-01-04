use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use color_eyre::{
    eyre::{bail, Context, OptionExt},
    Section,
};
use jsonwebtoken::{Algorithm, Header, TokenData, Validation};
use scrypt::{password_hash::SaltString, Params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    crypto::{siv_ctrmac, siv_gcm, Cryptor},
    fs::{EncryptedFile, EncryptedFileSystem},
    key::{MasterKey, WrappedKey},
    util, Result,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherCombo {
    /// AES-SIV for file name encryption, AES-CTR + HMAC for content encryption.
    #[serde(rename = "SIV_CTRMAC")]
    SivCtrMac,
    /// AES-SIV for file name encryption, AES-GCM for content encryption.
    #[serde(rename = "SIV_GCM")]
    SivGcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfig {
    pub jti: Uuid,
    pub format: u32,
    pub shortening_threshold: u32,
    pub cipher_combo: CipherCombo,
}

#[derive(Debug)]
pub struct Vault {
    path: PathBuf,
    config: TokenData<VaultConfig>,
    master_key: MasterKey,
}

impl Vault {
    // TODO: Maybe make creation options more configurable
    pub fn create(path: impl AsRef<Path>, password: String) -> Result<Self> {
        let params = Params::recommended();
        let salt_string = SaltString::generate(rand::thread_rng());
        let kek = util::derive_kek(password, params, salt_string.as_salt())?;
        let master_key = MasterKey::new()?;

        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(String::from("masterkeyfile:masterkey.cryptomator"));
        let claims = VaultConfig {
            jti: Uuid::new_v4(),
            format: 8,
            shortening_threshold: 220,
            cipher_combo: CipherCombo::SivGcm,
        };

        let config_jwt = master_key.sign_jwt(header.clone(), claims)?;
        let wrapped_key = master_key.wrap(&kek, params, salt_string, 8)?;

        fs::create_dir_all(path.as_ref())?;
        let path = path.as_ref().canonicalize()?;
        let vault = Self {
            path,
            config: TokenData { header, claims },
            master_key,
        };

        fs::write(vault.path.join("vault.cryptomator"), config_jwt)?;
        fs::write(
            vault.path.join("masterkey.cryptomator"),
            serde_json::to_string(&wrapped_key)?,
        )?;

        let fs = EncryptedFileSystem::new(&vault);
        fs::create_dir_all(fs.root_dir())?;
        EncryptedFile::create_new(vault.cryptor(), fs.root_dir().join("dirid.c9r"))?
            .write_all(b"")?;

        Ok(vault)
    }

    // Unlock procedure is as follows:
    // 1. Decode the config JWT header to get the master key URI
    // 2. Load the wrapped master key and grab the scrypt parameters
    // 3. Derive a KEK with the password and scrypt parameters
    // 4. Use the KEK to unwrap the master key and decode/verify the config JWT
    pub fn open(config_dir: impl AsRef<Path>, password: String) -> Result<Self> {
        let config_dir = config_dir.as_ref().canonicalize()?;
        let jwt = fs::read_to_string(config_dir.join("vault.cryptomator"))?;
        let header = jsonwebtoken::decode_header(&jwt)?;
        let master_key_uri = header.kid.ok_or_eyre("JWT header is missing `kid` claim")?;

        if master_key_uri.starts_with("masterkeyfile:") {
            let key_path = config_dir.join(master_key_uri.split_once("masterkeyfile:").unwrap().1);
            let wrapped_key = WrappedKey::from_file(key_path)?;
            let kek = util::derive_kek(password, wrapped_key.params(), wrapped_key.salt())?;
            let master_key = MasterKey::from_wrapped(&wrapped_key, &kek)
                .context("failed to unwrap master key")
                .suggestion("make sure you're using the correct password")?;

            let mut validation = Validation::new(header.alg);
            validation.validate_exp = false;
            validation.required_spec_claims.clear();

            let config: TokenData<VaultConfig> = master_key.verify_jwt(jwt, validation)?;

            // Only version 8 is supported for now
            match config.claims.format {
                8 => {}
                other => bail!("unsupported vault format: {other}"),
            }

            Ok(Self {
                path: config_dir,
                config,
                master_key,
            })
        } else {
            bail!("unsupported key URI format: {master_key_uri}");
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn config(&self) -> &TokenData<VaultConfig> {
        &self.config
    }

    pub fn cryptor(&self) -> Cryptor {
        match self.config().claims.cipher_combo {
            CipherCombo::SivCtrMac => {
                Cryptor::SivCtrMac(siv_ctrmac::Cryptor::new(&self.master_key))
            }
            CipherCombo::SivGcm => Cryptor::SivGcm(siv_gcm::Cryptor::new(&self.master_key)),
        }
    }
}
