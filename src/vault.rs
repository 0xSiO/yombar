use anyhow::{Context, Result};
use scrypt::{password_hash::SaltString, Params};

use crate::{
    master_key::{MasterKey, WrappedKey},
    util,
};

mod config;

pub use self::config::*;

// Vaults have a vault config and a set of encrypted keys.
//
// Opening a vault requires a password, the vault config, and the encrypted keys.
//
// The encrypted keys are decrypted by generating a KEK using the password and the encrypted key
// parameters.
pub struct Vault {
    config: Config,
    wrapped_key: WrappedKey,
    master_key: Option<MasterKey>,
}

impl Vault {
    pub fn is_locked(&self) -> bool {
        self.master_key.is_none()
    }

    pub fn unlock(&mut self, password: String) -> Result<()> {
        if !self.is_locked() {
            return Ok(());
        }

        // TODO: Use params from self.wrapped_key
        let params = Params::recommended();
        let salt = SaltString::new(&self.wrapped_key.scrypt_salt)
            .context("failed to parse scrypt salt")?;
        let kek = util::derive_kek(password, params, salt.as_salt())
            .context("failed to derive key-encryption key")?;
        let master_key = MasterKey::from_wrapped(&self.wrapped_key, kek)
            .context("failed to decrypt master key")?;

        self.master_key.replace(master_key);

        Ok(())
    }

    pub fn lock(&mut self) {
        let _ = self.master_key.take();
    }
}
