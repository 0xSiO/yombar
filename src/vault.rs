use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::{master_key::MasterKey, util, wrapped_key::WrappedKey};

mod config;

pub use self::config::*;

pub struct Vault {
    path: PathBuf,
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

        let kek = util::derive_kek(
            password,
            self.wrapped_key.params()?,
            self.wrapped_key.salt()?,
        )
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
