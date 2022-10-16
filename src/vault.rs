use std::path::PathBuf;

use zeroize::Zeroize;

use crate::{error::*, master_key::MasterKey, util, wrapped_key::WrappedKey};

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

    pub fn unlock(&mut self, mut password: String) -> Result<(), VaultUnlockError> {
        if !self.is_locked() {
            password.zeroize();
            return Ok(());
        }

        let kek = util::derive_kek(
            password,
            self.wrapped_key.params(),
            self.wrapped_key.salt()?,
        )?;

        self.master_key
            .replace(MasterKey::from_wrapped(&self.wrapped_key, kek)?);

        Ok(())
    }

    pub fn lock(&mut self) {
        let _ = self.master_key.take();
    }
}
