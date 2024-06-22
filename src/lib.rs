pub mod crypto;
pub mod error;
pub mod fs;
mod key;
pub mod util;
mod vault;

pub use self::{
    key::{MasterKey, WrappedKey},
    vault::{CipherCombo, Vault, VaultConfig},
};

pub type Result<T> = color_eyre::Result<T>;
