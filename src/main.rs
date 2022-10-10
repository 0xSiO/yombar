use anyhow::Result;

mod master_key;
pub mod util;
mod vault;
mod wrapped_key;

pub use self::{
    master_key::MasterKey,
    vault::{CipherCombo, Config, Vault},
    wrapped_key::WrappedKey,
};

fn main() -> Result<()> {
    Ok(())
}
