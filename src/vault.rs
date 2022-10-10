use aes_kw::KekAes256;

use crate::master_key::WrappedKey;

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
    key_info: WrappedKey,
    // TODO: Zero this on drop?
    kek: Option<KekAes256>,
}

impl Vault {}
