use aes_kw::{Kek, KekAes256};
use anyhow::{Context, Result};
use scrypt::{
    password_hash::{PasswordHasher, Salt},
    Params, Scrypt,
};
use zeroize::Zeroize;

const KEK_LENGTH: usize = 32;

pub fn derive_kek(mut password: String, params: Params, salt: Salt) -> Result<KekAes256> {
    let password_hash = Scrypt
        .hash_password_customized(password.as_bytes(), None, None, params, salt)
        .context("failed to generate key-encryption key")?;

    password.zeroize();
    debug_assert_eq!(password_hash.hash.unwrap().len(), KEK_LENGTH);

    let mut kek_bytes = [0_u8; KEK_LENGTH];
    kek_bytes.copy_from_slice(password_hash.hash.unwrap().as_bytes());
    Ok(Kek::from(kek_bytes))
}
