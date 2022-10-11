use aes_kw::{Kek, KekAes256};
use scrypt::{
    password_hash::{PasswordHasher, Salt},
    Params, Scrypt,
};
use zeroize::Zeroize;

use crate::{error::*, master_key::SUBKEY_LENGTH};

pub fn derive_kek(
    mut password: String,
    params: Params,
    salt: Salt,
) -> Result<KekAes256, KekDerivationError> {
    let password_hash =
        Scrypt.hash_password_customized(password.as_bytes(), None, None, params, salt)?;

    password.zeroize();
    debug_assert_eq!(password_hash.hash.unwrap().len(), SUBKEY_LENGTH);

    let mut kek_bytes = [0_u8; SUBKEY_LENGTH];
    kek_bytes.copy_from_slice(password_hash.hash.unwrap().as_bytes());
    Ok(Kek::from(kek_bytes))
}
