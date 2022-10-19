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

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};
    use scrypt::password_hash::SaltString;

    use super::*;

    #[test]
    fn kek_derivation_test() {
        let password = String::from("this is a test password");
        let salt_string = SaltString::new("W3huAdpTVi9F+VAdJEKG2g").unwrap();
        let kek = derive_kek(password, Params::recommended(), salt_string.as_salt()).unwrap();
        let wrapped_data = kek.wrap_vec(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();

        assert_eq!(
            Base64::encode_string(&wrapped_data),
            "LcAc5FUpnDrComkVESnE8g=="
        );
    }
}
