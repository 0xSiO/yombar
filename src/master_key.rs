use aes_kw::KekAes256;
use rand_core::{self, OsRng, RngCore};
use scrypt::{password_hash::SaltString, Params};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{util, wrapped_key::WrappedKey};

pub const SUBKEY_LENGTH: usize = 32;

#[derive(Debug, PartialEq, Eq, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; SUBKEY_LENGTH * 2]);

impl MasterKey {
    pub fn new() -> Result<Self, rand_core::Error> {
        let mut key = Self([0_u8; SUBKEY_LENGTH * 2]);
        OsRng.try_fill_bytes(&mut key.0)?;
        Ok(key)
    }

    /// Create a [MasterKey] from the provided byte array.
    ///
    /// # Safety
    ///
    /// - `bytes` should contain secret, random bytes with sufficient entropy
    pub unsafe fn from_bytes(bytes: [u8; SUBKEY_LENGTH * 2]) -> Self {
        MasterKey(bytes)
    }

    pub(crate) fn enc_key(&self) -> &[u8] {
        &self.0[0..SUBKEY_LENGTH]
    }

    pub(crate) fn mac_key(&self) -> &[u8] {
        &self.0[SUBKEY_LENGTH..]
    }

    pub(crate) fn raw_key(&self) -> &[u8] {
        &self.0
    }

    pub fn wrap(
        &self,
        key_encryption_key: &KekAes256,
        scrypt_params: Params,
        scrypt_salt: SaltString,
        format_version: u32,
    ) -> Result<WrappedKey, aes_kw::Error> {
        let mut wrapped_enc_master_key = [0_u8; SUBKEY_LENGTH + 8];
        let mut wrapped_mac_master_key = [0_u8; SUBKEY_LENGTH + 8];

        key_encryption_key.wrap(self.enc_key(), &mut wrapped_enc_master_key)?;
        key_encryption_key.wrap(self.mac_key(), &mut wrapped_mac_master_key)?;

        Ok(WrappedKey {
            scrypt_salt,
            scrypt_params,
            enc_key: wrapped_enc_master_key.to_vec(),
            mac_key: wrapped_mac_master_key.to_vec(),
            version_mac: util::hmac(&format_version.to_be_bytes(), self),
        })
    }

    pub fn from_wrapped(
        wrapped_key: &WrappedKey,
        key_encryption_key: &KekAes256,
    ) -> Result<Self, aes_kw::Error> {
        let mut buffer = [0_u8; SUBKEY_LENGTH * 2];
        key_encryption_key.unwrap(wrapped_key.enc_key(), &mut buffer[0..SUBKEY_LENGTH])?;
        key_encryption_key.unwrap(wrapped_key.mac_key(), &mut buffer[SUBKEY_LENGTH..])?;
        Ok(MasterKey(buffer))
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding};

    use crate::util;

    use super::*;

    #[test]
    #[ignore]
    fn wrap_and_unwrap_test() {
        let key_bytes = [[10; SUBKEY_LENGTH], [20; SUBKEY_LENGTH]].concat();
        let key = MasterKey(key_bytes.try_into().unwrap());
        let password = String::from("this is a test password");
        let params = Params::new(15, 8, 1, SUBKEY_LENGTH).unwrap();
        let salt_string = SaltString::encode_b64(b"test salt").unwrap();
        let kek = util::derive_kek(password, params, salt_string.as_salt()).unwrap();
        let wrapped_key = key.wrap(&kek, params, salt_string.clone(), 8).unwrap();

        assert_eq!(wrapped_key.scrypt_salt, salt_string);
        assert_eq!(wrapped_key.scrypt_params.log_n(), params.log_n());
        assert_eq!(wrapped_key.scrypt_params.r(), params.r());
        assert_eq!(wrapped_key.scrypt_params.p(), params.p());
        assert_eq!(
            Base64::encode_string(wrapped_key.enc_key()),
            "1bCocbTJN6z7IgHSW0ooxg5sgiN11sILWVnEMxcE8ZN6DHPQplCDhA=="
        );
        assert_eq!(
            Base64::encode_string(wrapped_key.mac_key()),
            "Cn4g11WzO5BG3bQ6aZ+JLrYpLNY49FfAec088PfNCcAB5weaAdrJ7g=="
        );
        assert_eq!(
            Base64::encode_string(wrapped_key.version_mac()),
            "P7wUK1BElZEaHemyhC7j4WWdxOrwb6d+5SSdjVAICmA="
        );

        assert_eq!(MasterKey::from_wrapped(&wrapped_key, &kek).unwrap(), key);
    }
}
