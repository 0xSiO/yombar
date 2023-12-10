use std::{fs, path::Path};

use aes_kw::KekAes256;
use base64ct::{Base64, Encoding};
use rand_core::{self, OsRng, RngCore};
use scrypt::{
    password_hash::{Salt, SaltString},
    Params,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{error::*, util};

pub const SUBKEY_LEN: usize = 32;

#[derive(Debug, PartialEq, Eq, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; SUBKEY_LEN * 2]);

impl MasterKey {
    pub fn new() -> Result<Self, rand_core::Error> {
        let mut key = Self([0_u8; SUBKEY_LEN * 2]);
        OsRng.try_fill_bytes(&mut key.0)?;
        Ok(key)
    }

    /// Create a [`MasterKey`] from the provided byte array.
    ///
    /// # Safety
    ///
    /// - `bytes` should contain secret, random bytes with sufficient entropy
    pub unsafe fn from_bytes(bytes: [u8; SUBKEY_LEN * 2]) -> Self {
        MasterKey(bytes)
    }

    pub(crate) fn enc_key(&self) -> &[u8; SUBKEY_LEN] {
        self.0[0..SUBKEY_LEN].try_into().unwrap()
    }

    pub(crate) fn mac_key(&self) -> &[u8; SUBKEY_LEN] {
        self.0[SUBKEY_LEN..].try_into().unwrap()
    }

    pub(crate) fn raw_key(&self) -> &[u8; SUBKEY_LEN * 2] {
        &self.0
    }

    pub fn wrap(
        &self,
        key_encryption_key: &KekAes256,
        scrypt_params: Params,
        scrypt_salt: SaltString,
        format_version: u32,
    ) -> Result<WrappedKey, aes_kw::Error> {
        let mut wrapped_enc_master_key = [0_u8; SUBKEY_LEN + 8];
        let mut wrapped_mac_master_key = [0_u8; SUBKEY_LEN + 8];

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
        let mut buffer = [0_u8; SUBKEY_LEN * 2];
        key_encryption_key.unwrap(wrapped_key.enc_key(), &mut buffer[0..SUBKEY_LEN])?;
        key_encryption_key.unwrap(wrapped_key.mac_key(), &mut buffer[SUBKEY_LEN..])?;
        Ok(MasterKey(buffer))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawWrappedKey {
    version: u32,
    scrypt_salt: String,
    scrypt_cost_param: u32,
    scrypt_block_size: u32,
    primary_master_key: String,
    hmac_master_key: String,
    version_mac: String,
}

#[derive(Debug)]
pub struct WrappedKey {
    pub(crate) scrypt_salt: SaltString,
    pub(crate) scrypt_params: Params,
    pub(crate) enc_key: Vec<u8>,
    pub(crate) mac_key: Vec<u8>,
    pub(crate) version_mac: Vec<u8>,
}

impl WrappedKey {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, KeyFromFileError> {
        let json = fs::read_to_string(path)?;
        let raw: RawWrappedKey = serde_json::from_str(&json)?;
        let recommended_params = Params::recommended();
        let salt_no_padding = raw.scrypt_salt.replace('=', "");

        Ok(Self {
            scrypt_salt: SaltString::from_b64(&salt_no_padding)?,
            scrypt_params: Params::new(
                raw.scrypt_cost_param.ilog2() as u8,
                raw.scrypt_block_size,
                recommended_params.p(),
                SUBKEY_LEN,
            )?,
            enc_key: Base64::decode_vec(&raw.primary_master_key)?,
            mac_key: Base64::decode_vec(&raw.hmac_master_key)?,
            version_mac: Base64::decode_vec(&raw.version_mac)?,
        })
    }

    pub fn salt(&self) -> Salt {
        self.scrypt_salt.as_salt()
    }

    pub fn params(&self) -> Params {
        self.scrypt_params
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.enc_key
    }

    pub fn mac_key(&self) -> &[u8] {
        &self.mac_key
    }

    pub fn version_mac(&self) -> &[u8] {
        &self.version_mac
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
        let key_bytes = [[10; SUBKEY_LEN], [20; SUBKEY_LEN]].concat();
        let key = MasterKey(key_bytes.try_into().unwrap());
        let password = String::from("this is a test password");
        let params = Params::new(15, 8, 1, SUBKEY_LEN).unwrap();
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
