use aes_kw::KekAes256;
use hmac::{Hmac, Mac};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use scrypt::{
    password_hash::{
        rand_core::{self, OsRng, RngCore},
        SaltString,
    },
    Params,
};
use serde::{de::DeserializeOwned, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::wrapped_key::WrappedKey;

pub const SUBKEY_LENGTH: usize = 32;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey(pub(crate) [u8; SUBKEY_LENGTH * 2]);

impl MasterKey {
    pub fn new() -> Result<Self, rand_core::Error> {
        let mut key = Self([0_u8; SUBKEY_LENGTH * 2]);
        OsRng.try_fill_bytes(&mut key.0)?;
        Ok(key)
    }

    fn enc_key(&self) -> &[u8] {
        &self.0[0..SUBKEY_LENGTH]
    }

    fn mac_key(&self) -> &[u8] {
        &self.0[SUBKEY_LENGTH..]
    }

    // TODO: Should we make this take &self?
    pub fn wrap(
        self,
        key_encryption_key: KekAes256,
        format_version: u32,
    ) -> Result<WrappedKey, aes_kw::Error> {
        let mut wrapped_enc_master_key = [0_u8; SUBKEY_LENGTH + 8];
        let mut wrapped_mac_master_key = [0_u8; SUBKEY_LENGTH + 8];
        let params = Params::recommended();
        let salt_string = SaltString::generate(OsRng);

        key_encryption_key.wrap(self.enc_key(), &mut wrapped_enc_master_key)?;
        key_encryption_key.wrap(self.mac_key(), &mut wrapped_mac_master_key)?;

        let version_mac = Hmac::<sha2::Sha256>::new_from_slice(self.mac_key())
            // Ok to unwrap, HMAC can take keys of any size
            .unwrap()
            .chain_update(format_version.to_be_bytes())
            .finalize()
            .into_bytes();

        Ok(WrappedKey {
            scrypt_salt: salt_string,
            scrypt_params: params,
            enc_key: wrapped_enc_master_key.to_vec(),
            mac_key: wrapped_mac_master_key.to_vec(),
            version_mac: version_mac.to_vec(),
        })
    }

    pub fn unwrap(
        wrapped_key: &WrappedKey,
        key_encryption_key: KekAes256,
    ) -> Result<Self, aes_kw::Error> {
        let mut buffer = [0_u8; SUBKEY_LENGTH * 2];
        key_encryption_key.unwrap(wrapped_key.enc_key(), &mut buffer[0..SUBKEY_LENGTH])?;
        key_encryption_key.unwrap(wrapped_key.mac_key(), &mut buffer[SUBKEY_LENGTH..])?;
        Ok(MasterKey(buffer))
    }

    pub fn sign_jwt(
        &self,
        header: Header,
        claims: impl Serialize,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(&self.0))
    }

    pub fn verify_jwt<T: DeserializeOwned>(
        &self,
        token: String,
        validation: Validation,
    ) -> Result<TokenData<T>, jsonwebtoken::errors::Error> {
        jsonwebtoken::decode(&token, &DecodingKey::from_secret(&self.0), &validation)
    }
}
