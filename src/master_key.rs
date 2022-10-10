use aes_kw::KekAes256;
use anyhow::{Context, Result};
use base64ct::{Base64, Encoding};
use hmac::{Hmac, Mac};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation};
use scrypt::{
    password_hash::{
        rand_core::{OsRng, RngCore},
        SaltString,
    },
    Params,
};
use serde::{de::DeserializeOwned, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{util, wrapped_key::WrappedKey};

pub const SUBKEY_LENGTH: usize = 32;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; SUBKEY_LENGTH * 2]);

impl MasterKey {
    pub fn new_raw() -> Result<Self> {
        let mut key = Self([0_u8; SUBKEY_LENGTH * 2]);
        OsRng
            .try_fill_bytes(&mut key.0)
            .context("failed to generate random bytes")?;
        Ok(key)
    }

    fn enc_key(&self) -> &[u8] {
        &self.0[0..SUBKEY_LENGTH]
    }

    fn mac_key(&self) -> &[u8] {
        &self.0[SUBKEY_LENGTH..]
    }

    pub fn new_wrapped(password: String, version: u32) -> Result<WrappedKey> {
        let mut wrapped_enc_master_key = [0_u8; SUBKEY_LENGTH + 8];
        let mut wrapped_mac_master_key = [0_u8; SUBKEY_LENGTH + 8];
        let params = Params::recommended();
        let salt_string = SaltString::generate(OsRng);
        let key_encryption_key = util::derive_kek(password, params, salt_string.as_salt())
            .context("failed to derive key-encryption key")?;
        let master_key = Self::new_raw().context("failed to generate master key")?;

        key_encryption_key
            .wrap(master_key.enc_key(), &mut wrapped_enc_master_key)
            .context("failed to wrap encryption master key")?;
        key_encryption_key
            .wrap(master_key.mac_key(), &mut wrapped_mac_master_key)
            .context("failed to wrap MAC master key")?;

        let version_mac = Hmac::<sha2::Sha256>::new_from_slice(master_key.mac_key())?
            .chain_update(version.to_be_bytes())
            .finalize()
            .into_bytes();

        Ok(WrappedKey {
            version: 999,
            scrypt_salt: salt_string.to_string(),
            scrypt_cost_param: 2_u32.pow(params.log_n() as u32),
            scrypt_block_size: params.r(),
            primary_master_key: Base64::encode_string(&wrapped_enc_master_key),
            hmac_master_key: Base64::encode_string(&wrapped_mac_master_key),
            version_mac: Base64::encode_string(&version_mac),
        })
    }

    pub fn from_wrapped(wrapped_key: &WrappedKey, kek: KekAes256) -> Result<Self> {
        let mut buffer = [0_u8; SUBKEY_LENGTH * 2];

        kek.unwrap(&wrapped_key.enc_key()?, &mut buffer[0..SUBKEY_LENGTH])
            .context("failed to unwrap encryption master key")?;
        kek.unwrap(&wrapped_key.mac_key()?, &mut buffer[SUBKEY_LENGTH..])
            .context("failed to unwrap MAC master key")?;

        Ok(Self(buffer))
    }

    pub fn sign_jwt(&self, header: Header, claims: impl Serialize) -> Result<String> {
        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(&self.0))
            .context("failed to sign JWT")
    }

    pub fn verify_jwt<T: DeserializeOwned>(
        &self,
        token: String,
        validation: Validation,
    ) -> Result<TokenData<T>> {
        jsonwebtoken::decode(&token, &DecodingKey::from_secret(&self.0), &validation)
            .context("failed to verify JWT")
    }
}
