use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherCombo {
    /// AES-SIV for file name encryption, AES-CTR + HMAC for content encryption.
    #[serde(rename = "SIV_CTRMAC")]
    SivCtrMac,
    /// AES-SIV for file name encryption, AES-GCM for content encryption.
    #[serde(rename = "SIV_GCM")]
    SivGcm,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Config {
    pub id: Uuid,
    pub format_version: u32,
    pub shortening_threshold: u32,
    pub cipher_combo: CipherCombo,
    pub master_key_uri: String,
    pub signing_algorithm: Algorithm,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigClaims {
    format: u32,
    shortening_threshold: u32,
    jti: Uuid,
    cipher_combo: CipherCombo,
}

impl Config {
    pub fn as_jwt(&self) -> Result<String> {
        let mut header = Header::new(self.signing_algorithm);
        header.kid.replace(self.master_key_uri.clone());

        let claims = ConfigClaims {
            format: self.format_version,
            shortening_threshold: self.shortening_threshold,
            jti: self.id,
            cipher_combo: self.cipher_combo,
        };

        // TODO: Fetch master key from location in self.master_key_uri
        let secret = b"this is a test";

        jsonwebtoken::encode(&header, &claims, &EncodingKey::from_secret(secret))
            .context("failed to encode and sign JWT")
    }

    pub fn from_jwt(token: String) -> Result<Self> {
        let header = jsonwebtoken::decode_header(&token).context("failed to decode JWT header")?;

        // TODO: Fetch master key from location specified in header
        let secret = b"this is a test";

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();

        let result = jsonwebtoken::decode::<ConfigClaims>(
            &token,
            &DecodingKey::from_secret(secret),
            &validation,
        )
        .context("failed to decode/verify JWT payload")?;

        Ok(Self {
            id: result.claims.jti,
            format_version: result.claims.format,
            shortening_threshold: result.claims.shortening_threshold,
            cipher_combo: result.claims.cipher_combo,
            master_key_uri: result.header.kid.context("no `kid` claim in JWT header")?,
            signing_algorithm: result.header.alg,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_test() {
        let config = Config {
            id: Uuid::nil(),
            format_version: 8,
            shortening_threshold: 220,
            cipher_combo: CipherCombo::SivCtrMac,
            master_key_uri: String::from("masterkeyfile:masterkey.cryptomator"),
            signing_algorithm: Algorithm::HS256,
        };

        let token = config.as_jwt().unwrap();
        assert_eq!(
            token,
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Im1hc3RlcmtleWZpbGU6bWFzdGVya2V5LmNyeXB0b21hdG9yIn0.eyJmb3JtYXQiOjgsInNob3J0ZW5pbmdUaHJlc2hvbGQiOjIyMCwianRpIjoiMDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwIiwiY2lwaGVyQ29tYm8iOiJTSVZfQ1RSTUFDIn0.2V3B2Z-7qRnVvzsdXut6YRjSjnN3Cs0K6QSTZIP74Jc"
        );
        assert_eq!(Config::from_jwt(token).unwrap(), config);
    }
}
