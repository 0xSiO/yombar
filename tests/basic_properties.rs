use base64ct::{Base64, Encoding};
use cryptomator::{
    crypto::{v1::Cryptor, FileCryptor},
    util, CipherCombo, MasterKey, Vault, VaultConfig,
};
use jsonwebtoken::{TokenData, Validation};

#[test]
pub fn basic_properties() {
    let vault = Vault::open(
        "tests/fixtures/vault_v8_siv_ctrmac/vault.cryptomator",
        String::from("password"),
    )
    .unwrap();

    // Check vault imported correctly
    assert_eq!(
        vault.config().claims.jti.to_string(),
        "3c34938f-8acb-4c41-9a48-7a8f3c42835a"
    );
    assert_eq!(vault.config().claims.format, 8);
    assert_eq!(vault.config().claims.shortening_threshold, 220);
    assert_eq!(vault.config().claims.cipher_combo, CipherCombo::SivCtrMac);

    // Check key imported correctly
    let key = vault.master_key();
    assert_eq!(*key, unsafe {
        MasterKey::from_bytes(
            Base64::decode_vec("6RqWrWltqvYqQAowjweyJs8Hq/45NL3t/yIB/gVcubF8id+XIsrTnr7qfnd2YKLP/otupwsBCC+jaoIiduSxlw==")
                .unwrap()
                .try_into()
                .unwrap(),
        )
    });

    // Check JWT signing/verifying with key works correctly
    let config_jwt =
        util::sign_jwt(vault.config().header.clone(), vault.config().claims, key).unwrap();

    let mut validation = Validation::new(vault.config().header.alg);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    let decoded_config: TokenData<VaultConfig> =
        util::verify_jwt(config_jwt, validation, key).unwrap();

    assert_eq!(decoded_config.header, vault.config().header);
    assert_eq!(decoded_config.claims, vault.config().claims);

    // TODO: Fix SIV encryption, doesn't seem to match what's in the vault
    let cryptor = Cryptor::new(key);
    println!("{}", cryptor.hash_dir_id(""));
}
