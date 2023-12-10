use base64ct::{Base64, Encoding};
use cryptomator::{
    crypto::{v1::Cryptor, FileCryptor},
    util, CipherCombo, MasterKey, Vault, VaultConfig,
};
use jsonwebtoken::{TokenData, Validation};

#[test]
pub fn basic_properties() {
    // Check vault import
    let vault = Vault::open(
        "tests/fixtures/vault_v8_siv_ctrmac/vault.cryptomator",
        String::from("password"),
    )
    .unwrap();

    assert_eq!(
        vault.config().claims.jti.to_string(),
        "3c34938f-8acb-4c41-9a48-7a8f3c42835a"
    );
    assert_eq!(vault.config().claims.format, 8);
    assert_eq!(vault.config().claims.shortening_threshold, 220);
    assert_eq!(vault.config().claims.cipher_combo, CipherCombo::SivCtrMac);

    // Check key import
    let key = vault.master_key();

    assert_eq!(*key, unsafe {
        MasterKey::from_bytes(
            Base64::decode_vec("6RqWrWltqvYqQAowjweyJs8Hq/45NL3t/yIB/gVcubF8id+XIsrTnr7qfnd2YKLP/otupwsBCC+jaoIiduSxlw==")
                .unwrap()
                .try_into()
                .unwrap(),
        )
    });

    // Check JWT signing/verifying
    let config_jwt =
        util::sign_jwt(vault.config().header.clone(), vault.config().claims, key).unwrap();

    let mut validation = Validation::new(vault.config().header.alg);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    let decoded_config: TokenData<VaultConfig> =
        util::verify_jwt(config_jwt, validation, key).unwrap();

    assert_eq!(decoded_config.header, vault.config().header);
    assert_eq!(decoded_config.claims, vault.config().claims);

    // Check file name encryption/decryption
    let cryptor = Cryptor::new(key);

    assert_eq!(
        cryptor.decrypt_name("TKDIJ1vsa0Tp5ZCcUudycUuYTcz17tdgI489pGU=", ""),
        "test_file.txt"
    );
    assert_eq!(
        cryptor.encrypt_name("test_file.txt", ""),
        "TKDIJ1vsa0Tp5ZCcUudycUuYTcz17tdgI489pGU="
    );

    // Check file header encryption/decryption
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/B3/EO5WWODTDD254SS2TQWVAQKJAWPBKK/TKDIJ1vsa0Tp5ZCcUudycUuYTcz17tdgI489pGU=.c9r",
    )
    .unwrap();

    let header = cryptor.decrypt_header(&ciphertext[..88]);
    assert_eq!(cryptor.encrypt_header(&header), &ciphertext[..88]);

    // Check file content encryption/decryption
    let plaintext = b"this is a test file with some text in it\n";

    assert_eq!(
        cryptor.decrypt_chunk(&ciphertext[88..], &header, 0),
        plaintext
    );
    assert_eq!(
        cryptor.encrypt_chunk(
            plaintext,
            &header,
            0,
            // Known nonce for this chunk
            &[
                0xa5, 0xbe, 0xe9, 0xc7, 0xac, 0x21, 0x72, 0xf, 0xfd, 0xef, 0x47, 0x6e, 0x2f, 0xeb,
                0x3d, 0x4c,
            ],
        ),
        ciphertext[88..]
    );
}
