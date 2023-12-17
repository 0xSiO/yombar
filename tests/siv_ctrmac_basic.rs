use std::fs;

use base64ct::{Base64, Encoding};
use cryptomator::{
    crypto::{siv_ctrmac::Cryptor, FileCryptor},
    util, CipherCombo, MasterKey, Vault, VaultConfig,
};
use jsonwebtoken::{TokenData, Validation};

#[test]
pub fn siv_ctrmac_basic() {
    // Check vault import
    let vault = Vault::open(
        "tests/fixtures/vault_v8_siv_ctrmac/vault.cryptomator",
        String::from("password"),
    )
    .unwrap();

    assert_eq!(
        vault.path(),
        fs::canonicalize("./tests/fixtures/vault_v8_siv_ctrmac").unwrap()
    );

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
        cryptor
            .decrypt_name("TKDIJ1vsa0Tp5ZCcUudycUuYTcz17tdgI489pGU=", "")
            .unwrap(),
        "test_file.txt"
    );
    assert_eq!(
        cryptor.encrypt_name("test_file.txt", "").unwrap(),
        "TKDIJ1vsa0Tp5ZCcUudycUuYTcz17tdgI489pGU="
    );

    assert_eq!(
        cryptor
            .decrypt_name(
                "3ZnmWpMsMPllwZCto1Gb0R7JvkiWcuV1Kmk6aczQPQ==",
                "68fdafca-2315-4840-87bc-19c48baf897f"
            )
            .unwrap(),
        "test_file_2.txt"
    );
    assert_eq!(
        cryptor
            .encrypt_name("test_file_2.txt", "68fdafca-2315-4840-87bc-19c48baf897f")
            .unwrap(),
        "3ZnmWpMsMPllwZCto1Gb0R7JvkiWcuV1Kmk6aczQPQ==",
    );

    // Check file header encryption/decryption
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/B3/EO5WWODTDD254SS2TQWVAQKJAWPBKK/TKDIJ1vsa0Tp5ZCcUudycUuYTcz17tdgI489pGU=.c9r",
    )
    .unwrap();

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "8OHhIeke26MS1E8KnbjGJqDyrZorAAxvNRrmZUqdHPTSpu42TXT4dFT5qbrd57PEaYUilUK9tAwD3gKNTWg9fmLvehEWBqDey+8FPgp4lUOkUlViiv1Q+aW+6cesIXIP/e9Hbi/rPUxjWnfHsKRLyzUyzHc+tU3DVZeKjMJnXoWWNqifsOnVFPeQPMjFpJ5h0mJWhUmuzSu+mWSeKGsPeT2GT5FkpD5hawtXD/q0WPyQ"
    );

    let header = cryptor.decrypt_header(&ciphertext[..88]).unwrap();
    assert_eq!(cryptor.encrypt_header(&header).unwrap(), &ciphertext[..88]);

    // Check file content decryption
    let plaintext = b"this is a test file with some text in it\n";

    assert_eq!(
        cryptor
            .decrypt_chunk(&ciphertext[88..], &header, 0)
            .unwrap(),
        plaintext
    );

    // Check root directory ID hashing
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/B3/EO5WWODTDD254SS2TQWVAQKJAWPBKK/dirid.c9r",
    )
    .unwrap();

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "A7raPuW/ve4JGJcznX5GcOtKBX956uBrQRjUrO2loItd8VekyvbDfJP2mnCm5mnFnMoP8jRZD+GzzAJvOAo1Y7mQTCKIVTt3r6S8zjBe9LQ4FSz6ASiu7w=="
    );

    let _ = cryptor.decrypt_header(&ciphertext[..88]).unwrap();
    assert_eq!(&ciphertext[88..], b"");

    assert_eq!(
        cryptor.hash_dir_id("").unwrap(),
        "B3EO5WWODTDD254SS2TQWVAQKJAWPBKK"
    );

    // Check subdirectory ID hashing
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/QQ/I7Q3TUGAZFNCXWWEXUSOJS7PQ4K4HE/dirid.c9r",
    )
    .unwrap();

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "kevHWULbQN6e9NYLNLM9psqkEfxibHIsVlK7DMNgGzo+d31XncWBv1jqkVtIXEVzsVjFdcdE3QhPVdOAzRu7hJslfEMb2QAWTZsyr/cn6dQZkhLHyv+zO3qE7QPUefj9SNEJ/PqIS05Nb5dnqm963iPkAS823kPlhxkRn/VwvpS3Mb2K23mTG9/EECdKfEcdhhTgkfeuYxr6QBIniA52OQcoyiJuDa2DBDa6lw=="
    );

    let header = cryptor.decrypt_header(&ciphertext[..88]).unwrap();
    assert_eq!(
        cryptor
            .decrypt_chunk(&ciphertext[88..], &header, 0)
            .unwrap(),
        b"68fdafca-2315-4840-87bc-19c48baf897f"
    );

    assert_eq!(
        cryptor
            .hash_dir_id("68fdafca-2315-4840-87bc-19c48baf897f")
            .unwrap(),
        "QQI7Q3TUGAZFNCXWWEXUSOJS7PQ4K4HE"
    );
}
