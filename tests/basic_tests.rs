use std::{
    fs::{self, File},
    io::{Read, Seek, Write},
    path::PathBuf,
    str::FromStr,
};

use base64ct::{Base64, Encoding};
use jsonwebtoken::{TokenData, Validation};
use uuid::Uuid;
use yombar::{
    crypto::FileCryptor, fs::EncryptedFile, util, CipherCombo, MasterKey, Vault, VaultConfig,
};

#[test]
pub fn siv_ctrmac_basic() -> yombar::Result<()> {
    // Check vault import
    let vault = Vault::open(
        "tests/fixtures/vault_v8_siv_ctrmac",
        String::from("password"),
    )?;

    assert_eq!(
        vault.path(),
        fs::canonicalize("./tests/fixtures/vault_v8_siv_ctrmac")?
    );

    assert_eq!(
        vault.config().claims,
        VaultConfig {
            jti: Uuid::from_str("3c34938f-8acb-4c41-9a48-7a8f3c42835a")?,
            format: 8,
            shortening_threshold: 220,
            cipher_combo: CipherCombo::SivCtrMac
        }
    );

    // Check key import
    let key = vault.master_key();

    assert_eq!(*key, unsafe {
        MasterKey::from_bytes(
            Base64::decode_vec("6RqWrWltqvYqQAowjweyJs8Hq/45NL3t/yIB/gVcubF8id+XIsrTnr7qfnd2YKLP/otupwsBCC+jaoIiduSxlw==")?
                .try_into()
                .unwrap(),
        )
    });

    // Check JWT signing/verifying
    let config_jwt = util::sign_jwt(vault.config().header.clone(), vault.config().claims, key)?;

    let mut validation = Validation::new(vault.config().header.alg);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    let decoded_config: TokenData<VaultConfig> = util::verify_jwt(config_jwt, validation, key)?;

    assert_eq!(decoded_config.header, vault.config().header);
    assert_eq!(decoded_config.claims, vault.config().claims);

    // Check file name encryption/decryption
    let cryptor = vault.cryptor();

    assert_eq!(
        cryptor.decrypt_name("TKDIJ1vsa0Tp5ZCcUudycUuYTcz17tdgI489pGU=", "")?,
        "test_file.txt"
    );
    assert_eq!(
        cryptor.encrypt_name("test_file.txt", "")?,
        "TKDIJ1vsa0Tp5ZCcUudycUuYTcz17tdgI489pGU="
    );

    assert_eq!(
        cryptor.decrypt_name(
            "3ZnmWpMsMPllwZCto1Gb0R7JvkiWcuV1Kmk6aczQPQ==",
            "68fdafca-2315-4840-87bc-19c48baf897f"
        )?,
        "test_file_2.txt"
    );
    assert_eq!(
        cryptor.encrypt_name("test_file_2.txt", "68fdafca-2315-4840-87bc-19c48baf897f")?,
        "3ZnmWpMsMPllwZCto1Gb0R7JvkiWcuV1Kmk6aczQPQ==",
    );

    // Check file header encryption/decryption
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/B3/EO5WWODTDD254SS2TQWVAQKJAWPBKK/TKDIJ1vsa0Tp5ZCcUudycUuYTcz17tdgI489pGU=.c9r",
    )?;

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "0HtXhtsJDgIA4uDKS3PrXnVv4Nnn0ZbuJRWV35QQzGHM/8JjmEDXKgrYauFcj9WgFihKEYJLzzGae/jxCtQqloI3jvmhSc86LvBL7qKjV/O98nsPQoqBiBYrg9yKuhZOqC2xFK/TqohR/eSuIuRnmlKodNy9TTa8CDd5fVVh0zZDHfG63d4qoKeAtPXxyRQ7ConN+4iN4qToWz7xrOT++ptUUUQKzg4WN+DInMfPzTlU"
    );

    let header = cryptor.decrypt_header(&ciphertext[..88])?;
    assert_eq!(cryptor.encrypt_header(&header)?, &ciphertext[..88]);

    // Check file content decryption
    assert_eq!(
        cryptor.decrypt_chunk(&ciphertext[88..], &header, 0)?,
        b"this is a test file with some text in it\n"
    );

    // Check root directory ID hashing
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/B3/EO5WWODTDD254SS2TQWVAQKJAWPBKK/dirid.c9r",
    )?;

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "A7raPuW/ve4JGJcznX5GcOtKBX956uBrQRjUrO2loItd8VekyvbDfJP2mnCm5mnFnMoP8jRZD+GzzAJvOAo1Y7mQTCKIVTt3r6S8zjBe9LQ4FSz6ASiu7w=="
    );

    let _ = cryptor.decrypt_header(&ciphertext[..88])?;
    assert_eq!(&ciphertext[88..], b"");

    assert_eq!(
        cryptor.hash_dir_id("")?,
        PathBuf::from("B3").join("EO5WWODTDD254SS2TQWVAQKJAWPBKK")
    );

    // Check subdirectory ID hashing
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/QQ/I7Q3TUGAZFNCXWWEXUSOJS7PQ4K4HE/dirid.c9r",
    )?;

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "kevHWULbQN6e9NYLNLM9psqkEfxibHIsVlK7DMNgGzo+d31XncWBv1jqkVtIXEVzsVjFdcdE3QhPVdOAzRu7hJslfEMb2QAWTZsyr/cn6dQZkhLHyv+zO3qE7QPUefj9SNEJ/PqIS05Nb5dnqm963iPkAS823kPlhxkRn/VwvpS3Mb2K23mTG9/EECdKfEcdhhTgkfeuYxr6QBIniA52OQcoyiJuDa2DBDa6lw=="
    );

    let header = cryptor.decrypt_header(&ciphertext[..88])?;
    assert_eq!(
        cryptor.decrypt_chunk(&ciphertext[88..], &header, 0)?,
        b"68fdafca-2315-4840-87bc-19c48baf897f"
    );

    assert_eq!(
        cryptor.hash_dir_id("68fdafca-2315-4840-87bc-19c48baf897f")?,
        PathBuf::from("QQ").join("I7Q3TUGAZFNCXWWEXUSOJS7PQ4K4HE")
    );

    // Check reading smaller files
    let mut file = EncryptedFile::open(
        cryptor,
        "tests/fixtures/vault_v8_siv_ctrmac/d/B3/EO5WWODTDD254SS2TQWVAQKJAWPBKK/TKDIJ1vsa0Tp5ZCcUudycUuYTcz17tdgI489pGU=.c9r",
        File::options().read(true).clone()
    )?;

    let mut decrypted = String::new();
    file.read_to_string(&mut decrypted)?;
    assert_eq!(decrypted, "this is a test file with some text in it\n");

    // Check reading larger files
    let mut file = EncryptedFile::open(
        cryptor,
        "tests/fixtures/vault_v8_siv_ctrmac/d/B3/EO5WWODTDD254SS2TQWVAQKJAWPBKK/elqiMLEIVhXP94ydJeId4vavM_9rPv380wdMYzwg.c9r",
        File::options().read(true).clone()
    )?;

    let mut decrypted = Vec::new();
    file.read_to_end(&mut decrypted)?;
    assert_eq!(decrypted, fs::read("tests/fixtures/test_image.jpg")?);

    // Check writing smaller files
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/B3/EO5WWODTDD254SS2TQWVAQKJAWPBKK/TKDIJ1vsa0Tp5ZCcUudycUuYTcz17tdgI489pGU=.c9r",
    )?;

    let _ = fs::remove_file("tests/test_small_siv_ctrmac.txt");
    let mut file = EncryptedFile::create_new(cryptor, "tests/test_small_siv_ctrmac.txt")?;
    file.write_all(b"this is a test file with some text in it\n")?;
    file.flush()?;

    let mut decrypted = String::new();
    file.rewind()?;
    file.read_to_string(&mut decrypted)?;

    assert_eq!(file.metadata()?.len() as usize, ciphertext.len());
    assert_eq!(decrypted, "this is a test file with some text in it\n");

    fs::remove_file("tests/test_small_siv_ctrmac.txt")?;

    // Check writing larger files
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/B3/EO5WWODTDD254SS2TQWVAQKJAWPBKK/elqiMLEIVhXP94ydJeId4vavM_9rPv380wdMYzwg.c9r",
    )?;
    let image_data = fs::read("tests/fixtures/test_image.jpg")?;

    let _ = fs::remove_file("tests/test_larger_siv_ctrmac.jpg");
    let mut file = EncryptedFile::create_new(cryptor, "tests/test_larger_siv_ctrmac.jpg")?;
    file.write_all(&image_data)?;
    file.flush()?;

    let mut decrypted = Vec::new();
    file.rewind()?;
    file.read_to_end(&mut decrypted)?;

    assert_eq!(file.metadata()?.len() as usize, ciphertext.len());
    assert_eq!(decrypted, image_data);

    fs::remove_file("tests/test_larger_siv_ctrmac.jpg")?;

    Ok(())
}

#[test]
pub fn siv_gcm_basic() -> yombar::Result<()> {
    // Check vault import
    let vault = Vault::open("tests/fixtures/vault_v8_siv_gcm", String::from("password"))?;

    assert_eq!(
        vault.path(),
        fs::canonicalize("./tests/fixtures/vault_v8_siv_gcm")?
    );

    assert_eq!(
        vault.config().claims,
        VaultConfig {
            jti: Uuid::from_str("46cd26de-d575-4563-ad30-432123f85f36")?,
            format: 8,
            shortening_threshold: 220,
            cipher_combo: CipherCombo::SivGcm
        }
    );

    // Check key import
    let key = vault.master_key();

    assert_eq!(*key, unsafe {
        MasterKey::from_bytes(
            Base64::decode_vec("sXs8e6rKQX3iySTUkOd6V0FqaM3nqN/x8ULcUYdtBXQBSSDBbf8FEBAkUuGhpqot8leMQTfevZKICb7t8voIOQ==")?
                .try_into()
                .unwrap(),
        )
    });

    // Check JWT signing/verifying
    let config_jwt = util::sign_jwt(vault.config().header.clone(), vault.config().claims, key)?;

    let mut validation = Validation::new(vault.config().header.alg);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();
    let decoded_config: TokenData<VaultConfig> = util::verify_jwt(config_jwt, validation, key)?;

    assert_eq!(decoded_config.header, vault.config().header);
    assert_eq!(decoded_config.claims, vault.config().claims);

    // Check file name encryption/decryption
    let cryptor = vault.cryptor();

    assert_eq!(
        cryptor.decrypt_name("AlBBrYyQQqFiMXocarsNhcWd2oQ0yyRu86LZdZw=", "")?,
        "test_file.txt"
    );
    assert_eq!(
        cryptor.encrypt_name("test_file.txt", "")?,
        "AlBBrYyQQqFiMXocarsNhcWd2oQ0yyRu86LZdZw="
    );

    assert_eq!(
        cryptor.decrypt_name(
            "j2O1bILonFELjBCQTaqZEBgfUh1_uHvXjOdMdc2ZEg==",
            "1a3534ba-34fb-4ba6-ad67-1e37627d40be"
        )?,
        "test_file_2.txt"
    );
    assert_eq!(
        cryptor.encrypt_name("test_file_2.txt", "1a3534ba-34fb-4ba6-ad67-1e37627d40be")?,
        "j2O1bILonFELjBCQTaqZEBgfUh1_uHvXjOdMdc2ZEg=="
    );

    // Check file header encryption/decryption
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_gcm/d/RC/WG5EI3VR4DOIGAFUPFXLALP5SBGCL5/AlBBrYyQQqFiMXocarsNhcWd2oQ0yyRu86LZdZw=.c9r",
    )?;

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "EOc16Sc/NMUcA9N8K6aYhNWdXdX34sZbTUw0WWVXjtxDAHiuLoTtrre0PNzb1SwvLGz2Ow6/7lBDb+inNxZr7sAc5BwkJHmHJaEjLbOU5i+tCSI7inkX9YmFv6Zm9ZjeDy8lK1360cCTHQ9d4IQ2dhX6Qa5ZMeKSC31r5Y3Eg+rY0U8eIjzby8Q="
    );

    let header = cryptor.decrypt_header(&ciphertext[..68])?;
    assert_eq!(cryptor.encrypt_header(&header)?, &ciphertext[..68]);

    // Check file content decryption
    assert_eq!(
        cryptor.decrypt_chunk(&ciphertext[68..], &header, 0)?,
        b"this is a test file with some text in it\n"
    );

    // Check root directory ID hashing
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_gcm/d/RC/WG5EI3VR4DOIGAFUPFXLALP5SBGCL5/dirid.c9r",
    )?;

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "ftvD3GxyBnhbFU6kxs5CEHUh0LMhCXHVfQJLZrVCbq9cZ8ptPl2KD9oEGvGlcaI/XVhPT17C4y1P9Y6qhDTRZFGF5xw="
    );

    let _ = cryptor.decrypt_header(&ciphertext[..68])?;
    assert_eq!(&ciphertext[68..], b"");

    assert_eq!(
        cryptor.hash_dir_id("")?,
        PathBuf::from("RC").join("WG5EI3VR4DOIGAFUPFXLALP5SBGCL5")
    );

    // Check subdirectory ID hashing
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_gcm/d/RT/C3KT7DD5C3X6QE32X4IL6PM6WHHNB5/dirid.c9r",
    )?;

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "u53iAARXqaZVGLJMguDq2KQZ2A5eu/jxzjsqapLwVGEe2FeazwpWRptqUHEFzKVwbFh16L7Y++pR1s+WunbJU0uOKvVS9lDTEV9B9MsjSOIijAsUg0tgcoOplb5BL5Og0G10AgbWCall/smk1fgsWaIF0y2g8ScFhlmMJGA7HhXqolOf"
    );

    let header = cryptor.decrypt_header(&ciphertext[..68])?;

    assert_eq!(
        cryptor.decrypt_chunk(&ciphertext[68..], &header, 0)?,
        b"1a3534ba-34fb-4ba6-ad67-1e37627d40be"
    );

    assert_eq!(
        cryptor.hash_dir_id("1a3534ba-34fb-4ba6-ad67-1e37627d40be")?,
        PathBuf::from("RT").join("C3KT7DD5C3X6QE32X4IL6PM6WHHNB5")
    );

    // Check reading smaller files
    let mut file = EncryptedFile::open(
        cryptor,
        "tests/fixtures/vault_v8_siv_gcm/d/RC/WG5EI3VR4DOIGAFUPFXLALP5SBGCL5/AlBBrYyQQqFiMXocarsNhcWd2oQ0yyRu86LZdZw=.c9r",
        File::options().read(true).clone()
    )?;

    let mut decrypted = String::new();
    file.read_to_string(&mut decrypted)?;
    assert_eq!(decrypted, "this is a test file with some text in it\n");

    // Check reading larger files
    let mut file = EncryptedFile::open(
        cryptor,
        "tests/fixtures/vault_v8_siv_gcm/d/RC/WG5EI3VR4DOIGAFUPFXLALP5SBGCL5/LNyfONa3J2M1pirw-S-YBasDwUyV7RyhSwz7oMlP.c9r",
        File::options().read(true).clone()
    )?;

    let mut decrypted = Vec::new();
    file.read_to_end(&mut decrypted)?;
    assert_eq!(decrypted, fs::read("tests/fixtures/test_image.jpg")?);

    // Check writing smaller files
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_gcm/d/RC/WG5EI3VR4DOIGAFUPFXLALP5SBGCL5/AlBBrYyQQqFiMXocarsNhcWd2oQ0yyRu86LZdZw=.c9r",
    )?;

    let _ = fs::remove_file("tests/test_small_siv_gcm.txt");
    let mut file = EncryptedFile::create_new(cryptor, "tests/test_small_siv_gcm.txt")?;
    file.write_all(b"this is a test file with some text in it\n")?;
    file.flush()?;

    let mut decrypted = String::new();
    file.rewind()?;
    file.read_to_string(&mut decrypted)?;

    assert_eq!(file.metadata()?.len() as usize, ciphertext.len());
    assert_eq!(decrypted, "this is a test file with some text in it\n");

    fs::remove_file("tests/test_small_siv_gcm.txt")?;

    // Check writing larger files
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_gcm/d/RC/WG5EI3VR4DOIGAFUPFXLALP5SBGCL5/LNyfONa3J2M1pirw-S-YBasDwUyV7RyhSwz7oMlP.c9r",
    )?;
    let image_data = fs::read("tests/fixtures/test_image.jpg")?;

    let _ = fs::remove_file("tests/test_larger_siv_gcm.jpg");
    let mut file = EncryptedFile::create_new(cryptor, "tests/test_larger_siv_gcm.jpg")?;
    file.write_all(&image_data)?;
    file.flush()?;

    let mut decrypted = Vec::new();
    file.rewind()?;
    file.read_to_end(&mut decrypted)?;

    assert_eq!(file.metadata()?.len() as usize, ciphertext.len());
    assert_eq!(decrypted, image_data);

    fs::remove_file("tests/test_larger_siv_gcm.jpg")?;

    Ok(())
}
