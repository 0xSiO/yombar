use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    str::FromStr,
};

use base64ct::{Base64, Encoding};
use uuid::Uuid;
use yombar::{
    crypto::FileCryptor,
    fs::EncryptedFile,
    vault::{CipherCombo, Vault, VaultConfig},
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
            jti: Uuid::from_str("9228c6d3-7666-4198-b253-09891c2ad88c")?,
            format: 8,
            shortening_threshold: 220,
            cipher_combo: CipherCombo::SivCtrMac
        }
    );

    // Check file name encryption/decryption
    let cryptor = vault.cryptor();

    assert_eq!(
        cryptor.decrypt_name("IOiZwngROqT1h7atIffotwJTN42_OtnvLdLgJTQ=", "")?,
        "test_file.txt"
    );
    assert_eq!(
        cryptor.encrypt_name("test_file.txt", "")?,
        "IOiZwngROqT1h7atIffotwJTN42_OtnvLdLgJTQ="
    );

    assert_eq!(
        cryptor.decrypt_name(
            "kWQ67rcnZ-30y4C6oXIOuAjzGu0x_gc45QXQhNdjcA==",
            "cfe5fb8b-129f-4c4b-9dbc-6508765cc077"
        )?,
        "test_file_2.txt"
    );
    assert_eq!(
        cryptor.encrypt_name("test_file_2.txt", "cfe5fb8b-129f-4c4b-9dbc-6508765cc077")?,
        "kWQ67rcnZ-30y4C6oXIOuAjzGu0x_gc45QXQhNdjcA=="
    );

    // Check file header encryption/decryption
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/GI/YO5RUXD5NP6IP7GFAWSNT5IIEP6J7A/IOiZwngROqT1h7atIffotwJTN42_OtnvLdLgJTQ=.c9r"
    )?;

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "/roktGKA1o3myAw7S6GObmqlIuE6nee5yrqjvaVPKqEXmB2uLsm1tXVGWd/KFgkARnb0JyBNvzX6qtqjpa4l5lrFN9hvE5aB5lf4pl8vATCLlLIrG3tA0Gi8kKgpPYNCxvba9umsQ+k7y7B8F+7+tBTH0rLCDcT4o/kFrgu23h61lWAB6wpQUz276xQnz9yVlls6M5IBPOBUJZMvKKPM40y1BDEfTNyCizLqSzLVtTcG"
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
        "tests/fixtures/vault_v8_siv_ctrmac/d/GI/YO5RUXD5NP6IP7GFAWSNT5IIEP6J7A/dirid.c9r",
    )?;

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "Ij45Bem+qnJOjGXF+rAeYfJJ1okxMJMLqvaRFHp81LoCz91eMBn0BWpSSbITWIMNIcMTWRdr/Pkc0yFnoPNIb+8aw7BfHFBuFx8X10MNkoi1iuiwdcUArA=="
    );

    let _ = cryptor.decrypt_header(&ciphertext[..88])?;
    assert_eq!(&ciphertext[88..], b"");

    assert_eq!(
        cryptor.hash_dir_id("")?,
        PathBuf::from("GI").join("YO5RUXD5NP6IP7GFAWSNT5IIEP6J7A")
    );

    // Check subdirectory ID hashing
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/7T/X2VJCKD5CWG6UKR4UUHF5VIYWV7BGL/dirid.c9r",
    )?;

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "JLRFeWkacyca4rOAfGns4npc64+wyRFukLfP37pWivTaAKOqDDsukYRfYTihOTSp3BVVAY5yJ7Syuhd+/riLrIEAgpD+oS/SDhQd16XZnXDX+H0pxji+Td5dJew7SM6Hxg5wXruO7COKAmS/qMpS2hterw/5edsqVlsLsnHc0rYGgmBk3GJp00J2YDDg+OSDyvYAQeMRX6zu3p3AJGOnHS5voKmnVhJ7nDLV8g=="
    );

    let header = cryptor.decrypt_header(&ciphertext[..88])?;
    assert_eq!(
        cryptor.decrypt_chunk(&ciphertext[88..], &header, 0)?,
        b"cfe5fb8b-129f-4c4b-9dbc-6508765cc077"
    );

    assert_eq!(
        cryptor.hash_dir_id("cfe5fb8b-129f-4c4b-9dbc-6508765cc077")?,
        PathBuf::from("7T").join("X2VJCKD5CWG6UKR4UUHF5VIYWV7BGL")
    );

    // Check reading smaller files
    let mut file = EncryptedFile::open(
        cryptor,
        "tests/fixtures/vault_v8_siv_ctrmac/d/GI/YO5RUXD5NP6IP7GFAWSNT5IIEP6J7A/IOiZwngROqT1h7atIffotwJTN42_OtnvLdLgJTQ=.c9r",
        File::options().read(true).clone()
    )?;

    let mut decrypted = String::new();
    file.read_to_string(&mut decrypted)?;
    assert_eq!(decrypted, "this is a test file with some text in it\n");

    // Check reading larger files
    let mut file = EncryptedFile::open(
        cryptor,
        "tests/fixtures/vault_v8_siv_ctrmac/d/GI/YO5RUXD5NP6IP7GFAWSNT5IIEP6J7A/lTrI2Jfu-YkLpHmfu_OZPge73NerWUK5wjFewa8E.c9r",
        File::options().read(true).clone()
    )?;

    let mut decrypted = Vec::new();
    file.read_to_end(&mut decrypted)?;
    assert_eq!(decrypted, fs::read("tests/fixtures/test_image.jpg")?);

    // Check seeking & writing smaller files
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/GI/YO5RUXD5NP6IP7GFAWSNT5IIEP6J7A/IOiZwngROqT1h7atIffotwJTN42_OtnvLdLgJTQ=.c9r",
    )?;

    let _ = fs::remove_file("tests/test_small_siv_ctrmac.c9r");
    let mut file = EncryptedFile::create_new(cryptor, "tests/test_small_siv_ctrmac.c9r")?;
    file.write_all(b"this is a test file with some text in it\n")?;
    file.flush()?;

    let mut decrypted = String::new();
    file.rewind()?;
    file.read_to_string(&mut decrypted)?;

    assert_eq!(file.metadata()?.len() as usize, ciphertext.len());
    assert_eq!(decrypted, "this is a test file with some text in it\n");

    file.seek(SeekFrom::Start(10))?;
    file.write_all(b"text")?;
    decrypted.clear();
    file.rewind()?;
    file.read_to_string(&mut decrypted)?;

    assert_eq!(decrypted, "this is a text file with some text in it\n");

    fs::remove_file("tests/test_small_siv_ctrmac.c9r")?;

    // Check writing larger files
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_ctrmac/d/GI/YO5RUXD5NP6IP7GFAWSNT5IIEP6J7A/lTrI2Jfu-YkLpHmfu_OZPge73NerWUK5wjFewa8E.c9r",
    )?;
    let image_data = fs::read("tests/fixtures/test_image.jpg")?;

    let _ = fs::remove_file("tests/test_larger_siv_ctrmac.c9r");
    let mut file = EncryptedFile::create_new(cryptor, "tests/test_larger_siv_ctrmac.c9r")?;
    file.write_all(&image_data)?;
    file.flush()?;

    let mut decrypted = Vec::new();
    file.rewind()?;
    file.read_to_end(&mut decrypted)?;

    assert_eq!(file.metadata()?.len() as usize, ciphertext.len());
    assert_eq!(decrypted, image_data);

    fs::remove_file("tests/test_larger_siv_ctrmac.c9r")?;

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
            jti: Uuid::from_str("8e8d17a2-7b14-4439-a72f-5813e6843559")?,
            format: 8,
            shortening_threshold: 220,
            cipher_combo: CipherCombo::SivGcm
        }
    );

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

    // Check seeking & writing smaller files
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_gcm/d/RC/WG5EI3VR4DOIGAFUPFXLALP5SBGCL5/AlBBrYyQQqFiMXocarsNhcWd2oQ0yyRu86LZdZw=.c9r",
    )?;

    let _ = fs::remove_file("tests/test_small_siv_gcm.c9r");
    let mut file = EncryptedFile::create_new(cryptor, "tests/test_small_siv_gcm.c9r")?;
    file.write_all(b"this is a test file with some text in it\n")?;
    file.flush()?;

    let mut decrypted = String::new();
    file.rewind()?;
    file.read_to_string(&mut decrypted)?;

    assert_eq!(file.metadata()?.len() as usize, ciphertext.len());
    assert_eq!(decrypted, "this is a test file with some text in it\n");

    file.seek(SeekFrom::Start(10))?;
    file.write_all(b"text")?;
    decrypted.clear();
    file.rewind()?;
    file.read_to_string(&mut decrypted)?;

    assert_eq!(decrypted, "this is a text file with some text in it\n");

    fs::remove_file("tests/test_small_siv_gcm.c9r")?;

    // Check writing larger files
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_gcm/d/RC/WG5EI3VR4DOIGAFUPFXLALP5SBGCL5/LNyfONa3J2M1pirw-S-YBasDwUyV7RyhSwz7oMlP.c9r",
    )?;
    let image_data = fs::read("tests/fixtures/test_image.jpg")?;

    let _ = fs::remove_file("tests/test_larger_siv_gcm.c9r");
    let mut file = EncryptedFile::create_new(cryptor, "tests/test_larger_siv_gcm.c9r")?;
    file.write_all(&image_data)?;
    file.flush()?;

    let mut decrypted = Vec::new();
    file.rewind()?;
    file.read_to_end(&mut decrypted)?;

    assert_eq!(file.metadata()?.len() as usize, ciphertext.len());
    assert_eq!(decrypted, image_data);

    fs::remove_file("tests/test_larger_siv_gcm.c9r")?;

    Ok(())
}
