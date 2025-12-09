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
    util::SecretString,
    vault::{CipherCombo, Vault, VaultConfig},
};

#[test]
pub fn siv_ctrmac_basic() -> yombar::Result<()> {
    // Check vault import
    let vault = Vault::open(
        "tests/fixtures/vault_v8_siv_ctrmac",
        SecretString::from(String::from("password")),
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
    let vault = Vault::open(
        "tests/fixtures/vault_v8_siv_gcm",
        SecretString::from(String::from("password")),
    )?;

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
        cryptor.decrypt_name("Nl7o6qgpvLuA9XfYd_VxL0JwzfAO_tuJLghsGuY=", "")?,
        "test_file.txt"
    );
    assert_eq!(
        cryptor.encrypt_name("test_file.txt", "")?,
        "Nl7o6qgpvLuA9XfYd_VxL0JwzfAO_tuJLghsGuY="
    );

    assert_eq!(
        cryptor.decrypt_name(
            "EbRMA8Bi4uhKIxjTyXs5e53PHMMckHX0_HCJiiYTgg==",
            "16b1ae69-5913-4c7e-b68e-aa827440e263"
        )?,
        "test_file_2.txt"
    );
    assert_eq!(
        cryptor.encrypt_name("test_file_2.txt", "16b1ae69-5913-4c7e-b68e-aa827440e263")?,
        "EbRMA8Bi4uhKIxjTyXs5e53PHMMckHX0_HCJiiYTgg==",
    );

    // Check file header encryption/decryption
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_gcm/d/QD/W5WPJ7TSDTMH2G4363MJUELZ7KZMHK/Nl7o6qgpvLuA9XfYd_VxL0JwzfAO_tuJLghsGuY=.c9r",
    )?;

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "jf1U5SkG/AOYYESWb6oZgg0V5AEG4bpSlPgiSfRP5hJLAuvoJbFHyynkH2/ianaOpm8q329kpq8bEwxUlRt9DQUX7ZON9JlEz1jLRgcWyJnR1GVcsRmdaLICGAGHCxsU4Uq8d31AQr3bd7oUJnHdvBevw20EQKa1ERzflyflfqJfsufGRCRNOqg="
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
        "tests/fixtures/vault_v8_siv_gcm/d/QD/W5WPJ7TSDTMH2G4363MJUELZ7KZMHK/dirid.c9r",
    )?;

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "RvnxmEumxEo980tpHuTDXgvcpDjB3kFuV7Z9PdCy8bKBd/e6PdHCYcLSCY/TimCcgAI3gncdlJgxb4OYpzWt//JmGeI="
    );

    let _ = cryptor.decrypt_header(&ciphertext[..68])?;
    assert_eq!(&ciphertext[68..], b"");

    assert_eq!(
        cryptor.hash_dir_id("")?,
        PathBuf::from("QD").join("W5WPJ7TSDTMH2G4363MJUELZ7KZMHK")
    );

    // Check subdirectory ID hashing
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_gcm/d/UW/RBQWYYXJZZTYB4UCJAMR5D6Z55K2ZF/dirid.c9r",
    )?;

    assert_eq!(
        Base64::encode_string(&ciphertext),
        "GZ8HdDcCBuSy9B9D+4nfIoxYCrsnLgOKhHMt4cr62wF2oMy5i1/nbCcsoseihgOKOU0JDkNb4zSlXgNIezALBqHjjM76E4PNktvL2VacgqTX/cp3UsT4HMWPygy9t+PDds2ZSG1t++rhpfINmOuEmC4hZIr3V9z5gsqXF7rqQ7XsMGQW"
    );

    let header = cryptor.decrypt_header(&ciphertext[..68])?;

    assert_eq!(
        cryptor.decrypt_chunk(&ciphertext[68..], &header, 0)?,
        b"16b1ae69-5913-4c7e-b68e-aa827440e263"
    );

    assert_eq!(
        cryptor.hash_dir_id("16b1ae69-5913-4c7e-b68e-aa827440e263")?,
        PathBuf::from("UW").join("RBQWYYXJZZTYB4UCJAMR5D6Z55K2ZF")
    );

    // Check reading smaller files
    let mut file = EncryptedFile::open(
        cryptor,
        "tests/fixtures/vault_v8_siv_gcm/d/QD/W5WPJ7TSDTMH2G4363MJUELZ7KZMHK/Nl7o6qgpvLuA9XfYd_VxL0JwzfAO_tuJLghsGuY=.c9r",
        File::options().read(true).clone()
    )?;

    let mut decrypted = String::new();
    file.read_to_string(&mut decrypted)?;
    assert_eq!(decrypted, "this is a test file with some text in it\n");

    // Check reading larger files
    let mut file = EncryptedFile::open(
        cryptor,
        "tests/fixtures/vault_v8_siv_gcm/d/QD/W5WPJ7TSDTMH2G4363MJUELZ7KZMHK/WQ6sflYGPWPHJubj3F4ZMYwhKraEQUCV42gL11XA.c9r",
        File::options().read(true).clone()
    )?;

    let mut decrypted = Vec::new();
    file.read_to_end(&mut decrypted)?;
    assert_eq!(decrypted, fs::read("tests/fixtures/test_image.jpg")?);

    // Check seeking & writing smaller files
    let ciphertext = std::fs::read(
        "tests/fixtures/vault_v8_siv_gcm/d/QD/W5WPJ7TSDTMH2G4363MJUELZ7KZMHK/Nl7o6qgpvLuA9XfYd_VxL0JwzfAO_tuJLghsGuY=.c9r",
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
        "tests/fixtures/vault_v8_siv_gcm/d/QD/W5WPJ7TSDTMH2G4363MJUELZ7KZMHK/WQ6sflYGPWPHJubj3F4ZMYwhKraEQUCV42gL11XA.c9r",
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
