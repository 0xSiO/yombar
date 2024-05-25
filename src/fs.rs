use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
};

use crate::{crypto::FileCryptor, io::DecryptStream, Vault};

pub struct EncryptedFileSystem<'v> {
    vault: &'v Vault,
}

#[allow(dead_code)]
impl<'v> EncryptedFileSystem<'v> {
    pub fn new(vault: &'v Vault) -> Self {
        Self { vault }
    }

    pub fn root_ciphertext_path(&self) -> PathBuf {
        self.vault
            .path()
            .join("d")
            .join(self.vault.cryptor().hash_dir_id("").unwrap())
    }

    fn decrypt_file_to_string(&self, ciphertext_path: impl AsRef<Path>) -> io::Result<String> {
        let file = File::open(ciphertext_path)?;
        let mut cleartext = String::new();
        DecryptStream::new(self.vault.cryptor(), BufReader::new(file))
            .read_to_string(&mut cleartext)?;
        Ok(cleartext)
    }

    fn is_file(&self, ciphertext_path: impl AsRef<Path>) -> bool {
        ciphertext_path.as_ref().is_file()
    }

    fn is_dir(&self, ciphertext_path: impl AsRef<Path>) -> bool {
        ciphertext_path.as_ref().is_dir() && ciphertext_path.as_ref().join("dir.c9r").is_file()
    }

    fn is_symlink(&self, ciphertext_path: impl AsRef<Path>) -> bool {
        ciphertext_path.as_ref().is_dir() && ciphertext_path.as_ref().join("symlink.c9r").is_file()
    }

    fn get_ciphertext_name(
        &self,
        cleartext_path: impl AsRef<Path>,
        parent_dir_id: impl AsRef<str>,
    ) -> io::Result<String> {
        Ok(self
            .vault
            .cryptor()
            .encrypt_name(
                cleartext_path.as_ref().file_name().unwrap(),
                parent_dir_id.as_ref(),
            )
            .unwrap())
    }

    // TODO: Cache results from this function
    fn get_dir_id(&self, cleartext_path: impl AsRef<Path>) -> io::Result<String> {
        let parent_dir_id = match cleartext_path.as_ref().parent() {
            Some(parent) => self.get_dir_id(parent)?,
            None => return Ok(String::new()),
        };

        self.decrypt_file_to_string(
            self.vault
                .cryptor()
                .hash_dir_id(&parent_dir_id)
                .unwrap()
                .join(
                    self.get_ciphertext_name(cleartext_path, parent_dir_id)
                        .unwrap(),
                )
                .join("dir.c9r"),
        )
    }

    fn get_ciphertext_path(&self, cleartext_path: impl AsRef<Path>) -> io::Result<PathBuf> {
        let parent_dir_id = match cleartext_path.as_ref().parent() {
            Some(parent) => self.get_dir_id(parent)?,
            None => return Ok(self.root_ciphertext_path()),
        };

        Ok(self.vault.path().join("d").join(
            self.vault
                .cryptor()
                .hash_dir_id(&parent_dir_id)
                .unwrap()
                .join(
                    self.get_ciphertext_name(cleartext_path, parent_dir_id)
                        .unwrap(),
                ),
        ))
    }
}
