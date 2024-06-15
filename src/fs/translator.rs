use std::{
    ffi::OsStr,
    fs, io,
    path::{Path, PathBuf},
};

use base64ct::{Base64Url, Encoding};
use sha1::{Digest, Sha1};

use crate::{crypto::FileCryptor, Vault};

#[derive(Debug, Copy, Clone)]
pub struct Translator<'v> {
    vault: &'v Vault,
}

impl<'v> Translator<'v> {
    pub fn new(vault: &'v Vault) -> Self {
        Self { vault }
    }

    /// Translates a cleartext name to its full, unshortened ciphertext name, including .c9r
    /// extension.
    pub fn get_full_ciphertext_name(
        &self,
        cleartext_name: impl AsRef<OsStr>,
        dir_id: impl AsRef<str>,
    ) -> io::Result<String> {
        Ok(self
            .vault
            .cryptor()
            .encrypt_name(cleartext_name, dir_id)
            .unwrap()
            + ".c9r")
    }

    /// Translates a cleartext path to a ciphertext path, which may be shortened depending on vault
    /// config. Extension may be either .c9r or .c9s.
    pub fn get_ciphertext_path(
        &self,
        cleartext_path: impl AsRef<Path>,
        dir_id: impl AsRef<str>,
    ) -> io::Result<PathBuf> {
        let cleartext_name = cleartext_path.as_ref().file_name().unwrap();
        let ciphertext_name = self.get_full_ciphertext_name(cleartext_name, &dir_id)?;
        let hashed_dir_id = self.vault.cryptor().hash_dir_id(dir_id).unwrap();
        let path = self.vault.path().join("d").join(hashed_dir_id);
        let final_name =
            if ciphertext_name.len() > self.vault.config().claims.shortening_threshold as usize {
                let hash = Sha1::new().chain_update(ciphertext_name).finalize();
                Base64Url::encode_string(&hash) + ".c9s"
            } else {
                ciphertext_name
            };

        Ok(path.join(final_name))
    }

    /// Translates a cleartext directory path to its directory ID, or translates a cleartext file
    /// path to its containing directory's ID.
    pub fn get_dir_id(&self, cleartext_path: impl AsRef<Path>) -> io::Result<String> {
        let parent_dir_id = match cleartext_path.as_ref().parent() {
            Some(parent) => self.get_dir_id(parent)?,
            None => return Ok(String::new()),
        };

        let ciphertext_path = self.get_ciphertext_path(cleartext_path, &parent_dir_id)?;

        if ciphertext_path.join("dir.c9r").is_file() {
            fs::read_to_string(ciphertext_path.join("dir.c9r"))
        } else {
            Ok(parent_dir_id)
        }
    }

    /// Translates a ciphertext path (either full-length or shortened) into the decrypted filename
    /// of the corresponding cleartext file.
    // TODO: Refactor this if possible
    pub fn get_cleartext_name(
        &self,
        ciphertext_path: impl AsRef<Path>,
        dir_id: impl AsRef<str>,
    ) -> io::Result<String> {
        match ciphertext_path.as_ref().extension() {
            Some(extension) => {
                if extension == "c9s" {
                    let mut ciphertext_name = PathBuf::from(fs::read_to_string(
                        ciphertext_path.as_ref().join("name.c9s"),
                    )?);

                    // Remove .c9r from name
                    ciphertext_name.set_extension("");

                    self.vault
                        .cryptor()
                        .decrypt_name(ciphertext_name.to_string_lossy(), dir_id)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                } else {
                    let stem = ciphertext_path.as_ref().file_stem().unwrap_or_default();

                    self.vault
                        .cryptor()
                        .decrypt_name(stem.to_string_lossy(), dir_id)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                }
            }
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ciphertext path",
            )),
        }
    }
}
