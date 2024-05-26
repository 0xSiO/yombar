#![allow(dead_code)]

use std::{
    ffi::OsString,
    fs::{File, Metadata},
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
};

use crate::{crypto::FileCryptor, io::DecryptStream, Vault};

pub mod fuse;

#[derive(Copy, Clone)]
enum FileKind {
    File,
    Directory,
    Symlink,
}

struct DirEntry {
    file_name: OsString,
    file_kind: FileKind,
    metadata: Metadata,
}

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

    // TODO: Handle case when name is too long to be stored in the file stem
    fn get_cleartext_name(
        &self,
        ciphertext_path: impl AsRef<Path>,
        parent_dir_id: impl AsRef<str>,
    ) -> io::Result<String> {
        self.vault
            .cryptor()
            .decrypt_name(
                ciphertext_path
                    .as_ref()
                    .file_stem()
                    .map(|s| s.to_string_lossy())
                    // TODO: This may not be the best idea
                    .unwrap_or_default(),
                &parent_dir_id,
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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

    fn read_dir(
        &self,
        cleartext_dir_path: impl AsRef<Path>,
    ) -> io::Result<impl Iterator<Item = io::Result<DirEntry>> + '_> {
        let cleartext_dir_path = cleartext_dir_path.as_ref().to_path_buf();
        let dir_id = self.get_dir_id(&cleartext_dir_path)?;
        let ciphertext_dir_path = self.get_ciphertext_path(&cleartext_dir_path)?;

        Ok(ciphertext_dir_path
            .read_dir()?
            .filter(|entry| {
                entry
                    .as_ref()
                    .map(|e| e.file_name() != "dirid.c9r")
                    .unwrap_or(false)
            })
            .map(move |entry| match entry {
                Ok(entry) => {
                    let cleartext_name = self.get_cleartext_name(entry.path(), &dir_id)?;

                    let file_kind = if self.is_dir(entry.path()) {
                        FileKind::Directory
                    } else if self.is_symlink(entry.path()) {
                        FileKind::Symlink
                    } else {
                        FileKind::File
                    };

                    Ok(DirEntry {
                        file_name: cleartext_name.into(),
                        file_kind,
                        metadata: entry.metadata()?,
                    })
                }
                Err(err) => Err(err),
            }))
    }
}
