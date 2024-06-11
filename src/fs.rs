use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata},
    io::{self, Read},
    path::{Path, PathBuf},
};

use base64ct::{Base64Url, Encoding};
use sha1::{Digest, Sha1};

use crate::{crypto::FileCryptor, io::EncryptedStream, util, Vault};

pub mod fuse;

#[derive(Debug, Copy, Clone, PartialEq)]
enum FileKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug)]
struct DirEntry {
    kind: FileKind,
    size: u64,
    metadata: Metadata,
}

#[derive(Debug)]
pub struct EncryptedFileSystem<'v> {
    vault: &'v Vault,
}

impl<'v> EncryptedFileSystem<'v> {
    pub fn new(vault: &'v Vault) -> Self {
        Self { vault }
    }

    pub fn root_dir(&self) -> PathBuf {
        self.vault
            .path()
            .join("d")
            .join(self.vault.cryptor().hash_dir_id("").unwrap())
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

    fn get_ciphertext_path(
        &self,
        cleartext_path: impl AsRef<Path>,
        parent_dir_id: impl AsRef<str>,
    ) -> io::Result<PathBuf> {
        let ciphertext_name = self.get_ciphertext_name(cleartext_path, &parent_dir_id)?;
        let mut path = self
            .vault
            .path()
            .join("d")
            .join(self.vault.cryptor().hash_dir_id(parent_dir_id).unwrap());

        if ciphertext_name.len() > self.vault.config().claims.shortening_threshold as usize {
            // TODO: This doesn't seem to be working correctly
            let hash = Sha1::new().chain_update(ciphertext_name).finalize();
            path = path.join(Base64Url::encode_string(&hash));
            path.set_extension("c9s");
        } else {
            path = path.join(ciphertext_name);
            path.set_extension("c9r");
        }

        Ok(path)
    }

    // TODO: Be more careful about unwrap/unwrap_or_default
    fn get_cleartext_name(
        &self,
        ciphertext_path: impl AsRef<Path>,
        parent_dir_id: impl AsRef<str>,
    ) -> io::Result<String> {
        let extension = ciphertext_path.as_ref().extension().unwrap();

        if extension == "c9s" {
            let mut ciphertext_name = PathBuf::from(fs::read_to_string(
                ciphertext_path.as_ref().join("name.c9s"),
            )?);

            // Remove .c9r from name
            ciphertext_name.set_extension("");

            self.vault
                .cryptor()
                .decrypt_name(ciphertext_name.to_string_lossy(), parent_dir_id)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        } else {
            let stem = ciphertext_path.as_ref().file_stem().unwrap_or_default();

            self.vault
                .cryptor()
                .decrypt_name(stem.to_string_lossy(), parent_dir_id)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        }
    }

    fn get_dir_id(&self, cleartext_dir: impl AsRef<Path>) -> io::Result<String> {
        let parent_dir_id = match cleartext_dir.as_ref().parent() {
            Some(parent) => self.get_dir_id(parent)?,
            None => return Ok(String::new()),
        };

        fs::read_to_string(
            self.get_ciphertext_path(cleartext_dir, parent_dir_id)?
                .join("dir.c9r"),
        )
    }

    fn get_virtual_dir_entry(
        &self,
        cleartext_path: impl AsRef<Path>,
        parent_dir_id: impl AsRef<str>,
    ) -> io::Result<DirEntry> {
        let ciphertext_path = self.get_ciphertext_path(cleartext_path, parent_dir_id)?;

        if ciphertext_path.is_file() {
            let meta = ciphertext_path.metadata()?;
            let size = util::get_cleartext_size(self.vault.cryptor(), meta.len());
            return Ok(DirEntry {
                kind: FileKind::File,
                size,
                metadata: meta,
            });
        }

        if ciphertext_path.is_dir() && ciphertext_path.join("contents.c9r").is_file() {
            let meta = ciphertext_path.join("contents.c9r").metadata()?;
            let size = util::get_cleartext_size(self.vault.cryptor(), meta.len());
            return Ok(DirEntry {
                kind: FileKind::File,
                size,
                metadata: meta,
            });
        }

        if ciphertext_path.is_dir() && ciphertext_path.join("dir.c9r").is_file() {
            let dir_id = fs::read_to_string(ciphertext_path.join("dir.c9r"))?;
            let hashed_dir_path = self
                .vault
                .path()
                .join("d")
                .join(self.vault.cryptor().hash_dir_id(dir_id).unwrap());
            let meta = hashed_dir_path.metadata()?;
            return Ok(DirEntry {
                kind: FileKind::Directory,
                size: meta.len(),
                metadata: meta,
            });
        }

        if ciphertext_path.is_dir() && ciphertext_path.join("symlink.c9r").is_file() {
            let meta = ciphertext_path.join("symlink.c9r").metadata()?;
            let size = util::get_cleartext_size(self.vault.cryptor(), meta.len());
            return Ok(DirEntry {
                kind: FileKind::Symlink,
                size,
                metadata: meta,
            });
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid file type",
        ))
    }

    fn get_virtual_dir_entries(
        &self,
        cleartext_dir: impl AsRef<Path>,
    ) -> io::Result<BTreeMap<PathBuf, DirEntry>> {
        let dir_id = self.get_dir_id(&cleartext_dir)?;
        let hashed_dir_path = self
            .vault
            .path()
            .join("d")
            .join(self.vault.cryptor().hash_dir_id(&dir_id).unwrap());

        let ciphertext_entries = hashed_dir_path
            .read_dir()?
            .collect::<io::Result<Vec<_>>>()?;

        let mut cleartext_entries: BTreeMap<PathBuf, DirEntry> = Default::default();
        for entry in ciphertext_entries {
            if entry.file_name() == "dirid.c9r" {
                continue;
            }

            let cleartext_name = self.get_cleartext_name(entry.path(), &dir_id)?;
            let cleartext_path = cleartext_dir.as_ref().join(&cleartext_name);
            let entry = self.get_virtual_dir_entry(&cleartext_path, &dir_id)?;
            cleartext_entries.insert(cleartext_path, entry);
        }

        Ok(cleartext_entries)
    }

    fn get_link_target(
        &self,
        cleartext_path: impl AsRef<Path>,
        parent_dir_id: impl AsRef<str>,
    ) -> io::Result<String> {
        let ciphertext_path = self.get_ciphertext_path(&cleartext_path, &parent_dir_id)?;
        let encrypted_link_path = ciphertext_path.join("symlink.c9r");

        if encrypted_link_path.is_file() {
            let mut decrypted = String::new();
            let file = File::open(encrypted_link_path)?;
            EncryptedStream::open(self.vault.cryptor(), file.metadata()?.len(), file)?
                .read_to_string(&mut decrypted)?;

            return Ok(decrypted);
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid file type",
        ))
    }

    fn open_file(
        &self,
        cleartext_path: impl AsRef<Path>,
        parent_dir_id: impl AsRef<str>,
    ) -> io::Result<EncryptedStream<'v, File>> {
        let ciphertext_path = self.get_ciphertext_path(cleartext_path, parent_dir_id)?;

        let file = if ciphertext_path.join("contents.c9r").is_file() {
            File::open(ciphertext_path.join("contents.c9r"))?
        } else {
            File::open(ciphertext_path)?
        };

        EncryptedStream::open(self.vault.cryptor(), file.metadata()?.len(), file)
    }
}
