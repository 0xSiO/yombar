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
            .unwrap()
            + ".c9r")
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
            let hash = Sha1::new().chain_update(ciphertext_name).finalize();
            path = path.join(Base64Url::encode_string(&hash) + ".c9s");
        } else {
            path = path.join(ciphertext_name);
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

    // TODO: Need to write an abstraction for encrypted files so I don't need to deal with all this
    //       path nonsense
    // fn rename_file(
    //     &self,
    //     old_parent: impl AsRef<Path>,
    //     old_name: &OsStr,
    //     new_parent: impl AsRef<Path>,
    //     new_name: &OsStr,
    // ) -> io::Result<()> {
    //     let old_dir_id = self.get_dir_id(old_parent)?;
    //     let old_ciphertext_path =
    //         self.get_ciphertext_path(old_parent.as_ref().join(old_name), old_dir_id)?;
    //     let new_dir_id = self.get_dir_id(new_parent)?;
    //     let new_ciphertext_path =
    //         self.get_ciphertext_path(new_parent.as_ref().join(new_name), new_dir_id)?;
    //
    //     match (
    //         old_ciphertext_path.extension().unwrap(),
    //         new_ciphertext_path.extension().unwrap(),
    //     ) {
    //         ("c9r", "c9r") => fs::rename(old_ciphertext_path, new_ciphertext_path),
    //         ("c9r", "c9s") => {
    //             fs::create_dir_all(new_ciphertext_path)?;
    //             fs::write(
    //                 new_ciphertext_path.join("name.c9s"),
    //                 self.get_ciphertext_name(new_parent.as_ref().join(new_name), new_dir_id)?,
    //             )?;
    //             fs::rename(
    //                 old_ciphertext_path,
    //                 new_ciphertext_path.join("contents.c9r"),
    //             )
    //         }
    //         ("c9s", "c9r") => {}
    //         ("c9s", "c9s") => {}
    //     }
    // }
}
