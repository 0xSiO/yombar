use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata},
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use crate::{
    crypto::FileCryptor,
    io::{DecryptStream, EncryptStream},
    Vault,
};

pub mod fuse;

#[derive(Debug, Copy, Clone, PartialEq)]
enum FileKind {
    File,
    Directory,
    Symlink,
}

type DirEntries = BTreeMap<PathBuf, (FileKind, Metadata)>;

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
        let mut path = self.vault.path().join("d").join(
            self.vault
                .cryptor()
                .hash_dir_id(&parent_dir_id)
                .unwrap()
                .join(self.get_ciphertext_name(cleartext_path, parent_dir_id)?),
        );
        path.set_extension("c9r");

        Ok(path)
    }

    // TODO: Handle case when name is too long to be stored in the file stem
    fn get_cleartext_name(
        &self,
        ciphertext_path: impl AsRef<Path>,
        parent_dir_id: impl AsRef<str>,
    ) -> io::Result<String> {
        // TODO: unwrap_or_default may not be the best idea
        let stem = ciphertext_path.as_ref().file_stem().unwrap_or_default();

        self.vault
            .cryptor()
            .decrypt_name(stem.to_string_lossy(), parent_dir_id)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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

    fn get_virtual_file_info(
        &self,
        cleartext_path: impl AsRef<Path>,
        parent_dir_id: impl AsRef<str>,
    ) -> io::Result<(FileKind, Metadata)> {
        let ciphertext_path = self.get_ciphertext_path(cleartext_path, parent_dir_id)?;

        if ciphertext_path.is_file() {
            return Ok((FileKind::File, ciphertext_path.metadata()?));
        }

        if ciphertext_path.is_dir() && ciphertext_path.join("dir.c9r").is_file() {
            let dir_id = fs::read_to_string(ciphertext_path.join("dir.c9r"))?;
            let hashed_dir_path = self
                .vault
                .path()
                .join("d")
                .join(self.vault.cryptor().hash_dir_id(dir_id).unwrap());
            return Ok((FileKind::Directory, hashed_dir_path.metadata()?));
        }

        if ciphertext_path.is_dir() && ciphertext_path.join("symlink.c9r").is_file() {
            return Ok((
                FileKind::Symlink,
                ciphertext_path.join("symlink.c9r").metadata()?,
            ));
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid file type",
        ))
    }

    fn get_virtual_dir_entries(&self, cleartext_dir: impl AsRef<Path>) -> io::Result<DirEntries> {
        let dir_id = self.get_dir_id(&cleartext_dir)?;
        let hashed_dir_path = self
            .vault
            .path()
            .join("d")
            .join(self.vault.cryptor().hash_dir_id(&dir_id).unwrap());

        let ciphertext_entries = hashed_dir_path
            .read_dir()?
            .collect::<io::Result<Vec<_>>>()?;

        let mut cleartext_entries: DirEntries = Default::default();
        for entry in ciphertext_entries {
            if entry.file_name() == "dirid.c9r" {
                continue;
            }

            let cleartext_name = self.get_cleartext_name(entry.path(), &dir_id)?;
            let (file_kind, metadata) =
                self.get_virtual_file_info(cleartext_dir.as_ref().join(&cleartext_name), &dir_id)?;

            cleartext_entries.insert(
                cleartext_dir.as_ref().join(cleartext_name),
                (file_kind, metadata),
            );
        }

        Ok(cleartext_entries)
    }

    #[allow(dead_code)]
    fn get_virtual_reader(
        &self,
        cleartext_path: impl AsRef<Path>,
        parent_dir_id: impl AsRef<str>,
    ) -> io::Result<DecryptStream<'_, impl Read>> {
        let ciphertext_path = self.get_ciphertext_path(cleartext_path, parent_dir_id)?;
        let file = File::open(ciphertext_path)?;

        Ok(DecryptStream::new(
            self.vault.cryptor(),
            BufReader::new(file),
        ))
    }

    #[allow(dead_code)]
    fn get_virtual_writer(
        &self,
        cleartext_path: impl AsRef<Path>,
        parent_dir_id: impl AsRef<str>,
    ) -> io::Result<EncryptStream<'_, impl Write>> {
        let ciphertext_path = self.get_ciphertext_path(cleartext_path, parent_dir_id)?;
        let file = File::open(ciphertext_path)?;

        Ok(EncryptStream::new(
            self.vault.cryptor(),
            // TODO: Is it okay to re-encrypt everything with a new content key like this?
            self.vault.cryptor().new_header()?,
            BufWriter::new(file),
        ))
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
            DecryptStream::new(
                self.vault.cryptor(),
                BufReader::new(File::open(encrypted_link_path)?),
            )
            .read_to_string(&mut decrypted)?;

            return Ok(decrypted);
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid file type",
        ))
    }
}
