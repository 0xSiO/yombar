use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fmt::Debug,
    fs::{self, File, FileTimes, Metadata, OpenOptions, Permissions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use crate::{crypto::FileCryptor, util, Result, Vault};

mod encrypted_file;
pub mod fuse;
mod translator;

use color_eyre::eyre::bail;
pub use encrypted_file::EncryptedFile;
use translator::Translator;
use uuid::Uuid;

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

#[derive(Debug, Copy, Clone)]
pub struct EncryptedFileSystem<'v> {
    vault: &'v Vault,
    translator: Translator<'v>,
}

impl<'v> EncryptedFileSystem<'v> {
    pub fn new(vault: &'v Vault) -> Self {
        Self {
            vault,
            translator: Translator::new(vault),
        }
    }

    fn root_dir(&self) -> PathBuf {
        self.vault
            .path()
            .join("d")
            .join(self.vault.cryptor().hash_dir_id("").unwrap())
    }

    fn dir_entry(&self, cleartext_path: impl AsRef<Path>) -> Result<DirEntry> {
        // TOOD: Handle case with no parent
        let parent_dir_id = self
            .translator
            .get_dir_id(cleartext_path.as_ref().parent().unwrap())?;
        let ciphertext_path = self
            .translator
            .get_ciphertext_path(&cleartext_path, parent_dir_id)?;

        // File, full-length name
        if ciphertext_path.is_file() {
            let meta = ciphertext_path.metadata()?;
            let size = util::get_cleartext_size(self.vault.cryptor(), meta.len());
            return Ok(DirEntry {
                kind: FileKind::File,
                size,
                metadata: meta,
            });
        }

        // File, shortened name
        if ciphertext_path.is_dir() && ciphertext_path.join("contents.c9r").is_file() {
            let meta = ciphertext_path.join("contents.c9r").metadata()?;
            let size = util::get_cleartext_size(self.vault.cryptor(), meta.len());
            return Ok(DirEntry {
                kind: FileKind::File,
                size,
                metadata: meta,
            });
        }

        // Directory, either full-length or shortened name
        if ciphertext_path.is_dir() && ciphertext_path.join("dir.c9r").is_file() {
            let dir_id = self.translator.get_dir_id(&cleartext_path)?;
            let hashed_dir_id = self.vault.cryptor().hash_dir_id(dir_id).unwrap();
            let meta = self.vault.path().join("d").join(hashed_dir_id).metadata()?;
            return Ok(DirEntry {
                kind: FileKind::Directory,
                size: meta.len(),
                metadata: meta,
            });
        }

        // Symlink, either full-length or shortened name
        if ciphertext_path.is_dir() && ciphertext_path.join("symlink.c9r").is_file() {
            let meta = ciphertext_path.join("symlink.c9r").metadata()?;
            let size = util::get_cleartext_size(self.vault.cryptor(), meta.len());
            return Ok(DirEntry {
                kind: FileKind::Symlink,
                size,
                metadata: meta,
            });
        }

        bail!("invalid file type");
    }

    fn dir_entries(&self, cleartext_dir: impl AsRef<Path>) -> Result<BTreeMap<PathBuf, DirEntry>> {
        let dir_id = self.translator.get_dir_id(&cleartext_dir)?;
        let hashed_dir_id = self.vault.cryptor().hash_dir_id(&dir_id).unwrap();
        let hashed_dir_path = self.vault.path().join("d").join(hashed_dir_id);
        let ciphertext_entries = hashed_dir_path
            .read_dir()?
            .collect::<io::Result<Vec<_>>>()?;

        let mut cleartext_entries: BTreeMap<PathBuf, DirEntry> = Default::default();
        for entry in ciphertext_entries {
            if entry.file_name() == "dirid.c9r" {
                continue;
            }

            let cleartext_name = self.translator.get_cleartext_name(entry.path(), &dir_id)?;
            let cleartext_path = cleartext_dir.as_ref().join(&cleartext_name);
            let entry = self.dir_entry(&cleartext_path)?;
            cleartext_entries.insert(cleartext_path, entry);
        }

        Ok(cleartext_entries)
    }

    fn link_target(&self, cleartext_path: impl AsRef<Path> + Debug) -> Result<PathBuf> {
        let dir_id = self.translator.get_dir_id(&cleartext_path)?;
        let ciphertext_path = self
            .translator
            .get_ciphertext_path(&cleartext_path, dir_id)?
            .join("symlink.c9r");

        if ciphertext_path.is_file() {
            let mut decrypted = String::new();
            let mut options = OpenOptions::new();
            options.read(true);
            EncryptedFile::open(self.vault.cryptor(), ciphertext_path, options)?
                .read_to_string(&mut decrypted)?;

            return Ok(decrypted.into());
        }

        Err(io::Error::new(io::ErrorKind::InvalidData, "not a link").into())
    }

    fn open_file(
        &self,
        cleartext_path: impl AsRef<Path>,
        options: OpenOptions,
        append: bool,
    ) -> Result<EncryptedFile<'v>> {
        let dir_id = self.translator.get_dir_id(&cleartext_path)?;
        let mut ciphertext_path = self
            .translator
            .get_ciphertext_path(cleartext_path, dir_id)?;

        if ciphertext_path.join("contents.c9r").is_file() {
            ciphertext_path = ciphertext_path.join("contents.c9r");
        }

        let mut file = EncryptedFile::open(self.vault.cryptor(), ciphertext_path, options)?;
        file.set_append(append);

        Ok(file)
    }

    fn rename_file(
        &self,
        old_parent: impl AsRef<Path>,
        old_name: &OsStr,
        new_parent: impl AsRef<Path>,
        new_name: &OsStr,
    ) -> Result<()> {
        let old_dir_id = self.translator.get_dir_id(&old_parent)?;
        let old_ciphertext_path = self
            .translator
            .get_ciphertext_path(old_parent.as_ref().join(old_name), old_dir_id)?;
        let new_dir_id = self.translator.get_dir_id(&new_parent)?;
        let new_ciphertext_path = self
            .translator
            .get_ciphertext_path(new_parent.as_ref().join(new_name), &new_dir_id)?;

        // These are probably fine to unwrap since get_ciphertext_path always gives a c9r/c9s
        // extension
        match (
            old_ciphertext_path.extension().unwrap().to_str().unwrap(),
            new_ciphertext_path.extension().unwrap().to_str().unwrap(),
        ) {
            ("c9r", "c9r") => {
                fs::rename(&old_ciphertext_path, new_ciphertext_path)?;
            }
            ("c9r", "c9s") => {
                let new_ciphertext_name = self
                    .translator
                    .get_full_ciphertext_name(new_parent.as_ref().join(new_name), new_dir_id)?;
                fs::create_dir_all(&new_ciphertext_path)?;
                fs::write(new_ciphertext_path.join("name.c9s"), new_ciphertext_name)?;
                fs::rename(
                    &old_ciphertext_path,
                    new_ciphertext_path.join("contents.c9r"),
                )?;
            }
            ("c9s", "c9r") => {
                fs::rename(
                    old_ciphertext_path.join("contents.c9r"),
                    new_ciphertext_path,
                )?;
                fs::remove_dir_all(old_ciphertext_path)?;
            }
            ("c9s", "c9s") => {
                let new_ciphertext_name = self
                    .translator
                    .get_full_ciphertext_name(new_parent.as_ref().join(new_name), new_dir_id)?;
                fs::create_dir_all(&new_ciphertext_path)?;
                fs::write(new_ciphertext_path.join("name.c9s"), new_ciphertext_name)?;
                fs::rename(
                    old_ciphertext_path.join("contents.c9r"),
                    new_ciphertext_path.join("contents.c9r"),
                )?;
                fs::remove_dir_all(old_ciphertext_path)?;
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    fn rename_dir(
        &self,
        old_parent: impl AsRef<Path>,
        old_name: &OsStr,
        new_parent: impl AsRef<Path>,
        new_name: &OsStr,
    ) -> Result<()> {
        let old_dir_id = self.translator.get_dir_id(&old_parent)?;
        let old_ciphertext_path = self
            .translator
            .get_ciphertext_path(old_parent.as_ref().join(old_name), old_dir_id)?;
        let new_dir_id = self.translator.get_dir_id(&new_parent)?;
        let new_ciphertext_path = self
            .translator
            .get_ciphertext_path(new_parent.as_ref().join(new_name), &new_dir_id)?;

        // These are probably fine to unwrap since get_ciphertext_path always gives a c9r/c9s
        // extension
        match (
            old_ciphertext_path.extension().unwrap().to_str().unwrap(),
            new_ciphertext_path.extension().unwrap().to_str().unwrap(),
        ) {
            ("c9r", "c9r") => {
                fs::rename(&old_ciphertext_path, new_ciphertext_path)?;
            }
            ("c9s", "c9r") => {
                fs::create_dir_all(&new_ciphertext_path)?;
                fs::rename(
                    old_ciphertext_path.join("dir.c9r"),
                    new_ciphertext_path.join("dir.c9r"),
                )?;
                fs::remove_dir_all(old_ciphertext_path)?;
            }
            (_, "c9s") => {
                let new_ciphertext_name = self
                    .translator
                    .get_full_ciphertext_name(new_parent.as_ref().join(new_name), new_dir_id)?;
                fs::create_dir_all(&new_ciphertext_path)?;
                fs::write(new_ciphertext_path.join("name.c9s"), new_ciphertext_name)?;
                fs::rename(
                    old_ciphertext_path.join("dir.c9r"),
                    new_ciphertext_path.join("dir.c9r"),
                )?;
                let _ = fs::remove_dir_all(old_ciphertext_path);
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    fn rename_link(
        &self,
        old_parent: impl AsRef<Path>,
        old_name: &OsStr,
        new_parent: impl AsRef<Path>,
        new_name: &OsStr,
    ) -> Result<()> {
        let old_dir_id = self.translator.get_dir_id(&old_parent)?;
        let old_ciphertext_path = self
            .translator
            .get_ciphertext_path(old_parent.as_ref().join(old_name), old_dir_id)?;
        let new_dir_id = self.translator.get_dir_id(&new_parent)?;
        let new_ciphertext_path = self
            .translator
            .get_ciphertext_path(new_parent.as_ref().join(new_name), &new_dir_id)?;

        // These are probably fine to unwrap since get_ciphertext_path always gives a c9r/c9s
        // extension
        match (
            old_ciphertext_path.extension().unwrap().to_str().unwrap(),
            new_ciphertext_path.extension().unwrap().to_str().unwrap(),
        ) {
            ("c9r", "c9r") => {
                fs::rename(&old_ciphertext_path, new_ciphertext_path)?;
            }
            ("c9s", "c9r") => {
                fs::create_dir_all(&new_ciphertext_path)?;
                fs::rename(
                    old_ciphertext_path.join("symlink.c9r"),
                    new_ciphertext_path.join("symlink.c9r"),
                )?;
                fs::remove_dir_all(old_ciphertext_path)?;
            }
            (_, "c9s") => {
                let new_ciphertext_name = self
                    .translator
                    .get_full_ciphertext_name(new_parent.as_ref().join(new_name), new_dir_id)?;
                fs::create_dir_all(&new_ciphertext_path)?;
                fs::write(new_ciphertext_path.join("name.c9s"), new_ciphertext_name)?;
                fs::rename(
                    old_ciphertext_path.join("symlink.c9r"),
                    new_ciphertext_path.join("symlink.c9r"),
                )?;
                let _ = fs::remove_dir_all(old_ciphertext_path);
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    fn rename(
        &self,
        old_parent: impl AsRef<Path>,
        old_name: &OsStr,
        new_parent: impl AsRef<Path>,
        new_name: &OsStr,
    ) -> Result<()> {
        let old_entry = self.dir_entry(old_parent.as_ref().join(old_name))?;
        match old_entry.kind {
            FileKind::File => self.rename_file(old_parent, old_name, new_parent, new_name),
            FileKind::Directory => self.rename_dir(old_parent, old_name, new_parent, new_name),
            FileKind::Symlink => self.rename_link(old_parent, old_name, new_parent, new_name),
        }
    }

    fn mknod(
        &self,
        parent: impl AsRef<Path> + Debug,
        name: &OsStr,
        permissions: Permissions,
    ) -> Result<DirEntry> {
        let parent_dir_id = self.translator.get_dir_id(&parent)?;
        let mut ciphertext_path = self
            .translator
            .get_ciphertext_path(parent.as_ref().join(name), &parent_dir_id)?;

        if ciphertext_path.extension().unwrap().to_str().unwrap() == "c9s" {
            fs::create_dir_all(&ciphertext_path)?;
            let full_name = self
                .translator
                .get_full_ciphertext_name(parent.as_ref().join(name), parent_dir_id)?;
            fs::write(ciphertext_path.join("name.c9s"), full_name)?;
            ciphertext_path = ciphertext_path.join("contents.c9r");
        }

        let file = EncryptedFile::create_new(self.vault.cryptor(), &ciphertext_path)?;
        fs::set_permissions(ciphertext_path, permissions)?;

        Ok(DirEntry {
            kind: FileKind::File,
            size: 0,
            metadata: file.metadata()?,
        })
    }

    fn mkdir(
        &self,
        parent: impl AsRef<Path>,
        name: &OsStr,
        permissions: Permissions,
    ) -> Result<DirEntry> {
        let parent_dir_id = self.translator.get_dir_id(&parent)?;
        let ciphertext_path = self
            .translator
            .get_ciphertext_path(parent.as_ref().join(name), &parent_dir_id)?;

        fs::create_dir_all(&ciphertext_path)?;
        let dir_id = Uuid::new_v4().to_string();
        fs::write(ciphertext_path.join("dir.c9r"), &dir_id)?;

        if ciphertext_path.extension().unwrap().to_str().unwrap() == "c9s" {
            let full_name = self
                .translator
                .get_full_ciphertext_name(parent.as_ref().join(name), parent_dir_id)?;
            fs::write(ciphertext_path.join("name.c9s"), full_name)?;
        }

        let hashed_dir_id = self.vault.cryptor().hash_dir_id(dir_id).unwrap();
        let hashed_dir_path = self.vault.path().join("d").join(hashed_dir_id);
        fs::create_dir_all(&hashed_dir_path)?;
        fs::set_permissions(&hashed_dir_path, permissions)?;
        // TODO: Write encrypted dirid.c9r under hashed dir path

        let meta = hashed_dir_path.metadata()?;
        Ok(DirEntry {
            kind: FileKind::Directory,
            size: meta.len(),
            metadata: meta,
        })
    }

    fn symlink(
        &self,
        parent: impl AsRef<Path>,
        link_name: &OsStr,
        target: impl AsRef<Path>,
    ) -> Result<DirEntry> {
        let parent_dir_id = self.translator.get_dir_id(&parent)?;
        let ciphertext_path = self
            .translator
            .get_ciphertext_path(parent.as_ref().join(link_name), &parent_dir_id)?;

        fs::create_dir_all(&ciphertext_path)?;

        if ciphertext_path.extension().unwrap().to_str().unwrap() == "c9s" {
            let full_name = self
                .translator
                .get_full_ciphertext_name(parent.as_ref().join(link_name), parent_dir_id)?;
            fs::write(ciphertext_path.join("name.c9s"), full_name)?;
        }

        let mut symlink =
            EncryptedFile::create_new(self.vault.cryptor(), ciphertext_path.join("symlink.c9r"))?;
        symlink.write_all(target.as_ref().as_os_str().as_encoded_bytes())?;
        symlink.flush()?;

        Ok(DirEntry {
            kind: FileKind::Symlink,
            size: symlink.len()?,
            metadata: symlink.metadata()?,
        })
    }

    fn unlink(&self, parent: impl AsRef<Path>, name: &OsStr) -> Result<()> {
        let parent_dir_id = self.translator.get_dir_id(&parent)?;
        let ciphertext_path = self
            .translator
            .get_ciphertext_path(parent.as_ref().join(name), parent_dir_id)?;

        if ciphertext_path.is_file() {
            Ok(fs::remove_file(ciphertext_path)?)
        } else {
            Ok(fs::remove_dir_all(&ciphertext_path)?)
        }
    }

    fn rmdir(&self, parent: impl AsRef<Path>, name: &OsStr) -> Result<()> {
        let dir_id = self.translator.get_dir_id(parent.as_ref().join(name))?;
        let hashed_dir_id = self.vault.cryptor().hash_dir_id(dir_id).unwrap();
        fs::remove_dir_all(self.vault.path().join("d").join(hashed_dir_id))?;

        let parent_dir_id = self.translator.get_dir_id(&parent)?;
        let ciphertext_path = self
            .translator
            .get_ciphertext_path(parent.as_ref().join(name), parent_dir_id)?;
        Ok(fs::remove_dir_all(ciphertext_path)?)
    }

    fn set_permissions(
        &self,
        cleartext_path: impl AsRef<Path>,
        permissions: Permissions,
    ) -> Result<()> {
        let entry = self.dir_entry(&cleartext_path)?;

        match entry.kind {
            FileKind::File => {
                let parent_dir_id = self
                    .translator
                    .get_dir_id(cleartext_path.as_ref().parent().unwrap())?;
                let mut ciphertext_path = self
                    .translator
                    .get_ciphertext_path(&cleartext_path, parent_dir_id)?;

                if ciphertext_path.is_dir() && ciphertext_path.join("contents.c9r").is_file() {
                    ciphertext_path = ciphertext_path.join("contents.c9r");
                }

                fs::set_permissions(ciphertext_path, permissions)?;
            }
            FileKind::Directory => {
                let dir_id = self.translator.get_dir_id(&cleartext_path)?;
                let hashed_dir_id = self.vault.cryptor().hash_dir_id(dir_id).unwrap();
                fs::set_permissions(self.vault.path().join("d").join(hashed_dir_id), permissions)?;
            }
            FileKind::Symlink => {
                let parent_dir_id = self
                    .translator
                    .get_dir_id(cleartext_path.as_ref().parent().unwrap())?;
                let ciphertext_path = self
                    .translator
                    .get_ciphertext_path(&cleartext_path, parent_dir_id)?;
                fs::set_permissions(ciphertext_path.join("symlink.c9r"), permissions)?;
            }
        }

        Ok(())
    }

    fn set_times(&self, cleartext_path: impl AsRef<Path>, times: FileTimes) -> Result<()> {
        let entry = self.dir_entry(&cleartext_path)?;

        match entry.kind {
            FileKind::File => {
                let parent_dir_id = self
                    .translator
                    .get_dir_id(cleartext_path.as_ref().parent().unwrap())?;
                let mut ciphertext_path = self
                    .translator
                    .get_ciphertext_path(&cleartext_path, parent_dir_id)?;

                if ciphertext_path.is_dir() && ciphertext_path.join("contents.c9r").is_file() {
                    ciphertext_path = ciphertext_path.join("contents.c9r");
                }

                let file = File::open(ciphertext_path)?;
                file.set_times(times)?;
            }
            FileKind::Directory => {
                // let dir_id = self.translator.get_dir_id(&cleartext_path)?;
                // let hashed_dir_id = self.vault.cryptor().hash_dir_id(dir_id).unwrap();
                bail!("not yet implemented");
            }
            FileKind::Symlink => {
                let parent_dir_id = self
                    .translator
                    .get_dir_id(cleartext_path.as_ref().parent().unwrap())?;
                let ciphertext_path = self
                    .translator
                    .get_ciphertext_path(&cleartext_path, parent_dir_id)?;

                let file = File::open(ciphertext_path.join("symlink.c9r"))?;
                file.set_times(times)?;
            }
        }

        Ok(())
    }
}
