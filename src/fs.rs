use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fmt::Debug,
    fs::{self, File, FileTimes, Metadata, OpenOptions, Permissions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use color_eyre::eyre::bail;
use uuid::Uuid;

use crate::{crypto::FileCryptor, util, vault::Vault, Result};

mod encrypted_file;
mod translator;

#[cfg(unix)]
pub mod fuse;
pub mod webdav;

pub use encrypted_file::EncryptedFile;
pub use translator::Translator;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum FileKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub kind: FileKind,
    pub size: u64,
    pub metadata: Metadata,
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

    pub(crate) fn root_dir(&self) -> PathBuf {
        self.vault
            .path()
            .join("d")
            .join(self.vault.cryptor().hash_dir_id("").unwrap())
    }

    pub fn dir_entry(&self, cleartext_path: impl AsRef<Path>) -> Result<DirEntry> {
        if cleartext_path.as_ref().parent().is_none() {
            let metadata = self.root_dir().metadata()?;
            return Ok(DirEntry {
                kind: FileKind::Directory,
                size: metadata.len(),
                metadata,
            });
        }

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
            let hashed_dir_id = self.vault.cryptor().hash_dir_id(dir_id)?;
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

        bail!("invalid or unknown ciphertext path: {ciphertext_path:?}");
    }

    pub fn dir_entries(
        &self,
        cleartext_dir: impl AsRef<Path>,
    ) -> Result<BTreeMap<PathBuf, DirEntry>> {
        let dir_id = self.translator.get_dir_id(&cleartext_dir)?;
        let hashed_dir_id = self.vault.cryptor().hash_dir_id(&dir_id)?;
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

    pub fn link_target(&self, cleartext_path: impl AsRef<Path> + Debug) -> Result<PathBuf> {
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

            Ok(decrypted.into())
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "not a link").into())
        }
    }

    pub fn open_file(
        &self,
        cleartext_path: impl AsRef<Path>,
        options: OpenOptions,
    ) -> Result<EncryptedFile<'v>> {
        let dir_id = self.translator.get_dir_id(&cleartext_path)?;
        let mut ciphertext_path = self
            .translator
            .get_ciphertext_path(cleartext_path, dir_id)?;

        if ciphertext_path.join("contents.c9r").is_file() {
            ciphertext_path = ciphertext_path.join("contents.c9r");
        }

        EncryptedFile::open(self.vault.cryptor(), ciphertext_path, options)
    }

    pub fn rename_file(
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
                    .get_full_ciphertext_name(new_name, new_dir_id)?;
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
                    .get_full_ciphertext_name(new_name, new_dir_id)?;
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

    pub fn rename_dir(
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
                    .get_full_ciphertext_name(new_name, new_dir_id)?;
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

    pub fn rename_link(
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
                    .get_full_ciphertext_name(new_name, new_dir_id)?;
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

    pub fn rename(
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

    pub fn mknod(
        &self,
        parent: impl AsRef<Path> + Debug,
        name: &OsStr,
        permissions: Permissions,
    ) -> Result<DirEntry> {
        let parent_dir_id = self.translator.get_dir_id(&parent)?;
        let mut ciphertext_path = self
            .translator
            .get_ciphertext_path(parent.as_ref().join(name), &parent_dir_id)?;

        // Probably fine to unwrap since get_ciphertext_path always gives a c9r/c9s extension
        if ciphertext_path.extension().unwrap() == "c9s" {
            fs::create_dir_all(&ciphertext_path)?;
            let full_name = self
                .translator
                .get_full_ciphertext_name(name, parent_dir_id)?;
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

    pub fn mkdir(
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

        // Probably fine to unwrap since get_ciphertext_path always gives a c9r/c9s extension
        if ciphertext_path.extension().unwrap() == "c9s" {
            let full_name = self
                .translator
                .get_full_ciphertext_name(name, parent_dir_id)?;
            fs::write(ciphertext_path.join("name.c9s"), full_name)?;
        }

        let hashed_dir_id = self.vault.cryptor().hash_dir_id(&dir_id)?;
        let hashed_dir_path = self.vault.path().join("d").join(hashed_dir_id);
        fs::create_dir_all(&hashed_dir_path)?;
        fs::set_permissions(&hashed_dir_path, permissions)?;
        EncryptedFile::create_new(self.vault.cryptor(), hashed_dir_path.join("dirid.c9r"))?
            .write_all(dir_id.as_bytes())?;

        let meta = hashed_dir_path.metadata()?;
        Ok(DirEntry {
            kind: FileKind::Directory,
            size: meta.len(),
            metadata: meta,
        })
    }

    pub fn symlink(
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

        // Probably fine to unwrap since get_ciphertext_path always gives a c9r/c9s extension
        if ciphertext_path.extension().unwrap() == "c9s" {
            let full_name = self
                .translator
                .get_full_ciphertext_name(link_name, parent_dir_id)?;
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

    pub fn unlink(&self, parent: impl AsRef<Path>, name: &OsStr) -> Result<()> {
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

    pub fn rmdir(&self, parent: impl AsRef<Path>, name: &OsStr) -> Result<()> {
        let dir_id = self.translator.get_dir_id(parent.as_ref().join(name))?;
        let hashed_dir_id = self.vault.cryptor().hash_dir_id(dir_id)?;
        fs::remove_dir_all(self.vault.path().join("d").join(hashed_dir_id))?;

        let parent_dir_id = self.translator.get_dir_id(&parent)?;
        let ciphertext_path = self
            .translator
            .get_ciphertext_path(parent.as_ref().join(name), parent_dir_id)?;
        Ok(fs::remove_dir_all(ciphertext_path)?)
    }

    pub fn set_permissions(
        &self,
        cleartext_path: impl AsRef<Path>,
        permissions: Permissions,
    ) -> Result<()> {
        let entry = self.dir_entry(&cleartext_path)?;

        match entry.kind {
            FileKind::File => {
                // Ok to unwrap, top-level files will just have an empty parent
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
                let hashed_dir_id = self.vault.cryptor().hash_dir_id(dir_id)?;
                fs::set_permissions(self.vault.path().join("d").join(hashed_dir_id), permissions)?;
            }
            FileKind::Symlink => {
                // Ok to unwrap, top-level links will just have an empty parent
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

    pub fn set_times(&self, cleartext_path: impl AsRef<Path>, times: FileTimes) -> Result<()> {
        let entry = self.dir_entry(&cleartext_path)?;

        match entry.kind {
            FileKind::File => {
                // Ok to unwrap, top-level files will just have an empty parent
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
                let dir_id = self.translator.get_dir_id(&cleartext_path)?;
                let hashed_dir_id = self.vault.cryptor().hash_dir_id(dir_id)?;
                let dir = File::open(self.vault.path().join("d").join(hashed_dir_id))?;
                dir.set_times(times)?;
            }
            FileKind::Symlink => {
                // Ok to unwrap, top-level links will just have an empty parent
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

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::time::UNIX_EPOCH;

    use super::*;

    fn get_vault_siv_ctrmac() -> Result<Vault> {
        Vault::open(
            "tests/fixtures/vault_v8_siv_ctrmac",
            String::from("password"),
        )
    }

    fn get_vault_siv_gcm() -> Result<Vault> {
        Vault::open("tests/fixtures/vault_v8_siv_gcm", String::from("password"))
    }

    fn rename_test_helper(
        fs: &EncryptedFileSystem,
        old_parent: impl AsRef<Path>,
        old_name: &OsStr,
        new_parent: impl AsRef<Path>,
        new_name: &OsStr,
        expected_kind: FileKind,
    ) -> Result<()> {
        assert_eq!(
            fs.dir_entry(old_parent.as_ref().join(old_name))?.kind,
            expected_kind
        );
        assert!(fs.dir_entry(new_parent.as_ref().join(new_name)).is_err());

        fs.rename(old_parent.as_ref(), old_name, new_parent.as_ref(), new_name)?;

        assert_eq!(
            fs.dir_entry(new_parent.as_ref().join(new_name))?.kind,
            expected_kind
        );
        assert!(fs.dir_entry(old_parent.as_ref().join(old_name)).is_err());

        Ok(())
    }

    mod siv_ctrmac {
        use super::*;

        #[test]
        fn root_dir_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);
            assert_eq!(
                fs.root_dir(),
                vault.path().join("d/GI/YO5RUXD5NP6IP7GFAWSNT5IIEP6J7A")
            );

            Ok(())
        }

        #[test]
        fn dir_entry_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);

            let entry = fs.dir_entry("")?;
            assert_eq!(entry.kind, FileKind::Directory);

            let entry = fs.dir_entry("test_file.txt")?;
            assert_eq!(entry.kind, FileKind::File);
            assert_eq!(entry.size, 41);

            let entry = fs.dir_entry(
                "test_dir/test_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long.txt",
            )?;
            assert_eq!(entry.kind, FileKind::File);
            assert_eq!(entry.size, 29);

            let entry = fs.dir_entry("test_dir")?;
            assert_eq!(entry.kind, FileKind::Directory);

            let entry = fs.dir_entry(
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
            )?;
            assert_eq!(entry.kind, FileKind::Directory);
            assert_eq!(
                entry.size,
                vault
                    .path()
                    .join("d/55/YKAU6VJ4B7QTWNPM4GHQ66HJXT4OJA")
                    .metadata()?
                    .len()
            );

            let entry = fs.dir_entry("test_link")?;
            assert_eq!(entry.kind, FileKind::Symlink);
            assert_eq!(entry.size, 24);

            let entry = fs.dir_entry(
                "test_dir/test_link_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
            )?;
            assert_eq!(entry.kind, FileKind::Symlink);
            assert_eq!(entry.size, 148);

            assert!(fs.dir_entry("invalid.unknown").is_err());

            Ok(())
        }

        #[test]
        fn dir_entries_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);

            let entries = fs.dir_entries("")?;
            assert!(entries.len() > 1);
            let entry = entries.get(&PathBuf::from("test_file.txt")).unwrap();
            assert_eq!(entry.kind, FileKind::File);
            assert_eq!(entry.size, 41);

            let entries = fs.dir_entries("test_dir")?;
            assert!(entries.len() > 1);
            let entry = entries
                .get(&PathBuf::from("test_dir/test_file_2.txt"))
                .unwrap();
            assert_eq!(entry.kind, FileKind::File);
            assert_eq!(entry.size, 47);

            Ok(())
        }

        #[test]
        fn link_target_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);

            assert_eq!(
                fs.link_target("test_link")?,
                PathBuf::from("test_dir/test_file_2.txt")
            );

            assert_eq!(
                fs.link_target(
                    "test_dir/test_link_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long"
                )?,
                PathBuf::from(
                    "test_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long.txt"
                )
            );

            assert!(fs.link_target("test_file.txt").is_err());
            assert!(fs.link_target("invalid.unknown").is_err());

            Ok(())
        }

        #[test]
        fn open_file_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);

            let mut options = OpenOptions::new();
            options.read(true).write(true);
            assert!(fs.open_file("test_file.txt", options.clone()).is_ok());
            assert!(fs
                .open_file(
                    "test_dir/test_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long.txt",
                    options.clone()
                )
                .is_ok()
            );
            assert!(fs.open_file("invalid.unknown", options).is_err());

            Ok(())
        }

        #[test]
        fn rename_file_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);

            let name_1 = OsStr::new("rename_file_test_siv_ctrmac_1");
            let name_2 = OsStr::new("rename_file_test_siv_ctrmac_2");

            fs.mknod("", name_1, Permissions::from_mode(0o400))?;

            // short -> short
            rename_test_helper(&fs, "", name_1, "", name_2, FileKind::File)?;

            // short -> long
            rename_test_helper(
                &fs,
                "",
                name_2,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_2,
                FileKind::File
            )?;

            // long -> long
            rename_test_helper(
                &fs,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_2,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_1,
                FileKind::File
            )?;

            // long -> short
            rename_test_helper(
                &fs,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_1,
                "",
                name_2,
                FileKind::File
            )?;

            fs.unlink("", name_2)?;

            Ok(())
        }

        #[test]
        fn rename_dir_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);

            let name_1 = OsStr::new("rename_dir_test_siv_ctrmac_1");
            let name_2 = OsStr::new("rename_dir_test_siv_ctrmac_2");

            fs.mkdir("", name_1, Permissions::from_mode(0o755))?;

            // short -> short
            rename_test_helper(&fs, "", name_1, "", name_2, FileKind::Directory)?;

            // short -> long
            rename_test_helper(
                &fs,
                "",
                name_2,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_2,
                FileKind::Directory
            )?;

            // long -> long
            rename_test_helper(
                &fs,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_2,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_1,
                FileKind::Directory
            )?;

            // long -> short
            rename_test_helper(
                &fs,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_1,
                "",
                name_2,
                FileKind::Directory
            )?;

            fs.rmdir("", name_2)?;

            Ok(())
        }

        #[test]
        fn rename_link_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);

            let name_1 = OsStr::new("rename_link_test_siv_ctrmac_1");
            let name_2 = OsStr::new("rename_link_test_siv_ctrmac_2");

            fs.symlink("", name_1, "test_file.txt")?;

            // short -> short
            rename_test_helper(&fs, "", name_1, "", name_2, FileKind::Symlink)?;

            // short -> long
            rename_test_helper(
                &fs,
                "",
                name_2,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_2,
                FileKind::Symlink
            )?;

            // long -> long
            rename_test_helper(
                &fs,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_2,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_1,
                FileKind::Symlink
            )?;

            // long -> short
            rename_test_helper(
                &fs,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_1,
                "",
                name_2,
                FileKind::Symlink
            )?;

            fs.unlink("", name_2)?;

            Ok(())
        }

        #[test]
        fn mknod_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);
            let long_dir = "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long";
            let name = OsStr::new("mknod_test_siv_ctrmac");

            assert!(fs.dir_entry(name).is_err());
            fs.mknod("", name, Permissions::from_mode(0o644))?;
            assert_eq!(fs.dir_entry(name)?.kind, FileKind::File);
            fs.unlink("", name)?;
            assert!(fs.dir_entry(name).is_err());

            assert!(fs.dir_entry(PathBuf::from(long_dir).join(name)).is_err());
            fs.mknod(long_dir, name, Permissions::from_mode(0o646))?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?.kind,
                FileKind::File
            );
            fs.unlink(long_dir, name)?;
            assert!(fs.dir_entry(PathBuf::from(long_dir).join(name)).is_err());

            Ok(())
        }

        #[test]
        fn mkdir_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);
            let long_dir = "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long";
            let name = OsStr::new("mkdir_test_siv_ctrmac");

            assert!(fs.dir_entry(name).is_err());
            fs.mkdir("", name, Permissions::from_mode(0o744))?;
            assert_eq!(fs.dir_entry(name)?.kind, FileKind::Directory);
            fs.rmdir("", name)?;
            assert!(fs.dir_entry(name).is_err());

            assert!(fs.dir_entry(PathBuf::from(long_dir).join(name)).is_err());
            fs.mkdir(long_dir, name, Permissions::from_mode(0o755))?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?.kind,
                FileKind::Directory
            );
            fs.rmdir(long_dir, name)?;
            assert!(fs.dir_entry(PathBuf::from(long_dir).join(name)).is_err());

            Ok(())
        }

        #[test]
        fn symlink_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);
            let long_dir = "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long";
            let name = OsStr::new("symlink_test_siv_ctrmac");

            assert!(fs.dir_entry(name).is_err());
            fs.symlink("", name, "test_file.txt")?;
            assert_eq!(fs.dir_entry(name)?.kind, FileKind::Symlink);
            fs.unlink("", name)?;
            assert!(fs.dir_entry(name).is_err());

            assert!(fs.dir_entry(PathBuf::from(long_dir).join(name)).is_err());
            fs.symlink(long_dir, name, "unknown")?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?.kind,
                FileKind::Symlink
            );
            fs.unlink(long_dir, name)?;
            assert!(fs.dir_entry(PathBuf::from(long_dir).join(name)).is_err());

            Ok(())
        }

        #[test]
        fn set_permissions_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);
            let long_dir = "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long";
            let name = OsStr::new("set_permissions_test_siv_ctrmac");

            // files
            fs.mknod("", name, Permissions::from_mode(0o644))?;
            assert_eq!(
                fs.dir_entry(name)?.metadata.permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o644)
            );
            fs.set_permissions(name, Permissions::from_mode(0o777))?;
            assert_eq!(
                fs.dir_entry(name)?.metadata.permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o777)
            );
            fs.unlink("", name)?;

            fs.mknod(long_dir, name, Permissions::from_mode(0o600))?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o600)
            );
            fs.set_permissions(
                PathBuf::from(long_dir).join(name),
                Permissions::from_mode(0o700),
            )?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o700)
            );
            fs.unlink(long_dir, name)?;

            // directories
            fs.mkdir("", name, Permissions::from_mode(0o744))?;
            assert_eq!(
                fs.dir_entry(name)?.metadata.permissions(),
                Permissions::from_mode(libc::S_IFDIR | 0o744)
            );
            fs.set_permissions(name, Permissions::from_mode(0o755))?;
            assert_eq!(
                fs.dir_entry(name)?.metadata.permissions(),
                Permissions::from_mode(libc::S_IFDIR | 0o755)
            );
            fs.rmdir("", name)?;

            fs.mkdir(long_dir, name, Permissions::from_mode(0o755))?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .permissions(),
                Permissions::from_mode(libc::S_IFDIR | 0o755)
            );
            fs.set_permissions(
                PathBuf::from(long_dir).join(name),
                Permissions::from_mode(0o777),
            )?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name),)?
                    .metadata
                    .permissions(),
                Permissions::from_mode(libc::S_IFDIR | 0o777)
            );
            fs.rmdir(long_dir, name)?;

            // symlinks
            fs.symlink("", name, "test_file.txt")?;
            assert_eq!(
                fs.dir_entry(name)?.metadata.permissions(),
                // Don't worry about S_IFLNK - FUSE will automatically set the entry type for us
                Permissions::from_mode(libc::S_IFREG | 0o644)
            );
            fs.set_permissions(name, Permissions::from_mode(0o755))?;
            assert_eq!(
                fs.dir_entry(name)?.metadata.permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o755)
            );
            fs.unlink("", name)?;

            fs.symlink(long_dir, name, "unknown")?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o644)
            );
            fs.set_permissions(
                PathBuf::from(long_dir).join(name),
                Permissions::from_mode(0o755),
            )?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o755)
            );
            fs.unlink(long_dir, name)?;

            Ok(())
        }

        #[test]
        fn set_times_test() -> Result<()> {
            let vault = get_vault_siv_ctrmac()?;
            let fs = EncryptedFileSystem::new(&vault);
            let long_dir = "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long";
            let name = OsStr::new("set_times_test_siv_ctrmac");
            let epoch_times = FileTimes::new()
                .set_accessed(UNIX_EPOCH)
                .set_modified(UNIX_EPOCH);

            // files
            fs.mknod("", name, Permissions::from_mode(0o644))?;
            assert_ne!(fs.dir_entry(name)?.metadata.accessed()?, UNIX_EPOCH);
            assert_ne!(fs.dir_entry(name)?.metadata.modified()?, UNIX_EPOCH);
            fs.set_times(name, epoch_times)?;
            assert_eq!(fs.dir_entry(name)?.metadata.accessed()?, UNIX_EPOCH);
            assert_eq!(fs.dir_entry(name)?.metadata.modified()?, UNIX_EPOCH);
            fs.unlink("", name)?;

            fs.mknod(long_dir, name, Permissions::from_mode(0o644))?;
            assert_ne!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .accessed()?,
                UNIX_EPOCH
            );
            assert_ne!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .modified()?,
                UNIX_EPOCH
            );
            fs.set_times(PathBuf::from(long_dir).join(name), epoch_times)?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .accessed()?,
                UNIX_EPOCH
            );
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .modified()?,
                UNIX_EPOCH
            );
            fs.unlink(long_dir, name)?;

            // directories
            fs.mkdir("", name, Permissions::from_mode(0o755))?;
            assert_ne!(fs.dir_entry(name)?.metadata.accessed()?, UNIX_EPOCH);
            assert_ne!(fs.dir_entry(name)?.metadata.modified()?, UNIX_EPOCH);
            fs.set_times(name, epoch_times)?;
            assert_eq!(fs.dir_entry(name)?.metadata.accessed()?, UNIX_EPOCH);
            assert_eq!(fs.dir_entry(name)?.metadata.modified()?, UNIX_EPOCH);
            fs.rmdir("", name)?;

            fs.mkdir(long_dir, name, Permissions::from_mode(0o755))?;
            assert_ne!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .accessed()?,
                UNIX_EPOCH
            );
            assert_ne!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .modified()?,
                UNIX_EPOCH
            );
            fs.set_times(PathBuf::from(long_dir).join(name), epoch_times)?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .accessed()?,
                UNIX_EPOCH
            );
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .modified()?,
                UNIX_EPOCH
            );
            fs.rmdir(long_dir, name)?;

            // symlinks
            fs.symlink("", name, "test_file.txt")?;
            assert_ne!(fs.dir_entry(name)?.metadata.accessed()?, UNIX_EPOCH);
            assert_ne!(fs.dir_entry(name)?.metadata.modified()?, UNIX_EPOCH);
            fs.set_times(name, epoch_times)?;
            assert_eq!(fs.dir_entry(name)?.metadata.accessed()?, UNIX_EPOCH);
            assert_eq!(fs.dir_entry(name)?.metadata.modified()?, UNIX_EPOCH);
            fs.unlink("", name)?;

            fs.symlink(long_dir, name, "unknown")?;
            assert_ne!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .accessed()?,
                UNIX_EPOCH
            );
            assert_ne!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .modified()?,
                UNIX_EPOCH
            );
            fs.set_times(PathBuf::from(long_dir).join(name), epoch_times)?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .accessed()?,
                UNIX_EPOCH
            );
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .modified()?,
                UNIX_EPOCH
            );
            fs.unlink(long_dir, name)?;

            Ok(())
        }
    }

    mod siv_gcm {
        use super::*;

        #[test]
        fn root_dir_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);
            assert_eq!(
                fs.root_dir(),
                vault.path().join("d/QD/W5WPJ7TSDTMH2G4363MJUELZ7KZMHK")
            );

            Ok(())
        }

        #[test]
        fn dir_entry_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);

            let entry = fs.dir_entry("")?;
            assert_eq!(entry.kind, FileKind::Directory);

            let entry = fs.dir_entry("test_file.txt")?;
            assert_eq!(entry.kind, FileKind::File);
            assert_eq!(entry.size, 41);

            let entry = fs.dir_entry(
                "test_dir/test_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long.txt",
            )?;
            assert_eq!(entry.kind, FileKind::File);
            assert_eq!(entry.size, 29);

            let entry = fs.dir_entry("test_dir")?;
            assert_eq!(entry.kind, FileKind::Directory);

            let entry = fs.dir_entry(
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
            )?;
            assert_eq!(entry.kind, FileKind::Directory);
            assert_eq!(
                entry.size,
                vault
                    .path()
                    .join("d/UI/6ZF2IIZX3LXLARPP2U64V65SL3B4VM")
                    .metadata()?
                    .len()
            );

            let entry = fs.dir_entry("test_link")?;
            assert_eq!(entry.kind, FileKind::Symlink);
            assert_eq!(entry.size, 24);

            let entry = fs.dir_entry(
                "test_dir/test_link_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
            )?;
            assert_eq!(entry.kind, FileKind::Symlink);
            assert_eq!(entry.size, 148);

            assert!(fs.dir_entry("invalid.unknown").is_err());

            Ok(())
        }

        #[test]
        fn dir_entries_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);

            let entries = fs.dir_entries("")?;
            assert!(entries.len() > 1);
            let entry = entries.get(&PathBuf::from("test_file.txt")).unwrap();
            assert_eq!(entry.kind, FileKind::File);
            assert_eq!(entry.size, 41);

            let entries = fs.dir_entries("test_dir")?;
            assert!(entries.len() > 1);
            let entry = entries
                .get(&PathBuf::from("test_dir/test_file_2.txt"))
                .unwrap();
            assert_eq!(entry.kind, FileKind::File);
            assert_eq!(entry.size, 47);

            Ok(())
        }

        #[test]
        fn link_target_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);

            assert_eq!(
                fs.link_target("test_link")?,
                PathBuf::from("test_dir/test_file_2.txt")
            );

            assert_eq!(
                fs.link_target(
                    "test_dir/test_link_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long"
                )?,
                PathBuf::from(
                    "test_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long.txt"
                )
            );

            assert!(fs.link_target("test_file.txt").is_err());
            assert!(fs.link_target("invalid.unknown").is_err());

            Ok(())
        }

        #[test]
        fn open_file_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);

            let mut options = OpenOptions::new();
            options.read(true).write(true);
            assert!(fs.open_file("test_file.txt", options.clone()).is_ok());
            assert!(fs
                .open_file(
                    "test_dir/test_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long.txt",
                    options.clone()
                )
                .is_ok()
            );
            assert!(fs.open_file("invalid.unknown", options).is_err());

            Ok(())
        }

        #[test]
        fn rename_file_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);

            let name_1 = OsStr::new("rename_file_test_siv_gcm_1");
            let name_2 = OsStr::new("rename_file_test_siv_gcm_2");

            fs.mknod("", name_1, Permissions::from_mode(0o400))?;

            // short -> short
            rename_test_helper(&fs, "", name_1, "", name_2, FileKind::File)?;

            // short -> long
            rename_test_helper(
                &fs,
                "",
                name_2,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_2,
                FileKind::File
            )?;

            // long -> long
            rename_test_helper(
                &fs,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_2,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_1,
                FileKind::File
            )?;

            // long -> short
            rename_test_helper(
                &fs,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_1,
                "",
                name_2,
                FileKind::File
            )?;

            fs.unlink("", name_2)?;

            Ok(())
        }

        #[test]
        fn rename_dir_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);

            let name_1 = OsStr::new("rename_dir_test_siv_gcm_1");
            let name_2 = OsStr::new("rename_dir_test_siv_gcm_2");

            fs.mkdir("", name_1, Permissions::from_mode(0o755))?;

            // short -> short
            rename_test_helper(&fs, "", name_1, "", name_2, FileKind::Directory)?;

            // short -> long
            rename_test_helper(
                &fs,
                "",
                name_2,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_2,
                FileKind::Directory
            )?;

            // long -> long
            rename_test_helper(
                &fs,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_2,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_1,
                FileKind::Directory
            )?;

            // long -> short
            rename_test_helper(
                &fs,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_1,
                "",
                name_2,
                FileKind::Directory
            )?;

            fs.rmdir("", name_2)?;

            Ok(())
        }

        #[test]
        fn rename_link_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);

            let name_1 = OsStr::new("rename_link_test_siv_gcm_1");
            let name_2 = OsStr::new("rename_link_test_siv_gcm_2");

            fs.symlink("", name_1, "test_file.txt")?;

            // short -> short
            rename_test_helper(&fs, "", name_1, "", name_2, FileKind::Symlink)?;

            // short -> long
            rename_test_helper(
                &fs,
                "",
                name_2,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_2,
                FileKind::Symlink
            )?;

            // long -> long
            rename_test_helper(
                &fs,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_2,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_1,
                FileKind::Symlink
            )?;

            // long -> short
            rename_test_helper(
                &fs,
                "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long",
                name_1,
                "",
                name_2,
                FileKind::Symlink
            )?;

            fs.unlink("", name_2)?;

            Ok(())
        }

        #[test]
        fn mknod_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);
            let long_dir = "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long";
            let name = OsStr::new("mknod_test_siv_gcm");

            assert!(fs.dir_entry(name).is_err());
            fs.mknod("", name, Permissions::from_mode(0o644))?;
            assert_eq!(fs.dir_entry(name)?.kind, FileKind::File);
            fs.unlink("", name)?;
            assert!(fs.dir_entry(name).is_err());

            assert!(fs.dir_entry(PathBuf::from(long_dir).join(name)).is_err());
            fs.mknod(long_dir, name, Permissions::from_mode(0o646))?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?.kind,
                FileKind::File
            );
            fs.unlink(long_dir, name)?;
            assert!(fs.dir_entry(PathBuf::from(long_dir).join(name)).is_err());

            Ok(())
        }

        #[test]
        fn mkdir_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);
            let long_dir = "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long";
            let name = OsStr::new("mkdir_test_siv_gcm");

            assert!(fs.dir_entry(name).is_err());
            fs.mkdir("", name, Permissions::from_mode(0o744))?;
            assert_eq!(fs.dir_entry(name)?.kind, FileKind::Directory);
            fs.rmdir("", name)?;
            assert!(fs.dir_entry(name).is_err());

            assert!(fs.dir_entry(PathBuf::from(long_dir).join(name)).is_err());
            fs.mkdir(long_dir, name, Permissions::from_mode(0o755))?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?.kind,
                FileKind::Directory
            );
            fs.rmdir(long_dir, name)?;
            assert!(fs.dir_entry(PathBuf::from(long_dir).join(name)).is_err());

            Ok(())
        }

        #[test]
        fn symlink_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);
            let long_dir = "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long";
            let name = OsStr::new("symlink_test_siv_gcm");

            assert!(fs.dir_entry(name).is_err());
            fs.symlink("", name, "test_file.txt")?;
            assert_eq!(fs.dir_entry(name)?.kind, FileKind::Symlink);
            fs.unlink("", name)?;
            assert!(fs.dir_entry(name).is_err());

            assert!(fs.dir_entry(PathBuf::from(long_dir).join(name)).is_err());
            fs.symlink(long_dir, name, "unknown")?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?.kind,
                FileKind::Symlink
            );
            fs.unlink(long_dir, name)?;
            assert!(fs.dir_entry(PathBuf::from(long_dir).join(name)).is_err());

            Ok(())
        }

        #[test]
        fn set_permissions_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);
            let long_dir = "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long";
            let name = OsStr::new("set_permissions_test_siv_gcm");

            // files
            fs.mknod("", name, Permissions::from_mode(0o644))?;
            assert_eq!(
                fs.dir_entry(name)?.metadata.permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o644)
            );
            fs.set_permissions(name, Permissions::from_mode(0o777))?;
            assert_eq!(
                fs.dir_entry(name)?.metadata.permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o777)
            );
            fs.unlink("", name)?;

            fs.mknod(long_dir, name, Permissions::from_mode(0o600))?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o600)
            );
            fs.set_permissions(
                PathBuf::from(long_dir).join(name),
                Permissions::from_mode(0o700),
            )?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o700)
            );
            fs.unlink(long_dir, name)?;

            // directories
            fs.mkdir("", name, Permissions::from_mode(0o744))?;
            assert_eq!(
                fs.dir_entry(name)?.metadata.permissions(),
                Permissions::from_mode(libc::S_IFDIR | 0o744)
            );
            fs.set_permissions(name, Permissions::from_mode(0o755))?;
            assert_eq!(
                fs.dir_entry(name)?.metadata.permissions(),
                Permissions::from_mode(libc::S_IFDIR | 0o755)
            );
            fs.rmdir("", name)?;

            fs.mkdir(long_dir, name, Permissions::from_mode(0o755))?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .permissions(),
                Permissions::from_mode(libc::S_IFDIR | 0o755)
            );
            fs.set_permissions(
                PathBuf::from(long_dir).join(name),
                Permissions::from_mode(0o777),
            )?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name),)?
                    .metadata
                    .permissions(),
                Permissions::from_mode(libc::S_IFDIR | 0o777)
            );
            fs.rmdir(long_dir, name)?;

            // symlinks
            fs.symlink("", name, "test_file.txt")?;
            assert_eq!(
                fs.dir_entry(name)?.metadata.permissions(),
                // Don't worry about S_IFLNK - FUSE will automatically set the entry type for us
                Permissions::from_mode(libc::S_IFREG | 0o644)
            );
            fs.set_permissions(name, Permissions::from_mode(0o755))?;
            assert_eq!(
                fs.dir_entry(name)?.metadata.permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o755)
            );
            fs.unlink("", name)?;

            fs.symlink(long_dir, name, "unknown")?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o644)
            );
            fs.set_permissions(
                PathBuf::from(long_dir).join(name),
                Permissions::from_mode(0o755),
            )?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .permissions(),
                Permissions::from_mode(libc::S_IFREG | 0o755)
            );
            fs.unlink(long_dir, name)?;

            Ok(())
        }

        #[test]
        fn set_times_test() -> Result<()> {
            let vault = get_vault_siv_gcm()?;
            let fs = EncryptedFileSystem::new(&vault);
            let long_dir = "test_dir/test_dir_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long_name_too_long";
            let name = OsStr::new("set_times_test_siv_gcm");
            let epoch_times = FileTimes::new()
                .set_accessed(UNIX_EPOCH)
                .set_modified(UNIX_EPOCH);

            // files
            fs.mknod("", name, Permissions::from_mode(0o644))?;
            assert_ne!(fs.dir_entry(name)?.metadata.accessed()?, UNIX_EPOCH);
            assert_ne!(fs.dir_entry(name)?.metadata.modified()?, UNIX_EPOCH);
            fs.set_times(name, epoch_times)?;
            assert_eq!(fs.dir_entry(name)?.metadata.accessed()?, UNIX_EPOCH);
            assert_eq!(fs.dir_entry(name)?.metadata.modified()?, UNIX_EPOCH);
            fs.unlink("", name)?;

            fs.mknod(long_dir, name, Permissions::from_mode(0o644))?;
            assert_ne!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .accessed()?,
                UNIX_EPOCH
            );
            assert_ne!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .modified()?,
                UNIX_EPOCH
            );
            fs.set_times(PathBuf::from(long_dir).join(name), epoch_times)?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .accessed()?,
                UNIX_EPOCH
            );
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .modified()?,
                UNIX_EPOCH
            );
            fs.unlink(long_dir, name)?;

            // directories
            fs.mkdir("", name, Permissions::from_mode(0o755))?;
            assert_ne!(fs.dir_entry(name)?.metadata.accessed()?, UNIX_EPOCH);
            assert_ne!(fs.dir_entry(name)?.metadata.modified()?, UNIX_EPOCH);
            fs.set_times(name, epoch_times)?;
            assert_eq!(fs.dir_entry(name)?.metadata.accessed()?, UNIX_EPOCH);
            assert_eq!(fs.dir_entry(name)?.metadata.modified()?, UNIX_EPOCH);
            fs.rmdir("", name)?;

            fs.mkdir(long_dir, name, Permissions::from_mode(0o755))?;
            assert_ne!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .accessed()?,
                UNIX_EPOCH
            );
            assert_ne!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .modified()?,
                UNIX_EPOCH
            );
            fs.set_times(PathBuf::from(long_dir).join(name), epoch_times)?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .accessed()?,
                UNIX_EPOCH
            );
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .modified()?,
                UNIX_EPOCH
            );
            fs.rmdir(long_dir, name)?;

            // symlinks
            fs.symlink("", name, "test_file.txt")?;
            assert_ne!(fs.dir_entry(name)?.metadata.accessed()?, UNIX_EPOCH);
            assert_ne!(fs.dir_entry(name)?.metadata.modified()?, UNIX_EPOCH);
            fs.set_times(name, epoch_times)?;
            assert_eq!(fs.dir_entry(name)?.metadata.accessed()?, UNIX_EPOCH);
            assert_eq!(fs.dir_entry(name)?.metadata.modified()?, UNIX_EPOCH);
            fs.unlink("", name)?;

            fs.symlink(long_dir, name, "unknown")?;
            assert_ne!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .accessed()?,
                UNIX_EPOCH
            );
            assert_ne!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .modified()?,
                UNIX_EPOCH
            );
            fs.set_times(PathBuf::from(long_dir).join(name), epoch_times)?;
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .accessed()?,
                UNIX_EPOCH
            );
            assert_eq!(
                fs.dir_entry(PathBuf::from(long_dir).join(name))?
                    .metadata
                    .modified()?,
                UNIX_EPOCH
            );
            fs.unlink(long_dir, name)?;

            Ok(())
        }
    }
}
