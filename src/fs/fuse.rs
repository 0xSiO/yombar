use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::Metadata,
    os::unix::fs::{MetadataExt, PermissionsExt},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, UNIX_EPOCH},
};

use fuser::{FileAttr, FileType, Filesystem, FUSE_ROOT_ID};

use crate::fs::{DirEntry, EncryptedFileSystem, FileKind};

// Things we need:
// - attr_map: Mapping of inode -> attributes
// - entry_map: Mapping of inode -> directory entries (mapping of file names -> (inode, FileType))
//
// Initial values:
// attr_map = { 1 -> (root dir attrs) }
// entry_map = { 1 -> { "." -> (1, Directory) } }
//
// We identify a text file inside the root dir. This becomes:
// attr_map = { 1 -> (root dir attrs), 2 -> (text file attrs) }
// entry_map = { 1 -> { "." -> (1, Directory), "a.txt" -> (2, File) } }
//
// Important notes on metadata:
// - file metadata = same as the appropriate *.c9r files
// - directory metadata = same as second half of hashed dir ID, NOT the dir's *.c9r folder
// - symlink metadata = same as the appropriate symlink.c9r file
//
// ^ This all should be handled under the hood by EncryptedFileSystem
//
// Capabilities we need from EncryptedFileSystem:
// - map cleartext path -> virtual file/dir/symlink info (kind, metadata)
// - map cleartext dir path -> list of virtual dir entries (filename, file kind, metadata)

const TTL: Duration = Duration::from_secs(1);

type Inode = u64;
type DirEntries = BTreeMap<OsString, (Inode, FileKind)>;

impl From<FileKind> for FileType {
    fn from(kind: FileKind) -> Self {
        match kind {
            FileKind::File => fuser::FileType::RegularFile,
            FileKind::Directory => fuser::FileType::Directory,
            FileKind::Symlink => fuser::FileType::Symlink,
        }
    }
}

struct Attributes {
    inode: Inode,
    kind: FileKind,
    meta: std::fs::Metadata,
}

impl From<&Attributes> for FileAttr {
    fn from(value: &Attributes) -> Self {
        Self {
            ino: value.inode,
            size: value.meta.size(),
            blocks: value.meta.blocks(),
            atime: value.meta.accessed().unwrap_or(UNIX_EPOCH),
            mtime: value.meta.modified().unwrap_or(UNIX_EPOCH),
            // TODO: handle times before epoch?
            ctime: UNIX_EPOCH
                .checked_add(Duration::from_secs(value.meta.ctime() as u64))
                .unwrap_or(UNIX_EPOCH),
            crtime: value.meta.created().unwrap_or(UNIX_EPOCH),
            kind: value.kind.into(),
            perm: value.meta.permissions().mode() as u16,
            nlink: value.meta.nlink() as u32,
            uid: value.meta.uid(),
            gid: value.meta.gid(),
            rdev: value.meta.rdev() as u32,
            blksize: value.meta.blksize() as u32,
            flags: 0,
        }
    }
}

pub struct FuseFileSystem<'v> {
    inner: EncryptedFileSystem<'v>,
    attr_map: BTreeMap<Inode, Attributes>,
    entry_map: BTreeMap<Inode, DirEntries>,
    next_inode: AtomicU64,
}

impl<'v> FuseFileSystem<'v> {
    pub fn new(fs: EncryptedFileSystem<'v>) -> Self {
        Self {
            inner: fs,
            attr_map: Default::default(),
            entry_map: Default::default(),
            next_inode: AtomicU64::new(FUSE_ROOT_ID),
        }
    }

    fn cache_attrs(&mut self, kind: FileKind, meta: Metadata) -> Inode {
        let inode = self.next_inode.fetch_add(1, Ordering::SeqCst);

        self.attr_map
            .insert(inode, Attributes { inode, kind, meta });

        inode
    }

    fn cache_entries(&mut self, inode: Inode, entries: Vec<DirEntry>) {
        let map = self.entry_map.entry(inode).or_default();
        for entry in entries {
            let inode = self.next_inode.fetch_add(1, Ordering::SeqCst);

            self.attr_map.insert(
                inode,
                Attributes {
                    inode,
                    kind: entry.file_kind,
                    meta: entry.metadata,
                },
            );

            map.insert(entry.file_name, (inode, entry.file_kind));
        }
    }
}

impl<'v> Filesystem for FuseFileSystem<'v> {
    fn init(
        &mut self,
        _req: &fuser::Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        // Cache metadata and contents for root dir, inode 1
        let meta = self.inner.root_dir().metadata().or(Err(libc::EIO))?;
        let inode = self.cache_attrs(FileKind::Directory, meta);
        let entries = self.inner.get_virtual_dir_entries("").or(Err(libc::EIO))?;
        self.cache_entries(inode, entries);

        Ok(())
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        match self.attr_map.get(&ino) {
            Some(attrs) => reply.attr(&TTL, &FileAttr::from(attrs)),
            None => reply.error(libc::ENOENT),
        }
    }
}
