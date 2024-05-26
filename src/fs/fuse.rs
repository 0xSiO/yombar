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
// - file metadata = use appropriate *.c9r file
// - directory metadata = use second half of hashed dir ID, NOT the dir's *.c9r folder
// - symlink metadata = use appropriate symlink.c9r file
//
// ^ This all should be handled under the hood by EncryptedFileSystem
//
// Capabilities we need from EncryptedFileSystem:
// - map cleartext path -> virtual file/dir/symlink info (kind, metadata)
// - map cleartext dir path -> list of virtual dir entries (filename, file kind, metadata)
//
// We also need to be able to read the contents of a file given its inode, so we may need a mapping
// of inodes to virtual paths

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

#[derive(Debug)]
struct Attributes {
    inode: Inode,
    kind: FileKind,
    meta: std::fs::Metadata,
}

impl From<&Attributes> for FileAttr {
    fn from(value: &Attributes) -> Self {
        Self {
            ino: value.inode,
            // TODO: This is wrong, calculate decrypted size somehow
            size: value.meta.size(),
            // TOD: Cryptomator sets this to 0, should we do the same?
            blocks: value.meta.blocks(),
            atime: value.meta.accessed().unwrap_or(UNIX_EPOCH),
            mtime: value.meta.modified().unwrap_or(UNIX_EPOCH),
            // TODO: Is created() the right one to use here? Looks like Cryptomator does this also
            ctime: value.meta.created().unwrap_or(UNIX_EPOCH),
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

#[derive(Debug)]
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
        let meta = self.inner.root_dir().metadata().unwrap();
        let inode = self.cache_attrs(FileKind::Directory, meta);
        let entries = self.inner.get_virtual_dir_entries("").unwrap();
        self.cache_entries(inode, entries);

        Ok(())
    }

    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        if let Some(entries) = self.entry_map.get(&parent) {
            if let Some(&(inode, _)) = entries.get(name) {
                // If the inode exists in the entry map, we should have attrs for it
                let attrs = self.attr_map.get(&inode).unwrap();
                return reply.entry(&TTL, &FileAttr::from(attrs), 0);
            }
        }
        reply.error(libc::ENOENT);
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        match self.attr_map.get(&ino) {
            Some(attrs) => reply.attr(&TTL, &FileAttr::from(attrs)),
            None => reply.error(libc::ENOENT),
        }
    }

    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        match self.entry_map.get(&ino) {
            Some(entries) => {
                for (i, entry) in entries.iter().enumerate().skip(offset as usize) {
                    let (name, &(inode, kind)) = entry;
                    // i + 1 means the index of the next entry
                    if reply.add(inode, (i + 1) as i64, kind.into(), name) {
                        break;
                    }
                }
                reply.ok();
            }
            None => reply.error(libc::ENOENT),
        }
    }
}
