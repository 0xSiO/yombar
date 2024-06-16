use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{Seek, SeekFrom},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, UNIX_EPOCH},
};

use fuser::{FileAttr, FileType, Filesystem, FUSE_ROOT_ID};

use crate::{
    fs::{DirEntry, EncryptedFileSystem, FileKind},
    io::{try_read_exact, EncryptedStream},
};

mod dir_tree;

use dir_tree::DirTree;

const TTL: Duration = Duration::from_secs(1);

type Inode = u64;

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
    entry: DirEntry,
}

impl From<Attributes> for FileAttr {
    fn from(value: Attributes) -> Self {
        Self {
            ino: value.inode,
            size: value.entry.size,
            // TOD: Cryptomator sets this to 0, should we do the same?
            blocks: value.entry.metadata.blocks(),
            atime: value.entry.metadata.accessed().unwrap_or(UNIX_EPOCH),
            mtime: value.entry.metadata.modified().unwrap_or(UNIX_EPOCH),
            // TODO: Is created() the right one to use here? Looks like Cryptomator does this also
            ctime: value.entry.metadata.created().unwrap_or(UNIX_EPOCH),
            crtime: value.entry.metadata.created().unwrap_or(UNIX_EPOCH),
            kind: value.entry.kind.into(),
            perm: value.entry.metadata.permissions().mode() as u16,
            nlink: value.entry.metadata.nlink() as u32,
            uid: value.entry.metadata.uid(),
            gid: value.entry.metadata.gid(),
            rdev: value.entry.metadata.rdev() as u32,
            blksize: value.entry.metadata.blksize() as u32,
            flags: 0,
        }
    }
}

pub struct FuseFileSystem<'v> {
    fs: EncryptedFileSystem<'v>,
    tree: DirTree,
    dir_entries: HashMap<Inode, BTreeMap<PathBuf, DirEntry>>,
    file_handles: HashMap<u64, EncryptedStream<'v, File>>,
    next_file_handle: AtomicU64,
}

impl<'v> FuseFileSystem<'v> {
    pub fn new(fs: EncryptedFileSystem<'v>) -> Self {
        Self {
            fs,
            tree: DirTree::new(),
            dir_entries: Default::default(),
            file_handles: Default::default(),
            next_file_handle: AtomicU64::new(0),
        }
    }
}

// TODO: Look into removing cached tree entries that are no longer valid where possible
impl<'v> Filesystem for FuseFileSystem<'v> {
    fn init(
        &mut self,
        _req: &fuser::Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        Ok(())
    }

    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        if let Some(parent_path) = self.tree.get_path(parent) {
            let target_path = parent_path.join(name);

            if let Ok(entry) = self.fs.dir_entry(&target_path) {
                let inode = self.tree.insert_path(target_path);
                return reply.entry(&TTL, &FileAttr::from(Attributes { inode, entry }), 0);
            }
        }

        reply.error(libc::ENOENT);
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        if let Some(path) = self.tree.get_path(ino) {
            if path.parent().is_none() {
                let metadata = self.fs.root_dir().metadata().unwrap();
                return reply.attr(
                    &TTL,
                    &FileAttr::from(Attributes {
                        inode: FUSE_ROOT_ID,
                        entry: DirEntry {
                            kind: FileKind::Directory,
                            size: metadata.size(),
                            metadata,
                        },
                    }),
                );
            }

            if let Ok(entry) = self.fs.dir_entry(path) {
                return reply.attr(&TTL, &FileAttr::from(Attributes { inode: ino, entry }));
            }
        }

        reply.error(libc::ENOENT);
    }

    fn readlink(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyData) {
        if let Some(path) = self.tree.get_path(ino) {
            if let Ok(target) = self.fs.link_target(path) {
                return reply.data(target.as_os_str().as_bytes());
            }
        }

        reply.error(libc::ENOENT);
    }

    // TODO: Use mode, umask
    fn mkdir(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        _mode: u32,
        _umask: u32,
        reply: fuser::ReplyEntry,
    ) {
        if let Some(parent) = self.tree.get_path(parent) {
            if let Ok(entry) = self.fs.mkdir(&parent, name) {
                let inode = self.tree.insert_path(parent.join(name));
                return reply.entry(&TTL, &FileAttr::from(Attributes { inode, entry }), 0);
            }
        }

        reply.error(libc::ENOENT);
    }

    fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, flags: i32, reply: fuser::ReplyOpen) {
        if let Some(path) = self.tree.get_path(ino) {
            if path.parent().is_none() {
                return reply.error(libc::EINVAL);
            }

            // TODO: Maybe check flags and modify open options
            if let Ok(stream) = self.fs.open_file(path) {
                let fh = self.next_file_handle.fetch_add(1, Ordering::SeqCst);
                self.file_handles.insert(fh, stream);
                return reply.opened(fh, flags as u32);
            }
        }

        reply.error(libc::ENOENT);
    }

    fn read(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: fuser::ReplyData,
    ) {
        if let Some(mut stream) = self.file_handles.get_mut(&fh) {
            debug_assert!(offset >= 0);
            match stream.seek(SeekFrom::Start(offset as u64)) {
                Ok(pos) => {
                    debug_assert_eq!(pos, offset as u64);
                    let mut buf = vec![0_u8; size as usize];
                    if let (false, n) = try_read_exact(&mut stream, &mut buf).unwrap() {
                        buf.truncate(n)
                    }
                    return reply.data(&buf);
                }
                // TODO: Maybe add better error handling here
                Err(_) => return reply.data(&[]),
            }
        }

        reply.error(libc::ENOENT);
    }

    fn release(
        &mut self,
        _req: &fuser::Request<'_>,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        self.file_handles.remove(&fh);
        reply.ok();
    }

    fn opendir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        flags: i32,
        reply: fuser::ReplyOpen,
    ) {
        if let Some(path) = self.tree.get_path(ino) {
            if let Ok(entries) = self.fs.dir_entries(path) {
                self.dir_entries.insert(ino, entries);
                // TODO: Do we need to allocate a file handle?
                return reply.opened(0, flags as u32);
            }
        }

        reply.error(libc::ENOENT);
    }

    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        if let Some(entries) = self.dir_entries.get(&ino) {
            for (i, (path, dir_entry)) in entries.iter().enumerate().skip(offset as usize) {
                let name = path.file_name().unwrap().to_os_string();
                let inode = self.tree.insert_path(path);

                // i + 1 means the index of the next entry
                if reply.add(inode, (i + 1) as i64, dir_entry.kind.into(), name) {
                    break;
                }
            }

            return reply.ok();
        }

        reply.error(libc::ENOENT);
    }

    fn releasedir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        _flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        match self.dir_entries.remove(&ino) {
            Some(_) => reply.ok(),
            None => reply.error(libc::ENOENT),
        }
    }

    fn rename(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        newparent: u64,
        newname: &std::ffi::OsStr,
        _flags: u32,
        reply: fuser::ReplyEmpty,
    ) {
        if let Some(old_parent) = self.tree.get_path(parent) {
            if let Some(new_parent) = self.tree.get_path(newparent) {
                if self
                    .fs
                    .rename(old_parent, name, new_parent, newname)
                    .is_ok()
                {
                    self.tree.rename(parent, name, newparent, newname);
                    return reply.ok();
                } else {
                    return reply.error(libc::EIO);
                }
            }
        }

        reply.error(libc::ENOENT);
    }
}
