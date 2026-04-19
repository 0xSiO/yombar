use std::{
    collections::BTreeMap,
    ffi::{CString, OsStr},
    fs::{FileTimes, OpenOptions, Permissions},
    io::{self, Seek, SeekFrom, Write},
    mem,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use fuser::*;

use crate::{
    fs::{DirEntry, EncryptedFile, EncryptedFileSystem, FileKind},
    util,
};

mod dir_tree;

use dir_tree::DirTree;
use fuser::{ReplyCreate, ReplyStatfs};

const TTL: Duration = Duration::from_secs(1);

impl From<FileKind> for FileType {
    fn from(kind: FileKind) -> Self {
        match kind {
            FileKind::File => FileType::RegularFile,
            FileKind::Directory => FileType::Directory,
            FileKind::Symlink => FileType::Symlink,
        }
    }
}

#[derive(Debug)]
struct Attributes {
    inode: INodeNo,
    entry: DirEntry,
}

impl From<Attributes> for FileAttr {
    fn from(value: Attributes) -> Self {
        Self {
            ino: value.inode,
            size: value.entry.size,
            blocks: value.entry.metadata.blocks(),
            atime: value.entry.metadata.accessed().unwrap_or(UNIX_EPOCH),
            mtime: value.entry.metadata.modified().unwrap_or(UNIX_EPOCH),
            ctime: UNIX_EPOCH
                + Duration::from_secs(value.entry.metadata.ctime() as u64)
                + Duration::from_nanos(value.entry.metadata.ctime_nsec() as u64),
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
    open_dirs: BTreeMap<FileHandle, BTreeMap<PathBuf, DirEntry>>,
    open_files: BTreeMap<FileHandle, EncryptedFile<'v>>,
    next_handle: AtomicU64,
}

impl<'v> FuseFileSystem<'v> {
    pub fn new(fs: EncryptedFileSystem<'v>) -> Self {
        Self {
            fs,
            tree: DirTree::new(),
            open_dirs: Default::default(),
            open_files: Default::default(),
            next_handle: AtomicU64::new(0),
        }
    }
}

// TODO: Explore flags sent to and returned from these methods
// e.g. https://github.com/torvalds/linux/blob/7c626ce4bae1ac14f60076d00eafe71af30450ba/include/uapi/linux/fuse.h#L353
impl Filesystem for FuseFileSystem<'static> {
    fn init(&mut self, _req: &Request, _config: &mut KernelConfig) -> io::Result<()> {
        Ok(())
    }

    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if let Some(parent_path) = self.tree.get_path(parent) {
            let target_path = parent_path.join(name);

            match self.fs.dir_entry(&target_path) {
                Ok(entry) => {
                    let inode = self.tree.insert_path(target_path);
                    reply.entry(
                        &TTL,
                        &FileAttr::from(Attributes { inode, entry }),
                        Generation(0),
                    );
                }
                Err(err) => {
                    tracing::trace!("{err:?}");
                    tracing::debug!(?target_path, "failed to lookup path");
                    reply.error(Errno::ENOENT);
                }
            }
        } else {
            tracing::warn!(?parent, "parent inode not found");
            reply.error(Errno::ENOENT);
        }
    }

    fn forget(&self, _req: &Request, ino: INodeNo, _nlookup: u64) {
        self.tree.forget(ino);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if let Some(path) = self.tree.get_path(ino) {
            match self.fs.dir_entry(path) {
                Ok(entry) => {
                    reply.attr(&TTL, &FileAttr::from(Attributes { inode: ino, entry }));
                }
                Err(err) => {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                }
            }
        } else {
            tracing::warn!(?ino, "inode not found");
            reply.error(Errno::ENOENT);
        }
    }

    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if let Some(path) = self.tree.get_path(ino) {
            if let Some(mode) = mode
                && let Err(err) = self.fs.set_permissions(&path, Permissions::from_mode(mode))
            {
                tracing::error!("{err:?}");
                return reply.error(Errno::EIO);
            }

            if let Some(size) = size {
                if let Some(fh) = fh {
                    match self.open_files.get_mut(&fh) {
                        Some(file) => {
                            if let Err(err) = file.set_len(size) {
                                tracing::error!("{err:?}");
                                return reply.error(Errno::EIO);
                            }
                        }
                        None => {
                            tracing::warn!(?fh, "invalid file handle");
                            return reply.error(Errno::ESTALE);
                        }
                    }
                } else {
                    let mut options = OpenOptions::new();
                    options.read(true).write(true);

                    match self.fs.open_file(&path, options) {
                        Ok(mut file) => {
                            if let Err(err) = file.set_len(size) {
                                tracing::error!("{err:?}");
                                return reply.error(Errno::EIO);
                            }
                        }
                        Err(err) => {
                            tracing::error!("{err:?}");
                            return reply.error(Errno::EIO);
                        }
                    }
                }
            }

            let mut times = FileTimes::new();
            let now = SystemTime::now();
            match atime {
                Some(TimeOrNow::SpecificTime(t)) => times = times.set_accessed(t),
                Some(TimeOrNow::Now) => times = times.set_accessed(now),
                None => {}
            };
            match mtime {
                Some(TimeOrNow::SpecificTime(t)) => times = times.set_modified(t),
                Some(TimeOrNow::Now) => times = times.set_modified(now),
                None => {}
            };

            if let Err(err) = self.fs.set_times(&path, times) {
                tracing::error!("{err:?}");
                return reply.error(Errno::EIO);
            }

            match self.fs.dir_entry(path) {
                Ok(entry) => {
                    reply.attr(&TTL, &FileAttr::from(Attributes { inode: ino, entry }));
                }
                Err(err) => {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                }
            }
        } else {
            tracing::warn!(?ino, "inode not found");
            reply.error(Errno::ENOENT);
        }
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        if let Some(path) = self.tree.get_path(ino) {
            match self.fs.link_target(path) {
                Ok(target) => reply.data(target.as_os_str().as_bytes()),
                Err(err) => {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                }
            }
        } else {
            tracing::warn!(?ino, "inode not found");
            reply.error(Errno::ENOENT);
        }
    }

    fn mknod(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        _rdev: u32,
        reply: ReplyEntry,
    ) {
        if let Some(parent) = self.tree.get_path(parent) {
            match self
                .fs
                .mknod(&parent, name, Permissions::from_mode(mode & !umask))
            {
                Ok(entry) => {
                    let inode = self.tree.insert_path(parent.join(name));
                    reply.entry(
                        &TTL,
                        &FileAttr::from(Attributes { inode, entry }),
                        Generation(0),
                    );
                }
                Err(err) => {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                }
            }
        } else {
            tracing::warn!(?parent, "parent inode not found");
            reply.error(Errno::ENOENT);
        }
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        if let Some(parent) = self.tree.get_path(parent) {
            match self
                .fs
                .mkdir(&parent, name, Permissions::from_mode(mode & !umask))
            {
                Ok(entry) => {
                    let inode = self.tree.insert_path(parent.join(name));
                    reply.entry(
                        &TTL,
                        &FileAttr::from(Attributes { inode, entry }),
                        Generation(0),
                    );
                }
                Err(err) => {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                }
            }
        } else {
            tracing::warn!(?parent, "parent inode not found");
            reply.error(Errno::ENOENT);
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Some(parent_path) = self.tree.get_path(parent) {
            if let Err(err) = self.fs.unlink(parent_path, name) {
                tracing::error!("{err:?}");
                reply.error(Errno::EIO);
            } else {
                self.tree.remove(parent, name);
                reply.ok();
            }
        } else {
            tracing::warn!(?parent, "parent inode not found");
            reply.error(Errno::ENOENT);
        }
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if let Some(parent_path) = self.tree.get_path(parent) {
            match self.fs.dir_entries(parent_path.join(name)) {
                Ok(entries) => {
                    if !entries.is_empty() {
                        tracing::warn!("directory not empty");
                        return reply.error(Errno::ENOTEMPTY);
                    }

                    if let Err(err) = self.fs.rmdir(parent_path, name) {
                        tracing::error!("{err:?}");
                        reply.error(Errno::EIO);
                    } else {
                        self.tree.remove(parent, name);
                        reply.ok()
                    }
                }
                Err(err) => {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                }
            }
        } else {
            tracing::warn!(?parent, "parent inode not found");
            reply.error(Errno::ENOENT);
        }
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &std::path::Path,
        reply: ReplyEntry,
    ) {
        if let Some(parent) = self.tree.get_path(parent) {
            match self.fs.symlink(&parent, link_name, target) {
                Ok(entry) => {
                    let inode = self.tree.insert_path(parent.join(link_name));
                    reply.entry(
                        &TTL,
                        &FileAttr::from(Attributes { inode, entry }),
                        Generation(0),
                    )
                }
                Err(err) => {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                }
            }
        } else {
            tracing::warn!(?parent, "parent inode not found");
            reply.error(Errno::ENOENT);
        }
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if let Some(old_parent) = self.tree.get_path(parent) {
            if let Some(new_parent) = self.tree.get_path(newparent) {
                if let Err(err) = self.fs.rename(old_parent, name, new_parent, newname) {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                } else {
                    self.tree.rename(parent, name, newparent, newname);
                    reply.ok()
                }
            } else {
                tracing::warn!(?newparent, "new parent inode not found");
                reply.error(Errno::ENOENT);
            }
        } else {
            tracing::warn!(?parent, "old parent inode not found");
            reply.error(Errno::ENOENT);
        }
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if let Some(path) = self.tree.get_path(ino) {
            // We'll support opening files in either read mode or read-write mode
            let mut options = OpenOptions::new();
            options.read(true);
            options.write(matches!(
                flags.acc_mode(),
                OpenAccMode::O_WRONLY | OpenAccMode::O_RDWR
            ));

            match self.fs.open_file(path, options) {
                Ok(mut file) => {
                    file.set_append(flags.0 & libc::O_APPEND > 0);
                    let fh = FileHandle(self.next_handle.fetch_add(1, Ordering::SeqCst));
                    self.open_files.insert(fh, file);
                    reply.opened(fh, FopenFlags::empty())
                }
                Err(err) => {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                }
            }
        } else {
            tracing::warn!(?ino, "inode not found");
            reply.error(Errno::ENOENT);
        }
    }

    fn read(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        if let Some(file) = self.open_files.get_mut(&fh) {
            if offset < 0 {
                tracing::warn!(offset, "invalid file offset");
                return reply.error(Errno::EINVAL);
            }

            match file.seek(SeekFrom::Start(offset)) {
                Ok(pos) if pos == offset => {
                    let mut buf = vec![0_u8; size as usize];
                    match util::try_read_exact(file, &mut buf) {
                        Ok((false, n)) => buf.truncate(n),
                        Ok(_) => {}
                        Err(err) => {
                            tracing::error!("{err:?}");
                            return reply.error(Errno::EIO);
                        }
                    }
                    reply.data(&buf);
                }
                Ok(pos) => {
                    tracing::warn!(pos, offset, "failed to seek to requested offset");
                    reply.error(Errno::EIO);
                }
                Err(err) => {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                }
            }
        } else {
            tracing::warn!(?fh, "invalid file handle");
            reply.error(Errno::ESTALE);
        }
    }

    fn write(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        if let Some(file) = self.open_files.get_mut(&fh) {
            if offset < 0 {
                tracing::warn!(offset, "invalid file offset");
                return reply.error(Errno::EINVAL);
            }

            match file.seek(SeekFrom::Start(offset)) {
                Ok(pos) if pos == offset => {
                    if let Err(err) = file.write_all(data) {
                        tracing::error!("{err:?}");
                        return reply.error(Errno::EIO);
                    }
                    reply.written(data.len() as u32);
                }
                Ok(pos) => {
                    tracing::warn!(pos, offset, "failed to seek to requested offset");
                    reply.error(Errno::EIO);
                }
                Err(err) => {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                }
            }
        } else {
            tracing::warn!(?fh, "invalid file handle");
            reply.error(Errno::ESTALE);
        }
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        if let Some(file) = self.open_files.get_mut(&fh) {
            if let Err(err) = file.flush() {
                tracing::error!("{err:?}");
                reply.error(Errno::EIO);
            } else {
                reply.ok();
            }
        } else {
            tracing::warn!(?fh, "invalid file handle");
            reply.error(Errno::ESTALE);
        }
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.open_files.remove(&fh);
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        if let Some(file) = self.open_files.get_mut(&fh) {
            let result = if datasync {
                file.sync_data()
            } else {
                file.sync_all()
            };

            if let Err(err) = result {
                tracing::error!("{err:?}");
                reply.error(Errno::EIO);
            } else {
                reply.ok();
            }
        } else {
            tracing::warn!(?fh, "invalid file handle");
            reply.error(Errno::ESTALE);
        }
    }

    fn opendir(&self, _req: &Request, ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        if let Some(path) = self.tree.get_path(ino) {
            match self.fs.dir_entries(path) {
                Ok(entries) => {
                    let fh = FileHandle(self.next_handle.fetch_add(1, Ordering::SeqCst));
                    self.open_dirs.insert(fh, entries);
                    reply.opened(fh, FopenFlags::empty());
                }
                Err(err) => {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                }
            }
        } else {
            tracing::warn!(?ino, "inode not found");
            reply.error(Errno::ENOENT);
        }
    }

    fn readdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if let Some(entries) = self.open_dirs.get(&fh) {
            for (i, (path, dir_entry)) in entries.iter().enumerate().skip(offset as usize) {
                // Each entry in a dir should have a name
                let name = path.file_name().unwrap().to_os_string();
                let inode = self.tree.insert_path(path);
                if reply.add(inode, (i + 1) as u64, dir_entry.kind.into(), name) {
                    break;
                }
            }

            reply.ok();
        } else {
            tracing::warn!(?fh, "invalid dir handle");
            reply.error(Errno::ESTALE);
        }
    }

    fn releasedir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        fh: FileHandle,
        _flags: OpenFlags,
        reply: ReplyEmpty,
    ) {
        self.open_dirs.remove(&fh);
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        match CString::new(self.fs.root_dir().as_os_str().as_bytes()) {
            Ok(root_dir) => {
                let mut stats: libc::statvfs64 = unsafe { mem::zeroed() };
                let ret = unsafe { libc::statvfs64(root_dir.as_ptr(), &mut stats) };
                if ret == 0 {
                    reply.statfs(
                        stats.f_blocks,
                        stats.f_bfree,
                        stats.f_bavail,
                        stats.f_files,
                        stats.f_ffree,
                        stats.f_bsize as u32,
                        stats.f_namemax as u32,
                        stats.f_frsize as u32,
                    );
                } else {
                    reply.error(Errno::ENOSYS);
                }
            }
            Err(err) => {
                tracing::error!("{err:?}");
                reply.error(Errno::EIO);
            }
        }
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        if let Some(parent) = self.tree.get_path(parent) {
            // Permit reads/writes initially, at least until the file descriptor is created
            match self.fs.mknod(
                &parent,
                name,
                Permissions::from_mode(
                    libc::S_IRUSR | libc::S_IWUSR | libc::S_IRGRP | libc::S_IWGRP,
                ),
            ) {
                Ok(entry) => {
                    let path = parent.join(name);
                    let inode = self.tree.insert_path(&path);

                    // We'll support opening files in either read mode or read-write mode
                    let mut options = OpenOptions::new();
                    options.read(true);
                    options.write(flags & libc::O_WRONLY > 0 || flags & libc::O_RDWR > 0);

                    match self.fs.open_file(&path, options) {
                        Ok(mut file) => {
                            file.set_append(flags & libc::O_APPEND > 0);

                            // Set the correct access mode now that we have a file descriptor
                            if let Err(err) = self
                                .fs
                                .set_permissions(&path, Permissions::from_mode(mode & !umask))
                            {
                                tracing::error!("{err:?}");
                                return reply.error(Errno::EIO);
                            }

                            let fh = FileHandle(self.next_handle.fetch_add(1, Ordering::SeqCst));
                            self.open_files.insert(fh, file);
                            reply.created(
                                &TTL,
                                &FileAttr::from(Attributes { inode, entry }),
                                Generation(0),
                                fh,
                                FopenFlags::empty(),
                            );
                        }
                        Err(err) => {
                            tracing::error!("{err:?}");
                            reply.error(Errno::EIO);
                        }
                    }
                }
                Err(err) => {
                    tracing::error!("{err:?}");
                    reply.error(Errno::EIO);
                }
            }
        } else {
            tracing::warn!(?parent, "parent inode not found");
            reply.error(Errno::ENOENT);
        }
    }
}
