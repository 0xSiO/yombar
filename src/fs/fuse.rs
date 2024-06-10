use std::{
    collections::HashMap,
    fs::File,
    io::{Seek, SeekFrom},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, UNIX_EPOCH},
};

use fuser::{FileAttr, FileType, Filesystem, FUSE_ROOT_ID};

use crate::{
    fs::{DirEntry, EncryptedFileSystem, FileKind},
    io::{try_read_exact, EncryptedStream},
};

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
    inodes_to_paths: HashMap<Inode, PathBuf>,
    paths_to_inodes: HashMap<PathBuf, Inode>,
    file_handles: HashMap<u64, EncryptedStream<'v, File>>,
    next_inode: AtomicU64,
    next_file_handle: AtomicU64,
}

impl<'v> FuseFileSystem<'v> {
    pub fn new(fs: EncryptedFileSystem<'v>) -> Self {
        Self {
            fs,
            inodes_to_paths: Default::default(),
            paths_to_inodes: Default::default(),
            file_handles: Default::default(),
            next_inode: AtomicU64::new(FUSE_ROOT_ID),
            next_file_handle: AtomicU64::new(0),
        }
    }
}

impl<'v> Filesystem for FuseFileSystem<'v> {
    fn init(
        &mut self,
        _req: &fuser::Request<'_>,
        _config: &mut fuser::KernelConfig,
    ) -> Result<(), libc::c_int> {
        let root_inode = self.next_inode.fetch_add(1, Ordering::SeqCst);
        self.inodes_to_paths.insert(root_inode, PathBuf::new());
        self.paths_to_inodes.insert(PathBuf::new(), root_inode);

        Ok(())
    }

    fn lookup(
        &mut self,
        _req: &fuser::Request<'_>,
        parent: u64,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        if let Some(path) = self.inodes_to_paths.get(&parent) {
            if let Ok(mut entries) = self.fs.get_virtual_dir_entries(path) {
                let target_path = path.join(name);

                if let Some(entry) = entries.remove(&target_path) {
                    let inode = *self
                        .paths_to_inodes
                        .entry(target_path.clone())
                        .or_insert_with(|| self.next_inode.fetch_add(1, Ordering::SeqCst));
                    self.inodes_to_paths.insert(inode, target_path);

                    return reply.entry(&TTL, &FileAttr::from(Attributes { inode, entry }), 0);
                }
            }
        }

        reply.error(libc::ENOENT);
    }

    fn getattr(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyAttr) {
        if let Some(path) = self.inodes_to_paths.get(&ino) {
            let parent_dir_id = match path.parent() {
                Some(parent) => self.fs.get_dir_id(parent).unwrap(),
                None => {
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
            };

            if let Ok(entry) = self.fs.get_virtual_dir_entry(path, parent_dir_id) {
                return reply.attr(&TTL, &FileAttr::from(Attributes { inode: ino, entry }));
            }
        }

        // Remove any cached data if not found
        // TODO: Do this in other methods too where needed
        self.inodes_to_paths
            .remove(&ino)
            .map(|path| self.paths_to_inodes.remove(&path));

        reply.error(libc::ENOENT);
    }

    fn readlink(&mut self, _req: &fuser::Request<'_>, ino: u64, reply: fuser::ReplyData) {
        if let Some(path) = self.inodes_to_paths.get(&ino) {
            let parent_dir_id = match path.parent() {
                Some(parent) => self.fs.get_dir_id(parent).unwrap(),
                None => return reply.error(libc::ENOENT),
            };

            if let Ok(target) = self.fs.get_link_target(path, parent_dir_id) {
                return reply.data(target.as_bytes());
            }
        }

        reply.error(libc::ENOENT);
    }

    fn open(&mut self, _req: &fuser::Request<'_>, ino: u64, flags: i32, reply: fuser::ReplyOpen) {
        if let Some(path) = self.inodes_to_paths.get(&ino) {
            let parent_dir_id = match path.parent() {
                Some(parent) => self.fs.get_dir_id(parent).unwrap(),
                None => return reply.error(libc::ENOENT),
            };

            // TODO: Maybe check flags and modify open options
            if let Ok(stream) = self.fs.open_file(path, parent_dir_id) {
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
            let start_time = std::time::Instant::now();
            debug_assert!(offset >= 0);
            match stream.seek(SeekFrom::Start(offset as u64)) {
                Ok(pos) => {
                    debug_assert_eq!(pos, offset as u64);
                    let mut buf = vec![0_u8; size as usize];
                    if let (false, n) = try_read_exact(&mut stream, &mut buf).unwrap() {
                        buf.truncate(n)
                    }
                    log::debug!("read took {} ms", start_time.elapsed().as_millis());
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

    fn readdir(
        &mut self,
        _req: &fuser::Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: fuser::ReplyDirectory,
    ) {
        if let Some(path) = self.inodes_to_paths.get(&ino) {
            if let Ok(entries) = self.fs.get_virtual_dir_entries(path) {
                for (i, (path, dir_entry)) in entries.into_iter().enumerate().skip(offset as usize)
                {
                    let name = path.file_name().unwrap().to_os_string();
                    let inode = *self
                        .paths_to_inodes
                        .entry(path.clone())
                        .or_insert_with(|| self.next_inode.fetch_add(1, Ordering::SeqCst));
                    self.inodes_to_paths.insert(inode, path);

                    // i + 1 means the index of the next entry
                    if reply.add(inode, (i + 1) as i64, dir_entry.kind.into(), name) {
                        break;
                    }
                }

                return reply.ok();
            }
        }

        reply.error(libc::ENOENT);
    }
}
