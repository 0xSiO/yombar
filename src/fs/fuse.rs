use std::{
    collections::BTreeMap,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, UNIX_EPOCH},
};

use fuser::{FileAttr, FileType, Filesystem, FUSE_ROOT_ID};

use crate::fs::{EncryptedFileSystem, FileKind};

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
    kind: FileKind,
    meta: std::fs::Metadata,
}

impl From<Attributes> for FileAttr {
    fn from(value: Attributes) -> Self {
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
    fs: EncryptedFileSystem<'v>,
    inodes_to_paths: BTreeMap<Inode, PathBuf>,
    paths_to_inodes: BTreeMap<PathBuf, Inode>,
    next_inode: AtomicU64,
}

impl<'v> FuseFileSystem<'v> {
    pub fn new(fs: EncryptedFileSystem<'v>) -> Self {
        Self {
            fs,
            inodes_to_paths: Default::default(),
            paths_to_inodes: Default::default(),
            next_inode: AtomicU64::new(FUSE_ROOT_ID),
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

                if let Some((kind, meta)) = entries.remove(&target_path) {
                    let inode = *self
                        .paths_to_inodes
                        .entry(target_path.clone())
                        .or_insert_with(|| self.next_inode.fetch_add(1, Ordering::SeqCst));
                    self.inodes_to_paths.insert(inode, target_path);

                    return reply.entry(&TTL, &FileAttr::from(Attributes { inode, kind, meta }), 0);
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
                    return reply.attr(
                        &TTL,
                        &FileAttr::from(Attributes {
                            inode: FUSE_ROOT_ID,
                            kind: FileKind::Directory,
                            meta: self.fs.root_dir().metadata().unwrap(),
                        }),
                    )
                }
            };

            if let Ok((kind, meta)) = self.fs.get_virtual_file_info(path, parent_dir_id) {
                return reply.attr(
                    &TTL,
                    &FileAttr::from(Attributes {
                        inode: ino,
                        kind,
                        meta,
                    }),
                );
            }
        }

        // Remove any cached data if not found
        // TODO: Do this in other methods too where needed
        self.inodes_to_paths
            .remove(&ino)
            .map(|path| self.paths_to_inodes.remove(&path));

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
        if let Some(path) = self.inodes_to_paths.get(&ino) {
            if let Ok(entries) = self.fs.get_virtual_dir_entries(path) {
                for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
                    let (path, (kind, _)) = entry;
                    let name = path.file_name().unwrap().to_os_string();
                    let inode = *self
                        .paths_to_inodes
                        .entry(path.clone())
                        .or_insert_with(|| self.next_inode.fetch_add(1, Ordering::SeqCst));
                    self.inodes_to_paths.insert(inode, path);

                    // i + 1 means the index of the next entry
                    if reply.add(inode, (i + 1) as i64, kind.into(), name) {
                        break;
                    }
                }

                return reply.ok();
            }
        }

        reply.error(libc::ENOENT);
    }
}
