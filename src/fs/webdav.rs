use std::{
    ffi::OsString,
    io::{Read, Seek, SeekFrom, Write},
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::{Buf, Bytes, BytesMut};
use dav_server::{
    davpath::DavPath,
    fs::{
        DavDirEntry, DavFile, DavFileSystem, DavMetaData, FsError, FsFuture, FsResult, FsStream,
        OpenOptions, ReadDirMeta,
    },
};

use crate::fs::{DirEntry, EncryptedFile, EncryptedFileSystem, FileKind};

// TODO: Replace calls to unwrap() with proper error handling
// TODO: Use threadpool for blocking logic

// TODO: Maybe implement some other methods in this trait
impl DavMetaData for DirEntry {
    fn len(&self) -> u64 {
        self.size
    }

    fn modified(&self) -> FsResult<SystemTime> {
        Ok(self.metadata.modified().unwrap_or(UNIX_EPOCH))
    }

    fn is_dir(&self) -> bool {
        self.kind == FileKind::Directory
    }

    fn is_file(&self) -> bool {
        self.kind == FileKind::File
    }

    fn is_symlink(&self) -> bool {
        self.kind == FileKind::Symlink
    }

    fn accessed(&self) -> FsResult<SystemTime> {
        Ok(self.metadata.accessed().unwrap_or(UNIX_EPOCH))
    }

    fn created(&self) -> FsResult<SystemTime> {
        Ok(self.metadata.created().unwrap_or(UNIX_EPOCH))
    }
}

struct WebDavDirEntry {
    name: OsString,
    dir_entry: DirEntry,
}

impl DavDirEntry for WebDavDirEntry {
    fn name(&self) -> Vec<u8> {
        self.name.as_encoded_bytes().to_vec()
    }

    fn metadata(&self) -> FsFuture<Box<dyn DavMetaData>> {
        Box::pin(async move { Ok(Box::new(self.dir_entry.clone()) as _) })
    }
}

#[derive(Debug)]
struct WebDavFile<'k> {
    dir_entry: DirEntry,
    encrypted_file: EncryptedFile<'k>,
}

impl DavFile for WebDavFile<'_> {
    fn metadata(&mut self) -> FsFuture<Box<dyn DavMetaData>> {
        Box::pin(async move { Ok(Box::new(self.dir_entry.clone()) as _) })
    }

    fn write_buf(&mut self, buf: Box<dyn Buf + Send>) -> FsFuture<()> {
        Box::pin(async move {
            self.encrypted_file.write_all(buf.chunk()).unwrap();
            Ok(())
        })
    }

    fn write_bytes(&mut self, buf: Bytes) -> FsFuture<()> {
        Box::pin(async move {
            self.encrypted_file.write_all(&buf).unwrap();
            Ok(())
        })
    }

    fn read_bytes(&mut self, count: usize) -> FsFuture<Bytes> {
        Box::pin(async move {
            let mut buf = BytesMut::zeroed(count);
            self.encrypted_file.read_exact(&mut buf).unwrap();
            Ok(buf.freeze())
        })
    }

    fn seek(&mut self, pos: SeekFrom) -> FsFuture<u64> {
        Box::pin(async move {
            let pos = self.encrypted_file.seek(pos).unwrap();
            Ok(pos)
        })
    }

    fn flush(&mut self) -> FsFuture<()> {
        Box::pin(async move {
            self.encrypted_file.flush().unwrap();
            Ok(())
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct WebDavFileSystem {
    fs: EncryptedFileSystem<'static>,
}

impl WebDavFileSystem {
    pub fn new(fs: EncryptedFileSystem<'static>) -> Self {
        Self { fs }
    }
}

impl DavFileSystem for WebDavFileSystem {
    fn open<'a>(
        &'a self,
        path: &'a DavPath,
        options: OpenOptions,
    ) -> FsFuture<'a, Box<dyn DavFile>> {
        Box::pin(async move {
            // We'll support opening files in either read mode or read-write mode
            let mut open_options = std::fs::OpenOptions::new();
            open_options.read(true).write(options.write);

            let dir_entry = self.fs.dir_entry(path.as_rel_ospath()).unwrap();
            let encrypted_file = self
                .fs
                .open_file(path.as_rel_ospath(), open_options)
                .unwrap();

            Ok(Box::new(WebDavFile {
                dir_entry,
                encrypted_file,
            }) as _)
        })
    }

    fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        _meta: ReadDirMeta,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
        Box::pin(async move {
            let dir_entries = self.fs.dir_entries(path.as_rel_ospath()).unwrap();

            Ok(
                Box::pin(futures_util::stream::iter(dir_entries.into_iter().map(
                    |(path, dir_entry)| {
                        FsResult::Ok(Box::new(WebDavDirEntry {
                            name: path.file_name().unwrap().to_owned(),
                            dir_entry,
                        }) as Box<dyn DavDirEntry>)
                    },
                ))) as _,
            )
        })
    }

    fn metadata<'a>(&'a self, path: &'a DavPath) -> FsFuture<'a, Box<dyn DavMetaData>> {
        Box::pin(async move {
            let dir_entry = self
                .fs
                .dir_entry(path.as_rel_ospath())
                .map_err(|_| FsError::NotFound)?;
            Ok(Box::new(dir_entry) as _)
        })
    }
}
