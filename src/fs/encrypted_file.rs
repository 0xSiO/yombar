use std::{
    cmp::Ordering,
    fmt::Debug,
    fs::{File, Metadata, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

use fd_lock::RwLock;

use crate::{
    crypto::{Cryptor, FileCryptor, FileHeader},
    util, Result,
};

// TODO: Arithmetic for converting between cleartext/ciphertext byte positions may need to change
// in the future if we add new cryptor types that change the length of encrypted/decrypted data.
pub struct EncryptedFile<'k> {
    cryptor: Cryptor<'k>,
    file: RwLock<File>,
    header: FileHeader,
    append: bool,
}

impl<'k> EncryptedFile<'k> {
    /// Open an existing encrypted file at the provided path, using the provided options.
    pub fn open(
        cryptor: Cryptor<'k>,
        path: impl AsRef<Path> + Debug,
        options: OpenOptions,
    ) -> Result<Self> {
        let file = RwLock::new(options.open(path)?);

        // Read and decrypt the file header - error if header is missing/invalid
        let guard = file.try_read()?;
        let mut encrypted_header = vec![0; cryptor.encrypted_header_len()];
        (&*guard).read_exact(&mut encrypted_header)?;
        let header = cryptor.decrypt_header(encrypted_header)?;
        drop(guard);

        Ok(Self {
            cryptor,
            file,
            header,
            append: false,
        })
    }

    /// Create a new encrypted file in read-write mode; error if the file exists.
    pub fn create_new(cryptor: Cryptor<'k>, path: impl AsRef<Path> + Debug) -> Result<Self> {
        let mut file = RwLock::new(File::create_new(&path)?);

        // Write a header in the new file
        let guard = file.try_write()?;
        let header = cryptor.new_header()?;
        let header_bytes = cryptor.encrypt_header(&header)?;
        (&*guard).write_all(&header_bytes)?;
        guard.sync_all()?;
        drop(guard);

        // Now that the file is created, open it normally for reading/writing
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        Self::open(cryptor, path, options)
    }

    pub(crate) fn set_append(&mut self, append: bool) {
        self.append = append;
    }

    // Fetch the current byte position in the underlying ciphertext file.
    fn ciphertext_pos(mut file: &File) -> io::Result<u64> {
        file.stream_position()
    }

    /// Fetch the size of the underlying ciphertext file, in bytes.
    fn ciphertext_len(file: &File) -> io::Result<u64> {
        Ok(file.metadata()?.len())
    }

    // Fetch the current cleartext byte position in the file.
    fn cleartext_pos(cryptor: Cryptor<'k>, file: &File) -> io::Result<u64> {
        Ok(util::get_cleartext_size(
            cryptor,
            Self::ciphertext_pos(file)?,
        ))
    }

    /// Fetch the cleartext size of the file, in bytes.
    fn cleartext_len(cryptor: Cryptor<'k>, file: &File) -> io::Result<u64> {
        Ok(util::get_cleartext_size(
            cryptor,
            Self::ciphertext_len(file)?,
        ))
    }

    /// Seek without needing &mut self.
    fn seek_inner(cryptor: Cryptor<'k>, mut file: &File, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(n) => {
                if n == Self::cleartext_pos(cryptor, file)? {
                    return Ok(n);
                }

                let chunk_number = n / (cryptor.max_chunk_len() as u64);
                let chunk_offset = n % (cryptor.max_chunk_len() as u64);
                let mut desired_pos = (cryptor.encrypted_header_len() as u64)
                    + chunk_number * (cryptor.max_encrypted_chunk_len() as u64);

                // Skip chunk header if desired position is partway through a chunk
                if chunk_offset > 0 {
                    desired_pos += chunk_offset
                        + (cryptor.max_encrypted_chunk_len() - cryptor.max_chunk_len()) as u64;
                }

                // Cap the seek to the end of the ciphertext file
                let new_ciphertext_pos = desired_pos.min(Self::ciphertext_len(file)?);
                file.seek(SeekFrom::Start(new_ciphertext_pos))?;
                Self::cleartext_pos(cryptor, file)
            }
            SeekFrom::End(n) => {
                let cleartext_size = Self::cleartext_len(cryptor, file)?;
                Self::seek_inner(
                    cryptor,
                    file,
                    SeekFrom::Start(
                        // Don't permit seeking past the beginning or end
                        cleartext_size.saturating_sub(-n.max(0) as u64),
                    ),
                )
            }
            SeekFrom::Current(n) => {
                let cleartext_pos = Self::cleartext_pos(cryptor, file)?;
                let new_cleartext_pos = match n.cmp(&0) {
                    Ordering::Less => cleartext_pos.saturating_sub(-n as u64),
                    Ordering::Equal => return Ok(cleartext_pos),
                    Ordering::Greater => cleartext_pos
                        .saturating_add(n as u64)
                        .min(Self::cleartext_len(cryptor, file)?),
                };

                Self::seek_inner(cryptor, file, SeekFrom::Start(new_cleartext_pos))
            }
        }
    }

    /// Fetch the cleartext size of the file, in bytes.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> Result<u64> {
        Ok(Self::cleartext_len(self.cryptor, &*self.file.try_read()?)?)
    }

    /// Fetch the metadata of the underlying ciphertext file.
    pub fn metadata(&self) -> Result<Metadata> {
        Ok(self.file.try_read()?.metadata()?)
    }

    /// Sync ciphertext file content and metadata to disk.
    pub fn sync_all(&mut self) -> Result<()> {
        Ok(self.file.try_write()?.sync_all()?)
    }

    /// Sync ciphertext file content to disk, but maybe not metadata.
    pub fn sync_data(&mut self) -> Result<()> {
        Ok(self.file.try_write()?.sync_data()?)
    }
}

impl<'k> Read for EncryptedFile<'k> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let guard = self.file.try_read()?;

        if buf.is_empty() || Self::ciphertext_pos(&guard)? == Self::ciphertext_len(&guard)? {
            return Ok(0);
        }

        let max_chunk_len = self.cryptor.max_chunk_len();
        let current_pos = Self::cleartext_pos(self.cryptor, &guard)? as usize;
        let chunk_number = current_pos / max_chunk_len;
        let chunk_offset = current_pos % max_chunk_len;
        let chunk_start = chunk_number * max_chunk_len;

        // Ensure we're positioned at a chunk boundary
        if chunk_offset > 0 {
            Self::seek_inner(self.cryptor, &guard, SeekFrom::Start(chunk_start as u64))?;
        }

        let mut ciphertext_chunk = vec![0; self.cryptor.max_encrypted_chunk_len()];
        if let (false, n) = util::try_read_exact(&*guard, &mut ciphertext_chunk)? {
            ciphertext_chunk.truncate(n)
        }

        let chunk = self
            .cryptor
            .decrypt_chunk(ciphertext_chunk, &self.header, chunk_number)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let bytes_read = (&chunk[chunk_offset..]).read(buf)?;
        Self::seek_inner(
            self.cryptor,
            &guard,
            SeekFrom::Start((current_pos + bytes_read) as u64),
        )?;

        Ok(bytes_read)
    }
}

impl<'k> Seek for EncryptedFile<'k> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let guard = self.file.try_read()?;
        Self::seek_inner(self.cryptor, &guard, pos)
    }
}

impl<'k> Write for EncryptedFile<'k> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let guard = self.file.try_write()?;

        if buf.is_empty() {
            return Ok(0);
        }

        // TODO: Maybe there's a more elegant way of implementing this 'append mode'
        if self.append {
            // If we're in append mode, we can skip to the end of the file while we hold the
            // exclusive lock, which should be safe
            (&*guard).seek(SeekFrom::End(0))?;
        }

        let max_chunk_len = self.cryptor.max_chunk_len();
        let current_pos = Self::cleartext_pos(self.cryptor, &guard)? as usize;
        let chunk_number = current_pos / max_chunk_len;
        let chunk_offset = current_pos % max_chunk_len;
        let chunk_start = chunk_number * max_chunk_len;

        // Ensure we're positioned at a chunk boundary
        if chunk_offset > 0 {
            Self::seek_inner(self.cryptor, &guard, SeekFrom::Start(chunk_start as u64))?;
        }

        let bytes_written;
        let mut ciphertext_chunk = vec![0; self.cryptor.max_encrypted_chunk_len()];
        let replacement_chunk = match util::try_read_exact(&*guard, &mut ciphertext_chunk)? {
            // At EOF - replacement chunk is either a max-size chunk or the entire buffer,
            // whichever is smaller
            (false, 0) => {
                let chunk = &buf[..buf.len().min(max_chunk_len)];
                bytes_written = chunk.len();
                self.cryptor
                    .encrypt_chunk(chunk, &self.header, chunk_number)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            }
            // Within last chunk - replacement chunk is the last chunk overwritten with data from
            // buffer, up to one max-size chunk
            (false, n) => {
                ciphertext_chunk.truncate(n);
                let mut chunk = self
                    .cryptor
                    .decrypt_chunk(ciphertext_chunk, &self.header, chunk_number)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                let old_len = chunk.len();
                chunk.resize(max_chunk_len, 0);
                bytes_written = (&mut chunk[chunk_offset..]).write(buf)?;

                // If we made the chunk bigger, truncate to a larger size than the original chunk.
                // Otherwise, truncate to the original chunk size.
                chunk.truncate(old_len.max(chunk_offset + bytes_written));

                self.cryptor
                    .encrypt_chunk(chunk, &self.header, chunk_number)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            }
            // Got a whole chunk
            _ => {
                // If we're just overwriting the whole chunk, no need to decrypt existing chunk
                if chunk_offset == 0 && buf.len() >= max_chunk_len {
                    let chunk = &buf[..max_chunk_len];
                    bytes_written = chunk.len();
                    self.cryptor
                        .encrypt_chunk(chunk, &self.header, chunk_number)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                // Otherwise, write data from buffer into the existing chunk
                } else {
                    let mut chunk = self
                        .cryptor
                        .decrypt_chunk(ciphertext_chunk, &self.header, chunk_number)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    bytes_written = (&mut chunk[chunk_offset..]).write(buf)?;

                    self.cryptor
                        .encrypt_chunk(chunk, &self.header, chunk_number)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                }
            }
        };

        Self::seek_inner(self.cryptor, &guard, SeekFrom::Start(chunk_start as u64))?;
        (&*guard).write_all(&replacement_chunk)?;
        Self::seek_inner(
            self.cryptor,
            &guard,
            SeekFrom::Start((current_pos + bytes_written) as u64),
        )?;

        Ok(bytes_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.try_write()?.flush()
    }
}
