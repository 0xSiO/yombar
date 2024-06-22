use std::{
    cmp::Ordering,
    collections::VecDeque,
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    ops::Deref,
    path::Path,
};

use crate::{
    crypto::{Cryptor, FileCryptor, FileHeader},
    util,
};

pub struct EncryptedFile<'k> {
    cryptor: Cryptor<'k>,
    file: File,
    header: FileHeader,
    chunk_buffer: VecDeque<u8>,
}

impl<'k> EncryptedFile<'k> {
    /// Open an existing encrypted file in read-write mode.
    pub fn open(cryptor: Cryptor<'k>, path: impl AsRef<Path>) -> io::Result<Self> {
        let mut file = File::options().read(true).write(true).open(path)?;
        let mut encrypted_header = vec![0; cryptor.encrypted_header_len()];
        let header = match file.read_exact(&mut encrypted_header) {
            // Decrypt the file header if it exists
            Ok(_) => cryptor
                .decrypt_header(encrypted_header)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            // Otherwise, write a new one
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                let header = cryptor.new_header()?;
                let header_bytes = cryptor.encrypt_header(&header).map_err(io::Error::other)?;
                file.write_all(&header_bytes)?;
                file.flush()?;
                header
            }
            Err(err) => return Err(err),
        };

        Ok(Self {
            cryptor,
            file,
            header,
            chunk_buffer: Default::default(),
        })
    }

    /// Create a new encrypted file in read-write mode; error if the file exists.
    pub fn create_new(cryptor: Cryptor<'k>, path: impl AsRef<Path>) -> io::Result<Self> {
        File::create_new(&path)?;
        Self::open(cryptor, path)
    }

    // Fetch the current cleartext byte position in the file.
    fn cleartext_pos(&mut self) -> io::Result<u64> {
        Ok(util::get_cleartext_size(
            self.cryptor,
            self.file.stream_position()?,
        ))
    }

    /// Fetch the cleartext size of the file, in bytes.
    pub fn cleartext_size(&mut self) -> io::Result<u64> {
        Ok(util::get_cleartext_size(
            self.cryptor,
            self.file.metadata()?.len(),
        ))
    }
}

impl<'k> Deref for EncryptedFile<'k> {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

// TODO: This implementation assumes the file position is always at a chunk boundary, which is no
// longer the case with the new Write impl. This needs to be rewritten, probably without the chunk
// buffer. Also take another look at the Seek impl to see if it's affected by the same issue.
impl<'k> Read for EncryptedFile<'k> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.chunk_buffer.len() <= buf.len() {
            // Try to fill up the buffer's remaining space as best we can
            let chunks_to_read =
                1.max((buf.len() - self.chunk_buffer.len()) / self.cryptor.max_chunk_len());

            for _ in 0..chunks_to_read {
                let mut ciphertext_chunk = vec![0; self.cryptor.max_encrypted_chunk_len()];
                match util::try_read_exact(&mut self.file, &mut ciphertext_chunk)? {
                    // Got EOF immediately
                    (false, 0) => break,
                    // Got some data, then hit EOF
                    (false, n) => ciphertext_chunk.truncate(n),
                    // Got a whole chunk, no EOF
                    _ => {}
                }

                // Find beginning of current chunk, ignore header, and divide by max chunk length
                let ciphertext_pos = self.file.stream_position()? as usize;
                let chunk_number = (ciphertext_pos
                    .saturating_sub(ciphertext_chunk.len())
                    .saturating_sub(self.cryptor.encrypted_header_len()))
                    / self.cryptor.max_encrypted_chunk_len();

                self.chunk_buffer.extend(
                    self.cryptor
                        .decrypt_chunk(ciphertext_chunk, &self.header, chunk_number)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                );
            }
        }

        self.chunk_buffer.read(buf)
    }
}

impl<'k> Seek for EncryptedFile<'k> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(n) => {
                if n == self.cleartext_pos()? {
                    return Ok(n);
                }

                // We're moving somewhere else, so forget the current chunk buffer
                self.chunk_buffer.clear();

                // Move to the beginning of the appropriate ciphertext chunk, maxing out at the end
                // of the ciphertext file
                let enc_chunk_start = self.cryptor.encrypted_header_len()
                    + (n as usize / self.cryptor.max_chunk_len()
                        * self.cryptor.max_encrypted_chunk_len());
                let new_ciphertext_pos = (enc_chunk_start as u64).min(self.file.metadata()?.len());
                self.file.seek(SeekFrom::Start(new_ciphertext_pos))?;

                // Skip some bytes to move to the final position within the chunk
                let remainder = n as usize % self.cryptor.max_chunk_len();
                self.read_exact(&mut vec![0; remainder])?;

                Ok(n)
            }
            SeekFrom::End(n) => {
                let cleartext_size = self.cleartext_size()?;
                self.seek(SeekFrom::Start(
                    // Don't permit seeking past the beginning or end
                    cleartext_size.saturating_sub(-n.max(0) as u64),
                ))
            }
            SeekFrom::Current(n) => {
                let cleartext_pos = self.cleartext_pos()?;
                let new_cleartext_pos = match n.cmp(&0) {
                    Ordering::Less => cleartext_pos.saturating_sub(-n as u64),
                    Ordering::Equal => return Ok(cleartext_pos),
                    Ordering::Greater => cleartext_pos
                        .saturating_add(n as u64)
                        .min(self.cleartext_size()?),
                };

                self.seek(SeekFrom::Start(new_cleartext_pos))
            }
        }
    }
}

impl<'k> Write for EncryptedFile<'k> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let max_chunk_len = self.cryptor.max_chunk_len();
        let current_pos = self.cleartext_pos()? as usize;
        let chunk_number = current_pos / max_chunk_len;
        let chunk_offset = current_pos % max_chunk_len;
        let chunk_start = chunk_number * max_chunk_len;

        // Ensure we're positioned at a chunk boundary
        if chunk_offset > 0 {
            self.seek(SeekFrom::Start(chunk_start as u64))?;
        }

        let bytes_written;
        let mut ciphertext_chunk = vec![0; self.cryptor.max_encrypted_chunk_len()];
        let replacement_chunk = match util::try_read_exact(&mut self.file, &mut ciphertext_chunk)? {
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

        self.seek(SeekFrom::Start(chunk_start as u64))?;
        self.file.write_all(&replacement_chunk)?;
        self.seek(SeekFrom::Start((current_pos + bytes_written) as u64))?;

        Ok(bytes_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
