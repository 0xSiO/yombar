use std::{
    collections::VecDeque,
    io::{self, Read, Seek, SeekFrom, Write},
};

use crate::{
    crypto::{Cryptor, FileCryptor, FileHeader},
    util,
};

/// A modified version of read_exact that ignores an unexpected EOF, returning whether the whole
/// buffer could be filled and the number of bytes read.
pub fn try_read_exact<R: Read + ?Sized>(
    this: &mut R,
    mut buf: &mut [u8],
) -> io::Result<(bool, usize)> {
    let mut bytes_read: usize = 0;
    while !buf.is_empty() {
        match this.read(buf) {
            Ok(0) => break,
            Ok(n) => {
                buf = &mut buf[n..];
                bytes_read += n;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok((buf.is_empty(), bytes_read))
}

pub struct EncryptedStream<'k, I> {
    inner: I,
    cleartext_size: u64,
    cryptor: Cryptor<'k>,
    file_header: FileHeader,
    chunk_buffer: VecDeque<u8>,
}

impl<'k, I: Read + Seek + Write> EncryptedStream<'k, I> {
    pub fn open(cryptor: Cryptor<'k>, mut inner: I) -> io::Result<Self> {
        let mut encrypted_header = vec![0; cryptor.encrypted_header_len()];
        inner.rewind()?;
        let file_header = match inner.read_exact(&mut encrypted_header) {
            // Decrypt the file header if it exists
            Ok(()) => cryptor
                .decrypt_header(encrypted_header)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            // Otherwise, write a new one
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                let header = cryptor.new_header()?;
                let header_bytes = cryptor.encrypt_header(&header).map_err(io::Error::other)?;
                inner.rewind()?;
                inner.write_all(&header_bytes)?;
                header
            }
            Err(err) => return Err(err),
        };

        // Grab the length of the stream, then skip back to the end of the header
        // TODO: Use stream_len once stabilized?
        let old_pos = inner.stream_position()?;
        let cleartext_size = util::get_cleartext_size(cryptor, inner.seek(SeekFrom::End(0))?);
        if old_pos != cleartext_size {
            inner.seek(SeekFrom::Start(old_pos))?;
        }

        Ok(Self {
            inner,
            cleartext_size,
            cryptor,
            file_header,
            chunk_buffer: Default::default(),
        })
    }
}

impl<'k, I: Read + Seek> Read for EncryptedStream<'k, I> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.chunk_buffer.len() <= buf.len() {
            // Try to fill up the buffer's remaining space as best we can
            let chunks_to_read =
                1.max((buf.len() - self.chunk_buffer.len()) / self.cryptor.max_chunk_len());

            for _ in 0..chunks_to_read {
                let mut ciphertext_chunk = vec![0; self.cryptor.max_encrypted_chunk_len()];
                match try_read_exact(&mut self.inner, &mut ciphertext_chunk)? {
                    // Got EOF immediately
                    (false, 0) => break,
                    // Got some data, then hit EOF
                    (false, n) => ciphertext_chunk.truncate(n),
                    // Got a whole chunk, no EOF
                    _ => {}
                }

                // Find beginning of current chunk, ignore header, and divide by max chunk length
                let chunk_number = (self
                    .inner
                    .stream_position()?
                    .saturating_sub(ciphertext_chunk.len() as u64)
                    .saturating_sub(self.cryptor.encrypted_header_len() as u64))
                    / self.cryptor.max_encrypted_chunk_len() as u64;

                self.chunk_buffer.extend(
                    self.cryptor
                        .decrypt_chunk(ciphertext_chunk, &self.file_header, chunk_number as usize)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                );
            }
        }

        self.chunk_buffer.read(buf)
    }
}

impl<'k, I: Read + Seek> Seek for EncryptedStream<'k, I> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(n) => {
                let num_full_chunks = n / self.cryptor.max_chunk_len() as u64;
                let remainder = n % self.cryptor.max_chunk_len() as u64;

                // Move to the beginning of the appropriate chunk
                let chunk_start = self.cryptor.encrypted_header_len() as u64
                    + (num_full_chunks * self.cryptor.max_encrypted_chunk_len() as u64);
                self.inner.seek(SeekFrom::Start(chunk_start))?;

                // We're moving somewhere else, so forget the current chunk buffer
                self.chunk_buffer.clear();

                // Skip some bytes to move to the final position within the chunk
                let mut temp = vec![0; remainder as usize];
                self.read_exact(&mut temp)?;

                Ok(n)
            }
            SeekFrom::End(n) => {
                // Don't permit seeking past the beginning or end
                let offset = -n.max(0) as u64;
                self.seek(SeekFrom::Start(self.cleartext_size.saturating_sub(offset)))
            }
            SeekFrom::Current(n) => {
                let enc_header_len = self.cryptor.encrypted_header_len() as u64;
                let max_enc_chunk_len = self.cryptor.max_encrypted_chunk_len() as u64;
                let max_chunk_len = self.cryptor.max_chunk_len() as u64;

                let chunk_number = (self.inner.stream_position()?.saturating_sub(enc_header_len))
                    / max_enc_chunk_len;
                let chunk_remainder =
                    (self.inner.stream_position()?.saturating_sub(enc_header_len))
                        % max_enc_chunk_len;
                let remainder = chunk_remainder.saturating_sub(max_enc_chunk_len - max_chunk_len);

                let current_pos = chunk_number * max_chunk_len + remainder;

                let new_pos = if n > 0 {
                    current_pos.saturating_add_signed(n)
                } else {
                    current_pos.saturating_sub(-n as u64)
                };

                self.seek(SeekFrom::Start(new_pos))
            }
        }
    }
}

// TODO: Maybe review addition/subtraction for potential overflow/underflow
impl<'k, I: Read + Seek + Write> Write for EncryptedStream<'k, I> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let max_chunk_len = self.cryptor.max_chunk_len();

        let current_pos = self.stream_position()? as usize;
        let chunk_number = current_pos / max_chunk_len;
        let chunk_offset = current_pos % max_chunk_len;
        let chunk_start = chunk_number * max_chunk_len;
        println!(
            "chunk_number: {}, chunk_offset: {}, chunk_start: {}",
            chunk_number, chunk_offset, chunk_start
        );

        // Ensure we're positioned at a chunk boundary
        if chunk_offset > 0 {
            self.seek(SeekFrom::Start(chunk_start as u64))?;
        }

        let bytes_written;
        let mut ciphertext_chunk = vec![0; self.cryptor.max_encrypted_chunk_len()];
        let replacement_chunk = match try_read_exact(&mut self.inner, &mut ciphertext_chunk)? {
            // At EOF - replacement chunk is either a max-size chunk or the entire buffer,
            // whichever is smaller
            (false, 0) => {
                println!("end of file, adding chunk");
                let chunk = &buf[..buf.len().min(max_chunk_len)];
                bytes_written = chunk.len();
                self.cryptor
                    .encrypt_chunk(
                        chunk,
                        &self.file_header,
                        // We're writing a new chunk at the end
                        chunk_number + 1,
                    )
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            }
            // Within last chunk - replacement chunk is the last chunk overwritten with data from
            // buffer, up to one max-size chunk
            (false, n) => {
                println!("end of file, replacing partial chunk");
                ciphertext_chunk.truncate(n);
                let mut chunk = self
                    .cryptor
                    .decrypt_chunk(ciphertext_chunk, &self.file_header, chunk_number)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                chunk.resize(max_chunk_len, 0);
                bytes_written = (&mut chunk[chunk_offset..]).write(buf)?;
                // If we made the chunk bigger, truncate to a larger size than the original chunk.
                // Otherwise, truncate to the original chunk size.
                chunk.truncate(n.max(chunk_offset + bytes_written));

                self.cryptor
                    .encrypt_chunk(chunk, &self.file_header, chunk_number)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            }
            // Got a whole chunk
            _ => {
                println!("replacing full chunk");
                // If we're just overwriting the whole chunk, no need to decrypt existing chunk
                if chunk_offset == 0 && buf.len() >= max_chunk_len {
                    let chunk = &buf[..max_chunk_len];
                    bytes_written = chunk.len();
                    self.cryptor
                        .encrypt_chunk(chunk, &self.file_header, chunk_number)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                // Otherwise, write data from buffer into the existing chunk
                } else {
                    let mut chunk = self
                        .cryptor
                        .decrypt_chunk(ciphertext_chunk, &self.file_header, chunk_number)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    bytes_written = (&mut chunk[chunk_offset..]).write(buf)?;

                    self.cryptor
                        .encrypt_chunk(chunk, &self.file_header, chunk_number)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                }
            }
        };

        if bytes_written > 0 {
            self.inner.write_all(&replacement_chunk)?;
            self.cleartext_size = self.seek(SeekFrom::End(0))?;
            self.seek(SeekFrom::Start((current_pos + bytes_written) as u64))
                .unwrap();
        }

        Ok(bytes_written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// TEMPORARY until we implement Write for EncryptedStream

pub struct EncryptStream<'k, W: Write> {
    cryptor: Cryptor<'k>,
    inner: W,
    header: FileHeader,
    header_written: bool,
    chunk_number: usize,
    eof: bool,
    buffer: VecDeque<u8>,
}

impl<'k, W: Write> EncryptStream<'k, W> {
    pub fn new(cryptor: Cryptor<'k>, header: FileHeader, inner: W) -> Self {
        let buffer = VecDeque::with_capacity(cryptor.max_chunk_len());

        Self {
            cryptor,
            inner,
            header,
            header_written: false,
            chunk_number: 0,
            eof: false,
            buffer,
        }
    }
}

impl<'k, W: Write> Write for EncryptStream<'k, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // The file header must be written exactly once
        if !self.header_written {
            let header_bytes = self
                .cryptor
                .encrypt_header(&self.header)
                .map_err(io::Error::other)?;
            self.inner.write_all(&header_bytes)?;
            self.header_written = true;
        }

        if self.eof {
            return Ok(0);
        }

        self.buffer.extend(buf);

        // Write as many full chunks as possible
        while self.buffer.len() >= self.cryptor.max_chunk_len() {
            let mut chunk = vec![0; self.cryptor.max_chunk_len()];
            self.buffer.read_exact(&mut chunk)?;
            self.inner.write_all(
                &self
                    .cryptor
                    .encrypt_chunk(chunk, &self.header, self.chunk_number)
                    .map_err(io::Error::other)?,
            )?;
            self.chunk_number += 1;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Write partial chunk if any leftover data in buffer
        if !self.buffer.is_empty() {
            debug_assert!(self.buffer.len() < self.cryptor.max_chunk_len());
            let mut chunk = vec![0; self.buffer.len()];
            self.buffer.read_exact(&mut chunk)?;
            self.inner.write_all(
                &self
                    .cryptor
                    .encrypt_chunk(chunk, &self.header, self.chunk_number)
                    .map_err(io::Error::other)?,
            )?;
            self.chunk_number += 1;
            // Because we wrote a partial chunk, this has to be the last one
            self.eof = true;
        }

        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64Url, Encoding};
    use io::Cursor;

    use crate::{crypto::siv_ctrmac, key::SUBKEY_LEN, MasterKey};

    use super::*;

    #[test]
    fn stream_write_test() {
        // Safe, this is for test purposes only
        let key = unsafe { MasterKey::from_bytes([19_u8; SUBKEY_LEN * 2]) };
        let cryptor = Cryptor::SivCtrMac(siv_ctrmac::Cryptor::new(&key));

        let mut buffer: Vec<u8> = vec![];
        let mut stream = EncryptedStream::open(cryptor, Cursor::new(&mut buffer)).unwrap();
        stream.write_all(b"this is a").unwrap();
        stream.write_all(b"test").unwrap();
        stream.flush().unwrap();

        let header = stream.file_header.clone();
        drop(stream);

        dbg!(Base64Url::encode_string(&buffer));

        let mut stream = EncryptStream::new(cryptor, header, Cursor::new(&mut buffer));
        stream.write_all(b"this is a").unwrap();
        stream.write_all(b"test").unwrap();
        stream.flush().unwrap();

        dbg!(Base64Url::encode_string(&buffer));
    }
}
