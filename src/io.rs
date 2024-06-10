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

pub struct EncryptedStream<'k, I: Read + Seek> {
    inner: I,
    cleartext_size: u64,
    cryptor: Cryptor<'k>,
    file_header: FileHeader,
    chunk_buffer: VecDeque<u8>,
}

impl<'k, I: Read + Seek> EncryptedStream<'k, I> {
    pub fn open(cryptor: Cryptor<'k>, ciphertext_size: u64, mut inner: I) -> io::Result<Self> {
        let mut encrypted_header = vec![0; cryptor.encrypted_header_len()];
        inner.read_exact(&mut encrypted_header)?;
        let file_header = cryptor
            .decrypt_header(encrypted_header)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Self {
            inner,
            cleartext_size: util::get_cleartext_size(cryptor, ciphertext_size),
            cryptor,
            file_header,
            chunk_buffer: Default::default(),
        })
    }
}

// TODO: Handle overflow/underflow as needed
impl<'k, I: Read + Seek> Read for EncryptedStream<'k, I> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Try to use buffered data first if available
        let mut bytes_read = self.chunk_buffer.read(buf)?;
        if bytes_read == buf.len() {
            return Ok(bytes_read);
        }

        let mut ciphertext_chunk = vec![0; self.cryptor.max_encrypted_chunk_len()];
        match try_read_exact(&mut self.inner, &mut ciphertext_chunk)? {
            // Got EOF immediately
            (false, 0) => {
                return Ok(bytes_read);
            }
            // Got some data, then hit EOF
            (false, n) => {
                ciphertext_chunk.truncate(n);
            }
            // Got a whole chunk, no EOF
            _ => {}
        }

        // Find beginning of current chunk, ignore header, and divide by max chunk length
        let chunk_number = (self.inner.stream_position()?
            - ciphertext_chunk.len() as u64
            - self.cryptor.encrypted_header_len() as u64)
            / self.cryptor.max_encrypted_chunk_len() as u64;

        self.chunk_buffer.extend(
            self.cryptor
                .decrypt_chunk(ciphertext_chunk, &self.file_header, chunk_number as usize)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        );

        bytes_read += self.chunk_buffer.read(&mut buf[bytes_read..])?;

        Ok(bytes_read)
    }
}

// TODO: Handle overflow/underflow as needed
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
                // Don't permit seeking beyond the end
                let offset = -n.max(0) as u64;
                self.seek(SeekFrom::Start(self.cleartext_size - offset))
            }
            SeekFrom::Current(n) => {
                let enc_header_len = self.cryptor.encrypted_header_len() as u64;
                let max_enc_chunk_len = self.cryptor.max_encrypted_chunk_len() as u64;
                let max_chunk_len = self.cryptor.max_chunk_len() as u64;

                let chunk_number =
                    (self.inner.stream_position()? - enc_header_len) / max_enc_chunk_len;
                let mut chunk_remainder =
                    (self.inner.stream_position()? - enc_header_len) % max_enc_chunk_len;

                if chunk_remainder > 0 {
                    chunk_remainder -= max_enc_chunk_len - max_chunk_len;
                }

                let current_pos = chunk_number * max_chunk_len + chunk_remainder;

                let new_pos = if n > 0 {
                    current_pos + n as u64
                } else {
                    current_pos - -n as u64
                };

                self.seek(SeekFrom::Start(new_pos))
            }
        }
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
