use std::{
    collections::VecDeque,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
};

use crate::crypto::{Cryptor, FileCryptor, FileHeader};

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

pub struct DecryptStream<'k, R: Read> {
    cryptor: Cryptor<'k>,
    inner: R,
    header: Option<FileHeader>,
    chunk_number: usize,
    eof: bool,
    buffer: Cursor<Vec<u8>>,
}

impl<'k, R: Read> DecryptStream<'k, R> {
    pub fn new(cryptor: Cryptor<'k>, inner: R) -> Self {
        Self {
            cryptor,
            inner,
            header: None,
            chunk_number: 0,
            eof: false,
            buffer: Default::default(),
        }
    }
}

impl<'k, R: Read> Read for DecryptStream<'k, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // The file header must be read exactly once
        if self.header.is_none() {
            let mut encrypted_header = vec![0; self.cryptor.encrypted_header_len()];
            self.inner.read_exact(&mut encrypted_header)?;
            self.header.replace(
                self.cryptor
                    .decrypt_header(encrypted_header)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            );
        }

        // Try to use buffered data first if available
        let mut bytes_read = self.buffer.read(buf)?;
        if bytes_read == buf.len() || self.eof {
            return Ok(bytes_read);
        }

        let mut ciphertext_chunk = vec![0; self.cryptor.max_encrypted_chunk_len()];
        match try_read_exact(&mut self.inner, &mut ciphertext_chunk)? {
            // Got EOF immediately
            (false, 0) => {
                self.eof = true;
                return Ok(bytes_read);
            }
            // Got some data, then hit EOF
            (false, n) => {
                ciphertext_chunk.truncate(n);
                self.eof = true;
            }
            // Got a whole chunk, no EOF
            _ => {}
        }

        // Safe to unwrap, header has been read by now
        let header = self.header.as_ref().unwrap();

        self.buffer.get_mut().extend(
            self.cryptor
                .decrypt_chunk(ciphertext_chunk, header, self.chunk_number)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        );
        self.chunk_number += 1;

        bytes_read += self.buffer.read(&mut buf[bytes_read..])?;
        Ok(bytes_read)
    }
}

impl<'k, R: Read> Seek for DecryptStream<'k, R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        // TODO: Handle overflow/underflow where appropriate
        match pos {
            SeekFrom::Start(n) => {
                if n > self.buffer.position() {
                    let mut buf = vec![0; (n - self.buffer.position()) as usize];
                    self.read_exact(&mut buf)?;
                }

                self.buffer.seek(pos)
            }
            SeekFrom::End(_) => {
                self.buffer.seek(SeekFrom::End(0))?;
                let mut buf = Vec::new();
                self.read_to_end(&mut buf)?;

                self.buffer.seek(pos)
            }
            SeekFrom::Current(n) => {
                if n > 0 {
                    self.seek(SeekFrom::Start(self.buffer.position() + n as u64))
                } else {
                    self.buffer.seek(pos)
                }
            }
        }
    }
}

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
