use std::{
    collections::VecDeque,
    io::{self, Read, Write},
};

use crate::crypto::{FileCryptor, FileHeader};

/// A modified version of read_exact that ignores an unexpected EOF, returning whether the whole
/// buffer could be filled and the number of bytes read.
fn try_read_exact<R: Read + ?Sized>(this: &mut R, mut buf: &mut [u8]) -> io::Result<(bool, usize)> {
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

pub struct DecryptStream<C: FileCryptor, R: Read> {
    cryptor: C,
    inner: R,
    header: Option<C::Header>,
    chunk_number: usize,
    eof: bool,
    buffer: VecDeque<u8>,
}

impl<C: FileCryptor, R: Read> DecryptStream<C, R> {
    pub fn new(cryptor: C, inner: R) -> Self {
        Self {
            cryptor,
            inner,
            header: None,
            chunk_number: 0,
            eof: false,
            buffer: VecDeque::with_capacity(C::MAX_CHUNK_LEN),
        }
    }
}

impl<C: FileCryptor, R: Read> Read for DecryptStream<C, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // The file header must be read exactly once
        if self.header.is_none() {
            let mut encrypted_header = vec![0; C::Header::ENCRYPTED_HEADER_LEN];
            self.inner.read_exact(&mut encrypted_header)?;
            self.header.replace(
                self.cryptor
                    .decrypt_header(encrypted_header)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            );
        }

        // If we have leftover data from a previous read, write that to buf
        if !self.buffer.is_empty() {
            return self.buffer.read(buf);
        }

        if self.eof {
            return Ok(0);
        }

        let mut ciphertext_chunk = vec![0; C::MAX_ENCRYPTED_CHUNK_LEN];
        match try_read_exact(&mut self.inner, &mut ciphertext_chunk)? {
            // Got EOF immediately
            (false, 0) => {
                self.eof = true;
                return Ok(0);
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

        self.buffer.extend(
            self.cryptor
                .decrypt_chunk(ciphertext_chunk, header, self.chunk_number)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        );
        self.chunk_number += 1;
        self.buffer.read(buf)
    }
}

pub struct EncryptStream<C: FileCryptor, W: Write> {
    cryptor: C,
    inner: W,
    header: C::Header,
    header_written: bool,
    chunk_number: usize,
    eof: bool,
    buffer: VecDeque<u8>,
}

impl<C: FileCryptor, W: Write> EncryptStream<C, W> {
    pub fn new(cryptor: C, header: C::Header, inner: W) -> Self {
        Self {
            cryptor,
            inner,
            // TODO: Use Header::new? i.e. do we re-encrypt everything with a new content key?
            header,
            header_written: false,
            chunk_number: 0,
            eof: false,
            buffer: VecDeque::with_capacity(C::MAX_CHUNK_LEN),
        }
    }
}

impl<C: FileCryptor, W: Write> Write for EncryptStream<C, W> {
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
        while self.buffer.len() >= C::MAX_CHUNK_LEN {
            let mut chunk = vec![0; C::MAX_CHUNK_LEN];
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
            debug_assert!(self.buffer.len() < C::MAX_CHUNK_LEN);
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
