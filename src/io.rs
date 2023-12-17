use std::{
    collections::VecDeque,
    io::{self, Read},
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

pub struct EncryptedStream<C: FileCryptor, R: Read> {
    cryptor: C,
    inner: R,
    header: Option<C::Header>,
    chunk_number: usize,
    eof: bool,
    buffered_cleartext: VecDeque<u8>,
}

impl<C: FileCryptor, R: Read> EncryptedStream<C, R> {
    pub fn new(cryptor: C, inner: R) -> Self {
        Self {
            cryptor,
            inner,
            header: None,
            chunk_number: 0,
            eof: false,
            buffered_cleartext: VecDeque::with_capacity(C::CHUNK_SIZE),
        }
    }
}

impl<C: FileCryptor, R: Read> Read for EncryptedStream<C, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // The file header must be read exactly once
        if self.header.is_none() {
            let mut encrypted_header = vec![0; C::Header::HEADER_SIZE];
            self.inner.read_exact(&mut encrypted_header)?;
            self.header.replace(
                self.cryptor
                    .decrypt_header(&encrypted_header)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            );
        }

        // If we have leftover data from a previous read, write that to buf
        if !self.buffered_cleartext.is_empty() {
            return self.buffered_cleartext.read(buf);
        }

        if self.eof {
            return Ok(0);
        }

        let mut ciphertext_chunk = vec![0; C::CHUNK_SIZE];
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

        self.buffered_cleartext.extend(
            self.cryptor
                .decrypt_chunk(&ciphertext_chunk, header, self.chunk_number)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        );
        self.chunk_number += 1;
        self.buffered_cleartext.read(buf)
    }
}
