use std::{
    collections::VecDeque,
    fs::File,
    io::{self, BufReader, Read, Seek, SeekFrom},
};

use crate::{
    crypto::{Cryptor, FileCryptor, FileHeader},
    io::try_read_exact,
};

pub struct EncryptedFile<'k> {
    cryptor: Cryptor<'k>,
    file: File,
    file_header: FileHeader,
    chunk_buffer: VecDeque<u8>,
}

impl<'k> EncryptedFile<'k> {
    pub fn open(cryptor: Cryptor<'k>, file: File) -> io::Result<Self> {
        let mut encrypted_header = vec![0; cryptor.encrypted_header_len()];
        BufReader::new(&file).read_exact(&mut encrypted_header)?;
        let file_header = cryptor
            .decrypt_header(encrypted_header)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        Ok(Self {
            cryptor,
            file,
            file_header,
            chunk_buffer: Default::default(),
        })
    }

    pub fn get_cleartext_size(cryptor: Cryptor<'k>, ciphertext_size: u64) -> u64 {
        let max_enc_chunk_len = cryptor.max_encrypted_chunk_len() as u64;
        let max_chunk_len = cryptor.max_chunk_len() as u64;
        let enc_chunks_len = ciphertext_size - cryptor.encrypted_header_len() as u64;
        let num_full_chunks = enc_chunks_len / max_enc_chunk_len;
        // TODO: What if modulo returns 0
        let remainder = enc_chunks_len % max_enc_chunk_len - (max_enc_chunk_len - max_chunk_len);

        num_full_chunks * max_chunk_len + remainder
    }
}

impl<'k> Read for EncryptedFile<'k> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Try to use buffered data first if available
        let mut bytes_read = self.chunk_buffer.read(buf)?;
        if bytes_read == buf.len() {
            return Ok(bytes_read);
        }

        let mut reader =
            BufReader::with_capacity(self.cryptor.max_encrypted_chunk_len(), &self.file);
        let mut ciphertext_chunk = vec![0; self.cryptor.max_encrypted_chunk_len()];
        match try_read_exact(&mut reader, &mut ciphertext_chunk)? {
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
        let chunk_number = (self.file.stream_position()?
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
impl<'k> Seek for EncryptedFile<'k> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match pos {
            SeekFrom::Start(n) => {
                let num_full_chunks = n / self.cryptor.max_chunk_len() as u64;
                let remainder = n % self.cryptor.max_chunk_len() as u64;

                // Move to the beginning of the appropriate chunk
                let chunk_start = self.cryptor.encrypted_header_len() as u64
                    + (num_full_chunks * self.cryptor.max_encrypted_chunk_len() as u64);
                self.file.seek(SeekFrom::Start(chunk_start))?;

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
                let cleartext_size =
                    Self::get_cleartext_size(self.cryptor, self.file.metadata()?.len());
                self.seek(SeekFrom::Start(cleartext_size - offset))
            }
            SeekFrom::Current(n) => {
                let enc_header_len = self.cryptor.encrypted_header_len() as u64;
                let max_enc_chunk_len = self.cryptor.max_encrypted_chunk_len() as u64;
                let max_chunk_len = self.cryptor.max_chunk_len() as u64;

                let chunk_number =
                    (self.file.stream_position()? - enc_header_len) / max_enc_chunk_len;
                let mut chunk_remainder =
                    (self.file.stream_position()? - enc_header_len) % max_enc_chunk_len;

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
