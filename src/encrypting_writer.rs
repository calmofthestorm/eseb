use anyhow::{Context, Result};
use record_reader::{RecordReader, RecordWriter};
use sodiumoxide::crypto::secretstream;

use std::collections::VecDeque;
use std::io::{BufRead, Read, Write};

use crate::SymmetricKey;

pub struct EncryptingWriter<O: RecordWriter> {
    inner: Option<O>,
    stream: secretstream::Stream<secretstream::Push>,
    compress: bool,
}

pub struct DecryptingReader<I: RecordReader> {
    inner: I,
    stream: secretstream::Stream<secretstream::Pull>,
    compress: bool,
    buf: VecDeque<u8>,
}

impl<O: RecordWriter> EncryptingWriter<O> {
    pub fn new(mut inner: O, key: SymmetricKey, compress: bool) -> Result<EncryptingWriter<O>> {
        let (stream, header) = secretstream::Stream::init_push(key.as_ref())
            .ok()
            .context("NaCl init_push")?;

        inner
            .write_record(header.as_ref())
            .context("write header")?;

        Ok(EncryptingWriter {
            inner: Some(inner),
            stream,
            compress,
        })
    }

    #[must_use]
    pub fn into_inner(mut self) -> Result<O> {
        self.write_record_internal(b"", secretstream::Tag::Final)
            .context("finalize stream")?;
        self.inner.take().context("already called finish")
    }

    pub(crate) fn write_record_internal<'a>(
        &'a mut self,
        data: &[u8],
        tag: secretstream::Tag,
    ) -> Result<()> {
        let crypttext = self
            .stream
            .push(data, None, tag)
            .ok()
            .context("encrypt chunk")?;
        self.inner
            .as_mut()
            .context("already called finish")?
            .write_record(&crypttext)
            .context("write chunk")
    }
}

impl<O: RecordWriter> Write for EncryptingWriter<O> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.compress {
            let mut v = Vec::default();
            let mut compressor = brotli::CompressorReader::new(&*buf, 8192, 8, 18);
            compressor
                .read_to_end(&mut v)
                .expect("Compression must not fail.");
            self.write_record_internal(&v, secretstream::Tag::Push)
        } else {
            self.write_record_internal(buf, secretstream::Tag::Push)
        }
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        .map(|()| buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<I: RecordReader> DecryptingReader<I> {
    pub fn new(mut inner: I, key: SymmetricKey, compress: bool) -> Result<DecryptingReader<I>> {
        let data = inner.read_record().context("read header")?;
        let header = secretstream::xchacha20poly1305::Header::from_slice(&data)
            .context("parse stream header")?;

        let stream = secretstream::Stream::init_pull(&header, key.as_ref())
            .ok()
            .context("NaCl init_pull")?;

        Ok(DecryptingReader {
            inner,
            stream,
            compress,
            buf: VecDeque::default(),
        })
    }

    #[must_use]
    pub fn into_inner(self) -> I {
        self.inner
    }

    fn fill_buf_internal(&mut self) -> Result<&[u8]> {
        while self.buf.is_empty() {
            match self
                .inner
                .maybe_read_record()
                .context("read crypt record")?
            {
                None => return Ok(b""),
                Some(rec) => {
                    let (cleartext, _tag) =
                        self.stream.pull(rec, None).ok().context("decrypt chunk")?;
                    if self.compress && !cleartext.is_empty() {
                        brotli::BrotliDecompress(&mut cleartext.as_slice(), &mut self.buf)
                            .context("decompress")?;
                    } else {
                        self.buf.extend(&cleartext);
                    }
                }
            }
        }

        let (head, tail) = self.buf.as_slices();

        if !head.is_empty() {
            return Ok(head);
        }

        if !tail.is_empty() {
            return Ok(tail);
        }

        unreachable!()
    }

    fn read_internal(&mut self, buf: &mut [u8]) -> Result<usize> {
        let nread = {
            let mut rem = self.fill_buf()?;
            rem.read(buf)?
        };
        self.consume(nread);
        Ok(nread)
    }
}

impl<O: RecordReader> Read for DecryptingReader<O> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_internal(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }
}

impl<O: RecordReader> BufRead for DecryptingReader<O> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.fill_buf_internal()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
    }

    fn consume(&mut self, amt: usize) {
        self.buf.drain(..amt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use record_reader::{BufferRecordReader, BufferRecordWriter, Format};

    fn empty_test(compress: bool) {
        let key = SymmetricKey::gen_key().unwrap();
        let crypt_writer = EncryptingWriter::new(
            BufferRecordWriter::new(Format::Record32),
            key.clone(),
            compress,
        )
        .unwrap();

        let crypttext = crypt_writer.into_inner().unwrap().into_cow();

        let mut crypt_reader = DecryptingReader::new(
            BufferRecordReader::new(crypttext, Format::Record32, usize::MAX),
            key,
            compress,
        )
        .unwrap();

        let mut buf = [0 as u8; 64];

        assert_eq!(crypt_reader.read(&mut buf[..1]).unwrap(), 0);
    }

    fn smoke_test(compress: bool) {
        let key = SymmetricKey::gen_key().unwrap();
        let mut crypt_writer = EncryptingWriter::new(
            BufferRecordWriter::new(Format::Record32),
            key.clone(),
            compress,
        )
        .unwrap();

        crypt_writer.write_all(b"th").unwrap();
        crypt_writer.write_all(b"is ").unwrap();
        crypt_writer.write_all(b"is").unwrap();
        crypt_writer.write_all(b" Halloween").unwrap();

        let crypttext = crypt_writer.into_inner().unwrap().into_cow();

        let mut crypt_reader = DecryptingReader::new(
            BufferRecordReader::new(crypttext, Format::Record32, usize::MAX),
            key,
            compress,
        )
        .unwrap();

        let mut buf = [0 as u8; 64];

        crypt_reader.read_exact(&mut buf[..1]).unwrap();
        assert_eq!(&buf[..1], *b"t");

        crypt_reader.read_exact(&mut buf[..4]).unwrap();
        assert_eq!(&buf[..4], *b"his ");

        crypt_reader.read_exact(&mut buf[..11]).unwrap();
        assert_eq!(&buf[..11], *b"is Hallowee");

        crypt_reader.read_exact(&mut buf[..1]).unwrap();
        assert_eq!(&buf[..1], *b"n");

        assert_eq!(crypt_reader.read(&mut buf[..1]).unwrap(), 0);
    }

    #[test]
    fn test_smoke_compress() {
        smoke_test(/*compress=*/ true);
    }

    #[test]
    fn test_smoke() {
        smoke_test(/*compress=*/ false);
    }

    #[test]
    fn test_empty_compress() {
        empty_test(/*compress=*/ true);
    }

    #[test]
    fn test_empty() {
        empty_test(/*compress=*/ false);
    }
}
