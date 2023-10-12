use anyhow::{Context, Result};
use record_reader::{RecordReader, RecordWriter};
use sodiumoxide::crypto::secretstream;

use std::io::Read;

use crate::SymmetricKey;

pub struct EncryptingRecordWriter<O: RecordWriter> {
    inner: Option<O>,
    stream: secretstream::Stream<secretstream::Push>,
    compress: bool,
}

pub struct DecryptingRecordWriter<O: RecordWriter> {
    inner: Option<(O, DecryptState, Vec<u8>)>,
    compress: bool,
}

enum DecryptState {
    WantHeader(SymmetricKey),
    WantData(secretstream::Stream<secretstream::Pull>),
    Finished,
}

impl<O: RecordWriter> DecryptingRecordWriter<O> {
    pub fn new(inner: O, key: SymmetricKey, compress: bool) -> Result<DecryptingRecordWriter<O>> {
        Ok(DecryptingRecordWriter {
            inner: Some((inner, DecryptState::WantHeader(key), Vec::default())),
            compress,
        })
    }

    #[must_use]
    pub fn into_inner(mut self) -> Result<O> {
        self.into_inner_internal()?;
        Ok(self.inner.take().expect("").0)
    }

    fn into_inner_internal(&mut self) -> Result<()> {
        let (ref mut writer, _state, ref mut buf) =
            self.inner.as_mut().context("already called finish")?;
        if !buf.is_empty() {
            Self::write_internal(writer, buf, Vec::default(), self.compress)
                .expect("write final chunk at into_inner");
        }

        Ok(())
    }

    pub(crate) fn write_internal(
        writer: &mut O,
        buf: &mut Vec<u8>,
        mut cleartext: Vec<u8>,
        compress: bool,
    ) -> Result<()> {
        let data = if buf.is_empty() {
            cleartext
        } else {
            buf.append(&mut cleartext);
            std::mem::take(buf)
        };

        if compress {
            let mut v = Vec::default();
            brotli::BrotliDecompress(&mut data.as_slice(), &mut v).context("decompress")?;
            writer.write_record(&v)?;
        } else {
            writer.write_record(&data)?;
        }

        buf.clear();

        Ok(())
    }
}

impl<O: RecordWriter> RecordWriter for DecryptingRecordWriter<O> {
    fn write_record<'a>(&'a mut self, data: &[u8]) -> Result<()> {
        match self.inner.take().context("already called finish")? {
            (writer, DecryptState::WantHeader(key), buf) => {
                let header = secretstream::xchacha20poly1305::Header::from_slice(data)
                    .context("parse stream header")?;

                let stream = secretstream::Stream::init_pull(&header, key.as_ref())
                    .ok()
                    .context("NaCl init_pull")?;

                self.inner = Some((writer, DecryptState::WantData(stream), buf));
            }
            (mut writer, DecryptState::WantData(mut stream), mut buf) => {
                if stream.is_finalized() {
                    anyhow::bail!("stream marked finalized without Final tag");
                }

                let (mut cleartext, tag) = stream.pull(data, None).ok().context("decrypt chunk")?;
                match tag {
                    secretstream::Tag::Final => {
                        if !cleartext.is_empty() || !buf.is_empty() {
                            Self::write_internal(&mut writer, &mut buf, cleartext, self.compress)
                                .context("write final chunk")?;
                        }
                        self.inner = Some((writer, DecryptState::Finished, buf));
                    }
                    secretstream::Tag::Message => {
                        buf.append(&mut cleartext);
                        self.inner = Some((writer, DecryptState::WantData(stream), buf));
                    }
                    secretstream::Tag::Rekey => {
                        anyhow::bail!("received a Rekey tag which we don't use")
                    }
                    secretstream::Tag::Push => {
                        Self::write_internal(&mut writer, &mut buf, cleartext, self.compress)
                            .context("write chunk")?;
                        self.inner = Some((writer, DecryptState::WantData(stream), buf));
                    }
                }
            }
            (writer, DecryptState::Finished, buf) => {
                self.inner = Some((writer, DecryptState::Finished, buf));
                anyhow::bail!("write_record called after finished");
            }
        }

        Ok(())
    }

    // Flushing does not flush any partial messages in the buffer.
    fn flush(&mut self) -> Result<()> {
        self.inner
            .as_mut()
            .context("flush called after finished")?
            .0
            .flush()
            .context("flush DecryptingRecordWriter")
    }
}

impl<O: RecordWriter> Drop for DecryptingRecordWriter<O> {
    fn drop(&mut self) {
        if self.inner.is_some() {
            self.into_inner_internal()
                .expect("write final chunk at drop");
            self.inner
                .as_mut()
                .expect("")
                .0
                .flush()
                .expect("flush at drop");
        }
    }
}

impl<O: RecordWriter> EncryptingRecordWriter<O> {
    pub fn new(
        mut inner: O,
        key: SymmetricKey,
        compress: bool,
    ) -> Result<EncryptingRecordWriter<O>> {
        let (stream, header) = secretstream::Stream::init_push(key.as_ref())
            .ok()
            .context("NaCl init_push")?;

        inner
            .write_record(header.as_ref())
            .context("write header")?;

        Ok(EncryptingRecordWriter {
            inner: Some(inner),
            stream,
            compress,
        })
    }

    #[must_use]
    pub fn into_inner(mut self) -> Result<O> {
        self.into_inner_internal()?;
        self.inner.take().context("already called finish")
    }

    fn into_inner_internal(&mut self) -> Result<()> {
        self.write_record_internal(b"", secretstream::Tag::Final)
            .context("finalize stream")
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

impl<O: RecordWriter> RecordWriter for EncryptingRecordWriter<O> {
    fn write_record<'a>(&'a mut self, data: &[u8]) -> Result<()> {
        if self.compress {
            let mut v = Vec::default();
            let mut compressor = brotli::CompressorReader::new(&*data, 8192, 8, 18);
            compressor
                .read_to_end(&mut v)
                .expect("Compression must not fail.");
            self.write_record_internal(&v, secretstream::Tag::Push)
        } else {
            self.write_record_internal(data, secretstream::Tag::Push)
        }
    }

    fn flush(&mut self) -> Result<()> {
        let inner = self.inner.as_mut().context("flush called after finished")?;
        inner.flush().context("flush EncryptingRecordWriter")
    }
}

impl<O: RecordWriter> Drop for EncryptingRecordWriter<O> {
    fn drop(&mut self) {
        if self.inner.is_some() {
            self.into_inner_internal()
                .expect("write final chunk at drop");
            self.inner
                .as_mut()
                .expect("")
                .flush()
                .expect("flush at drop");
        }
    }
}

pub struct DecryptingRecordReader<I: RecordReader> {
    inner: I,
    stream: Option<secretstream::Stream<secretstream::Pull>>,
    compress: bool,
    buf: Vec<u8>,
}

impl<I: RecordReader> DecryptingRecordReader<I> {
    pub fn new(
        mut inner: I,
        key: SymmetricKey,
        compress: bool,
    ) -> Result<DecryptingRecordReader<I>> {
        let data = inner.read_record().context("read header")?;
        let header = secretstream::xchacha20poly1305::Header::from_slice(&data)
            .context("parse stream header")?;

        let stream = Some(
            secretstream::Stream::init_pull(&header, key.as_ref())
                .ok()
                .context("NaCl init_pull")?,
        );

        Ok(DecryptingRecordReader {
            inner,
            stream,
            compress,
            buf: Vec::default(),
        })
    }

    #[must_use]
    pub fn into_inner(self) -> I {
        self.inner
    }

    fn maybe_read_record_internal<'a>(
        mut stream: secretstream::Stream<secretstream::Pull>,
        reader: &mut I,
        buf: &'a mut Vec<u8>,
    ) -> Result<(Option<secretstream::Stream<secretstream::Pull>>, Vec<u8>)> {
        // The buffer we return must remain valid until the next record is read.
        // We optimize for the case that there is one/few NaCl messages per
        // message we return, hence the lack of somet kind of VecBuilder.
        buf.clear();
        while let Some(data) = reader.maybe_read_record().context("read record")? {
            let (mut cleartext, tag) = stream.pull(data, None).ok().context("decrypt chunk")?;

            match tag {
                secretstream::Tag::Final => {
                    return Ok((None, cleartext));
                }
                secretstream::Tag::Message => {
                    buf.append(&mut cleartext);
                }
                secretstream::Tag::Rekey => {
                    anyhow::bail!("received a Rekey tag which we don't use")
                }
                secretstream::Tag::Push => {
                    return Ok((Some(stream), cleartext));
                }
            }
        }

        Ok((None, Vec::default()))
    }
}

impl<I: RecordReader> RecordReader for DecryptingRecordReader<I> {
    fn maybe_read_record<'a>(&'a mut self) -> Result<Option<&'a [u8]>> {
        let stream = match self.stream.take() {
            None => return Ok(None),
            Some(stream) => stream,
        };

        if stream.is_finalized() {
            anyhow::bail!("stream marked finalized without Final tag");
        }

        let (stream, mut cleartext) =
            Self::maybe_read_record_internal(stream, &mut self.inner, &mut self.buf)?;

        self.stream = stream;

        if self.buf.is_empty() && cleartext.is_empty() {
            if self.stream.is_some() {
                Ok(Some(b""))
            } else {
                Ok(None)
            }
        } else {
            if !self.buf.is_empty() && !cleartext.is_empty() {
                self.buf.append(&mut cleartext);
            } else if self.buf.is_empty() {
                std::mem::swap(&mut self.buf, &mut cleartext);
            } else if cleartext.is_empty() {
                // Do nothing.
            } // else covered above.

            if self.compress {
                let v = std::mem::take(&mut self.buf);
                brotli::BrotliDecompress(&mut v.as_slice(), &mut self.buf).context("decompress")?;
            }

            Ok(Some(&self.buf[..]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use record_reader::{BufferRecordReader, BufferRecordWriter, Format, RecordReader};

    fn decrypt(
        crypt_writer: EncryptingRecordWriter<BufferRecordWriter>,
        key: SymmetricKey,
        compress: bool,
    ) -> BufferRecordReader<'static> {
        decrypt2(crypt_writer.into_inner().unwrap().into_cow(), key, compress)
    }

    fn decrypt2(
        ciphertext: std::borrow::Cow<'static, [u8]>,
        key: SymmetricKey,
        compress: bool,
    ) -> BufferRecordReader<'static> {
        // Try both ways of decrypting.
        let cleartext1 = {
            let mut cipher_reader = BufferRecordReader::new(
                ciphertext.clone(),
                Format::Record32,
                std::u32::MAX as usize,
            );
            let mut clear_writer = DecryptingRecordWriter::new(
                BufferRecordWriter::new(Format::Record32),
                key.clone(),
                compress,
            )
            .unwrap();

            while let Some(rec) = cipher_reader.maybe_read_record().unwrap() {
                clear_writer.write_record(&rec).unwrap();
            }

            clear_writer.into_inner().unwrap().into_cow()
        };

        let cleartext2 = {
            let cipher_reader =
                BufferRecordReader::new(ciphertext, Format::Record32, std::u32::MAX as usize);
            let mut clear_reader =
                DecryptingRecordReader::new(cipher_reader, key, compress).unwrap();
            let mut clear_writer = BufferRecordWriter::new(Format::Record32);

            while let Some(rec) = clear_reader.maybe_read_record().unwrap() {
                clear_writer.write_record(rec).unwrap();
            }

            clear_writer.into_cow()
        };

        assert_eq!(cleartext1, cleartext2);

        BufferRecordReader::new(cleartext1, Format::Record32, std::u32::MAX as usize)
    }

    // Needed for backward compatibility to be able to decrypt files from a
    // non-published previous version.
    #[test]
    fn test_multi_message_chunk() {
        const COMPRESS: bool = false;

        let key = SymmetricKey::gen_key().unwrap();
        let mut crypt_writer = EncryptingRecordWriter::new(
            BufferRecordWriter::new(Format::Record32),
            key.clone(),
            COMPRESS,
        )
        .unwrap();
        crypt_writer
            .write_record_internal(b"this ", secretstream::Tag::Message)
            .unwrap();
        crypt_writer
            .write_record_internal(b"is ", secretstream::Tag::Message)
            .unwrap();
        crypt_writer
            .write_record_internal(b"halloween", secretstream::Tag::Push)
            .unwrap();
        crypt_writer
            .write_record_internal(b"this is halloween", secretstream::Tag::Push)
            .unwrap();
        crypt_writer
            .write_record_internal(b"this is ", secretstream::Tag::Message)
            .unwrap();
        crypt_writer
            .write_record_internal(b"halloween", secretstream::Tag::Message)
            .unwrap();
        let mut clear_reader = decrypt(crypt_writer, key, COMPRESS);

        for _ in 0..3 {
            assert_eq!(clear_reader.read_record().unwrap(), b"this is halloween");
        }
    }

    // Needed for backward compatibility to be able to decrypt files from a
    // non-published previous version.
    #[test]
    fn test_multi_message_chunk_with_final_payload() {
        const COMPRESS: bool = false;

        let key = SymmetricKey::gen_key().unwrap();
        let mut crypt_writer = EncryptingRecordWriter::new(
            BufferRecordWriter::new(Format::Record32),
            key.clone(),
            COMPRESS,
        )
        .unwrap();
        crypt_writer
            .write_record_internal(b"this is ", secretstream::Tag::Message)
            .unwrap();
        crypt_writer
            .write_record_internal(b"halloween", secretstream::Tag::Final)
            .unwrap();
        let mut clear_reader =
            decrypt2(crypt_writer.inner.take().unwrap().into_cow(), key, COMPRESS);
        assert_eq!(clear_reader.read_record().unwrap(), b"this is halloween");
    }

    // Needed for backward compatibility to be able to decrypt files from a
    // non-published previous version.
    #[test]
    fn test_multi_message_chunk_with_only_final_payload() {
        const COMPRESS: bool = false;

        let key = SymmetricKey::gen_key().unwrap();
        let mut crypt_writer = EncryptingRecordWriter::new(
            BufferRecordWriter::new(Format::Record32),
            key.clone(),
            COMPRESS,
        )
        .unwrap();
        crypt_writer
            .write_record_internal(b"this is halloween", secretstream::Tag::Final)
            .unwrap();
        let mut clear_reader =
            decrypt2(crypt_writer.inner.take().unwrap().into_cow(), key, COMPRESS);
        assert_eq!(clear_reader.read_record().unwrap(), b"this is halloween");
    }

    fn chunk_test(chunks: Vec<&'static [u8]>) {
        const COMPRESS: bool = true;
        let key = SymmetricKey::gen_key().unwrap();
        let mut crypt_writer = EncryptingRecordWriter::new(
            BufferRecordWriter::new(Format::Record32),
            key.clone(),
            COMPRESS,
        )
        .unwrap();
        for chunk in chunks.iter() {
            crypt_writer.write_record(chunk).unwrap();
        }

        let mut clear_reader = decrypt(crypt_writer, key, COMPRESS);

        for chunk in chunks.iter() {
            assert_eq!(chunk, &clear_reader.read_record().unwrap());
        }

        assert!(clear_reader.maybe_read_record().unwrap().is_none());
    }

    #[test]
    fn test_no_chunks() {
        chunk_test(vec![]);
    }

    #[test]
    fn test_one_empty_chunk() {
        chunk_test(vec![b""]);
    }

    #[test]
    fn test_empty_chunk_edge_cases() {
        chunk_test(vec![b"", b""]);
        chunk_test(vec![b"pumpkins scream", b""]);
        chunk_test(vec![b"", b""]);
        chunk_test(vec![b"in the", b"", b""]);
        chunk_test(vec![b"", b"dead of ", b""]);
        chunk_test(vec![b"", b"", b" night "]);
    }
}
