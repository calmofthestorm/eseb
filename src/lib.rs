mod key_util;
mod snow_key;
mod symmetric_key;

pub use key_util::KeyMaterial;
pub use snow_key::{SnowKeyPair, SnowPublicKey};
pub use symmetric_key::SymmetricKey;

use std::convert::TryInto;

use anyhow::{Context, Error, Result};
use sodiumoxide::crypto::secretstream;

fn write_record<O: std::io::Write>(writer: &mut O, record: &[u8]) -> anyhow::Result<()> {
    let len: u32 = record.len() as u32;
    writer
        .write_all(&len.to_be_bytes())
        .context("record length")?;
    writer.write_all(record).context("record")
}

fn read_record<I: std::io::Read>(reader: &mut I, dest: &mut Vec<u8>) -> anyhow::Result<()> {
    dest.resize(4, 0);
    let n = reader.read(&mut dest[..1]).context("read record length")?;
    if n == 0 {
        dest.clear();
        return Ok(());
    } else {
        reader
            .read_exact(&mut dest[1..])
            .context("read record length")?;
    }
    let len = u32::from_be_bytes(dest[..4].try_into().unwrap());
    dest.resize(len as usize, 0);
    reader.read_exact(dest).context("read record")
}

pub fn symmetric_decrypt_verify_file<I: std::io::Read, O: std::io::Write>(
    key: &SymmetricKey,
    mut reader: I,
    mut writer: O,
) -> Result<()> {
    let mut buf = Vec::default();
    read_record(&mut reader, &mut buf).context("read header")?;

    let header = secretstream::xchacha20poly1305::Header::from_slice(&buf)
        .ok_or_else(|| Error::msg("parse encryption header"))?;

    let mut stream = secretstream::xchacha20poly1305::Stream::init_pull(&header, key.as_ref())
        .map_err(|_| Error::msg("init_pull secret stream"))?;

    // IDT we actually need these but it's easier this way.
    read_record(&mut reader, &mut buf).context("read header")?;

    if stream.is_finalized() {
        return Err(Error::msg("decrypt stream finalized earlier than expected"));
    }

    let (message, tag) = stream
        .pull(&buf, None)
        .map_err(|_| Error::msg("secret stream pull"))?;

    if tag != secretstream::Tag::Message {
        return Err(Error::msg("incorrect tag"));
    }

    if !message.is_empty() {
        return Err(Error::msg("initial message not empty"));
    }

    loop {
        buf.clear();
        read_record(&mut reader, &mut buf).context("read record")?;

        let (message, tag) = stream
            .pull(&buf, None)
            .map_err(|_| Error::msg("secret stream pull"))?;

        if stream.is_finalized() != (tag == secretstream::Tag::Final) {
            return Err(Error::msg("tag final mismatch"));
        }

        if stream.is_finalized() {
            read_record(&mut reader, &mut buf).context("read record")?;
            if !buf.is_empty() {
                return Err(Error::msg("data follows end of stream"));
            } else {
                return Ok(());
            }
        }

        writer.write_all(&message).context("write crypttext")?;
    }
}

pub fn symmetric_encrypt_sign_file<I: std::io::BufRead, O: std::io::Write>(
    key: &SymmetricKey,
    mut reader: I,
    mut writer: O,
) -> Result<()> {
    let (mut stream, header) = secretstream::xchacha20poly1305::Stream::init_push(key.as_ref())
        .map_err(|_| Error::msg("init_push secret stream"))?;

    write_record(&mut writer, header.as_ref()).context("write header")?;

    // Probably not necessary but should be sufficient.
    let message = stream
        .push(b"", None, secretstream::Tag::Message)
        .map_err(|_| Error::msg("secret stream push initial"))?;
    write_record(&mut writer, &message).context("write initial crypttext")?;

    loop {
        let data = reader.fill_buf().context("read cleartext")?;
        let n = data.len();

        if n == 0 {
            break;
        }

        let message = stream
            .push(data, None, secretstream::Tag::Push)
            .map_err(|_| Error::msg("secret stream push"))?;
        write_record(&mut writer, &message).context("write crypttext")?;

        reader.consume(n);
    }

    let message = stream
        .push(b"", None, secretstream::Tag::Final)
        .map_err(|_| Error::msg("secret stream push final"))?;
    write_record(&mut writer, &message).context("write initial crypttext")?;

    Ok(())
}

pub fn symmetric_decrypt_verify(key: &SymmetricKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut writer = Vec::default();
    symmetric_decrypt_verify_file(key, ciphertext, &mut writer)?;
    Ok(writer)
}

pub fn symmetric_encrypt_sign(key: &SymmetricKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut writer = Vec::default();
    symmetric_encrypt_sign_file(key, ciphertext, &mut writer)?;
    Ok(writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symmetric_encryption_and_signing() {
        let key1 = SymmetricKey::gen_key().unwrap();
        let key2 = SymmetricKey::gen_key().unwrap();
        let cleartext = b"my cool text is here";
        let ciphertext = symmetric_encrypt_sign(&key1, cleartext).unwrap();

        assert!(symmetric_decrypt_verify(&key2, &ciphertext).is_err());

        let decrypted = symmetric_decrypt_verify(&key1, &ciphertext).unwrap();

        assert_eq!(decrypted, cleartext);

        let mut ciphertext_bad = ciphertext.clone();
        ciphertext_bad.push(73);
        assert!(symmetric_decrypt_verify(&key1, &ciphertext_bad).is_err());
    }
}
