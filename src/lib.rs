mod deterministic;
mod encrypted_record_writer;
mod encrypting_writer;
mod key_util;
mod opaque_key;
mod serde_support;
mod snow;
mod symmetric_key;

pub use crate::deterministic::DeterministicEncryptionSymmetricKey256;
pub use crate::encrypted_record_writer::{
    DecryptingRecordReader, DecryptingRecordWriter, EncryptingRecordWriter,
};
pub use crate::encrypting_writer::{DecryptingReader, EncryptingWriter};
pub use crate::key_util::KeyMaterial;
pub use crate::opaque_key::OpaqueKey;
pub use crate::snow::{SnowKeyPair, SnowPsk, SnowPublicKey};
pub use crate::symmetric_key::SymmetricKey;

use anyhow::{Context, Result};
use record_reader::{Format, RecordReader, RecordWriter};

/// `format` is the format of the underlying file. You almost certainly want
/// `Record` or `Record32`.
pub fn symmetric_decrypt_verify_file<I: std::io::Read, O: std::io::Write>(
    key: &SymmetricKey,
    reader: I,
    writer: O,
    compress: bool,
    format: Format,
) -> Result<()> {
    let writer = record_reader::IoRecordWriter::new(writer, Format::Chunk);
    let mut decrypter =
        encrypted_record_writer::DecryptingRecordWriter::new(writer, key.clone(), compress)?;
    let mut reader = record_reader::IoRecordReader::from_read(reader, format, std::usize::MAX);

    while let Some(rec) = reader.maybe_read_record().context("read record")? {
        decrypter
            .write_record(&rec)
            .context("decrypt and write record")?;
    }

    decrypter.into_inner()?.into_inner().flush()?;

    Ok(())
}

/// `format` is the format of the underlying file. You almost certainly want
/// `Record` or `Record32`.
pub fn symmetric_encrypt_sign_file<I: std::io::BufRead, O: std::io::Write>(
    key: &SymmetricKey,
    reader: I,
    writer: O,
    compress: bool,
    format: Format,
) -> Result<()> {
    let writer = record_reader::IoRecordWriter::new(writer, format);
    let mut encrypter =
        encrypted_record_writer::EncryptingRecordWriter::new(writer, key.clone(), compress)?;
    let mut reader =
        record_reader::IoRecordReader::from_read(reader, Format::Chunk, std::usize::MAX);

    while let Some(rec) = reader.maybe_read_record().context("read record")? {
        encrypter
            .write_record(&rec)
            .context("encrypt and write record")?;
    }

    encrypter.into_inner()?.into_inner().flush()?;

    Ok(())
}

pub fn symmetric_decrypt_verify(
    key: &SymmetricKey,
    ciphertext: &[u8],
    compress: bool,
    format: Format,
) -> Result<Vec<u8>> {
    let mut writer = Vec::default();
    symmetric_decrypt_verify_file(key, ciphertext, &mut writer, compress, format)?;
    Ok(writer)
}

pub fn symmetric_encrypt_sign(
    key: &SymmetricKey,
    cleartext: &[u8],
    compress: bool,
    format: Format,
) -> Result<Vec<u8>> {
    let mut writer = Vec::default();
    symmetric_encrypt_sign_file(key, cleartext, &mut writer, compress, format)?;
    Ok(writer)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::str::FromStr;

    #[test]
    fn test_vectored() {
        let cleartext = b"my cool text is here";
        let key = SymmetricKey::from_str(
            "eseb0::sym::/lt9yVsxQPo61czskdm+noia18Qh5DYBaFZoFKMa/xA=::20332",
        )
        .unwrap();
        let ciphertext = [
            0, 0, 0, 24, 239, 168, 91, 213, 56, 92, 221, 57, 187, 59, 182, 195, 3, 23, 249, 110,
            169, 228, 140, 230, 45, 249, 245, 124, 0, 0, 0, 17, 2, 141, 26, 168, 146, 159, 230,
            180, 240, 191, 101, 219, 116, 27, 236, 55, 214, 0, 0, 0, 37, 246, 225, 40, 142, 131,
            231, 184, 45, 193, 238, 190, 170, 218, 197, 86, 219, 244, 100, 25, 185, 88, 245, 229,
            34, 189, 66, 216, 156, 241, 71, 137, 233, 44, 38, 210, 192, 16, 0, 0, 0, 17, 117, 152,
            71, 171, 96, 118, 226, 6, 103, 30, 208, 253, 129, 92, 35, 102, 208,
        ];
        let decrypted = symmetric_decrypt_verify(
            &key,
            &ciphertext,
            /*compress=*/ false,
            Format::Record32,
        )
        .unwrap();
        assert_eq!(decrypted, cleartext);
    }

    #[test]
    fn test_symmetric_encryption_and_signing() {
        for compress in &[false, true] {
            let key1 = SymmetricKey::gen_key().unwrap();
            let key2 = SymmetricKey::gen_key().unwrap();
            let cleartext = b"my cool text is here";
            let ciphertext =
                symmetric_encrypt_sign(&key1, cleartext, *compress, Format::Record32).unwrap();

            assert!(
                symmetric_decrypt_verify(&key2, &ciphertext, *compress, Format::Record32).is_err()
            );

            let decrypted =
                symmetric_decrypt_verify(&key1, &ciphertext, *compress, Format::Record32).unwrap();

            assert_eq!(decrypted, cleartext);

            let mut ciphertext_bad = ciphertext.clone();
            ciphertext_bad.push(73);
            assert!(
                symmetric_decrypt_verify(&key1, &ciphertext_bad, *compress, Format::Record32)
                    .is_err()
            );
        }
    }
}
