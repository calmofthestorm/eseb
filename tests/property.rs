use proptest::prelude::*;

use eseb::{
    DeterministicEncryptionSymmetricKey256, EncryptingRecordWriter, KeyMaterial, OpaqueKey,
    SnowKeyPair, SnowPsk, SnowPublicKey, SymmetricKey, symmetric_decrypt_verify,
    symmetric_encrypt_sign,
};
use record_reader::{BufferRecordReader, BufferRecordWriter, Format, RecordReader, RecordWriter};

proptest! {
    #[test]
    fn prop_symmetric_encrypt_decrypt_roundtrip(
        data in proptest::collection::vec(any::<u8>(), 0..1024),
        compress in any::<bool>(),
        legacy in any::<bool>(),
    ) {
        let key = SymmetricKey::gen_key().unwrap();
        let format = if legacy { Format::Record32 } else { Format::Record };
        let ciphertext = symmetric_encrypt_sign(&key, &data, compress, format).unwrap();
        let decrypted = symmetric_decrypt_verify(&key, &ciphertext, compress, format).unwrap();
        prop_assert_eq!(decrypted, data);
    }

    #[test]
    fn prop_opaque_key_serde_roundtrip(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let key = OpaqueKey::new(data.clone());
        let ser = key.serialize_to_string();
        let deser = ser.parse::<OpaqueKey>().unwrap();
        prop_assert_eq!(deser.key(), data.as_slice());
    }

    #[test]
    fn prop_key_material_roundtrip(_seed in any::<u64>()) {
        let sym = SymmetricKey::gen_key().unwrap();
        let sym_ser = sym.serialize_to_string();
        let sym_de = sym_ser.parse::<SymmetricKey>().unwrap();
        prop_assert_eq!(sym_de.key_bytes(), sym.key_bytes());

        let det = DeterministicEncryptionSymmetricKey256::gen_key().unwrap();
        let det_ser = det.serialize_to_string();
        let det_de = det_ser.parse::<DeterministicEncryptionSymmetricKey256>().unwrap();
        prop_assert_eq!(det_de.key_bytes(), det.key_bytes());

        let keypair = SnowKeyPair::gen_key().unwrap();
        let kp_ser = keypair.serialize_to_string();
        let kp_de = kp_ser.parse::<SnowKeyPair>().unwrap();
        prop_assert_eq!(kp_de.key_bytes(), keypair.key_bytes());

        let pubk: SnowPublicKey = keypair.to_public();
        let pub_ser = pubk.serialize_to_string();
        let pub_de = pub_ser.parse::<SnowPublicKey>().unwrap();
        prop_assert_eq!(pub_de.key_bytes(), pubk.key_bytes());

        let psk: SnowPsk = keypair.to_psk();
        let psk_ser = psk.serialize_to_string();
        let psk_de = psk_ser.parse::<SnowPsk>().unwrap();
        prop_assert_eq!(psk_de.key_bytes(), psk.key_bytes());
    }

    #[test]
    fn prop_record_writer_chunk_boundaries_roundtrip(
        chunks in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 1..64),
            1..32
        ),
        compress in any::<bool>(),
    ) {
        let key = SymmetricKey::gen_key().unwrap();
        let mut crypt_writer = EncryptingRecordWriter::new(
            BufferRecordWriter::new(Format::Record32),
            key.clone(),
            compress,
        )
        .unwrap();

        for chunk in &chunks {
            crypt_writer.write_record(chunk).unwrap();
        }

        let ciphertext = crypt_writer.into_inner().unwrap().into_cow();
        let mut clear_reader = eseb::DecryptingRecordReader::new(
            BufferRecordReader::new(ciphertext, Format::Record32, usize::MAX),
            key,
            compress,
        )
        .unwrap();

        let mut out_chunks: Vec<Vec<u8>> = Vec::new();
        while let Some(rec) = clear_reader.maybe_read_record().unwrap() {
            out_chunks.push(rec.to_vec());
        }

        prop_assert_eq!(out_chunks, chunks);
    }

    #[test]
    fn prop_record_format_streaming_roundtrip(
        chunks in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 1..128),
            1..64
        ),
        compress in any::<bool>(),
    ) {
        let key = SymmetricKey::gen_key().unwrap();
        let mut crypt_writer = EncryptingRecordWriter::new(
            BufferRecordWriter::new(Format::Record),
            key.clone(),
            compress,
        )
        .unwrap();

        for chunk in &chunks {
            crypt_writer.write_record(chunk).unwrap();
        }

        let ciphertext = crypt_writer.into_inner().unwrap().into_cow();
        let mut clear_reader = eseb::DecryptingRecordReader::new(
            BufferRecordReader::new(ciphertext, Format::Record, usize::MAX),
            key,
            compress,
        )
        .unwrap();

        let mut out_chunks: Vec<Vec<u8>> = Vec::new();
        while let Some(rec) = clear_reader.maybe_read_record().unwrap() {
            out_chunks.push(rec.to_vec());
        }

        prop_assert_eq!(out_chunks, chunks);
    }
}
