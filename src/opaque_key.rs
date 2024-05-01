use std::io::Read;

use anyhow::Result;

use crate::key_util::*;

#[derive(Clone)]
pub struct OpaqueKey {
    data: Vec<u8>,
}

crate::serde_support::derive_serde!(OpaqueKey, OpaqueKeyVisitor);

impl std::str::FromStr for OpaqueKey {
    type Err = anyhow::Error;
    fn from_str(data: &str) -> Result<OpaqueKey> {
        let enc_data = parse_header(data.trim(), &Self::HEADER)?;
        let mut decompressor = brotli::reader::Decompressor::new(&*enc_data, 8192);
        let mut data = Vec::default();
        decompressor.read_to_end(&mut data)?;
        Ok(OpaqueKey { data })
    }
}

impl OpaqueKey {
    pub fn new(data: Vec<u8>) -> OpaqueKey {
        OpaqueKey { data }
    }

    pub fn from_file(path: &std::path::Path) -> std::io::Result<OpaqueKey> {
        Ok(OpaqueKey::new(std::fs::read(path)?))
    }

    pub fn key(&self) -> &[u8] {
        &self.data
    }
}

impl KeyMaterial for OpaqueKey {
    const HEADER: &'static str = "eseb0::opaque_key::";
    fn key_bytes(&self) -> Vec<u8> {
        let mut v = Vec::default();
        let mut compressor = brotli::CompressorReader::new(&*self.data, 8192, 8, 18);
        compressor
            .read_to_end(&mut v)
            .expect("Compression must not fail.");
        v
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::str::FromStr;

    #[test]
    fn test_opaque_key() {
        let key = OpaqueKey::new(b"hello".to_vec());
        let ser_key = key.serialize_to_string();
        assert!(!ser_key.is_empty());
        let deser_key = OpaqueKey::from_str(&ser_key).unwrap();
        assert_eq!(deser_key.key(), key.key());
    }

    #[test]
    fn test_serde() {
        let key = OpaqueKey::new(b"foo".to_vec());
        let ser_key = bincode::serialize(&key).unwrap();
        assert!(!ser_key.is_empty());
        let deser_key: OpaqueKey = bincode::deserialize(&ser_key).unwrap();
        assert_eq!(deser_key.key_bytes(), key.key_bytes());
    }
}
