use std::io::Read;

use anyhow::Result;

use crate::key_util::{parse_header, KeyMaterial};

#[derive(Clone)]
pub struct SnowPsk {
    data: Vec<u8>,
}

crate::serde_support::derive_serde!(SnowPsk, SnowPskVisitor);

impl std::str::FromStr for SnowPsk {
    type Err = anyhow::Error;
    fn from_str(data: &str) -> Result<SnowPsk> {
        let enc_data = parse_header(data.trim(), &Self::HEADER)?;
        let mut decompressor = brotli::reader::Decompressor::new(&*enc_data, 8192);
        let mut data = Vec::default();
        decompressor.read_to_end(&mut data)?;
        if data.len() != 32 {
            anyhow::bail!("Bad preshared key length. Should be 32 bytes.");
        }
        Ok(SnowPsk { data })
    }
}

impl SnowPsk {
    pub fn new(data: Vec<u8>) -> Result<SnowPsk> {
        if data.len() != 32 {
            anyhow::bail!("Bad preshared key length. Should be 32 bytes.");
        }
        Ok(SnowPsk { data })
    }

    pub fn from_file(path: &std::path::Path) -> Result<SnowPsk> {
        SnowPsk::new(std::fs::read(path)?)
    }

    pub fn key(&self) -> &[u8] {
        &self.data
    }
}

impl KeyMaterial for SnowPsk {
    const HEADER: &'static str = "eseb1::snow_preshared_key::";
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
    fn test_psk() {
        let key = SnowPsk::new(b"hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh".to_vec()).unwrap();
        let ser_key = key.serialize_to_string();
        assert!(!ser_key.is_empty());
        let deser_key = SnowPsk::from_str(&ser_key).unwrap();
        assert_eq!(deser_key.key(), key.key());

        assert!(SnowPsk::new(b"hh".to_vec()).is_err());
    }

    #[test]
    fn test_serde() {
        let key = crate::SnowKeyPair::gen_key().unwrap().into_psk();
        let ser_key = bincode::serialize(&key).unwrap();
        assert!(!ser_key.is_empty());
        let deser_key: SnowPsk = bincode::deserialize(&ser_key).unwrap();
        assert_eq!(deser_key.key_bytes(), key.key_bytes());
    }
}
