use anyhow::Result;

use crate::key_util::{parse_header, KeyMaterial};

#[derive(Clone)]
pub struct SnowPrivateKey {
    key: Vec<u8>,
}

impl std::str::FromStr for SnowPrivateKey {
    type Err = anyhow::Error;
    fn from_str(data: &str) -> Result<SnowPrivateKey> {
        let key_data = parse_header(data.trim(), &Self::HEADER)?;
        assert_eq!(key_data.len(), 32);
        Ok(SnowPrivateKey { key: key_data })
    }
}

impl SnowPrivateKey {
    pub fn key(&self) -> &[u8] {
        self.key.as_slice()
    }

    pub fn new(key: Vec<u8>) -> SnowPrivateKey {
        SnowPrivateKey { key }
    }
}

impl KeyMaterial for SnowPrivateKey {
    const HEADER: &'static str = "eseb1::snow_private_key::";
    fn key_bytes(&self) -> Vec<u8> {
        self.key.clone()
    }
}
