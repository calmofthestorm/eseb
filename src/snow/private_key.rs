use anyhow::Result;

use crate::key_util::{parse_header, KeyMaterial};

#[derive(Clone)]
pub struct SnowPrivateKey {
    key: Vec<u8>,
}

crate::serde_support::derive_serde!(SnowPrivateKey, SnowPrivateKeyVisitor);

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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serde() {
        let key = crate::SnowKeyPair::gen_key().unwrap().into_private();
        let ser_key = bincode::serialize(&key).unwrap();
        assert!(!ser_key.is_empty());
        let deser_key: SnowPrivateKey = bincode::deserialize(&ser_key).unwrap();
        assert_eq!(deser_key.key_bytes(), key.key_bytes());
    }
}
